//! `agentfence synth`: traces in, profile out.
//!
//! Pipeline (see each module for detail):
//!
//! 1. events -> [`Need`]s ([`crate::needs`]), successful calls only;
//! 2. drop secrets ([`crate::roles`]) and remember them for the warning list;
//! 3. collapse ephemeral names ([`collapse`]);
//! 4. canonicalize, add ELF/shebang interpreters for execs ([`interp`]);
//! 5. add the project-wide read/write subtree needs;
//! 6. solve the weighted cover under exclusion zones ([`cover`]);
//! 7. network ports and warnings.

pub mod collapse;
pub mod cover;
pub mod interp;

use crate::event::{Event, Op};
use crate::needs::{needs_from_event, Need, NeedKind, Right};
use crate::profile::{tilde, Hardening, Network, Profile, Rule};
use crate::roles::{Ctx, ProtectOpts, Role};
use collapse::Collapser;
use cover::{CostModel, CoverNeed, FsView, ZoneKind, Zones};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One trace's worth of events.
pub struct TraceInput {
    pub name: String,
    pub events: Vec<Event>,
}

pub struct SynthOptions {
    pub project: PathBuf,
    pub home: PathBuf,
    pub tmpdir: Option<PathBuf>,
    pub protect: ProtectOpts,
    pub cost: CostModel,
    /// Grant read/write on the whole project (split around protected paths).
    pub project_grant: bool,
    /// Grant read+exec on the system toolchain roots and read on /etc, so tools
    /// the agent never ran during learning still start (never write).
    pub system_grant: bool,
}

/// Root-owned, world-readable system trees. Narrowing reads inside them buys
/// little (no per-user secrets live there) and is the main source of false
/// positives: an unseen tool, or an unseen library it loads, gets denied.
const SYSTEM_EXEC_ROOTS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"];
const SYSTEM_READ_ROOTS: &[&str] = &["/etc"];
/// Per-user tool directories (relative to a home): read+exec, never write.
const HOME_EXEC_ROOTS: &[&str] = &[".local/bin", ".cargo/bin", ".rustup/toolchains"];

/// Run the pipeline.
pub fn synthesize(traces: &[TraceInput], opts: &SynthOptions, fs: &dyn FsView) -> Profile {
    let canon = |p: &Path| fs.canonical(p);
    let ctx = Ctx {
        home: canon(&opts.home),
        project: canon(&opts.project),
        tmpdir: opts.tmpdir.as_ref().map(|t| canon(t)),
    };
    let raw_ctx = Ctx {
        home: opts.home.clone(),
        project: opts.project.clone(),
        tmpdir: opts.tmpdir.clone(),
    };
    let is_dir = |p: &Path| fs.is_dir(p) == Some(true);
    // The real account's home, when `$HOME` was redirected: its secrets still exist.
    let acct_ctx: Option<Ctx> = crate::roles::account_home()
        .map(|h| canon(&h))
        .filter(|h| *h != ctx.home)
        .map(|home| Ctx {
            home,
            project: ctx.project.clone(),
            tmpdir: None,
        });

    // 1. Needs per trace (+ network facts).
    let mut per_trace: Vec<Vec<Need>> = Vec::new();
    let mut tcp_connect = BTreeSet::new();
    let mut tcp_bind = BTreeSet::new();
    let mut udp = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut abstract_unix = false;
    for t in traces {
        let mut needs = Vec::new();
        for ev in &t.events {
            needs.extend(needs_from_event(ev, false, &is_dir));
            if !ev.succeeded() {
                continue;
            }
            if let (Some(net), true) = (&ev.net, matches!(ev.op, Op::Connect | Op::Bind)) {
                match (net.family.as_str(), net.proto.as_deref(), net.port) {
                    ("AF_INET" | "AF_INET6", proto, Some(port)) if proto != Some("udp") => {
                        if ev.op == Op::Connect {
                            tcp_connect.insert(port);
                            if let Some(a) = &net.addr {
                                endpoints.insert(format!("{a}:{port}"));
                            }
                        } else {
                            tcp_bind.insert(port);
                        }
                    }
                    ("AF_INET" | "AF_INET6", Some("udp"), Some(port)) => {
                        udp.insert(port);
                    }
                    ("AF_UNIX", _, _)
                        if net.addr.as_deref().is_some_and(|a| a.starts_with('@')) =>
                    {
                        abstract_unix = true;
                    }
                    _ => {}
                }
            }
        }
        per_trace.push(needs);
    }

    // 2. Cross-trace collapse knowledge.
    let collapser = Collapser::learn(
        &per_trace
            .iter()
            .map(|ns| {
                ns.iter()
                    .filter(|n| {
                        !is_secret_either(&raw_ctx, &ctx, acct_ctx.as_ref(), &n.path, &opts.protect)
                    })
                    .map(|n| n.path.clone())
                    .collect()
            })
            .collect::<Vec<Vec<PathBuf>>>(),
    );

    let anchors: Vec<PathBuf> = [&raw_ctx, &ctx]
        .iter()
        .flat_map(|c| {
            [
                Some(c.home.clone()),
                Some(c.project.clone()),
                c.tmpdir.clone(),
            ]
        })
        .flatten()
        .collect();
    let mut warnings: Vec<String> = Vec::new();
    let mut secrets: BTreeSet<String> = BTreeSet::new();
    let mut collapsed_notes: BTreeSet<String> = BTreeSet::new();
    let mut needs: BTreeMap<Need, (PathBuf, bool)> = BTreeMap::new();

    let add = |need: Need, split: bool, needs: &mut BTreeMap<Need, (PathBuf, bool)>| {
        let role = ctx.classify_with(&need.path, &opts.protect);
        let ceiling = ctx.ceiling(&need.path, role);
        needs.entry(need).or_insert((ceiling, split));
    };

    for ns in &per_trace {
        for n in ns {
            // 3. Secrets (checked on the raw and the symlink-resolved path).
            let resolved = canon(&n.path);
            if is_secret_either(&raw_ctx, &ctx, acct_ctx.as_ref(), &n.path, &opts.protect)
                || ctx.is_secret(&resolved, &opts.protect)
                || acct_ctx
                    .as_ref()
                    .is_some_and(|a| a.is_secret(&resolved, &opts.protect))
            {
                secrets.insert(format!(
                    "{} ({})",
                    tilde(&n.path.to_string_lossy(), &opts.home.to_string_lossy()),
                    n.right.verb()
                ));
                continue;
            }
            // 4. Collapse ephemeral components.
            let (cp, collapsed) = collapser.collapse_below(&n.path, &anchors);
            if collapsed {
                let target = canon(&cp);
                if n.right == Right::Write
                    && (target.starts_with("/proc") || target.starts_with("/sys"))
                {
                    // A write under a per-process pseudo-fs name (e.g. /proc/thread-self/attr/fscreate)
                    // cannot be granted by name, and collapsing it would hand out write access to
                    // every process's /proc entries. Leave it denied and say so.
                    collapsed_notes.insert(format!(
                        "write to {} not granted: per-process pseudo-fs name, a grant would cover all of {}",
                        n.path.display(),
                        target.display()
                    ));
                    continue;
                }
                let kind = NeedKind::Subtree;
                if ctx.classify_with(&target, &opts.protect) != Role::Project {
                    collapsed_notes.insert(format!(
                    "ephemeral name under {} collapsed: {} access to anything beneath it is now granted",
                    tilde(&target.to_string_lossy(), &opts.home.to_string_lossy()),
                    n.right.verb()
                    ));
                }
                add(Need::new(target, n.right, kind), false, &mut needs);
            } else {
                let target = canon(&n.path);
                add(Need::new(target, n.right, n.kind), false, &mut needs);
            }
        }
    }

    // 5. Interpreters for every exec.
    let execs: Vec<PathBuf> = needs
        .keys()
        .filter(|n| n.right == Right::Exec)
        .map(|n| n.path.clone())
        .collect();
    for e in execs {
        for i in interp::interpreters(&e) {
            let i = canon(&i);
            add(
                Need::new(i.clone(), Right::Exec, NeedKind::Exact),
                false,
                &mut needs,
            );
            add(
                Need::new(i, Right::ReadFile, NeedKind::Exact),
                false,
                &mut needs,
            );
        }
    }

    // 6. Project-wide grants.
    if opts.project_grant && fs.is_dir(&ctx.project) == Some(true) {
        // Exec too: venv entry points and build outputs live here, and a child the
        // agent execs stays inside the same Landlock domain.
        for r in [Right::ReadFile, Right::ReadDir, Right::Write, Right::Exec] {
            add(
                Need::new(ctx.project.clone(), r, NeedKind::Subtree),
                true,
                &mut needs,
            );
        }
    }

    // Zones.
    let mut zones = Zones::default();
    let mut seen = BTreeSet::new();
    let mut zone = |p: PathBuf, kind: ZoneKind, zones: &mut Zones| {
        if seen.insert((p.clone(), kind as u8)) {
            zones.add(p, kind);
        }
    };
    for c in [&raw_ctx, &ctx].into_iter().chain(acct_ctx.as_ref()) {
        for s in c.secret_roots(&opts.protect) {
            zone(s.clone(), ZoneKind::Secret, &mut zones);
            zone(canon(&s), ZoneKind::Secret, &mut zones);
        }
        for p in c.protected_roots(&opts.protect) {
            zone(p.clone(), ZoneKind::ProtectedWrite, &mut zones);
            zone(canon(&p), ZoneKind::ProtectedWrite, &mut zones);
        }
        zone(c.home.clone(), ZoneKind::Broad, &mut zones);
    }

    // 7. Cover.
    let input: Vec<CoverNeed> = needs
        .iter()
        .map(|(n, (c, sp))| CoverNeed {
            need: n.clone(),
            ceiling: c.clone(),
            split: *sp,
        })
        .collect();
    let result = cover::solve(&input, &zones, fs, &opts.cost);

    let mut by_path: BTreeMap<PathBuf, BTreeSet<Right>> = BTreeMap::new();
    for g in &result.grants {
        by_path.entry(g.path.clone()).or_default().insert(g.right);
    }
    if opts.system_grant {
        let homes: Vec<&Path> = [&ctx, &raw_ctx]
            .into_iter()
            .chain(acct_ctx.as_ref())
            .map(|c| c.home.as_path())
            .collect();
        add_system_grants(&mut by_path, fs, &homes);
    }
    let rules: Vec<Rule> = by_path
        .into_iter()
        .map(|(p, rs)| {
            let role = ctx.classify_with(&p, &opts.protect);
            Rule {
                path: p.to_string_lossy().into_owned(),
                access: rs.into_iter().collect(),
                role,
            }
        })
        .collect();

    // Warnings.
    let home_s = opts.home.to_string_lossy().into_owned();
    for r in &rules {
        if r.role == Role::Toolchain && r.access.contains(&Right::Write) {
            warnings.push(format!(
                "write access granted inside the toolchain/system area: {}",
                tilde(&r.path, &home_s)
            ));
        }
        if r.path == "/proc" && r.access.contains(&Right::ReadFile) {
            warnings.push(
                "read access to /proc exposes /proc/<pid>/environ of other same-user processes (Landlock cannot carve this out)".into(),
            );
        }
    }
    warnings.extend(collapsed_notes);
    let split_zones: BTreeSet<String> = result
        .splits
        .iter()
        .map(|(_, _, z)| {
            tilde(
                &z.strip_prefix(&ctx.project)
                    .map(|r| format!("./{}", r.display()))
                    .unwrap_or_else(|_| z.to_string_lossy().into_owned()),
                &home_s,
            )
        })
        .collect();
    if !split_zones.is_empty() {
        warnings.push(format!(
            "project grants were split into per-entry rules to keep protected paths read-only: {}. New top-level entries in those directories cannot be created (a Landlock rule on the parent would also cover the protected path)",
            split_zones.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if abstract_unix {
        warnings.push("abstract unix socket connects were observed: scope_abstract_unix disabled in the profile".into());
    }
    let mut unmet: Vec<String> = result
        .unmet
        .iter()
        .map(|u| {
            format!(
                "{} {}: {}",
                u.need.right.verb(),
                tilde(&u.need.path.to_string_lossy(), &home_s),
                u.reason
            )
        })
        .collect();
    unmet.dedup();

    Profile {
        version: 1,
        project_root: ctx.project.to_string_lossy().into_owned(),
        home: ctx.home.to_string_lossy().into_owned(),
        tmpdir: ctx
            .tmpdir
            .as_ref()
            .map(|t| t.to_string_lossy().into_owned()),
        traces: traces.iter().map(|t| t.name.clone()).collect(),
        blocked_secrets: secrets.into_iter().collect(),
        unmet,
        warnings,
        network: Network {
            enforce: true,
            connect_tcp: tcp_connect.into_iter().collect(),
            bind_tcp: tcp_bind.into_iter().collect(),
            observed_udp: udp.into_iter().collect(),
            observed_tcp_endpoints: endpoints.into_iter().collect(),
        },
        hardening: Hardening {
            scope_signals: true,
            scope_abstract_unix: !abstract_unix,
        },
        rules,
    }
}

/// Add the system-root grants and drop rules they make redundant.
fn add_system_grants(
    by_path: &mut BTreeMap<PathBuf, BTreeSet<Right>>,
    fs: &dyn FsView,
    homes: &[&Path],
) {
    let read: BTreeSet<Right> = [Right::ReadFile, Right::ReadDir].into();
    let exec: BTreeSet<Right> = [Right::ReadFile, Right::ReadDir, Right::Exec].into();
    let mut roots: Vec<(PathBuf, BTreeSet<Right>)> = Vec::new();
    let home_bins = homes
        .iter()
        .flat_map(|h| HOME_EXEC_ROOTS.iter().map(move |r| h.join(r)));
    let candidates = SYSTEM_EXEC_ROOTS
        .iter()
        .map(|r| (PathBuf::from(r), &exec))
        .chain(home_bins.map(|p| (p, &exec)))
        .chain(SYSTEM_READ_ROOTS.iter().map(|r| (PathBuf::from(r), &read)));
    for (r, rights) in candidates {
        let p = fs.canonical(&r);
        if fs.is_dir(&p) == Some(true) && !roots.iter().any(|(q, _)| *q == p) {
            roots.push((p, rights.clone()));
        }
    }
    by_path.retain(|p, rs| {
        !roots
            .iter()
            .any(|(root, granted)| p.starts_with(root) && p != root && rs.is_subset(granted))
    });
    for (root, rights) in roots {
        by_path.entry(root).or_default().extend(rights);
    }
}

fn is_secret_either(raw: &Ctx, canon: &Ctx, acct: Option<&Ctx>, p: &Path, o: &ProtectOpts) -> bool {
    raw.is_secret(p, o) || canon.is_secret(p, o) || acct.is_some_and(|a| a.is_secret(p, o))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strace::parse_all;
    use cover::RealFs;

    /// End to end on a real temp tree with a fake HOME: strace text in,
    /// profile out.
    #[test]
    fn synth_from_strace_text() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let proj = root.join("proj");
        let home = root.join("home");
        for p in [
            "proj/src",
            "proj/.git/hooks",
            "proj/target",
            "home/.ssh",
            "home/.cache",
        ] {
            std::fs::create_dir_all(root.join(p)).unwrap();
        }
        std::fs::write(proj.join("src/a.txt"), "x").unwrap();
        std::fs::write(proj.join(".git/HEAD"), "x").unwrap();
        std::fs::write(proj.join(".git/config"), "x").unwrap();
        std::fs::write(home.join(".ssh/id_ed25519"), "k").unwrap();
        std::fs::write(home.join(".gitconfig"), "x").unwrap();

        let (p, h) = (proj.display(), home.display());
        let t1 = format!(
            "1 openat(AT_FDCWD<{p}>, \"src/a.txt\", O_RDONLY) = 3<{p}/src/a.txt>\n\
             1 openat(AT_FDCWD<{p}>, \"target/out\", O_WRONLY|O_CREAT, 0666) = 4<{p}/target/out>\n\
             1 openat(AT_FDCWD<{p}>, \"{h}/.ssh/id_ed25519\", O_RDONLY) = 5<{h}/.ssh/id_ed25519>\n\
             1 openat(AT_FDCWD<{p}>, \"{h}/.gitconfig\", O_RDONLY) = 6<{h}/.gitconfig>\n\
             1 connect(7<TCP:[1]>, {{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"1.2.3.4\")}}, 16) = 0\n\
             1 openat(AT_FDCWD<{p}>, \"{h}/.cache/tmpa8f3k2x1/x\", O_WRONLY|O_CREAT, 0600) = 8<{h}/.cache/tmpa8f3k2x1/x>\n"
        );
        let opts = SynthOptions {
            project: proj.clone(),
            home: home.clone(),
            tmpdir: None,
            protect: ProtectOpts::default(),
            cost: CostModel::default(),
            project_grant: true,
            system_grant: false,
        };
        let prof = synthesize(
            &[TraceInput {
                name: "t1".into(),
                events: parse_all(&t1, &p.to_string()),
            }],
            &opts,
            &RealFs::new(false),
        );

        // Secret was observed but never granted.
        assert!(prof
            .blocked_secrets
            .iter()
            .any(|s| s.contains(".ssh/id_ed25519")));
        for r in &prof.rules {
            assert!(!Path::new(&r.path).starts_with(home.join(".ssh")), "{r:?}");
            assert_ne!(Path::new(&r.path), home.as_path());
        }
        // Single-file home read granted exactly.
        assert!(prof
            .rules
            .iter()
            .any(|r| Path::new(&r.path) == home.join(".gitconfig")
                && r.access.contains(&Right::ReadFile)));
        // Project write grants exist but never cover .git/hooks or .git/config.
        let writes: Vec<&Rule> = prof
            .rules
            .iter()
            .filter(|r| r.access.contains(&Right::Write))
            .collect();
        assert!(writes
            .iter()
            .any(|r| Path::new(&r.path) == proj.join("src")));
        for w in &writes {
            let wp = Path::new(&w.path);
            assert!(!proj.join(".git/hooks").starts_with(wp), "{w:?}");
            assert!(!proj.join(".git/config").starts_with(wp), "{w:?}");
        }
        // Ephemeral cache dir collapsed to its parent.
        let cache = home.join(".cache");
        assert!(prof
            .rules
            .iter()
            .any(|r| Path::new(&r.path) == cache && r.access.contains(&Right::Write)));
        assert!(prof.warnings.iter().any(|w| w.contains("ephemeral")));
        assert_eq!(prof.network.connect_tcp, vec![443]);
    }

    #[test]
    fn deterministic() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(root.join("proj/src")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        let line = format!(
            "1 openat(AT_FDCWD<{0}/proj>, \"src/x\", O_RDONLY) = 3<{0}/proj/src/x>\n",
            root.display()
        );
        let mk = || {
            let opts = SynthOptions {
                project: root.join("proj"),
                home: root.join("home"),
                tmpdir: None,
                protect: ProtectOpts::default(),
                cost: CostModel::default(),
                project_grant: true,
                system_grant: false,
            };
            synthesize(
                &[TraceInput {
                    name: "a".into(),
                    events: parse_all(&line, "/"),
                }],
                &opts,
                &RealFs::new(true),
            )
        };
        assert_eq!(mk(), mk());
    }
    /// A write to a per-process /proc name must not be collapsed into a write
    /// grant on all of /proc (found by the eval: libselinux writes
    /// /proc/thread-self/attr/fscreate from rm/mkdir).
    #[test]
    fn proc_self_write_is_not_collapsed_to_proc() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let proj = root.join("proj");
        let home = root.join("home");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let p = proj.display();
        let t = format!(
            "1 openat(AT_FDCWD<{p}>, \"/proc/thread-self/attr/fscreate\", O_RDWR) = 3<anon>\n\
             1 openat(AT_FDCWD<{p}>, \"/proc/self/maps\", O_RDONLY) = 4<anon>\n"
        );
        let opts = SynthOptions {
            project: proj.clone(),
            home,
            tmpdir: None,
            protect: ProtectOpts::default(),
            cost: CostModel::default(),
            project_grant: false,
            system_grant: false,
        };
        let prof = synthesize(
            &[TraceInput {
                name: "t".into(),
                events: parse_all(&t, &p.to_string()),
            }],
            &opts,
            &RealFs::new(false),
        );
        for r in &prof.rules {
            if Path::new(&r.path).starts_with("/proc") {
                assert!(!r.access.contains(&Right::Write), "{r:?}");
            }
        }
        assert!(prof.warnings.iter().any(|w| w.contains("not granted")));
    }
    /// With `$HOME` redirected, the real account's credentials are still secrets
    /// and its home directory must not be granted as a whole.
    #[test]
    fn redirected_home_still_protects_account_home() {
        let Some(acct) = crate::roles::account_home() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let proj = root.join("proj");
        let home = root.join("home");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let (p, a) = (proj.display(), acct.display());
        let t = format!(
            "1 openat(AT_FDCWD<{p}>, \"{a}/.ssh/id_ed25519\", O_RDONLY) = 3<{a}/.ssh/id_ed25519>\n\
             1 openat(AT_FDCWD<{p}>, \"{a}/.cache/x/one\", O_RDONLY) = 4<{a}/.cache/x/one>\n\
             1 openat(AT_FDCWD<{p}>, \"{a}/.local/y/two\", O_RDONLY) = 5<{a}/.local/y/two>\n"
        );
        let opts = SynthOptions {
            project: proj.clone(),
            home,
            tmpdir: None,
            protect: ProtectOpts::default(),
            cost: CostModel::default(),
            project_grant: false,
            system_grant: false,
        };
        let prof = synthesize(
            &[TraceInput {
                name: "t".into(),
                events: parse_all(&t, &p.to_string()),
            }],
            &opts,
            &RealFs::new(false),
        );
        assert!(prof
            .blocked_secrets
            .iter()
            .any(|s| s.contains("id_ed25519")));
        for r in &prof.rules {
            let rp = Path::new(&r.path);
            assert!(rp != acct && !acct.starts_with(rp), "{r:?}");
            assert!(!rp.starts_with(acct.join(".ssh")), "{r:?}");
        }
    }

    #[test]
    fn system_grant_covers_toolchain_roots_and_never_writes() {
        let fs = RealFs::new(false);
        let usr = fs.canonical(Path::new("/usr"));
        let etc = fs.canonical(Path::new("/etc"));
        let mut by_path: BTreeMap<PathBuf, BTreeSet<Right>> = BTreeMap::new();
        by_path.insert(usr.join("bin/ls"), [Right::Exec, Right::ReadFile].into());
        by_path.insert(usr.join("lib/odd"), [Right::Write].into());
        by_path.insert(PathBuf::from("/home/u/proj"), [Right::Write].into());
        add_system_grants(&mut by_path, &fs, &[Path::new("/nonexistent-home")]);
        assert!(by_path[&usr].contains(&Right::Exec));
        assert!(!by_path[&usr].contains(&Right::Write));
        assert!(
            !by_path.contains_key(&usr.join("bin/ls")),
            "subsumed rule kept"
        );
        assert!(
            by_path.contains_key(&usr.join("lib/odd")),
            "a write rule must survive"
        );
        assert!(by_path.contains_key(Path::new("/home/u/proj")));
        assert!(!by_path[&etc].contains(&Right::Exec));
        assert!(by_path[&etc].contains(&Right::ReadFile));
    }
}
