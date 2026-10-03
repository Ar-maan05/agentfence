//! `agentfence report`: what did the profile block / what is new?

use crate::event::{Event, Op};
use crate::needs::{needs_from_event, Need, NeedKind};
use crate::profile::{tilde, Profile};
use crate::roles::Role;
use crate::synth::cover::canonicalize_lossy;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A denial log recorded by `run`: failures to explain.
    Denials,
    /// A fresh learn trace: successes to compare with the profile.
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// The profile does not allow it (enforced: blocked; trace: would be).
    Blocked,
    /// Failed although the profile allows it (permissions, missing file, ...).
    OtherFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub role: Role,
    pub verdict: Verdict,
    pub action: String,
    pub target: String,
    pub count: usize,
}

#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Needs seen that the profile allows (trace mode only).
    pub allowed: usize,
}

fn role_rank(r: Role) -> u8 {
    match r {
        Role::Secret => 0,
        Role::Project => 1,
        Role::Other => 2,
        Role::Cache => 3,
        Role::Toolchain => 4,
    }
}

fn action_of(n: &Need) -> &'static str {
    match n.kind {
        NeedKind::Entry | NeedKind::Mkdir => "modify",
        _ => n.right.verb(),
    }
}

/// Evaluate events against the profile.
pub fn build(profile: &Profile, events: &[Event], source: Source) -> Report {
    let ctx = profile.ctx();
    let is_dir = |p: &Path| p.is_dir();
    let mut agg: BTreeMap<(Role, Verdict, String, String), usize> = BTreeMap::new();
    let mut allowed = 0usize;
    let include_failed = source == Source::Denials;

    for ev in events {
        if source == Source::Denials && !ev.is_denial() {
            continue;
        }
        let mut entries: Vec<(Role, String, String, bool)> = Vec::new(); // role, action, target, allowed
        for n in needs_from_event(ev, include_failed, &is_dir) {
            // Rules hold symlink-resolved paths (/lib64 -> /usr/lib64), traces
            // hold what the program typed. Judge the resolved path, but call
            // something a secret if either spelling is one.
            let canon = Need::new(canonicalize_lossy(&n.path), n.right, n.kind);
            if n.kind == NeedKind::Mkdir && canon.path.is_dir() {
                continue; // mkdir -p on an existing directory is EEXIST, never a denial
            }
            let role = if ctx.classify(&n.path) == Role::Secret {
                Role::Secret
            } else {
                ctx.classify(&canon.path)
            };
            let ok = profile.allows(&canon);
            // Secrets are never allowed regardless of rules.
            let ok = ok && role != Role::Secret;
            entries.push((
                role,
                action_of(&n).to_string(),
                display_path(&n.path, role, profile),
                ok,
            ));
        }
        if let (Some(net), true) = (&ev.net, matches!(ev.op, Op::Connect | Op::Bind)) {
            if let (Some(port), true) = (
                net.port,
                net.proto.as_deref() != Some("udp") && net.family != "AF_UNIX",
            ) {
                let allowed_port = if ev.op == Op::Connect {
                    profile.is_tcp_connect_allowed(port)
                } else {
                    !profile.network.enforce || profile.network.bind_tcp.contains(&port)
                };
                let verb = if ev.op == Op::Connect {
                    "connect tcp"
                } else {
                    "bind tcp"
                };
                let host = net.addr.clone().unwrap_or_default();
                entries.push((
                    Role::Other,
                    verb.into(),
                    format!("{host}:{port}"),
                    allowed_port,
                ));
            }
        }
        for (role, action, target, ok) in entries {
            if ok && source == Source::Trace {
                allowed += 1;
                continue;
            }
            let verdict = if !ok {
                Verdict::Blocked
            } else {
                Verdict::OtherFailure
            };
            *agg.entry((role, verdict, action, target)).or_default() += 1;
        }
    }
    let mut findings: Vec<Finding> = agg
        .into_iter()
        .map(|((role, verdict, action, target), count)| Finding {
            role,
            verdict,
            action,
            target,
            count,
        })
        .collect();
    findings.sort_by(|a, b| {
        (role_rank(a.role), a.verdict, &a.target, &a.action).cmp(&(
            role_rank(b.role),
            b.verdict,
            &b.target,
            &b.action,
        ))
    });
    Report { findings, allowed }
}

fn display_path(p: &Path, role: Role, profile: &Profile) -> String {
    if role == Role::Project {
        if let Ok(rel) = p.strip_prefix(&profile.project_root) {
            let rel: PathBuf = rel.into();
            return if rel.as_os_str().is_empty() {
                ".".into()
            } else {
                format!("./{}", rel.display())
            };
        }
    }
    tilde(&p.to_string_lossy(), &profile.home)
}

/// Pretty-print. `color` enables ANSI escapes.
pub fn render(
    profile: &Profile,
    report: &Report,
    source: Source,
    source_name: &str,
    color: bool,
) -> String {
    let (red, bold, dim, reset) = if color {
        ("\x1b[31;1m", "\x1b[1m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "")
    };
    let mut o = String::new();
    o.push_str(&format!("{bold}agentfence report{reset}\n"));
    o.push_str(&format!(
        "  profile: {} rule(s) from {} trace(s)\n  source:  {} ({})\n\n",
        profile.rules.len(),
        profile.traces.len(),
        source_name,
        match source {
            Source::Denials => "denials recorded while enforcing",
            Source::Trace => "new trace compared with the profile",
        }
    ));
    let blocked_word = if source == Source::Denials {
        "BLOCKED"
    } else {
        "WOULD BE BLOCKED"
    };

    let mut by_role: BTreeMap<u8, Vec<&Finding>> = BTreeMap::new();
    for f in &report.findings {
        by_role.entry(role_rank(f.role)).or_default().push(f);
    }
    for (_, fs) in by_role {
        let role = fs[0].role;
        let title = match role {
            Role::Secret => "SECRETS: the agent tried to reach credentials",
            Role::Project => "PROJECT",
            Role::Other => "OTHER (unclassified paths and network)",
            Role::Cache => "CACHE / TEMP",
            Role::Toolchain => "TOOLCHAIN / SYSTEM",
        };
        o.push_str(&format!("{bold}{title}{reset}\n"));
        for f in fs {
            let times = if f.count > 1 {
                format!(" x{}", f.count)
            } else {
                String::new()
            };
            match (f.verdict, role) {
                (Verdict::Blocked, Role::Secret) => {
                    o.push_str(&format!("  {red}agent tried to {} {} -> {blocked_word}{reset}{times}\n", f.action, f.target))
                }
                (Verdict::Blocked, _) => {
                    o.push_str(&format!("  {bold}{blocked_word:<8}{reset} {:<11} {}{times}\n", f.action, f.target))
                }
                (Verdict::OtherFailure, _) => o.push_str(&format!(
                    "  {dim}failed (allowed by profile, so not a sandbox denial)  {} {}{times}{reset}\n",
                    f.action, f.target
                )),
            }
        }
        o.push('\n');
    }

    let blocked = report
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Blocked)
        .map(|f| f.count)
        .sum::<usize>();
    let secret = report
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Blocked && f.role == Role::Secret)
        .map(|f| f.count)
        .sum::<usize>();
    let other = report
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::OtherFailure)
        .map(|f| f.count)
        .sum::<usize>();
    if report.findings.is_empty() {
        o.push_str("Nothing to report: no operations outside the profile.\n");
    }
    o.push_str(&format!(
        "{bold}Summary{reset}: {blocked} {} ({secret} touching secrets)",
        blocked_word.to_lowercase()
    ));
    if other > 0 {
        o.push_str(&format!(", {other} unrelated failure(s)"));
    }
    if source == Source::Trace {
        o.push_str(&format!(", {} access(es) already covered", report.allowed));
        if blocked > 0 {
            o.push_str("\nDrift: re-run `agentfence synth` with this trace included if the new accesses are legitimate.");
        }
    }
    o.push('\n');
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::needs::Right;
    use crate::profile::{Hardening, Network, Rule};
    use crate::strace::parse_all;

    fn profile() -> Profile {
        Profile {
            version: 1,
            project_root: "/h/proj".into(),
            home: "/h".into(),
            tmpdir: None,
            traces: vec!["a".into()],
            blocked_secrets: vec![],
            unmet: vec![],
            warnings: vec![],
            network: Network {
                enforce: true,
                connect_tcp: vec![443],
                ..Default::default()
            },
            hardening: Hardening::default(),
            rules: vec![Rule {
                path: "/h/proj/src".into(),
                access: vec![Right::ReadFile, Right::Write],
                role: Role::Project,
            }],
        }
    }

    #[test]
    fn denial_report_groups_and_flags_secrets() {
        let text = concat!(
            "1 openat(AT_FDCWD</h/proj>, \"/h/.ssh/id_ed25519\", O_RDONLY) = -1 EACCES (Permission denied)\n",
            "1 openat(AT_FDCWD</h/proj>, \"/h/.bashrc\", O_WRONLY|O_APPEND) = -1 EACCES (Permission denied)\n",
            "1 openat(AT_FDCWD</h/proj>, \".git/hooks/pre-commit\", O_WRONLY|O_CREAT, 0755) = -1 EACCES (Permission denied)\n",
            "1 openat(AT_FDCWD</h/proj>, \"src/x\", O_WRONLY) = -1 EACCES (Permission denied)\n",
            "1 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr(\"6.6.6.6\")}, 16) = -1 EACCES (Permission denied)\n",
        );
        let ev = parse_all(text, "/h/proj");
        let r = build(&profile(), &ev, Source::Denials);
        let s = render(&profile(), &r, Source::Denials, "x.jsonl", false);
        assert!(
            s.contains("agent tried to read ~/.ssh/id_ed25519 -> BLOCKED"),
            "{s}"
        );
        assert!(s.contains("./.git/hooks/pre-commit"), "{s}");
        assert!(s.contains("~/.bashrc"));
        assert!(s.contains("6.6.6.6:9999"));
        // src/x is covered by the profile, so it is not counted as a block.
        assert!(s.contains("allowed by profile"));
        assert!(s.contains("4 blocked (1 touching secrets)"), "{s}");
        // secrets sort first
        assert!(s.find("SECRETS").unwrap() < s.find("PROJECT").unwrap());
    }

    #[test]
    fn trace_mode_counts_covered_accesses() {
        let text = concat!(
            "1 openat(AT_FDCWD</h/proj>, \"src/a\", O_RDONLY) = 3</h/proj/src/a>\n",
            "1 openat(AT_FDCWD</h/proj>, \"docs/b\", O_RDONLY) = 3</h/proj/docs/b>\n",
        );
        let r = build(&profile(), &parse_all(text, "/h/proj"), Source::Trace);
        assert_eq!(r.allowed, 1);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].target, "./docs/b");
        let s = render(&profile(), &r, Source::Trace, "t", false);
        assert!(s.contains("WOULD BE BLOCKED"));
        assert!(s.contains("Drift"));
    }

    #[test]
    fn color_marks_secret_lines_red() {
        let ev = parse_all(
            "1 openat(AT_FDCWD</h/proj>, \"/h/.aws/credentials\", O_RDONLY) = -1 EACCES (Permission denied)\n",
            "/h/proj",
        );
        let r = build(&profile(), &ev, Source::Denials);
        assert!(render(&profile(), &r, Source::Denials, "x", true)
            .contains("\x1b[31;1magent tried to read"));
    }
}
