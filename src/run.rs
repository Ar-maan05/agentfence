//! `agentfence run`: enforce a profile with Landlock, optionally recording
//! denials.
//!
//! # Process layout
//!
//! ```text
//! agentfence run -- cmd                      (outer, unrestricted)
//!  `- strace -f ... -- agentfence run --no-record -- cmd   (tracer, unrestricted)
//!      `- agentfence (inner): landlock_restrict_self(), then exec(cmd)
//!          `- cmd and all its descendants (restricted, traced)
//! ```
//!
//! The tracer sits *outside* the sandbox so it can write its log wherever it
//! likes while the agent cannot touch it, and the sandbox is applied by the
//! inner process right before `exec`, so everything the agent runs inherits it.
//!
//! # Why strace for denials
//!
//! Landlock (kernel >= 6.15) can emit audit records for denied accesses, but
//! those go to the kernel audit subsystem: reading them needs `CAP_AUDIT_READ`
//! (netlink audit socket) or access to the kernel log, and
//! `kernel.dmesg_restrict` is typically 1. An unprivileged user cannot rely on
//! them, so we record the `EACCES`/`EPERM`/`EXDEV` results of the traced file,
//! exec and network syscalls instead. Strace sees the *syscall that failed*;
//! the report then re-evaluates each failure against the profile to separate
//! genuine policy denials from unrelated errors.

use crate::event::{read_jsonl, to_jsonl, Event};
use crate::learn::{exit_code, require_strace, strace_args};
use crate::needs::Right;
use crate::profile::Profile;
use crate::store::Store;
use crate::strace::parse_all;
use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// What `enforce` managed to do.
#[derive(Debug)]
pub struct EnforceReport {
    pub status: RulesetStatus,
    pub landlock: LandlockStatus,
    pub fs_rules: usize,
    pub skipped_missing: Vec<String>,
    /// Rights/features requested but not supported by the running kernel.
    pub unsupported: Vec<String>,
}

fn write_rights() -> BitFlags<AccessFs> {
    AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::MakeSym
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
}

/// Map profile rights to Landlock rights for a path of the given type.
pub fn fs_access(rights: &[Right], is_dir: bool) -> BitFlags<AccessFs> {
    let mut a = BitFlags::<AccessFs>::empty();
    for r in rights {
        a |= match r {
            Right::ReadFile => AccessFs::ReadFile.into(),
            Right::ReadDir => AccessFs::ReadDir.into(),
            Right::Exec => AccessFs::Execute.into(),
            Right::Write => write_rights(),
            Right::ConnectUnix => AccessFs::ResolveUnix.into(),
        };
    }
    if !is_dir {
        a &= AccessFs::from_file(ABI::V9);
    }
    a
}

/// The set of filesystem rights the sandbox *handles* (denies unless granted).
/// Device ioctls are left unrestricted: a granted `/dev/pts` still needs
/// `TCGETS` and friends to work, and we do not model that right.
pub fn handled_fs() -> BitFlags<AccessFs> {
    let mut h = AccessFs::from_all(ABI::V9);
    h.remove(AccessFs::IoctlDev);
    h
}

/// Apply the profile to the *current process* (irreversible).
pub fn enforce(profile: &Profile) -> Result<EnforceReport> {
    let handled = handled_fs();
    let mut rs = Ruleset::default().handle_access(handled)?;
    let mut want_net = false;
    if profile.network.enforce {
        rs = rs.handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)?;
        want_net = true;
    }
    let mut scopes = BitFlags::<Scope>::empty();
    if profile.hardening.scope_signals {
        scopes |= Scope::Signal;
    }
    if profile.hardening.scope_abstract_unix {
        scopes |= Scope::AbstractUnixSocket;
    }
    if !scopes.is_empty() {
        rs = rs.scope(scopes)?;
    }
    let mut created = rs.create()?;

    let mut fs_rules = 0;
    let mut skipped = Vec::new();
    for r in &profile.rules {
        let p = Path::new(&r.path);
        let Ok(fd) = PathFd::new(p) else {
            skipped.push(r.path.clone());
            continue;
        };
        let is_dir = std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(true);
        let access = fs_access(&r.access, is_dir);
        if access.is_empty() {
            continue;
        }
        created = created.add_rule(PathBeneath::new(fd, access))?;
        fs_rules += 1;
    }
    if want_net {
        for port in &profile.network.connect_tcp {
            created = created.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
        }
        for port in &profile.network.bind_tcp {
            created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
        }
    }
    let st = created.restrict_self()?;

    let mut unsupported = Vec::new();
    match st.landlock {
        LandlockStatus::Available { effective_abi, .. } => {
            let missing = handled & !AccessFs::from_all(effective_abi);
            for m in missing.iter() {
                unsupported.push(format!("filesystem right {m:?}"));
            }
            if want_net && effective_abi < ABI::V4 {
                unsupported.push("TCP connect/bind port rules (needs ABI 4)".into());
            }
            if !scopes.is_empty() && effective_abi < ABI::V6 {
                unsupported.push("signal / abstract-unix-socket scoping (needs ABI 6)".into());
            }
        }
        _ => unsupported.push("everything (Landlock unavailable)".into()),
    }
    Ok(EnforceReport {
        status: st.ruleset,
        landlock: st.landlock,
        fs_rules,
        skipped_missing: skipped,
        unsupported,
    })
}

fn describe_abi(l: &LandlockStatus) -> String {
    match l {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => match kernel_abi {
            Some(k) => format!("ABI v{} (kernel reports v{k})", *effective_abi as i32),
            None => format!("ABI v{}", *effective_abi as i32),
        },
        LandlockStatus::NotEnabled => "not enabled (boot with lsm=landlock)".into(),
        LandlockStatus::NotImplemented => "not implemented by this kernel".into(),
    }
}

/// Inner half: restrict ourselves, then become the command. Never returns on
/// success.
pub fn restrict_and_exec(
    profile: &Profile,
    cmd: &[String],
    allow_unenforced: bool,
    quiet: bool,
) -> Result<()> {
    let rep = enforce(profile)?;
    if !quiet {
        eprintln!(
            "agentfence: Landlock {}: {:?}, {} filesystem rules, TCP connect ports {:?}",
            describe_abi(&rep.landlock),
            rep.status,
            rep.fs_rules,
            profile.network.connect_tcp
        );
        for u in &rep.unsupported {
            eprintln!("agentfence: warning: not enforced on this kernel: {u}");
        }
        if !rep.skipped_missing.is_empty() {
            eprintln!(
                "agentfence: note: {} rule path(s) no longer exist and were skipped",
                rep.skipped_missing.len()
            );
        }
    }
    if rep.status == RulesetStatus::NotEnforced && !allow_unenforced {
        bail!("Landlock is not enforcing anything here; refusing to run unsandboxed (use --allow-unenforced to override)");
    }
    let err = Command::new(&cmd[0]).args(&cmd[1..]).exec();
    bail!("failed to exec `{}`: {err}", cmd[0]);
}

/// Outer half: run the inner process under strace and collect denials.
/// Returns the command's exit code.
pub fn run_recorded(
    store: &Store,
    profile_path: &Path,
    cmd: &[String],
    allow_unenforced: bool,
) -> Result<i32> {
    let strace = require_strace()?;
    store.ensure(&store.denials_dir())?;
    let stem = store.fresh_stem(&store.denials_dir(), None);
    let raw = store.denials_dir().join(format!("{stem}.strace"));
    let exe = std::env::current_exe().context("locating agentfence executable")?;
    let profile_abs = std::fs::canonicalize(profile_path)?;
    let cwd = std::env::current_dir()?;

    let mut c = Command::new(strace);
    c.args(strace_args(&raw, true))
        .arg(exe)
        .args(["run", "--no-record", "--profile"])
        .arg(&profile_abs);
    if allow_unenforced {
        c.arg("--allow-unenforced");
    }
    c.arg("--").args(cmd);
    let status = c.status().context("failed to start strace")?;
    let code = exit_code(status);

    let text = std::fs::read_to_string(&raw).unwrap_or_default();
    let events: Vec<Event> = parse_all(&text, &cwd.to_string_lossy())
        .into_iter()
        .filter(|e| e.is_denial())
        .collect();
    let jsonl = store.denials_dir().join(format!("{stem}.jsonl"));
    std::fs::write(&jsonl, to_jsonl(&events))?;
    if events.is_empty() {
        eprintln!("agentfence: no denied operations ({})", jsonl.display());
    } else {
        eprintln!(
            "agentfence: {} denied operation(s) recorded in {}; run `agentfence report`",
            events.len(),
            jsonl.display()
        );
    }
    Ok(code)
}

/// Load a denial/trace JSONL.
pub fn load_events(path: &Path) -> Result<Vec<Event>> {
    read_jsonl(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
}

/// `agentfence doctor`: what can this machine do?
pub fn doctor() -> String {
    let mut out = String::new();
    // Read everything we need *before* the probe restricts this process.
    let dmesg = std::fs::read_to_string("/proc/sys/kernel/dmesg_restrict").unwrap_or_default();
    match crate::learn::find_in_path("strace") {
        Some(p) => out.push_str(&format!("strace:   {}\n", p.display())),
        None => out.push_str("strace:   MISSING (learn and recorded runs need it)\n"),
    }
    // Probe Landlock by restricting this (short-lived) process with a trivial ruleset.
    let probe = Ruleset::default()
        .handle_access(AccessFs::ReadFile)
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self());
    match probe {
        Ok(st) => {
            out.push_str(&format!("landlock: {}\n", describe_abi(&st.landlock)));
            if let LandlockStatus::Available { effective_abi, .. } = st.landlock {
                let a = effective_abi as i32;
                out.push_str(&format!(
                    "          filesystem: yes, refer/truncate: {}, tcp port rules: {}, scopes: {}, resolve_unix: {}\n",
                    if a >= 3 { "yes" } else if a >= 2 { "refer only" } else { "no" },
                    if a >= 4 { "yes" } else { "no" },
                    if a >= 6 { "yes" } else { "no" },
                    if a >= 9 { "yes" } else { "no" },
                ));
            }
        }
        Err(e) => out.push_str(&format!("landlock: unavailable ({e})\n")),
    }
    out.push_str(&format!(
        "audit:    Landlock denial audit records need CAP_AUDIT_READ or readable kernel log (dmesg_restrict={}); \
         agentfence records denials via strace instead\n",
        dmesg.trim()
    ));
    out
}

/// Is Landlock usable? (for tests that should skip gracefully)
pub fn landlock_available() -> bool {
    matches!(
        Ruleset::default()
            .handle_access(AccessFs::ReadFile)
            .and_then(|r| r.create())
            .map(|_| ()),
        Ok(())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_mapping() {
        let w = fs_access(&[Right::Write], true);
        assert!(w.contains(AccessFs::MakeReg | AccessFs::RemoveDir | AccessFs::Refer));
        assert!(!w.contains(AccessFs::ReadFile));
        let f = fs_access(&[Right::Write, Right::ReadFile, Right::Exec], false);
        assert!(f.contains(
            AccessFs::WriteFile | AccessFs::Truncate | AccessFs::ReadFile | AccessFs::Execute
        ));
        assert!(!f.contains(AccessFs::MakeReg));
        assert!(fs_access(&[Right::ReadDir], false).is_empty());
    }

    #[test]
    fn handled_set_excludes_device_ioctl() {
        assert!(!handled_fs().contains(AccessFs::IoctlDev));
        assert!(handled_fs().contains(AccessFs::Execute));
    }
}
