//! The intermediate representation between traces and policy: a [`Need`] is
//! "this path must be reachable with this right".
//!
//! `synth` turns observed events into needs, the cover solver turns needs into
//! grants, and `report` turns *new* events into needs again to ask the profile
//! whether it would allow them. Keeping one definition of "what does this
//! syscall require" makes all three agree.

use crate::event::{Access, Event, Op};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A kind of access a rule can grant. Each maps onto one or more Landlock
/// access rights (see `run.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Right {
    /// Read file contents.
    ReadFile,
    /// List a directory.
    ReadDir,
    /// Modify contents and the namespace: write, truncate, create, remove,
    /// rename/link (the whole Landlock "write" family).
    Write,
    /// Execute a file.
    Exec,
    /// `connect()` to a pathname unix socket (Landlock ABI >= 9).
    ConnectUnix,
}

impl Right {
    pub fn as_str(self) -> &'static str {
        match self {
            Right::ReadFile => "read_file",
            Right::ReadDir => "read_dir",
            Right::Write => "write",
            Right::Exec => "exec",
            Right::ConnectUnix => "connect_unix",
        }
    }

    /// Verb used by `report`.
    pub fn verb(self) -> &'static str {
        match self {
            Right::ReadFile => "read",
            Right::ReadDir => "list",
            Right::Write => "write",
            Right::Exec => "exec",
            Right::ConnectUnix => "connect to socket",
        }
    }
}

/// How a need constrains which grants can satisfy it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NeedKind {
    /// The path itself or any ancestor directory may carry the grant.
    Exact,
    /// A file that may be created: an ancestor grant, or (if the file already
    /// exists at synth time) a grant on the file itself, since opening an
    /// existing file with `O_CREAT` does not need the create right.
    Create,
    /// Directory-entry changes (unlink/rename/...): only a *strict ancestor*
    /// directory can carry the grant.
    Entry,
    /// `mkdir`: like `Entry`, but if the directory already exists when the
    /// profile is synthesized and no grant is possible, the need is dropped
    /// silently (`mkdir -p` on an existing directory fails with `EEXIST`
    /// before any permission check, so nothing is lost).
    Mkdir,
    /// "Anything beneath this directory" (collapsed ephemeral names, the
    /// project root). Satisfied by a grant on the directory or an ancestor;
    /// if that would expose a protected path the solver splits it into its
    /// children.
    Subtree,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Need {
    pub path: PathBuf,
    pub right: Right,
    pub kind: NeedKind,
}

impl Need {
    pub fn new(path: impl Into<PathBuf>, right: Right, kind: NeedKind) -> Self {
        Need {
            path: path.into(),
            right,
            kind,
        }
    }

    /// Would a rule on `rule_path` carrying this right satisfy the need?
    pub fn covered_by(&self, rule_path: &Path) -> bool {
        match self.kind {
            NeedKind::Entry | NeedKind::Mkdir => {
                self.path != rule_path && self.path.starts_with(rule_path)
            }
            _ => self.path.starts_with(rule_path),
        }
    }
}

/// Translate one event into the needs it implies. Failed events produce
/// nothing unless `include_failed` (used when interpreting denial logs).
/// `is_dir` tells whether a path is a directory (opening a directory for
/// reading needs `ReadDir`, not `ReadFile`).
pub fn needs_from_event(
    ev: &Event,
    include_failed: bool,
    is_dir: &dyn Fn(&Path) -> bool,
) -> Vec<Need> {
    // A failed open with ENXIO (e.g. /dev/tty without a controlling terminal)
    // still needs the grant: the same program under a terminal would succeed,
    // and under Landlock the permission error would mask the ENXIO.
    let benign_failure = ev.op == Op::Open && ev.result == "ENXIO";
    if !include_failed && !ev.succeeded() && !benign_failure {
        return Vec::new();
    }
    let p = match &ev.path {
        Some(p) => PathBuf::from(p),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    match ev.op {
        Op::Open => {
            if matches!(ev.access, Access::Read | Access::ReadWrite) {
                let r = if ev.dir || is_dir(&p) {
                    Right::ReadDir
                } else {
                    Right::ReadFile
                };
                out.push(Need::new(&p, r, NeedKind::Exact));
            }
            if matches!(ev.access, Access::Write | Access::ReadWrite) {
                let k = if ev.create {
                    NeedKind::Create
                } else {
                    NeedKind::Exact
                };
                out.push(Need::new(&p, Right::Write, k));
            }
        }
        Op::Exec => {
            // The kernel opens the binary for reading as well as executing it
            // (verified empirically: execute-only rules fail with EACCES).
            out.push(Need::new(&p, Right::Exec, NeedKind::Exact));
            out.push(Need::new(&p, Right::ReadFile, NeedKind::Exact));
        }
        Op::Connect => {
            if ev.net.as_ref().is_some_and(|n| n.family == "AF_UNIX") {
                out.push(Need::new(&p, Right::ConnectUnix, NeedKind::Exact));
            }
        }
        Op::Bind => {
            if ev.net.as_ref().is_some_and(|n| n.family == "AF_UNIX") {
                out.push(Need::new(&p, Right::Write, NeedKind::Entry));
            }
        }
        Op::Mkdir => out.push(Need::new(&p, Right::Write, NeedKind::Mkdir)),
        Op::Unlink | Op::Rmdir | Op::Symlink => {
            out.push(Need::new(&p, Right::Write, NeedKind::Entry));
        }
        Op::Rename | Op::Link => {
            out.push(Need::new(&p, Right::Write, NeedKind::Entry));
            if let Some(p2) = &ev.path2 {
                out.push(Need::new(p2, Right::Write, NeedKind::Entry));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strace::parse_all;

    fn needs(line: &str) -> Vec<Need> {
        parse_all(line, "/w")
            .iter()
            .flat_map(|e| needs_from_event(e, false, &|_| false))
            .collect()
    }

    #[test]
    fn open_modes_map_to_rights() {
        let n = needs(r#"1 openat(AT_FDCWD</w>, "/a/b", O_RDWR|O_CREAT, 0644) = 3</a/b>"#);
        assert_eq!(
            n,
            vec![
                Need::new("/a/b", Right::ReadFile, NeedKind::Exact),
                Need::new("/a/b", Right::Write, NeedKind::Create)
            ]
        );
        let d = needs(r#"1 openat(AT_FDCWD</w>, "/a", O_RDONLY|O_DIRECTORY) = 3</a>"#);
        assert_eq!(d, vec![Need::new("/a", Right::ReadDir, NeedKind::Exact)]);
    }

    #[test]
    fn exec_needs_read_and_execute() {
        let n = needs(r#"1 execve("/usr/bin/true", ["true"], 0x1 /* 1 var */) = 0"#);
        assert_eq!(
            n,
            vec![
                Need::new("/usr/bin/true", Right::Exec, NeedKind::Exact),
                Need::new("/usr/bin/true", Right::ReadFile, NeedKind::Exact)
            ]
        );
    }

    #[test]
    fn failures_ignored_unless_requested() {
        let line = r#"1 openat(AT_FDCWD</w>, "/a", O_RDONLY) = -1 EACCES (Permission denied)"#;
        assert!(needs(line).is_empty());
        let evs = parse_all(line, "/w");
        assert_eq!(needs_from_event(&evs[0], true, &|_| false).len(), 1);
    }

    #[test]
    fn entry_needs_require_strict_ancestor() {
        let n = Need::new("/p/x", Right::Write, NeedKind::Entry);
        assert!(!n.covered_by(Path::new("/p/x")));
        assert!(n.covered_by(Path::new("/p")));
        assert!(Need::new("/p/x", Right::Write, NeedKind::Exact).covered_by(Path::new("/p/x")));
    }

    #[test]
    fn rename_has_two_entry_needs() {
        let n = needs(r#"1 rename("/p/a", "/q/b") = 0"#);
        assert_eq!(n.len(), 2);
        assert!(n.iter().all(|x| x.kind == NeedKind::Entry));
    }
}
