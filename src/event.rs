//! Normalized event model shared by the strace parser, `synth` and `report`.
//!
//! One [`Event`] is one traced syscall whose path arguments have been resolved
//! to absolute, lexically normalized paths. Events are persisted as JSONL next
//! to the raw strace output so `synth` never has to re-parse strace text.

use serde::{Deserialize, Serialize};

/// The syscall family an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Open,
    Exec,
    Connect,
    Bind,
    Unlink,
    Rmdir,
    Rename,
    Mkdir,
    Symlink,
    Link,
}

/// How a path was accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    Exec,
    /// Namespace operation (unlink, mkdir, rename...) or network call.
    None,
}

/// Destination of a `connect`/`bind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetAddr {
    /// `AF_INET`, `AF_INET6`, `AF_UNIX`, ...
    pub family: String,
    /// `tcp`, `udp`, `unix`, ... as decoded by `strace -y` (absent if unknown).
    pub proto: Option<String>,
    /// IP address, or the socket path for `AF_UNIX` (`@name` for abstract).
    pub addr: Option<String>,
    pub port: Option<u16>,
}

/// One normalized syscall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub pid: u32,
    pub op: Op,
    /// Absolute path the syscall acted on (source for rename/link).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
    /// Rename/link destination, or the (unresolved) target of a symlink.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path2: Option<String>,
    pub access: Access,
    /// The call may create the entry (`O_CREAT`, `O_TMPFILE`).
    #[serde(default)]
    pub create: bool,
    /// The call opened with `O_DIRECTORY`.
    #[serde(default)]
    pub dir: bool,
    /// `"ok"` or an errno name such as `"EACCES"`.
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub net: Option<NetAddr>,
}

impl Event {
    /// Did the syscall succeed? `EINPROGRESS` counts for `connect` on
    /// non-blocking sockets: the attempt was made and would have succeeded.
    pub fn succeeded(&self) -> bool {
        self.result == "ok" || (self.op == Op::Connect && self.result == "EINPROGRESS")
    }

    /// Was this failure plausibly caused by a sandbox (as opposed to ENOENT)?
    pub fn is_denial(&self) -> bool {
        matches!(self.result.as_str(), "EACCES" | "EPERM" | "EXDEV")
    }
}

/// Parse a JSONL event log.
pub fn read_jsonl(text: &str) -> anyhow::Result<Vec<Event>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l).map_err(|e| anyhow::anyhow!("event line {}: {e}", i + 1))
        })
        .collect()
}

/// Serialize events as JSONL.
pub fn to_jsonl(events: &[Event]) -> String {
    let mut s = String::new();
    for e in events {
        s.push_str(&serde_json::to_string(e).expect("event serializes"));
        s.push('\n');
    }
    s
}
