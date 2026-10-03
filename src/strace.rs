//! Parser for `strace -f -y` output.
//!
//! The parser is deliberately line-oriented and syscall-table driven rather
//! than regex based. The three things that make strace output awkward are all
//! handled here:
//!
//! * **Split calls.** With `-f`, a syscall that blocks is printed as
//!   `<unfinished ...>` and completed later by a `<... name resumed>` line,
//!   possibly with other pids' lines in between. We stash the prefix per pid
//!   and splice the two halves back together.
//! * **Path resolution.** `-y` decorates every fd argument with the path it
//!   refers to (`openat(AT_FDCWD</cwd>, "rel", ...)`), so relative paths are
//!   resolved against the decoded dirfd. For the non-`*at` variants (`open`,
//!   `execve`, `rename`, ...) we fall back to a per-pid cwd that is tracked
//!   from `chdir` and from every `AT_FDCWD<...>` decoration we see.
//! * **Nested syntax.** Arguments contain quoted strings with C escapes,
//!   `{structs}`, `[arrays]`, `/* comments */` and `<fd annotations>` that may
//!   themselves contain commas. [`scan_args`] finds top-level argument
//!   boundaries while respecting all of them.

use crate::event::{Access, Event, NetAddr, Op};
use std::collections::HashMap;

/// The syscalls `learn` asks strace to trace (and the parser understands).
pub const TRACED_SYSCALLS: &str = "open,openat,openat2,creat,execve,connect,bind,unlink,unlinkat,rmdir,rename,renameat,renameat2,mkdir,mkdirat,symlink,symlinkat,link,linkat,chdir";

/// Stateful parser. Feed it lines in file order.
pub struct Parser {
    initial_cwd: String,
    cwd: HashMap<u32, String>,
    pending: HashMap<u32, String>,
}

/// Parse a whole strace output.
pub fn parse_all(text: &str, initial_cwd: &str) -> Vec<Event> {
    let mut p = Parser::new(initial_cwd);
    text.lines().filter_map(|l| p.feed(l)).collect()
}

impl Parser {
    pub fn new(initial_cwd: &str) -> Self {
        Parser {
            initial_cwd: initial_cwd.to_string(),
            cwd: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Feed one output line; returns an event when a traced call completes.
    pub fn feed(&mut self, line: &str) -> Option<Event> {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("+++") || line.starts_with("---") {
            return None;
        }
        let (pid, rest) = split_pid(line)?;
        let rest = rest.trim_start();
        if rest.starts_with("+++") || rest.starts_with("---") || rest.starts_with("<detached") {
            return None;
        }

        let full: String = if let Some(r) = rest.strip_prefix("<... ") {
            // "<... openat resumed>) = 3</x>"
            let end = r.find("resumed>")?;
            let tail = &r[end + "resumed>".len()..];
            let head = self.pending.remove(&pid)?;
            if let Some(t) = tail.trim_end().strip_suffix("<unfinished ...>") {
                // Resumed and immediately blocked again (rare): keep waiting.
                self.pending.insert(pid, format!("{head}{t}"));
                return None;
            }
            format!("{head}{tail}")
        } else if let Some(prefix) = rest.strip_suffix("<unfinished ...>") {
            self.pending.insert(pid, prefix.trim_end().to_string());
            return None;
        } else {
            rest.to_string()
        };
        self.handle_call(pid, &full)
    }

    fn cwd_of(&self, pid: u32) -> &str {
        self.cwd
            .get(&pid)
            .map(|s| s.as_str())
            .unwrap_or(&self.initial_cwd)
    }

    /// Resolve `path` against the dirfd argument (or cwd) to an absolute path.
    fn resolve(&mut self, pid: u32, dirfd: Option<&str>, path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }
        if path.starts_with('/') {
            return Some(normalize(path));
        }
        let base = match dirfd {
            Some(fd) => {
                let ann = fd_annotation(fd);
                if fd.trim_start().starts_with("AT_FDCWD") {
                    match ann {
                        Some(p) if p.starts_with('/') => {
                            self.cwd.insert(pid, p.clone());
                            p
                        }
                        _ => self.cwd_of(pid).to_string(),
                    }
                } else {
                    let p = ann?;
                    if !p.starts_with('/') {
                        return None; // pipe:[..], socket:[..], anon_inode:...
                    }
                    p
                }
            }
            None => self.cwd_of(pid).to_string(),
        };
        Some(normalize(&format!("{base}/{path}")))
    }

    fn handle_call(&mut self, pid: u32, call: &str) -> Option<Event> {
        let open = call.find('(')?;
        let name = &call[..open];
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        let scan = scan_args(call, open)?;
        let args = split_at_commas(call, open, &scan);
        let result = parse_result(&call[scan.close + 1..])?;
        let a = |i: usize| args.get(i).map(|s| s.trim());
        let st = |i: usize| a(i).and_then(parse_quoted);

        let mut ev = Event {
            pid,
            op: Op::Open,
            path: None,
            path2: None,
            access: Access::None,
            create: false,
            dir: false,
            result,
            net: None,
        };
        match name {
            "open" | "creat" | "openat" | "openat2" => {
                let (dirfd, pi) = if name.starts_with("openat") {
                    (a(0), 1)
                } else {
                    (None, 0)
                };
                let raw = st(pi)?;
                let flags: String = match name {
                    "creat" => "O_CREAT|O_WRONLY|O_TRUNC".into(),
                    "openat2" => extract_field(a(pi + 1)?, "flags")?,
                    _ => a(pi + 1)?.to_string(),
                };
                let fl: Vec<&str> = flags.split('|').map(str::trim).collect();
                if fl.contains(&"O_PATH") {
                    return None;
                }
                let tmpfile = fl.contains(&"O_TMPFILE");
                ev.access = if fl.contains(&"O_RDWR") {
                    Access::ReadWrite
                } else if fl.contains(&"O_WRONLY") || tmpfile {
                    Access::Write
                } else {
                    Access::Read
                };
                ev.create = fl.contains(&"O_CREAT") || tmpfile;
                ev.dir = fl.contains(&"O_DIRECTORY") && !tmpfile;
                let mut p = self.resolve(pid, dirfd, &raw)?;
                if tmpfile {
                    p = format!("{}/<tmpfile>", p.trim_end_matches('/'));
                }
                ev.path = Some(p);
            }
            "execve" => {
                ev.op = Op::Exec;
                ev.access = Access::Exec;
                ev.path = Some(self.resolve(pid, None, &st(0)?)?);
            }
            "connect" | "bind" => {
                ev.op = if name == "connect" {
                    Op::Connect
                } else {
                    Op::Bind
                };
                let net = parse_sockaddr(a(1)?, a(0).unwrap_or(""))?;
                if net.family == "AF_UNIX" {
                    if let Some(p) = &net.addr {
                        if p.starts_with('/') {
                            ev.path = Some(normalize(p));
                        }
                    }
                }
                ev.net = Some(net);
            }
            "unlink" | "unlinkat" | "rmdir" => {
                let (dirfd, pi) = if name == "unlinkat" {
                    (a(0), 1)
                } else {
                    (None, 0)
                };
                ev.op = if name == "rmdir" || (name == "unlinkat" && a(2)?.contains("AT_REMOVEDIR"))
                {
                    Op::Rmdir
                } else {
                    Op::Unlink
                };
                ev.path = Some(self.resolve(pid, dirfd, &st(pi)?)?);
            }
            "mkdir" | "mkdirat" => {
                let (dirfd, pi) = if name == "mkdirat" {
                    (a(0), 1)
                } else {
                    (None, 0)
                };
                ev.op = Op::Mkdir;
                ev.path = Some(self.resolve(pid, dirfd, &st(pi)?)?);
            }
            "rename" | "renameat" | "renameat2" | "link" | "linkat" => {
                ev.op = if name.starts_with("rename") {
                    Op::Rename
                } else {
                    Op::Link
                };
                let at = name.ends_with("at") || name.ends_with("at2");
                let (d1, p1, d2, p2) = if at {
                    (a(0), 1, a(2), 3)
                } else {
                    (None, 0, None, 1)
                };
                let old = st(p1)?;
                let new = st(p2)?;
                ev.path = Some(self.resolve(pid, d1, &old)?);
                ev.path2 = Some(self.resolve(pid, d2, &new)?);
            }
            "symlink" | "symlinkat" => {
                ev.op = Op::Symlink;
                let (dirfd, pi) = if name == "symlinkat" {
                    (a(1), 2)
                } else {
                    (None, 1)
                };
                ev.path2 = st(0);
                ev.path = Some(self.resolve(pid, dirfd, &st(pi)?)?);
            }
            "chdir" => {
                if ev.result == "ok" {
                    let target = self.resolve(pid, None, &st(0)?)?;
                    self.cwd.insert(pid, target);
                }
                return None;
            }
            _ => return None,
        }
        Some(ev)
    }
}

/// Split the leading pid off a line (`[pid  123] ...` or `123  ...`).
fn split_pid(line: &str) -> Option<(u32, &str)> {
    if let Some(r) = line.strip_prefix("[pid") {
        let end = r.find(']')?;
        let pid = r[..end].trim().parse().ok()?;
        return Some((pid, &r[end + 1..]));
    }
    let end = line.find(|c: char| !c.is_ascii_digit())?;
    if end == 0 {
        // No pid prefix at all (strace run without -f): attribute to pid 0.
        return Some((0, line));
    }
    let pid = line[..end].parse().ok()?;
    Some((pid, &line[end..]))
}

/// Lexically normalize an absolute path (`.`/`..`/duplicate slashes).
pub fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

struct Scan {
    commas: Vec<usize>,
    close: usize,
}

/// Locate top-level commas and the closing paren of the call whose `(` is at
/// byte index `open`.
fn scan_args(s: &str, open: usize) -> Option<Scan> {
    let b = s.as_bytes();
    let mut i = open + 1;
    let mut depth = 0usize;
    let mut commas = Vec::new();
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = s[i + 2..].find("*/")?;
                i += 2 + end + 1;
            }
            b'<' if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') => {
                // fd annotation: runs to a '>' followed by a delimiter.
                let mut j = i + 1;
                while j < b.len() {
                    if b[j] == b'>'
                        && b.get(j + 1)
                            .is_none_or(|c| matches!(c, b',' | b')' | b' ' | b'}' | b']'))
                    {
                        break;
                    }
                    j += 1;
                }
                i = j;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return (b[i] == b')').then_some(Scan { commas, close: i });
                }
                depth -= 1;
            }
            b',' if depth == 0 => commas.push(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_at_commas<'a>(s: &'a str, open: usize, scan: &Scan) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut start = open + 1;
    for &c in &scan.commas {
        out.push(&s[start..c]);
        start = c + 1;
    }
    if start < scan.close || !scan.commas.is_empty() {
        out.push(&s[start..scan.close]);
    }
    out
}

/// Parse the ` = 3</x>` / ` = -1 ENOENT (...)` tail. `None` for `= ?` style
/// results (interrupted/restarted calls), which carry no verdict.
fn parse_result(tail: &str) -> Option<String> {
    let t = tail.trim().strip_prefix('=')?.trim_start();
    let mut it = t.split_whitespace();
    let first = it.next()?;
    if first == "?" {
        return None;
    }
    if first == "-1" {
        let errno = it.next()?;
        if errno
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Some(errno.to_string());
        }
        return None;
    }
    Some("ok".to_string())
}

/// Decode a C-escaped, double-quoted strace string (tolerates a trailing `...`).
pub fn parse_quoted(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let b = arg.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some(String::from_utf8_lossy(&out).into_owned()),
            b'\\' => {
                i += 1;
                match *b.get(i)? {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'v' => out.push(11),
                    b'x' => {
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 2 && i + 1 < b.len() && b[i + 1].is_ascii_hexdigit() {
                            v = v * 16 + (b[i + 1] as char).to_digit(16)?;
                            i += 1;
                            n += 1;
                        }
                        out.push(v as u8);
                    }
                    c @ b'0'..=b'7' => {
                        let mut v = (c - b'0') as u32;
                        let mut n = 1;
                        while n < 3 && i + 1 < b.len() && (b'0'..=b'7').contains(&b[i + 1]) {
                            v = v * 8 + (b[i + 1] - b'0') as u32;
                            i += 1;
                            n += 1;
                        }
                        out.push(v as u8);
                    }
                    c => out.push(c),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    None
}

/// The `<...>` decoration of a `-y` fd argument (`3</tmp/x>` -> `/tmp/x`).
fn fd_annotation(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let s = arg.find('<')?;
    let e = arg.rfind('>')?;
    if e <= s {
        return None;
    }
    let inner = &arg[s + 1..e];
    Some(
        inner
            .strip_suffix(" (deleted)")
            .unwrap_or(inner)
            .to_string(),
    )
}

/// Pull `key=VALUE` out of a `{key=VALUE, ...}` struct argument.
fn extract_field(arg: &str, key: &str) -> Option<String> {
    let start = arg.find(&format!("{key}="))? + key.len() + 1;
    let rest = &arg[start..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn parse_sockaddr(arg: &str, fd_arg: &str) -> Option<NetAddr> {
    let family = extract_field(arg, "sa_family")?;
    let proto = fd_annotation(fd_arg).map(|a| {
        let p = a.split(':').next().unwrap_or("").to_ascii_lowercase();
        if p.starts_with("tcp") {
            "tcp".to_string()
        } else if p.starts_with("udp") {
            "udp".to_string()
        } else {
            p
        }
    });
    let port = arg.find("htons(").and_then(|i| {
        let r = &arg[i + 6..];
        r[..r.find(')')?].parse().ok()
    });
    let addr = match family.as_str() {
        "AF_INET" => arg
            .find("inet_addr(")
            .and_then(|i| parse_quoted(&arg[i + 10..])),
        "AF_INET6" => arg.find("inet_pton(").and_then(|i| {
            let r = &arg[i..];
            let q = r.find('"')?;
            parse_quoted(&r[q..])
        }),
        "AF_UNIX" => arg.find("sun_path=").and_then(|i| {
            let r = &arg[i + 9..];
            if let Some(abs) = r.strip_prefix("@\"") {
                parse_quoted(&format!("\"{abs}")).map(|s| format!("@{s}"))
            } else {
                parse_quoted(r)
            }
        }),
        _ => None,
    };
    Some(NetAddr {
        family,
        proto,
        addr,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Event {
        parse_all(line, "/work")
            .into_iter()
            .next()
            .expect("one event")
    }

    #[test]
    fn openat_readonly_with_fd_decoration() {
        let e = one(
            r#"13457 openat(AT_FDCWD</home/u/proj>, "src/main.rs", O_RDONLY|O_CLOEXEC) = 3</home/u/proj/src/main.rs>"#,
        );
        assert_eq!(e.pid, 13457);
        assert_eq!(e.op, Op::Open);
        assert_eq!(e.path.as_deref(), Some("/home/u/proj/src/main.rs"));
        assert_eq!(e.access, Access::Read);
        assert_eq!(e.result, "ok");
        assert!(!e.create && !e.dir);
    }

    #[test]
    fn openat_failure_and_directory_flags() {
        let e = one(
            r#"7 openat(AT_FDCWD</w>, "/etc/ld.so.preload", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)"#,
        );
        assert_eq!(e.result, "ENOENT");
        assert!(!e.succeeded());
        let d = one(
            r#"7 openat(AT_FDCWD</w>, "/tmp", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4</tmp>"#,
        );
        assert!(d.dir);
    }

    #[test]
    fn write_create_modes() {
        let e = one(
            r#"9 openat(AT_FDCWD</p>, "target/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5</p/target/out.txt>"#,
        );
        assert_eq!(e.access, Access::Write);
        assert!(e.create);
        assert_eq!(e.path.as_deref(), Some("/p/target/out.txt"));
        let rw = one(r#"9 open("/p/db", O_RDWR|O_CREAT, 0644) = 5</p/db>"#);
        assert_eq!(rw.access, Access::ReadWrite);
        let c = one(r#"9 creat("/p/new", 0644) = 3</p/new>"#);
        assert_eq!((c.access, c.create), (Access::Write, true));
    }

    #[test]
    fn relative_open_uses_cwd_and_chdir() {
        let text = "5 chdir(\"sub\") = 0\n5 open(\"f.txt\", O_RDONLY) = 3</work/sub/f.txt>\n";
        let evs = parse_all(text, "/work");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].path.as_deref(), Some("/work/sub/f.txt"));
    }

    #[test]
    fn dirfd_relative_and_dotdot() {
        let e = one(r#"3 openat(4</usr/lib>, "../share/x", O_RDONLY) = 5</usr/share/x>"#);
        assert_eq!(e.path.as_deref(), Some("/usr/share/x"));
        // dirfd that is not a path is dropped
        let text = r#"3 openat(5<pipe:[123]>, "x", O_RDONLY) = 6"#;
        assert!(parse_all(text, "/").is_empty());
    }

    #[test]
    fn unfinished_resumed_across_pids() {
        let text = concat!(
            "100 openat(AT_FDCWD</w>, \"/etc/hosts\", O_RDONLY <unfinished ...>\n",
            "101 openat(AT_FDCWD</w>, \"/etc/passwd\", O_RDONLY) = 3</etc/passwd>\n",
            "100 <... openat resumed>)  = 4</etc/hosts>\n",
        );
        let evs = parse_all(text, "/w");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].path.as_deref(), Some("/etc/passwd"));
        assert_eq!(evs[1].pid, 100);
        assert_eq!(evs[1].path.as_deref(), Some("/etc/hosts"));
        assert_eq!(evs[1].result, "ok");
    }

    #[test]
    fn resumed_with_remaining_args() {
        let text = concat!(
            "[pid  22] openat(AT_FDCWD</w>, \"/tmp/x\", O_WRONLY|O_CREAT <unfinished ...>\n",
            "[pid  22] <... openat resumed>, 0600) = 3</tmp/x>\n",
        );
        let evs = parse_all(text, "/w");
        assert_eq!(evs.len(), 1);
        assert!(evs[0].create);
        assert_eq!(evs[0].path.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn orphan_resume_and_noise_lines_are_ignored() {
        let text = "5 <... read resumed>) = 0\n5 +++ exited with 0 +++\n--- SIGCHLD {si_signo=SIGCHLD} ---\n\n";
        assert!(parse_all(text, "/").is_empty());
    }

    #[test]
    fn execve_with_env_comment() {
        let e = one(
            r#"1 execve("/usr/bin/cargo", ["cargo", "build"], 0x7ffd5acc5e18 /* 82 vars */) = 0"#,
        );
        assert_eq!(e.op, Op::Exec);
        assert_eq!(e.access, Access::Exec);
        assert_eq!(e.path.as_deref(), Some("/usr/bin/cargo"));
    }

    #[test]
    fn escapes_in_paths() {
        let e = one(r#"1 openat(AT_FDCWD</w>, "/tmp/a b\"c\n\303\251", O_RDONLY) = 3</x>"#);
        assert_eq!(e.path.as_deref(), Some("/tmp/a b\"c\n\u{e9}"));
        assert_eq!(parse_quoted(r#""a\x41\101""#).as_deref(), Some("aAA"));
    }

    #[test]
    fn annotation_with_comma_in_path() {
        let e = one(r#"1 openat(AT_FDCWD</w/a, b>, "f", O_RDONLY) = 3</w/a, b/f>"#);
        assert_eq!(e.path.as_deref(), Some("/w/a, b/f"));
    }

    #[test]
    fn connect_inet_inet6_unix() {
        let c = one(
            r#"4 connect(3<TCP:[1234]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.112.3")}, 16) = -1 EINPROGRESS (Operation now in progress)"#,
        );
        let n = c.net.as_ref().unwrap();
        assert_eq!((n.family.as_str(), n.port), ("AF_INET", Some(443)));
        assert_eq!(n.addr.as_deref(), Some("140.82.112.3"));
        assert_eq!(n.proto.as_deref(), Some("tcp"));
        assert!(c.succeeded());
        let c6 = one(
            r#"4 connect(5<TCPv6:[99]>, {sa_family=AF_INET6, sin6_port=htons(8080), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        );
        let n6 = c6.net.unwrap();
        assert_eq!(
            (n6.port, n6.addr.as_deref(), n6.proto.as_deref()),
            (Some(8080), Some("::1"), Some("tcp"))
        );
        let cu = one(
            r#"4 connect(3<UNIX:[1]>, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 110) = 0"#,
        );
        assert_eq!(
            cu.path.as_deref(),
            Some("/run/systemd/resolve/io.systemd.Resolve")
        );
        let ca = one(
            r#"4 connect(3<UNIX:[1]>, {sa_family=AF_UNIX, sun_path=@"/tmp/.X11-unix/X0"}, 20) = 0"#,
        );
        assert_eq!(ca.path, None);
        assert_eq!(ca.net.unwrap().addr.as_deref(), Some("@/tmp/.X11-unix/X0"));
        let udp = one(
            r#"4 connect(3<UDP:[1]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0"#,
        );
        assert_eq!(udp.net.unwrap().proto.as_deref(), Some("udp"));
    }

    #[test]
    fn namespace_ops() {
        let u = one(r#"1 unlinkat(AT_FDCWD</p>, "a.tmp", 0) = 0"#);
        assert_eq!((u.op, u.path.as_deref()), (Op::Unlink, Some("/p/a.tmp")));
        let r = one(r#"1 unlinkat(AT_FDCWD</p>, "d", AT_REMOVEDIR) = 0"#);
        assert_eq!(r.op, Op::Rmdir);
        let m = one(r#"1 mkdirat(AT_FDCWD</p>, "target", 0777) = 0"#);
        assert_eq!(m.op, Op::Mkdir);
        let rn = one(r#"1 renameat2(AT_FDCWD</p>, "a", AT_FDCWD</p>, "b", RENAME_NOREPLACE) = 0"#);
        assert_eq!(rn.op, Op::Rename);
        assert_eq!(
            (rn.path.as_deref(), rn.path2.as_deref()),
            (Some("/p/a"), Some("/p/b"))
        );
        let rn1 = one(r#"1 rename("a", "b/c") = 0"#);
        assert_eq!(rn1.path2.as_deref(), Some("/work/b/c"));
        let s = one(r#"1 symlinkat("../x", AT_FDCWD</p>, "lnk") = 0"#);
        assert_eq!(
            (s.op, s.path.as_deref(), s.path2.as_deref()),
            (Op::Symlink, Some("/p/lnk"), Some("../x"))
        );
    }

    #[test]
    fn openat2_struct_flags_and_o_path_skipped() {
        let e = one(
            r#"1 openat2(AT_FDCWD</w>, "/etc/x", {flags=O_RDONLY|O_CLOEXEC, resolve=RESOLVE_NO_SYMLINKS}, 24) = 3</etc/x>"#,
        );
        assert_eq!(e.access, Access::Read);
        assert!(parse_all(
            r#"1 openat(AT_FDCWD</w>, "/x", O_PATH|O_CLOEXEC) = 3</x>"#,
            "/"
        )
        .is_empty());
    }

    #[test]
    fn tmpfile_and_plain_pid_prefix_variants() {
        let e = one(
            r#"[pid 3] openat(AT_FDCWD</w>, "/tmp", O_RDWR|O_TMPFILE|O_EXCL, 0600) = 3</tmp/#12>"#,
        );
        assert!(e.create);
        assert_eq!(e.path.as_deref(), Some("/tmp/<tmpfile>"));
        assert_eq!(e.pid, 3);
    }

    #[test]
    fn restarted_results_carry_no_verdict() {
        assert!(parse_all(r#"1 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(1), sin_addr=inet_addr("1.1.1.1")}, 16) = ? ERESTARTSYS (To be restarted)"#, "/").is_empty());
    }

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("/a/./b/../c//d/"), "/a/c/d");
        assert_eq!(normalize("/.."), "/");
    }
}
