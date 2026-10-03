//! `agentfence learn`: run a command under strace and normalize the trace.

use crate::event::to_jsonl;
use crate::store::{now_unix, Meta, Store};
use crate::strace::{parse_all, TRACED_SYSCALLS};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate an executable on `PATH`.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// strace arguments shared by `learn` and the recording mode of `run`.
pub fn strace_args(output: &Path, failed_only: bool) -> Vec<String> {
    let mut a: Vec<String> = [
        "-f",
        "-qq",
        "-y",
        "-s",
        "4096",
        "--seccomp-bpf",
        "-e",
        "signal=none",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push("-e".into());
    a.push(format!("trace={TRACED_SYSCALLS}"));
    if failed_only {
        a.push("-e".into());
        a.push("status=failed".into());
    }
    a.push("-o".into());
    a.push(output.to_string_lossy().into_owned());
    a.push("--".into());
    a
}

pub fn require_strace() -> Result<PathBuf> {
    find_in_path("strace")
        .context("strace not found in PATH (install it, e.g. `dnf install strace`)")
}

/// Translate an exit status into a shell-style code.
pub fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

pub fn learn(store: &Store, cmd: &[String], name: Option<&str>) -> Result<i32> {
    if cmd.is_empty() {
        bail!("no command given (usage: agentfence learn -- <command> [args...])");
    }
    let strace = require_strace()?;
    store.ensure(&store.traces_dir())?;
    let stem = store.fresh_stem(&store.traces_dir(), name);
    let raw = store.traces_dir().join(format!("{stem}.strace"));
    let cwd = std::env::current_dir()?;

    eprintln!("agentfence: learning from `{}`", cmd.join(" "));
    let status = Command::new(strace)
        .args(strace_args(&raw, false))
        .args(cmd)
        .status()
        .context("failed to start strace")?;
    let code = exit_code(status);

    let text = std::fs::read_to_string(&raw).unwrap_or_default();
    if text.trim().is_empty() {
        bail!(
            "strace produced no output (is ptrace allowed here? check /proc/sys/kernel/yama/ptrace_scope and that `{}` exists)",
            cmd[0]
        );
    }
    let events = parse_all(&text, &cwd.to_string_lossy());
    std::fs::write(
        store.traces_dir().join(format!("{stem}.jsonl")),
        to_jsonl(&events),
    )?;
    let meta = Meta {
        command: cmd.to_vec(),
        cwd: cwd.to_string_lossy().into_owned(),
        home: std::env::var("HOME").unwrap_or_default(),
        tmpdir: std::env::var("TMPDIR").ok().filter(|s| !s.is_empty()),
        project_root: store.project.to_string_lossy().into_owned(),
        started_unix: now_unix(),
        exit_code: Some(code),
    };
    std::fs::write(
        store.traces_dir().join(format!("{stem}.meta.json")),
        serde_json::to_string_pretty(&meta)?,
    )?;

    let ok = events.iter().filter(|e| e.succeeded()).count();
    eprintln!(
        "agentfence: trace `{stem}`: {} events ({ok} successful), command exited {code}",
        events.len()
    );
    eprintln!(
        "agentfence: run `agentfence synth` once you have traces for the tasks you care about"
    );
    Ok(code)
}
