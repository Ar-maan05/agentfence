//! End-to-end tests that drive the real binary. They skip (pass with a
//! message) when strace or Landlock is unavailable, e.g. in minimal CI containers.

use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_agentfence");

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn landlock_ok() -> bool {
    let out = Command::new(BIN)
        .arg("doctor")
        .output()
        .expect("doctor runs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with("landlock: ABI"))
}

fn skip_reason() -> Option<&'static str> {
    if !have("strace") {
        Some("strace not installed")
    } else if !have("git") || !have("bash") {
        Some("git/bash not installed")
    } else if !landlock_ok() {
        Some("Landlock unavailable")
    } else {
        None
    }
}

fn af(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .expect("agentfence runs")
}

#[test]
fn injection_demo_blocks_attacks_and_keeps_benign_work() {
    if let Some(why) = skip_reason() {
        eprintln!("SKIP injection demo: {why}");
        return;
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/demo/injection.sh");
    let out = Command::new("bash")
        .arg(script)
        .env("AGENTFENCE_BIN", BIN)
        .env("COLOR", "never")
        .output()
        .expect("demo runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.code() == Some(77) {
        eprintln!("SKIP injection demo: {stdout}");
        return;
    }
    assert!(
        out.status.success(),
        "demo failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for needle in [
        "PASS  benign task still succeeds under the profile",
        "PASS  no attack succeeded",
        "PASS  ~/.bashrc unchanged",
        "PASS  no .git/hooks/pre-commit created",
        "agent tried to read ~/.ssh/id_ed25519 -> BLOCKED",
    ] {
        assert!(stdout.contains(needle), "missing `{needle}` in:\n{stdout}");
    }
    assert!(!stdout.contains("FAIL"), "{stdout}");
}

#[test]
fn subcommands_fail_cleanly_without_state() {
    let d = tempfile::tempdir().unwrap();
    for args in [&["synth"][..], &["report"][..], &["run", "--", "true"][..]] {
        let out = af(d.path(), args);
        assert!(!out.status.success(), "{args:?} should fail");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("agentfence: error"), "{args:?}: {err}");
    }
}

#[test]
fn learn_then_synth_writes_both_profile_formats() {
    if let Some(why) = skip_reason() {
        eprintln!("SKIP learn/synth: {why}");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let proj = std::fs::canonicalize(d.path()).unwrap().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("src/a.txt"), "x\n").unwrap();
    let learn = Command::new(BIN)
        .current_dir(&proj)
        .env("HOME", d.path().join("home"))
        .args(["learn", "--", "sh", "-c", "cat src/a.txt > out.txt"])
        .output()
        .unwrap();
    assert!(
        learn.status.success(),
        "{}",
        String::from_utf8_lossy(&learn.stderr)
    );
    let synth = af(&proj, &["synth"]);
    assert!(
        synth.status.success(),
        "{}",
        String::from_utf8_lossy(&synth.stderr)
    );
    let toml = std::fs::read_to_string(proj.join(".agentfence/profile.toml")).unwrap();
    assert!(toml.contains("[[rules]]"));
    let rules = std::fs::read_to_string(proj.join(".agentfence/profile.rules")).unwrap();
    assert!(rules.starts_with("agentfence-rules 2\n"));
    let parsed =
        agentfence::rules::parse(&rules).expect("profile.rules parses with the reference parser");
    assert!(parsed.iter().any(|r| matches!(r, agentfence::rules::RuleLine::Fs { path, .. } if path == proj.to_str().unwrap())));
}
