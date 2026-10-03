//! Tests for the C launcher (`launcher/agentfence-exec`). Both skip (pass with a
//! message) when the C binary is not built: `meson setup launcher/build launcher &&
//! ninja -C launcher/build`, or point `AGENTFENCE_EXEC` at a build.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_agentfence");

fn c_launcher() -> Option<PathBuf> {
    let p = std::env::var_os("AGENTFENCE_EXEC")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("launcher/build/agentfence-exec")
        });
    p.is_file().then_some(p)
}

#[test]
fn rust_and_c_launchers_agree_on_the_probe() {
    let Some(exec) = c_launcher() else {
        eprintln!("SKIP differential: C launcher not built");
        return;
    };
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/launcher/tests/differential.sh"
    );
    let out = Command::new("bash")
        .arg(script)
        .env("AGENTFENCE_EXEC", exec)
        .env("AGENTFENCE_BIN", BIN)
        .output()
        .expect("differential runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.code() == Some(77) {
        eprintln!("SKIP differential: {stdout}");
        return;
    }
    assert!(
        out.status.success(),
        "differential failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("PASS  outcome vectors identical"),
        "{stdout}"
    );
    assert!(!stdout.contains("FAIL"), "{stdout}");
}

/// Does the C parser accept `input` (via `agentfence-exec --check`)?
fn c_accepts(exec: &PathBuf, input: &[u8]) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("x.rules");
    std::fs::write(&f, input).unwrap();
    Command::new(exec)
        .arg("--check")
        .arg("--rules")
        .arg(&f)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
        == Some(0)
}

fn rust_accepts(input: &[u8]) -> bool {
    match std::str::from_utf8(input) {
        Ok(s) => agentfence::rules::parse(s).is_ok(),
        Err(_) => false, // the CLI reads files with read_to_string
    }
}

#[test]
fn c_and_rust_parsers_accept_the_same_inputs() {
    let Some(exec) = c_launcher() else {
        eprintln!("SKIP parser parity: C launcher not built");
        return;
    };
    let valid: &[u8] = b"agentfence-rules 2\n# c\noption\tnet_enforce\noption\tscope_signal\n\
fs\t/p\twrite_file,read_file,truncate\nfs\t/run/x.sock\tresolve_unix\nnet\tconnect\t443\nnet\tbind\t0\n";
    let mut cases: Vec<Vec<u8>> = vec![valid.to_vec()];
    for s in [
        "",
        "\n",
        "agentfence-rules 1",
        "agentfence-rules 1\n",
        "agentfence-rules 2\r\n",
        "agentfence-rules 3\n",
        "agentfence-rules  1\n",
        "Agentfence-rules 1\n",
        "agentfence-rules 1\r",
        "agentfence-rules 1\n\n\n# x\n",
        "agentfence-rules 1\r\n# x\r\nfs\t/a\tread_file\r\n",
        "agentfence-rules 1\nfs\t/a\tread_file\r",
        "agentfence-rules 1\nfs\t/a\tread_file\r\r\n",
        "agentfence-rules 1\nfs\t/a\tread_file",
        "agentfence-rules 1\n \n",
        "agentfence-rules 1\nfs\t/a\tread_file,\n",
        "agentfence-rules 1\nfs\t/a\t,read_file\n",
        "agentfence-rules 1\nfs\t/a\t\n",
        "agentfence-rules 1\nfs\t/a\tread_file,read_file\n",
        "agentfence-rules 1\nfs\t/a\tREAD_FILE\n",
        "agentfence-rules 1\nfs\ta\tread_file\n",
        "agentfence-rules 1\nfs\t\tread_file\n",
        "agentfence-rules 1\nfs\t/a\tb\tread_file\n",
        "agentfence-rules 1\nfs\t/a\n",
        "agentfence-rules 1\nfs\n",
        "agentfence-rules 1\nfs \t/a\tread_file\n",
        "agentfence-rules 1\nfs\t/a b/c\tread_file\n",
        "agentfence-rules 1\nfs\t/a\u{e9}\tread_file\n",
        "agentfence-rules 1\nfs\t/a\0b\tread_file\n",
        "agentfence-rules 1\n# \u{e9}\0\n",
        "agentfence-rules 1\nnet\tconnect\t80\n",
        "agentfence-rules 1\nnet\tconnect\t0080\n",
        "agentfence-rules 1\nnet\tconnect\t+80\n",
        "agentfence-rules 1\nnet\tconnect\t-0\n",
        "agentfence-rules 1\nnet\tconnect\t65535\n",
        "agentfence-rules 1\nnet\tconnect\t65536\n",
        "agentfence-rules 1\nnet\tconnect\t0000000000000000000065535\n",
        "agentfence-rules 1\nnet\tconnect\t99999999999999999999999\n",
        "agentfence-rules 1\nnet\tconnect\t\n",
        "agentfence-rules 1\nnet\tconnect\t8 0\n",
        "agentfence-rules 1\nnet\tudp\t80\n",
        "agentfence-rules 1\nnet\tconnect\n",
        "agentfence-rules 1\nnet\tconnect\t80\t1\n",
        "agentfence-rules 1\nbogus\tx\n",
        "agentfence-rules 1\nresolve\n",
        "agentfence-rules 1\nfs\t/a\tresolve_unix\n",
        "agentfence-rules 2\nfs\t/a\tresolve_unix\n",
        "agentfence-rules 2\nfs\t/a\tresolve_unix,execute\n",
        "agentfence-rules 1\noption\tscope_signal\n",
        "agentfence-rules 2\noption\tscope_signal\n",
        "agentfence-rules 2\noption\tbogus\n",
        "agentfence-rules 2\noption\n",
        "agentfence-rules 2\noption\tscope_signal\tx\n",
        "agentfence-rules 2\noption\tnet_enforce\r\n",
        "agentfence-rules 2\noption\tnet_enforce\noption\tnet_enforce\n",
        " agentfence-rules 1\n",
        "\u{feff}agentfence-rules 1\n",
    ] {
        cases.push(s.as_bytes().to_vec());
    }
    // Invalid UTF-8 in a path, a comment and the header.
    cases.push(b"agentfence-rules 1\nfs\t/a\xff\tread_file\n".to_vec());
    cases.push(b"agentfence-rules 1\n# \xc3\n".to_vec());
    cases.push(b"agentfence-rules 1\n# \xed\xa0\x80\n".to_vec()); // surrogate
    cases.push(b"agentfence-rules 1\n# \xc0\x80\n".to_vec()); // overlong
    cases.push(b"agentfence-rules 1\n# \xf4\x90\x80\x80\n".to_vec()); // > U+10FFFF
    cases.push(b"agentfence-rules 1\n# \xf0\x9f\x98\x80\n".to_vec()); // valid 4-byte
    cases.push(b"\xffgentfence-rules 1\n".to_vec());
    // Deterministic byte-level mutations of the valid file.
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let alphabet = b"\t\n\r,#/ 0123456789+-fsnetopuabcdrw_\0\xff";
    for _ in 0..300 {
        let mut m = valid.to_vec();
        for _ in 0..1 + next() % 3 {
            let i = (next() % m.len() as u64) as usize;
            match next() % 3 {
                0 => m[i] = alphabet[(next() % alphabet.len() as u64) as usize],
                1 => {
                    m.remove(i);
                }
                _ => m.insert(i, alphabet[(next() % alphabet.len() as u64) as usize]),
            }
        }
        cases.push(m);
    }
    let mut accepted = 0;
    for case in &cases {
        let (r, c) = (rust_accepts(case), c_accepts(&exec, case));
        accepted += r as usize;
        assert_eq!(
            r,
            c,
            "parsers disagree (rust accepts: {r}, C accepts: {c}) on {:?}",
            String::from_utf8_lossy(case)
        );
    }
    assert!(
        accepted > 10 && accepted < cases.len() - 10,
        "corpus is degenerate"
    );
}

#[test]
fn c_check_reports_line_numbers() {
    let Some(exec) = c_launcher() else {
        eprintln!("SKIP line numbers: C launcher not built");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("x.rules");
    let mut h = std::fs::File::create(&f).unwrap();
    h.write_all(b"agentfence-rules 2\n# ok\n\nfs\t/a\tfly\n")
        .unwrap();
    let out = Command::new(exec)
        .args(["--check", "--rules"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("line 4: unknown right `fly`"), "{err}");
}
