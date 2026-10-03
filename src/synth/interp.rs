//! Exec needs more than the exec'd file: the *kernel* opens the ELF
//! interpreter (`ld.so`) or the `#!` interpreter itself, and Landlock checks
//! `Execute` on those opens. They never appear in an strace of userspace
//! syscalls, so `synth` reconstructs them by reading the binary.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `PT_INTERP` of a 64-bit little-endian ELF file.
pub fn elf_interp(path: &Path) -> Option<PathBuf> {
    let mut f = File::open(path).ok()?;
    let mut h = [0u8; 64];
    f.read_exact(&mut h).ok()?;
    if &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
        return None;
    }
    let phoff = u64le(&h[32..40]);
    let phentsize = u16le(&h[54..56]) as u64;
    let phnum = u16le(&h[56..58]) as u64;
    for i in 0..phnum.min(64) {
        f.seek(SeekFrom::Start(phoff + i * phentsize)).ok()?;
        let mut ph = [0u8; 56];
        f.read_exact(&mut ph).ok()?;
        if u32le(&ph[0..4]) == 3 {
            let off = u64le(&ph[8..16]);
            let sz = u64le(&ph[32..40]).min(4096) as usize;
            f.seek(SeekFrom::Start(off)).ok()?;
            let mut buf = vec![0u8; sz];
            f.read_exact(&mut buf).ok()?;
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return Some(PathBuf::from(
                String::from_utf8_lossy(&buf[..end]).into_owned(),
            ));
        }
    }
    None
}

/// Interpreter named by a `#!` line.
pub fn shebang_interp(path: &Path) -> Option<PathBuf> {
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; 256];
    let n = f.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let line = text.strip_prefix("#!")?.lines().next()?;
    let first = line.split_whitespace().next()?;
    first.starts_with('/').then(|| PathBuf::from(first))
}

/// All interpreters the kernel will open (transitively) to exec `path`.
pub fn interpreters(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cur = path.to_path_buf();
    for _ in 0..4 {
        let next = shebang_interp(&cur).or_else(|| elf_interp(&cur));
        match next {
            Some(n) if !out.contains(&n) => {
                out.push(n.clone());
                cur = n;
            }
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn shebang_chain() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("run.sh");
        std::fs::File::create(&s)
            .unwrap()
            .write_all(b"#!/bin/sh\necho hi\n")
            .unwrap();
        assert_eq!(shebang_interp(&s), Some(PathBuf::from("/bin/sh")));
        let all = interpreters(&s);
        assert_eq!(all[0], PathBuf::from("/bin/sh"));
    }

    #[test]
    fn elf_interp_of_real_binary() {
        // /bin/sh is a dynamically linked ELF on any glibc/musl distro the
        // tests run on; skip quietly on static or exotic systems.
        if let Some(i) = elf_interp(Path::new("/bin/sh")) {
            assert!(i.to_string_lossy().contains("ld"), "{i:?}");
        }
    }

    #[test]
    fn non_executables_have_none() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("data");
        std::fs::write(&s, "plain").unwrap();
        assert!(interpreters(&s).is_empty());
    }
}
