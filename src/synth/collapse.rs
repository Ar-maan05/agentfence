//! Collapsing ephemeral path components.
//!
//! `/tmp/tmpa8f3k2x1/out.json` cannot be granted by name: next run the random
//! component differs. We detect such components two ways and truncate the path
//! at the parent (the need then becomes "anything under `/tmp`").
//!
//! 1. **Entropy/shape heuristics** ([`looks_random`]): pid-like numbers, hex
//!    hashes, UUIDs, `tmp` + random tail, mkstemp-style mixed-case tokens.
//!    Works on a single trace.
//! 2. **Cross-trace variation** ([`Collapser::learn`]): if the same path
//!    skeleton shows up in several traces with a different component each
//!    time (`/x/<A>/log` in trace 1, `/x/<B>/log` in trace 2) and every
//!    variant is exclusive to one trace, the component is ephemeral. Version-
//!    like names (`python3.11` vs `python3.12`) are exempt.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};

fn is_hex_token(t: &str) -> bool {
    t.len() >= 8
        && t.bytes().all(|b| b.is_ascii_hexdigit())
        && t.bytes().any(|b| b.is_ascii_digit())
}

fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&p)
            .all(|(n, s)| s.len() == *n && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn strip_ext(s: &str) -> &str {
    match s.rfind('.') {
        Some(i)
            if i > 0
                && s.len() - i <= 5
                && s[i + 1..].bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            &s[..i]
        }
        _ => s,
    }
}

/// `python3.12`, `libfoo-1.2.3`, `v20`, `3.11`: names that vary by release,
/// not by run.
fn is_version_like(s: &str) -> bool {
    let rest = s.trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '-');
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

fn shape(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                'a'
            } else if c.is_ascii_uppercase() {
                'A'
            } else if c.is_ascii_digit() {
                '0'
            } else {
                c
            }
        })
        .collect()
}

/// Does this single path component look machine-generated?
pub fn looks_random(name: &str) -> bool {
    if name.len() < 3 {
        return false;
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return true; // pid-like / timestamp
    }
    if is_uuid(name) {
        return true;
    }
    for pre in ["tmp", "temp"] {
        if let Some(tail) = name.trim_start_matches('.').strip_prefix(pre) {
            let tail = strip_ext(tail.trim_start_matches(['.', '_', '-']));
            let alnum = tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if tail.len() >= 6
                && alnum
                && (tail.bytes().any(|b| b.is_ascii_digit())
                    || (tail.len() == 8 && entropy(tail) >= 2.7))
            {
                return true;
            }
        }
    }
    name.split(['-', '_', '.']).any(|tok| {
        is_hex_token(tok)
            || (tok.len() >= 8
                && tok.bytes().all(|b| b.is_ascii_alphanumeric())
                && tok.bytes().any(|b| b.is_ascii_uppercase())
                && tok.bytes().any(|b| b.is_ascii_lowercase())
                && tok.bytes().any(|b| b.is_ascii_digit()))
    })
}

/// Short numeric names are only ephemeral under well-known pid parents.
fn pid_context(parent: &str, name: &str) -> bool {
    (name.bytes().all(|b| b.is_ascii_digit())
        && matches!(parent, "proc" | "pts" | "fd" | "task" | "fdinfo"))
        || (parent == "proc" && matches!(name, "self" | "thread-self"))
}

fn comps(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn join(parts: &[String]) -> PathBuf {
    let mut p = PathBuf::from("/");
    p.extend(parts);
    p
}

/// Learned set of ephemeral components.
#[derive(Debug, Default)]
pub struct Collapser {
    /// `(parent path, component)` pairs found ephemeral by cross-trace variation.
    varying: HashSet<(PathBuf, String)>,
}

impl Collapser {
    /// Learn cross-trace variation from the path sets of each trace.
    pub fn learn(traces: &[Vec<PathBuf>]) -> Self {
        // (prefix, suffix) -> component -> traces that exhibited it
        let mut groups: BTreeMap<(PathBuf, String), BTreeMap<String, BTreeSet<usize>>> =
            BTreeMap::new();
        for (t, paths) in traces.iter().enumerate() {
            for p in paths {
                let c = comps(p);
                for i in 0..c.len() {
                    let key = (join(&c[..i]), c[i + 1..].join("/"));
                    groups
                        .entry(key)
                        .or_default()
                        .entry(c[i].clone())
                        .or_default()
                        .insert(t);
                }
            }
        }
        let mut varying = HashSet::new();
        for ((prefix, suffix), by_comp) in groups {
            if by_comp.len() < 2 {
                continue;
            }
            let all: BTreeSet<usize> = by_comp.values().flatten().copied().collect();
            let exclusive = by_comp.values().all(|ts| ts.len() == 1);
            if all.len() < 2 || !exclusive {
                continue;
            }
            let names: Vec<&String> = by_comp.keys().collect();
            let plausible = names.iter().all(|n| n.len() >= 5 && !is_version_like(n));
            let ok = if suffix.is_empty() {
                // Leaves legitimately differ between tasks; demand the same
                // generated-looking shape ("tmpa8f3k2" / "tmpq1z9x7").
                let s0 = shape(names[0]);
                plausible
                    && names.iter().all(|n| {
                        n.len() >= 6 && shape(n) == s0 && n.bytes().any(|b| b.is_ascii_digit())
                    })
            } else {
                plausible
            };
            if ok {
                for n in names {
                    varying.insert((prefix.clone(), n.clone()));
                }
            }
        }
        Collapser { varying }
    }

    /// Truncate `p` at its first ephemeral component. Returns the (possibly
    /// shorter) path and whether anything was collapsed.
    pub fn collapse(&self, p: &Path) -> (PathBuf, bool) {
        self.collapse_below(p, &[])
    }

    /// Like [`collapse`](Self::collapse) but components at or above any of
    /// `anchors` (project root, home, ...) are never treated as ephemeral:
    /// a project living in `/work/proj-3f2a8c91d0` is still a stable project.
    pub fn collapse_below(&self, p: &Path, anchors: &[PathBuf]) -> (PathBuf, bool) {
        let c = comps(p);
        let skip = anchors
            .iter()
            .filter(|a| p.starts_with(a))
            .map(|a| comps(a).len())
            .max()
            .unwrap_or(0);
        for i in skip..c.len() {
            let parent = if i > 0 { c[i - 1].as_str() } else { "" };
            let random = (looks_random(&c[i])
                && !(parent == "user" && c[i].bytes().all(|b| b.is_ascii_digit())))
                || pid_context(parent, &c[i])
                || self.varying.contains(&(join(&c[..i]), c[i].clone()));
            if random {
                return (join(&c[..i]), true);
            }
        }
        (p.to_path_buf(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_names() {
        for n in [
            "tmpa8f3k2x1",
            "tmp9q2z1x",
            ".tmpA1b2C3",
            "3f2a8c91d0e4b7a1",
            "foo-3f2a8c91d0e4b7a1",
            "5ad8a5d6.0",
            "123e4567-e89b-12d3-a456-426614174000",
            "98213",
            "tmp.Xk3Pq9ZtW1",
            "pytest-Ab3dE9fG1h",
        ] {
            assert!(looks_random(n), "{n} should look random");
        }
    }

    #[test]
    fn stable_names() {
        for n in [
            "libssl.so.3",
            "python3.12",
            "x86_64-linux-gnu",
            "node_modules",
            "Cargo.lock",
            "main.rs",
            "libLLVM-17.so",
            "cpu0",
            "utf8mb4",
            "template.txt",
            "tmpl",
            "deadbeef",
            "README.md",
            ".git",
            "id_ed25519",
            "target",
            "ld-linux-x86-64.so.2",
            "12",
            "tmp",
            "tmpfile",
        ] {
            assert!(!looks_random(n), "{n} should not look random");
        }
    }

    #[test]
    fn collapses_at_first_random_component() {
        let c = Collapser::default();
        assert_eq!(
            c.collapse(Path::new("/tmp/tmpa8f3k2x1/out/x.json")),
            (PathBuf::from("/tmp"), true)
        );
        assert_eq!(
            c.collapse(Path::new("/proc/4242/status")),
            (PathBuf::from("/proc"), true)
        );
        assert_eq!(
            c.collapse(Path::new("/dev/pts/3")),
            (PathBuf::from("/dev/pts"), true)
        );
        assert_eq!(
            c.collapse(Path::new("/run/user/1000/bus")),
            (PathBuf::from("/run/user/1000/bus"), false)
        );
        assert!(!c.collapse(Path::new("/usr/lib/python3.12/os.py")).1);
        assert_eq!(
            c.collapse(Path::new("/p/target/debug/build/foo-3f2a8c91d0e4b7a1/out"))
                .0,
            PathBuf::from("/p/target/debug/build")
        );
    }

    #[test]
    fn anchors_are_never_collapsed() {
        let c = Collapser::default();
        let anchors = [PathBuf::from("/work/proj-3f2a8c91d0e4b7a1")];
        assert_eq!(
            c.collapse_below(Path::new("/work/proj-3f2a8c91d0e4b7a1/src/a.rs"), &anchors),
            (PathBuf::from("/work/proj-3f2a8c91d0e4b7a1/src/a.rs"), false)
        );
        assert!(
            c.collapse(Path::new("/work/proj-3f2a8c91d0e4b7a1/src/a.rs"))
                .1
        );
        assert_eq!(
            c.collapse_below(
                Path::new("/work/proj-3f2a8c91d0e4b7a1/tmpa8f3k2x1/a"),
                &anchors
            )
            .0,
            PathBuf::from("/work/proj-3f2a8c91d0e4b7a1")
        );
    }

    #[test]
    fn variation_across_traces_collapses_midpath() {
        let t1 = vec![
            PathBuf::from("/work/session-alpha/log.txt"),
            PathBuf::from("/usr/lib/python3.11/os.py"),
        ];
        let t2 = vec![
            PathBuf::from("/work/session-bravo/log.txt"),
            PathBuf::from("/usr/lib/python3.12/os.py"),
        ];
        let c = Collapser::learn(&[t1, t2]);
        assert_eq!(
            c.collapse(Path::new("/work/session-alpha/log.txt")),
            (PathBuf::from("/work"), true)
        );
        assert_eq!(
            c.collapse(Path::new("/work/session-bravo/log.txt")),
            (PathBuf::from("/work"), true)
        );
        // version-like names are not ephemeral
        assert!(!c.collapse(Path::new("/usr/lib/python3.11/os.py")).1);
    }

    #[test]
    fn shared_components_do_not_collapse() {
        // Both traces touch the same dir: not exclusive to one trace.
        let t1 = vec![
            PathBuf::from("/work/shared/a"),
            PathBuf::from("/work/onlyone/a"),
        ];
        let t2 = vec![PathBuf::from("/work/shared/a")];
        let c = Collapser::learn(&[t1, t2]);
        assert!(!c.collapse(Path::new("/work/shared/a")).1);
    }

    #[test]
    fn leaf_variation_needs_same_shape() {
        let t1 = vec![PathBuf::from("/data/run4821x")];
        let t2 = vec![PathBuf::from("/data/run9937q")];
        let c = Collapser::learn(&[t1, t2]);
        assert_eq!(
            c.collapse(Path::new("/data/run4821x")),
            (PathBuf::from("/data"), true)
        );
        // different leaves with different shapes: ordinary files
        let t3 = vec![PathBuf::from("/data/report.csv")];
        let t4 = vec![PathBuf::from("/data/summary2.json")];
        let c2 = Collapser::learn(&[t3, t4]);
        assert!(!c2.collapse(Path::new("/data/report.csv")).1);
    }
}
