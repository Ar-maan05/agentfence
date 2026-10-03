//! Layout of the `.agentfence/` directory and small shared helpers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Handle to `<project>/.agentfence`.
#[derive(Debug, Clone)]
pub struct Store {
    pub project: PathBuf,
    pub root: PathBuf,
}

/// Facts about a learn run needed later by `synth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub command: Vec<String>,
    pub cwd: String,
    pub home: String,
    pub tmpdir: Option<String>,
    pub project_root: String,
    pub started_unix: u64,
    pub exit_code: Option<i32>,
}

impl Store {
    pub fn new(project: &Path) -> Result<Self> {
        let project = std::fs::canonicalize(project)
            .with_context(|| format!("project dir {}", project.display()))?;
        let root = project.join(".agentfence");
        Ok(Store { project, root })
    }

    pub fn traces_dir(&self) -> PathBuf {
        self.root.join("traces")
    }
    pub fn denials_dir(&self) -> PathBuf {
        self.root.join("denials")
    }
    pub fn profile_path(&self) -> PathBuf {
        self.root.join("profile.toml")
    }

    /// Create a directory (and the store root) and return it.
    pub fn ensure(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
    }

    /// A fresh `<timestamp>` stem in `dir` (suffix `-N` on collision).
    pub fn fresh_stem(&self, dir: &Path, name: Option<&str>) -> String {
        let base = match name {
            Some(n) => format!("{}-{}", timestamp(), sanitize(n)),
            None => timestamp(),
        };
        let mut stem = base.clone();
        let mut n = 1;
        while dir.join(format!("{stem}.strace")).exists()
            || dir.join(format!("{stem}.jsonl")).exists()
        {
            n += 1;
            stem = format!("{base}-{n}");
        }
        stem
    }

    /// Sorted trace stems that have a `.jsonl` event log.
    pub fn trace_stems(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.traces_dir())
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        e.file_name()
                            .to_str()
                            .and_then(|n| n.strip_suffix(".jsonl"))
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// Newest denial log, if any.
    pub fn latest_denials(&self) -> Option<PathBuf> {
        std::fs::read_dir(self.denials_dir())
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .max_by_key(|p| {
                (
                    std::fs::metadata(p).and_then(|m| m.modified()).ok(),
                    p.clone(),
                )
            })
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYYMMDD-HHMMSS` in UTC.
pub fn timestamp() -> String {
    format_unix(now_unix())
}

pub fn format_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_formatting() {
        assert_eq!(format_unix(0), "19700101-000000");
        assert_eq!(format_unix(1_000_000_000), "20010909-014640");
        assert_eq!(format_unix(1_782_864_000 + 3661), "20260701-010101");
    }

    #[test]
    fn fresh_stem_avoids_collisions() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path()).unwrap();
        let t = s.traces_dir();
        s.ensure(&t).unwrap();
        let a = s.fresh_stem(&t, Some("fix bug"));
        assert!(a.ends_with("-fix_bug"));
        std::fs::write(t.join(format!("{a}.strace")), "").unwrap();
        let b = s.fresh_stem(&t, Some("fix bug"));
        assert_ne!(a, b);
    }
}
