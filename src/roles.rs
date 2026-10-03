//! Path roles and the fixed "never grant" / "never write" knowledge base.
//!
//! Everything here is a static, auditable list. There is no heuristic about
//! file *contents*: a path is a secret because of where it lives or what it
//! is called.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Under the project root.
    Project,
    /// System/toolchain files: read (and exec) only in spirit.
    Toolchain,
    /// Caches and scratch space: /tmp, ~/.cache, ...
    Cache,
    /// Credentials and keys. Never granted, even if observed.
    Secret,
    Other,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Project => "project",
            Role::Toolchain => "toolchain",
            Role::Cache => "cache",
            Role::Secret => "secret",
            Role::Other => "other",
        }
    }
}

/// Environment needed to interpret paths.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub home: PathBuf,
    pub project: PathBuf,
    pub tmpdir: Option<PathBuf>,
}

/// Home-relative locations holding credentials, keys or session material.
const HOME_SECRETS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".config/hub",
    ".netrc",
    ".pgpass",
    ".git-credentials",
    ".config/git/credentials",
    ".docker/config.json",
    ".kube",
    ".config/gcloud",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".terraform.d/credentials.tfrc.json",
    ".config/rclone",
    ".config/doctl",
    ".config/op",
    ".local/share/keyrings",
    ".password-store",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
];

/// System locations that are secret or root-equivalent.
const SYSTEM_SECRETS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssl/private",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/root",
];

/// Home-relative shell-startup / hook / persistence locations. Observed reads
/// are fine; writes are never granted (a write here is code execution on the
/// next login).
const HOME_PROTECTED: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".config/fish",
    ".gitconfig",
    ".config/git",
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
    ".local/bin",
    ".pam_environment",
    ".xprofile",
    ".xinitrc",
];

const TOOLCHAIN_SYSTEM: &[&str] = &[
    "/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/nix",
];
const TOOLCHAIN_HOME: &[&str] = &[
    ".rustup",
    ".cargo",
    ".nvm",
    ".pyenv",
    ".volta",
    ".sdkman",
    ".rbenv",
    ".local/bin",
    ".local/lib",
    ".local/share/uv",
];
const CACHE_SYSTEM: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
const CACHE_HOME: &[&str] = &[".cache", ".npm", ".local/state"];

const KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ed25519_sk",
    "id_ecdsa_sk",
];

/// Home directory of the account running this process (from `/etc/passwd`,
/// keyed on the owner of `/proc/self`), which can differ from `$HOME` when the
/// agent runs with a redirected `HOME` (CI, containers, `sudo -H`, tests). The
/// credentials of the real account stay where they are in that case, so the
/// secret and protected-path lists must apply to this directory too.
pub fn account_home() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        let home = f.get(5)?;
        (f.len() >= 6 && f[2].parse::<u32>().ok()? == uid && home.starts_with('/'))
            .then(|| PathBuf::from(home))
    })
}

/// How `Ctx::zones` should treat project-internal hook/config paths.
#[derive(Debug, Clone, Default)]
pub struct ProtectOpts {
    /// Do not protect `.git/hooks`, `.git/config` (needed for `git commit`).
    pub allow_git_writes: bool,
    /// Extra project-relative or absolute paths that must stay read-only.
    pub extra_protected: Vec<PathBuf>,
    /// Paths the user explicitly released from the secret list.
    pub allow_secrets: Vec<PathBuf>,
}

impl Ctx {
    fn home_join(&self, rels: &[&str]) -> Vec<PathBuf> {
        rels.iter().map(|r| self.home.join(r)).collect()
    }

    /// Absolute secret locations (not including name-based rules).
    pub fn secret_roots(&self, opts: &ProtectOpts) -> Vec<PathBuf> {
        let mut v = self.home_join(HOME_SECRETS);
        v.extend(SYSTEM_SECRETS.iter().map(PathBuf::from));
        v.retain(|p| {
            !opts
                .allow_secrets
                .iter()
                .any(|a| p.starts_with(a) || a.starts_with(p))
        });
        v
    }

    /// Locations whose *write* must never be granted.
    pub fn protected_roots(&self, opts: &ProtectOpts) -> Vec<PathBuf> {
        let mut v = self.home_join(HOME_PROTECTED);
        v.push(self.project.join(".agentfence"));
        if !opts.allow_git_writes {
            v.push(self.project.join(".git/hooks"));
            v.push(self.project.join(".git/config"));
        }
        for p in &opts.extra_protected {
            v.push(if p.is_absolute() {
                p.clone()
            } else {
                self.project.join(p)
            });
        }
        v
    }

    /// Is the *file name* a well-known key/credential name?
    fn secret_by_name(&self, p: &Path) -> bool {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        if KEY_NAMES.contains(&name) {
            return true;
        }
        let in_project = p.starts_with(&self.project);
        if !in_project && (name == ".env" || (name.starts_with(".env.") && !is_env_template(name)))
        {
            return true;
        }
        false
    }

    pub fn is_secret(&self, p: &Path, opts: &ProtectOpts) -> bool {
        if opts.allow_secrets.iter().any(|a| p.starts_with(a)) {
            return false;
        }
        self.secret_roots(opts).iter().any(|r| p.starts_with(r)) || self.secret_by_name(p)
    }

    /// Classify a path (secret check uses the default options).
    pub fn classify(&self, p: &Path) -> Role {
        self.classify_with(p, &ProtectOpts::default())
    }

    pub fn classify_with(&self, p: &Path, opts: &ProtectOpts) -> Role {
        if self.is_secret(p, opts) {
            return Role::Secret;
        }
        if p.starts_with(&self.project) {
            return Role::Project;
        }
        if p.starts_with(&self.home) {
            if self.home_join(CACHE_HOME).iter().any(|r| p.starts_with(r)) {
                return Role::Cache;
            }
            if self
                .home_join(TOOLCHAIN_HOME)
                .iter()
                .any(|r| p.starts_with(r))
            {
                return Role::Toolchain;
            }
            return Role::Other;
        }
        if let Some(t) = &self.tmpdir {
            if p.starts_with(t) {
                return Role::Cache;
            }
        }
        if CACHE_SYSTEM.iter().any(|r| p.starts_with(r)) {
            return Role::Cache;
        }
        if TOOLCHAIN_SYSTEM.iter().any(|r| p.starts_with(r)) {
            return Role::Toolchain;
        }
        Role::Other
    }

    /// The highest directory a grant for `p` may sit at. This stops a single
    /// stray access from widening into a grant on an unrelated parent.
    pub fn ceiling(&self, p: &Path, role: Role) -> PathBuf {
        let roots: Vec<PathBuf> = match role {
            Role::Project => return self.project.clone(),
            Role::Toolchain => self
                .home_join(TOOLCHAIN_HOME)
                .into_iter()
                .chain(TOOLCHAIN_SYSTEM.iter().map(PathBuf::from))
                .collect(),
            Role::Cache => self
                .home_join(CACHE_HOME)
                .into_iter()
                .chain(self.tmpdir.clone())
                .chain(CACHE_SYSTEM.iter().map(PathBuf::from))
                .collect(),
            _ => Vec::new(),
        };
        if let Some(r) = roots
            .iter()
            .filter(|r| p.starts_with(r))
            .max_by_key(|r| r.components().count())
        {
            // ~/.cache and ~/.local/state are shared by every application (XDG): one
            // app's cache grant must not climb to the directory that holds the others'.
            if role == Role::Cache
                && [".cache", ".local/state"]
                    .iter()
                    .any(|rel| *r == self.home.join(rel))
            {
                if let Some(app) = p
                    .strip_prefix(r)
                    .ok()
                    .and_then(|rest| rest.components().next())
                {
                    return r.join(app);
                }
            }
            return r.clone();
        }
        // Other: at most two components up from the root ("/run/user", "/dev/pts").
        let comps: Vec<_> = p.components().take(3).collect();
        comps.iter().collect()
    }
}

fn is_env_template(name: &str) -> bool {
    ["example", "sample", "template", "dist", "defaults"]
        .iter()
        .any(|s| name.ends_with(s))
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_home_is_absolute_when_known() {
        if let Some(h) = account_home() {
            assert!(h.is_absolute());
        }
    }

    use super::*;

    fn ctx() -> Ctx {
        Ctx {
            home: "/home/u".into(),
            project: "/home/u/proj".into(),
            tmpdir: None,
        }
    }

    #[test]
    fn secrets_by_location_and_name() {
        let c = ctx();
        assert_eq!(
            c.classify(Path::new("/home/u/.ssh/id_ed25519")),
            Role::Secret
        );
        assert_eq!(
            c.classify(Path::new("/home/u/.aws/credentials")),
            Role::Secret
        );
        assert_eq!(
            c.classify(Path::new("/home/u/.config/gh/hosts.yml")),
            Role::Secret
        );
        assert_eq!(c.classify(Path::new("/etc/shadow")), Role::Secret);
        assert_eq!(c.classify(Path::new("/srv/other/id_rsa")), Role::Secret);
        assert_eq!(c.classify(Path::new("/srv/other/.env")), Role::Secret);
        assert_eq!(
            c.classify(Path::new("/srv/other/.env.production")),
            Role::Secret
        );
        assert_ne!(
            c.classify(Path::new("/srv/other/.env.example")),
            Role::Secret
        );
    }

    #[test]
    fn project_env_file_is_not_secret() {
        assert_eq!(
            ctx().classify(Path::new("/home/u/proj/.env")),
            Role::Project
        );
    }

    #[test]
    fn roles_for_common_paths() {
        let c = ctx();
        assert_eq!(c.classify(Path::new("/usr/lib/libc.so.6")), Role::Toolchain);
        assert_eq!(
            c.classify(Path::new("/home/u/.rustup/toolchains")),
            Role::Toolchain
        );
        assert_eq!(c.classify(Path::new("/home/u/.cache/pip")), Role::Cache);
        assert_eq!(c.classify(Path::new("/tmp/x")), Role::Cache);
        assert_eq!(c.classify(Path::new("/home/u/Documents/x")), Role::Other);
        assert_eq!(c.classify(Path::new("/proc/meminfo")), Role::Other);
    }

    #[test]
    fn fake_home_under_tmp_is_not_cache() {
        let c = Ctx {
            home: "/tmp/w/home".into(),
            project: "/tmp/w/proj".into(),
            tmpdir: None,
        };
        assert_eq!(c.classify(Path::new("/tmp/w/home/.bashrc")), Role::Other);
        assert_eq!(c.classify(Path::new("/tmp/w/home/.ssh/k")), Role::Secret);
    }

    #[test]
    fn allow_secrets_override() {
        let c = ctx();
        let o = ProtectOpts {
            allow_secrets: vec!["/home/u/.config/gh".into()],
            ..Default::default()
        };
        assert_eq!(
            c.classify_with(Path::new("/home/u/.config/gh/hosts.yml"), &o),
            Role::Other
        );
        assert_eq!(
            c.classify_with(Path::new("/home/u/.ssh/id_rsa"), &o),
            Role::Secret
        );
    }

    #[test]
    fn cache_ceiling_is_the_app_dir() {
        let c = Ctx {
            home: "/home/u".into(),
            project: "/home/u/proj".into(),
            tmpdir: None,
        };
        assert_eq!(
            c.ceiling(Path::new("/home/u/.cache/uv/archive-v0/ab/x"), Role::Cache),
            Path::new("/home/u/.cache/uv")
        );
        assert_eq!(
            c.ceiling(Path::new("/home/u/.cache"), Role::Cache),
            Path::new("/home/u/.cache")
        );
        // dedicated cache roots keep their old ceiling
        assert_eq!(
            c.ceiling(Path::new("/home/u/.npm/_cacache/x"), Role::Cache),
            Path::new("/home/u/.npm")
        );
    }

    #[test]
    fn ceilings() {
        let c = ctx();
        assert_eq!(
            c.ceiling(Path::new("/usr/lib/x/y"), Role::Toolchain),
            PathBuf::from("/usr")
        );
        assert_eq!(
            c.ceiling(Path::new("/home/u/proj/a/b"), Role::Project),
            PathBuf::from("/home/u/proj")
        );
        assert_eq!(
            c.ceiling(Path::new("/run/user/1000/bus"), Role::Other),
            PathBuf::from("/run/user")
        );
        assert_eq!(
            c.ceiling(Path::new("/dev/null"), Role::Other),
            PathBuf::from("/dev/null")
        );
    }

    #[test]
    fn protected_roots_follow_options() {
        let c = ctx();
        let p = c.protected_roots(&ProtectOpts::default());
        assert!(p.contains(&PathBuf::from("/home/u/proj/.git/hooks")));
        let p2 = c.protected_roots(&ProtectOpts {
            allow_git_writes: true,
            ..Default::default()
        });
        assert!(!p2.contains(&PathBuf::from("/home/u/proj/.git/hooks")));
        assert!(p2.contains(&PathBuf::from("/home/u/proj/.agentfence")));
    }
}
