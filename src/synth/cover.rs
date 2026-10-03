//! Privilege-minimizing grant selection: a weighted set cover with hard
//! exclusion zones. This is the heart of `agentfence synth`.
//!
//! # The problem
//!
//! A trace says the agent needed `/proj/src/a.rs` (read), `/proj/src/b.rs`
//! (read), `/usr/lib/libc.so.6` (read), `/tmp/<random>/x` (write), ...
//! Landlock can only express *hierarchical* allow rules: a rule on a directory
//! grants the right to everything beneath it. So the question is which
//! directories (or individual files) to put rules on.
//!
//! * Too fine (one rule per observed file) and the profile is huge and
//!   brittle: the next task reads `c.rs` and is denied.
//! * Too coarse (grant `/usr`, `$HOME`, `/`) and the sandbox is meaningless.
//!
//! # Model
//!
//! * Every observed requirement is a [`Need`]: `(path, right, kind)`.
//! * A **candidate grant** is `(directory-or-file, right)`. A need can be
//!   satisfied by the candidates on its own path and its ancestors, subject to
//!   its [`NeedKind`] (entry changes such as `unlink`/`mkdir` need a strict
//!   ancestor; "create" needs fall back to the file itself only if it exists)
//!   and to a per-need **ceiling** (a grant for a `/usr/...` need may not climb
//!   above `/usr`; a project need may not climb above the project root).
//! * A candidate has a **privilege cost** `weight(right) * reach(dir) +
//!   rule_overhead`, where `reach` estimates how many files live under the
//!   directory (the real tree, walked with a cap, or a depth heuristic) and
//!   `weight` prices rights (write is 4x read, exec 1.5x). A file candidate
//!   has reach 1. The overhead makes the solver prefer one directory rule over
//!   dozens of single-file rules when that is cheap, which also keeps the
//!   profile readable and lets it generalize a little to sibling files.
//! * **Zones** are hard constraints, not costs. A candidate that would make a
//!   [`ZoneKind::Secret`] path reachable is invalid for every right except
//!   directory listing; a [`ZoneKind::ProtectedWrite`] path (git hooks, shell
//!   rc files, the profile itself) makes write candidates invalid;
//!   [`ZoneKind::Broad`] (`$HOME`, `/`) can never be granted wholesale.
//!
//! # Algorithm
//!
//! 1. **Split.** A [`NeedKind::Subtree`] need ("everything under the project")
//!    whose directory is itself invalid is replaced by needs for each child,
//!    recursively, until every piece is either grantable or contains only
//!    zone paths. This is how a write grant on the project becomes "every
//!    top-level entry except `.git`, and inside `.git` everything except
//!    `hooks`/`config`". Children that *are* zone paths are dropped.
//! 2. **Mandatory picks.** Needs with exactly one valid candidate force it.
//! 3. **Greedy cover.** Repeatedly take the candidate with the lowest
//!    `cost / newly-covered-needs` ratio (the classic `ln n` approximation for
//!    weighted set cover). Ties break on path order so the output is
//!    deterministic. Rule overhead is waived for a path that already carries a
//!    rule (a second right on the same directory is one Landlock rule).
//! 4. **Prune.** Walking grants from most to least expensive, drop any grant
//!    whose needs are all still covered by the remaining grants.
//!
//! Needs with no valid candidate end up in [`CoverResult::unmet`] with the
//! zone that blocked them; synth reports them instead of widening anything.

use crate::needs::{Need, NeedKind, Right};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Read-only view of the filesystem used for existence checks, splitting and
/// cost estimation. Abstracted so the solver is testable without a real tree.
pub trait FsView {
    /// `Some(true)` dir, `Some(false)` non-dir, `None` missing.
    fn is_dir(&self, p: &Path) -> Option<bool>;
    /// Sorted children of a directory (empty if unreadable).
    fn children(&self, p: &Path) -> Vec<PathBuf>;
    /// Estimated number of files reachable beneath `p` (>= 1).
    fn reach(&self, p: &Path) -> u64;
    /// Symlink-free form of `p` (Landlock rules apply to resolved inodes).
    fn canonical(&self, p: &Path) -> PathBuf {
        p.to_path_buf()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneKind {
    /// No right except listing may reach this path.
    Secret,
    /// Reads are fine, writes must not reach this path.
    ProtectedWrite,
    /// This path and its ancestors may not be granted (listing excepted).
    Broad,
}

#[derive(Debug, Clone)]
pub struct Zone {
    pub path: PathBuf,
    pub kind: ZoneKind,
}

#[derive(Debug, Clone, Default)]
pub struct Zones(pub Vec<Zone>);

impl Zones {
    pub fn add(&mut self, path: impl Into<PathBuf>, kind: ZoneKind) {
        self.0.push(Zone {
            path: path.into(),
            kind,
        });
    }

    /// The first zone that makes a grant of `right` on `d` invalid.
    pub fn blocks(&self, d: &Path, right: Right) -> Option<&Zone> {
        self.0.iter().find(|z| match z.kind {
            ZoneKind::Secret => {
                right != Right::ReadDir && (z.path.starts_with(d) || d.starts_with(&z.path))
            }
            ZoneKind::ProtectedWrite => {
                right == Right::Write && (z.path.starts_with(d) || d.starts_with(&z.path))
            }
            ZoneKind::Broad => right != Right::ReadDir && z.path.starts_with(d),
        })
    }

    /// Is `p` itself inside a zone for `right` (so it must not be granted at all)?
    fn forbids_inside(&self, p: &Path, right: Right) -> Option<&Zone> {
        self.0.iter().find(|z| match z.kind {
            ZoneKind::Secret => right != Right::ReadDir && p.starts_with(&z.path),
            ZoneKind::ProtectedWrite => right == Right::Write && p.starts_with(&z.path),
            ZoneKind::Broad => false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CostModel {
    /// Price per reachable file, by right (integer, relative).
    pub read_file: u64,
    pub read_dir: u64,
    pub write: u64,
    pub exec: u64,
    pub connect_unix: u64,
    /// Fixed price of one Landlock rule.
    pub rule_overhead: u64,
}

impl Default for CostModel {
    fn default() -> Self {
        CostModel {
            read_file: 10,
            read_dir: 3,
            write: 40,
            exec: 15,
            connect_unix: 10,
            rule_overhead: 320,
        }
    }
}

impl CostModel {
    fn weight(&self, r: Right) -> u64 {
        match r {
            Right::ReadFile => self.read_file,
            Right::ReadDir => self.read_dir,
            Right::Write => self.write,
            Right::Exec => self.exec,
            Right::ConnectUnix => self.connect_unix,
        }
    }
}

/// A need plus the highest directory its grant may sit at.
#[derive(Debug, Clone)]
pub struct CoverNeed {
    pub need: Need,
    pub ceiling: PathBuf,
    /// May a blocked [`NeedKind::Subtree`] be split into per-child needs?
    /// Only sensible for the project: splitting `/tmp` into "everything in
    /// /tmp except the zone" would grant access to unrelated data, so for
    /// everything else a blocked subtree is reported as unmet instead.
    pub split: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Grant {
    pub path: PathBuf,
    pub right: Right,
}

#[derive(Debug, Clone)]
pub struct Unmet {
    pub need: Need,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct CoverResult {
    pub grants: Vec<Grant>,
    pub unmet: Vec<Unmet>,
    /// Directories that had to be split into children, with the zone why.
    pub splits: Vec<(PathBuf, Right, PathBuf)>,
    /// `mkdir` needs on already-existing directories that no grant could cover.
    pub ignored_mkdirs: usize,
}

struct Work {
    cands: Vec<Grant>,
}

/// Valid candidate grants for a need, plus the first zone that rejected a
/// candidate (for diagnostics).
fn candidates(n: &CoverNeed, zones: &Zones, fs: &dyn FsView) -> (Vec<Grant>, Option<PathBuf>) {
    let need = &n.need;
    let exists = fs.is_dir(&need.path);
    let mut chain: Vec<&Path> = Vec::new();
    let self_ok = match need.kind {
        NeedKind::Entry | NeedKind::Mkdir => false,
        NeedKind::Create => exists == Some(false),
        NeedKind::Exact => {
            exists.is_some() && (exists == Some(true) || need.right != Right::ReadDir)
        }
        NeedKind::Subtree => exists == Some(true),
    };
    if self_ok {
        chain.push(&need.path);
    }
    chain.extend(need.path.ancestors().skip(1));
    let mut out = Vec::new();
    let mut blocked_by = None;
    for d in chain {
        if d.parent().is_none() || !d.starts_with(&n.ceiling) {
            continue; // "/" and anything above the ceiling
        }
        match zones.blocks(d, need.right) {
            Some(z) => {
                blocked_by.get_or_insert_with(|| z.path.clone());
            }
            None => out.push(Grant {
                path: d.to_path_buf(),
                right: need.right,
            }),
        }
    }
    (out, blocked_by)
}

/// Solve the cover. See the module docs for the algorithm.
pub fn solve(input: &[CoverNeed], zones: &Zones, fs: &dyn FsView, cost: &CostModel) -> CoverResult {
    let mut result = CoverResult::default();

    // 1. Dedupe (order-independent) and split invalid subtrees.
    let mut queue: BTreeMap<Need, (PathBuf, bool)> = BTreeMap::new();
    for n in input {
        let e = queue
            .entry(n.need.clone())
            .or_insert_with(|| (n.ceiling.clone(), n.split));
        e.1 |= n.split;
    }
    let mut work: BTreeMap<Need, Work> = BTreeMap::new();
    let mut guard = 0usize;
    while let Some((need, (ceiling, split))) = queue.pop_first() {
        guard += 1;
        if guard > 200_000 {
            result.unmet.push(Unmet {
                need,
                reason: "split limit reached".into(),
            });
            continue;
        }
        if work.contains_key(&need) {
            continue;
        }
        let cn = CoverNeed {
            need: need.clone(),
            ceiling: ceiling.clone(),
            split,
        };
        let (cands, blocked) = candidates(&cn, zones, fs);
        if cands.is_empty() {
            if split
                && need.kind == NeedKind::Subtree
                && blocked.is_some()
                && fs.is_dir(&need.path) == Some(true)
            {
                result
                    .splits
                    .push((need.path.clone(), need.right, blocked.clone().unwrap()));
                for child in fs.children(&need.path) {
                    if zones.forbids_inside(&child, need.right).is_some() {
                        continue; // the zone itself: simply not granted
                    }
                    let is_dir = fs.is_dir(&child) == Some(true);
                    if !is_dir && need.right == Right::ReadDir {
                        continue;
                    }
                    let kind = if is_dir {
                        NeedKind::Subtree
                    } else {
                        NeedKind::Exact
                    };
                    queue
                        .entry(Need::new(child, need.right, kind))
                        .or_insert_with(|| (ceiling.clone(), true));
                }
            } else if need.kind == NeedKind::Mkdir && fs.is_dir(&need.path) == Some(true) {
                // Directory already exists: mkdir -p would see EEXIST first.
                result.ignored_mkdirs += 1;
            } else {
                let reason = match blocked {
                    Some(z) => format!("a grant would expose protected path {}", z.display()),
                    None => "no existing path to attach a rule to".to_string(),
                };
                result.unmet.push(Unmet { need, reason });
            }
            continue;
        }
        work.insert(need, Work { cands });
    }
    let work: Vec<Work> = work.into_values().collect();

    // Candidate -> needs index (BTreeMap: deterministic iteration).
    let mut index: BTreeMap<Grant, Vec<usize>> = BTreeMap::new();
    for (i, w) in work.iter().enumerate() {
        for c in &w.cands {
            index.entry(c.clone()).or_default().push(i);
        }
    }

    let mut covered = vec![false; work.len()];
    let mut chosen: Vec<Grant> = Vec::new();
    let mut chosen_set: BTreeSet<Grant> = BTreeSet::new();
    let mut chosen_paths: BTreeSet<PathBuf> = BTreeSet::new();

    let pick = |g: &Grant,
                covered: &mut Vec<bool>,
                chosen: &mut Vec<Grant>,
                chosen_set: &mut BTreeSet<Grant>,
                chosen_paths: &mut BTreeSet<PathBuf>| {
        if chosen_set.insert(g.clone()) {
            chosen.push(g.clone());
            chosen_paths.insert(g.path.clone());
        }
        for &i in &index[g] {
            covered[i] = true;
        }
    };

    // 2. Mandatory picks.
    for w in &work {
        if w.cands.len() == 1 {
            let g = w.cands[0].clone();
            pick(
                &g,
                &mut covered,
                &mut chosen,
                &mut chosen_set,
                &mut chosen_paths,
            );
        }
    }

    // Cost of a candidate (cached reach).
    let mut reach_cache: HashMap<PathBuf, u64> = HashMap::new();
    let mut base_cost = |g: &Grant| -> u64 {
        let reach = *reach_cache.entry(g.path.clone()).or_insert_with(|| {
            if fs.is_dir(&g.path) == Some(true) {
                fs.reach(&g.path).max(1)
            } else {
                1
            }
        });
        cost.weight(g.right).saturating_mul(reach)
    };

    // 3. Greedy by cost / newly covered.
    loop {
        let mut best: Option<(u128, u128, &Grant)> = None; // (num, den)
        for (g, idxs) in &index {
            let newly = idxs.iter().filter(|&&i| !covered[i]).count() as u128;
            if newly == 0 {
                continue;
            }
            let overhead = if chosen_paths.contains(&g.path) {
                0
            } else {
                cost.rule_overhead
            };
            let num = (base_cost(g) + overhead) as u128;
            // num/newly < best.num/best.den  <=>  num*best.den < best.num*newly
            let better = match best {
                None => true,
                Some((bn, bd, _)) => num * bd < bn * newly,
            };
            if better {
                best = Some((num, newly, g));
            }
        }
        let Some((_, _, g)) = best else { break };
        let g = g.clone();
        pick(
            &g,
            &mut covered,
            &mut chosen,
            &mut chosen_set,
            &mut chosen_paths,
        );
    }

    // 4. Prune redundant grants, most expensive first.
    let mut count = vec![0usize; work.len()];
    for g in &chosen {
        for &i in &index[g] {
            count[i] += 1;
        }
    }
    let mut order: Vec<Grant> = chosen.clone();
    order.sort_by(|a, b| base_cost(b).cmp(&base_cost(a)).then_with(|| a.cmp(b)));
    let mut removed: BTreeSet<Grant> = BTreeSet::new();
    for g in order {
        if index[&g].iter().all(|&i| count[i] >= 2) {
            for &i in &index[&g] {
                count[i] -= 1;
            }
            removed.insert(g);
        }
    }
    let mut grants: Vec<Grant> = chosen
        .into_iter()
        .filter(|g| !removed.contains(g))
        .collect();
    grants.sort();
    result.grants = grants;
    result.unmet.sort_by(|a, b| a.need.cmp(&b.need));
    result.splits.sort();
    result
}

/// Filesystem-backed [`FsView`].
pub struct RealFs {
    /// Count real files for `reach` (otherwise a depth heuristic).
    pub estimate: bool,
    memo: RefCell<HashMap<PathBuf, u64>>,
}

/// Counting stops here: beyond it "huge" is all we need to know.
const REACH_CAP: u64 = 5000;

impl RealFs {
    pub fn new(estimate: bool) -> Self {
        RealFs {
            estimate,
            memo: RefCell::new(HashMap::new()),
        }
    }

    fn count(&self, p: &Path) -> u64 {
        if let Some(v) = self.memo.borrow().get(p) {
            return *v;
        }
        let mut total = 0u64;
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                total += 1;
                if total >= REACH_CAP {
                    break;
                }
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    total += self.count(&e.path());
                    if total >= REACH_CAP {
                        total = REACH_CAP;
                        break;
                    }
                }
            }
        }
        self.memo.borrow_mut().insert(p.to_path_buf(), total);
        total
    }
}

impl FsView for RealFs {
    fn is_dir(&self, p: &Path) -> Option<bool> {
        std::fs::metadata(p).ok().map(|m| m.is_dir())
    }

    fn children(&self, p: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn canonical(&self, p: &Path) -> PathBuf {
        canonicalize_lossy(p)
    }

    fn reach(&self, p: &Path) -> u64 {
        if self.estimate {
            self.count(p).max(1)
        } else {
            // Depth heuristic: a directory N levels from the root reaches
            // roughly 4^(6-N) files.
            let depth = p.components().count().saturating_sub(1) as u32;
            4u64.pow(6u32.saturating_sub(depth.min(6)))
        }
    }
}

/// Canonicalize the longest existing prefix of `p` and re-append the rest.
/// `/proc` and `/dev` are left alone: their entries are per-process magic.
pub fn canonicalize_lossy(p: &Path) -> PathBuf {
    if p.starts_with("/proc") || p.starts_with("/dev") {
        return p.to_path_buf();
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            let mut out = c;
            out.extend(tail.iter().rev());
            return out;
        }
        match (
            cur.file_name().map(|n| n.to_os_string()),
            cur.parent().map(|p| p.to_path_buf()),
        ) {
            (Some(n), Some(par)) => {
                tail.push(n);
                cur = par;
            }
            _ => return p.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-memory tree: dirs map to their children; any path listed as a
    /// child but not a key is a file.
    struct MockFs {
        dirs: BTreeMap<PathBuf, Vec<PathBuf>>,
        reach: HashMap<PathBuf, u64>,
    }

    impl MockFs {
        fn new(spec: &[(&str, &[&str])]) -> Self {
            let mut dirs = BTreeMap::new();
            for (d, kids) in spec {
                dirs.insert(PathBuf::from(d), kids.iter().map(PathBuf::from).collect());
            }
            MockFs {
                dirs,
                reach: HashMap::new(),
            }
        }
        fn with_reach(mut self, p: &str, r: u64) -> Self {
            self.reach.insert(p.into(), r);
            self
        }
    }

    impl FsView for MockFs {
        fn is_dir(&self, p: &Path) -> Option<bool> {
            if self.dirs.contains_key(p) {
                return Some(true);
            }
            let is_child = self.dirs.values().any(|k| k.iter().any(|c| c == p));
            is_child.then_some(false)
        }
        fn children(&self, p: &Path) -> Vec<PathBuf> {
            self.dirs.get(p).cloned().unwrap_or_default()
        }
        fn reach(&self, p: &Path) -> u64 {
            if let Some(r) = self.reach.get(p) {
                return *r;
            }
            let kids = self.dirs.get(p).cloned().unwrap_or_default();
            kids.iter()
                .map(|c| {
                    1 + if self.dirs.contains_key(c) {
                        self.reach(c)
                    } else {
                        0
                    }
                })
                .sum::<u64>()
                .max(1)
        }
    }

    fn need(p: &str, r: Right, k: NeedKind, ceil: &str) -> CoverNeed {
        CoverNeed {
            need: Need::new(p, r, k),
            ceiling: ceil.into(),
            split: false,
        }
    }

    fn paths(r: &CoverResult, right: Right) -> Vec<String> {
        r.grants
            .iter()
            .filter(|g| g.right == right)
            .map(|g| g.path.display().to_string())
            .collect()
    }

    fn home_zones() -> Zones {
        let mut z = Zones::default();
        z.add("/home/u", ZoneKind::Broad);
        z.add("/home/u/.ssh", ZoneKind::Secret);
        z
    }

    #[test]
    fn many_files_in_small_dir_collapse_to_the_dir() {
        let kids: Vec<String> = (0..12).map(|i| format!("/p/src/f{i}.rs")).collect();
        let kid_refs: Vec<&str> = kids.iter().map(|s| s.as_str()).collect();
        let fs = MockFs::new(&[("/p", &["/p/src"]), ("/p/src", &kid_refs)]);
        let needs: Vec<_> = kids
            .iter()
            .map(|k| need(k, Right::ReadFile, NeedKind::Exact, "/p"))
            .collect();
        let r = solve(&needs, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::ReadFile), vec!["/p/src"]);
    }

    #[test]
    fn few_files_in_huge_dir_stay_individual() {
        let fs = MockFs::new(&[
            ("/usr", &["/usr/lib"]),
            ("/usr/lib", &["/usr/lib/a.so", "/usr/lib/b.so"]),
        ])
        .with_reach("/usr/lib", 8000)
        .with_reach("/usr", 100_000);
        let needs = vec![
            need("/usr/lib/a.so", Right::ReadFile, NeedKind::Exact, "/usr"),
            need("/usr/lib/b.so", Right::ReadFile, NeedKind::Exact, "/usr"),
        ];
        let r = solve(&needs, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(
            paths(&r, Right::ReadFile),
            vec!["/usr/lib/a.so", "/usr/lib/b.so"]
        );
    }

    #[test]
    fn zones_force_split_instead_of_parent_grant() {
        // Reading two files in $HOME must not become a grant on $HOME even
        // though it would be the cheapest cover.
        let fs = MockFs::new(&[
            ("/home", &["/home/u"]),
            (
                "/home/u",
                &["/home/u/.gitconfig", "/home/u/.ssh", "/home/u/.vimrc"],
            ),
        ]);
        let needs = vec![
            need(
                "/home/u/.gitconfig",
                Right::ReadFile,
                NeedKind::Exact,
                "/home/u/.gitconfig",
            ),
            need(
                "/home/u/.vimrc",
                Right::ReadFile,
                NeedKind::Exact,
                "/home/u/.vimrc",
            ),
        ];
        let r = solve(&needs, &home_zones(), &fs, &CostModel::default());
        assert_eq!(
            paths(&r, Right::ReadFile),
            vec!["/home/u/.gitconfig", "/home/u/.vimrc"]
        );
        assert!(r.unmet.is_empty());
    }

    #[test]
    fn listing_may_span_secret_but_reading_may_not() {
        let fs = MockFs::new(&[
            ("/home", &["/home/u"]),
            ("/home/u", &["/home/u/.ssh", "/home/u/a"]),
        ]);
        let z = {
            let mut z = Zones::default();
            z.add("/home/u/.ssh", ZoneKind::Secret);
            z
        };
        let n = vec![
            need("/home/u", Right::ReadDir, NeedKind::Exact, "/home/u"),
            need("/home/u/a", Right::ReadFile, NeedKind::Exact, "/home/u"),
        ];
        let r = solve(&n, &z, &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::ReadDir), vec!["/home/u"]);
        assert_eq!(paths(&r, Right::ReadFile), vec!["/home/u/a"]);
    }

    #[test]
    fn project_write_splits_around_protected_hooks() {
        let fs = MockFs::new(&[
            ("/h", &["/h/proj"]),
            (
                "/h/proj",
                &["/h/proj/.git", "/h/proj/src", "/h/proj/Cargo.toml"],
            ),
            (
                "/h/proj/.git",
                &[
                    "/h/proj/.git/HEAD",
                    "/h/proj/.git/hooks",
                    "/h/proj/.git/config",
                    "/h/proj/.git/objects",
                ],
            ),
            (
                "/h/proj/.git/hooks",
                &["/h/proj/.git/hooks/pre-commit.sample"],
            ),
            ("/h/proj/.git/objects", &[]),
            ("/h/proj/src", &["/h/proj/src/main.rs"]),
        ]);
        let mut z = Zones::default();
        z.add("/h/proj/.git/hooks", ZoneKind::ProtectedWrite);
        z.add("/h/proj/.git/config", ZoneKind::ProtectedWrite);
        let mut n = vec![
            need("/h/proj", Right::Write, NeedKind::Subtree, "/h/proj"),
            need("/h/proj", Right::ReadFile, NeedKind::Subtree, "/h/proj"),
        ];
        n.iter_mut().for_each(|x| x.split = true);
        let r = solve(&n, &z, &fs, &CostModel::default());
        let w = paths(&r, Right::Write);
        assert_eq!(
            w,
            vec![
                "/h/proj/.git/HEAD",
                "/h/proj/.git/objects",
                "/h/proj/Cargo.toml",
                "/h/proj/src"
            ]
        );
        // Read is not restricted: the whole project, hooks included.
        assert_eq!(paths(&r, Right::ReadFile), vec!["/h/proj"]);
        assert!(!r.splits.is_empty());
        // Invariant: no write grant touches a protected zone.
        for g in r.grants.iter().filter(|g| g.right == Right::Write) {
            assert!(z.blocks(&g.path, Right::Write).is_none(), "{:?}", g);
        }
    }

    #[test]
    fn entry_needs_never_use_the_file_itself() {
        let fs = MockFs::new(&[("/p", &["/p/a"])]);
        let n = vec![need("/p/a", Right::Write, NeedKind::Entry, "/p")];
        let r = solve(&n, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::Write), vec!["/p"]);
    }

    #[test]
    fn create_prefers_file_only_if_it_exists() {
        let mut z = Zones::default();
        z.add("/p/.git/hooks", ZoneKind::ProtectedWrite);
        let fs = MockFs::new(&[
            ("/p", &["/p/Cargo.lock", "/p/.git"]),
            ("/p/.git", &["/p/.git/hooks"]),
            ("/p/.git/hooks", &[]),
        ]);
        let n = vec![
            need("/p/Cargo.lock", Right::Write, NeedKind::Create, "/p"),
            need("/p/new.txt", Right::Write, NeedKind::Create, "/p"),
            need("/p/.git/index.lock", Right::Write, NeedKind::Create, "/p"),
        ];
        let r = solve(&n, &z, &fs, &CostModel::default());
        // Cargo.lock exists -> file rule; the other two have no valid ancestor
        // except /p, which would expose hooks -> unmet.
        assert_eq!(paths(&r, Right::Write), vec!["/p/Cargo.lock"]);
        assert_eq!(r.unmet.len(), 2);
        assert!(r.unmet[0].reason.contains("hooks"));
    }

    #[test]
    fn ceiling_stops_widening() {
        let fs = MockFs::new(&[("/usr", &["/usr/lib"]), ("/usr/lib", &["/usr/lib/a"])]);
        let n = vec![need(
            "/usr/lib/a",
            Right::ReadFile,
            NeedKind::Exact,
            "/usr/lib/a",
        )];
        let r = solve(&n, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::ReadFile), vec!["/usr/lib/a"]);
    }

    #[test]
    fn root_is_never_granted() {
        let fs = MockFs::new(&[("/", &["/x"]), ("/x", &[])]);
        let n = vec![need("/x", Right::Write, NeedKind::Subtree, "/")];
        let r = solve(&n, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::Write), vec!["/x"]);
        assert!(r.grants.iter().all(|g| g.path != Path::new("/")));
    }

    #[test]
    fn pruning_drops_files_under_a_chosen_dir() {
        let fs = MockFs::new(&[("/p", &["/p/s"]), ("/p/s", &["/p/s/a", "/p/s/b"])]);
        let n = vec![
            need("/p/s/a", Right::ReadFile, NeedKind::Exact, "/p"),
            need("/p/s/b", Right::ReadFile, NeedKind::Exact, "/p"),
            need("/p/s", Right::ReadFile, NeedKind::Subtree, "/p"),
        ];
        let r = solve(&n, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(paths(&r, Right::ReadFile), vec!["/p/s"]);
    }

    #[test]
    fn deterministic_under_input_order() {
        let fs = MockFs::new(&[("/p", &["/p/a", "/p/b", "/p/c"]), ("/q", &["/q/a"])]);
        let mut n: Vec<CoverNeed> = ["/p/a", "/p/b", "/p/c", "/q/a"]
            .iter()
            .map(|p| need(p, Right::ReadFile, NeedKind::Exact, "/"))
            .collect();
        let a = solve(&n, &Zones::default(), &fs, &CostModel::default());
        n.reverse();
        let b = solve(&n, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(a.grants, b.grants);
    }

    #[test]
    fn rule_overhead_drives_widening() {
        // 3 files in a 200-file dir: individual rules by default, one dir rule
        // once rules are priced high enough.
        let fs = MockFs::new(&[("/p", &["/p/d"]), ("/p/d", &["/p/d/1", "/p/d/2", "/p/d/3"])])
            .with_reach("/p/d", 200);
        let files = ["/p/d/1", "/p/d/2", "/p/d/3"];
        let reads: Vec<_> = files
            .iter()
            .map(|f| need(f, Right::ReadFile, NeedKind::Exact, "/p"))
            .collect();
        let writes: Vec<_> = files
            .iter()
            .map(|f| need(f, Right::Write, NeedKind::Exact, "/p"))
            .collect();
        let rr = solve(&reads, &Zones::default(), &fs, &CostModel::default());
        let rw = solve(&writes, &Zones::default(), &fs, &CostModel::default());
        assert_eq!(rr.grants.len(), 3);
        assert_eq!(rw.grants.len(), 3);
        let big = CostModel {
            rule_overhead: 2000,
            ..Default::default()
        };
        let rr2 = solve(&reads, &Zones::default(), &fs, &big);
        assert_eq!(paths(&rr2, Right::ReadFile), vec!["/p/d"]);
    }

    #[test]
    fn non_project_subtrees_are_not_split() {
        // A blocked /tmp-style subtree must not degrade into "every child of /tmp".
        let fs = MockFs::new(&[
            ("/t", &["/t/a", "/t/home"]),
            ("/t/home", &["/t/home/.ssh"]),
            ("/t/home/.ssh", &[]),
        ]);
        let mut z = Zones::default();
        z.add("/t/home/.ssh", ZoneKind::Secret);
        let n = vec![need("/t", Right::Write, NeedKind::Subtree, "/t")];
        let r = solve(&n, &z, &fs, &CostModel::default());
        assert!(r.grants.is_empty());
        assert_eq!(r.unmet.len(), 1);
        assert!(r.unmet[0].reason.contains(".ssh"));
    }

    #[test]
    fn mkdir_of_existing_dir_is_dropped_quietly_when_ungrantable() {
        let mut z = Zones::default();
        z.add("/p/.git/hooks", ZoneKind::ProtectedWrite);
        let fs = MockFs::new(&[
            ("/p", &["/p/target", "/p/.git"]),
            ("/p/target", &[]),
            ("/p/.git", &["/p/.git/hooks"]),
            ("/p/.git/hooks", &[]),
        ]);
        let n = vec![
            need("/p/target", Right::Write, NeedKind::Mkdir, "/p"),
            need("/p/newdir", Right::Write, NeedKind::Mkdir, "/p"),
        ];
        let r = solve(&n, &z, &fs, &CostModel::default());
        assert_eq!(r.ignored_mkdirs, 1);
        assert_eq!(r.unmet.len(), 1);
    }

    #[test]
    fn unmet_when_nothing_valid() {
        let fs = MockFs::new(&[("/home", &["/home/u"]), ("/home/u", &["/home/u/.bashrc"])]);
        let mut z = Zones::default();
        z.add("/home/u/.bashrc", ZoneKind::ProtectedWrite);
        let n = vec![need(
            "/home/u/.bashrc",
            Right::Write,
            NeedKind::Exact,
            "/home/u/.bashrc",
        )];
        let r = solve(&n, &z, &fs, &CostModel::default());
        assert!(r.grants.is_empty());
        assert_eq!(r.unmet.len(), 1);
    }
}
