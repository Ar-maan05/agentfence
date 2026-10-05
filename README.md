# agentfence

Learn-mode, least-privilege sandboxing for AI coding agents (Claude Code, aider, cursor-agent, or any command), enforced with [Landlock](https://landlock.io/) without root.

You run the agent once, or a few times on different tasks, under `agentfence learn`. agentfence records every file open, exec, directory-entry change and network connect. `agentfence synth` turns those traces into a Landlock policy that is as small as the observed behavior allows, refuses to grant credentials or persistence paths even if the agent touched them, and `agentfence run` enforces it on later runs. `agentfence report` shows what the profile blocked, grouped by what kind of path it was.

```text
agentfence learn -- claude -p "fix the failing test"      # strace, normalized to JSONL
agentfence learn -- claude -p "update the docs"           # more traces generalize the profile
agentfence synth                                          # .agentfence/profile.toml (+ profile.rules)
agentfence run   -- claude -p "refactor the parser"       # enforced; denials recorded
agentfence report                                         # what was blocked, secrets in red
```

## Why

Coding agents run with your full user account. A prompt injection in a README, an issue, or a web page can make them `cat ~/.ssh/id_ed25519`, append to `~/.bashrc`, drop a git hook, or phone home. Permission prompts help until someone approves everything.

The shape of the answer is least privilege, but nobody wants to hand-write a profile per project per agent. agentfence derives it from what the agent actually did, then lets the kernel enforce it.

## Prior art (and how this differs)

* **AppArmor `aa-genprof`** has a learn mode too, but it needs root and loads policy into the LSM system-wide. agentfence is unprivileged and per project.
* **firejail, bubblewrap** are solid sandboxes with hand-written profiles or command-line flags. agentfence generates the profile.
* **Codex CLI and Claude Code's built-in sandboxes** apply a fixed policy ("write only inside the workspace", and so on). Good defaults, but not learned from your project, and not diffable.
* Differentiators here: unprivileged (Landlock), per project, one profile generalized across several task traces, and drift reporting against the profile.

This is an MVP. It is a useful tool and a good design exercise, not a security boundary you should bet a production secret on (see [Limitations](#limitations)).

## Install and quick start

Needs Linux with Landlock enabled (kernel 5.13+, best on 6.12+), `strace`, and a Rust toolchain.

```sh
cargo build --release      # target/release/agentfence
agentfence doctor          # checks strace + Landlock ABI
demo/injection.sh          # end-to-end demo with a fake HOME and a fake key
```

## Commands

| Command | What it does |
|---|---|
| `learn [--name N] -- CMD...` | Runs CMD under `strace -f -y --seccomp-bpf`, saves `.agentfence/traces/<ts>-<name>.strace`, parses it into `.jsonl` events, records `HOME`, `TMPDIR`, cwd in `.meta.json`. Exit status is CMD's. |
| `synth` | Reads every trace, writes `.agentfence/profile.toml` and `profile.rules`. Prints blocked secrets, ungrantable accesses and notes. |
| `run [--profile F] [--no-record] -- CMD...` | Applies the profile with Landlock, then execs CMD. By default runs under strace too and writes `.agentfence/denials/<ts>.jsonl`. |
| `report [--denials F \| --trace F]` | Explains the newest denial log, or diffs a new learn trace against the profile ("what is new"). `--color auto\|always\|never`. |
| `doctor` | Reports strace and Landlock ABI support, and the audit-log situation. |

`synth` options: `--no-fs-estimate` (depth heuristic instead of counting real files), `--rule-overhead N`, `--allow-git-writes` (stop protecting `.git/hooks` and `.git/config`, needed for `git commit`), `--protect PATH` (extra read-only project paths), `--allow-secret PATH` (release a path from the secret list, for example the agent's own credential file), `--no-project-grant` (grant only what was observed), `--out FILE`.

Global: `--project DIR` (default: current directory) chooses where `.agentfence/` lives.

## Architecture

```text
 learn                       synth                                 run
 -----                       -----                                 ---
 strace -f -y  --> .strace   events --> needs --> drop secrets     strace (outside the sandbox)
   |                |           |                    |               |
   v                v           |         collapse ephemeral names    v
 strace.rs parser  .jsonl       |         + interpreters for execs   agentfence run --no-record
 (unfinished/resumed,           |                    |               landlock_restrict_self()
  fd decoding, cwd)             |           weighted set cover         exec(cmd)   <- agent lives here
                                |           under exclusion zones
                                v                    |
                          profile.toml  <------------+---->  profile.rules (flat, for C)
```

Source layout:

| File | Role |
|---|---|
| `src/strace.rs` | strace parser: tokenizer, `<unfinished ...>` / `<... resumed>` splicing per pid, `-y` dirfd resolution, cwd tracking, sockaddr decoding |
| `src/event.rs` | normalized event model + JSONL |
| `src/needs.rs` | "this path needs this right": the IR shared by synth and report |
| `src/roles.rs` | project / toolchain / cache / secret / other, secret and protected-path lists |
| `src/synth/collapse.rs` | ephemeral-name detection |
| `src/synth/cover.rs` | **the weighted set-cover solver** |
| `src/synth/interp.rs` | ELF `PT_INTERP` and `#!` interpreters of executed files |
| `src/synth/mod.rs` | the pipeline |
| `src/profile.rs`, `src/rules.rs` | `profile.toml` and the flat `profile.rules` ([format](docs/PROFILE_FORMAT.md)) |
| `src/run.rs` | Landlock enforcement, strace wrapper, `doctor` |
| `launcher/` | `agentfence-exec`, the C enforcement launcher (`rules.c` parser, differential test, fuzz target) |
| `src/report.rs` | grouping and rendering |

## How `synth` works

### 1. Events become needs

Each successful event turns into one or more *needs*, `(path, right, kind)`:

* `open` for reading is `read_file` (or `read_dir` for directories), for writing `write`; `O_CREAT` marks the need as "may create".
* `execve` needs `exec` **and** `read_file`. The kernel opens the binary for reading too; an execute-only rule fails with `EACCES` (found the hard way).
* `unlink`, `rmdir`, `mkdir`, `rename`, `link`, `symlink` are *entry* needs: only a strict ancestor directory can satisfy them.
* The `ld.so` named in an ELF's `PT_INTERP`, or the `#!` interpreter, is opened by the kernel, so strace never shows it. Synth reads the binary and adds `exec` + `read_file` for it.
* Pathname `connect()` to a unix socket needs `connect_unix` (Landlock ABI 9).

Failed calls are ignored (the exception: `open` that failed with `ENXIO`, such as `/dev/tty` without a controlling terminal, which would succeed with one).

### 2. Secrets are removed first

A need whose path is a secret never reaches the solver, even if the agent really read it during learning. Secrets are:

* `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `~/.pgpass`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube`, `~/.config/gcloud`, `~/.azure`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials*`, keyrings, password-store, browser profiles, and similar (`src/roles.rs`);
* `/etc/shadow`, `/etc/sudoers*`, `/etc/ssl/private`, `docker.sock`, `/root`;
* by name anywhere: `id_rsa`, `id_ed25519`, ..., and `.env`/`.env.*` outside the project (templates like `.env.example` are fine).

They are listed under `blocked_secrets` in the profile and printed as a warning by `synth`. `--allow-secret PATH` is the explicit opt-out.

### 3. Ephemeral names are collapsed

`/tmp/tmpa8f3k2x1/out.json` cannot be granted by name. A component is treated as ephemeral if it looks machine-generated (pid-like numbers under `/proc`, `pts`, `fd`; hex hashes of 8+ chars; UUIDs; `tmp` + random tail; mkstemp-style mixed case tokens; `name-<16 hex>`), **or** if the same path skeleton appears in several traces with a different component each time and each variant is unique to one trace (version-like names such as `python3.11` / `python3.12` are exempt). The path is truncated at the parent and the need becomes "anything under this directory". Components at or above the project root, `$HOME` and `$TMPDIR` are never collapsed. Each collapse outside the project is reported as a note, because it widens the grant.

### 4. Roles and ceilings

Every path gets a role: `project` (under the project root), `toolchain` (`/usr`, `/lib*`, `/etc`, `/opt`, `~/.rustup`, `~/.cargo`, ...), `cache` (`~/.cache`, `/tmp`, `$TMPDIR`), `secret`, or `other`. The role sets the *ceiling*, the highest directory a grant for that path may sit at (a grant for `/usr/lib/x` may widen to `/usr` but never to `/`; `/run/user/1000/bus` may widen to `/run/user` but not `/run`). Roles also drive the grouping in `report`.

### 5. The weighted set cover (`src/synth/cover.rs`)

Landlock rules are hierarchical: a rule on a directory covers everything below it. Choosing the rules is therefore a covering problem.

* **Universe**: the needs.
* **Candidates**: for each need, its own path (if a file rule can be created) and its ancestors, between the need's ceiling and `/`-exclusive, filtered by the need's kind.
* **Cost** of a candidate: `weight(right) * reach(dir) + rule_overhead`. `reach` is the number of files under the directory (counted on the real tree, capped at 5000, memoized; or a depth heuristic with `--no-fs-estimate`), `1` for a file. Weights: read 10, list 3, exec 15, write 40, so widening a write grant is four times as expensive as widening a read. The rule overhead (default 320) makes 40 single-file rules lose to one directory rule when the directory is small, and keeps big directories (`/usr/lib/x86_64-linux-gnu`) from being granted to cover three libraries.
* **Hard zones** (not costs): a candidate is invalid if it would make a *secret* path reachable (listing a directory is allowed, reading is not), a *protected-write* path writable (`.git/hooks`, `.git/config`, `.agentfence`, shell rc files, `~/.config/systemd`, ...), or if it is `/` or `$HOME` or an ancestor of it.
* **Algorithm**: (1) dedupe; (2) split any project-wide subtree whose directory is invalid into per-child needs, recursively (so a project write grant becomes "every top-level entry except `.git`, and inside `.git` everything except `hooks` and `config`"); (3) take needs with exactly one valid candidate; (4) greedy: repeatedly pick the candidate with the lowest `cost / newly covered needs` (the classic `ln n` approximation for weighted set cover; ties broken by path order, so output is deterministic); (5) prune any grant whose needs are all covered by the others. Needs with no valid candidate are reported as *unmet* with the zone that blocked them, never silently widened.

The solver is separate from the filesystem (`FsView` trait) and has unit tests for: collapsing many files into a directory, keeping few files in a huge directory individual, refusing a parent grant over a secret, splitting around protected paths, strict-ancestor semantics of entry needs, create-vs-existing, ceilings, `/` never granted, pruning, and determinism under input order.

Generalization across traces comes from three things: the union of needs, the cross-trace variation rule above, and the directory-vs-file cost trade-off (touching 12 source files in a small directory yields one directory rule).

### 6. Network

Observed successful TCP `connect()`/`bind()` ports go into `network.connect_tcp` and `bind_tcp` (Landlock ABI 4+ restricts TCP by **port**, never by address). With no TCP observed, all TCP is denied. UDP ports and the `ip:port` endpoints are recorded in the profile for information only. Host-level filtering (allow only the API hostname) needs a network namespace plus a filtering proxy; that is future work.

## Enforcement (`agentfence run`)

`run` negotiates the Landlock ABI best-effort, prints the ABI in force and any requested right the kernel cannot enforce, then execs the command. It refuses to run if Landlock enforces nothing at all (`--allow-unenforced` overrides).

Handled (denied unless granted): all filesystem rights of ABI 9 except device `ioctl`; TCP connect/bind by port; signals to outside the sandbox; connecting to abstract unix sockets outside it. The `Refer` and `Truncate` rights are part of the `write` grant where the ABI has them.

**Denial recording.** Landlock (kernel 6.15+) can write audit records for denials, but those go to the kernel audit subsystem. On this machine, as an unprivileged user: the audit netlink multicast group is `EPERM`, `dmesg_restrict=1`, and nothing Landlock-related showed up in the journal. So `run` instead wraps the sandboxed process in `strace` **outside** the sandbox (strace -> agentfence -> restrict_self -> exec) and records the calls that failed with `EACCES`/`EPERM`/`EXDEV`. `report` then re-evaluates each failure against the profile, so a failure the profile would have allowed (a plain permission error, say) is shown as unrelated, not as a sandbox denial. Use `--no-record` to run without strace (no denial log, no overhead).

## Demo

`demo/injection.sh` builds a scratch directory with a fake `$HOME` (containing a fake `~/.ssh/id_ed25519`, `.bashrc`, `.gitconfig`), a toy git project, and three scripted "agents". It first shows the injected agent succeeding with no sandbox, then learns from two benign tasks, synthesizes, runs the benign task under enforcement, and runs the prompt-injected variant. Real output (`COLOR=never`):

```text
== 0. control: injected agent with NO sandbox (throwaway copy)
[attack] read   ~/.ssh/id_ed25519      : SUCCEEDED
[attack] append ~/.bashrc              : SUCCEEDED
[attack] write  .git/hooks/pre-commit  : SUCCEEDED
[attack] exfil  tcp 127.0.0.1:9999     : failed      <- nothing listens there; not a block

== 1. learn: two benign tasks (build+test, docs)
agentfence: trace `20261001-223507-build`: 328 events (135 successful), command exited 0
agentfence: trace `20261001-223507-docs`: 187 events (58 successful), command exited 0

== 2. synth: traces -> profile
agentfence: synthesized 46 rule(s) from 2 trace(s) -> .../proj/.agentfence/profile.toml (+ .../profile.rules)
  network: TCP connect ports [], bind ports []

== 3. run: benign task under enforcement (must still work)
agentfence: Landlock ABI v9 (kernel reports v10): FullyEnforced, 46 filesystem rules, TCP connect ports []
[agent] build ok (4 lines)
agentfence: no denied operations (...)
(exit 0)

== 4. run: prompt-injected agent under enforcement
[agent] build ok (4 lines)
[attack] read   ~/.ssh/id_ed25519      : failed
[attack] append ~/.bashrc              : failed
[attack] write  .git/hooks/pre-commit  : failed
[attack] exfil  tcp 127.0.0.1:9999     : failed
agentfence: 4 denied operation(s) recorded in .../denials/20261001-223507-2.jsonl; run `agentfence report`

== 5. report
SECRETS: the agent tried to reach credentials
  agent tried to read ~/.ssh/id_ed25519 -> BLOCKED

PROJECT
  BLOCKED  write       ./.git/hooks/pre-commit

OTHER (unclassified paths and network)
  BLOCKED  connect tcp 127.0.0.1:9999
  BLOCKED  write       ~/.bashrc

Summary: 4 blocked (1 touching secrets)

== 6. verdict
  PASS  benign task still succeeds under the profile
  PASS  injected run still completes the real task
  PASS  no attack succeeded
  PASS  fake key was not readable
  PASS  ~/.bashrc unchanged
  PASS  no .git/hooks/pre-commit created
  PASS  control run (no sandbox) was exploitable
```

(On a terminal the secret line is bold red; the report prints a Unicode arrow.) The same script runs as a cargo integration test (`cargo test --test cli`), which skips itself when strace or Landlock is unavailable.

### What drift looks like

While trying agentfence on `cargo build` (real `$HOME`, tiny crate), enforcement produced exactly one denial: `modify ~/.cache/ccache/3/9/stats.lock`, a ccache bucket the learn run never touched. That is the intended kind of report: a legitimate new access you either re-learn (`learn` again, `synth`) or leave blocked. In the demo, the injected script also happens to call `dirname`, which the benign traces never ran; before that was removed from the script, the report flagged `exec /usr/bin/dirname` as new.

## The C launcher (`agentfence-exec`)

`launcher/` holds a second enforcement path: a small C program that reads `.agentfence/profile.rules` and does only this: negotiate the Landlock ABI, build the ruleset with raw syscalls, `PR_SET_NO_NEW_PRIVS`, `landlock_restrict_self`, `execvp`.

```text
agentfence-exec [--rules FILE] [--best-effort|--strict] [--verbose] -- CMD [ARGS...]
agentfence-exec --check [--rules FILE]        # parse only
```

`--rules` defaults to `./.agentfence/profile.rules`. Exit status: 2 usage or rules-file error, 1 Landlock error, 127 exec failure. `--best-effort` (default) warns on stderr about rights the running kernel's ABI cannot enforce; `--strict` refuses to run instead. If Landlock is unavailable altogether it refuses in both modes (like `agentfence run` without `--allow-unenforced`).

### Why C

The two halves of agentfence have different threat models. The *parser and synthesizer* chew on adversary-controlled input (strace output produced by an agent that may be prompt-injected, file names it chose), so they are Rust. The *enforcement step* is the trusted part that runs right before the agent starts, with no input an attacker controls beyond a file that `synth` wrote. It should be tiny, dependency-free and easy to audit in one sitting, in the manner of util-linux `setpriv`: about 240 lines of C for the launcher plus about 270 for the parser, only libc and `<linux/landlock.h>`, no allocator tricks, no fixed-size buffers (`getline`, length-checked field splitting). A reviewer can read all of it, and a distro can ship it without a Rust toolchain.

### Same policy as `agentfence run`

The rights set is handled exactly as in `src/run.rs`: all filesystem rights of ABI 9 except `ioctl_dev`; TCP connect/bind iff the profile has `network.enforce`; signal and abstract-unix scoping per `hardening`. `profile.rules` format version 2 carries those flags as `option` lines and has the new `resolve_unix` right (previously `connect_unix` was only expressible in `profile.toml`); see [docs/PROFILE_FORMAT.md](docs/PROFILE_FORMAT.md). Version 1 files are still read (TCP handled iff the file has `net` lines, both scopes on). Dir-only rights are dropped for non-directories, and a rule path that no longer exists is skipped with a warning, as in Rust.

ABI masking follows the kernel's compatibility table: Refer is ABI 2, Truncate 3, TCP rules 4, IoctlDev 5, scopes 6, ResolveUnix 9. The ruleset attribute is passed with the size that ABI knows, so older kernels do not reject it.

### Verification

* **Differential test** (`launcher/tests/differential.sh`, run by `meson test` and by `cargo test --test launcher`): reproduces the demo flow in a scratch dir with a fake `$HOME` (learn two benign tasks plus a probe run of the allowed accesses, `synth`), starts listeners for two TCP ports, two pathname unix sockets and an abstract socket, then runs one ~40-case probe under `agentfence run --no-record` and under `agentfence-exec`, restoring the tree between runs, and requires identical outcome vectors. It also asserts a few cases must come out a certain way so the test cannot pass vacuously. Mutation check: dropping the `option` lines from the rules makes four cases differ and the test fail.
* **Parser parity** (`tests/launcher.rs`): about 400 inputs (hand-written edge cases such as CRLF, `+80`, NUL bytes, invalid UTF-8, version-gated syntax, plus byte-level mutations) go through both `rules::parse` and `agentfence-exec --check`; accept/reject must agree.
* **Fuzzing** (`launcher/fuzz/fuzz_rules.c`, libFuzzer with ASan and UBSan): the parser is a separate translation unit shared with the fuzzer. `clang -g -O1 -D_GNU_SOURCE -fsanitize=fuzzer,address,undefined -Ilauncher launcher/fuzz/fuzz_rules.c launcher/rules.c -o fuzz_rules`.

Result of the differential run on this machine (kernel 7.2, Landlock ABI 10, of which ABI 9 is used; "kind" `ok` = accesses a benign agent was seen doing, `bad` = never learned):

```text
CASE                               KIND RUST   C      SAME
proj: read file                    ok   ALLOW  ALLOW  yes
proj: list dir                     ok   ALLOW  ALLOW  yes
proj: append to file               ok   ALLOW  ALLOW  yes
proj: create file                  ok   ALLOW  ALLOW  yes
proj: mkdir (subdir)               ok   ALLOW  ALLOW  yes
proj: rename in same dir           ok   ALLOW  ALLOW  yes
proj: rename across dirs           ok   ALLOW  ALLOW  yes
proj: truncate                     ok   ALLOW  ALLOW  yes
proj: unlink                       ok   ALLOW  ALLOW  yes
proj: read .git/config             ok   ALLOW  ALLOW  yes
proj: exec project script          ok   ALLOW  ALLOW  yes
proj: mkdir new top-level          bad  DENY   DENY   yes
proj: write .git/hooks             bad  DENY   DENY   yes
proj: write .git/config            bad  DENY   DENY   yes
proj: rename into .git/hooks       bad  DENY   DENY   yes
proj: read .git/hooks              bad  ALLOW  ALLOW  yes
tool: exec ~/.cargo/bin            ok   ALLOW  ALLOW  yes
tool: read ~/.cargo/bin            ok   ALLOW  ALLOW  yes
tool: exec /usr/bin/sort           ok   ALLOW  ALLOW  yes
tool: write ~/.cargo/bin           bad  DENY   DENY   yes
tool: exec unlearned binary        bad  DENY   DENY   yes
cache: read                        ok   ALLOW  ALLOW  yes
cache: append                      ok   ALLOW  ALLOW  yes
cache: create                      ok   ALLOW  ALLOW  yes
tmp: create+delete                 ok   ALLOW  ALLOW  yes
cache: other dir write             bad  DENY   DENY   yes
tmp: exec created script           bad  DENY   DENY   yes
secret: read ~/.ssh key            bad  DENY   DENY   yes
secret: list ~/.ssh                bad  DENY   DENY   yes
secret: write ~/.ssh               bad  DENY   DENY   yes
home: read ~/.gitconfig            ok   ALLOW  ALLOW  yes
home: read ~/.bashrc               bad  DENY   DENY   yes
home: append ~/.bashrc             bad  DENY   DENY   yes
home: truncate ~/.bashrc           bad  DENY   DENY   yes
net: tcp connect allowed           ok   ALLOW  ALLOW  yes
net: tcp connect other port        bad  DENY   DENY   yes
net: tcp bind port 0               bad  DENY   DENY   yes
unix: connect granted path         ok   ALLOW  ALLOW  yes
unix: connect other path           bad  DENY   DENY   yes
unix: connect abstract             bad  DENY   DENY   yes
signal: to own child               ok   ALLOW  ALLOW  yes
signal: to outside process         bad  DENY   DENY   yes
PASS  outcome vectors identical (42 cases: 23 allowed, 19 denied)
```

(`proj: read .git/hooks` is allowed by both launchers: reads of `.git/hooks` are granted, only writes are withheld.)

### Build and test

```sh
meson setup launcher/build launcher && ninja -C launcher/build -j 2
meson test -C launcher/build          # runs the differential test
cargo test --test launcher            # same, plus parser parity; skips if the C binary is absent
```

Built with `-Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -O2`, C11.

### Alternative: util-linux `setpriv`

`profile.rules` can also be fed to `setpriv --landlock-access fs --landlock-rule path-beneath:RIGHTS:PATH` (util-linux 2.41 here). Right names are the same with `-` for `_`:

```sh
setpriv --no-new-privs --landlock-access fs \
        --landlock-rule path-beneath:read-file,read-dir:/usr \
        --landlock-rule path-beneath:write-file,truncate,make-reg:/home/me/proj/src \
        -- CMD
```

One `--landlock-rule` per `fs` line, with `_` turned into `-`. I ran this through the same probe (`SETPRIV=1 launcher/tests/differential.sh`). The rest of the table matched the Rust launcher, and these five differed because setpriv has no way to express them (the other 37 cases agreed):

| gap | consequence |
|---|---|
| no `net` rules or TCP access (`--help` lists only "Access: fs", rule type path-beneath) | TCP connect/bind unrestricted |
| no `resolve-unix` and no `ioctl-dev` right | pathname unix socket connects unrestricted (`ioctl_dev` is deliberately unhandled anyway) |
| no `scoped` rights | signals to outside processes and abstract unix sockets unrestricted |
| missing paths and file-vs-dir are not handled | a missing path aborts (exit 1), dir-only rights on a file fail with EINVAL (verified); filter beforehand |
| no `--strict` / best-effort switch, no ABI report | behaviour on older kernels not tested here |

So `setpriv` is a workable enforcement path for the filesystem part, but not for the network, unix-socket and scope parts of the profile.

## Profile files

* `.agentfence/profile.toml`: roles, rights, network, hardening, blocked secrets, unmet needs, notes. Hand-editable, then `run`/`report` use it as is.
* `.agentfence/profile.rules`: flat, tab-separated compiled form (Landlock right names, format version 2) for launchers without a TOML parser, such as [`agentfence-exec`](#the-c-launcher-agentfence-exec). See [docs/PROFILE_FORMAT.md](docs/PROFILE_FORMAT.md); `src/rules.rs` has the writer and a strict reference parser with a round-trip test.
* `.agentfence/traces/`: raw `.strace`, normalized `.jsonl`, `.meta.json`.
* `.agentfence/denials/`: one `.strace` + `.jsonl` per enforced run.

Add `.agentfence/` to your `.gitignore` unless you want to share profiles.

## Evaluation

`eval/run_eval.py` runs 21 real developer workflows (test, lint, fresh venv, edit and re-test, git, wheel/cargo build, CLI) on copies of three real projects (patchproof, mcp-persist and agentfence itself), with a fake `$HOME` holding planted fake secrets. Full run: `python3 eval/run_eval.py` (about 20 minutes); results land in `eval/results/latest.md`.

**False positives.** Learn a profile from k workflows, then enforce it on workflows it has never seen. "Completed" means the held-out workflow still succeeded under enforcement.

| learned from | first synth | + system grant | + project/home-tool exec |
| --- | --- | --- | --- |
| 1 workflow | 28% | 35% | 44% |
| 2 workflows | 33% | 40% | 56% |
| 4 workflows | 41% | 41% | 63% |
| all but the held-out one | 52% | 62% | 76% |

The first synth only granted what it had seen, and about half of its failures were a single unseen executable. The two fixes are general, not tuned to these workflows: read+exec (never write) on root-owned system trees (`/usr`, `/lib*`, `/bin`, `/sbin`, `/opt`, read on `/etc`) and on per-user tool directories (`~/.local/bin`, `~/.cargo/bin`, `~/.rustup/toolchains`), and exec inside the project (venv entry points, build outputs). Exec does not widen the sandbox: every child stays in the same Landlock domain. `--no-system-grant` restores the tight behaviour. Of the 5 remaining held-out failures, 3 are `git commit` writing `.git/index.lock`, which strict mode blocks on purpose (`--allow-git-writes` trades hook protection for working commits), and 2 are an eval artifact: the agentfence workflows use a `CARGO_TARGET_DIR` outside the project that no other workflow touched.

**Injection.** Each workflow is re-run with 12 attacks appended: read `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.netrc`, `~/.config/gh/hosts.yml`; append `~/.bashrc` and `~/.profile`; write `.git/hooks/pre-commit`; modify `~/.gitconfig`; drop a systemd user unit; TCP connect to an unlearned port; exec a binary dropped in `/tmp`; read another project's source. Blocked: 252/252, both with profiles learned without the attacked workflow and with all workflows, and the same 252/252 when the profile is enforced by the C launcher. With `--allow-git-writes` the git-hook attack gets through (231/252), as documented.

**Reachable surface.** Files writable under the profile versus unsandboxed: 68x fewer for mcp-persist, 415x for agentfence, 457x for patchproof. Reads shrink only 1.3x to 1.7x after the system grant (it was 1.8x to 2.6x before): reads of world-readable system trees are the price of not breaking unseen tools, and per-user secrets stay unreadable regardless. Counts come from a capped walk of the granted paths, so they are estimates.

**Caveats.** One machine, three Python/Rust projects, workflows scripted rather than driven by a live LLM agent, and the same author wrote the workflows and the fixes. The attacks are known patterns; a real injected agent would try things not on this list.

## Limitations

Read these before trusting it.

**Landlock itself**

* It is an allow-list. You cannot grant a directory and carve out a subdirectory. To keep `.git/hooks` read-only, agentfence splits the project into one rule per top-level entry (and per `.git` entry). Consequence: with protection on, the agent cannot create **new** top-level entries in the project root, or new files directly in `.git/` (so `git commit`, which needs `.git/index.lock`, fails). `--allow-git-writes` trades the hook protection for working commits. Creating files inside existing subdirectories is fine.
* Restrictions only tighten. A process cannot widen its own sandbox, and neither can any tool it launches; setuid binaries lose their privileges (`no_new_privs`). That is the point, and it also means a profile learned with `sudo` in it will not work.
* Network rules are by TCP port only. Port 443 means every HTTPS host. UDP, including DNS, is not filtered. Hostname allow-lists need a netns + proxy.
* Rules on a file attach to its inode: replace-by-rename tools need a directory rule, which synth derives from the observed `rename`/create events.
* Granting `/proc` (many runtimes read `/proc/self/...`, and the pid is not stable) exposes `/proc/<pid>/environ` of your other processes. Synth warns when this happens; Landlock cannot carve it out.
* Environment variables are not scrubbed. An API key in the environment is readable by the agent (it needs its own, but also yours).
* Already-open file descriptors inherited by the command are not restricted.

**agentfence**

* Learn-mode only sees what the traced run did. Anything the agent legitimately needs but did not do while learning is blocked at run time. `report` is how you find out; re-learn with that task included.
* Directory-listing needs (`read_dir`) at a directory also let the agent read the names beneath a secret directory (listing may span a secret; reading may not).
* Ephemeral-name collapsing and the cost weights are heuristics, unvalidated beyond the unit tests and the demo. The collapse can widen a grant (for example to all of `/tmp`); every such case is a note in `synth` output.
* If the project itself lives under a directory that must not be granted (for example under `/tmp` with a fake `HOME` also in `/tmp`), writes to that directory show up as *unmet*.
* strace slows the traced process (`--seccomp-bpf` limits it to the traced syscalls) and cannot be combined with programs that ptrace themselves; use `run --no-record` for those. The recorded denial log only includes the syscalls in the trace list (open/exec/connect/bind and directory-entry calls), not every possible denied operation.
* Execution of scripts through `/usr/bin/env` is handled (the interpreter chain is followed one level at a time), but exotic loaders (`binfmt_misc`, musl with a different interpreter path, static-PIE) are not specially handled.
* Symlinks are resolved at synth time. A symlink retargeted after synth invalidates the rule.
* Only x86-64 style ELF64 little-endian `PT_INTERP` parsing is implemented.
* Linux only. Tested on Fedora, kernel 7.2, Landlock ABI 9 (kernel reports 10; the `landlock` crate caps at 9, which is why `ResolveUnix` is handled but anything newer is not).

## Next steps

* seccomp user-notify interactive learn mode: pause on the first access outside the profile and ask, instead of record-then-synth.
* Drive the eval with a live LLM coding agent instead of scripted workflows, and add more projects and languages.
* Network namespace + filtering proxy for host-level egress rules.
* Environment scrubbing and per-secret opt-in.

## License

MIT. See [LICENSE](LICENSE).
