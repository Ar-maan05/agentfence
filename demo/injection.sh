#!/bin/bash
# agentfence end-to-end demo: learn from benign agent runs, then enforce the
# profile against a prompt-injected run.
#
# Everything happens inside a scratch directory with a FAKE $HOME and a FAKE
# private key. Nothing under your real home is read or written.
#
#   demo/injection.sh                  # builds agentfence if needed
#   AGENTFENCE_BIN=/path/to/agentfence demo/injection.sh
#   KEEP=1 demo/injection.sh           # keep the scratch dir for inspection
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
BIN=${AGENTFENCE_BIN:-}
if [ -z "$BIN" ]; then
  (cd "$ROOT" && cargo build -q -j 4) || exit 1
  BIN=$ROOT/target/debug/agentfence
fi

if ! "$BIN" doctor | grep -q '^landlock: ABI'; then
  echo "SKIP: Landlock is not available on this kernel"; exit 77
fi
command -v strace >/dev/null || { echo "SKIP: strace not installed"; exit 77; }
command -v git >/dev/null || { echo "SKIP: git not installed"; exit 77; }

WORK=$(mktemp -d)
[ -z "${KEEP:-}" ] && trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.ssh" "$WORK/tmp" "$WORK/proj"

# Fake home with a fake secret.
echo "-----BEGIN FAKE KEY-----DO-NOT-LEAK-----END FAKE KEY-----" > "$WORK/home/.ssh/id_ed25519"
echo "# fake bashrc" > "$WORK/home/.bashrc"
printf '[user]\n\tname = Demo\n\temail = demo@example.com\n' > "$WORK/home/.gitconfig"
cp "$WORK/home/.bashrc" "$WORK/bashrc.orig"

# Toy project (a git repo).
cp -r "$HERE/toy/." "$WORK/proj/"
cp -r "$HERE/agents" "$WORK/proj/.agents"
export HOME="$WORK/home" TMPDIR="$WORK/tmp"
export GIT_CONFIG_NOSYSTEM=1
(cd "$WORK/proj" && git init -q && git add -A >/dev/null 2>&1 && git -c user.name=d -c user.email=d@d commit -qm init)

# Unprotected control: the same injected run on a throwaway copy.
cp -r "$WORK/proj" "$WORK/ctl-proj"; cp -r "$WORK/home" "$WORK/ctl-home"
echo "== 0. control: injected agent with NO sandbox (throwaway copy)"
(cd "$WORK/ctl-proj" && HOME="$WORK/ctl-home" bash .agents/injected.sh | grep -E '^\[attack\]')

cd "$WORK/proj"
echo
echo "== 1. learn: two benign tasks (build+test, docs)"
"$BIN" learn --name build -- bash .agents/benign_build.sh   || exit 1
"$BIN" learn --name docs  -- bash .agents/benign_docs.sh    || exit 1

echo
echo "== 2. synth: traces -> profile"
"$BIN" synth 2>&1 | grep -vE '^  note:' || exit 1

echo
echo "== 3. run: benign task under enforcement (must still work)"
"$BIN" run -- bash .agents/benign_build.sh; BENIGN=$?
echo "(exit $BENIGN)"

echo
echo "== 4. run: prompt-injected agent under enforcement"
OUT=$("$BIN" run -- bash .agents/injected.sh 2>"$WORK/injected.stderr"); INJ=$?
echo "$OUT"
grep -E 'agentfence: (Landlock|[0-9]+ denied)' "$WORK/injected.stderr"

echo
echo "== 5. report"
"$BIN" report --color "${COLOR:-auto}"

echo
echo "== 6. verdict"
FAIL=0
check() { if eval "$2"; then echo "  PASS  $1"; else echo "  FAIL  $1"; FAIL=1; fi; }
check "benign task still succeeds under the profile"  '[ "$BENIGN" = 0 ]'
check "injected run still completes the real task"    '[ "$INJ" = 0 ] && echo "$OUT" | grep -q "build ok"'
check "no attack succeeded"                           '! echo "$OUT" | grep -q "SUCCEEDED"'
check "fake key was not readable"                     '! echo "$OUT" | grep -q "FAKE KEY"'
check "~/.bashrc unchanged"                           'cmp -s "$WORK/home/.bashrc" "$WORK/bashrc.orig"'
check "no .git/hooks/pre-commit created"              '[ ! -e "$WORK/proj/.git/hooks/pre-commit" ]'
check "control run (no sandbox) was exploitable"      '[ -e "$WORK/ctl-proj/.git/hooks/pre-commit" ]'
[ -n "${KEEP:-}" ] && echo "scratch dir kept: $WORK"
exit $FAIL
