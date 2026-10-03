#!/bin/bash
# Differential test: run the same probe under the Rust launcher (`agentfence run
# --no-record`) and the C launcher (`agentfence-exec`) with the profile produced by
# the demo flow (learn -> synth), and require identical allowed/denied outcomes.
#
#   AGENTFENCE_EXEC=launcher/build/agentfence-exec AGENTFENCE_BIN=target/debug/agentfence \
#     launcher/tests/differential.sh
#   KEEP=1 keeps the scratch dir.  Exit: 0 pass, 1 fail, 77 skipped.
# Everything runs under a scratch dir with a FAKE $HOME; the real home is never touched.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
EXEC=${AGENTFENCE_EXEC:-$ROOT/launcher/build/agentfence-exec}
BIN=${AGENTFENCE_BIN:-}
if [ -z "$BIN" ]; then
  (cd "$ROOT" && cargo build -q -j 2) || exit 1
  BIN=$ROOT/target/debug/agentfence
fi
[ -x "$EXEC" ] || { echo "SKIP: C launcher not built ($EXEC)"; exit 77; }
"$BIN" doctor | grep -q '^landlock: ABI' || { echo "SKIP: Landlock is not available"; exit 77; }
for tool in strace git python3 truncate; do
  command -v $tool >/dev/null || { echo "SKIP: $tool not installed"; exit 77; }
done

WORK=$(mktemp -d) || exit 1
PIDS=()
cleanup() {
  [ ${#PIDS[@]} -gt 0 ] && kill "${PIDS[@]}" 2>/dev/null
  [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/home/.ssh" "$WORK/home/.cargo/bin" "$WORK/home/.cache/probe" "$WORK/home/.cache/other" \
         "$WORK/tmp" "$WORK/proj/run-a" "$WORK/proj/run-b"

# Fake home.
echo "-----BEGIN FAKE KEY-----DO-NOT-LEAK-----END FAKE KEY-----" > "$WORK/home/.ssh/id_ed25519"
echo "# fake bashrc" > "$WORK/home/.bashrc"
printf '[user]\n\tname = Demo\n\temail = demo@example.com\n' > "$WORK/home/.gitconfig"
printf '#!/bin/sh\necho tool\n' > "$WORK/home/.cargo/bin/faketool"; chmod +x "$WORK/home/.cargo/bin/faketool"
echo cached > "$WORK/home/.cache/probe/cached.txt"
echo other > "$WORK/home/.cache/other/o.txt"
# Toy project (a git repo) plus a script to exec. The run-* dirs hold the listener's unix
# sockets; they live in the project because synth refuses to grant a socket under a mktemp
# directory directly below /tmp (the collapsed grant would expose the fake ~/.ssh).
cp -r "$ROOT/demo/toy/." "$WORK/proj/"
cp -r "$ROOT/demo/agents" "$WORK/proj/.agents"
mkdir "$WORK/proj/tools"; printf '#!/bin/bash\necho hello\n' > "$WORK/proj/tools/hello.sh"; chmod +x "$WORK/proj/tools/hello.sh"
export HOME="$WORK/home" TMPDIR="$WORK/tmp" GIT_CONFIG_NOSYSTEM=1
(cd "$WORK/proj" && git init -q && echo '#!/bin/sh' > .git/hooks/sample.sh && git add -A >/dev/null 2>&1 \
   && git -c user.name=d -c user.email=d@d commit -qm init)

# Pristine copies, restored before each launcher's probe run (taken before the sockets exist).
cp -a "$WORK/proj" "$WORK/proj.pre"; cp -a "$WORK/home" "$WORK/home.pre"

# Listeners (outside any sandbox): two TCP ports, two pathname unix sockets, one abstract socket.
ABS_NAME=agentfence-diff-$$
cat > "$WORK/listener.py" <<PY
import socket, select, sys, os
w = sys.argv[1]
socks = []
ports = []
for _ in range(2):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(8); socks.append(s); ports.append(s.getsockname()[1])
for p in (w + "/proj/run-a/ok.sock", w + "/proj/run-b/no.sock"):
    s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen(8); socks.append(s)
s = socket.socket(socket.AF_UNIX); s.bind("\0$ABS_NAME"); s.listen(8); socks.append(s)
open(w + "/ports.tmp", "w").write("%d %d\n" % tuple(ports)); os.rename(w + "/ports.tmp", w + "/ports")
while True:
    for s in select.select(socks, [], [])[0]:
        s.accept()[0].close()
PY
python3 "$WORK/listener.py" "$WORK" & PIDS+=($!)
sleep 600 & OUTSIDE_PID=$!; PIDS+=($!)
for _ in $(seq 100); do [ -e "$WORK/ports" ] && break; sleep 0.1; done
[ -e "$WORK/ports" ] || { echo "FAIL: listener did not start"; exit 1; }
read -r ALLOW_PORT DENY_PORT < "$WORK/ports"
export ALLOW_PORT DENY_PORT ABS_NAME OUTSIDE_PID SOCK_OK="$WORK/proj/run-a/ok.sock" SOCK_NO="$WORK/proj/run-b/no.sock"

reset() {
  rm -rf "${WORK:?}/home"; cp -a "$WORK/home.pre" "$WORK/home"
  # keep run-*: they hold the live listener sockets
  find "${WORK:?}/proj" -mindepth 1 -maxdepth 1 ! -name 'run-*' -exec rm -rf {} +
  cp -a "$WORK/proj.pre/." "$WORK/proj/"
}

echo "== learn + synth (demo flow, plus a probe run covering the benign accesses)"
cd "$WORK/proj" || exit 1
"$BIN" learn --name build -- bash .agents/benign_build.sh >/dev/null 2>&1 || exit 1
"$BIN" learn --name docs  -- bash .agents/benign_docs.sh  >/dev/null 2>&1 || exit 1
MODE=learn "$BIN" learn --name probe -- bash "$HERE/probe.sh" >/dev/null 2>&1 || exit 1
"$BIN" synth >/dev/null 2>"$WORK/synth.log" || { cat "$WORK/synth.log"; exit 1; }
mv "$WORK/proj/.agentfence" "$WORK/af"
head -1 "$WORK/af/profile.rules"
echo "   $(grep -c '^fs' "$WORK/af/profile.rules") fs rules, $(grep -c '^net' "$WORK/af/profile.rules") net rules, $(grep -c '^option' "$WORK/af/profile.rules") options"

run_probe() { # label, command prefix...
  local label=$1; shift
  reset; cd "$WORK/proj" || exit 1
  MODE=full "$@" -- bash "$HERE/probe.sh" > "$WORK/$label.out" 2> "$WORK/$label.err"
  echo "   $label: exit $?, $(wc -l < "$WORK/$label.out") outcomes"
}
echo "== probe under each launcher"
run_probe rust "$BIN" run --no-record --profile "$WORK/af/profile.toml"
run_probe c    "$EXEC" --rules "$WORK/af/profile.rules" --verbose

# Optional (SETPRIV=1): also run util-linux setpriv with the same rules, to document what it lacks.
if [ -n "${SETPRIV:-}" ] && command -v setpriv >/dev/null; then
  reset
  args=(--no-new-privs --landlock-access fs)
  while IFS=$'\t' read -r kind path rights; do
    [ "$kind" = fs ] && [ -e "$path" ] || continue
    r=$(echo "$rights" | tr ',' '\n' | grep -vE '^(resolve_unix|ioctl_dev)$' | tr '_' '-' | paste -sd,)
    [ -n "$r" ] && args+=(--landlock-rule "path-beneath:$r:$path")
  done < "$WORK/af/profile.rules"
  cd "$WORK/proj" && MODE=full setpriv "${args[@]}" bash "$HERE/probe.sh" > "$WORK/setpriv.out" 2> "$WORK/setpriv.err"
  echo "== setpriv (fs rights only) vs Rust: cases that differ"
  paste "$WORK/rust.out" "$WORK/setpriv.out" | awk -F'\t' '$3 != $6 { printf "   %-34s rust=%-6s setpriv=%s\n", $1, $3, $6 }'
  echo
fi

echo
echo "== outcome table (ALLOW = access succeeded)"
printf '%-34s %-4s %-6s %-6s %s\n' CASE KIND RUST C SAME
FAIL=0; NALLOW=0; NDENY=0
paste "$WORK/rust.out" "$WORK/c.out" | while IFS=$'\t' read -r n g r _ _ c; do
  [ "$r" = "$c" ] && same=yes || same=NO
  printf '%-34s %-4s %-6s %-6s %s\n' "$n" "$g" "$r" "$c" "$same"
done
NROWS=$(wc -l < "$WORK/rust.out")
if cmp -s "$WORK/rust.out" "$WORK/c.out"; then
  echo "PASS  outcome vectors identical ($NROWS cases: $(grep -c ALLOW "$WORK/rust.out") allowed, $(grep -c DENY "$WORK/rust.out") denied)"
else
  echo "FAIL  outcome vectors differ"; diff "$WORK/rust.out" "$WORK/c.out"; FAIL=1
fi

# Sanity: the test must actually exercise the sandbox.
expect() { # name, outcome
  if grep -qF "$(printf '%s\t' "$1")" "$WORK/c.out" && grep -F "$(printf '%s\t' "$1")" "$WORK/c.out" | grep -q "	$2\$"; then
    echo "PASS  $1 -> $2"
  else echo "FAIL  expected '$1' -> $2"; FAIL=1; fi
}
[ "$NROWS" -ge 30 ] || { echo "FAIL  fewer than 30 cases ran"; FAIL=1; }
expect 'proj: read file' ALLOW
expect 'net: tcp connect allowed' ALLOW
expect 'unix: connect granted path' ALLOW
expect 'secret: read ~/.ssh key' DENY
expect 'proj: write .git/hooks' DENY
expect 'home: append ~/.bashrc' DENY
expect 'net: tcp connect other port' DENY
expect 'unix: connect abstract' DENY
expect 'signal: to outside process' DENY
grep -q 'warning' "$WORK/c.err" && { echo "note: C launcher warnings:"; grep warning "$WORK/c.err"; }
[ -n "${KEEP:-}" ] && echo "scratch dir kept: $WORK"
exit $FAIL
