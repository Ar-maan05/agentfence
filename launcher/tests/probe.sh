#!/bin/bash
# Probe: ~38 accesses; prints "<name>\t<ALLOW|DENY>" per case. Run from the project dir.
# MODE=learn runs only the cases in the "ok" group (what a benign agent does), so the
# synthesized profile permits them. MODE=full runs everything.
# Env: ALLOW_PORT DENY_PORT SOCK_OK SOCK_NO ABS_NAME OUTSIDE_PID MODE (HOME is a fake home)
t() {
  local name=$1 group=$2 cmd=$3 r
  [ "$MODE" = learn ] && [ "$group" != ok ] && return 0
  if ( eval "$cmd" ) >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi
  printf '%s\t%s\t%s\n' "$name" "$group" "$r"
}
UNIX='import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])'

# project
t 'proj: read file'              ok   'cat src/greeting.txt'
t 'proj: list dir'               ok   'ls src'
t 'proj: append to file'         ok   'echo x >> src/notes.txt'
t 'proj: create file'            ok   'echo hi > docs/new.md'
t 'proj: mkdir (subdir)'         ok   'mkdir docs/newdir'
t 'proj: rename in same dir'     ok   'mv docs/new.md docs/renamed.md'
t 'proj: rename across dirs'     ok   'mv docs/renamed.md src/moved.md'
t 'proj: truncate'               ok   'truncate -s 0 src/notes.txt'
t 'proj: unlink'                 ok   'rm src/moved.md'
t 'proj: read .git/config'       ok   'cat .git/config'
t 'proj: exec project script'    ok   './tools/hello.sh'
t 'proj: mkdir new top-level'    bad  'mkdir newtop'
t 'proj: write .git/hooks'       bad  'echo "#!/bin/sh" > .git/hooks/pre-commit'
t 'proj: write .git/config'      bad  'echo "[x]" >> .git/config'
t 'proj: rename into .git/hooks' bad  'echo m > src/m2.txt; mv src/m2.txt .git/hooks/m2'
t 'proj: read .git/hooks'        bad  'cat .git/hooks/sample.sh'
# toolchain
t 'tool: exec ~/.cargo/bin'      ok   '$HOME/.cargo/bin/faketool'
t 'tool: read ~/.cargo/bin'      ok   'cat $HOME/.cargo/bin/faketool'
t 'tool: exec /usr/bin/sort'     ok   'sort </dev/null'
t 'tool: write ~/.cargo/bin'     bad  'echo x >> $HOME/.cargo/bin/faketool'
t 'tool: exec unlearned binary'  bad  '/usr/bin/base64 </dev/null'
# cache and tmp
t 'cache: read'                  ok   'cat $HOME/.cache/probe/cached.txt'
t 'cache: append'                ok   'echo y >> $HOME/.cache/probe/cached.txt'
t 'cache: create'                ok   'echo z > $HOME/.cache/probe/new.txt'
t 'tmp: create+delete'           ok   'f=$(mktemp) && echo a > $f && rm $f'
t 'cache: other dir write'       bad  'echo z > $HOME/.cache/other/x'
t 'tmp: exec created script'     bad  'f=$(mktemp) && printf "#!/bin/sh\n:\n" > $f && chmod +x $f && $f'
# secrets and shell startup
t 'secret: read ~/.ssh key'      bad  'cat $HOME/.ssh/id_ed25519'
t 'secret: list ~/.ssh'          bad  'ls $HOME/.ssh'
t 'secret: write ~/.ssh'         bad  'echo k >> $HOME/.ssh/authorized_keys'
t 'home: read ~/.gitconfig'      ok   'cat $HOME/.gitconfig'
t 'home: read ~/.bashrc'         bad  'cat $HOME/.bashrc'
t 'home: append ~/.bashrc'       bad  'echo "evil" >> $HOME/.bashrc'
t 'home: truncate ~/.bashrc'     bad  'truncate -s 0 $HOME/.bashrc'
# network and unix sockets
t 'net: tcp connect allowed'     ok   'exec 3<>/dev/tcp/127.0.0.1/$ALLOW_PORT'
t 'net: tcp connect other port'  bad  'exec 3<>/dev/tcp/127.0.0.1/$DENY_PORT'
t 'net: tcp bind port 0'         bad  'python3 -c "import socket; socket.socket().bind((\"127.0.0.1\",0))"'
t 'unix: connect granted path'   ok   'python3 -c "$UNIX" $SOCK_OK'
t 'unix: connect other path'     bad  'python3 -c "$UNIX" $SOCK_NO'
t 'unix: connect abstract'       bad  'python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"\\0\"+\"$ABS_NAME\")"'
# signals
t 'signal: to own child'         ok   'sleep 5 & kill -URG $!; wait $!'
t 'signal: to outside process'   bad  'kill -URG $OUTSIDE_PID'
exit 0
