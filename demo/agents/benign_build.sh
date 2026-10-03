#!/bin/bash
# "Agent" task A: build and test the toy project (stands in for a coding agent).
set -eu
echo "[agent] building"
mkdir -p target
scratch=$(mktemp -d)
for f in src/*.txt; do tr a-z A-Z < "$f" >> "$scratch/all.txt"; done
sort "$scratch/all.txt" > target/app.out
wc -l < target/app.out > target/build.log
git --no-optional-locks status --short > "$scratch/git-status.txt" || true
bash tests/check.sh target/app.out
rm -rf "$scratch"
echo "[agent] build ok ($(cat target/build.log) lines)"
