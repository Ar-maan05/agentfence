#!/bin/bash
# "Agent" task B: regenerate the docs index (a different task, different temp names).
set -eu
echo "[agent] writing docs"
mkdir -p docs
tmp=$(mktemp)
grep -h . src/*.txt | sed 's/^/- /' > "$tmp"
{ echo "# Index"; cat "$tmp"; } > docs/index.md
rm -f "$tmp"
echo "[agent] docs ok ($(wc -l < docs/index.md) lines)"
