#!/bin/bash
# Toy "test suite": the built artifact must be non-empty and sorted.
set -eu
out=$1
[ -s "$out" ] || { echo "empty build output" >&2; exit 1; }
sort -c "$out" || { echo "build output not sorted" >&2; exit 1; }
echo "tests passed: $(wc -l < "$out") lines checked"
