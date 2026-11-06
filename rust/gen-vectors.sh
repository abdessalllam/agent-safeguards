#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for generator in rust/*/tests/gen_*.py; do
    echo "running $generator"
    python3 "$generator"
done
