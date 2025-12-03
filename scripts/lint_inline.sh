#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

echo "Running inline style guards..."

# 1) Forbid indented `use` statements inside functions/blocks (allow only top-level `use`)
violations_use=$(grep -RIn --include='*.rs' '^[[:space:]]\+use[[:space:]]' src || true)
if [[ -n "$violations_use" ]];
then
  echo "Error: found indented 'use' statements (must be at file top-level):"
  echo "$violations_use"
  exit 1
fi

# 2) Forbid inline module bodies in source files, except unit-test modules named `tests`
violations_mod=$(grep -RIn --include='*.rs' '^[[:space:]]*mod[[:space:]]\+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*{' src | grep -v 'mod[[:space:]]\+tests[[:space:]]*{' || true)
if [[ -n "$violations_mod" ]];
then
  echo "Error: found inline module bodies (use separate files). Allowed exception: 'mod tests { ... }' for unit tests."
  echo "$violations_mod"
  exit 1
fi

echo "Inline style guards passed."
