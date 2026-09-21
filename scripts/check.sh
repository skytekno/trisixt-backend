#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
scripts/validate-config.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py'
if [[ "${1:-}" == "--unit" ]]; then
  cargo test --locked --all-targets --all-features
else
  scripts/integration.sh
fi
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo 'Security audit not run: install cargo-audit with cargo install --locked cargo-audit.' >&2
  exit 1
fi
