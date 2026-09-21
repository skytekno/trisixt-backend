#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check_branding.py
for script in scripts/*.sh src/google_play_setup.sh bin/setup bin/dev run_clickhouse.sh; do
  bash -n "$script"
done
for compose in docker-compose.yml docker-compose.rust.yml docker-compose.test.yml; do
  docker compose -f "$compose" config --quiet
done
if [[ "${1:-}" == "--terraform" ]]; then
  terraform=(docker run --rm -v "$PWD/deploy/google:/work" -w /work hashicorp/terraform:1.14)
  "${terraform[@]}" fmt -check
  "${terraform[@]}" init -backend=false -input=false -lockfile=readonly
  "${terraform[@]}" validate -no-color
fi
