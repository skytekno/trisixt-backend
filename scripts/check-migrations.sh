#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DATABASE_URL:?Set the disposable migration database URL}"
: "${MIGRATION_CONTAINER:?Set the disposable PostgreSQL container ID}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo run --locked -- migrate
snapshot() {
  docker exec "$MIGRATION_CONTAINER" psql -U trisixt -d trisixt_migrations -At \
    -c "SELECT version, description, success, encode(checksum, 'hex') FROM _sqlx_migrations ORDER BY version"
}
snapshot > "$work/first"
cargo run --locked -- migrate
snapshot > "$work/second"
diff -u "$work/first" "$work/second"
expected=$(find migrations -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')
actual=$(docker exec "$MIGRATION_CONTAINER" psql -U trisixt -d trisixt_migrations -At \
  -c 'SELECT count(*) FROM _sqlx_migrations WHERE success')
[[ "$actual" == "$expected" ]]
echo "Applied $actual migrations; repeat invocation preserved the migration ledger."
