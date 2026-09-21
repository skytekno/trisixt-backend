#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${TEST_COMPOSE_PROJECT:-trisixt-rewrite-test}"
compose=(docker compose -f docker-compose.test.yml)
cleanup() {
  status=$?
  if [[ "$status" != 0 ]]; then "${compose[@]}" logs --tail=80 || true; fi
  if [[ "${KEEP_TEST_STACK:-0}" != 1 ]]; then "${compose[@]}" down --volumes --remove-orphans; fi
  exit "$status"
}
trap cleanup EXIT
services=(redis clickhouse minio)
if [[ "${TEST_EXTERNAL_POSTGRES:-0}" != 1 ]]; then services+=(postgres); fi
"${compose[@]}" up --detach --build --wait "${services[@]}"
"${compose[@]}" run --rm minio-init
export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgresql://trisixt:trisixt@127.0.0.1:${TEST_POSTGRES_PORT:-55436}/trisixt_test}"
export TEST_REDIS_URL="${TEST_REDIS_URL:-redis://127.0.0.1:${TEST_REDIS_PORT:-56386}/0}"
export TEST_CLICKHOUSE_URL="${TEST_CLICKHOUSE_URL:-http://trisixt:trisixt@127.0.0.1:${TEST_CLICKHOUSE_PORT:-58123}}"
export TEST_S3_ENDPOINT="${TEST_S3_ENDPOINT:-http://127.0.0.1:${TEST_S3_PORT:-59000}}"
export AWS_ENDPOINT="$TEST_S3_ENDPOINT"
export TEST_S3_BUCKET="${TEST_S3_BUCKET:-trisixt}"
export AWS_ACCESS_KEY_ID=trisixt
export AWS_SECRET_ACCESS_KEY=trisixt-test-secret
export AWS_ALLOW_HTTP=true
export AWS_REGION=us-east-1
export TRISIXT_ENCRYPTION_KEY="${TRISIXT_ENCRYPTION_KEY:-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=}"
if [[ "${TEST_EXTERNAL_POSTGRES:-0}" == 1 ]]; then
  : "${TEST_POSTGRES_CONTAINER:?Set the GitHub PostgreSQL service container ID}"
  docker exec "$TEST_POSTGRES_CONTAINER" psql -U trisixt -d trisixt_test -Atc 'SHOW server_version' | grep '^18\.6'
else
  "${compose[@]}" exec -T postgres psql -U trisixt -d trisixt_test -Atc 'SHOW server_version' | grep '^18\.6'
fi
"${compose[@]}" exec -T redis redis-server --version | grep 'v=8\.10\.2'
cargo test --locked --all-targets --all-features -- --include-ignored
