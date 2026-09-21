#!/usr/bin/env bash
# Validate the exact release image against a disposable PostgreSQL 18.6 database.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${IMAGE_SMOKE_PROJECT:-trisixt-image-smoke}"
export TEST_POSTGRES_PORT="${IMAGE_SMOKE_PG_PORT:-55437}"
image="${IMAGE_NAME:-trisixt-backend:validation}"
web_name="${COMPOSE_PROJECT_NAME}-web"
compose=(docker compose -f docker-compose.test.yml)
cleanup() {
  status=$?
  if [[ "$status" != 0 ]]; then docker logs "$web_name" --tail=50 2>/dev/null || true; fi
  docker rm -f "$web_name" >/dev/null 2>&1 || true
  docker rm -f "${COMPOSE_PROJECT_NAME}-invalid-worker" >/dev/null 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans
  exit "$status"
}
trap cleanup EXIT
"${compose[@]}" up --detach --wait postgres
docker run --rm "$image" --version
uid=$(docker run --rm --entrypoint id "$image" -u)
[[ "$uid" != 0 ]]
network="${COMPOSE_PROJECT_NAME}_default"
database_url=postgresql://trisixt:trisixt@postgres:5432/trisixt_test
docker run --detach --name "$web_name" --network "$network" \
  -e DATABASE_URL="$database_url" -p "127.0.0.1:${IMAGE_SMOKE_HTTP_PORT:-53001}:3000" "$image" serve >/dev/null
export TRISIXT_SMOKE_HTTP_PORT="${IMAGE_SMOKE_HTTP_PORT:-53001}"
export TRISIXT_SMOKE_IMAGE="$image"
export TRISIXT_SMOKE_NETWORK="$network"
export TRISIXT_SMOKE_DATABASE_URL="$database_url"
python3 - <<'PY'
import json, os, subprocess, time, urllib.error, urllib.request
port=os.environ['TRISIXT_SMOKE_HTTP_PORT']
for attempt in range(60):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/up', timeout=1) as response:
            assert response.status == 200
            assert response.read() == b'ok'
        break
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        time.sleep(0.25)
else:
    raise RuntimeError('release image did not become healthy')
with urllib.request.urlopen(f'http://127.0.0.1:{port}/ready', timeout=5) as response:
    assert response.status == 200
    assert json.load(response)['status'] == 'ready'
command=['docker','run','--rm','--name',os.environ['COMPOSE_PROJECT_NAME']+'-invalid-worker',
         '--network',os.environ['TRISIXT_SMOKE_NETWORK'],
         '-e','DATABASE_URL='+os.environ['TRISIXT_SMOKE_DATABASE_URL'],
         '-e','ANALYTICS_BACKEND=bigquery',os.environ['TRISIXT_SMOKE_IMAGE'],'worker']
result=subprocess.run(command, capture_output=True, text=True, timeout=15)
assert result.returncode != 0, 'invalid worker configuration must fail startup'
assert 'GOOGLE_CLOUD_PROJECT' in result.stderr + result.stdout, result.stderr
print('Release image: non-root, version, migrations, /up, /ready, invalid-worker startup checks passed.')
PY
