# Testing the Trisixt rewrite and provider options

Prepared 2026-09-19. This is an execution guide, not a report of newly executed tests. Historical results are in [VALIDATION.md](VALIDATION.md); MAN-5's source capture and current local evidence are linked from [the baseline guide](baseline/README.md). The requested capability scope is in [REWRITE_STATUS.md](REWRITE_STATUS.md).

Use this guide to validate the Rust runtime, PostgreSQL 18.6, Redis 8.10.2, ClickHouse or BigQuery through Pub/Sub, MinIO/S3 or GCS, and all retained application capabilities. A release needs evidence for the exact source and image being deployed.

## 1. What counts as valid

Complete these gates in order. Mark each result `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN`. An unavailable provider account is `BLOCKED`, not a pass.

| Gate | Required evidence | What it establishes |
| --- | --- | --- |
| A. Local automation | Full test logs, dependency audit, configuration validation | Native behavior against local services and provider HTTP contracts |
| B. Release image | Image ID/digest, startup and migration smoke logs | The built artifact runs as intended on a fresh database |
| C. Provider acceptance | Actual warehouse rows, object bytes, permissions and failure/recovery results | The deployed provider configuration works with its runtime identity |
| D. Application acceptance | Complete user journeys, capability comparison and client results | Retained business behavior and usable frontend/mobile integrations |
| E. Deployment rehearsal | Data reconciliation, load measurements, restore and rollback results | Readiness for the intended deployment and cutover |

The historical local result is **130 tests passed, zero failed, zero ignored**. Reproduce it for the current candidate; investigate a lower count or any ignored tests. A higher count is normal when tests have been added. Test counts alone do not establish coverage.

### Known gaps to include in the test record

- **Rails parity:** the [2026-09-20 audit](RUST_PARITY_AUDIT.md) records 31 confirmed missing, partial or materially changed behaviors, plus the legacy-data conversion/archive-recovery boundary. Include its per-finding acceptance scenarios in the release record; the existing 130 tests do not cover those contracts sufficiently to establish parity. Prioritize external billing cleanup, SCIM lifecycle, SDK configuration gates and analytics correctness.
- **BigQuery deletion permission:** as inspected on 2026-09-19, [main.tf](../deploy/google/main.tf) grants the runtime `roles/bigquery.dataViewer` and `roles/bigquery.jobUser`. The writer grant belongs to the Pub/Sub service agent, not the runtime. [analytics.rs](../src/providers/analytics.rs) executes `DELETE` for retention and project cleanup, which requires `bigquery.tables.updateData`. Infer that a runtime with only the Terraform grants will fail these operations. Resolve scoped deletion permissions and demonstrate BQ-05/BQ-06 below before declaring BigQuery ready. This is a code/configuration finding, not an observed live-cloud failure. See [BigQuery table permissions](https://docs.cloud.google.com/bigquery/docs/control-access-to-resources-iam#permissions_for_tables_and_views).
- The existing real HTTP test in [end_to_end.rs](../tests/end_to_end.rs) uses **ClickHouse + MinIO**. Changing environment selectors does not turn that test into a BigQuery/GCS test: its fixture explicitly selects those local backends.
- BigQuery and GCS HTTP contract tests do not establish real IAM, token refresh, Pub/Sub export, or GCS access. Terraform validation also does not establish these.
- `/up` proves the web process responds. `/ready` currently queries PostgreSQL only; neither proves worker, Redis, warehouse, storage, or SMTP health.
- Native identifiers and some response contracts differ from Rails. Capability retention is separate from existing-client compatibility and existing-data conversion.

## 2. Prepare the test environment

For local automation, install Docker with Compose, the toolchain from [rust-toolchain.toml](../rust-toolchain.toml), Python 3, Bash, and `cargo-audit`. The Terraform check uses a Docker image; a host Terraform installation is unnecessary for that check. Network access is needed for images, dependencies, provider initialization and advisory data.

```bash
rustup show active-toolchain
rustc --version
docker info
docker compose version
python3 --version
cargo audit --version
# Install only if missing:
# cargo install --locked cargo-audit
```

Run repository commands from its root. Check these default localhost ports are available before running tests:

| Purpose | Ports |
| --- | --- |
| Integration PostgreSQL, Redis, ClickHouse, MinIO | 55436, 56386, 58123, 59000 |
| Image smoke PostgreSQL, HTTP | 55437, 53001 |

The integration runner accepts `TEST_POSTGRES_PORT`, `TEST_REDIS_PORT`, `TEST_CLICKHOUSE_PORT`, and `TEST_S3_PORT`. Image smoke accepts `IMAGE_SMOKE_PG_PORT` and `IMAGE_SMOKE_HTTP_PORT`. A different Compose project name does not prevent a host-port collision.

Use disposable resources throughout this guide. The integration and image-smoke scripts remove their selected Compose projects and volumes on exit. Never point `TEST_DATABASE_URL`, other `TEST_*` URLs, or a test Compose project at an existing deployment. The integration PostgreSQL service uses tmpfs; it is unsuitable for a durable backup or restart-persistence rehearsal.

For staging acceptance, prepare two separate instances, A and B, with projects, owners and restricted members; a fresh empty project; SDK project keys; an agreed UTC test window; and a unique run ID. Use synthetic data and sandbox provider accounts. Include both web and worker processes with matching provider configuration and persistent encryption keys. Record resource names and runtime service-account identity, but exclude tokens, passwords, service-account JSON and sensitive payloads from shareable evidence.

Use the versioned [shared baseline fixtures](testing/BASELINE_FIXTURES.md) for two-owner identity, SDK declarations, fixed event/payment inputs and independent expectations. Extend that contract for the additional restricted-member and empty-project scenarios above. Record the exact fixture version, run ID, source identity and actual provider combination using the [evidence template](testing/EVIDENCE_TEMPLATE.md).

## 3. Run the existing local and image gates

This block runs the same major gates as [CI](../.github/workflows/ci.yml), saves logs outside the repository, uses unique test resource names, and stops at the first failed command. It clears inherited test URLs in a subshell so the runner uses its disposable local services. Choose alternative ports first if needed.

```bash
export TRISIXT_EVIDENCE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trisixt-validation.XXXXXX")"
bash <<'BASH'
set -euo pipefail
export TEST_COMPOSE_PROJECT="trisixt-qa-$(date -u +%Y%m%d%H%M%S)-$$"
export IMAGE_SMOKE_PROJECT="${TEST_COMPOSE_PROJECT}-image"
export IMAGE_NAME="trisixt-backend:${TEST_COMPOSE_PROJECT}"
export KEEP_TEST_STACK=0
unset TEST_DATABASE_URL TEST_REDIS_URL TEST_CLICKHOUSE_URL TEST_S3_ENDPOINT TEST_S3_BUCKET

git status --short --branch > "$TRISIXT_EVIDENCE_DIR/git-status.txt"
if ! git rev-parse --verify HEAD > "$TRISIXT_EVIDENCE_DIR/commit.txt" 2>/dev/null; then
  printf 'UNCOMMITTED: identify this run using source hashes\n' > "$TRISIXT_EVIDENCE_DIR/commit.txt"
fi
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
paths = [Path(p) for p in (
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'Dockerfile', '.dockerignore',
    'docker-compose.yml', 'docker-compose.rust.yml', 'docker-compose.test.yml',
    '.env.example', '.env.rust.example', '.env.test', 'LICENSE', 'ee/LICENSE',
    'bin/setup', 'bin/dev', 'run_clickhouse.sh', 'run_sidekiq.sh')]
for folder in ('src', 'migrations', 'tests', 'scripts', 'deploy', 'docs', '.github/workflows'):
    paths.extend(p for p in Path(folder).rglob('*') if p.is_file()
                 and '.terraform' not in p.parts
                 and not any(s in p.name for s in ('.tfstate', '.tfplan', '.tfvars')))
manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths)) if p.is_file() and not p.is_symlink()}
Path(os.environ['TRISIXT_EVIDENCE_DIR'], 'source-sha256.json').write_text(
    json.dumps(manifest, indent=2) + '\n')
PY
scripts/check.sh 2>&1 | tee "$TRISIXT_EVIDENCE_DIR/check.log"
scripts/validate-config.sh --terraform 2>&1 | tee "$TRISIXT_EVIDENCE_DIR/terraform.log"
docker build --tag "$IMAGE_NAME" . 2>&1 | tee "$TRISIXT_EVIDENCE_DIR/image-build.log"
scripts/image-smoke.sh 2>&1 | tee "$TRISIXT_EVIDENCE_DIR/image-smoke.log"
docker image inspect --format '{{.Id}} {{.Config.User}}' "$IMAGE_NAME" \
  > "$TRISIXT_EVIDENCE_DIR/image-identity.txt"
printf 'All local gates passed. Evidence: %s\n' "$TRISIXT_EVIDENCE_DIR"
BASH
```

Do not edit the candidate during this run. Source hashes include untracked implementation and test files; a commit hash alone would miss them. Before deployment, record the reviewed commit, clean worktree and registry image digest, and ensure the deployed image is the one validated.

Expected results:

- `check.sh`: formatting, warnings-as-errors Clippy, branding, shell syntax and Compose validation pass; every native test, including infrastructure tests, runs; `cargo audit` succeeds without ignored advisories.
- The integration log confirms PostgreSQL **18.6** and Redis **8.10.2** from running services.
- Terraform format, initialization with the checked-in lockfile, and validation pass. This command does not apply infrastructure.
- Image smoke confirms version, non-root UID, fresh migrations, `/up`, `/ready`, and prompt rejection of incomplete BigQuery worker configuration. It does not run complete user journeys inside the image.

### Diagnosing a failure

Keep the failed log and fix or classify the failure before proceeding. Do not turn a failed gate green by skipping tests or excluding advisories.

`scripts/check.sh --unit` is a quicker diagnostic pass that skips ignored infrastructure tests. `scripts/test-all.sh` is an alias for `check.sh`, not an additional independent suite. Neither adds live cloud coverage.

To retain local services while debugging, rerun with a disposable project and `KEEP_TEST_STACK=1`. The runner's environment exports do not survive in your terminal. For a focused database suite, explicitly set its URL:

```bash
TEST_DATABASE_URL=postgresql://trisixt:trisixt@127.0.0.1:55436/trisixt_test \
  cargo test --locked --test analytics -- --include-ignored
# HTTP contract tests; live provider tests remain ignored here:
cargo test --locked --test providers
```

Use the actual port selected for the retained stack. Other suites need their documented environment variables; prefer the full runner for the real ClickHouse/MinIO flow. After collecting evidence, clean up only that disposable project with `docker compose -p YOUR_TEST_PROJECT -f docker-compose.test.yml down --volumes --remove-orphans`. Retained test stacks are not staging environments.

## 4. Test all provider combinations

PostgreSQL 18.6 and Redis 8.10.2 remain common to every combination. Run the same event, query, asset, export and cleanup acceptance cases using separately identified fixtures for each row.

| ID | Analytics | Storage | Existing automated evidence | Additional acceptance required |
| --- | --- | --- | --- | --- |
| M-01 | ClickHouse | MinIO (`s3`) | Local HTTP E2E and real provider tests | Staging image, clients, failures and recovery |
| M-02 | BigQuery via Pub/Sub | MinIO (`s3`) | BigQuery HTTP contracts + separate MinIO tests | Actual cloud export/query/delete with the runtime identity |
| M-03 | ClickHouse | GCS | Real ClickHouse + separate GCS HTTP contracts | Actual GCS access, export, cleanup and token refresh |
| M-04 | BigQuery via Pub/Sub | GCS | Separate provider HTTP contracts | Combined cloud user journey and independent-provider outage recovery |

If AWS S3 is offered in the release, repeat the object/export/cleanup cases against actual AWS S3 as well; MinIO does not validate AWS IAM or deployment networking.

Provider selection is global per runtime configuration, not per tenant and not dual writing. Restart/redeploy both web and worker when selecting another combination. Changing the selector does not copy historical objects or backfill a new warehouse. Use fresh fixtures for this matrix; separately plan and reconcile any real provider migration.

### Configuration examples

Use [the environment example](../.env.rust.example) and [Google deployment notes](../deploy/google/README.md) to prepare an isolated staging configuration. Replace all placeholders. Do not overwrite an existing `.env` just to test another combination.

```dotenv
# BigQuery analytics
ANALYTICS_BACKEND=bigquery
GOOGLE_CLOUD_PROJECT=YOUR_TEST_CLOUD_PROJECT
PUBSUB_TOPIC=projects/YOUR_TEST_CLOUD_PROJECT/topics/trisixt-events
BIGQUERY_DATASET=trisixt
BIGQUERY_TABLE=events
BIGQUERY_LOCATION=US

# Choose GCS storage
STORAGE_BACKEND=gcs
STORAGE_BUCKET=YOUR_PRIVATE_TEST_BUCKET
# Prefer the attached runtime identity. If using a service-account file:
# GCS_CREDENTIALS=/run/secrets/service-account.json
```

For MinIO, use `STORAGE_BACKEND=s3`, its bucket, region and credentials, and the correct endpoint. Host execution uses `AWS_ENDPOINT`; the supplied Docker Compose configuration overrides this with `COMPOSE_AWS_ENDPOINT` or `http://minio:9000`. Plain HTTP is for local test MinIO only. For AWS S3, use the documented regional endpoint and TLS settings.

For live Google tests, remove `PUBSUB_EMULATOR_HOST` and stale `GOOGLE_ACCESS_TOKEN` settings from the actual runtime environment. Emulator mode cannot query BigQuery. Verify the deployed identity rather than relying on an administrator's successful CLI calls. Mount any credential file read-only at a path visible to both containers. The storage loader does not support impersonated-service-account ADC files; use a supported attached identity or service-account file. [Google authentication background](https://docs.cloud.google.com/storage/docs/authentication).

The provided Compose stack reads `.env` through both interpolation and `env_file`. Merely exporting an arbitrary Google variable in the invoking shell does not guarantee it reaches the containers. Likewise, `docker compose --env-file qa.env` changes interpolation inputs but does not replace the service's literal `.env` file. Use a dedicated staging Compose override that supplies the intended environment file/settings and credential mounts to both web and worker, or export configuration when running native processes. Inspect the deployment's effective environment privately and verify redacted settings; do not publish full configuration containing secrets.

## 5. Execute one common live acceptance flow

Run this flow for M-01 through M-04 against the candidate image. The existing [HTTP E2E test](../tests/end_to_end.rs) is the reference for request shapes and assertions.

1. Register a synthetic user with `POST /auth/register` (`email`, `password`; expect 201), log in with `POST /auth/login` (expect 200; response `token`), then create an instance with `POST /api/v1/instances` (`name`; expect 201).
2. Create an isolated project with `POST /api/v1/instances/{instance_id}/projects`, body `{"name":"QA","environment":"test","domain":"qa-RUNID-a.example.test"}` (201). Replace `RUNID` with a unique lowercase run/matrix identifier; use a different domain for B. Domains are globally unique and an instance has only one project per environment, so use fresh instances for each matrix run. Create its SDK key at `POST /api/v1/projects/{project_id}/keys`, body `{"name":"QA SDK"}` (201). Use bearer authorization for management calls. Record the returned project UUID; keep credentials private.
3. Create B under a different instance/owner, not merely another project accessible to A's owner. Confirm A cannot access B's analytics or objects.
4. In a fresh A project, submit the following single event twice using identical `event_id` and `visitor_id`. Set the shell variables below from the actual fixture and save a UTC timestamp inside the query window. Replace the example UUIDs for every new run.

```bash
# BASE_URL, PROJECT_ID, PROJECT_KEY and USER_TOKEN come from your staging fixture.
# Supply them privately in this terminal; do not enable shell tracing.
cat > "$TRISIXT_EVIDENCE_DIR/event.json" <<'JSON'
{"events":[{"event_id":"11111111-1111-4111-8111-111111111111","visitor_id":"22222222-2222-4222-8222-222222222222","event_type":"qa_probe","occurred_at":"REPLACE_WITH_CURRENT_UTC_TIMESTAMP","properties":{"qa_run":"REPLACE_WITH_RUN_ID","source":"acceptance"}}]}
JSON
# Edit the fixture before executing these requests.
for attempt in 1 2; do
  curl --fail-with-body --silent --show-error \
    -H "x-project-key: $PROJECT_KEY" -H 'Content-Type: application/json' \
    --data-binary "@$TRISIXT_EVIDENCE_DIR/event.json" \
    "$BASE_URL/api/v1/sdk/events"
done
```

5. Expect both submissions to succeed, but one canonical event and one logical warehouse event. Run a separate B fixture, then verify A's counts exclude it. Wait for the worker and asynchronous delivery within a deadline agreed before the test; record actual delivery latency.
6. Query `GET /api/v1/projects/{project_id}/analytics?from=...&to=...` with A's bearer token. This is the selected **warehouse** endpoint: expect `total_events=1`, `unique_visitors=1`, and `qa_probe` count 1 for a fresh project containing only this fixture. Use URL-encoded RFC3339 bounds surrounding the event. Empty projects return zero totals. Do not use overview users to count a custom `qa_probe`: custom-only activity is not a countable-user event.
7. Also inspect `/api/v1/projects/{project_id}/analytics/events` and the overview/retention/session endpoints using [analytics parity](parity/ANALYTICS.md). These richer queries use canonical PostgreSQL facts. Their success alone is not evidence of warehouse delivery.
8. Upload/download/delete an object through the application, not just a cloud CLI:

```bash
printf 'Trisixt acceptance object\n' > "$TRISIXT_EVIDENCE_DIR/object.txt"
curl --fail-with-body --silent --show-error -X PUT \
  -H "Authorization: Bearer $USER_TOKEN" \
  --data-binary "@$TRISIXT_EVIDENCE_DIR/object.txt" \
  -o /dev/null -w 'PUT status: %{http_code}\n' \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/objects/qa/probe.txt"
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $USER_TOKEN" \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/objects/qa/probe.txt" \
  -o "$TRISIXT_EVIDENCE_DIR/object-downloaded.txt"
cmp "$TRISIXT_EVIDENCE_DIR/object.txt" "$TRISIXT_EVIDENCE_DIR/object-downloaded.txt"
curl --fail-with-body --silent --show-error -X DELETE \
  -H "Authorization: Bearer $USER_TOKEN" -o /dev/null -w 'DELETE status: %{http_code}\n' \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/objects/qa/probe.txt"
# Expected failure after deletion: inspect the status, do not fail the shell here.
curl --silent --show-error -H "Authorization: Bearer $USER_TOKEN" \
  -o /dev/null -w 'GET after delete: %{http_code}\n' \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/objects/qa/probe.txt"
```

Expect PUT 204, GET 200 with identical bytes and attachment disposition, DELETE 204, then GET 404. A GET without authorization must be 401. Repeat with B's identity and confirm it cannot read or mutate A's object. The bucket path is `projects/{project_id}/qa/probe.txt`.

9. Generate a multi-page links export with `POST /api/v1/projects/{project_id}/exports/links`, poll its returned `status_url`, and download parts through `GET /api/v1/instances/{instance_id}/exports/{export_id}/parts/{part}` (parts start at 0). Reconcile every expected row and total. Verify formula-like values are escaped. Revoke the user's permission during generation and again before download: access must be denied. Test expired exports and worker restart during generation. Usage exports live under the instance's storage namespace; test instance deletion as well as project deletion.
10. Delete a disposable project containing events and objects, inspect its durable cleanup status, and confirm both remote namespaces are eventually empty while B survives. Do not remove the tombstone manually. Follow the delayed-delivery cases below.

## 6. BigQuery and Pub/Sub acceptance

Prerequisites: a test cloud project with billing, the enabled APIs and resources in [deploy/google](../deploy/google/README.md), matching dataset/query location, and the actual application runtime identity. Infrastructure provisioning is a separate operation from `validate-config.sh`; review the Terraform plan before applying it to the test project. The module does not deploy the application.

Confirm the export subscription targets the expected table, uses its schema, and does not silently drop unknown fields. For the supplied module, inspect:

```bash
gcloud pubsub subscriptions describe trisixt-events-bigquery \
  --project="$GOOGLE_CLOUD_PROJECT" --format=json
```

The subscription delivers at least once, so repeated physical rows are possible. Validate distinct event IDs and logical counts rather than asserting one physical row per event. A publish acknowledgement establishes Pub/Sub acceptance, not arrival in BigQuery. [Google BigQuery subscription documentation](https://docs.cloud.google.com/pubsub/docs/bigquery).

Run this GoogleSQL in the BigQuery console after replacing the table, project UUID and run ID. Compare the result to the fixture and to the warehouse endpoint. Keep the query job ID and result as evidence.

```sql
SELECT
  project_id,
  event_type,
  COUNT(*) AS physical_rows,
  COUNT(DISTINCT event_id) AS logical_events,
  COUNT(DISTINCT visitor_id) AS visitors
FROM `YOUR_TEST_CLOUD_PROJECT.trisixt.events`
WHERE project_id = 'YOUR_APP_PROJECT_UUID'
  AND JSON_VALUE(properties, '$.qa_run') = 'YOUR_RUN_ID'
GROUP BY project_id, event_type;
```

| ID | Procedure | Pass condition |
| --- | --- | --- |
| BQ-01 | Run the common flow; inspect rows, query endpoint and subscription metrics | Exact event/visitor/project IDs, UTC timestamp, event type and user properties arrive; logical totals agree; no persistent export backlog |
| BQ-02 | Replay ingestion; separately replay an identical published test message on an isolated topic/table or interrupt the worker around acknowledgement | Retries preserve event identity; logical counts do not increase; record any physical duplicates |
| BQ-03 | Temporarily deny publishing or interrupt provider networking for the test runtime, ingest events, then restore access | Canonical events and pending delivery work survive; failures are visible/redacted; delivery recovers without logical duplication |
| BQ-04 | Break export permission/schema on dedicated test resources after Pub/Sub acceptance, then restore it | Subscription failure/backlog is observable even if the application outbox is acknowledged; all fixture IDs eventually arrive |
| BQ-05 | Seed expired and recent events; run the configured retention job using the runtime identity | Expired warehouse rows are removed before local source cleanup; recent rows and pending deliveries survive; denied DELETE keeps work retryable |
| BQ-06 | Publish an event, delay export, delete its application project, then restore export and allow recurring cleanup to run | Late arrivals are removed; the tombstone remains retryable/reconcilable; unrelated projects are unchanged |
| BQ-07 | Query A using B's user; supply invalid ranges; exercise query-job polling/pagination and a deliberately inadequate query byte budget | No tenant leakage; explicit failures rather than empty success; complete results when allowed; query cost stays within configuration |
| BQ-08 | Keep web/worker running through credential expiry/refresh, then revoke the test identity's access | Refresh works for the deployed credential mode; revoked permissions cause observable failure, not silent success |

Do not count BQ-05/BQ-06 as passed until the known runtime DELETE-permission gap is resolved. Project tombstones reconcile hourly after success; allow for that schedule when defining the deletion observation window. See [cleanup behavior](parity/CLEANUP.md).

For BQ-04/BQ-06, capture both layers: the application outbox and Pub/Sub export state. A drained outbox can coexist with a blocked subscription. When reconciling PostgreSQL, join `analytics_outbox.event_id` to `events.id`; the public deduplication UUID is `events.event_id`, also present in the outbox payload. Test timestamps, Unicode/nested/null properties and malformed messages against the actual table schema; a direct Pub/Sub test message must match the publisher's wire representation, including JSON-encoded `properties`. Reposting the SDK event tests ingestion deduplication; a separate delivery replay is needed to test warehouse deduplication. The operator flush endpoint only retries unprocessed outbox entries and does not replay already processed history.

## 7. GCS and MinIO/S3 acceptance

Run the same cases against each storage backend. Test through the application first, then inspect remote state to prove what happened.

| ID | Procedure | Pass condition |
| --- | --- | --- |
| ST-01 | Run object PUT/GET/DELETE and export steps from the common flow | Exact bytes, correct namespace and download behavior on both backends |
| ST-02 | Test empty content, nested valid keys, missing objects, invalid/traversal keys and boundary sizes | Empty bytes survive; missing object is 404; invalid keys are rejected without an out-of-namespace write |
| ST-03 | Test below/at/above 16 MiB through HTTP; separately test 20 MiB adapter limit | HTTP rejects bodies above its 16 MiB limit; adapter rejects above 20 MiB. Do not confuse the two limits or claim the public API accepts 20 MiB |
| ST-04 | Remove read, write, list or delete access individually in staging; restore it | Calls/jobs report failures, cleanup stays retryable, no success is recorded for an incomplete operation |
| ST-05 | Use B's identity for A's paths; attempt an anonymous bucket read | Application authorization blocks cross-tenant access; private GCS bucket does not permit public reads |
| ST-06 | Delete a project with more than 250 objects and an in-flight upload/export; interrupt and restart the worker | Bounded passes eventually remove the exact namespace; unrelated prefixes survive; deletion does not finish ahead of committed uploads |
| ST-07 | Keep warehouse unavailable while deleting objects, then invert the outage | Independent provider cleanup progresses; failure in one provider does not discard the other's work |
| ST-08 | Let credentials refresh and expire/revoke in the actual runtime | Supported credentials refresh; revocation is visible and does not leak secrets in logs |
| ST-09 | Change storage provider on a separate migration rehearsal | Existing objects are copied and checksummed under an explicit migration plan, or the new environment is clearly empty; selection alone is never counted as migration |

Current limits and namespace handling are in [integrations.rs](../src/integrations.rs) and [storage.rs](../src/providers/storage.rs). Use `curl --path-as-is` for traversal probes so client-side URL normalization does not hide the input being tested. The Terraform GCS bucket enables uniform access and public access prevention; verify the deployed bucket matches this. An administrator's successful `gcloud storage` command is not proof of the runtime service account's access.

## 8. PostgreSQL 18.6, Redis and data migration

| ID | Procedure | Pass condition |
| --- | --- | --- |
| DB-01 | Run local automation and fresh-image smoke; query `SHOW server_version` on staging | Actual server is 18.6; all native migrations complete; schema initialization succeeds |
| DB-02 | Run `trisixt migrate` twice against a dedicated native staging database, then start web and worker | Second migration run is harmless; application reads/writes work; no checksum or partial-migration error |
| DB-03 | Exercise concurrent identity merges/event ingestion, partial updates, session revocation and export deletion races | No deadlock-induced data loss, duplicate canonical events, invalid authorization or partially applied state |
| DB-04 | Restart services using persistent staging volumes; temporarily interrupt PostgreSQL connectivity | Committed data survives, requests fail explicitly during outage, and services recover within the agreed deadline |
| DB-05 | Restore a staging backup into a fresh isolated 18.6 server and run the common flow | Counts, relationships, ledger totals and representative payloads reconcile; measured recovery meets the agreed target |
| DB-06 | Rehearse a cutover from an existing Rails database, if applicable | Explicit ID-to-UUID mapping, transformed schema and full reconciliation; clients use the new identifiers; rollback is demonstrated |
| RD-01 | Inspect `redis-server --version`; inspect worker heartbeat `trisixt:worker:heartbeat`; interrupt/restart Redis and test deployed authentication/TLS if configured | Version is 8.10.2; heartbeat expiry/recovery and outage warnings are observable; events remain durable in PostgreSQL; unrelated host Redis is unchanged |

A PostgreSQL engine upgrade and Rails-to-native schema conversion are separate tasks. The native migrations do not convert a Rails database. For a major-version engine upgrade, rehearse a supported logical dump/restore or `pg_upgrade` workflow and check extensions, roles, locale/collation and indexes. Do not attach an old major-version data directory directly to the new server. Follow [PostgreSQL's upgrade documentation](https://www.postgresql.org/docs/18/upgrading.html).

For an existing deployment, record source version/schema, snapshot/cutover time, write-freeze or change-capture approach, conversion tool version, ID mapping, per-table row counts, foreign-key/orphan checks, tenant memberships, event totals, purchase/subscription amounts and states, and object references. Restore encryption keys through the secret-management process and prove encrypted records remain usable. Compare representative analytics before and after using the same time window and mapped identifiers. A database restore alone does not restore cloud objects or reconcile in-flight provider work.

For a fresh installation with no existing users/data, DB-06 can be `N/A — fresh installation`, with the deployment owner recorded. Do not use that exception for an upgrade of an existing customer deployment.

## 9. Validate every retained capability

The files below are existing native suites, not a claim that every listed staging case is already automated. Use the [parity documents](REWRITE_STATUS.md#capability-mapping) to map each required Rails behavior to a native case and an acceptance result. Execute real browser/mobile journeys with the candidate image for the flows users depend on.

| Area / case ID | Existing suites under `tests/` | Staging acceptance and critical negative cases |
| --- | --- | --- |
| APP-01 Accounts | `accounts.rs` | Register, confirm, reset/change password, invite, TOTP/recovery and refresh rotation; reject expired/reused tokens; revoked sessions lose access; SMTP reaches a test inbox |
| APP-02 Tenants and provisioning | `core_api.rs`, `management.rs`, `mcp.rs`, `operations.rs` | Atomic production/test project provisioning, roles and key lifecycle; no partial provisioning or cross-instance access; repair requires operator authorization |
| APP-03 Links and SDK | `sdk.rs`, `management.rs`, `imports.rs` | Create/open rich links, QR/preview, installed/uninstalled app routing, universal/app links, deferred attribution and identity merge; replay/parallel claims create one logical open; test actual iOS/Android SDKs |
| APP-04 Analytics | `analytics.rs`, `management.rs`, `providers.rs` | Known independent fixture totals, empty states, filters/cursors, timezone boundaries, sessions, mature retention cohorts and immutable attribution; errors and query limits stay explicit |
| APP-05 Billing and quotas | `billing.rs` | Stripe sandbox checkout/portal/webhooks, coupons, plan changes, MAU/quota thresholds and exemptions; duplicates, bad signatures and out-of-order delivery cannot double-charge or change entitlement incorrectly |
| APP-06 Purchases | `purchase_lifecycle.rs`, `enterprise.rs` | Apple/Google sandbox purchase, renew, cancel, refund and reconcile; wrong package/environment and forged callbacks rejected; signed ledger totals agree with provider records |
| APP-07 Messaging | `messaging.rs`, `accounts.rs` | SMTP, FCM and APNs to test recipients/devices, templates, retry, invalid-token retirement and open/read tracking; missing SMTP is visible; worker restart does not silently drop recipients |
| APP-08 Enterprise | `enterprise.rs`, `enterprise_administration.rs`, `oidc.rs` | Default-on feature config, real IdP OIDC/JIT/domain enforcement, SCIM deactivation/revocation and chained audit/export; wrong issuer/audience, revoked access and demoted users denied; test explicit EE-off behavior too |
| APP-09 Domains and imports | `domains.rs`, `imports.rs` | DNS ownership and certificate lifecycle; representative Branch/AppsFlyer/Firebase fixtures, retry and resolution; invalid credentials/ownership never create an active verified domain |
| APP-10 MCP and automation | `mcp.rs` | Real client registration/consent, scoped grants, refresh/revocation and JSON-RPC; invalid redirect URI, expired grants and unauthorized tool calls rejected |
| APP-11 Objects and exports | `exports.rs`, `providers.rs`, `end_to_end.rs` | Complete common flow for every provider combination; paginated totals, formula escaping, authorization during generation/download, expiration and cleanup |
| APP-12 Maintenance | `maintenance.rs`, `cleanup.rs`, `worker.rs`, `operations.rs` | Retention, repair, deletion tombstones, durable retries and supervised workers; restart/outage recovery with pending work; independent storage/warehouse failures |
| APP-13 Packaging and naming | `scripts/check_branding.py`, configuration/image gates | User-visible/configuration naming is Trisixt, native image needs no Ruby/Sidekiq, non-root runtime, original license notices retained |

For APP-04, compute expected values independently of the implementation: use a fixed fixture with countable and custom events, known visitors, UTC/Jakarta boundary timestamps, repeat identities, a signed purchase/refund pair and mature/immature cohorts. Compare exact currency units and denominators, not approximate dashboard appearance. Use [analytics parity](parity/ANALYTICS.md) and [billing parity](parity/BILLING.md) for the declared contracts.

For client compatibility, record frontend build and mobile SDK/OS versions. Compare Rails and Rust with equivalent mapped fixtures and expected side effects; document intentional response/status/ID differences and their client handling. Retained Ruby suites are reference evidence, not automatically runnable Rust acceptance tests.

Exercise supported browsers and iOS/Android installed/uninstalled states. Where the flow exposes a UI (account forms, consent, links, exports), check keyboard operation, screen-reader labels/errors and large text. The backend-only protocol has no visual accessibility gate; its consuming user journeys do.

## 10. Load, recovery and release decision

Agree on targets **before** execution: expected/peak request and event rates, p95/p99 latency, error rate, maximum warehouse lag, maximum queue age, export completion time, recovery-time objective (RTO) and acceptable recovery-point/data-loss objective (RPO). Record the staging resources and data scale. An unmeasured target is `NOT RUN`, not a pass; no production thresholds are implied by this guide.

Replay representative ingestion, analytics, objects and export work at normal, peak and burst load, followed by a sustained run long enough to observe backlog and resource trends. Measure CPU/memory, PostgreSQL connections/locks/slow queries, worker queue age/retries, Pub/Sub backlog, BigQuery errors/bytes billed and object errors. Include quota/429 responses and simultaneous tenants. Pass only if agreed latency/error/lag limits hold, logical events are neither lost nor duplicated, and backlog drains after a burst.

Rehearse worker termination while jobs are leased, PostgreSQL unavailability, provider outages and credential revocation on test resources. Restore service and reconcile all fixture IDs, jobs, objects and purchase totals. Demonstrate a restore to a new environment, and a rollback to the previous validated application/data state. A binary rollback is insufficient if the previous version cannot read the new schema or identifiers. Include queued/in-flight work and persistent encryption keys in recovery planning.

Release only when:

- The exact reviewed candidate passes local and image gates, with complete logs and source/image identity.
- Every supported provider combination passes its required live cases, including BigQuery deletion and delayed export cleanup.
- All required capability and security cases pass; client differences are explicitly handled.
- Existing-data conversion reconciles or the documented fresh-install exception applies.
- Load, backup/restore and rollback meet agreed targets.
- Every failure is resolved and retested, or a noncritical exception has an owner, rationale and deadline. Do not waive tenant isolation, data loss, duplicate financial effects, or inability to perform required retention/deletion as cosmetic issues.

## 11. Test result record

Copy this record for each candidate. Link evidence for individual case IDs; do not replace the historical validation report with an unexecuted checklist.

```text
Run ID / UTC start and finish:
Tester / reviewer:
Commit / dirty-worktree state / source manifest:
Image ID / registry digest / deployed digest:
Environment / PostgreSQL and Redis versions:
Provider matrix row / runtime identity / resource names (no secrets):
Client and SDK versions:
Fixture IDs / time window / independent expected values:
Targets: load, latency, error rate, warehouse lag, RTO, RPO:

Case ID | PASS/FAIL/BLOCKED/NOT RUN/N/A | Expected | Actual | Evidence | Issue/owner
A:
B:
M-01 through M-04 (and AWS S3 if offered):
BQ-01 through BQ-08:
ST-01 through ST-09:
DB-01 through DB-06 / RD-01:
APP-01 through APP-13:
Load / restore / rollback:

Open defects and explicit exceptions:
Cleanup: test resources removed or retained with owner and expiry:
Release decision / reviewer / date:
```

After evidence collection, remove only the test fixtures and resources created for this run. Preserve deletion tombstones until reconciliation is complete. Google table deletion protection and bucket `force_destroy=false` are intentional; do not disable them broadly to clean up a test. Retain the redacted results, query/job IDs and image/source identity with the release record.
