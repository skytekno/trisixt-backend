# Gap-closure evidence record

Copy this template for each issue and each actual provider/client run. Keep the
record with the tested source. Store large logs and screenshots outside the
source archive, recording their SHA-256 hashes here. Do not record credentials,
tokens, connection strings, real customer data, or unredacted provider responses.

## Identity

- Linear issue / audit finding:
- Operator and UTC start/end:
- Result: `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN` (never treat the last two as a pass).
- Git commit and branch; dirty files at start/end:
- Recovery manifest path and `source_sha256` for an uncommitted checkout:
- Fixture contract version and manifest SHA-256:
- Run ID and UTC anchor (keep the rendered, redacted fixture manifest):
- Candidate OCI image digest, platform and build-input source identity:
  `NOT_BUILT` if this run did not build/test a candidate. A mutable tag or a
  historic image digest is not proof that an image contains the tested source.
- PostgreSQL / Redis versions observed from the running services:
- Analytics selector (`clickhouse` or `bigquery`):
- Storage selector (`s3` for MinIO, or `gcs`):
- Isolated infrastructure identifiers and client/SDK build identifiers:

## Reproduction and result

| Scenario / fixture phase | Exact command or request | Independent expectation | Actual result | Evidence path and SHA-256 |
|---|---|---|---|---|
| Fresh migration and repeat migration | | | | |
| Configured SDK request | | | | |
| Primary event batch and exact replay | | | | |
| Cross-tenant read/write denial | | | | |
| Alias merge; canonical and immutable counts | | | | |
| Purchase, refund and reversal | | | | |
| Asset upload, hash check and deletion | | | | |
| Provider failure, retry and recovery | | | | |

Use the fixed values in `tests/fixtures/baseline/manifest.v1.json` as the numerical
oracle. Expected results must not be calculated by calling application analytics
or copying actual API results. Preserve the distinction between pre-payment
events, payment ledger effects, post-merge canonical identity, and immutable
warehouse rows. Record the phase and query interval alongside every count.

## Provider and release boundaries

| Actual combination | Status | Evidence |
|---|---|---|
| ClickHouse + MinIO (`clickhouse` / `s3`) | NOT_RUN | |
| BigQuery/Pub/Sub + MinIO (`bigquery` / `s3`) | NOT_RUN | |
| ClickHouse + GCS (`clickhouse` / `gcs`) | NOT_RUN | |
| BigQuery/Pub/Sub + GCS (`bigquery` / `gcs`) | NOT_RUN | |

Record direct warehouse arrival/deduplication and object byte hashes separately
from the application response. A successful PostgreSQL-backed API query or
`/ready` response does not establish cloud delivery. Local mock transport tests
do not establish real IAM, SDK compatibility, device delivery or IdP behavior.

- Exact tests passed / failed / ignored; exit codes:
- Blockers, unresolved acceptance criteria and follow-up issue links:
- Cleanup performed; unrelated services/volumes preserved:
- Reviewer and review scope:
- Rollback/recovery evidence (if relevant):

Closing an individual finding requires its own acceptance evidence. Closing the
fresh release also requires all planned findings, live provider/client gates,
load, recovery and deployment checks. M1 legacy Rails conversion remains deferred.
