# MAN-5 shared baseline fixture contract

The versioned source is [manifest.v1.json](../../tests/fixtures/baseline/manifest.v1.json).
It contains synthetic data and handwritten expectations for two independently owned
instances and projects. It describes the native Rust API as inspected for MAN-5;
it does not close the remaining parity findings or establish live provider access.
Use the same contract in native integration tests, provider acceptance, client
acceptance and recovery rehearsals. Record which stages were actually executed.

The reusable native loader and two-owner seeder are
[tests/support/baseline.rs](../../tests/support/baseline.rs).
[tests/baseline_contract.rs](../../tests/baseline_contract.rs) exercises configured
SDK authentication, event replay before/after alias merge, owner isolation,
immutable outbox identities, purchase/refund/reversal replay and canonical metrics
against the literal manifest expectations. Its default SDK headers select each
project's declared iOS app. Run it through `scripts/check.sh` to include the
PostgreSQL test; plain `cargo test` leaves that infrastructure test ignored.

## Render and identify a run

[render.py](../../tests/fixtures/baseline/render.py) uses Python's standard library
and writes resolved JSON to stdout. It checks the committed asset hashes, contacts
no service and never seeds a database. For a reproducible reference rendering:

```bash
python3 tests/fixtures/baseline/render.py \
  --run-id man5-reference \
  --anchor 2026-09-18T00:00:00Z \
  > /tmp/trisixt-man5-fixtures-reference.json
```

For a live run, choose a fresh run ID and an anchor at **UTC midnight yesterday**.
Record both once; replay must reuse them. The example anchor is a reference vector,
not a permanently valid live query date: retention and timestamp guards still
apply. Every event and payment lies between anchor + 01:00 and + 04:00. Queries use
the explicit half-open range `[anchor, anchor + 1 day)` and `timezone=UTC`.

Run IDs match `[a-z][a-z0-9-]{0,39}`. Each logical UUID is the first 16 bytes of
`SHA256(UTF8("trisixt-baseline-v1/" + run_id + "/" + logical_key))`, with byte 6
set to `(byte & 0x0f) | 0x80` and byte 8 to `(byte & 0x3f) | 0x80`, giving an RFC
variant UUIDv8. This is fixture identity, never credential generation. Reference
vectors for `man5-reference` are:

| Logical key | UUID |
| --- | --- |
| `owner_a` | `dc5c26cc-d87d-8389-b9e3-fc7f37a7c35e` |
| `project_a` | `5bb1d807-da0c-8766-98d9-3a64712bae02` |
| `event_a_view_alias` | `3b9e3080-6f5a-8d8d-b7e7-236acb486c2f` |

The JSON template has only three token forms: `{{run_id}}`, `{{id:logical_key}}`
and `{{time:seconds_from_anchor}}`. `id_keys` is the closed logical key list.
Resolved output adds `resolved.ids`, `resolved.run_id` and `resolved.anchor_utc`.
The handwritten `expected` object must not be regenerated from runtime responses
or production aggregation code when an assertion fails.

## Provisioning and application order

Use an isolated test database/schema and test-only accounts. Before any live
provider stage, verify that endpoints, cloud project, dataset and bucket belong to
the disposable test environment. This contract does not authorize production
seeding or cleanup. Keep credentials in the harness's transient environment and
omit them from saved JSON, logs and screenshots.

1. Apply native SQLx migrations. Create owners A and B, one owned instance and one
   project each, and fresh access tokens and project SDK keys. A must have no role
   in B; B must have no role in A. Revenue collection and enterprise features must
   be enabled for payment stages. Use deterministic IDs for isolated SQL seeding.
2. For public API provisioning, use `/auth/register`, `/auth/login`,
   `/api/v1/instances`, `/api/v1/instances/{id}/projects`, and
   `/api/v1/projects/{id}/keys`. These routes assign IDs; sending fixture `id`
   fields is not a supported way to choose them. Save a separate mapping from
   logical keys to returned IDs and replace all matching references. Retain
   deterministic SDK `event_id` and caller-supplied `visitor_id` values.
3. Declare each project's iOS, Android and web configuration using its owner token.
   The fixture app IDs, iOS team and Android fingerprint are synthetic. They are
   accepted configuration shapes, not signed device builds or valid store assets.
4. Seed visitors with the specified attributes, create campaigns, then create
   their links. The manifest's `request` objects are the exact request bodies;
   `key`, `id`, `project_id` and explanatory fields are harness metadata.
5. Authenticate A's customer device. SDK authentication may generate a `device_id`;
   record it rather than expecting a deterministic UUID from the public route.
   Seed or set visitor attributes before ingestion so frozen event snapshots are
   predictable. Registration and device authentication themselves add no fixture
   event rows.
6. Submit each project's initial events as one batch, then repeat the event named
   in `event_replays`. Before the optional merge stage, assert initial ledger and
   outbox counts. Provider runners should dispatch and independently confirm the
   initial event IDs in the selected warehouse before proceeding.
7. Apply the A alias merge. The native harness calls
   `trisixt::sdk::merge_visitors(project_a, alias, customer)` with application state.
   There is no standalone public merge endpoint. `visitor_attributes` changes
   profile fields and does not merge two visitors merely because they have equal
   `sdk_identifier` values. Client/deferred-link merge journeys remain in their
   own acceptance suites. Replay the first event again and verify no extra row.
8. Submit payments in listed order, repeating each request once. Assert each
   intermediate A money stage before the next adjustment. Complete B's purchase
   separately. These calls are explicitly SDK-reported, not externally verified.
9. For provider/storage acceptance, upload both committed assets, download and
   compare length and SHA-256, check owner isolation, delete the exact run's keys,
   and verify 404. Record missing provider access as `BLOCKED` or `NOT RUN`.

Do not reseed an existing run and overwrite evidence. Use a new run ID for a new
experiment; use the same run for intentional duplicate/recovery tests. Teardown
must use the harness-owned schema or captured runtime IDs and object keys. Never
use an unscoped `DELETE`, bucket purge, or cloud-project cleanup as fixture cleanup.

## Native request and response contracts

JSON calls send `Content-Type: application/json`. Owner calls use
`Authorization: Bearer <owner token>`; SDK calls use `x-project-key: <project key>`.
When exercising domain routing, also send the selected project's `Host`. Owner
credentials do not replace an SDK key. Tokens and keys are created at runtime.

| Operation | Request | Response assertions |
| --- | --- | --- |
| Platform declaration | `PUT /api/v1/projects/{project}/configurations/{platform}`; matching `sdk_configurations[].request` | 200, project configuration object with saved platform data; foreign owner 403 |
| SDK declaration read | `GET /api/v1/sdk/configurations`; SDK key | 200, saved project configuration; declaration enforcement is still C5 |
| Visitor profile | `POST /api/v1/sdk/visitor_attributes`; existing `visitor_id`, `sdk_identifier`, `attributes` | 200, `visitor_id`, `sdk_identifier`, `attributes`; attributes replace the profile object |
| Device authentication | `POST /api/v1/sdk/authenticate`; `sdk_authentication.request` | 200, matching `visitor_id`, generated `device_id`, `uri_scheme="baseline"`; same vendor/project reuses device and visitor |
| Campaign | `POST /api/v1/projects/{project}/campaigns`; `campaigns[].request` | 201, campaign object with server `id` |
| Link | `POST /api/v1/projects/{project}/links`; `links[].request` | 201, link object with server `id`; retain campaign/data/tracking fields |
| Event batch | `POST /api/v1/sdk/events`; `{"events": [event.request, ...]}` | 200, A `{"accepted":4,"duplicates":0}` or B `{"accepted":2,"duplicates":0}` |
| Single event/replay | `POST /api/v1/sdk/event`; exact original `event.request` | 200, initial `accepted=1,duplicates=0` if not batched; replay `accepted=0,duplicates=1` |
| Reported purchase | `POST /api/v1/sdk/add_payment_event`; `payments[].request` | 200, stable purchase `id`, `verified=false`, `source="sdk_reported"`; BUY replay has `duplicate=true`; adjustment replies need not expose `duplicate` |
| Canonical explorer | `GET /api/v1/projects/{project}/analytics/events?from=...&to=...&include_count=true` | 200, `count=4` for A and `count=2` for B; `data` rows remain within selected project |
| Canonical metrics | `GET /api/v1/projects/{project}/analytics/overview/key-metrics?from=...&to=...&timezone=UTC` | 200, nested `metrics` matching `expected.overview_after_merge_and_payments` |
| Provider dashboard | `GET /api/v1/projects/{project}/analytics?from=...&to=...` | 200 only when configured warehouse works; `total_events`, `unique_visitors`, `events:[{event_type,count}]`; current immutable A visitor count remains 3 after merge (A6 gap) |
| Private object | `PUT`, `GET`, `DELETE /api/v1/projects/{project}/objects/{object_key}`; raw asset bytes for PUT | 204/200/204; GET is `application/octet-stream`, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`; GET after delete 404 |

`EventInput` denies unknown top-level fields. Its fields are `event_id`,
`visitor_id`, `event_type`, `occurred_at` and object-valued `properties`. Do not
invent top-level `app_id`, `platform`, `run_id` or `device_id` fields to make a
planned gate pass. C5 owns any later gate-specific contract changes.

Current source references: [core_api.rs](../../src/core_api.rs),
[sdk.rs](../../src/sdk.rs), [auth.rs](../../src/auth.rs),
[analytics_api.rs](../../src/analytics_api.rs),
[integrations.rs](../../src/integrations.rs),
[purchase_lifecycle.rs](../../src/purchase_lifecycle.rs).

## Independent expected results

| Result | Project A | Project B |
| --- | ---: | ---: |
| Unique event IDs / outbox rows | 4 / 4 | 2 / 2 |
| Event types | view 2, open 1, checkout 1 | view 1, open 1 |
| Original immutable distinct visitor IDs | 3 | 1 |
| Canonical visitors after alias merge | 2 | 1 |
| Canonical views / link views / opens | 2 / 1 / 1 | 1 / 1 / 1 |
| Verified-purchase table rows after all reported calls | 1 | 1 |
| Signed ledger rows after all reported calls | 3 | 1 |
| Net USD cents / units | 2000 / 2 | 700 / 1 |
| Net USD nanos | 20000000000 | 7000000000 |
| Canonical ARPU / ARPPU in cents | 1000 / 2000 | 700 / 700 |

A has an anonymous alias, a customer and a guest. Merging the alias into the
customer leaves two people, without rewriting historical event payload IDs.
`checkout` is a custom event, not an extra person or a purchase. Only A's first
view references a link, hence two views but one link view. B's independent IDs
and owner remain unchanged by A's operations. Zero additional rows are allowed
on exact event and payment replay.

A buys two units at 1000 cents each: 2000 cents. A one-unit refund subtracts 1000,
then reversal adds that same 1000 back. B uses the same product identifier at a
700-cent promotional unit price. One cent is 10,000,000 nanos. SDK `price_cents`
is a unit price and is multiplied by quantity. The canonical overview's `revenue`
and ARPU/ARPPU use cents; `revenue_usd_nanos` is an exact decimal string. Do not
compare these to floating-point dollar totals or combine B's revenue into A.

The non-secret SVG assets have deliberately different dimensions and bytes. Their
lengths and SHA-256 values are committed in the manifest and checked by the
renderer. This covers object identity and byte preservation. It does not validate
image codecs, branding transformations, public caching, or client rendering.

## Provider selectors and evidence boundaries

| Matrix key | `ANALYTICS_BACKEND` | `STORAGE_BACKEND` | Object store |
| --- | --- | --- | --- |
| `clickhouse-minio` | `clickhouse` | `s3` | MinIO |
| `bigquery-minio` | `bigquery` | `s3` | MinIO |
| `clickhouse-gcs` | `clickhouse` | `gcs` | GCS |
| `bigquery-gcs` | `bigquery` | `gcs` | GCS |

Selectors alone provide no provider credentials or resources. BigQuery requires
the configured Pub/Sub path and dataset; its acceptance must observe actual
arrival and IAM behavior. Storage needs the correct test bucket and runtime
identity. MinIO's selector is `s3`, not `minio`. Web and worker processes must use
the same matrix row. Never mutate process-wide selectors concurrently in native
tests; construct per-fixture configuration instead.

The existing [end_to_end.rs](../../tests/end_to_end.rs) explicitly uses
ClickHouse and MinIO, so changing shell selectors does not turn it into a four-way
provider test. MAN-5 establishes fixture inputs and local assertions. Shared live
provider execution, client behavior and restore/replay evidence remain separate
release gates described in [TESTING_GUIDE.md](../TESTING_GUIDE.md).

After alias merge, the canonical PostgreSQL overview expects two A users while
the current warehouse distinct-ID aggregate can still report three. Record the
distinction; A6 owns correction of customer-facing provider counts. Never alter
the fixture to hide the gap or infer successful provider delivery from a working
PostgreSQL explorer. No GeoIP, screen/timezone enrichment, app-configuration gate,
external purchase verification or branding-image gap is closed by this contract.

Every execution record should include the contract version and manifest hash,
run ID and anchor, source identity, image digest when applicable, matrix row,
runtime ID mapping, exact stage and query range, independent expected result,
actual result, pass/fail/blocked status, and remaining gates. Shareable evidence
must exclude tokens, passwords and provider credential contents.
