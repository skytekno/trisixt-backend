# MAN-25 routed migration validation — 2026-09-27

Issue: [MAN-25 / C1](https://linear.app/skyholding/issue/MAN-25/c1-routed-sdk-support-for-raw-play-install-referrer-and-bare-migration).
Contract: [SDK_CONFIGURATION.md](../SDK_CONFIGURATION.md).
Base: `69f35478fb65e262e190408fa211e4993ee4bac0`.

## Regression and acceptance scenarios

The original routed handler returned `400 invalid link URL` for the encoded
referrer in the new acceptance test. With input classification before native
host routing, the same request returns the expected link, custom data, tracking,
and persisted attribution. The six tests in `tests/sdk_migration.rs` use the
actual HTTP router and isolated PostgreSQL schemas.

| Scenario | Observed result |
| --- | --- |
| Migrated HTTPS URL, encoded Play referrer, bare slug, hierarchical custom scheme | Exact expected data/link/link ID/tracking and attribution; cached requests create no duplicate link |
| Native host, native-host custom scheme, case/trailing-dot hostname, colliding migration slug | Native link takes precedence |
| Invalid/empty/oversized input, malformed percent escapes, nested/repeated referrer, unsafe scheme, credentials | `400`; complete rows unchanged across eight identity, event, link, and migration tables |
| Missing source, foreign project/host, corrupt cross-project cached link | Empty SDK result; no foreign attribution or link disclosure |
| Active primary versus migration custom host; suspended migration host | Primary resolves natively; migration uses old-path mapping only while active |
| Disabled/auto-disabled source, archived/deleted link, negative/transient cache | Existing valid cache remains usable; unavailable entries return empty SDK data |
| Referrer carrying clipboard token, replay | Canonical identity claim preserved; exactly one open event |
| Local Branch HTTP fixture, query strings, repeated lookup, provider 404/503 | Exact provider query preserved; successful/failed responses cached; repeated calls do not refetch or duplicate links |

The provider fixture uses a separate child test process for endpoint and test-key
configuration, avoiding process-global environment changes during parallel tests.
Existing tests continue to cover Branch/AppsFlyer provider mappings and requests.

## Reproduction and source identity

`scripts/check.sh` passed: formatting, Clippy with warnings denied, configuration
validation, 9 Python recovery tests, 144 Rust tests (0 failed, 0 ignored), and
the dependency audit (397 dependencies). Integration used PostgreSQL 18.6,
Redis 8.10.2, ClickHouse, and pinned source-built MinIO, including the existing
HTTP ingestion/analytics/object-storage E2E test. Final source review and
`git diff --check` passed.

```sh
TEST_COMPOSE_PROJECT=trisixt-man25 KEEP_TEST_STACK=1 \
  CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 scripts/check.sh
```

The local log is `/tmp/man25-check.log`; the original failing regression is
`/tmp/man25-red.log`. These are local artifacts, not committed credentials or
production data. Relevant source SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `src/imports.rs` | `3e5f234b27efae8da9da847fdb955ff1e20ecc9c0afccf266e7d5a00602e6c24` |
| `src/sdk.rs` | `3e39c09848576b47a1eee12314aa2831241f9d227cf2a434a59677ef1a25ce42` |
| `tests/sdk_migration.rs` | `6f06c9d82abbb91f919fd9979a74428929788847c3214a41c8e8e4eeb605fdc5` |

## Acceptance boundary

This establishes backend parser/routing behavior with real local database and
service integration plus deterministic provider fixtures. Actual Android Play
Install Referrer delivery, supported client/device builds, and Branch/AppsFlyer
real-account round trips remain separate acceptance gates. GitHub-hosted checks
are recorded on the pull request for its exact head commit. Release publication
still depends on the repository's release GitHub App configuration; this change
does not configure or deploy it.
