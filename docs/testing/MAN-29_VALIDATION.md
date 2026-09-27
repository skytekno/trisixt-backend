# MAN-29 local validation — 2026-09-27

Issue: [MAN-29 / RUST-C5](https://linear.app/mandays-labs/issue/MAN-29/c5-mandatory-sdk-appplatform-configuration-gate). Contract: [SDK_CONFIGURATION.md](../SDK_CONFIGURATION.md).

The candidate starts from remote `main` at `914ccdb694df1b7d538300f40dd7fc982e6e3e84` and includes setup fix `02dce49`. Local runtime, fixture, and build inputs were captured in `/tmp/trisixt-man29-validation/source-sha256.json`; that manifest's SHA-256 is `b03d77dca684450635083841af26f56c508f842b5afdf27e27421f80192a0e50`. Logs are local artifacts, not committed credentials or production data.

## Results

| Check | Result |
| --- | --- |
| `TEST_COMPOSE_PROJECT=trisixt-man29-validation KEEP_TEST_STACK=1 scripts/check.sh` | PASS: formatting, Clippy with warnings denied, branding/configuration, 9 recovery tests, 138 Rust tests; 0 failed and 0 ignored |
| Integration services | PostgreSQL 18.6, Redis 8.10.2, ClickHouse, and pinned source-built MinIO; real HTTP/warehouse/object-storage E2E passed |
| MAN-29 routed PostgreSQL regressions | 6 tests passed; 20 client routes checked for missing/unconfigured/disabled/foreign declarations; rejected requests leave complete rows unchanged across 22 effect tables |
| Baseline replay | Existing numeric expectations preserved; mixed-platform input now uses homogeneous per-platform requests |
| `scripts/validate-config.sh --terraform` | PASS: formatting, readonly provider-lock initialization, validation |
| `cargo audit --deny warnings` | PASS: 397 dependencies scanned |
| `npm audit --audit-level=high` | PASS: 0 vulnerabilities |
| `rhysd/actionlint:1.7.7` | PASS: no workflow diagnostics |
| `scripts/check-migrations.sh` | PASS: all 33 migrations applied; second invocation preserved ledger/checksums |
| `docker build --tag trisixt-backend:man29-validation .` | PASS: linux/arm64 image |
| `IMAGE_NAME=trisixt-backend:man29-validation IMAGE_SMOKE_PROJECT=trisixt-man29-image scripts/image-smoke.sh` | PASS: version, nonroot execution, fresh migrations, `/up`, `/ready`, rejection of incomplete worker configuration |
| MinIO setup fix | PASS: both images build, healthy server, initialization repeated twice, object upload/readback/delete, pinned versions and nonroot UID verified |
| Independent source review / `git diff --check` | PASS: no unresolved blocking gate findings or whitespace errors |

Image ID: `sha256:255bcb9053c3a2e6320cfb6a399518514b327bdfb8c5be309a3271664b5ff353`. All 79 Docker source inputs stayed unchanged through image build and smoke verification. Detailed logs are under `/tmp/trisixt-man29-validation/`; MinIO setup logs are under `/tmp/trisixt-minio-validation-20260927/`.

## Acceptance boundary

The gate requires enabled configured clients, rejects body/header conflicts before effects, and preserves separately authenticated server SDK and internal calls. Device/deferred-link platform selection, event platform defaults, notification filtering, and reported purchase metadata use the authenticated declaration. Rollout requires configuring each client app and sending matching declarations; bare-key client requests now fail.

This record establishes local candidate behavior. GitHub-hosted checks, registry publication, supported mobile/browser/server client builds, live Google provider accounts, and deployment rehearsal are separate gates. It does not claim a release, deployment, or completion of other parity findings. Release automation still requires its repository-scoped GitHub App configuration.
