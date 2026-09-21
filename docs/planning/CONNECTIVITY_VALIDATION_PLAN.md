# Connectivity closure and release validation proposal

Planning only; no implementation, tests, or cloud changes performed. Inputs: `docs/RUST_PARITY_AUDIT.md`, `docs/audit/CONNECTIVITY_FINDINGS.md`, current `scripts/check.sh`, `scripts/integration.sh`, `tests/end_to_end.rs`, `tests/providers.rs`, and `docs/TESTING_GUIDE.md`. One engineer, fresh Rust installation first; legacy Rails data/asset conversion (M1) is deferred. Native backup/restore and recovery remain required. Estimates below are engineering effort, include focused regression tests, exclude waiting for credentials/devices and shared release rehearsal; they are ranges rather than calendar commitments.

## Recommended sequence and compact PR packages

Prepare isolated provider resources and client fixtures in the first planning week, while closing the highest-risk native gates. C5 first; then C1 and C2; then C4; then C3 in three small PRs. Domain compensation follows its explicit decision. Independent packages may be reordered around external access, but this plan assumes no parallel engineering capacity.

### P-C5 — Enforce the declared SDK application contract (1–2 engineer-days)

Source homes: `src/auth.rs` (`SdkProject`), affected SDK extraction/body validation in `src/sdk.rs`, shared fixtures in `tests/support/mod.rs`; regression suite `tests/sdk.rs`. Update request examples in `docs/TESTING_GUIDE.md`, native SDK samples and any API schema.

Work: define one normalized SDK declaration contract per mobile/web/desktop family. Require the declarations and configured/enabled app needed for that family before serving SDK configuration or writing identity/events. Reject missing/unconfigured app state as well as explicit disabled state. Propagate the authenticated platform/identity so a conflicting body cannot bypass the declaration. Keep genuine server-SDK/API-key and internal delegation contracts distinct; audit every `SdkProject` extraction site. This restores a configuration gate, not cryptographic app attestation.

New acceptance tests through the router: all declarations omitted; platform only; identifier only; unsupported platform; wrong/missing configured package/bundle/domain; absent config row; enabled=false; body/header disagreement; valid native/web declarations; origin/identifier disagreement; revoked project key. Negative requests create no visitor/device/event/link side effects. Existing declared-identifier/domain tests must stay green. Exercise server SDK and trusted internal delegation to catch accidental regressions. Update all SDK fixture projects to be explicitly configured; do not relax checks just to retain old tests.

Dependency: settle the native client contract and supported platform families at the start. No cloud credentials needed for regression tests. Closure evidence: routed denial/success table plus a real supported client making authenticated calls.

### P-C1 — Connect raw migration inputs to the SDK resolver (0.5–1 engineer-day)

Source homes: `src/sdk.rs::resolve`, `src/imports.rs::resolve_sdk`; tests `tests/sdk.rs`, `tests/imports.rs`.

Work: classify supported input shapes before an HTTP URL parse becomes mandatory, while preserving tenant/host ownership, safe schemes and native link precedence. Reuse the existing import helper, preserve provider query/referrer tracking, and keep documented default/disabled-source behavior. Define invalid/ambiguous inputs explicitly.

New acceptance: POST the actual `/api/v1/sdk/data_for_device_and_url` route for native URL, migrated HTTPS URL, Branch percent-encoded `~referring_link`, bare slug and supported custom scheme. Assert exact returned link/data/tracking and resulting attribution, not just HTTP 200. Add empty/malformed/overlong referrer, nested invalid URL, unrecognized key, wrong-project source, foreign unconfigured host, cached resolved row, archived/deleted target, provider 404/transient failure and replay. No caller may materialize a source in another project. One direct helper test is insufficient.

Dependencies: P-C5 fixture declarations; provider fixtures can be mocked for deterministic routed tests. Real Android Play Install Referrer delivery is a separate client/platform gate; Branch/AppsFlyer real-account round trips are a separate credential gate, not needed to prove parser integration.

### P-C2 — Delegate MCP rich searches to native search handlers (0.5–1 engineer-day)

Source homes: `src/mcp.rs` gateway/RPC/schema, reuse `src/management.rs` search handlers; tests `tests/mcp.rs` and `tests/management.rs`.

Work: preserve structured JSON search arguments and route to existing POST search handlers (or a shared typed search service), retaining MCP authorization and scope checks. Expose the chosen native response contract and tool schema. Do not duplicate SQL/search logic in MCP.

New acceptance: same fixtures queried via management, MCP REST and JSON-RPC tools have identical entity sets/metrics for term, campaign, sdk-generated, active/archive, tags/ads platform, date/platform, sort direction and pagination. Include zero-activity rows, empty result, malformed filter and stable ties across pages; assert filters change the result. Test links and campaigns independently. Read-scoped token may search but cannot mutate; revoked/ungranted/cross-project token is denied. Keep existing OAuth/PKCE/resource/refresh replay tests green.

Dependencies: management search semantics and shared metrics are owned by the analytics workstream; this package can wire the correct path before deeper analytics corrections, but final metrics acceptance follows those fixes. No external credentials needed.

### P-C4 — Restore project clipboard activity without requiring a read (0.5–1 engineer-day)

Source homes: `src/public_links.rs` eligible copy-enabled click/render path, `src/sdk.rs::clipboard_status`, optional additive native SQL migration; tests `tests/sdk.rs`, public-flow fixtures in `tests/imports.rs`.

Work: add the tokenless project activity result while preserving the existing optional token availability check under an explicit contract. Stamp only eligible copy-enabled public activity; use the Rails 48-hour activity TTL as the reference unless deliberately changed. Prefer a durable timestamp/qualified click field in PostgreSQL to adding a mandatory new Redis data dependency. Ensure the stamp records eligibility rather than treating every click as clipboard activity.

New acceptance: fresh project=false; eligible copy-enabled mobile preview=true; unrelated project remains false; non-copy/desktop-ineligible click does not activate; 48-hour boundary expiry via controlled time; concurrent clicks preserve newest activity; restart does not lose a still-valid durable marker. Token validation/consume/replay tests continue to pass. Real iOS/browser test proves the client can check activity without first reading clipboard; the result is a hint, not permission to bypass OS privacy prompts.

Dependencies: P-C5 declaration contract and a chosen response shape for updated clients. No live provider dependency.

### P-C3a — Add asset metadata, provider-backed bytes and safe public image delivery (1.5–2.5 engineer-days)

Source homes: new focused `src/assets.rs` (proposed), additive `migrations/`, `src/providers/storage.rs`, route composition, configuration; new `tests/assets.rs` (proposed).

Work: asset metadata binds immutable object key, owner scope, content type/size/hash and lifecycle state; store bytes through selected GCS/S3 adapter. Define an anonymous read path for explicitly published image assets with correct image Content-Type, caching/ETag and nosniff. Keep private generic object endpoints private. Decide image formats, actual-byte validation, size/dimension limits and anonymous quick-link ownership/TTL/rate budget before implementation; suggested first scope is raster PNG/JPEG/WebP, no arbitrary active content. This is a native attachment model, not a Rails ActiveStorage emulation layer.

New acceptance: accepted image bytes re-download exactly; wrong MIME/bytes, unsupported format, malformed/empty file, excessive dimensions and below/at/above limits reject; tenant cannot bind/read/mutate another tenant's unpublished asset; private export/object is never reachable via public image path; public delivery only exposes published asset; removed asset returns 404; upload failure has explicit retryable/failed state and no falsely published binding. Test meaningful limits rather than copying existing generic 16 MiB HTTP/20 MiB adapter limits into an image contract by accident.

Dependency: agree image/quick-link lifecycle contract. Pure and in-memory tests first, MinIO and GCS live bytes/public-render checks later. No legacy asset conversion for first fresh installation.

### P-C3b — Integrate attachments with link and branding APIs (1–2 engineer-days)

Source homes: `src/core_api.rs`, `src/automation.rs`, `src/public_links.rs`, `src/domains.rs`, shared asset module, `tests/assets.rs`; frontend/mobile/server SDK request samples.

Work: attach/upload, replace, explicit removal and external URL precedence across dashboard links, SDK-created links, public quick links, and domain branding. Choose either multipart on existing routes or upload-then-bind on a documented native contract; breaking wire changes are allowed, so capability equivalence matters more than preserving old multipart syntax. Ensure renderer consumes the binding and uses the established link/domain/store-art fallback order. Do not treat JSON `image` acceptance without rendered bytes as completion.

New acceptance for each surface: initial attach produces anonymously fetchable OG/preview image; replacement changes binding; removal restores intended fallback; switching external URL ↔ upload removes stale precedence; failed replacement preserves old working image; concurrent replacements leave one valid current binding; unauthorized bind denied. Browser crawler and real frontend exercise final forms, error messages and preview; keyboard access and accessible error state for any changed upload UI.

Dependencies: P-C3a; SDK creation follows P-C5; actual frontend/client contract adapters required. This is the capability completion PR, not merely generic object storage work.

### P-C3c — Make asset cleanup retryable (1–2 engineer-days)

Source homes: asset module, `src/maintenance.rs`/native cleanup worker integration, existing project deletion lifecycle; `tests/assets.rs`, `tests/cleanup.rs`, `tests/maintenance.rs`.

Work: replacement/removal schedules unreferenced blob cleanup; failed upload/DB commit and expired anonymous quick assets are swept; project deletion accounts for image namespaces. Use durable lifecycle work with idempotent retries. Preserve the last committed working image on provider failure and avoid deleting an asset that a concurrent edit retained/rebound.

New acceptance: failure before/after blob write and before/after binding commit; worker interruption after remote delete; denied list/delete then restored permission; retry/replay; simultaneous replace/delete; project deletion with active uploads and more than one cleanup batch; B's assets survive; no orphan published image after completed cleanup. Two provider outages progress independently rather than one discarding the other's work.

Dependencies: C3a–b and shared deletion/retention fixes. Live MinIO/GCS cleanup is required before closure. Approximate C1–C5 subtotal: 6–11.5 engineer-days; allow contingency for image/client contract decisions rather than silently compressing those decisions.

## Domain compensation: decision before implementation

This is a known partial-state behavior with an unresolved contract, not automatically a confirmed missing feature. Source homes: `src/imports.rs::create`, `src/domains.rs::provision` and lifecycle; tests `tests/imports.rs`, `tests/domains.rs`.

Decision package (~0.5 engineer-day): state whether failed migration setup should (A) compensate both source and hostname, or (B) retain a durable, visible setup operation for adoption/retry. Record ownership and deletion authority, pending response/status, retry identity and timeout behavior. Avoid the current ambiguous outcome of a deleted source plus silently retried hostname. Choose with the product owner in the first planning week; no answer is assumed here.

Implementation (~1–2 engineer-days after decision): A requires non-resolvable teardown state and durable cleanup when Cloudflare deletion fails; B requires retained source/operation linkage and explicit pending/failed status, rather than silently active orphan domain. Either choice must handle Cloudflare create timeout after remote success, lookup/adoption, source insert failure, worker retry/restart, simultaneous duplicate creates, retry with same versus changed hostname, entitlement/ownership revoked, and delete while pending. Assert no unauthorized active host and no unrecoverable reserved slot. Mocked deterministic state-machine tests first; real controlled Cloudflare/manual DNS/TLS rehearsal afterward. Not counted in C1–C5 subtotal.

## Shared validation work (reuse across the 31 findings)

### Establish now, before feature closure

Reserve one disposable Google test project/dataset/topic/export subscription/private bucket, one runtime service identity with intended production-style permissions, an isolated MinIO/ClickHouse stack, a DNS test zone, and a native PostgreSQL 18.6 staging database with persistent volumes and backups. Name owner, expiry/cleanup and budget. Attach actual client repos/builds (frontend, iOS, Android, server SDK) or record their unavailability; HTTP fixtures alone cannot establish actual client compatibility. Provision test apps/package IDs/associated domains and a synthetic first-tenant fixture. Start access requests early; do not wait until release week.

Use shared acceptance data with run ID, two independent owners/instances/projects, deterministic event IDs, visitors, links/campaigns, aliases, uploaded image hashes and expected outputs. Choose small independent expected-results fixtures rather than deriving expected output with the production query code. Save native request/response contracts alongside scenarios; old wire route matching is not a substitute for this. Changing C5 means current testing-guide event curl examples must acquire platform/identifier declarations and configured fixture apps.

### Existing evidence versus new work versus external gates

| Layer | Existing tests/checks now | New work to plan | External gate |
|---|---|---|---|
| Local correctness | `scripts/check.sh`: fmt, Clippy, configuration validation, integration runner, audit; runner provisions PG/Redis/CH/MinIO and includes ignored tests | Routed C1–C5 regressions above; shared acceptance assertions; no test count is itself a release criterion | Docker/resources and required tools |
| Current HTTP flow | `tests/end_to_end.rs::http_ingestion_analytics_and_storage_flow` hard-codes ClickHouse + S3/MinIO | Parameterized candidate-image acceptance runner for all matrix rows, actual client contracts and added images | Deployed image with web+worker |
| Provider contracts | `tests/providers.rs` mocks BigQuery/PubSub/S3/GCS HTTP; real CH/MinIO tests via integration runner | New deterministic failure cases only where current tests miss the corrected behavior | Mocks do not prove Google IAM, refresh, export subscription or real GCS |
| Image | `scripts/image-smoke.sh`: native startup/migrate/health/incomplete-config checks | Full new feature flow against the built candidate, persistently backed PG | Correct deployment environment/image digest |
| Clients | Rust route fixtures for SDK/imports/MCP exist | Golden request/response fixtures from each supported frontend/mobile/server client; tool calls through actual MCP client | Actual client build and device/browser harness |
| Recovery | Some worker/cleanup retry suites already exist | Native backup/restore to a fresh environment, replay queued work, application rollback rehearsal | Isolated persistent staging storage, stable encryption keys |

### Provider acceptance matrix

Run core local tests for every PR. Run relevant live provider checks when adapters/lifecycle change. Run the full common acceptance sequence against the same candidate image for all four rows before declaring the whole selectable feature set supported:

| Analytics | Storage | Required real acceptance |
|---|---|---|
| ClickHouse | MinIO | Reference flow plus all corrected client flows, exported files/images and cleanup |
| BigQuery via Pub/Sub | MinIO | Actual publish → subscription export → query, logical deduplication, BQ retention/project deletion; MinIO assets/exports |
| ClickHouse | GCS | Actual runtime identity GCS put/get/list/delete and public app image serving, export, expiry/revocation and cleanup; CH reconciliation |
| BigQuery via Pub/Sub | GCS | Combined cloud flow and independent warehouse/storage outage recovery |

Each run: create fresh A/B owners and instances, authenticate clients/configure SDK, create link/campaign/domain metadata, ingest fixed events twice, resolve C1 inputs, verify C2 filters/metrics, use C4 tokenless check, attach/render/replace C3 images, export/download, then delete A and confirm remote cleanup while B survives. Under the proposed A6 fix, `GET /api/v1/projects/{project_id}/analytics` becomes canonical PostgreSQL analytics. Check delivery separately with direct selected-provider queries or an explicit provider diagnostic; that customer endpoint must not be used as warehouse-arrival evidence. Verify logical event IDs/counts in the actual warehouse, not just endpoint status. BigQuery physical duplicate rows are possible; ingestion replay and delivery replay are separate tests.

Required cloud failure cases: publisher denied; publish succeeds but export subscription cannot write; malformed/schema-incompatible message; delayed export after project deletion; credential refresh then revocation; warehouse DELETE denied then restored; GCS read/write/list/delete each denied; storage unavailable while warehouse cleanup succeeds and the inverse; process terminated around provider acknowledgement/leased job. Assert observable failed/pending work, recovery with preserved IDs, no false completion, eventual exact tenant cleanup. Choose bounded observation windows before running, based on actual worker and tombstone schedules; a Pub/Sub acknowledgement or `/ready` response is never sufficient evidence.

BigQuery deletion currently has audit item A10 (runtime IAM missing DELETE capability); mark those tests expected-failing/blocked until A10 is fixed and re-run using the deployed identity, not an administrator's CLI identity. Remove emulator/static-token overrides for live Google runs. Google access, test DNS/TLS and real provider accounts are credential/environment gates; a skip remains unverified rather than passed.

Provider selectors are global and do not dual-write or move data. Restart/configure web and worker together; use separate fixtures/environments per row. Fresh release avoids any historical provider migration, but changing providers after the first tenant starts collecting data will require an explicit migration/reconciliation plan. Never switch a live tenant's selector to run acceptance.

### Client fixtures and device/browser gates

- Frontend/dashboard: account → project/app configuration → link/campaign filter/search → image attach/replace/remove → brand preview → export; exact native body/status/error contracts, two-owner authorization and expiry. Public quick-link and crawler image flow included. Keep shared server expected fixtures small; add only relevant UI accessibility checks, not a generic UI rewrite.
- Android: configured package SDK authentication; Play Install Referrer with encoded Branch link → intended deferred data; direct custom/native link; missing/mismatched identifier rejected; one-time attribution/identity merge and retries; clipboard disabled and stale marker. Install Referrer delivery itself needs a test app/store or representative device integration, separate from HTTP parser tests.
- iOS: configured bundle/associated domain; direct/deferred links; clipboard activity queried before any clipboard read; token consumption and privacy prompt behavior on device; configured disable takes effect. Emulator-only clipboard behavior is insufficient for the privacy flow.
- Server SDK/automation: valid/revoked/wrong-scope keys; generate/details/metrics; retry and deterministic IDs; image binding if that client exposes it; native path changes reflected in client fixtures.
- MCP: actual supported client tool discovery + REST/JSON-RPC search, configured project grants/read-only scope, filters/pagination/empty sets, denial on revocation. Management-handler tests cannot substitute for MCP gateway tests.

### Fresh-install first-tenant release gate

Before onboarding: all initial-release P1 and required retained capabilities closed with linked tests, four matrix results green if all combinations remain advertised, no unresolved data-integrity/security failure, native restore/recovery rehearsal passed. Preserve the separate deferred M1 status; do not describe fresh-install success as Rails cutover readiness.

Minimal production canary: deploy the validated image/config to a fresh native installation on the chosen production provider pair; create a synthetic first tenant with two isolated test principals; execute login/config, one link/preview and public image, one SDK event/deferred resolution, one filtered MCP search, one export, and one synthetic cleanup. Confirm worker heartbeat, pending queue age, actual warehouse arrival, asset fetch, auth rejection and provider errors. Do not run outages/credential revocation/load tests against production. Hold onboarding for the pre-agreed observation window and delivery/cleanup cadence; continue only when counts and logs reconcile. On failure, stop onboarding/ingress as needed, retain evidence, restore or roll back the compatible validated native state; no blind binary rollback across incompatible schema.

Evidence per package/matrix: finding ID, source revision/worktree hash, image digest, redacted effective providers/versions, test command and actual result, fixture IDs/hashes and expected-versus-observed output, cloud query/job/export evidence, cleanup completion, remaining gate and owner. A PR closes implementation only after its tests pass; release closure also needs the corresponding client/provider gate. Re-run only affected evidence after changes, plus final integrated smoke on the exact candidate image.
