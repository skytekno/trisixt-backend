# Rust parity audit — 2026-09-20

**Rust does not yet cover all retained Rails behavior.** This audit identifies **31 missing, partial, or materially changed behaviors**, plus a separate legacy-data conversion/archive-recovery gap. Having a handler, schema, adapter or passing test suite does not establish equivalent behavior.

The [gap-closure plan](RUST_GAP_CLOSURE_PLAN.md) targets a fresh Rust release by 20 December 2026 with one engineer. All 31 findings remain planned; M1 is deferred until after the fresh release. The plan does not mark these findings fixed.

The findings below are confirmed by source inspection. Their scenarios are acceptance cases to execute, not claims of newly reproduced runtime failures. No application source was changed, no application test suite was rerun, and no cloud or production operation was performed for this audit. The previous **130-test pass is historical evidence from 2026-09-19**.

## Highest-priority findings

1. **Deleting a paying instance does not cancel Stripe billing** (E1), including deletion through its last administrator's account.
2. **SCIM provisioning no longer depends on an active SSO connection or verified domains** (E2); **SCIM cannot deactivate a nonlast administrator** (E3).
3. **SDK configuration restrictions can be skipped by omitting platform/origin declarations** (C5). This is a same-project configuration gate, not a demonstrated cross-tenant access flaw.
4. **Analytics results diverge from retained behavior**: missing GeoIP/OS/screen enrichment (A1–A3), own activity returned for referral tables (A4), and split warehouse identities after visitor merge (A6).
5. **Supplied BigQuery runtime IAM does not allow deletion** (A10). **The Rust Redis client has no TLS feature enabled** (O5), even though the Redis server image supports TLS.
6. **SDK migration referrers and MCP filtered searches are partially implemented but unreachable/misrouted** (C1–C2).

These findings supersede broad claims that the rewrite retains every existing capability. The detailed evidence reports pair Rails and Rust source locations, explain impact, identify existing coverage, and specify acceptance scenarios.

## Complete findings register

Priority: **P1** = address before release with the affected feature enabled; **P2** = close or explicitly approve a reduced capability before claiming full parity. These are proposed release priorities, not formal security severity ratings. “Changed policy” identifies a real capability/actor change that may be intentional; it requires a product decision rather than blindly copying Rails internals.

### Accounts, enterprise, billing and revenue

Evidence and closure scenarios: [enterprise findings](audit/ENTERPRISE_FINDINGS.md).

| ID | Priority | Missing or partial behavior | User-visible result |
|---|---|---|---|
| E1 | P1 | Stripe cancellation on instance/last-admin deletion | Local subscription reference is deleted while external billing can continue; cleanup has no cancellation obligation. |
| E2 | P1 | SCIM active-SSO, verified-domain and operator-email gates | Unverified-domain users can be provisioned; instance-bound tokens survive SSO disable/delete. Existing-email takeover was not established. |
| E3 | P1 | SCIM deactivation of nonlast administrators | IdP deprovisioning returns forbidden and leaves membership/sessions active. |
| E4 | P2 | SCIM member/invitation adoption, UPN/email distinction, externalId filtering, name/email PATCH, retained string-active payloads | Common retained provisioning and profile-update workflows fail or lose fields. |
| E5 | P2 / changed policy | Controlled OIDC preferred_username/SCIM-UPN fallback | Previously supported IdPs without email/email_verified claims cannot sign in. |
| E6 | P2 | Purchase browser pagination/search/sort and adjustment event rows | At most 1000 sales are visible; refunds/cancellations stored in the ledger are absent from the browser query. |
| E7 | P2 | Product-level revenue tables | Project totals exist, but filtered/sorted/paged product revenue and product ARPU/ARPPU are absent. |
| E8 | P2 | Audit actor snapshots, before/after changes, outcome, request context, failed-login records and operational chain verification | Chaining exists, but investigation loses retained identity/context and failure evidence. |
| E9 | P2 / changed administration | Tenant credential onboarding/rotation for SSO, push and stores; APNs certificate mode | Tenant admins must rely on operator-provided profiles; provider transports themselves exist. |

### Analytics, enrichment, exports and maintenance

Evidence and closure scenarios: [analytics findings](audit/ANALYTICS_FINDINGS.md).

| ID | Priority | Missing or partial behavior | User-visible result |
|---|---|---|---|
| A1 | P1 | Automatic IP-to-country/city enrichment and MMDB loading | Country/city remain blank unless supplied as event properties. Rails GeoIP environment variables do not enable native detection. |
| A2 | P1 | Applying saved screen aliases and retained screen-name fallbacks | Aliases are stored but never read; screen/session reports retain raw names or blanks. |
| A3 | P2 | Device UA-to-OS/version and timezone propagation into events | Known device metadata is absent from analytics unless sent explicitly with each event. Fingerprint UA handling exists. |
| A4 | P1 | Dashboard inviter/referral aggregate semantics | Referral tables query the visitor's own activity. Inviter-aware server-SDK metrics exist separately. |
| A5 | P2 | Visitor metric pagination, metric/identity sort/search, revenue hydration and rich detail | Metric lists stop at 200; plain visitor search does not replace a paged metrics table. |
| A6 | P1 | Merge-aware unique visitors in warehouse analytics | Canonical PostgreSQL analytics folds aliases; ClickHouse/BigQuery endpoint counts still use original visitor IDs. |
| A7 | P2 | Retained link CSV counters | Reinstalls, reactivations and time-spent columns are absent. Native export queue/access/expiry handling exists. |
| A8 | P2 / deprecated reference endpoint | Range-sensitive usage CSV, daily active users and empty-period fill | Partial-month exports count whole monthly billing snapshots, including activity outside the requested range. |
| A9 | P2 | Expired migration negative-cache pruning | Old not-found/transient rows accumulate until their source is deleted. |
| A10 | P1 for BigQuery | Runtime table-data deletion grant | Supplied Terraform grants read/query permissions, while retention and namespace cleanup issue DELETE. Live IAM failure has not been reproduced here. |

### Links, SDK, assets, migrations and MCP

Evidence and closure scenarios: [connectivity findings](audit/CONNECTIVITY_FINDINGS.md).

| ID | Priority | Missing or partial behavior | User-visible result |
|---|---|---|---|
| C1 | P1 | Routed SDK support for raw Play Install Referrer and bare migration slug | URL parsing rejects these before reaching the resolver that supports them. |
| C2 | P1 | MCP rich link/campaign search delegation | MCP calls simple list handlers, so term/filter/statistics arguments are ignored. Native link limit/offset still works. |
| C3 | P2 | Uploaded link images and domain branding attachments | JSON external-image URLs work; multipart attach/replace/purge/public rendering does not. Generic private GCS/MinIO objects are not an equivalent image workflow. |
| C4 | P2 | Tokenless clipboard project-activity check | SDK must already have read a token before asking status, losing the retained pre-read activity signal. |
| C5 | P1 | Mandatory SDK app/platform configuration gate | Valid project-key calls without platform or Origin skip disabled-app/identifier/domain restrictions. |

### Configuration, operations and tenant lifecycle

Evidence and closure scenarios: [operations findings](audit/OPERATIONS_FINDINGS.md).

| ID | Priority | Missing or partial behavior | User-visible result |
|---|---|---|---|
| O1 | P1 / changed policy | Self-hosted flag automatically closing registration | TRISIXT_SELF_HOSTED alone does not close Rust signup; the separate DISABLE_REGISTRATION setting is required. |
| O2 | P1 | Retained per-IP request throttles | Native account/token/project counters and password-work semaphore do not reproduce source-IP protection across rotating account identifiers or SDK requests. |
| O3 | P2 | OpenTelemetry/OTLP trace integration and metrics instrumentation | Local tracing logs exist, but the retained instrumentation/export integration is absent. Historical Rails metric delivery was not established. |
| O4 | P2 | Deep dependency diagnostics and dedicated diagnostics-key contract | Queue/job health exists; independent Redis/warehouse probes and retained diagnostic exercises are reduced. Readiness only checks PostgreSQL. |
| O5 | P1 for TLS-only Redis | Redis TLS client features/configuration | rediss URLs are rejected by the compiled client; the worker discards client-open errors and skips Redis heartbeat. PostgreSQL event delivery remains separate. |
| O6 | P2 | Atomic initial-member provisioning | Rust creates production/test projects atomically, but cannot include the initial invited members in the same operation. Separate invitations exist. |
| O7 | P2 | Renaming paired projects with an instance | Instance name changes while production/test project names remain unchanged. |

## Legacy data and recovery work remains separate

**M1 — Existing-deployment conversion and legacy event/archive recovery tooling is absent.** SQLx migrations initialize/evolve the native schema; they do not translate Rails integer identities/data into native UUIDs, import existing warehouse history, or replay the retained gzipped event archives with the Rails resumable manifest. Native repair only requeues events already in native PostgreSQL. Branch/AppsFlyer/Firebase link migration is a different capability.

This is an acknowledged cutover workstream, not a claim that native schema migrations are missing. It is conditional for a fresh installation and mandatory for migrating an existing Rails deployment. See the [evidence](audit/ANALYTICS_FINDINGS.md#known-migrationbackfill-boundary) and [database validation guide](TESTING_GUIDE.md#8-postgresql-186-redis-and-data-migration).

## Behavior changes and unresolved decisions

These are tracked separately from the 31 findings so a wire change or different architecture is not automatically labeled a missing feature.

| Topic | Decision or validation required |
|---|---|
| API/client compatibility | Native UUIDs, API keys, visitor identity, paths/methods, response envelopes and notification URL handling differ. Replay adapted real dashboard/mobile/server clients; literal route matches do not establish compatibility. |
| Quota boundary and notifications | Native ingestion caps a new visitor at count >= allowance, but exceeded state/alerts use count > allowance. Decide the intended cap/alert boundary. Warning recipients now exclude ordinary members. |
| Billing/usage responses | Current-month MAUs and raw Stripe invoice/subscription rows differ from normalized billing-cycle envelopes. Map the actual client requirements. |
| Mail delivery/content | Native mail is text-only. Self-hosted copyable invitation links exist, but invitations still queue SMTP work when SMTP is absent. Agree on the intended no-mail deployment behavior. |
| Migration/domain compensation | A failed migration-source create can delete its source while retaining a retryable custom hostname; the lifecycle worker may later provision it. Define rollback versus durable adoption and test the combined failure path. |
| Store purchase trust | Native authoritative provider amounts and account-UUID binding are stronger than retained SDK financial evidence. Preserve that validation and migrate clients/configuration deliberately. |
| Worker throughput | Native durable PostgreSQL delivery replaces Redis/Sidekiq event buffering and currently publishes individual outbox events. Absence of the old batch/spill jobs is not itself missing functionality; verify throughput and recovery under load. |

## Implemented capabilities versus validation gaps

The audit found substantial native implementations for account confirmation/reset/MFA/session rotation, tenant authorization and roles, public redirects/previews/associations/QR, deferred attribution, transactional identity merge, event ingestion/outbox, explorer/overview/retention/session analytics, Stripe/store processing, messaging/mail queues, OIDC, SCIM, chained audit, custom domains/imports, MCP/OAuth, storage/exports, retention and deleted-namespace cleanup. Each has the exceptions above; none is certified fully equivalent by this inventory.

Architectural replacements are valid where they preserve observable behavior. PostgreSQL canonical analytics can replace Rails ClickHouse rollups/session-builder jobs. Durable SQL outboxes can replace Redis buffers/Sidekiq queues. UUID-based native schema management can replace ActiveRecord migrations for fresh native installs. The warehouse identity disagreement in A6 is nevertheless observable through a mounted endpoint and therefore remains a gap.

**Still unverified, rather than proven missing:** live BigQuery/Pub/Sub/GCS and AWS S3 delivery; Cloudflare/DNS/TLS; Branch/AppsFlyer upstream behavior; Stripe settlement and real Apple/Google lifecycle events; actual IdP/SCIM interoperability; FCM/APNs devices; mail deliverability; browser/mobile journeys; production-size load; restore/rollback and deployment rehearsal. A10 is a specific configuration defect in addition to this live-validation boundary.

## Audit method and evidence limits

- Compared retained routes, controllers, services, jobs, configuration, schema and selected test scenarios against native handlers, worker scheduling, providers and SQL. Followed suspicious matches through their call paths rather than counting function names.
- Parallel reviews covered connectivity; analytics/enrichment/maintenance; enterprise/billing/purchases/messaging; and configuration/operations/tenant lifecycle. Hindsight and the existing Graphify graph supplied navigation, not proof. The source is authoritative for these findings.
- [Rails route inventory](audit/RAILS_ROUTE_INVENTORY.csv): **224 explicit declarations**, of which **152** have a literal normalized method/path candidate in Rust. [Rust route inventory](audit/RUST_ROUTE_INVENTORY.csv): **240 literal method/path entries**. The other **72 Rails declarations are not 72 missing features**. This lexical inventory excludes engine-expanded routes and does not fully expand dynamic dispatch; host/enterprise constraints, moved paths and wildcard handlers need semantic review.
- Inventory scope includes 61 main Rails controllers, 109 services, 36 jobs; 8 enterprise controllers, 30 services and 5 jobs; 38 Rust source files; 446 main Ruby test files and 22 Rust integration test files. Counts describe navigation scope, not an assertion that every test/line was reviewed. Enterprise test evidence was inspected separately.
- [Source SHA256 snapshot](audit/SOURCE_SHA256.json) fingerprints **1321 files** because this checkout has no commits. It records source identity, not coverage. Documentation and generated graph artifacts are not part of that snapshot.
- This is a broad static parity audit, **not an exhaustive proof that no additional gaps exist**. A paired behavioral test harness and real client/provider runs are still needed. No application suite, live provider or Rails-to-Rust differential suite was executed for this report.

## How to close the findings

1. Establish the intended contract for each ID. Record an explicit scope decision for changed policy/administration; do not mark an unimplemented retained capability complete merely because a new route exists.
2. Turn each detailed scenario into an independent expected-result fixture. Prioritize E1–E3, C5, O1–O2, then analytics/deferred-link/MCP correctness and provider configuration.
3. Exercise the routed API and worker/provider result together. Alias-storage tests alone miss A2; helper-only tests miss C1; management search tests miss C2; PostgreSQL merge tests miss A6.
4. Run affected native suites and the full local gate from [TESTING_GUIDE.md](TESTING_GUIDE.md). Then run all four warehouse/storage combinations where relevant and the live-provider acceptance cases. Test the actual runtime principal for BigQuery DELETE and the compiled Redis client against TLS.
5. For existing deployments, rehearse M1 with row/identity/value reconciliation and restore/rollback before cutover. Retain redacted logs, source/image identity and pass/fail evidence per finding.

No findings are marked fixed by this audit. Earlier parity mappings remain navigation aids and must be read together with this report.
