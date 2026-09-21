# Rust rewrite status

Updated 2026-09-20. The requested scope is **all existing capabilities**, but that scope is **not yet complete**. The [parity audit](RUST_PARITY_AUDIT.md) records 31 missing, partial or materially changed behaviors, plus missing legacy conversion/archive-recovery tooling. Its findings qualify the capability mappings below. Rust is the default web, worker and migration runtime. The Rails source remains the reference inventory and is excluded from the runtime image. The native schema uses UUIDs and some routes and response envelopes have changed; capability coverage does not establish wire compatibility or automatic migration of an existing Rails database.

## Requested platform changes

| Request | Implementation | Validation boundary |
|---|---|---|
| Rust 1.98.1 | Exact toolchain; Axum, Tokio, SQLx; native web/worker/migrate binary and non-root image | Native format, lint, unit, integration and image gates |
| Enterprise on by default | `TRISIXT_EE=true` default; audit, SSO, SCIM and purchase processing in the same executable | External credentials still required |
| ClickHouse or BigQuery via Pub/Sub | Selectable adapters, durable outbox, event UUID deduplication, BigQuery export subscription/table/IAM Terraform | Real ClickHouse tested; Google authenticated HTTP contracts; live cloud delivery needs deployment credentials |
| PostgreSQL 18.6 | Exact default/test image, PostgreSQL 18 volume layout | Test server version checked; no production volume upgraded |
| Latest stable Redis | 8.10.2 core and server TLS, exact upstream source with pinned SHA256 | Test server version checked; host Redis untouched; native client TLS missing (audit O5) |
| Product rename | First-party product names, namespaces, paths, configuration and documentation use Trisixt | Original `LICENSE` and `ee/LICENSE` legal notices preserved |
| S3 or GCS | Project-scoped storage adapter, assets and durable export artifacts; optional Terraform GCS bucket/IAM | Actual MinIO and GCS protocol tests; live AWS/GCS accounts unverified |

Redis 8.10.2 was verified against the [official release archive](https://download.redis.io/releases/) on 2026-09-19. Its Docker Hub tag was unavailable, so `deploy/redis.Dockerfile` builds that release directly.

## Capability mapping

The inventory includes `config/routes.rb`, controllers, services, jobs and the corresponding `ee/` source. Detailed mappings connect the reference behavior, Rust implementation and regression cases. These are family-level implementation maps, not full-parity certification; consult the [current exceptions](RUST_PARITY_AUDIT.md#complete-findings-register).

| Capability family | Native implementation | Mapping / evidence |
|---|---|---|
| Accounts | Registration, confirmation, password reset/change, invitation acceptance, profile/deletion, TOTP/QR/recovery, refresh rotation/reuse detection, mail queue | [Accounts and messaging](parity/ACCOUNTS_MESSAGING.md) |
| Tenants and administration | Instances, atomic production/test onboarding at `/api/v1/instances/provision`, roles/invitations, API keys, onboarding, configurable retention, operator diagnostics and repair | `core_api.rs`, `management.rs`, `operations.rs`; core/management/operations integration suites |
| Public links and SDK | Rich links/campaigns, platform fallbacks and previews, QR/clipboard, custom schemes, universal/app links, devices, attributes, screen aliases, deferred matching and identity merge, device marketing names | [SDK and management](parity/SDK_MANAGEMENT.md), [connectivity](parity/CONNECTIVITY.md) |
| Analytics | Explorer/detail/fields/values/volume, typed filters and cursors, overview/time series/versions/sources, mature retention cohorts, session stitching, link/campaign/visitor metrics and sortable management statistics | [Analytics](parity/ANALYTICS.md); analytics/management integration suites |
| Billing | Stripe checkout/portal/subscriptions/webhooks, metered MAUs, coupons, quotas, exemptions, enterprise subscriptions and alerts | [Billing and purchases](parity/BILLING.md) |
| Revenue | Authoritative Apple/Google verification, signed/authenticated store notifications, refunds/reversals/cancellations, recurring state, FX, attribution, reconciliation, explicitly SDK-reported external payments | [Billing and purchases](parity/BILLING.md) |
| Messaging | Campaign notification templates, recipient queues, FCM/APNs, retries, invalid-token retirement, notification open/read, SMTP account/usage/export mail | [Accounts and messaging](parity/ACCOUNTS_MESSAGING.md) |
| Enterprise | Append-only chained audit, revocable read-only export tokens, OIDC, verified domains, SSO enforcement, controlled JIT/claim roles, SCIM lifecycle and revocation | [Enterprise contracts](ENTERPRISE.md); enterprise, administration and OIDC suites |
| Domains and migrations | DNS ownership, Cloudflare certificate lifecycle, Branch/AppsFlyer/Firebase imports/resolution, encrypted credentials and durable retries | [Connectivity](parity/CONNECTIVITY.md) |
| MCP and automation | OAuth metadata/registration/consent, scoped access/refresh grants, revocation, authenticated tool endpoints and JSON-RPC, machine operations and public quick links | [Connectivity](parity/CONNECTIVITY.md) |
| Assets and exports | S3/GCS objects; paginated CSV exports with metrics, formula escaping, scoped access, durable cursor/leases, expiration cleanup and email notification | `providers/storage.rs`, `integrations.rs`, `exports.rs`; providers/export/end-to-end suites |
| Deleted data cleanup | Durable project/instance tombstones, bounded namespace object deletion, repeated warehouse deletion for late Pub/Sub export, retries independent across providers | [Cleanup](parity/CLEANUP.md); cleanup suite |
| Background maintenance | Independent durable workers for events, billing, purchases, mail, push, domains, imports, exports, quotas, FX, metadata and hardware; bounded retention deletion and analytics repair | [Maintenance](parity/MAINTENANCE.md) |

Explorer and rich dashboard queries read the canonical PostgreSQL event ledger and verified purchase ledger independently of warehouse selection. The selected warehouse receives the durable event stream and serves provider analytics. Warehouse unique-visitor counts currently do not apply identity merges (audit A6), and the supplied BigQuery runtime grant cannot perform retention/deletion (A10). This architecture replaces the Rails mix of raw queries and incremental aggregate tables; repair re-enqueues source events rather than maintaining a second set of mutable business totals. Retention attempts warehouse deletion before local source rows and preserves pending deliveries on failure.

Identity alias changes, event ingestion and purchase writes use a shared lock protocol. Deferred-link claims survive failed processing and produce one replay-safe open event. Export jobs recheck authorization during generation and download; storage upload, cursor advancement and expiration are serialized. SSO enforcement, refresh rotation, unlinking and SCIM deactivation serialize against user-session issuance.

## Validation and rollout

The [gap-closure plan](RUST_GAP_CLOSURE_PLAN.md) sequences the 31 findings for a solo engineer targeting a fresh installation by 20 December 2026. Legacy Rails conversion is deferred; the plan includes a capacity checkpoint and separate local/live/recovery gates. No implementation completion is implied by planning.

Run `scripts/check.sh` for formatting, warnings-as-errors Clippy, branding, Compose validation, all native tests including infrastructure suites, and dependency audit. The integration runner uses isolated PostgreSQL 18.6, Redis 8.10.2, ClickHouse and MinIO. CI additionally builds and smoke-tests the native image. Executed results and external verification boundaries are in [VALIDATION.md](VALIDATION.md).

No production deployment, existing database conversion or Terraform apply is implied. A deployment must supply persistent encryption keys, configured provider accounts, DNS/TLS and mail settings. Real Stripe/store settlement, IdP interoperability, FCM/APNs delivery, Google IAM and Pub/Sub-to-BigQuery/GCS delivery require those accounts. The existing Rails database needs an explicit data conversion and reconciliation plan before cutover; SQL migrations initialize and evolve the native schema.
