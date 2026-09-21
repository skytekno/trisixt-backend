# Validation report — 2026-09-19

This is the historical 2026-09-19 execution record for the native implementation mapped in [REWRITE_STATUS.md](REWRITE_STATUS.md). These results supersede the earlier 51-test core-only report, but do not establish full Rails parity. The [2026-09-20 source audit](RUST_PARITY_AUDIT.md) found 31 missing, partial or materially changed behaviors plus a legacy conversion/archive-recovery gap. No application suite was rerun during that audit; the recorded pass counts below are unchanged historical evidence.

## Executed final gates

| Gate | Result |
|---|---|
| `KEEP_TEST_STACK=1 scripts/check.sh` | PASS, exit 0 |
| Rust formatting | PASS |
| Clippy, all targets/features, warnings denied | PASS |
| Native tests including all ignored infrastructure suites | **130 passed, 0 failed, 0 ignored** |
| `cargo audit` | PASS; 397 locked dependencies, no ignored advisories |
| Branding, shell syntax, all three Compose configurations | PASS |
| `scripts/validate-config.sh --terraform` | PASS; Terraform format, readonly provider initialization and validation |
| Production Docker build, Rust 1.98.1 | PASS |
| `scripts/image-smoke.sh` | PASS; non-root execution, version, fresh migrations, liveness/readiness, invalid worker fails promptly |
| Final image source manifest | PASS; 80 build inputs match the validated source |

Tests ran against actual PostgreSQL **18.6**, Redis **8.10.2**, ClickHouse **25.3** and MinIO. The integration script checks PostgreSQL and Redis versions explicitly. Provider transport tests use actual local HTTP/SMTP servers and signed synthetic tokens; they do not replace live provider accounts.

## Native test breakdown

| Suite | Passed |
|---|---:|
| Library | 32 |
| Accounts | 4 |
| Analytics | 9 |
| Billing | 4 |
| Deletion cleanup | 3 |
| Core API | 5 |
| Domains, store metadata and hardware | 8 |
| HTTP ingestion / warehouse / object E2E | 1 |
| Enterprise | 3 |
| Enterprise administration | 4 |
| Exports | 3 |
| Imports and public links | 7 |
| Retention and repair | 4 |
| Management | 3 |
| MCP and provisioning | 4 |
| Messaging | 2 |
| OIDC | 7 |
| Operator diagnostics/repair | 1 |
| Provider adapters | 16 |
| Purchase lifecycle and setup | 3 |
| SDK | 6 |
| Worker | 1 |
| **Total** | **130** |

## Corrections verified during implementation

- Ordered and coordinated identity, event and purchase locks; alias merges consolidate devices, purchase/subscription records, notifications and monthly MAUs.
- Durable deferred-link claims survive failed processing; concurrent replay creates one open event.
- Concurrent partial link updates preserve independent fields; metadata-only campaign edits preserve names.
- Export authorization is checked during generation and download; upload, cursor acknowledgment and expiration cannot race. Demoted administrators lose usage-export access.
- SSO enforcement, refresh/MCP issuance, SCIM deactivation, identity unlink and callback validation use consistent locks; linked sign-ins recheck verified domains and current role claims.
- Analytics golden cases cover countable events, installation cohorts, session stitching, timezone boundaries, mature retention, frozen attribution/property filters, signed revenue and bounce-excluding engagement averages.
- Browser linked-domain and declared application identifiers are validated; public previews, store attribution, installed-app selection and generated store buttons are exercised.
- Signed purchase adjustments preserve immutable referral/link attribution; Google notifications select the matching package and environment.
- Project/instance tombstones survive relational deletion, serialize with in-flight writers, and retry independent warehouse/object cleanup. Successful tombstones continue reconciling late Pub/Sub export.
- Background tasks are supervised; queued mail without SMTP produces an explicit health error.
- Upgraded Hickory to 0.26.3 to remove [message encoding](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-q2qq-hmj6-3wpp) and [DNSSEC validation](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465) advisories. No audit exclusions were added.

## Build and local evidence

Validated image: `trisixt-backend:validation`; **49,168,053 bytes**, runtime user `trisixt:trisixt`. Both original license notices are included.

Image ID: `sha256:69139b66cca571d559182933270cc57f7fd43fdebe932d56eb0b8ada88f9f4cc`.

Detailed local logs:

- `/tmp/trisixt-full-capabilities-check.log`
- `/tmp/trisixt-full-capabilities-audit.log`
- `/tmp/trisixt-full-config-check.log`
- `/tmp/trisixt-full-docker-build.log`
- `/tmp/trisixt-full-image-smoke.log`
- `/tmp/trisixt-full-source-manifest.json`

The pre-rewrite backup remains at `/Users/roman/Workspace/github.com/mandays/trisixt-backend-backup-20260919-150450.tar.gz`. Existing unrelated host services and configuration were preserved. The repository has no commits; implementation changes remain local and uncommitted. Disposable integration/image-smoke containers and volumes are removed after validation; local images/build caches remain reusable.

## Verification boundaries

No production deployment, existing database upgrade/conversion, Terraform apply or real cloud provisioning was performed. Live Google IAM/Pub/Sub-to-BigQuery/GCS, AWS S3, Cloudflare/DNS/TLS, Branch/AppsFlyer, Stripe settlement, Apple/Google store notifications, IdP interoperability and FCM/APNs device delivery require configured external accounts. Local tests cover the protocol/persistence contracts and relevant failures without sending real recipient messages.

The retained Ruby suites were not executed against the Rust binary. Native acceptance tests were written from the reference contracts and golden cases. The native UUID schema and some API envelopes differ from Rails; an existing deployment needs explicit data/identifier conversion and reconciliation before cutover. Production-scale load/soak and disaster-recovery exercises remain deployment validation work. Passing this local suite establishes the stated coverage, not a guarantee that no undiscovered defects remain.
