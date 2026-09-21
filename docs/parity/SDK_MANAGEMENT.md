# SDK, links, management and export capability mapping

> Audit update (2026-09-20): this is an implementation map, not full-parity certification. Read the [confirmed gaps and acceptance scenarios](../RUST_PARITY_AUDIT.md) before relying on these coverage claims.

Native routes use UUID project/visitor/link identifiers, `x-project-key` for the mobile SDK and bearer credentials for the dashboard. Projects are the data boundary; instance membership controls dashboard access. The server SDK additionally accepts hashed instance credentials scoped by environment. Public browser cookies and clipboard secrets are separate project-bound capabilities.

| Reference behavior | Native implementation and regression evidence |
|---|---|
| Device authenticate/update/vendor lookup | `sdk.rs`, shared devices schema, vendor lock and visitor validation, hardware name lookup, platform/version/build/push/environment fields; SDK integration tests include stable identity and last-seen behavior |
| Visitor attributes and external identifiers | Scoped get/merge, external-ID identity consolidation, push-token updates; aliases are flattened, so events, devices, purchase ledger, subscription state, notification targets and monthly MAUs remain associated with the canonical visitor |
| Linked web applications | `web.domains` configuration, hostname validation, configured web-domain checks for browser origins and declared SDK identifiers; declared mobile bundle/package checks and disabled-platform rejection. Native and legacy project-key/platform/identifier header names supported. SDK integration test covers correct/foreign/missing domains and reset. |
| Screen aliases | Project-scoped bounded list/upsert, blank validation and deterministic last-value handling |
| Event ingestion and custom events | Bounded batches, timestamp/UUID/JSON validation, deduplication by project/client event UUID, stable lock ordering, shared project identity lock, transactional canonical event + warehouse outbox + billing usage |
| Historical dimensions | Server-derived link/campaign/source/tracking, user-attribute/external-ID and device snapshots prevent later mutable metadata from rewriting historical analytics |
| Public-to-app attribution | Browser cookie ownership, opaque clipboard claims, bounded fingerprint window and complete device-dimension matching for ambiguous candidates; proxy forwarding accepted only from configured trusted peer addresses |
| Deferred-link retry and replay | Durable reserved claimant, canonical owner checks, deterministic open-event identity and completion only after successful processing; regression exercises failed processing followed by concurrent retries |
| Rich link operations | Partial metadata-preserving updates under row lock, active/archive reversal, campaign validation, tags/ads/tracking, safe custom app schemes, metadata pages and platform options; concurrent PATCH regression preserves all independent fields |
| Campaigns | Create, partial update, archive/restore, link association and metrics; metadata-only updates preserve the name |
| Search and statistics | Link/campaign term/tag/platform/campaign/SDK/status filters, date/retention/timezone validation, whitelisted column and counter/revenue ordering, stable UUID ties, pagination metadata and next offset; zero-activity rows retained and sort last for metrics |
| Onboarding/retention | Idempotent setup steps and dismiss action, explicit role lookup, owner-only bounded retention settings |
| Link/usage export | Durable multipart CSV, bounded pages and keyset cursor, formula escaping, metrics, authorization during generation/status/download, serialized upload/cursor/expiration, retry and expiration cleanup; usage exports require administrators |
| Diagnostics/repair | Operator key, health counters and job states, scoped pending-delivery flush, bounded reconstruction and explicit retention change; authentication/tenant regression tests |

Monetary link/campaign search totals are USD cents from the signed verified/reported purchase ledger; unconverted rows are explicitly counted. Campaign revenue follows the current link-to-campaign association, matching the reference revenue query. Event campaign attribution remains frozen at ingestion. Aggregate management queries use a 90-calendar-day range limit and a 15-second database execution budget. Pagination is bounded to 1,000 records per page; larger exports use the durable export endpoint.

`tests/core_api.rs`, `tests/sdk.rs`, `tests/management.rs`, `tests/exports.rs`, `tests/operations.rs`, and the analytics suites exercise these paths against isolated PostgreSQL. Public rendering/provider behavior is mapped separately in [CONNECTIVITY.md](CONNECTIVITY.md). Deferred matching is probabilistic when no explicit clipboard/link identifier is available; ambiguous fingerprints return no attribution instead of merging unrelated visitors.
