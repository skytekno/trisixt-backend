# Analytics, identity, enrichment, exports and maintenance parity audit

Read-only static audit, 2026-09-20. No implementation changes, native/Rails suites, cloud requests or production operations were run. Findings are code-confirmed behavior differences with proposed reproduction fixtures; they are not runtime reproduction claims.

> 🧠 **From Hindsight memory (Component map)** — PostgreSQL is the intended canonical store for rich analytics; ClickHouse/BigQuery receive the durable event stream. Consequently, a Rails materialized rollup/job need not have a one-for-one Rust replacement if the user result is served by the canonical query.

> 🧠 **From Hindsight memory (Key decisions and rationale)** — GeoIP lookup and the BigQuery runtime deletion grant were already known gaps. Both remain evident in current files.

An existing Graphify graph was queried for relevant surfaces; its result was truncated and used only for navigation. Conclusions below come from current files.

## Confirmed missing or materially partial behavior

### A1. Automatic GeoIP enrichment is absent (high confidence, P1/P2 by product release requirement)

- Rails: `config/initializers/geoip.rb:3-10` opens MaxMind City DB from `GEOIP_DB_PATH`; `app/services/geoip_service.rb:4-16` converts IP into country ISO and city with graceful empty strings on missing/failed lookup. `app/services/clickhouse_event_row_builder.rb:17-19,37-42` resolves `device.remote_ip` for every event; `app/jobs/sync_visitor_profile_job.rb:25` and `app/services/clickhouse_history_backfill_service.rb:266-272` reuse it.
- Rust: `src/core_api.rs:808-815` enriches from device ID/platform/app version/model/build/language only. `migrations/0040_attribution_analytics.sql:70-71` takes `country`/`city` only from event properties, otherwise empty. `src/sdk.rs:23-58` extracts trusted client IP, but no MMDB lookup/runtime exists. No GeoIP Rust dependency/config/module was found.
- Impact/scenario: Authenticate with a known public IP, ingest an event without explicit country/city. Country and city analytics/session filters remain blank; provider selection does not change this. Merely setting the Rails MaxMind variables will not enable Rust enrichment.
- Missing acceptance: real small MMDB fixture IPv4/IPv6 country/city, invalid/private/missing IP, missing/corrupt database policy, trusted-proxy IP behavior, and propagation to canonical facts/warehouse payload. Current `tests/analytics.rs:13` injects country directly.
- Rails database acquisition helper `bin/ensure_geoip_db:24-79` supports local file, S3 cache, MaxMind download and stale fallback; it is not called by current Rust runtime.

### A2. Stored SDK screen aliases are never applied to event/session analytics (high confidence, P1/P2)

- Rails: `app/services/clickhouse_event_row_builder.rb:92-105` resolves screen name from event properties then visitor attributes, applies project screen alias, tries alias of event name, then uses CUSTOM/SCREEN_VIEW event name fallback. Alias lookup is implemented at lines119-134.
- Rust: `src/sdk.rs:318-343` accepts and stores aliases; the only runtime occurrence of the `screen_aliases` table is its INSERT at line340. `src/core_api.rs:771-816` never reads aliases or resolves a screen name. `migrations/0040_attribution_analytics.sql:69` uses only `properties.screen_name` or empty.
- Impact/scenario: Save `home -> Home`, then send a screen-view event with `event_name=home` and no explicit screen_name. Rails reports Home; Rust stores blank screen_name. Explicit `screen_name=home` stays untranslated. Session `first_screen`, `last_screen`, and `screen_count` (`src/analytics_api.rs:963`) inherit the gap.
- Missing acceptance: post alias, ingest all three input shapes (explicit screen property, user screen attribute, event-name fallback), query event detail and session screen metadata. `tests/sdk.rs:31-40` only asserts alias storage.

### A3. User-agent OS enrichment is missing from analytics (high confidence, P2)

- Rails: `app/services/clickhouse_event_row_builder.rb:18,37-40,123-125` derives OS name/version from `Browser.new(device.user_agent)` and also emits timezone/language.
- Rust: stores user agent in `src/sdk.rs:231`; the OS parser at `src/sdk.rs:114-132` contributes only to fingerprint hashing. Device enrichment in `src/core_api.rs:809` selects neither user_agent nor timezone; `migrations/0040_attribution_analytics.sql:73-74` reads only event properties for OS/version.
- Impact/scenario: iOS/Android/browser SDK registers a recognizable UA and emits normal events without manually adding OS/version; OS filter/discovery and event detail are empty despite a known device. `timezone` stored on the device is also not automatically included in event properties. Platform classification itself is implemented, so do not report all UA support absent.
- Missing acceptance: register several UA fixtures, ingest property-minimal event, inspect OS/version and device timezone without supplying those in event body. No such assertion found in inspected Rust analytics/SDK tests.

### A4. Referral/inviter dashboard aggregates are wired to own-visitor aggregates (high confidence, P1)

- Rails: `app/controllers/api/v1/visitors_controller.rb:9-18` distinguishes `VisitorReferralStatisticsQuery` from `VisitorStatisticsQuery`; referral query `app/services/visitor_referral_statistics_query.rb:24-27,72-76,89-105` groups event-time inviter metrics and invited revenue.
- Rust: `/visitors/aggregated` and `/visitors/aggregated_metrics` both route to `visitors_post` (`src/analytics_api.rs:1185-1195`), which calls `visitor_metrics` (`1125-1132`). Query at `1114` always groups by the event's own canonical visitor. `AnalyticsQuery.referrals` exists (`86`) but is unused. `visitor_id` always filters the event visitor (`349-353`).
- Impact/scenario: inviter A shares a referral link used by visitor B for an install/purchase. Aggregated report returns B's own activity or no row for A, rather than A's invited activity. This is a semantic gap, not just changed field names.
- Covered related capability: `metrics_for_scope(... referrals=true)` has an inviter-aware predicate and ledger query (`src/analytics_api.rs:1244-1265`), used by server SDK/automation. It does not fix dashboard list routing.
- Missing acceptance: distinct inviter/invitee with own and referred activity, purchase/refund, A-filter and platform combination; compare own vs aggregated endpoints. No Rust dashboard referral-list fixture found.

### A5. Visitor metric table cannot page beyond the first 200 or sort/search by the retained table options; revenue/detail output is materially reduced (high confidence, P2)

- Rails: `app/services/visitor_statistics_query_base.rb:15-25,35-65,138-163` implements pagination/counts, identity text matching, metric/identity sorting and hydrated visitor metrics. `app/services/visitor_statistics_query.rb:54-83` attaches ledger revenue. `app/controllers/api/v1/visitors_controller.rb:60-75` returns own/referral metrics plus generated-link count in visitor detail.
- Rust: `src/analytics_api.rs:1114-1115` is a fixed latest-event sort and LIMIT, without cursor predicate, offset, next cursor, count, ledger revenue or identity hydration. Limit is 1..200 (`396-399`); even an accepted decoded cursor is ignored by this SQL. `src/management.rs:202-211` offers separate plain visitor search, but only last_seen order and no per-visitor metrics. `src/core_api.rs:889-903` detail is the visitor row only.
- Impact/scenario: more than 200 active visitors cannot all be enumerated from the metric endpoint; 'highest revenue/views first' and identifier search in that table do not work as Rails did. Separate non-metric search is not equivalent. Deprecated raw-event routes are not required to preserve old internals, but current Rails `visitors`/`aggregated_visitors` tables still require these capabilities.
- Missing acceptance: >200 fixture, disjoint page union, metric/identity sort ties, term+date filters, visitor detail including own/referral revenue and link count. Existing native analytics tests focus explorer/sessions/overview, not this table contract.

### A6. Identity merges never reach the warehouse analytics endpoint (high confidence, P1/P2)

- Rails: `app/jobs/merge_visitor_clickhouse_fold_job.rb:21-35` durably publishes an identity alias and marks affected aggregates for repair independently of PG merge.
- Rust: `src/sdk.rs:345-346,447-473` keeps events immutable and writes only PostgreSQL `visitor_aliases` (plus canonical related tables). Canonical rich analytics correctly resolve aliases (`migrations/0040_attribution_analytics.sql:60,88-89`). However, the mounted `/api/v1/projects/{id}/analytics` route calls warehouse dashboard (`src/integrations.rs:19-21,51-56`). ClickHouse counts raw `uniqExact(visitor_id)` (`src/providers/analytics.rs:516-522`); BigQuery counts distinct raw visitor_id (`580-582`), with no identity mapping join or emitted merge update.
- Impact/scenario: two visitors each publish an event, then merge. Rich PG analytics reports one canonical visitor; warehouse endpoint permanently reports two, even after the event queue drains. This affects an exposed API, not only users running external ad-hoc SQL. Pending stored outbox payloads also retain original IDs.
- Missing acceptance: publish events for both identities into each warehouse, merge, assert canonical and warehouse endpoint unique counts agree. `tests/sdk.rs:228-268` tests PG billing/purchase/notification identity but not warehouse outputs; provider tests have no merge fixture.

### A7. Link CSV export loses retained metrics (high confidence, P2)

- Rails: `app/helpers/link_metrics_helper.rb:41-45,66-74` exports view/open/install/reinstall/reactivation/time spent, engagement column, rich link metadata and campaign name. Counter generation is at84-99 and106-128.
- Rust: `src/exports.rs:214-216` computes/exports only views, opens, installs and revenue plus basic metadata. No reinstall, reactivation or time-spent counters are present. Metadata JSON may preserve some descriptive fields, so avoid overstating all metadata as lost. The Rails engagement export itself is currently 0.0 (`99,128`); missing real engagement export is not a newly regressed computed metric.
- Impact/scenario: link receives 2 reinstalls, 1 reactivation and 60 seconds time-spent; existing CSV reporting cannot obtain these retained counters from new export.
- Missing acceptance: a populated multi-event/link CSV golden fixture, compared semantically with Rails. `tests/exports.rs:9-80` proves paging/escaping/expiration/access but inserts links without events and does not validate metric columns.

### A8. Usage export changes date-range meaning and drops daily reporting (high confidence, P2; Rails marks endpoint deprecated)

- Rails: `app/services/active_users_report.rb:12-21,73-105,108-140` exports daily and monthly unique active counts, zero-fills periods, and respects partial-month date bounds. Invoked from `app/jobs/export_activity_data_job.rb:12-21`; endpoint is explicitly deprecated in `app/controllers/api/v1/export_controller.rb:36-38`.
- Rust: `src/exports.rs:215-216` reads preaggregated `monthly_active_visitors` by month boundary only, with columns month/monthly_active_users. It cannot restrict membership to days inside a partial month; no daily data or zero-filled empty months.
- Impact/scenario: request September15..September20 with A active only September1 and B only September18. Rust reports both because both exist in September's billing snapshot; Rails range report reports only B. Even zero selected-range activity may produce a nonzero monthly number. A deliberate replacement with a whole-month billing export needs explicit contract/name/UI change and rejection/normalization of partial-month inputs.
- Missing acceptance: above fixture, empty months, start/end at month boundaries, DAU checks. `tests/exports.rs:84-112` injects two monthly snapshots and checks only `,2`, so it encodes whole-month behavior without comparing range meaning.

### A9. Migration negative-cache garbage collection is absent (high confidence, P2 operational regression)

- Rails: `app/jobs/migrated_link_cleanup_job.rb:7-16` deletes expired not_found/transient_error rows after a seven-day grace, retaining resolved rows.
- Rust: `src/imports.rs:811-819` only processes queued migration jobs. `src/maintenance.rs:90-103` prunes auth/delivered jobs but no migrated_links. `src/worker.rs:69-84,139-201` schedules no separate cache GC. Search across src/migrations finds no `DELETE FROM migrated_links`; deletion occurs only via source cascade (`migrations/0031_connectivity_imports.sql:9`).
- Impact/scenario: bots or old URLs probe many unique nonexistent paths on an enabled legacy domain. Negative-cache expiry allows refetch but rows remain forever; current job does not retain Rails bounded-cache housekeeping.
- Missing acceptance: seed old expired negative/transient rows, fresh negatives and resolved rows; maintenance deletes only the expired negative rows.

### A10. BigQuery deployment grant prevents runtime retention/project erasure (known gap, high confidence)

- `src/providers/analytics.rs:411-428` issues BigQuery DELETE. `deploy/google/main.tf:101-109` grants runtime only dataset dataViewer plus jobUser; dataEditor at68-73 belongs to the separate Pub/Sub service agent.
- Therefore using the supplied Terraform runtime principal alone cannot perform table-data deletion. `src/maintenance.rs:58-72` preserves local data on this failure; `src/cleanup.rs:40-74` retains retrying tombstones and independently cleans storage. This is a configuration/implementation gap in shipped deployment, not merely a missing live test.
- Native mock test `tests/maintenance.rs:85-150` validates parameterized deletion/polling, not deployed IAM. Deployment acceptance must run actual deletion with the runtime principal.

## Known migration/backfill boundary

- SQLx startup migration is native schema management, not legacy-data conversion (`src/main.rs:20-32`). `src/maintenance.rs:117-146` only repairs missing event outbox records and monthly activity from events already in native PG. It does not import old integer IDs, Rails PG tables, existing ClickHouse events or CSV archives.
- Rails archive import is a real retained operational capability: `app/services/clickhouse_archive_import_service.rb:8-17,38-68` supports gzipped PG event archives, enrichment and resumable per-file manifest. `ClickhouseHistoryBackfillService` can construct canonical rows from Rails history.
- No native CSV/gzip legacy event importer/mapping tool was found in inspected src/main/scripts surfaces. `src/imports.rs` deals with Branch/AppsFlyer/Firebase **links**, not event/database migration. `docs/TESTING_GUIDE.md:294-299` explicitly calls for future conversion and reconciliation. Treat existing-deployment conversion + archive recovery as an acknowledged missing cutover tool/workstream, not evidence SQL migrations are missing or fresh native installs are broken. No actual Rails-to-Rust production-data rehearsal has been demonstrated by this audit.

## Inspected/covered equivalents, not reported missing

- Event ingestion validation, batches <=100, tenant-scoped dedup/event locks, visitor merge coordination, immutable attribution/user snapshot, atomic billing usage + event + outbox: `src/core_api.rs:676-850`; durable retrying provider delivery `src/worker.rs:12-42` replaces Redis/Sidekiq buffers/spills/DLQ architecture.
- Event explorer/filter discovery/values/search/sort/cursors/counts/timezone volume: `src/analytics_api.rs:21-642` and tests/analytics explorer + snapshot goldens. UUID/cursor differences remain explicit client-migration concerns.
- Overview event/countable-user counts, sources, versions, prior-period trends, revenue ledgers and day fill: `src/analytics_api.rs:645-915`; tests/analytics goldens at257,549. Not every source/edge has been executed in this audit.
- Retention mature cohorts/rates and lifetime filter membership: `src/analytics_api.rs:918-945`; tests/analytics at231,366.
- Native on-demand session assembly, 30min gaps, blank-event forward stitching, visitor/day session isolation, summary filters, real purchase matching: `src/analytics_api.rs:947-1078`; tests at97,437. The Rails SessionBuildJob/materialized tables are replaced, not inherently missing.
- Visitor alias flattening, billing-user folds, purchase and notification ownership/pending work preservation: `src/sdk.rs:345-474`; tests/sdk at228. Warehouse exception is A6.
- Durable export queue, leased page uploads/cursor commit, requester authorization rechecks, expiry cleanup incl crash orphan: `src/exports.rs:176-263`; tests/exports. Export content semantics remain partial (A7/A8).
- Per-project retention schedule, policy lock, synchronous warehouse delete, pending-delivery cutoff and retries, local deletion only on success: `src/maintenance.rs:26-78`; tests/maintenance at175,286.
- Retrying deleted-namespace tombstones, independent warehouse/storage cleanup, repeated late-export reconciliation, bounded namespace deletion: `src/cleanup.rs:13-79`; tests/cleanup.
- Reconciliation of native PG event delivery/usage at `src/maintenance.rs:117-146` substitutes materialized-rollup rebuild where rich analytics derives from canonical facts. Lack of identical Rails daily/rollup jobs alone is not a capability gap.
- Authentication/OAuth/MCP expired record pruning exists (`src/maintenance.rs:83-111`); old delivered mail/push/purchase/billing jobs pruned, pending work preserved.
- OrphanedActionsCleanupJob is Rails-specific relational housekeeping; don't report it absent unless a native analogue of orphaned Action records can actually occur. No such native table surfaced.
- Large data volume, load/soak/timeout suitability of live canonical SQL, actual BigQuery/GCS delivery, Rails client replay, restore/rollback and existing-data reconciliation remain validation-only gates except for explicit A10 configuration gap.

## Suggested order of acceptance work

1. Fix/prove A4 referral semantics, A2 screen names, A1/A3 enrichment, and A6 merge-aware warehouse output.
2. Complete visitor table/detail and CSV contracts (A5/A7/A8) with paired Rails/Rust golden fixtures.
3. Restore bounded cache cleanup (A9) and actual BigQuery deletion permissions (A10).
4. Build/rehearse explicit native data import/cutover before claiming an existing Rails deployment can migrate.
5. Run the relevant native suite plus paired fixtures against both warehouses; then perform volume and live provider acceptance.
