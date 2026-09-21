# Maintenance parity

> Audit update (2026-09-20): this is an implementation map, not full-parity certification. Read the [confirmed gaps and acceptance scenarios](../RUST_PARITY_AUDIT.md) before relying on these coverage claims.

`src/maintenance.rs` preserves the behavior of `AnalyticsRetentionDeletionJob`, `ClickhouseRollupRebuildService`, and `ReconcileLinkDimensionsJob` for the native canonical PostgreSQL design.

- Retention is scheduled durably per project using each instance's `delete_days`. A policy row lock prevents a concurrent retention extension from racing a deletion already in flight. ClickHouse deletion waits for mutations to complete and stops when the scoped mutation backlog exceeds 50. BigQuery uses parameterized DML and polls until the job completes. Provider failure schedules a retry and preserves local records.
- A pending analytics delivery lowers the deletion cutoff. Local deletion additionally requires that the event has no pending outbox record. Neither warehouse nor PostgreSQL cleanup claims a queued event was delivered. Purchases, signed revenue ledger, subscriptions, visitor identities and monthly billing usage are retained.
- `reconcile_range` is bounded to one project and at most 366 days. It repairs missing durable event delivery and missing monthly countable users, then records an audit event. Native analytics read the canonical view with current project/link/campaign dimensions and visitor aliases, eliminating the former stale materialized dimension copies. This is the replacement for separate CH rollup rebuild and dimension replay jobs.
- Hourly cleanup removes expired browser/OIDC/OAuth/account credentials and old delivered jobs. Refresh-token reuse records remain until the whole token family expires. Pending email/push/purchase/billing work is never age-deleted.

`tick(&AppState, &Analytics)` is the worker entry point. Migration `0050_maintenance.sql` stores schedules, retry state, cutoffs, results and failure status. Retention and reconciliation append tenant audit events.

`tests/maintenance.rs` verifies: actual ClickHouse event publication and synchronous tenant-scoped deletion; BigQuery parameterized deletion and asynchronous polling/errors; mutation-backlog protection; PostgreSQL retention failures/retry; preservation of pending events/purchases/billing usage; delivery repair and cleanup limited to sent jobs. Run using `scripts/integration.sh`; these tests require explicit PostgreSQL/ClickHouse endpoints when invoked independently. Live BigQuery DML requires the configured Google principal's query and table-data permissions.
