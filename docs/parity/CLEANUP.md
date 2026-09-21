# Deletion and worker lifecycle

> Audit update (2026-09-20): this is an implementation map, not full-parity certification. Read the [confirmed gaps and acceptance scenarios](../RUST_PARITY_AUDIT.md) before relying on these coverage claims.

Migration `0051_deleted_namespaces.sql` adds tombstones before project and instance deletion. The queue deliberately has no foreign keys: deleting a project, an instance or the last account administrator cannot cascade away the work needed to remove cloud objects. A transaction rollback also rolls back its tombstone. Retired identifiers cannot be reused for a new tenant.

`cleanup::dispatch_once` runs in the native worker. Project jobs synchronously delete the project's ClickHouse/BigQuery rows and independently remove its `projects/{uuid}/` S3/GCS namespace. Instance jobs remove the instance namespace used by usage exports. Prefix checks enforce an exact namespace boundary, and each pass deletes at most 250 objects. Failures retain the tombstone with a redacted error, attempt count and exponential retry schedule. The warehouse and storage completion times are separate, so one provider's outage does not block deletion from the other.

Successful tombstones remain and reconcile hourly. This is necessary for Pub/Sub: publication acknowledgment can precede export to BigQuery, so a single immediate DELETE cannot prove that no late event will arrive. The relational project disappears immediately; cloud deletion is asynchronous and its last successful pass is recorded. Tombstones must not be removed while delayed deliveries remain possible.

Asset uploads hold the project row until remote upload completes. Export uploads hold their durable job row through upload and cursor acknowledgment. Project/instance cascades wait for these writers before committing the tombstone, so cleanup cannot complete ahead of an already-running upload. The event outbox likewise holds its row through provider publication; cascades wait for that transaction, with the additional delayed-BigQuery reconciliation described above.

The worker supervises all periodic jobs. An unexpected child exit stops the process so its service supervisor can restart it. A mail queue with no SMTP configuration reports a health error; it is not counted as successful delivery. The local bootstrap generates a persistent account-encryption key only when creating a new `.env`, and preserves existing configuration.

`tests/cleanup.rs` verifies bounded object deletion and namespace isolation, rollback behavior, provider failure/retry, delayed-write reconciliation, identifier reuse refusal, instance/project cascade cleanup, and deletion waiting for an in-flight project writer. Provider tests separately verify complete-project warehouse DELETE requests. Live cloud IAM and actual Pub/Sub export delays remain deployment validation steps.
