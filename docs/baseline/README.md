# MAN-5 source baseline and recovery

The latest local execution record is [runs/MAN-5.json](runs/MAN-5.json). It records
the external recovery snapshot, exact source identity, validation logs and Linear
sync status. Run records and large logs are evidence alongside the source archive;
they are excluded from the archive's source identity to avoid self-referential
hashes. Copy the execution record alongside the archive for long-term retention.

The shared [fixture contract](../testing/BASELINE_FIXTURES.md) and
[evidence template](../testing/EVIDENCE_TEMPLATE.md) define request, identity,
provider and numeric result conventions for subsequent tasks.

The reviewed selection is [SELECTION.json](SELECTION.json). It retains native Rust
source, SQLx migrations, tests, deployment definitions, documentation, and the
Rails implementation/tests used as parity references. Existing branding assets
and the public Apple root certificate are source inputs. Root environment examples
and `.env.test` contain synthetic/local values. They must never receive operator
credentials. Retaining Rails sources does not enable Rails data conversion; M1
remains deferred.

The selection excludes Git metadata, local agent preferences, generated graph
analysis, build/provider caches, runtime files, actual environment files, mounted
credentials, operator deployment configuration, and generated baseline archives
or run records. New root files or directories require an explicit selection
change. All descendants of allowed source directories are included unless an
explicit exclusion applies, so review new files before every baseline capture.
Exclusion counts are counts of observed entries: an excluded directory counts
once, and its descendants are not traversed or counted.

Two intentional private keys are synthetic test inputs:

- `tests/fixtures/apple-test-key.p8`: the offline Apple fixture signing key.
- `tests/oidc.rs`: the embedded RSA key for the local mock OIDC issuer.

Their allowances pin the SHA-256 of the recognized key material, so replacing or
adding a key in either file still stops capture. They do not permit production use. Other recognized private key
material and high-confidence provider token patterns stop capture; diagnostic
output contains paths and pattern names only. This narrow scanner supports the
reviewed selection, and does not prove arbitrary source text contains no secret.

## Capture and verify

Run after source writers have finished. Choose a new directory outside this
checkout; its parent must already exist. No files are staged or committed and
the Git index is checked before/after capture. Existing backups and the checkout
are preserved. On hosts where the default Xcode tools cannot run Git, select the
already-installed command-line tools only for this command:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  python3 scripts/capture_baseline.py capture \
  ../trisixt-man5-baseline-20260920

python3 scripts/capture_baseline.py verify \
  ../trisixt-man5-baseline-20260920
```

The snapshot contains `source.tar.gz` and `manifest.json`. The manifest records
every selected path, byte length, permission mode, SHA-256, exclusions, synthetic
key allowances, current Git revision (null before the first commit), branch and
index hash. Unavailable Git tools fail capture; only a successfully inspected
unborn branch has a null revision. `source_sha256` hashes the canonical sorted source inventory including
file hashes and modes. `archive_sha256` hashes the exact compressed archive. Git
revision and source hash are separate: a worktree snapshot may differ from HEAD.

Capture immediately verifies the archive hash, validates that every member is an
expected regular file, and restores into a fresh temporary directory. It then
rehashes restored bytes and checks permission modes. Absolute paths, traversal,
symlinks, hardlinks, duplicate/unexpected/missing members and altered bytes/modes
fail verification. Source selection and Git metadata are checked again after
archiving to detect concurrent edits. The temporary recovery directory is removed afterward. A
failed capture is retained with an `INCOMPLETE` marker and must not be used.

For an actual recovery, first verify the saved snapshot using a trusted copy of
this script. Extract `source.tar.gz` into a new empty directory, keeping the
original checkout intact. Recreate operator configuration and separately
provisioned resources; none belong in this archive. Initialize Git in the
recovered directory only after reviewing its contents. This archive preserves
source bytes and executable modes, not Git history, external services or data.
Hashes establish integrity against the saved manifest, not an external signature.

## Local test safety and interpretation

`scripts/check.sh` runs formatting, locked Clippy, configuration checks, source
capture/recovery regression tests, all native
tests including ignored infrastructure tests, and the dependency advisory audit.
The integration script provisions PostgreSQL 18.6, Redis 8.10.2, ClickHouse and
MinIO. It removes its Compose project and volumes on exit by default. Always
inventory existing containers/volumes first and use a unique
`TEST_COMPOSE_PROJECT` with free `TEST_POSTGRES_PORT`, `TEST_REDIS_PORT`,
`TEST_CLICKHOUSE_PORT` and `TEST_S3_PORT` bindings. Do not inherit `TEST_DATABASE_URL`,
`TEST_REDIS_URL`, `TEST_CLICKHOUSE_URL` or `TEST_S3_ENDPOINT` pointing elsewhere;
the integration script otherwise honors those overrides. It sets `AWS_ENDPOINT`
to the selected test S3 endpoint. Never use production provider credentials or
shared service URLs for these tests, and never prune unrelated Docker resources.

The shared PostgreSQL fixture creates per-test schemas. Several current fixture
configs hard-code Redis localhost ports, while worker/E2E tests use
`TEST_REDIS_URL`; check relevant test behavior before changing bindings.
`scripts/check.sh --unit` leaves infrastructure tests ignored and is not the full
gate. A passing baseline establishes the measured current local behavior. It
does not close the 31 parity findings or the separate live-provider, client,
persistent recovery and release-candidate gates.
