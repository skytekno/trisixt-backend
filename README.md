# Trisixt backend

Trisixt is a Rust backend for multi-tenant deep linking, SDK events, analytics, and enterprise operations. The active runtime uses **Rust 1.98.1**, **PostgreSQL 18.6**, and **Redis 8.10.2**. Implemented enterprise features are enabled by default. Choose **ClickHouse or BigQuery via Pub/Sub** for analytics and **S3 or GCS** for object storage.

The rewrite implements these capability families with known gaps. The [2026-09-20 parity audit](docs/RUST_PARITY_AUDIT.md) records 31 missing, partial or materially changed behaviors and the separate legacy-data conversion gap. The retained Rails source is a reference inventory and is excluded from the Rust image. See [capability mapping and deployment boundaries](docs/REWRITE_STATUS.md) and [historical validation](docs/VALIDATION.md). Native UUIDs, schema and some API contracts differ from Rails; existing data needs a deliberate conversion before cutover.

## Local development

```sh
bin/setup
bin/dev
# In another terminal:
cargo run --locked -- worker
curl --fail http://localhost:3000/up
```

`bin/setup` creates `.env` from the example and generates persistent encryption keys only when `.env` does not exist, fetches Rust dependencies, starts PostgreSQL/Redis/ClickHouse/MinIO, initializes the object bucket, and applies SQL migrations. `GET /up` is a liveness endpoint. Register a user through the API, then create an instance with its authenticated token. There are no baked-in production accounts.

## Container runtime

```sh
cp .env.example .env
docker compose up --detach --build
```

The default Compose stack runs the Rust web and worker processes. Service ports bind to localhost; the app listens on port 3000. Redis requires the configured `REDIS_PASSWORD`; the app URL and health check use the same password. Change the example credentials and place the app behind a TLS ingress for a non-local deployment. PostgreSQL 18 data lives under `/var/lib/postgresql`; use new volumes or a deliberate database upgrade, not a PostgreSQL 16 volume mounted directly into PostgreSQL 18.

Commands are `trisixt serve` (default), `trisixt worker`, `trisixt migrate`, and `trisixt --version`. The runtime image contains the Rust executable and license only, runs as a non-root user, and does not require Ruby or Sidekiq.

Redis 8.10.2 was the latest stable upstream release verified on September 19, 2026. Its Docker Hub tag was unavailable, so `deploy/redis.Dockerfile` builds that exact version from the [official release archive](https://download.redis.io/releases/) with a pinned SHA256. It includes server TLS support, but the Rust Redis client currently lacks TLS features (audit O5). Optional Redis modules are not used by the application.

## Providers

`.env.example` documents provider selection and credentials. Local defaults use ClickHouse and S3-compatible MinIO. For native AWS S3 remove the local `AWS_ENDPOINT` and `AWS_ALLOW_HTTP` values. For Docker, set `COMPOSE_AWS_ENDPOINT` to your regional S3 endpoint and `AWS_ALLOW_HTTP=false`. For GCS set `STORAGE_BACKEND=gcs`, `STORAGE_BUCKET`, and Application Default Credentials (or `GCS_CREDENTIALS` pointing to a service-account file).

For BigQuery set `ANALYTICS_BACKEND=bigquery`, `GOOGLE_CLOUD_PROJECT`, `PUBSUB_TOPIC`, and the BigQuery dataset/table/location. The [Google deployment module](deploy/google/README.md) provisions the topic, export subscription, table, IAM, and optional GCS bucket. Publishing to Pub/Sub is asynchronous; BigQuery export requires the deployed subscription and its IAM.

Enterprise OIDC and store-verification configuration is documented in [enterprise contracts](docs/ENTERPRISE.md). See the capability mappings for [billing](docs/parity/BILLING.md), [accounts and notifications](docs/parity/ACCOUNTS_MESSAGING.md), [domains, imports and MCP](docs/parity/CONNECTIVITY.md), and [analytics](docs/parity/ANALYTICS.md).

Set a persistent `TRISIXT_ENCRYPTION_KEY` (32 random bytes, base64) for account secrets and queued mail; import credentials use the separately documented `MIGRATION_ENCRYPTION_KEY`. Run the worker alongside the web service. `CORS_ALLOWED_ORIGINS` accepts comma-separated frontend origins and defaults to `ACCOUNT_FRONTEND_URL` when supplied; explicit origins enable credentialed browser requests. Without either setting, bearer-token SDK requests use wildcard CORS without cookies. Only list trusted reverse-proxy addresses in `TRUSTED_PROXY_IPS` so forwarded IPs cannot spoof deferred matching.

## Validation

Follow the [testing guide](docs/TESTING_GUIDE.md) for local checks, the BigQuery/GCS/MinIO acceptance matrix, PostgreSQL upgrade and data-conversion rehearsals, and release evidence.

```sh
cargo install --locked cargo-audit
scripts/check.sh
```

After building an image, `IMAGE_NAME=your-image scripts/image-smoke.sh` verifies non-root execution, migrations, health/readiness and invalid-worker startup using a separate disposable PostgreSQL instance.

The check runs formatting, Clippy with warnings denied, branding and Compose validation, all Rust tests (including ignored integration tests) against an isolated PostgreSQL 18.6/Redis 8.10.2/ClickHouse/MinIO stack, and the dependency security audit. Test containers and volumes are removed on exit. Set `KEEP_TEST_STACK=1` only when diagnosing a test failure. Test Redis disables protected mode only on its isolated network and localhost port. Ports and test URLs can be overridden; see `scripts/integration.sh`. Real Google Cloud IAM, Pub/Sub-to-BigQuery export and GCS credential validation require a cloud project and are separate from local contract tests.

`cargo test --locked --all-targets --all-features` runs local tests; database/provider integration tests require their documented `TEST_*` environment variables. Existing Rails tests describe reference behavior and do not prove Rust compatibility.

## License and provenance

The original copyright and license notices in [LICENSE](LICENSE) and [ee/LICENSE](ee/LICENSE) are preserved unchanged. Rebranding and enabling feature flags do not alter those license terms. These original legal notices are the intentional exception to the product-name replacement.
