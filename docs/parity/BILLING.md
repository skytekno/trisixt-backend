# Billing and purchase capability mapping

> Audit update (2026-09-20): this is an implementation map, not full-parity certification. Read the [confirmed gaps and acceptance scenarios](../RUST_PARITY_AUDIT.md) before relying on these coverage claims.

The Rust service retains billing and revenue capabilities with UUID tenant/project identifiers. Monetary values use signed integer currency nanounits; USD conversion uses a persisted exchange rate and refunds reuse their original purchase conversion. API responses distinguish authoritative store verification from explicitly SDK-reported external payments.

| Rails source / capability | Rust implementation | Regression evidence |
| --- | --- | --- |
| `app/controllers/api/v1/payments_controller.rb`, `app/services/subscription_billing_service.rb`: checkout, customer, portal, cancel, details, usage | `billing.rs`, Stripe authenticated form client, stable idempotency keys, tenant customer/session/subscription records | `tests/billing.rs`: HTTP auth/form/idempotency, paid-through cancellation |
| `app/services/stripe_service/webhook_handlers.rb`, `test/services/stripe_webhook_ordering_test.rb`: late/duplicate webhooks, active/trialing/dunning/paused states | Timestamped HMAC verification of raw bytes; durable `billing_webhooks`; current subscription hydration; timestamp watermark; scheduled cancellation preserves entitlement | Signature/replay/raw-byte checks; stale snapshot and retry/idempotency tests |
| `app/jobs/disable_quotas_job.rb`, `quota_alert_job.rb`, `app/services/project_service.rb`: calendar-month distinct MAU, free allowance, enterprise/free-pass/self-host exemptions, threshold alerts | `record_usage`, `enforce_project_quota`, `report_usage`, durable `billing_alerts`; root calls usage only for countable events; three-day alert cooldown | Real PostgreSQL monthly deduplication and enterprise entitlement checks |
| `app/services/stripe_service.rb`: metered usage and threshold coupons | Stripe usage records (`action=set`), percentage tiers, free-allowance USD19.99 coupon, removal below threshold; persisted usage reports | HTTP client contract and billing workflow tests |
| `app/services/enterprise_subscription_service.rb`: enterprise dates/MAU limits/admin edits | `enterprise_subscriptions`, one active subscription per instance, admin-key protected create/update, paid entitlement helper | Paid entitlement regression and schema checks |
| `ee/app/services/apple_purchase_validator.rb`, `google_purchase_validator.rb`: authoritative SDK purchases | `purchases.rs`: App Store Server API ES256 JWT; Android Publisher product/subscription + Orders API; exact app/environment/account/product/token binding | Provider payload, forged amount, precision/overflow, tenant race, redirect credential isolation, signed JWT tests |
| `app/services/platform_configuration_service.rb#google_configuration_script`, Android setup template | Project-admin download of native shell setup; tenant endpoint, authenticated audience/service account, scoped publisher grants, optional protected credential file | Shell syntax and injection-safe rendering; authenticated project admin download tests |
| `ee/app/controllers/api/v1/iap_controller.rb`, Apple/Google webhook services | `purchase_lifecycle.rs`: Apple ES256 JWS chain pinned to official Apple G3 root and purpose OIDs; Google push JWT issuer/audience/service-account validation; durable notification inbox | Forged Apple/root rejection; durable failure retry; mapping regressions |
| Apple subscription/refund handlers, Google subscription/refund/bundle/quantity/rental handlers | Signed `purchase_ledger`; per-product bundle entries, rental classification, original subscription linkage, renewal/product switches, pause/grace/deferred states, partial/full refund/reversal bounds and exact original FX; cancellations once per transaction | Concurrent cumulative refunds; refund-to-reversal round trip; stale refund ordering; product switch / late-old-transaction tests |
| `ee/app/services/subscription_state_service.rb`, `purchase_attribution_service.rb`, SDK session tests | Durable subscription state; first known device/session; last-touch link lookup and immutable link/inviter snapshots surviving link deletion; late authoritative anonymous-account claim; fill-only attribution backfill | Late account/link attribution, existing account reassignment rejection, first-session preservation |
| `ee/app/services/sdk_payment_service.rb`: external non-store purchases | `/sdk/add_payment_event` stores `verification_source=sdk_reported`, supports signed adjustments, preserves currency/quantity/platform; explicitly returns `verified:false`; `store:true` directs to authoritative verify route | HTTP/PG reported payment workflow, source distinction, fabricated store request rejection, foreign-visitor refund rejection |
| Currency service and background purchase processing/retry jobs | Durable `fx_rates`, primary/fallback HTTP FX fetch, last good values retained; transactional reconciliation enrollment; daily paginated App Store history and Google current order reconciliation; persisted exponential retries | Unknown FX retained as unconverted; original purchase FX and retry persistence tests |
| Purchase revenue analytics and serializers | `revenue_metrics`: signed totals, units, cancellations, distinct first buyers/payers, per-currency totals/daily series; provider and reported platform filtering; root analytics adds its common filters/timezone contract | Signed EUR/USD workflow and duplicate/tenant isolation tests |

## Endpoint mapping

Native tenant-scoped billing prefix: `/api/v1/instances/{instance_id}/billing`.

| Legacy action | Native endpoint |
| --- | --- |
| Create subscription checkout | `POST .../billing/subscriptions` |
| Billing portal | `GET .../billing/stripe_portal` |
| Subscription details / cancel | `GET` / `DELETE .../billing/subscription` |
| Pause / resume | `PUT .../billing/subscription/pause` with `paused` |
| Current MAU / usage | `GET .../billing/mau`, `GET .../billing/usage` |
| Stripe webhook | `POST /api/v1/webhooks/stripe` |
| Operator usage report | `POST /api/v1/webhooks/send_stripe_quotas` with `x-api-key` |
| Enterprise subscription create / update | `POST /api/v1/admin/create_enterprise_subscription`, `PATCH /api/v1/admin/enterprise_subscriptions/{id}` |
| Revenue collection switch | `PUT /api/v1/instances/{id}/revenue_collection` |
| SDK store purchase | `POST /api/v1/sdk/purchases/verify` with `x-project-key` |
| SDK external payment | `POST /api/v1/sdk/add_payment_event` with `x-project-key` |
| Google Cloud configuration script | `GET /api/v1/projects/{id}/purchases/google_configuration_script` |
| Apple notification | `POST /api/v1/iap/apple/{test\|production}/{project_id}` |
| Google authenticated Pub/Sub push | `POST /api/v1/iap/google/{instance_id}` |
| Purchase list / revenue / subscription states | `GET /api/v1/projects/{id}/purchases`, `/purchases/revenue`, `/purchases/subscriptions` |
| Retry failed notification | `POST /api/v1/projects/{id}/purchases/notifications/{notification_id}/retry` |

Purchase verification input: `visitor_id`, `provider` (`apple`/`google`), `transaction_id`, `product_id`, `purchase_kind` (`one_time`/`subscription`/`rental`), Google `purchase_token`; optional `device_id`, `session_id`, `platform`. Client prices are rejected. External payment input instead takes `price_cents` per unit, `quantity`, `currency`, `event_type`, and optional `original_transaction_id` for adjustments. External adjustments require an existing original purchase belonging to the same visitor/project/product/currency.

## Worker and configuration contract

Root worker calls `billing::process_pending`, `billing::report_usage`, `purchase_lifecycle::process_pending`, `purchase_lifecycle::reconcile_due`, and `purchase_lifecycle::refresh_fx`. Ingestion acknowledges only persisted inbox entries. Errors retain pending entries with bounded exponential backoff. Subscription changes and all signed adjustments are idempotent. MAU is retained separately from event retention.

- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_STANDARD_PRICE_ID`, `TRISIXT_DASHBOARD_URL`; the explicit test client accepts a loopback HTTP mock server.
- Billing administration: `TRISIXT_ADMIN_KEY`; quotas: `FREE_MAU_COUNT` (10,000 default), `FREE_PASS_PROJECT_IDS`, `PUBLIC_GO_PROJECT_IDENTIFIER_ID`, optional tier threshold/percentage variables; `TRISIXT_SELF_HOSTED=true` bypasses commercial billing.
- `TRISIXT_IAP_PROFILES` is JSON keyed by project UUID. Apple profile: `issuer_id`, `key_id`, `private_key_path`, `bundle_id`. Google profile: `package_name`, optional `service_account_path` (otherwise ADC).
- Google push identity: `GOOGLE_PUBSUB_AUDIENCE`, `GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL`. Setup download origin: `TRISIXT_PUBLIC_BASE_URL` (HTTPS origin; defaults to `https://SERVER_HOST`). The setup script prints required identity settings and runs cloud operations only when the operator executes the downloaded file.
- EE defaults on through root configuration. Revenue collection can be disabled per instance.

Live Apple, Google and Stripe account calls require operator credentials and registered store products/subscriptions. Local tests use actual HTTP mock servers, signed synthetic JWTs and PostgreSQL; they do not claim live provider settlement verification. Official protocol references: [Google ProductPurchaseV2](https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.productsv2), [Google Orders](https://developers.google.com/android-publisher/api-ref/rest/v3/orders), [Apple certificate authority](https://www.apple.com/certificateauthority/), [Stripe usage records](https://docs.stripe.com/api/usage_records/create?api-version=2024-06-20).
