# Native enterprise configuration

`TRISIXT_EE` defaults to `true`. Audit, SCIM, OIDC and purchase verification code ship in the same Rust executable. Explicit `false` disables access to enterprise endpoints. External provider credentials and configuration remain necessary.

## OIDC

The operator defines profiles through `OIDC_PROVIDERS_JSON`, keyed by a short provider name. Each profile contains `issuer`, `client_id`, optional `client_secret_env` (an environment variable beginning `OIDC_CLIENT_SECRET_`), and optional `allowed_origins` for provider discovery endpoints on other trusted HTTPS origins. Set `OIDC_REDIRECT_URL` to the externally reachable HTTPS `/auth/oidc/callback` endpoint registered with your provider. Tenants select an existing profile; they cannot supply arbitrary discovery URLs.

```dotenv
OIDC_PROVIDERS_JSON='{"corporate":{"issuer":"https://id.example.com","client_id":"trisixt","client_secret_env":"OIDC_CLIENT_SECRET_CORPORATE","allowed_origins":[]}}'
OIDC_REDIRECT_URL=https://api.example.com/auth/oidc/callback
# Inject OIDC_CLIENT_SECRET_CORPORATE through the deployment secret store.
```

Instance administrators configure `PUT /api/v1/instances/{id}/sso` with `{"provider_key":"corporate","enabled":true}`. Existing authenticated users call `POST /api/v1/instances/{id}/sso/link` with their bearer token, then navigate the browser to the returned JSON `authorization_url`. The response also sets the state cookie. Subsequent login begins at `GET /auth/oidc/{id}/start`, which directly redirects the browser. Identity binding uses the issuer and subject rather than automatically claiming an existing account by email. The authorization flow uses PKCE, browser-bound state and nonce, verifies ID-token signatures/claims, and rejects arbitrary provider redirects. The callback returns JSON containing the application bearer token. Browser binding uses a Secure HttpOnly cookie, so the browser flow requires HTTPS. Instance administrators manage domain policy through PUT `/api/v1/instances/{id}/sso/policy` using `enforced`, `jit_provision`, optional `admin_claim_value`, and `domains`. GET on that route returns DNS proof records; POST `/sso/verify-domains` validates the actual DNS TXT records. Enforcement requires an enabled provider and a verified domain. Password registration, login, reset and refresh are rejected for verified enforced domains; `SUPER_ADMIN_EMAILS` is an explicit operator-managed break-glass exception. Enabling enforcement revokes existing dashboard and MCP sessions with user-row locks, including concurrently rotated credentials.

JIT is opt-in and requires a verified email domain. It can create a new identity or bind an account already managed by the same instance; it cannot claim an unmanaged existing account or an account belonging to another organisation. Every subsequent sign-in rechecks configured verified domains and applies matching IdP admin claims. The owner role is preserved. SCIM deactivation prevents sign-in and permanently revokes current sessions; reactivation does not restore old tokens. DELETE `/sso/link` unlinks the identity and revokes the user's sessions; callbacks recheck the binding after acquiring the user lock.

The SCIM API provisions users with instance-scoped revocable bearer tokens. `/api/v1/identity/sso/discover?email=...` locates a verified domain's connection. Instance administrators can issue read-only, scoped, revocable SIEM credentials at `/api/v1/instances/{id}/audit_export_tokens`; these read the immutable audit stream and chain head. Live IdP interoperability remains a deployment validation step.

## Store-verified purchases

`TRISIXT_IAP_PROFILES` is a JSON object keyed by project UUID. A project can define Apple, Google Play, or both profiles:

```json
{
  "11111111-1111-4111-8111-111111111111": {
    "apple": {
      "issuer_id": "YOUR_APP_STORE_CONNECT_ISSUER",
      "key_id": "YOUR_KEY_ID",
      "private_key_path": "/run/secrets/app-store-key.p8",
      "bundle_id": "com.example.app"
    },
    "google": {
      "package_name": "com.example.app",
      "service_account_path": "/run/secrets/google-play-service-account.json"
    }
  }
}
```

The Google service account file is optional when Application Default Credentials have the required Android Publisher access. Mount credential files read-only and grant the container user access; do not bake them into images. Apple credentials are App Store Connect API credentials. The project's `test`/`production` environment determines the required store environment.

`POST /api/v1/sdk/purchases/verify` uses the project's SDK key and accepts `visitor_id`, `provider` (`apple` or `google`), `transaction_id`, `product_id`, `purchase_kind` (`one_time`, `subscription` or `rental`), and Google's `purchase_token` when applicable. Client-supplied prices and receipt payloads are rejected. The server fetches purchase and pricing evidence from fixed authenticated store API endpoints. The app must set Apple's `appAccountToken` or Google's obfuscated external account ID to the visitor UUID when making the purchase.

Purchases feed a signed revenue ledger covering sales, partial and full refunds, refund reversals, cancellations, renewals and subscription product changes. Google bundle orders produce separate product entries. Amounts use integer currency nanounits; USD conversions use persisted exchange rates, and refunds reuse their purchase's original conversion. Revenue endpoints report net amounts with `includes_refunds=true`, per-currency totals and unconverted transactions. Referral attribution remains available after a link is edited or deleted. The explicitly SDK-reported `/api/v1/sdk/add_payment_event` endpoint records external payments with `verified:false`; it cannot mark client-reported amounts as store-verified.

Register Apple notifications at `POST /api/v1/iap/apple/{test|production}/{project_id}` and Google authenticated Pub/Sub push at `POST /api/v1/iap/google/{instance_id}`. Apple notification signatures are checked against the pinned official Apple G3 certificate chain; Google JWTs must match `GOOGLE_PUBSUB_AUDIENCE` and `GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL`. Processing verifies authoritative store state, persists retries and rejects stale or duplicate adjustments. Worker jobs reconcile App Store history and Google orders, update subscription states, refresh exchange rates and fill missing attribution. Instance administrators can enable revenue collection at `PUT /api/v1/instances/{id}/revenue_collection`.

Project administrators download `GET /api/v1/projects/{id}/purchases/google_configuration_script` for Google Play setup. Run the returned script as `bash trisixt_android_gcloud_setup.sh GCP_PROJECT_ID [NEW_CREDENTIAL_FILE]`. It creates or updates the RTDN topic, its authenticated push subscription and narrowly scoped publisher/token-creator grants. The optional credential destination creates a service-account key with restrictive file permissions; ADC deployments can omit it. The script uses the configured push identity/audience when present and otherwise prints the environment values to configure. Set `TRISIXT_PUBLIC_BASE_URL` to the service's HTTPS origin when `https://SERVER_HOST` is not the public origin. The download does not perform cloud operations. These settings follow [Google's authenticated push contract](https://docs.cloud.google.com/pubsub/docs/authenticate-push-subscriptions) and [Play's RTDN publisher requirements](https://developer.android.com/google/play/billing/getting-ready).

Stripe checkout, portal, paid-through cancellation, usage-based billing and enterprise subscription administration are native endpoints. Quota enforcement counts distinct monthly active visitors and respects paid enterprise subscriptions, configured exemptions and `TRISIXT_SELF_HOSTED=true`. See [billing and purchase endpoint mappings](parity/BILLING.md) for exact inputs, environment variables, background worker hooks and regression coverage. Live Apple, Google, Stripe and IdP validation requires operator credentials; local regression tests cover HTTP contracts, signed tokens, database transactions, retry ordering and lifecycle accounting.
