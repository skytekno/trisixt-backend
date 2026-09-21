# Enterprise, billing, purchases, and communications parity audit

Read-only source audit, 2026-09-20. No application tests, external API calls, provider operations, or repository edits were performed. Findings below compare retained executable Rails behavior with native Rust handlers/schema, rather than relying on parity documents. Priority is proposed release importance, not a claim of runtime reproduction.

## Confirmed material gaps

### E1 — P1: deleting an instance leaves its Stripe subscription uncanceled

- Rails: `app/services/instance_provisioning_service.rb:66-79` explicitly calls `StripeService.cancel_subscription(subscription)` before scheduling deletion.
- Rust: `src/core_api.rs:129-143` only deletes the instance in PostgreSQL. `src/accounts.rs:491-505` does the same for an orphaned instance when its last administrator deletes their account. `migrations/0010_billing.sql:5` cascades away `billing_subscriptions`, so the local provider subscription identifier is lost. `src/cleanup.rs:27-74` only purges warehouse rows and object namespaces; no Stripe cancellation is queued or performed. The sole native cancellation HTTP call is the separate billing cancel endpoint at `src/billing.rs:259-272`.
- Scenario: delete a paying organization directly without first using the billing cancel endpoint. The local organization disappears while Stripe continues billing; neither the worker nor the tombstone can recover the deleted subscription reference.
- Acceptance: record a durable cancellation obligation before deleting the local subscription, verify cancellation/retry/idempotency, and cover direct organization deletion plus last-admin account deletion.

### E2 — P1: SCIM no longer requires an active SSO connection or a verified email domain

- Rails: `config/initializers/scimitar.rb:5-10` authenticates only an active connection; `ee/app/models/sso_connection.rb:53-56` defines active as enabled, entitled and having a verified domain. `ee/app/controllers/scim_v2/users_controller.rb:20-24,69-73` requires the user email to belong to a verified domain and `:13,51` refuses operator accounts.
- Rust: `src/enterprise.rs:100-117` permits any instance administrator to mint a SCIM token without an SSO connection. `:139-157` validates only the instance token and global enterprise flag. `:293-326` creates a global user for any syntactically valid unused email; it does not consult verified domains or operator-email rules. `src/oidc.rs:340-370` removes the SSO connection without deleting these independently instance-bound tokens (`migrations/0004_enterprise.sql:49-64`).
- Scenarios: an instance with no verified domain provisions an address in another organization's domain; an old SCIM token continues provisioning after its SSO connection is disabled/deleted. This also allows reservation of unused operator addresses. Existing users cannot be hijacked via this path because Rust rejects all existing emails; the narrower verified risk is unauthorized account reservation/provisioning and stale provisioning access.
- Acceptance: explicitly restore the prior lifecycle/domain/operator gates or approve the changed product policy and implement equivalent account-ownership protection. Test no connection, disabled/deleted connection, no verified domains, foreign domain and operator email.

### E3 — P1: SCIM cannot deactivate an administrator even when another administrator remains

- Rails: `ee/app/controllers/scim_v2/users_controller.rb:90-101` permits administrator deactivation except the last admin, and revokes the user's sessions.
- Rust: `src/enterprise.rs:366-375` returns forbidden for every role other than `member`, before reaching role deletion and session revocation at `:396-402`.
- Scenario: SCIM creates a member, an IdP admin claim promotes them, then the IdP disables them while another owner/admin remains. SCIM returns forbidden, leaving their membership and sessions active.
- Acceptance: test member, nonlast admin, last admin, owner and operator deprovisioning with explicit agreed policy; nonlast managed admins need a functioning IdP deactivation path.

### E4 — P2: much of retained SCIM lifecycle/profile interoperability is missing

- Rails mappings: `ee/app/models/scim_user.rb:7-23,34-58` support separate UPN/email, name components, display name, external ID and queryable externalId/emails. `ee/app/controllers/scim_v2/users_controller.rb:10-18` adopts eligible existing/invited users. Tests explicitly prove invited/member adoption (`ee/test/integration/scim_users_test.rb:101-118`), externalId lookup (`:141-147,171-175`), Entra string `active: "False"` (`:178-195`), and rename within verified domains (`:228-237`).
- Rust: `src/enterprise.rs:225-238` returns email as UPN and only accepts `userName eq` filtering; `:268-277` ignores separate `emails` and `name` fields; `:301-311` rejects every existing email; `:381-384` forbids UPN rename; `:433-449` supports only boolean active PATCH operations. Display-name PUT updates only `scim_users.display_name`, not the normal user's `name`.
- Scenarios: adopting existing tenant members into SCIM fails; an IdP reconnecting by external ID fails; UPN differs from work email and the wrong identity address is stored; profile rename or standard name/email PATCH fails; the retained string-false Entra payload cannot deactivate.
- Acceptance: build an IdP contract fixture from these retained cases; establish which subset is intentionally supported instead of declaring general SCIM parity.

### E5 — P2: retained enterprise OIDC UPN fallback is absent

- Rails: `ee/app/services/sso_connections/enterprise_login.rb:37-52` accepts `preferred_username` when email is absent, mapping a provisioned SCIM UPN to its work email and still checking verified domain ownership.
- Rust: `src/oidc.rs:521-538` requires `email: String` and `email_verified: bool`; `:605-607` rejects false verification. There is no preferred_username/SCIM-UPN fallback.
- Scenario: the existing enterprise IdP issues a correctly signed token with preferred_username and provisioned SCIM identity but no email/email_verified claims. Native sign-in rejects it before identity resolution.
- This can be a deliberate stronger claim policy, but it is an explicit interoperability change rather than a live-test-only uncertainty. Acceptance should prove the actual IdP claim set or implement the retained controlled fallback.

### E6 — P2: purchase history loses pagination/search/sort and refund/cancellation event rows

- Rails: `ee/app/services/purchase_query_service.rb:2-26` supports event-type term filtering, an allowlisted sort column/direction, date range and pagination. The relation is purchase events, including their event types (`:31-35`); `ee/app/serializers/purchase_event_serializer.rb:2-7` exposes event type and processing/store state.
- Rust: `src/purchases.rs:655-686` accepts only from/to/limit, returns the first at most 1000 `verified_purchases`, and exposes no cursor/offset/search/sort. Refunds and cancellations live separately in `purchase_ledger` (`src/purchase_lifecycle.rs:427-532`) and this query never joins them.
- Scenarios: a busy customer cannot traverse all transactions in the selected interval, search refunds, or inspect a refund/cancellation's event row through the purchase browser. Narrower timestamp queries are not a reliable substitute for pagination when many rows share timestamps.
- Acceptance: traverse more than 1000 same-timestamp transactions without omissions/duplicates and display original sale plus its signed adjustments with verified/reported distinction.

### E7 — P2: per-product revenue reporting is absent

- Rails: `ee/app/controllers/api/v1/purchases_controller.rb:20-39` exposes filtered, sorted, paginated product revenue; `ee/app/services/revenue_metrics_query.rb:13-24,38-58` computes per-product totals, ARPU/ARPPU and paginates; its retained legacy query also exposes repeat purchases, LTV, platforms and cancellation counters (`:65-106`).
- Rust: `src/purchases.rs:688-708` exposes project totals/currency gross sales only. `src/purchase_lifecycle.rs:1129-1154` computes project aggregates/by-currency/daily series, with no product grouping/filter or pagination. `src/analytics_api.rs:686-694` supplies project-wide ARPU/ARPPU, not product rows.
- Scenario: the dashboard cannot compare two products by revenue/units/repeat buyers/ARPU or filter and sort its product revenue table. All required purchases may be stored, but the retained query capability is missing.
- Acceptance: independent two-product, two-platform sale/refund/renewal fixtures should reproduce the product report and stable pagination.

### E8 — P2: audit trail retains chaining but loses forensic content and failed-login events

- Rails: `ee/app/models/audit_event.rb:38-53` persists immutable structured actor/target, redacted before/after changes, outcome, IP, user agent and request ID; `app/services/audit.rb:24-33` produces before/after diffs; `app/controllers/concerns/audit_context.rb:10-19` captures request context. `app/controllers/custom_tokens_controller.rb:44-57` records known-user failed login with failure outcome and actor-via=password.
- Rust: `migrations/0004_enterprise.sql:2-24` stores actor UUID, action, target UUID, details, timestamps and hashes, but none of those forensic context columns. Generic triggers at `:30-39` preserve only name/role/user_id/project_id from the current or deleted row, with no old/new diff. `src/accounts.rs:224-228,264-291` records only successful login; there is no native failed-login audit call. `src/enterprise_admin.rs:353-365` resolves actor_email by a live users-table join, rather than immutable actor snapshot.
- Scenarios: after account rename/deletion, historical actor-email filtering loses the original identity; an investigator cannot connect a link/config mutation to source IP/request or see the changed values; password attack failures are absent from the tenant log.
- Native append-only triggers exist (`migrations/0008_audit_immutability.sql`), so this is not a claim that audit logging or tamper resistance is absent. The independent Rails chain-head/verifier behavior (`ee/app/models/audit_event.rb:71-97`) also lacks a native operational equivalent; native head endpoints only read the current last event.
- Acceptance: compare forensic fields, failed-login records, exact mutation before/after data, actor deletion survival, secret redaction and chain verification against the retained audit cases.

### E9 — P2 / explicit product scope change: tenant provider credential administration now requires operators

- Rails OIDC: tenant admins set issuer/client_id/client_secret and expiry through `ee/app/controllers/api/v1/sso_connections_controller.rb:13-18`; its serializer reports expiry status. Rust `src/oidc.rs:70-75,108-118,271-308` only selects an operator-preconfigured OIDC_PROVIDERS_JSON profile and has no secret-expiry field.
- Rails push/IAP: `app/controllers/api/v1/configurations_controller.rb:26-78,163-176` supports tenant uploads of APNs certificate/password, Firebase certificate/project and Apple/Google store API keys. Rust push is operator-managed PUSH_PROFILES_JSON (`src/messaging.rs:332-363`), with tenants selecting allowlisted references (`:365-397`); native APNs profiles support team/key/bundle/key-file authentication rather than uploaded certificate authentication. IAP reads operator-managed TRISIXT_IAP_PROFILES and key file paths (`src/purchases.rs:20-38,600-609`).
- Scenario: existing customers cannot onboard or rotate their existing SSO/push/store credentials through the product; APNs certificate users need key-based reconfiguration. Provider transport exists, but the self-service administration capability is materially changed.
- Acceptance: record explicit approval for operator-only onboarding or restore secure tenant credential management and rotation. Treat changing routes separately from this actor/ownership change.

## Observable behavior / wire changes to keep separate from missing capabilities

- Billing `/usage` and `/subscription` both route to `details` (`src/billing.rs:793-802`). It returns native subscription rows, raw Stripe invoice and current-month MAUs (`:322-333`), rather than Rails normalized amount, payment date, billing-cycle paid MAUs and usage-summary envelope (`app/services/subscription_billing_service.rb:70-127`). Much of the raw financial data remains available, so this is principally client-contract/semantic migration work, not total loss of billing reads.
- Native free quota rejects a new distinct visitor as soon as count >= allowance (`src/billing.rs:545-556`), while public quota_exceeded and exceeded alerts require count > allowance (`:574-592`). Rails permits usage to exceed and then sets exceeded (`app/jobs/disable_quotas_job.rb:53-61`). In a clean capped native instance, the rejected next visitor cannot increase the ledger beyond the allowance; the exceeded state/alert is therefore not normally reached. Decide intended cap/alert semantics and test the boundary.
- Native quota warnings target owners/admins (`src/accounts.rs:1118`) rather than all instance users (`app/jobs/quota_alert_job.rb:27-38`). Native SMTP sends text-only bodies (`src/accounts.rs:1038-1048`) instead of retained HTML mail templates. Both are explicit delivery/content behavior changes.
- Native SDK notification URLs are relative (`src/messaging.rs:203`), versus Rails `Notification#access_url` via `app/serializers/notification_message_serializer.rb:7`; client base-URL handling must be migrated. SDK identifiers, pagination sizes, payload shapes and method differences require compatibility fixtures.
- Authoritative store validation now rejects SDK-provided financial evidence and requires app-account UUID binding (`src/purchases.rs:211-259,340-381`). The retained Apple path allowed existing one-time SDK price to win (`ee/app/services/apple_purchase_validator.rb:66-68`, `ee/app/services/purchase_event_creator.rb:30-33`). Preserve the stronger native money validation, but explicitly migrate client purchase binding/configuration.

## Coverage inventory inspected

| Family | Native substance present | Remaining audit boundary |
|---|---|---|
| Stripe | checkout/customer/portal, cancel/pause, raw-byte HMAC inbox, hydrated subscription snapshots, usage reporting, discounts, free/self-hosted/enterprise exemptions | Deletion lifecycle gap above; live Stripe API/account/version compatibility not run |
| Store revenue | Apple chain verification, Google authenticated push, provider purchase lookup, integer money, durable inbox, signed refund/cancel/reversal ledger, product-change subscription state, reconciliation, FX and late attribution | Query/admin gaps above; full bundle/partial-refund/out-of-order replay matrix not independently executed |
| Messaging | segment/platform targeting, scheduled fanout, in-app/read/unread/archive, sanitizer, FCM/APNs adapters, durable retry, token invalidation | Real device delivery/transport not run; multi-device targeting semantics need differential fixtures |
| Mail | encrypted outbox, SMTP STARTTLS/implicit TLS, stable Message-ID, retry and account/quota/export/migration mail integration | Actual mail deliverability/content URLs not run; recipient/template behavior differs |
| Enterprise | OIDC PKCE/state/nonce/signatures, controlled JIT, domain ownership/enforcement, explicit linking/unlinking, refresh/session revocation, SCIM, chained audit and read-only revocable export tokens | SCIM, UPN, audit and self-service administration gaps above |

## Residual uncertainties and release evidence

This review does not certify every retained Rails example. Prior native tests and protocol mocks are useful but are not an independent Rails/Rust differential run. Add paired fixtures for the listed gaps, then run real sandbox Stripe/Apple/Google lifecycle flows, an actual IdP/SCIM connector, controlled mail inbox and FCM/APNs devices. Those live checks remain validation gates; they are not evidence that the provider implementations are missing. No external state was changed during this audit.
