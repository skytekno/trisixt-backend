# Accounts and communications parity

> Audit update (2026-09-20): this is an implementation map, not full-parity certification. Read the [confirmed gaps and acceptance scenarios](../RUST_PARITY_AUDIT.md) before relying on these coverage claims.

The native implementation is in `src/accounts.rs`, `src/messaging.rs`, migrations `0020_accounts.sql`/`0021_messaging.sql`, and integration suites `tests/accounts.rs`/`tests/messaging.rs`. Accounts use UUID identifiers. SDK requests use a project API key plus an explicit `visitor_id` (or `x-visitor-id`); every visitor/message query also checks the project. The old hashid/device-resolution contract maps to these identifiers.

| Existing behavior | Rust implementation and verification |
| --- | --- |
| Registration, normalized email, duplicate/pending-invite protection, welcome mail | `/auth/register` and `/api/v1/users`; bounded Argon2; `DISABLE_REGISTRATION=true` controls operator registration policy. Welcome is enqueued when SMTP is configured. Account workflow tests cover duplicate preclaim denial. |
| Password login, required OTP prompt, seven-day refresh eligibility, self-revocation | `/auth/login`, `/oauth/token`, `/oauth/revoke`, `/auth/logout`. OAuth accepts JSON and form bodies. Access lasts one hour; refresh rotates and reuse revokes its family. Password/MFA credential version and row locks prevent stale login completion. Account tests cover rotation/reuse and old-access rejection. |
| SSO-enforced password suppression | Verified enforced-domain policy applies to register/login/reset/password refresh. OIDC refresh sessions retain their method and continue normally. Policy shared locks serialize issuance against enforcement. Policy integration test covers both session kinds. |
| Reset request, six-hour expiry, single-use change, anti-enumeration | `/api/v1/users/reset_password`, `/change_password`. Hashed tokens; token-bearing emails encrypted in the outbox; password changes revoke access, refresh and MCP credentials. Known/unknown addresses return the same response. Expiry/replay/reset revocation tests. |
| Invitations and existing-account membership email | `/api/v1/instances/{id}/invitations`; shared `invite_member` for membership creation; pending roles are visible but pending users cannot sign in. `/api/v1/users/accept_invite` consumes a hashed token. Invites expire after 14 days (legacy default was indefinite). Self-hosted administrators also receive a copyable URL. No existing account password can be overwritten by accepting a later invite. Tenant/preclaim/single-use tests. |
| Name update, current details/roles, account deletion | GET/PATCH/DELETE `/api/v1/users/me`; `/auth/me`; last-administrator deletion removes the orphan instance; other memberships are removed. Sessions and MCP credentials are revoked; audit records persist. Workflow tests. |
| TOTP enrollment SVG, enable/disable, replay prevention, OTP-required login | `/api/v1/users/me/otp_qr`, PUT `/me/two_factor`, GET `/me/otp_status`, legacy POST `/users/otp_status`. RFC 6238 SHA1/30s/6-digit, one-period skew, last consumed counter; encrypted secrets bound to user ID. Enrolled secrets cannot be redisclosed. Ten one-use recovery codes are added, stored only as hashes. RFC vectors and complete integration tests. |
| Email confirmation | Legacy Devise did not enable `confirmable`; optional `/users/confirmation` and `/users/confirm` now provide a 24-hour hashed single-use proof without changing the legacy login default. Integration tests verify consumption. |
| SCIM account deactivation and restoration | User-first locking across session issuance and SCIM mutation; deactivation revokes access, refresh and MCP credentials. Reactivation never restores old sessions. Integration test exercises deactivate/reactivate. |
| Quota and migration warning emails | `enqueue_alerts` snapshots instance owner/admin recipients into encrypted mail jobs, with stable per-alert recipient deduplication. Billing/import alerts are marked delivered only after all SMTP jobs succeed. Quota integration test uses an actual local SMTP server. |
| Export/new-member/other transactional mail | `enqueue_mail(tx, Mail, dedup)` is shared by native domain jobs; no direct send in HTTP transactions. Mailer subjects/text are native equivalents, not ERB templates. SMTP mocks exercise transport, durable retry and exact deduplication. |
| Notification create/list/search/read count/targeting/archive | Project-authorized `/api/v1/projects/{id}/notifications`, `/search`, DELETE notification. Exactly one new/existing segment, valid platforms, pagination, search, read counts; existing-user broadcasts cannot be archived. Integration test covers each segment and archive rule. |
| New visitor messages, existing visitor fanout, scheduling | Bounded idempotent fanout from durable visitors/devices; new-user rules start at notification creation, existing-user broadcasts snapshot through scheduled publication; scheduled content stays hidden until due. Desktop platforms map to web targets. Repeated worker runs and SDK reads cannot duplicate messages. Tests include delayed notifications and device-platform exclusions. |
| SDK notification list, unread count, mark read, automatic display | `/api/v1/sdk/notifications` and legacy named notification routes. All mutations scope both project and visitor; only unread auto-display messages are returned. Integration test attempts another visitor's message and verifies read/unread state. |
| Public marketing HTML page | `/mm/{uuid}` requires the owning project's primary or active custom hostname. Parsed HTML sanitation and restrictive CSP remove scripts, dangerous URLs/styles and event handlers while preserving rich text. Wrong-host and sanitizer tests. |
| FCM and APNs delivery | Durable `push_outbox` separate from in-app message creation; authenticated FCM HTTP v1 and APNs HTTP/2 ES256 requests. Fixed Google/Apple hosts, bounded timeouts, per-device deduplication, retries, lease-matched acknowledgments. Invalid provider-confirmed device tokens are cleared only if still equal to the sent token. Local HTTP adapter tests verify authorization headers, payloads, APNs headers, invalid-token and retryable-error classification. Missing provider configuration remains a durable failure. |

## Operator configuration

Use a persistent random 32-byte base64 `TRISIXT_ENCRYPTION_KEY` for encrypted TOTP and mail payloads. Back it up outside the repository; changing it without migrating ciphertext prevents decryption. Configure `ACCOUNT_FRONTEND_URL` for reset/invite/confirmation links and optional `OTP_ISSUER` (default Trisixt). `SMTP_HOST`, `SMTP_PORT` (default 587), `MAILER_FROM`, optional `SMTP_USERNAME`/`SMTP_PASSWORD` enable SMTP; port 465 uses implicit TLS, other ports require STARTTLS. `SMTP_PLAINTEXT_LOCAL=true` is restricted to loopback test servers. The worker calls `enqueue_alerts`, `dispatch_mail_once`, and `messaging::dispatch_once`; no email or push is reported as delivered before provider acceptance. At-least-once transports can redeliver after a process dies between remote acceptance and local acknowledgment; SMTP uses a stable Message-ID and APNs uses a stable request identifier.

`PUSH_PROFILES_JSON` maps operator-chosen names to credentials. Each profile must explicitly whitelist project UUIDs. Project administrators select names with PUT `/api/v1/projects/{id}/push-profiles` using `android_profile`/`ios_profile`; they cannot choose profiles assigned to other projects. Key material stays in operator-managed files, not database JSON or API responses.

```json
{
  "android-main": {
    "kind": "fcm",
    "project_ids": ["PROJECT_UUID"],
    "firebase_project_id": "firebase-project-id",
    "credentials_file": "/run/secrets/firebase-service-account.json"
  },
  "ios-main": {
    "kind": "apns",
    "project_ids": ["PROJECT_UUID"],
    "team_id": "APPLE_TEAM_ID",
    "key_id": "APPLE_KEY_ID",
    "bundle_id": "com.example.app",
    "key_file": "/run/secrets/apns.p8"
  }
}
```

Legacy instance push-certificate uploads map to these project-scoped credential references. The iOS device `push_environment=test` selects Apple's sandbox endpoint; production selects the production endpoint. Platform and token fields are registered through the shared devices API.

Run `scripts/integration.sh` for PostgreSQL and transport suites, including ignored infrastructure tests. FCM/APNs cloud acceptance and delivery to a real device still require the operator's provider account, credentials and device token; local mocks verify the native request contract but cannot establish external IAM or device configuration. No real recipient was sent mail or push during local validation.
