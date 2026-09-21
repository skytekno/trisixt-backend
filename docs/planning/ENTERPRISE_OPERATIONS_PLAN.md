# Proposed enterprise and operations gap-closure packages

Planning only. Based on `docs/RUST_PARITY_AUDIT.md` and the paired enterprise/operations evidence. This proposes implementation; nothing below is recorded as approved, implemented or tested.

Constraints: one engineer, fresh Rust installation first, target 2026-12-20. Legacy Rails conversion/archive recovery M1 is outside this initial release. All E1–E9 and O1–O7 remain in proposed release scope, including tenant credential administration; do not quietly turn those into accepted omissions to fit the date. Use additive SQLx migrations for staged native candidates and preserve the existing uncommitted checkout until the baseline is captured.

Estimates are focused engineer-days for implementation, affected regression tests, local review and package documentation, assuming the existing build/test environment works. They exclude final full-system integration, external-account waiting time, frontend work not in this repository, release rehearsal and contingency. S/M indicates relative change size; no package is a calendar promise. Estimates have high uncertainty for SCIM, audit verification and tenant credentials.

## Decisions to freeze in week 1

1. **O1:** restore the retained self-hosted default of closed public signup; keep `DISABLE_REGISTRATION` as an independent restrictive switch. Do not add an unrestricted signup override unless actually requested.
2. **E2/E3/E4:** require an enabled SSO connection and verified ownership for SCIM; preserve enterprise-on-by-default without reintroducing an unrequested paid-license gate. Define managed-member adoption, separate UPN/work email, operator exclusion, last-owner/admin protection and nonlast-admin deactivation. Recommend retaining the observed Rails lifecycle cases under native tenant/identity checks.
3. **E5:** keep verified-email OIDC as default. For signed UPN-only identities, decide whether the retained verified-domain JIT fallback is required or only preprovisioned SCIM mapping is permitted. The narrower option is a scope reduction requiring explicit acceptance; it cannot be labeled full E5 parity.
4. **E9:** tenant-admin onboarding/rotation remains the target. Preserve operator profiles as a supported deployment option. Confirm who may configure provider origins, allowed credential formats, and whether APNs certificate mode must ship rather than migrate existing certificate users to key mode. Full retained scope currently includes certificate mode.
5. **E8:** agree a v2 audit event contract, redaction rules, request-context provenance and mixed v1/v2 chain-verification behavior. Existing native hashes must not be rewritten.
6. **O6/O7:** restore initial members within provisioning and the production/test rename convention. Explicitly decide behavior for projects independently renamed after provisioning.
7. **Related behavior contracts:** resolve free-quota boundary/alert recipients, no-SMTP self-hosted invitations, billing client response requirements and notification base URLs. These are listed audit decisions, not permission to reopen every subsystem.

## PR package register

| Package | IDs | Size | Focused days | Dependencies / implementation home |
|---|---|---:|---:|---|
| B1 Durable cancellation after tenant deletion | E1 | M | 2–3 | Baseline; `billing.rs`, deletion entry points, worker, new SQL migration |
| S1 SCIM lifecycle gates and safe deactivation | E2, E3 | M | 2–3 | Baseline; `enterprise.rs`, `enterprise_admin.rs`, `oidc.rs`, SQL |
| O1 Self-hosted signup defaults | O1 | S | 0.25–0.5 | Baseline; `accounts.rs`, config and examples |
| O2 Shared source-IP limits | O2 | M | 1.5–2.5 | Baseline; routing/auth/context, shared limiter and expiry migration |
| O5 Redis TLS and explicit config failures | O5 | S | 0.5–1 | Baseline; Cargo features, config and worker |
| S2 SCIM identity/profile interoperability | E4 | M | 2–3.5 | S1; SCIM schema/handlers, account invitation helper |
| S3 Controlled UPN OIDC fallback | E5 | S/M | 0.5–1.5 | S1/S2, claim-policy decision; `oidc.rs`, enterprise policy |
| A1 Audit v2 storage and chain verifier | E8 foundation | M | 2–3 | Baseline; audit SQL function/schema, new verifier command |
| A2 Audit request/actor/change coverage | E8 completion | M | 1.5–2.5 | A1 and IP provenance from O2; accounts/routes/mutation call sites |
| K1 Tenant credential envelope and lifecycle | E9 foundation | M | 2–3 | S1 and A1 required; provider resolver + SQL + encryption support |
| K2 Tenant SSO credentials and rotation | E9 SSO | M | 1.5–2.5 | K1/S1, approved issuer/UPN policy; `oidc.rs`, enterprise admin |
| K3 Tenant FCM/APNs credentials, including certificate mode | E9 push | M | 2–4 | K1; `messaging.rs`, provider transport/config, upload routes |
| K4 Tenant store credentials | E9 IAP | M | 1.5–2.5 | K1; `purchases.rs`, `purchase_lifecycle.rs`, configuration routes |
| P1 Purchase ledger browser | E6 | M | 1.5–2.5 | Baseline; purchase query/serializer SQL and API |
| P2 Product revenue report | E7 | M | 1.5–2.5 | P1 fixture vocabulary; purchase/analytics query layer |
| D1 Deep diagnostics and monitor-key separation | O4 | M | 1–2 | O5; operations and provider probes |
| T1 OTLP tracing | O3 tracing | M | 1–2 | Baseline; `main.rs`, routes, provider/worker spans |
| T2 Required metric instruments | O3 metrics | S/M | 0.5–1 | T1; existing queue/provider/worker measurements |
| N1 Transactional initial-member provisioning | O6 | M | 1–1.5 | S2 invitation helper coordination, no-SMTP policy; accounts/provisioning |
| N2 Paired project rename | O7 | S | 0.25–0.5 | Pair naming policy; core API transaction |

Sum of these packages: **about 26–44.5 focused days**. This is only the enterprise/operations share. Analytics/connectivity fixes and final validation still consume the same solo-engineer 65-weekday window. Reserving the final three weeks for integrated validation/release leaves about 50 weekdays for the entire implementation, so this subset alone consumes roughly half to nearly all of that capacity. The upper estimate cannot be reconciled with all other work merely by assuming weekends or perfect execution. Re-estimate after week-1 proof exercises; if the combined scope exceeds capacity, the user must choose scope changes or date movement explicitly.

## Implementation and acceptance details

### B1 — durable Stripe cancellation

Add a cancellation outbox that has **no cascading foreign key to instances/subscriptions/users**. Persist the known Stripe subscription ID, former instance UUID, provider/account reference, creation reason, stable deduplication key, attempt schedule, completion time and redacted error. Store no Stripe secret in this obligation. Queue it in the same PostgreSQL transaction that deletes the instance, before subscription rows disappear; a BEFORE DELETE instance hook fits the existing SQL tombstone architecture and covers both explicit deletion and last-admin deletion. Application entry points still own authorization.

The billing worker claims an obligation, performs the provider cancellation and acknowledges only confirmed terminal provider state. Retry outages and crash-after-acceptance safely; do not interpret every 4xx as successful cancellation. Existing explicit cancel can share the provider operation without becoming dependent on an instance that may be gone. Align locking with billing snapshot application and checkout creation so deletion cannot lose an already-known in-flight subscription. Inspect pending checkout sessions/late checkout webhooks during this PR: an accepted paid subscription created after deletion must either be prevented or attach to a retained cancellation tombstone. This is part of validating no continuing charges, not a separate billing redesign.

Acceptance in `tests/billing.rs` plus lifecycle/cleanup tests: direct deletion, last-admin deletion, rollback creates no obligation, provider unavailable, duplicate workers, crash between remote success/local acknowledgement, already-canceled subscription, late webhook and checkout/deletion race. Prove local cascade leaves the obligation queryable and sandbox provider subscription eventually terminal. Source deletion success must not falsely imply immediate remote cancellation.

### S1/S2/S3 — SCIM and OIDC

S1 centralizes active-connection eligibility and verified-domain/operator rules used by token issuance and request extraction. Tie tokens to connection identity/version or revoke them transactionally on connection disable/delete; re-check eligibility during mutation rather than trusting a pre-transaction extraction. Preserve native global EE defaults. A migration must invalidate or explicitly reauthorize existing staged tokens that lack the new binding; do not silently grandfather them.

For deactivation, retain user-before-session lock ordering and SCIM/session shared locks. Introduce one documented tenant-administrator lock order consistent with account deletion so concurrent removal of two admins cannot leave no administrator. Revoke access, refresh and MCP credentials in the same transaction as deactivation. Allow an eligible nonlast managed admin to be deactivated; protect operators and the last administrative authority according to the frozen owner policy. Test SCIM calls racing password login, refresh, MCP grants, OIDC callbacks, role changes and two simultaneous deactivations.

S2 adds explicit normalized UPN, work email/name fields and necessary scoped uniqueness/indexes to native SCIM state. Parse only retained supported SCIM paths/operations and reject unsupported modifications explicitly. Support exact externalId filtering, the retained active boolean/string forms, eligible member/invitation adoption and rename within verified domains. Existing-account adoption must use domain ownership plus same-tenant identity/membership checks; never rebind a foreign live IdP identity or overwrite a password simply because email matches. Factor invitation consumption/session revocation helpers inside the existing caller transaction. Update `users.name/email` only where the agreed identity ownership allows, keeping SCIM projection and account state coherent.

Use retained `ee/test/integration/scim_users_test.rb` scenarios as independent expected-result fixtures in native HTTP tests, not helper-only coverage. Test UPN != email, externalId lookup after login, patch/replace names, work email rename, uniqueness conflicts, pending invite consumption, revoked tokens, foreign tenants and both common `active` shapes. S3 resolves authenticated claims through this scoped UPN mapping; preserve signature, issuer/audience/nonce/PKCE, connection-version and revoked-session checks. A live IdP roundtrip is required before calling the integration ready.

### A1/A2 — audit evolution without rewriting hashes

Introduce an explicit v2 audit payload with immutable actor type/id/email/via, outcome, target, redacted before/after changes and trusted request context. Keep legacy v1 rows and their hashes intact; add nullable/versioned columns or a canonical payload envelope with migration defaults that identify old rows correctly. Store the exact canonical v2 payload used to hash so a verifier is independent of serializer/timezone differences. Seed a separate per-tenant chain-head record from the current native tail within a locking migration; append and head advancement remain one transaction. Keep append-only/no-truncate enforcement.

Provide a read-only verifier for full chains and mixed versions, detecting sequence gaps, hash mismatch and tail/head mismatch. A v1 fixture created by the old function must verify using its actual canonicalization; if old timezone/serialization provenance cannot be recovered, report that limitation instead of fabricating verification. Since launch is fresh-first, no Rails audit-chain conversion is required.

A2 supplies request context through sanitized middleware/typed helpers and transaction-local audit context for SQL triggers, always cleared by transaction scope. Use request path/route, not query strings containing OAuth secrets. Snapshot actor identity before account deletion; record known-user failed logins without changing anti-enumeration responses. Add meaningful old/new diffs for retained audited actions and provider/system actor types. Test cross-tenant context leakage through pooled connections, secret redaction, actor rename/delete, failed login, transaction rollback, concurrency and v1/v2 tamper fixtures. Update export serializer/filter semantics and version documentation.

### K1–K4 — tenant credential administration

Keep operator-managed profiles operational. Add one explicit credential-resolution layer that chooses the configured tenant credential or operator reference according to a documented precedence; do not silently change all workers to a second unrelated secret source. K1 defines tenant/provider credential identity, encrypted envelope version/key identifier, nonsecret metadata, active/revoked versions and expiration. Reuse established encryption primitives with purpose- and tenant-bound authenticated context; require the persistent key and document backup/rotation. Never include raw secret values in audit records, logs, list/read APIs, queue payloads or exports. Read responses expose only safe metadata/presence/expiry. Secret replacement is explicit; an omitted value must preserve existing secret material.

Credential uploads must be bounded and parsed as the expected provider format, with no tenant-chosen filesystem paths, arbitrary provider endpoints or unrestricted URLs. Keep SSRF protections and operator origin policy for configurable IdP discovery. Authorize tenant admins with the existing role policy; switching to a credential assigned to another tenant must be impossible. Version rotation must have a defined in-flight-job contract: worker reference resolution/retry may use a permitted retained version, while explicit revocation prevents future use. Prove this under rotation and running jobs before adding UI promises.

K2 restores tenant issuer/client ID/secret/expiry configuration and safe presence/expiring-soon readback, maintaining SSO version invalidation and state/claim controls. K3 restores Firebase and APNs onboarding/rotation plus retained APNs certificate/password mode without breaking key mode or sandbox/production selection. Use vetted TLS/certificate parsing; private key material must not appear in temp files or errors. K4 restores Google/Apple server key onboarding; preserve authoritative provider prices, app binding, signed notification verification and one-time key handling. Each package tests create/read-redaction/rotate/revoke/wrong-tenant/invalid-file plus one successful local protocol flow. Live FCM/APNs devices and Apple/Google sandbox accounts remain external acceptance gates, whose credentials should be prepared in week 1 rather than at the end.

### P1/P2 — purchase browsing and product reports

Build purchase history from the signed ledger joined to authoritative sale metadata, not by duplicating mutable financial totals. Provide stable sorting with a unique tie-breaker, bounded pagination/cursors, event-type search and agreed date filters; expose sale/refund/reversal/cancel rows with clear reported-versus-provider-verified provenance. Preserve integer nanounits in storage and define response units explicitly. Do not restore trusted client-supplied store prices. Add indexes only after representative query plans show the need.

Product reports aggregate the same facts, with retained product/platform filters, units, cancellations, repeat/first-time purchasers, revenue and product ARPU/ARPPU; include retained LTV only with the exact agreed definition from Rails fixtures. Reuse canonical visitor aliases and retention/date conventions instead of a new competing analytics model. Validate >1000 same-timestamp rows, both sort directions, cursor scope, two products/platforms, refunds/reversals, recurring renewals, unknown FX, changed/deleted attribution and cross-tenant access. P2 coordinates fixture definitions with the analytics workstream; project-wide ARPU does not close product-table parity.

### O1/O2/O5 — quick operational safeguards

O1 applies the frozen self-hosted signup policy before hashing/insertion at the common handler and keeps invitations separate. Cover both registration paths and combinations of self-hosted/disable-registration settings.

O2 reuses the native **PostgreSQL atomic expiry-window counters** initially, with a shared typed bucket/key function and bounded expiry cleanup; do not add a mandatory Redis dependency merely because Rails throttled through Redis. Match retained policy windows/thresholds where routes correspond, using route classes for moved aliases. Derive source IP from the socket plus only configured trusted proxies, and canonicalize IPv4/IPv6. Keep source keys bounded and avoid raw token/address data in logs; use appropriate hashing for sensitive bucket inputs. Maintain existing account/project limits and the Argon2 semaphore. Test distributed counters across two app instances, parallel increments, rotating identities from one source, legitimate separate sources, spoofed forwarding headers, cleanup, database failure policy and `Retry-After`/429 behavior. If the retained high-rate SDK policy makes one SQL write per request too expensive, measure first and choose an explicit ingress/shared limiter plan; changing the durability architecture silently is not necessary for parity.

O5 enables the appropriate Redis async TLS feature, configures peer/hostname verification and optional custom CA, and surfaces invalid URL/TLS configuration rather than converting Client::open errors to None. Redis connectivity outages can remain degraded/nonfatal because the event queue is PostgreSQL; distinguish invalid configuration from transient outage. Test actual local TLS Redis, password authentication, untrusted CA, hostname mismatch, reconnect and durable event progress while Redis is unavailable.

### D1/T1/T2 — diagnostics and telemetry

D1 introduces a separate monitoring-key check compatible with the retained key/header, while retaining the stronger admin credential for repair mutations. Do not accept a query-string secret by default just to copy the old permissive input. Add bounded independent probes for PostgreSQL, Redis and the configured warehouse; keep storage probes explicit and harmless because Rails did not establish that behavior. Surface fresh success/failure and timeouts independently from stored worker health. Preserve `/up` and document `/ready` dependency policy instead of making every provider outage block all service. Diagnostic exercises use unique disposable keys/rows, bounds and cleanup; monitor-only credentials cannot trigger repair. Test each isolated failure and that one timeout does not hide other subsystem results.

T1 adds optional OTLP export alongside existing formatted tracing, service/process/version resources and request/provider/worker spans with propagated correlation. An absent collector must not prevent serving or queue processing. T2 adds only required retained operation/error/latency/queue instruments and keeps label cardinality bounded; avoid tenant IDs, tokens and full URLs as metric labels. Validate a local collector receives expected spans/metrics and preserves redaction, and that collector downtime is safe. Do not claim old Rails metric delivery was proved by its wrapper.

### N1/N2 — tenant provisioning consistency

N1 extracts an `invite_member_tx`-style helper from the current self-committing invitation method. Authorize/validate the bounded member list before creation, then insert instance/projects/roles/invites/mail obligations in one SQL transaction. SMTP sending remains asynchronous; define self-hosted no-SMTP behavior from the existing audit decision. Avoid nested independent commits. Preserve one-time key responses and return copyable invite URLs only under the intended self-hosted contract. Test mixed existing/new members, duplicate emails, forbidden roles, invalid-member rollback, invitation replacement and outbox rollback.

N2 updates the instance and its known production/test pair under one transaction with deterministic row locking. Follow the frozen rule for custom project names; do not blindly rename unrelated projects. Verify both names, returned state, audit old/new values and rollback.

## Solo sequencing recommendation

After the baseline/fixture-contract package in the main closure plan, do **B1 → S1 → O1 → O2 → O5** first; these are approximately 6.25–10 days within this subset and remove the highest enterprise/operations release hazards. Prepare sandbox/IdP/device credentials during week 1 without waiting to implement every adapter.

Then complete **S2/S3** and **A1**, followed by **K1–K4** early enough for live provider/IdP feedback to land before final stabilization; run **A2** as the new administration paths settle. Insert P1/P2 and N1/N2 around the analytics/tenant fixtures they share. D1/T1/T2 must finish before full operational rehearsal, not after deployment. The main plan combines these packages as a single solo schedule, not represent these as parallel engineering capacity.

Release closure for every ID requires routed API tests, provider/worker/database effects where applicable, relevant native suites, the full local check and reviewed evidence tied to a source snapshot/commit and image. Mark local protocol PASS separately from live provider PASS. Fresh-install schema/restore rehearsal is mandatory; legacy Rails conversion remains deferred explicitly.
