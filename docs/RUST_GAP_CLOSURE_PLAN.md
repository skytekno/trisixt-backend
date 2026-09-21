# Rust gap-closure plan

Prepared 2026-09-20 from the [31-item audit](RUST_PARITY_AUDIT.md). **Owner: Roman, sole engineer. Target: fresh Rust release by 20 December 2026.** The original planning snapshot preceded implementation. MAN-5 baseline work has now started; its source selection, fixture contract and execution evidence are linked from [the baseline guide](baseline/README.md). The 31 parity findings remain open until their own acceptance gates pass.

Execution is tracked in [TrisixT on Linear](https://linear.app/mandays-labs/project/trisixt-91d84debbc6c/issues). The [52-task specification](planning/LINEAR_TASKS.json) retains the expanded implementation checklists; the [verified issue map](planning/LINEAR_SYNC.json) records issue links, milestones, parents and blockers as of 20 September 2026. Linear issues carry condensed acceptance criteria. Creating the backlog does not imply implementation or validation has started.

## Scope and feasibility

All **31 findings (E1–E9, A1–A10, C1–C5, O1–O7)** remain in the completion scope. **M1, Rails-data conversion and legacy archive recovery, is deferred until after the fresh release**, as requested. Native SQLx migration, backup/restore, key recovery and queued-work replay remain launch requirements.

Assume five working days per week from 21 September through 18 December: **65 weekdays** before the target, without assuming weekend work. This assumes full-time availability and excludes holidays or other business commitments. Reserve **weeks 11–13 for integration, recovery, fixes and release**, leaving roughly 50 weekdays for implementation and its local regression tests.

| Workstream | Initial focused engineer-day range | Included |
|---|---:|---|
| Enterprise and operations | 26–44.5 | E1–E9, O1–O7, targeted tests/review |
| Analytics | 15–23 | A1–A10, targeted tests plus 2–3 days of shared acceptance |
| Connectivity | 6–11.5 | C1–C5, targeted tests; external waits excluded |
| Feature-package total | **47–79** | Some shared acceptance overlaps the final validation period |

Baseline setup, related behavior decisions, remaining cross-system validation and contingency bring the initial planning envelope to **roughly 65–100 working days**. These are estimates, not measured throughput. **Full parity by 20 December is an optimistic target, not a reliable commitment yet.** Do not force the estimates to fit by dropping testing or assuming parallel human capacity.

At the **4 October checkpoint**, compare actual completed packages and remaining estimates with available days. If the forecast does not fit, choose explicitly between moving the full-parity date and narrowing the first release. A possible reduction is retaining operator-managed provider credentials temporarily instead of completing E9 tenant self-service/APNs certificate mode, but **that reduction is not approved by this plan**. M1 is the only currently agreed deferral. Disabled or deferred functionality remains open in the audit, and a reduced release must not be labeled full parity.

## Recommended technical direction

1. **Preserve the native architecture.** PostgreSQL remains canonical for identities, rich analytics and durable work; ClickHouse/BigQuery receive the immutable event stream. Keep the selected S3/MinIO or GCS storage adapter. Do not port Rails classes or Sidekiq queues one-for-one.
2. **Repair external side effects and authorization first.** Persist Stripe cancellation work before tenant cascades; bind SCIM access to current SSO/domain policy; enforce SDK declarations and registration policy; retain existing password concurrency and account limits while adding source-IP controls.
3. **Enrich once before persistence.** Resolve screen aliases, originating device UA/timezone and server GeoIP into the same frozen snapshot stored in PostgreSQL and the outbox. Duplicate event IDs and retries reuse that snapshot. Use a deployment-managed MMDB artifact with a checksum and explicit missing/stale database policy.
4. **Use canonical facts for the customer analytics endpoint (A6).** Preserve its response envelope and all-event count meaning, including custom-only visitors. Query existing alias-aware PostgreSQL facts instead of raw warehouse UUIDs. Test actual provider arrival separately. Direct warehouse canonical-identity views are an optional additional workstream, estimated at 5–8 days; raw warehouse rows must not be advertised as merge-aware.
5. **Restore capabilities through native contracts.** Stable pagination, typed search and upload-then-bind are acceptable; copying every Rails URL/envelope is unnecessary for a fresh installation. Adapt and test the actual clients. Existing raw-price trust, weak identity linking or secret exposure must not return in the name of parity.
6. **Keep migrations additive and small.** New SQLx migrations evolve the staged native schema. Preserve accepted events and existing audit hashes. No Rails converter or automatic historical enrichment rewrite is needed for the first release.

## Thirteen-week target sequence

This is the desired order at the optimistic end of the estimate range, not a claim that every weekly block already fits five days. Work one package at a time; reforecast at each checkpoint. The detailed plans split large blocks into reviewable PRs. Starts and finishes deliberately span weeks: audit storage precedes credential work, while later audit call-site coverage completes separately. These are implementation targets; final closure may wait for another package or live acceptance.

| Week | Dates (2026) | Focus and finding IDs | Exit evidence |
|---|---|---|---|
| 1 | 21–27 Sep | Baseline/fixture contracts; **C5, O1, A10, O5**; start **E1** | Reviewed baseline, configured SDK fixtures, quick gate regressions; sandbox access started; durable cancellation implementation begun |
| 2 | 28 Sep–4 Oct | Finish **E1**; SCIM lifecycle **E2, E3**; source-IP controls **O2**; start **C1** | Cascade/retry and deactivation/session tests; shared-IP policy; **capacity checkpoint** |
| 3 | 5–11 Oct | Finish resolver **C1**; MCP **C2**; SCIM/OIDC **E4, E5**; start shared enrichment **A2, A3** | Routed parser/search/IdP fixtures; common enrichment foundation begun |
| 4 | 12–18 Oct | Finish enrichment **A2, A3**, GeoIP **A1**, canonical customer counts **A6**; start **E8 audit storage foundation** | Snapshot/outbox/merge correctness; versioned audit storage work begun, not complete forensic coverage |
| 5 | 19–25 Oct | Finish **E8 storage/verifier foundation**; referral and visitor metrics **A4, A5** | Audit foundation available to later credentials; own/referral golden queries and visitor pagination work |
| 6 | 26 Oct–1 Nov | Finish **A4, A5**; clipboard **C4**; **E9 credential foundation and SSO**; start **C3 assets** | >200 visitor traversal; tokenless activity signal; encrypted SSO rotation after audit foundation; public asset foundation begun |
| 7 | 2–8 Nov | Finish attachments/cleanup **C3**; **A9, O6, O7**; start purchase browser **E6** | Image lifecycle and tenant isolation; atomic member/rename behavior; O7 forensic acceptance waits for E8 coverage |
| 8 | 9–15 Nov | Finish **E6**; product reports **E7**; CSVs **A7, A8**; start **E9 push credentials** | >1000 ledger rows; product money reconciliation; range-correct exports; push credential work begun |
| 9 | 16–22 Nov | Finish **E9 push/store credentials**; **E8 request/actor/change coverage**; start diagnostics **O4** | Credential-mode matrix incl APNs certificate; redacted forensic context and failed logins; finalize O7 audit assertions |
| 10 | 23–29 Nov | Finish **O4**; OTLP/metrics **O3**; agreed domain/quota/mail behavior work | Monitoring key cannot mutate; collector receipt/redaction; lifecycle behavior fixtures; **feature freeze and scope checkpoint** |
| 11 | 30 Nov–6 Dec | Same candidate image across all four provider combinations; real client and identity/billing/push journeys | Actual runtime-principal cloud proof, frontend/iOS/Android/server/MCP acceptance, no skipped required provider counted as passed |
| 12 | 7–13 Dec | Load/soak, fault recovery, native backup/restore and application rollback | Independent report reconciliation, queue-drain evidence, restored keys/data/objects, observed recovery bounds |
| 13 | 14–20 Dec | Fix reserve, final review and first-tenant rollout | Frozen candidate passes all gates; controlled synthetic tenant, monitoring and rollback ready; release by 20 Dec only if gates pass |

Credential and device access starts in week 1, and each feature receives local tests when implemented. Weeks 11–13 integrate already-tested work; they are not the first time the code is exercised. If week 10 still contains major unfinished features, do not consume the recovery reserve without an explicit date/scope decision.

## Work packages and dependency rules

Detailed implementation homes, schema choices, per-PR estimates and acceptance cases are in:

- [Enterprise and operations](planning/ENTERPRISE_OPERATIONS_PLAN.md): durable Stripe cancellation; SCIM/OIDC; audit v2; encrypted tenant credentials; purchase reporting; limits, TLS, diagnostics, telemetry and provisioning.
- [Analytics](planning/ANALYTICS_PLAN.md): shared enrichment/MMDB distribution; referral/visitor queries; A6 canonical endpoint; CSVs; cache pruning; BigQuery IAM; deferred M1.
- [Connectivity and validation](planning/CONNECTIVITY_VALIDATION_PLAN.md): SDK declaration/resolver; MCP delegation; clipboard signal; asset model/binding/cleanup; provider/client/recovery acceptance.
- [Machine-readable finding backlog](planning/GAP_CLOSURE_BACKLOG.json): every audited finding, target week, dependencies, work packages and closure criteria. Every item starts **planned**, except M1, which is **deferred**.

The [planning checks](planning/PLAN_CHECKS.json) verify all 31 findings are mapped, M1 is the only deferral, dependencies are acyclic, referenced files exist and the 1321-file source snapshot is unchanged. These checks validate the plan structure, not application behavior or the accuracy of effort estimates.

Key dependencies:

| Prerequisite | Enables | Why |
|---|---|---|
| Baseline and configured SDK fixture contract | All implementation; especially C5 then C1/C3/C4/A1–A3 | Current permissive fixtures must be updated rather than weakening the restored gate |
| SSO lifecycle/ownership rules, E2/E3 | E4 then E5; tenant SSO configuration E9 | Profile adoption and claim fallback must use current tenant/domain/session controls |
| Common enrichment, A2/A3 | A1; routed analytics/provider fixtures | Prevent divergent enrichment in PostgreSQL and outbox paths |
| Canonical identity query, A6 | Final A4/A5/E7/CSV consistency checks | All reports must use the same visitor interpretation and money units |
| Scoped reporting primitives, A4/A5 | A7/A8; C2 final metric parity | Avoid separate query logic disagreeing across dashboards, MCP and exports |
| Audit storage foundation, E8 | Credential mutation audit E9; final E8 coverage | Credential updates must be redacted and attributable from their first release |
| Credential envelope/lifecycle, E9 foundation | Separate SSO, push and IAP administration PRs | One tenant-scoped, versioned secret-resolution contract |
| Asset metadata/public-delivery foundation | Attachment binding then cleanup, C3 | Public images must never expose private object/export namespaces |
| Redis TLS/configuration, O5 | Full O4 diagnostic exercise | Probes must use the actual supported connection mode |
| All implemented slices plus live accounts | Integrated acceptance and fresh-install release | Local mocks do not establish IAM, device or IdP interoperability |

Prefer branches such as `fix/parity-e1-billing-deletion` and `feat/parity-e9-tenant-credentials`. The checkout currently has **zero commits**, so the first implementation task is a reviewed baseline of intended source/docs, excluding credentials, local artifacts and generated caches. Preserve the existing checkout; do not mass-stage it. Once a baseline exists, branch from current reviewed `main` and merge small, tested slices in dependency order. Shared modules such as `accounts.rs`, `sdk.rs`, `analytics_api.rs` and SQL migrations should have one active writer. Assistance from coding agents can help with independent tests/reviews but is not budgeted as extra human capacity.

## Contract decisions to settle in week 1

The recommendation is to restore the observed capability unless a change is explicitly accepted. These are design decisions within the work, not an instruction to request approval for every edit.

| Decision | Recommended baseline | Evidence needed before closure |
|---|---|---|
| Self-hosted registration, O1 | Disable public signup when self-hosted; preserve token-authorized invitations and independent disable flag | Both registration aliases and policy combinations |
| SCIM ownership/admin policy, E2–E4 | Active SSO + verified domain + operator exclusion; adopt only eligible same-tenant identities; deactivate nonlast managed admins safely | Retained adoption/profile payloads; race tests; actual target IdP |
| UPN OIDC fallback, E5 | Restore controlled retained fallback after signature/issuer/nonce checks, verified-domain policy and safe SCIM mapping | Actual IdP claim fixtures; no arbitrary email linking or weakening of default verified-email policy |
| Credential administration, E9 | Tenant-admin onboarding/rotation plus existing operator profiles; include retained APNs certificate mode | Per-provider create/redacted-read/rotate/revoke, wrong-tenant denial and live transport |
| GeoIP/enrichment | Server-derived canonical location; freeze on first accepted event; read-only MMDB artifact; explicit optional versus required deployment mode | IPv4/IPv6, proxy trust, missing/corrupt DB, provenance and replay |
| Customer versus raw warehouse counts, A6 | Customer API canonical PG; raw warehouse immutable IDs documented separately | Public envelope/all-event semantics preserved; direct-provider delivery still tested |
| Usage export, A8 | Exact requested activity interval, DAU/MAU and empty-period fill; distinguish billing snapshots | Partial-month and retention-boundary cases, timezone contract |
| Domain/import failure compensation | Prefer a durable visible pending/failed setup linked to its source; otherwise implement complete compensating cleanup | No unowned active host; timeout-after-remote-success, retry/adoption and delete-while-pending |
| Quota boundary and recipients | Keep the hard cap; define an observable cap-reached state/alert at the blocking boundary; explicitly choose recipients | Below/at/above allowance, deduplication and alert recipients |
| Mail/client behavior | Preserve useful self-hosted no-SMTP invitation links without a permanently failing mail queue; document text/HTML, billing envelopes and absolute/relative URL contracts | Representative actual clients and controlled inbox; unavailable clients remain an open gate |

No new external dependency version is selected by this plan. Check official documentation and compatibility with the locked toolchain when implementing MMDB, OTLP, TLS and provider permission changes.

## Acceptance and release gates

For each ID, add a regression that fails on the current behavior and checks the independent expected result through the actual route/worker boundary. Follow with the smallest relevant suites, then the full candidate checks. Do not close aliases by testing only their INSERT, migration referrers by calling only the helper, MCP search through only the dashboard route, or BigQuery cleanup with an administrator identity.

Existing commands, to run during execution from the repository root:

```sh
scripts/check.sh
scripts/validate-config.sh --terraform
docker build -t trisixt-backend:gap-closure .
IMAGE_NAME=trisixt-backend:gap-closure scripts/image-smoke.sh
```

The full local gate includes ignored infrastructure tests; an ordinary `cargo test` result alone is insufficient. The historical 130-test result is not the target count or a new pass. Update [TESTING_GUIDE.md](TESTING_GUIDE.md) as SDK declarations, images and new contracts change.

Use one candidate image digest and isolated fixtures for each combination:

| Analytics | Storage | Additional evidence |
|---|---|---|
| ClickHouse | MinIO | Full local reference flow, images/exports, tenant cleanup |
| BigQuery via Pub/Sub | MinIO | Actual export arrival, deduplicated logical event counts, runtime-principal retention/delete and delayed-export cleanup |
| ClickHouse | GCS | Runtime-identity put/get/list/delete, public app image delivery, export/expiry/cleanup |
| BigQuery via Pub/Sub | GCS | Combined cloud flow and independent warehouse/storage outage recovery |

Provider selectors do not migrate historical data. Run matrix rows in separate fresh test environments; never switch a collecting tenant's provider just to test the matrix. Cloud fixtures must use scoped runtime credentials, including deletion-denied then restored-permission cases. Pub/Sub acknowledgement and PostgreSQL readiness are not warehouse-delivery evidence. Direct AWS S3, if advertised for launch beyond MinIO compatibility, needs its own live account check.

Fresh-release gates:

1. **Coverage:** every finding has a linked implementation, routed regression, evidence and final status. All 31 must be closed for a full-parity claim. Approved reductions remain explicitly listed; no test skip becomes a pass.
2. **Correctness and isolation:** billing cancellation, SCIM/session races, SDK restrictions, exact referral/revenue/identity counts, image lifecycle, exports and two-tenant deletion all pass.
3. **External services and clients:** real Stripe/store sandboxes, target IdP/SCIM, push devices, mail, DNS/TLS/imports and supported dashboard/mobile/server/MCP clients pass their relevant scenarios. Obtain these resources early; absence blocks the affected launch claim.
4. **Performance:** by week 1 record expected peak ingest/query traffic, dataset size, latency/error limits and acceptable queue lag. Test sustained expected load and a documented burst with bounded queues and correct reports; do not invent a universal throughput target or optimize from unit tests alone.
5. **Recovery:** restore native PostgreSQL, selected object storage and required encryption keys into a clean environment; rebuild/replay recoverable warehouse data from preserved sources; prove pending jobs, identity, invoices/audit and attachments reconcile. Set RPO/RTO in week 1 and measure them. This does not require M1.
6. **Rollback:** deploy the previous compatible native image against additive migrations and rehearse recovery. Do not rely on destructive down-migrations or overwrite newly accepted billing/events to roll back. If a schema change prevents image rollback, its forward-repair/restore procedure must be tested before release.
7. **Rollout:** first deploy a controlled synthetic tenant; inspect logs, spans, metrics, outbox lag, dead work and provider cleanup before inviting the first real tenant. Record image/source identity and monitored rollback triggers. Production deployment is a later concrete action, not performed by this planning task.

## Definition of done and status updates

Track findings as **planned → in progress → local verified → live verified (where required) → closed**, with **deferred** and **blocked by environment** stated separately. Each record contains the audit ID, contract decision, PR/commit, fixture/command, independent expected result, actual result, image digest and remaining gate. Redact secrets and user data in evidence.

Review progress every Friday. On 4 October, 1 November and 29 November, reforecast remaining effort and evaluate external-access readiness. A finding is closed only when its behavior and required evidence are complete; merge status or route existence is insufficient. Update the audit/status documents when evidence changes, preserving the original historical findings and test dates.

After the fresh release, resume M1 as a separate discovery-led plan for actual Rails data, stable ID mappings, resumable archive ingestion, reconciliation and rehearsed cutover. Keep this deferred boundary visible in product/deployment documentation.
