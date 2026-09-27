# MAN-28 clipboard activity validation — 2026-09-27

Issue: [MAN-28 / C4](https://linear.app/skyholding/issue/MAN-28/c4-tokenless-clipboard-project-activity-check).
Contract: [CLIPBOARD_ACTIVITY.md](../CLIPBOARD_ACTIVITY.md).
Base: `6287e276691b5a68608a6e846044ce3db956f6d3`.

## Regression and acceptance scenarios

The original routed tokenless request returned `400 clipboard_token required`.
The same regression now returns `200 {"clipboard_active":false}` for a fresh
project and true after an eligible mobile copy render. Six routed PostgreSQL
tests in `tests/clipboard_activity.rs` and a fixed-clock unit test cover:

| Scenario | Observed result |
| --- | --- |
| Fresh project, iOS link copy configuration, Android project copy configuration | False initially; eligible HTML contains the copy token and activates the project hint |
| Non-copy, direct redirect, desktop, crawler, disabled platform, fallback/re-entry, dedicated preview host, archived link | No activity marker, including ordinary clicks that are ineligible for copying |
| Another tenant's key, caller-supplied project ID, missing/disabled/mismatched declarations, invalid/revoked key | Key owns project scope; foreign project remains inactive; declaration/credential failures denied |
| Read-only checks and malformed bodies/tokens | Complete activity/visitor/device/event/click rows remain unchanged; malformed input returns `400` |
| Expiry and refresh | Routed 47h/49h cases pass; controlled-time unit test verifies 48h minus 1 microsecond, exactly 48h, and 48h plus 1 microsecond; future markers inactive |
| Recreated router and database pool, link deletion, project deletion | Same durable timestamp survives fresh application connections and link deletion; project deletion cascades the marker |
| Eight concurrent eligible renders, earlier timestamp after a newer marker | All renders succeed; marker follows the newest activity and cannot move backward |
| Explicit token, foreign/forged/expired token, consume, same/other visitor replay | Existing `available` response retained; first consume returns link data; replay returns empty data; one open event; status/consume do not refresh the activity TTL |

## Reproduction and source identity

Full `scripts/check.sh` passed: formatting, Clippy with warnings denied,
configuration validation, 9 Python recovery tests, 157 Rust tests (0 failed,
0 ignored), and the dependency audit (397 dependencies). Integration used
PostgreSQL 18.6, Redis 8.10.2, ClickHouse, and pinned source-built MinIO,
including the existing HTTP ingestion/analytics/object-storage E2E test.
Final diff review and `git diff --check` passed.

```sh
TEST_COMPOSE_PROJECT=trisixt-man28 KEEP_TEST_STACK=1 \
  CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 scripts/check.sh
```

Local logs: `/tmp/man28-check.log`, `/tmp/man28-focused.log`, and
`/tmp/man28-red.log`. These are local artifacts, not production data.

| File | SHA-256 |
| --- | --- |
| `src/public_links.rs` | `533c568d52b6f123b7468a7e01630f1591f2cc3c64fc44d7452e4f52f2463fd8` |
| `src/sdk.rs` | `077eecbc99dbee54f9616a5f510a1622d8981d432b656926005aa842a8c854ce` |
| `migrations/0052_clipboard_activity.sql` | `d892435b2afd323d2f74dc28d61f2763fa20a29a4d24a9f528e85bc90851bfcb` |
| `tests/clipboard_activity.rs` | `e82d7204a74bb484d495027e686afdfa86db482719123e33ac2003745d1964d8` |

## Acceptance boundary

This establishes backend eligibility, persistence, expiry, and token contracts.
No actual iOS clipboard permission prompt or supported SDK/browser build was
exercised. The client must still prove its activity request precedes clipboard
access and respects the OS permission/user-gesture flow; the contract document
contains that acceptance sequence. A rendered page proves eligibility, not
completion of the browser clipboard write.

GitHub checks are recorded on the PR for its exact head, including migration
dry run and container smoke. Release publication remains dependent on the
existing release GitHub App configuration.
