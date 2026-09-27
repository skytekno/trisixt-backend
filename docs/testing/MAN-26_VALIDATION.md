# MAN-26 MCP search validation — 2026-09-27

Issue: [MAN-26 / C2](https://linear.app/skyholding/issue/MAN-26/c2-mcp-rich-linkcampaign-search-delegation).
Contract: [MCP_SEARCH.md](../MCP_SEARCH.md).
Base: `77099a63094c3a7eefab5a3344d48aad4dec3458`.

## Regression and acceptance scenarios

The original MCP search delegated to the simple GET list. The new routed
regression failed because its response omitted statistics, pagination metadata,
and archived rows. Delegating structured JSON to the native management POST
search now passes all six tests in `tests/mcp_search.rs`. The tests use the
actual HTTP router and isolated PostgreSQL schemas, comparing complete native,
MCP REST, and JSON-RPC results plus independent expected rows and counters.

| Scenario | Observed result |
| --- | --- |
| Link text, campaign/link IDs, SDK flag, active/archive, tags, ads platform, ID arrays | Exact expected rows and native response equality through both MCP surfaces |
| Campaign name, active/archive, IDs, empty results | Exact expected rows and native response equality |
| Date bounds, explicit timestamps, platform, metric sort, zero activity | Expected view/time-spent counters; excluded events do not contribute; zero-activity rows remain |
| Tied names in ascending/descending order, three pages, explicit offset | Stable UUID tie breaker, no gaps/duplicates, exact totals and next offsets |
| Invalid bounds, sort fields/orders, timezone/date, UUIDs, incorrectly typed filters | Same native error status/body through REST and error content through JSON-RPC; no entity/event mutations |
| Read-only token, write-only token, missing grant, foreign tenant, removed membership, revoked token | Reads succeed only with read scope and current access; creates denied; forbidden or unauthorized as appropriate |
| Tool discovery, legacy date aliases, ascending alias, non-object JSON | Typed schemas and read-only annotations; aliases preserve results; malformed bodies return errors without panic |

## Reproduction and source identity

`scripts/check.sh` passed: formatting, Clippy with warnings denied, configuration
validation, 9 Python recovery tests, 150 Rust tests (0 failed, 0 ignored), and
the dependency audit (397 dependencies). Integration used PostgreSQL, Redis,
ClickHouse, and pinned source-built MinIO, including the existing HTTP
ingestion/analytics/object-storage E2E test. Final source review and
`git diff --check` passed.

```sh
TEST_COMPOSE_PROJECT=trisixt-man26 KEEP_TEST_STACK=1 \
  CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 scripts/check.sh
```

Local logs are `/tmp/man26-check.log` (full checks), `/tmp/man26-focused.log`
(six focused tests), and `/tmp/man26-red.log` (original failing regression).
These are local artifacts, not production data or committed credentials.
Relevant source SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `src/mcp.rs` | `2bda99c5112076bd4959cdeff252b9ccd40af36e7d9405c499c6262869ee04a3` |
| `tests/mcp_search.rs` | `d33d0f0f652c4538470313c499ee6f5e636436af098776e6d9d8c046196084dd` |

## Acceptance boundary

This validates MCP delegation to current native search semantics. Final A4/A5
metric acceptance and supported MCP-client runtime acceptance remain separate
gates. GitHub-hosted checks are recorded on the pull request for its exact head
commit. Release publication still depends on the repository's release GitHub
App configuration; this change does not configure or deploy it.
