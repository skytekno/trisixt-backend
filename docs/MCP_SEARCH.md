# MCP link and campaign search

MCP searches use the same POST search handlers as the management API. The
authenticated MCP token must grant the requested project, contain `mcp:read`
or `mcp:full`, and belong to a user who still has access to that project.
`mcp:write` alone does not grant read access. Read-only tokens cannot create,
update, or archive entities.

| Surface | Links | Campaigns |
| --- | --- | --- |
| Management | `POST /api/v1/projects/{project_id}/links/search` | `POST /api/v1/projects/{project_id}/campaigns/search` |
| MCP REST | `POST /api/v1/mcp/links/search` | `POST /api/v1/mcp/campaigns/search` |
| MCP JSON-RPC | `search_links` | `search_campaigns` |

Both MCP surfaces require `project_id` in the JSON arguments. Keep arrays,
booleans, and numbers as JSON values. REST query-string parameters are strings;
use the JSON body for typed filters. `tools/list` exposes the search schemas.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "search_links",
    "arguments": {
      "project_id": "00000000-0000-4000-8000-000000000001",
      "term": "summer",
      "tags": ["Mobile"],
      "active": true,
      "sdk": false,
      "platform": "ios",
      "sort_by": "views",
      "sort_order": "desc",
      "per_page": 20,
      "page": 1
    }
  }
}
```

Replace the example project UUID with a project in the token's grant.

Common filters are `query`/`search`/`term` (in that precedence order),
`active`/`archived` (`active` takes precedence), and an `ids` array. Link searches
also support `campaign_id`, `link_id`, `sdk`, `ads_platform`, and `tags` (all
supplied tags must match). Campaigns support their own name search and common
filters; link-only filters do not narrow campaigns.

Activity metrics honor `start_date`, inclusive `end_date`, `timezone`, and
`platform`. Explicit RFC 3339 `from`/exclusive `to` timestamps override the date
bounds. MCP retains `date_from`/`date_to` as aliases for `start_date`/`end_date`;
use one spelling per bound. Retention and the native 90-calendar-day aggregate
window still apply. These filters affect metrics, retaining zero-activity rows.

Results include the entity array (`links` or `campaigns`), `meta` with `page`,
`per_page`, `total_entries`, and `total_pages`, and nullable `next_offset`.
Each entity includes native `total_*` statistics and `unpriced_purchases`.
JSON-RPC returns this JSON in `result.content[0].text`, with `isError: false`.
Tool execution errors retain the existing `isError: true` text-content envelope;
invalid/revoked authentication returns HTTP `401` before tool execution.

The default sort is `created_at desc`; supported fields are listed in each tool
schema. `sort_order` overrides `asc` (also spelled `ascending` or `ascendent`).
Null/zero metric sort values go last; UUID order breaks ties. `limit` overrides
`per_page` (1–1000), and `offset` overrides `page` (maximum offset 100000).
The default page size is 50, or a bounded 1000 with `all: true`.

This replaces the old MCP simple-list behavior: responses now include statistics
and pagination, and **both active and archived rows are included by default**.
Clients wanting only active entities must send `active: true`.

`tests/mcp_search.rs` checks complete response equality across management, MCP
REST, and JSON-RPC, plus independent expected rows/counters, pagination,
malformed input, schemas, and permissions. This proves delegation to current
native semantics; final A4/A5 metric acceptance and supported MCP-client runtime
acceptance remain separate gates.
