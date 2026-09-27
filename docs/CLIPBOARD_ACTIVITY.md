# SDK clipboard activity

`POST /api/v1/sdk/clipboard_status` supports two modes. Both require a live
project key and the [configured SDK declaration](SDK_CONFIGURATION.md). The
authenticated key determines the project; a JSON `project_id` cannot select a
different project's activity. The body must be a JSON object.

| Request body | Response | Meaning |
| --- | --- | --- |
| `{}` or `{"clipboard_token":null}` | `{"clipboard_active":true}` or `false` | This project had eligible mobile copy activity within the last 48 hours |
| `{"clipboard_token":"<token from ct>"}` | `{"available":true}` or `false` | This token belongs to an unhandled click in this project younger than 48 hours |

An empty or unknown token returns `available: false`. Non-string tokens and
tokens longer than 64 bytes return `400`. Invalid/revoked project keys return
`401`; missing, disabled, or mismatched SDK declarations return `403`, following
the common SDK error contract. Neither mode consumes a token, creates identity
or event records, nor extends an activity/token expiry.

## Eligibility and storage

The public renderer stamps activity only when an iOS/Android request is enabled
for its platform, has clipboard copying enabled through the existing link or
project configuration, records a click, and serves an HTML handoff page that
contains its copy token. Copy settings retain their existing precedence: link
platform field, nested custom redirect, platform redirect, project platform
field, then project default.

Non-copy pages, direct HTTP redirects, desktop requests, crawlers, disabled
platforms, forced fallbacks, redirect re-entry, dedicated preview-host requests,
and missing/archived links do not stamp activity. An ordinary recorded click
alone is insufficient. A regular public mobile preview is eligible; the
dedicated `preview.<SERVER_HOST>` inspection route creates no click/token.

Migration `0052_clipboard_activity.sql` adds one timestamp per project in
`project_clipboard_activity`. Writes preserve the newest timestamp under
concurrent requests. Both stamping and expiry use PostgreSQL time, so application
clock skew does not change the window. Activity expires at exactly 48 hours;
future-dated markers are inactive until the database clock catches up.

The marker survives application restarts, token consumption, and link deletion.
Project deletion removes it through a foreign-key cascade. It stores neither
clipboard contents nor client identifiers and introduces no Redis dependency.
Expired rows remain bounded to one per project and are refreshed by the next
eligible render. Existing projects start inactive; historical clicks are not
backfilled because they do not prove copy eligibility.

## Client privacy flow

1. Send `{}` with the configured SDK headers before accessing the OS clipboard.
2. If `clipboard_active` is false, skip the optional deferred clipboard read.
3. If true, use the client's normal OS-supported clipboard permission or user
   gesture flow. The hint is project-wide and does not prove that this device
   copied a link, that the browser write succeeded, or that OS access is allowed.
4. If a project link with `ct` is read, use the existing token availability check
   or deferred-link resolver. Consumption and replay protections remain intact.

The backend cannot observe completion of `navigator.clipboard.writeText`; it
records copy eligibility when rendering. Routed PostgreSQL tests cover both
status modes, positive/negative eligibility, isolation, read-only behavior,
expiry/refresh, fresh application connections, concurrent writes, and token
consumption/replay. A fixed-clock unit test covers the exact 48-hour boundary.

Real supported iOS/SDK and browser acceptance remains a release gate: capture
the client/OS build, verify the tokenless request occurs before any clipboard
read, verify the OS permission/user-gesture flow after an eligible click, and
verify no clipboard read when the hint is false. Backend tests alone do not
prove this client behavior.
