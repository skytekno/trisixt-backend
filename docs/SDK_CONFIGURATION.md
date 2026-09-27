# Client SDK configuration contract

MAN-29 / RUST-C5 requires a configured, enabled app before a client SDK request can read SDK configuration or perform identity, event, link, notification, or purchase operations. This enforces project configuration; it is not cryptographic app attestation.

## Request declarations

All client requests require a non-revoked project key in `x-project-key` or `project-key`. Configure the app through the authenticated dashboard API, `PUT /api/v1/projects/{id}/configurations/{platform}`, before using its SDK.

| Client | Declaration | Required project configuration |
| --- | --- | --- |
| iOS | `x-sdk-platform: ios` and `x-sdk-identifier: <bundle ID>` | `ios.enabled: true` and a nonblank matching `ios.bundle_id` |
| Android | `x-sdk-platform: android` and `x-sdk-identifier: <package name>` | `android.enabled: true` and a nonblank matching `android.package_name` |
| Web | `x-sdk-platform: web` plus an identifier or HTTP(S) `Origin` | `web.enabled: true` and the declared hostname in `web.domains` |
| Browser using Origin only | HTTP(S) `Origin`; platform is inferred as web | Same web requirements |
| Desktop | `x-sdk-platform: desktop`, `mac`, `windows`, or `linux` | `desktop.enabled: true`; a declared Mac/Windows client must also not be explicitly disabled by `mac_enabled`/`windows_enabled` |

The aliases `platform` and `identifier` remain supported. Platform names are case insensitive; mobile identifiers match exactly. Repeated or aliased headers must carry identical values. Empty, malformed, or conflicting declaration headers are rejected. Desktop has no configured app identifier field and does not accept an identifier declaration.

Web allowlists match normalized hostnames, ignoring case, trailing dots, scheme, and port. Wildcards, credentials, paths, queries, and fragments are not allowed. If both identifier and Origin are sent, they must identify the same allowed hostname. An Origin on a mobile or desktop declaration is rejected. `Origin: null` is rejected.

A project key alone or an identifier alone does not declare an app. An absent configuration row, empty app configuration, absent/false/non-boolean `enabled`, missing mobile identifier, or empty/unmatched web allowlist denies the request.

## Payload consistency

The validated declaration travels with the authenticated project. Client payload platform claims, including event properties, notification filters, and purchase platforms/providers, must agree before writes or provider calls. A batch containing a conflicting event rejects the whole batch. Top-level app identifier claims on JSON SDK payloads must also match; `sdk_identifier` remains the visitor's external identity.

Device authentication and deferred attribution use the declared platform rather than user-agent inference when the payload omits it. Desktop aliases normalize to the desktop device/redirect family. Events without a platform inherit the declared client platform before device enrichment. Notification filters and reported purchase metadata also default to the declaration.

Failures use the existing error contract: invalid/revoked credentials return `401`; missing, disabled, unconfigured, foreign, or mismatched declarations return `403`; malformed/unsupported platforms and conflicting headers return `400`. Typed JSON payloads reject unknown fields using Axum's existing `422` response. Authorization failures occur before SDK side effects.

## Server and internal callers

The genuine server SDK routes (`generate_link`, server link details, and metrics) keep their separate key plus `environment` authentication. They do not need a mobile/web declaration. Client `create_link` remains gated. In-process `InternalSdkProject` delegation is trusted application state and cannot be created by an HTTP header.

## Link and install-referrer inputs

`POST /api/v1/sdk/data_for_device_and_url` accepts an existing `visitor_id` and
one of these strings in `url`, with the same configured-app headers above:

| Input | Example | Resolution |
| --- | --- | --- |
| Native HTTP(S) URL | `https://links.example/l/offer` | The authenticated project's native or active primary custom host |
| Migrated HTTP(S) URL | `https://old.example/offer?utm_source=mail` | A migration host owned by the authenticated project |
| Raw Play Install Referrer | `utm_source=play&~referring_link=https%3A%2F%2Fold.example%2Foffer` | Exactly one decoded `~referring_link`, containing an HTTP(S) URL |
| Bare migration slug | `offer?utm_source=mail` | The authenticated project's migration source |
| Hierarchical custom scheme | `demoapp://prefix/offer?utm_source=mail` | Native host when owned; otherwise `prefix/offer` in the project's migration source |

The complete input is limited to 8,192 bytes and migration slugs to 2,048 bytes.
Malformed escapes, empty inputs, repeated referring links, nested referrer
wrappers, unknown referrer keys without a referring link, URL credentials,
control characters, protocol-relative URLs, and unsafe/reserved custom schemes
return `400`. Custom schemes must use `://`; `javascript`, `data`, `file`,
`vbscript`, `about`, `blob`, `ftp`, `ftps`, `ws`, and `wss` are rejected. Custom
scheme inputs are link identifiers, never destinations for outbound requests.

Query parameters on the resolved URL or slug are preserved for the provider
lookup. Native hosts retain precedence; migration custom hosts use the old-path
mapping even when a native path collides. Foreign/unconfigured hosts, missing
sources, archived/deleted targets, and cached provider failures return
`{"data":null,"link":null,"tracking":null}` without claiming fingerprint matches.
Resolved cache entries remain usable for disabled sources; uncached disabled
sources return the same empty result. Successful responses include `data`,
`link`, `link_id`, and `tracking`; clipboard identity claims retain their existing
one-time open-event behavior, including when `ct` is inside the referring URL.

## Verification

`POST /api/v1/sdk/clipboard_status` accepts `{}` for a project activity hint
before the client reads the clipboard. Explicit tokens retain their availability
check. See [clipboard activity](CLIPBOARD_ACTIVITY.md) for eligibility, the
48-hour window, response shapes, and the client privacy acceptance gate.

`tests/sdk_configuration_gate.rs` exercises the actual router and PostgreSQL. Negative requests compare complete rows across identity, event/outbox, attribution, link/import, notification, purchase, quota, rate-limit, and audit tables. It also covers valid clients, server callers, and internal delegation. Existing suites configure their apps explicitly.

Run the complete local suite with `scripts/check.sh`. Actual supported SDK/device builds and live cloud provider acceptance remain separate release gates described in [TESTING_GUIDE.md](TESTING_GUIDE.md).

`tests/sdk_migration.rs` exercises these input forms through the actual router,
including exact attribution, project boundaries, cache lifecycle, and provider
queries against a local HTTP fixture. Rejected-input tests compare full rows in
eight affected tables. These fixtures do not prove Android Play delivery or real
Branch/AppsFlyer account compatibility.
