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

## Verification

`tests/sdk_configuration_gate.rs` exercises the actual router and PostgreSQL. Negative requests compare complete rows across identity, event/outbox, attribution, link/import, notification, purchase, quota, rate-limit, and audit tables. It also covers valid clients, server callers, and internal delegation. Existing suites configure their apps explicitly.

Run the complete local suite with `scripts/check.sh`. Actual supported SDK/device builds and live cloud provider acceptance remain separate release gates described in [TESTING_GUIDE.md](TESTING_GUIDE.md).
