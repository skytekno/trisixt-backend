# CI/CD setup and operating rules

This repository is a Rust 1.98.1 backend. Node 24 is used only for commitlint and
Husky. PostgreSQL 18.6, Redis 8.10.2, ClickHouse and MinIO are the existing test
services. Redis is built from the existing checksum-verified source recipe.

## 1. Install the local commit hooks

1. Install Node 24 or newer and the Rust toolchain in `rust-toolchain.toml`.
2. Run `npm ci`. Its `prepare` script installs Husky in this repository only.
3. Run `git config --get core.hooksPath`; the expected value is `.husky/_`.
4. Keep `package-lock.json` committed. CI installs tooling with
   `npm ci --ignore-scripts` and runs its checks explicitly.
5. Husky retains the original `.githooks/pre-commit` formatting and branding gate.
   `.husky/commit-msg` rejects non-conventional messages and `Release-As` overrides.

Examples: `feat(sdk): enforce platform identity`, `fix(auth): reject disabled apps`,
`refactor: simplify token lookup`, `chore: update development tools`.
Use `feat!:` or a `BREAKING CHANGE:` footer for incompatible changes.

## 2. Establish GitHub access and bootstrap

1. Run `gh auth status` and `gh repo view` from this checkout. The current origin
   is `git@github.com:skytekno/trisixt-backend.git`. At setup time GitHub could not
   resolve this repository with the available credentials. Confirm that the
   repository exists and that the authenticated account has administration access.
   If the origin is outdated, correct it to the intended repository before proceeding.
2. Commit the reviewed configuration using `ci: configure validated semantic releases`.
   No commit, push, release, or image publication was performed during setup.
3. Push the initial configuration to `main` before enforcing protection, or use
   the existing PR process if the remote already has a protected `main`.
4. Open a PR against `main` and let all six CI jobs plus `CI required` complete.
   Required checks must first be reported to GitHub before they can be selected
   reliably in the repository settings.

## 3. Create the release GitHub App

1. In GitHub Developer settings, create a private GitHub App owned by the
   repository owner. Give it a descriptive name such as Trisixt Release Bot.
   Disable the webhook; this app only mints installation tokens in Actions.
2. Grant repository permissions: **Contents: Read and write**,
   **Pull requests: Read and write**, and **Issues: Read and write**.
   Metadata read access is automatic. Do not grant administration or bypass access.
3. Install the app for this repository only.
4. Generate its private key. In repository Settings → Secrets and variables →
   Actions, add the following:

| Kind | Name | Value |
| --- | --- | --- |
| Repository variable | `RELEASE_APP_ID` | The numeric App ID shown by GitHub |
| Repository secret | `RELEASE_APP_PRIVATE_KEY` | The complete generated PEM private key |
| Automatic Actions token | `GITHUB_TOKEN` | Supplied by GitHub; do not create it manually |

The app token allows bot-created release PRs to trigger normal PR CI. Using the
built-in token for those PRs would suppress automatic workflow triggering.
Container publication uses `GITHUB_TOKEN` with job-scoped `packages: write`.
No `REGISTRY_TOKEN`, production `DB_URL`, or cloud credentials are needed in CI.
All database passwords in CI are disposable, isolated test credentials.

## 4. Apply repository rules

After the initial checks have been reported, run:

```sh
scripts/configure-github.sh
```

The script discovers the repository through `gh`, backs up existing settings to
an external temporary directory, preserves existing checks, stronger review counts, code-owner requirements and
actor restrictions, applies the requested rules, and reads back protection.
Review the protection JSON before running it if organization policy differs. Organization
rulesets may impose additional requirements that this script does not remove.

Equivalent settings in GitHub:

1. Settings → General → Pull Requests: enable **Allow squash merging** only.
   Disable merge commits and rebase merging. Default squash title to **PR title**
   and message to **PR body**. Enable automatic branch deletion.
2. Settings → Branches → protection for `main`: require a pull request, at least
   **one independent approval**, dismiss stale approvals, and require approval
   of the latest reviewable push. Authors cannot approve their own PRs.
3. Require status check **CI required**, with the branch up to date before merge.
   It depends on Commit standards, Lint and static analysis, Dependency audit,
   Unit and integration tests, Migration dry run, and Container smoke test.
4. Require conversation resolution and linear history. Enforce rules for admins.
   Disable force pushes and branch deletion. Give the release app no bypass.
5. Settings → Actions → General: allow the pinned actions in these workflows;
   keep default workflow token permissions read-only. The container job grants
   its token package write permission explicitly.
6. For a private GHCR package, grant this repository Actions access to the
   package if it already exists. The first successful push creates a new package.
7. If private-repository protection is unavailable on the current GitHub plan,
   enable a plan that supports it; a JSON file alone does not enforce protection.

## 5. Release flow and version policy

1. Keep PR titles conventional because GitHub uses them as squash commit titles.
   Put breaking-change explanations in the PR body so they survive the squash.
2. A push to `main` runs the complete reusable CI workflow before release-please.
3. Release-please opens or updates a release PR. Its Rust strategy updates
   `Cargo.toml`, the root package in `Cargo.lock`, `CHANGELOG.md`, and
   `.release-please-manifest.json` together. The manifest starts at the current
   package version, `0.1.0`; no artificial historical release is created.
4. Review and squash-merge the release PR after CI succeeds. Release-please then
   creates the `vMAJOR.MINOR.PATCH` Git tag and GitHub Release.
5. `fix` and `perf` produce patch releases, `feat` produces a minor release, and
   breaking changes produce a major release, including while the version is
   below 1.0. Other non-breaking maintenance types do not independently trigger
   a release. Version overrides and manual release tags are not the release path.
6. The same release workflow calls container publication directly, avoiding
   reliance on a second workflow being triggered by a bot-created tag.
7. The publisher verifies the release tag, commit ancestry and Cargo version,
   builds `linux/amd64`, checks the image as non-root against a temporary database,
   and publishes `ghcr.io/skytekno/trisixt-backend:vMAJOR.MINOR.PATCH` and `latest`.
   The actual registry path is derived from `github.repository` in lowercase.
8. `latest` is updated only when the tag is still GitHub's latest release.
   An older release retry cannot intentionally move it backwards. Deploy by the
   immutable registry digest, never by the moving `latest` tag.
9. To retry a failed publication, use Actions → Publish container → Run workflow
   on `main`, supplying the existing release tag and its exact 40-character SHA.
   If the version already exists, the workflow verifies its revision label,
   pulls and smoke-tests it, and reuses it without overwriting the version tag.
   Authentication or registry errors fail closed.

## 6. Container reproducibility and maintenance

The Dockerfile pins both base images by digest, uses `Cargo.lock` with `--locked`,
and freezes runtime Debian package resolution to a dated, signed Debian snapshot.
HTTP is used to bootstrap the snapshot because the slim base lacks CA certificates;
APT still verifies repository signatures and package hashes. `.dockerignore`
allows only build inputs and required licenses. UID/GID 10001 executes the app,
SIGTERM requests its existing graceful shutdown, and `/up` is the liveness probe.
Readiness checks use `/ready` in the smoke suite and must also gate deployment.

Update image digests, the Debian snapshot date, action SHAs and tooling lockfile
through reviewed dependency-update PRs. Pinning prevents silent drift; it does
not automatically apply future security fixes or prove byte-identical artifacts.

## 7. Production rollout contract

These workflows provide CI, releases, and container delivery. They do not deploy
or claim zero downtime without a provisioned production scheduler and database.
For production, configure the following rollout policy on the actual platform:

1. Keep at least two healthy web replicas behind a load balancer; use rolling
   updates with zero unavailable replicas and at least one surge replica.
2. Gate traffic on HTTP `/ready`, use `/up` for liveness, allow at least 60 seconds
   for graceful SIGTERM draining, and retain the previous image digest.
3. Store `DATABASE_URL`, `TRISIXT_ENCRYPTION_KEY`, provider credentials and other
   values documented in `.env.example` in the platform's secret manager. Preserve
   the encryption key across releases. Do not bake them into images or CI.
4. Use an approved production environment and serialize rollout jobs. Verify a
   current backup and a rehearsed restore before schema-changing releases.
5. Add forward-only migrations. CI rejects edits/deletions of existing migrations
   and applies all migrations twice on a temporary PostgreSQL database.
6. Use expand/contract changes: add compatible schema first, deploy code that
   tolerates both versions, backfill separately, then remove old schema in a
   later release after all old web and worker replicas have drained.
7. Run `trisixt migrate` from the exact release image as a single controlled
   pre-rollout job. The application also migrates on startup, so all migrations
   must remain safe when old and new replicas overlap. SQLx serializes migration
   execution, but this alone does not prevent table locks or incompatible changes.
8. In staging, measure lock duration and query performance on representative data;
   check old/new application compatibility, use bounded lock timeouts where
   appropriate, and rehearse worker shutdown and rollback.
9. After rollout, verify readiness, API error rate, latency, queue lag and provider
   delivery. Roll back to the previous image digest if health degrades. Do not
   automatically reverse destructive schema changes.

The migration dry run proves syntax/execution and repeatability on a fresh test
DB. It does not prove live upgrade safety, data preservation at production scale,
or the duration of locks. The live BigQuery/GCS and device/client acceptance gates
remain separate from the local ClickHouse/MinIO integration suite.

## Validation performed locally

- Actual Husky hook: 11 valid/invalid Conventional Commit cases.
- Official release-please configuration schema and four SemVer scenarios;
  real Rust updaters verified for both Cargo files.
- All workflows pass actionlint; scripts pass shell syntax validation.
- Full `scripts/check.sh`: formatting, Clippy, configuration, Python recovery
  tests, native integration tests and Rust dependency audit.
- Additional `cargo audit --deny warnings` and npm dependency audit.
- Terraform formatting, initialization without backend, and validation.
- All 33 migrations applied and repeated with an unchanged migration ledger.
- Integration suite exercised with external PostgreSQL, matching the CI service
  container path.
- Digest-pinned Docker image built locally on ARM64; non-root and HTTP readiness
  smoke checks passed. Hosted Linux AMD64 execution remains a GitHub CI gate.

Remote GitHub rules, app credentials, hosted CI, GitHub Releases and GHCR pushes
were not applied or exercised because the configured repository was inaccessible.

## References

- [Release Please action](https://github.com/googleapis/release-please-action)
- [Release Please configuration](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md)
- [GitHub workflow triggering and token restrictions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
- [Husky setup](https://typicode.github.io/husky/get-started.html)
- [Commitlint rules](https://commitlint.js.org/reference/rules.html)
- [GitHub branch protection API](https://docs.github.com/en/rest/branches/branch-protection)
