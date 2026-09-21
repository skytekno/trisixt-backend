# Evidence for the 2026-09-20 parity audit

Start with [the findings register](../RUST_PARITY_AUDIT.md). All findings remain open; proposed scenarios have not been executed by this audit.

| Artifact | Purpose |
|---|---|
| [ENTERPRISE_FINDINGS.md](ENTERPRISE_FINDINGS.md) | E1–E9: billing, purchases, SCIM/OIDC, audit and credential administration |
| [ANALYTICS_FINDINGS.md](ANALYTICS_FINDINGS.md) | A1–A10: enrichment, identity, reporting, exports and cleanup; legacy conversion boundary |
| [CONNECTIVITY_FINDINGS.md](CONNECTIVITY_FINDINGS.md) | C1–C5: public/SDK links, attachments, clipboard, MCP and configuration gates |
| [OPERATIONS_FINDINGS.md](OPERATIONS_FINDINGS.md) | O1–O7: registration, throttling, telemetry, diagnostics, Redis and tenant lifecycle |
| [RAILS_ROUTE_INVENTORY.csv](RAILS_ROUTE_INVENTORY.csv) | 224 explicit route declarations and literal native candidates |
| [RUST_ROUTE_INVENTORY.csv](RUST_ROUTE_INVENTORY.csv) | 240 native literal method/path declarations and handlers |
| [SOURCE_SHA256.json](SOURCE_SHA256.json) | 1321 source/test/configuration file hashes for the uncommitted checkout |
| [REDIS_FEATURES.txt](REDIS_FEATURES.txt) | Output of `cargo tree --locked -e features -i redis` |
| [AUDIT_CHECKS.json](AUDIT_CHECKS.json) | Documentation/link checks, inventory counts and source-snapshot comparison |

Source references in the detailed reports are repository-relative `path:line` locations at this snapshot. A second range such as `:50-56` refers to the preceding path. No credentials or environment-file values are included.

The route inventory is a lexical navigation aid. It normalizes path parameter names and trailing slashes for candidate matching, records the Rails constraint context, and excludes native test-module declarations. It does not expand mounted Rails engines, fully evaluate dynamic routes, compare bodies/response envelopes, or prove authorization/host dispatch equivalence. The 72 unmatched literal Rails declarations must not be reported as 72 missing features.

To check whether the audited source has changed, run from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json
snapshot = json.loads(Path('docs/audit/SOURCE_SHA256.json').read_text())
changed = [name for name, expected in snapshot.items()
           if not Path(name).is_file()
           or hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected]
print(f'{len(snapshot)} recorded files; {len(changed)} changed or missing')
for name in changed:
    print(name)
raise SystemExit(bool(changed))
PY
```

Hash equality identifies the source only. It does not validate behavior, cover new files added after the snapshot, or replace the per-finding acceptance tests and [release testing guide](../TESTING_GUIDE.md).
