#!/usr/bin/env bash
# Apply repository merge policy and main protection after the initial push.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
backup=$(mktemp -d "${TMPDIR:-/tmp}/trisixt-github-settings.XXXXXX")
gh api "repos/$repo" > "$backup/repository.json"
# Fail on access errors; an unprotected branch legitimately returns 404.
if ! gh api "repos/$repo/branches/main/protection" > "$backup/protection.json" 2> "$backup/protection-error.txt"; then
  if ! grep -q 'HTTP 404' "$backup/protection-error.txt"; then
    cat "$backup/protection-error.txt" >&2
    exit 1
  fi
  printf '{}\n' > "$backup/protection.json"
fi
python3 - "$backup" <<'PY'
import json, sys
from pathlib import Path
backup = Path(sys.argv[1])
old = json.loads((backup / 'protection.json').read_text())
policy = json.loads(Path('.github/branch-protection.json').read_text())
checks = old.get('required_status_checks') or {}
policy['required_status_checks']['contexts'] = sorted(set(
    checks.get('contexts', []) + policy['required_status_checks']['contexts']))
if checks.get('checks'):
    policy['required_status_checks']['checks'] = checks['checks']
reviews = old.get('required_pull_request_reviews') or {}
policy['required_pull_request_reviews']['required_approving_review_count'] = max(
    1, reviews.get('required_approving_review_count', 0))
policy['required_pull_request_reviews']['require_code_owner_reviews'] = reviews.get(
    'require_code_owner_reviews', False)
def actors(value):
    return {kind: [entry[field] for entry in value.get(kind, [])]
            for kind, field in [('users', 'login'), ('teams', 'slug'), ('apps', 'slug')]}
if old.get('restrictions'):
    policy['restrictions'] = actors(old['restrictions'])
for name in ['dismissal_restrictions', 'bypass_pull_request_allowances']:
    if reviews.get(name):
        policy['required_pull_request_reviews'][name] = actors(reviews[name])
(backup / 'protection-request.json').write_text(json.dumps(policy, indent=2) + '\n')
PY
printf 'Existing settings saved to %s\n' "$backup"
gh api --method PATCH "repos/$repo" \
  -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
  -F delete_branch_on_merge=true \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY > /dev/null
gh api --method PUT "repos/$repo/branches/main/protection" \
  --input "$backup/protection-request.json" > /dev/null
gh api "repos/$repo/branches/main/protection" > "$backup/protection-applied.json"
echo 'Applied squash-only merges and main branch protection (CI required + one independent review).'
