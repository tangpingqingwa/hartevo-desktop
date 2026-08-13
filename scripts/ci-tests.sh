#!/usr/bin/env bash
set -euo pipefail

python3 scripts/ci-scope.py --self-test
bash scripts/ci-workflow-syntax.sh self-test
python3 scripts/ci-workflow-policy.py self-test
python3 scripts/ci-branch-policy.py self-test
python3 scripts/ci-result.py self-test
python3 scripts/ci-dependency-audit.py self-test
python3 scripts/ci-promotion.py self-test

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-ci-script-tests.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
printf '%s\n' 'immutable fixture artifact' > "$fixture_dir/artifact.bin"
bash scripts/ci-distribution-hook.sh \
  --artifact "$fixture_dir/artifact.bin" \
  --output "$fixture_dir/distribution.json"
jq -e '.release == false and .deployment == false and .status == "NOT_IMPLEMENTED"' \
  "$fixture_dir/distribution.json" >/dev/null
python3 scripts/ci-oidc-interface.py --output "$fixture_dir/oidc.json"
jq -e '.tokenRequested == false and .longLivedCredentials == false and .deployment == false' \
  "$fixture_dir/oidc.json" >/dev/null
if bash scripts/ci-rust-gate.sh unknown >/dev/null 2>&1; then
  echo 'ci-rust-gate accepted an unknown mode' >&2
  exit 1
fi
printf '%s\n' '{"schema":"hartevo-ci-tests/v1","status":"PASS"}'
