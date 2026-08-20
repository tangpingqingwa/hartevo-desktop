#!/usr/bin/env bash
set -euo pipefail

if ! command -v ruby >/dev/null 2>&1; then
  printf '%s\n' '{"schema":"hartevo-ci-workflow-syntax/v1","status":"BLOCKED_ENV","code":"RUBY_MISSING"}'
  exit 2
fi

mode="${1:-verify}"
if [[ "$mode" == "self-test" ]]; then
  fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-ci-yaml.XXXXXX")"
  trap 'rm -rf -- "$fixture_dir"' EXIT
  printf '%s\n' 'name: fixture' 'on: push' 'jobs:' '  check:' '    runs-on: ubuntu-latest' >"${fixture_dir}/valid.yml"
  printf '%s\n' 'name: fixture' 'jobs:' '  check: [' >"${fixture_dir}/invalid.yml"
  ruby -ryaml -e 'YAML.parse_file(ARGV.fetch(0))' "${fixture_dir}/valid.yml"
  if ruby -ryaml -e 'YAML.parse_file(ARGV.fetch(0))' "${fixture_dir}/invalid.yml" >/dev/null 2>&1; then
    echo "syntax self-test accepted invalid YAML" >&2
    exit 1
  fi
  printf '%s\n' '{"schema":"hartevo-ci-workflow-syntax-self-test/v1","status":"PASS"}'
  exit 0
fi

if [[ "$mode" != "verify" ]]; then
  echo 'usage: ci-workflow-syntax.sh [verify|self-test]' >&2
  exit 2
fi

workflow_files=()
while IFS= read -r workflow_file; do
  workflow_files+=("$workflow_file")
done < <(find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort)
[[ "${#workflow_files[@]}" -gt 0 ]] || { echo 'no workflow files found' >&2; exit 1; }

for workflow in "${workflow_files[@]}"; do
  ruby -ryaml -e 'YAML.parse_file(ARGV.fetch(0))' "$workflow"
done

printf '{"schema":"hartevo-ci-workflow-syntax/v1","status":"PASS","workflowCount":%s}\n' "${#workflow_files[@]}"
