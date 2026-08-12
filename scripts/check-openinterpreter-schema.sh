#!/usr/bin/env bash
set -euo pipefail

readonly repository="https://github.com/openinterpreter/openinterpreter.git"
readonly release="rust-v0.0.34"
readonly commit="52a31019714294add53cafbc5268e1467b471263"
readonly source_root="https://raw.githubusercontent.com/openinterpreter/openinterpreter/${commit}"
readonly schema_root="https://raw.githubusercontent.com/openinterpreter/openinterpreter/${commit}/codex-rs/app-server-protocol/schema/json"
readonly expected_schema="f5d28066430a14cb5f7b98545fbff3683734ea6112a1e9944bf7f268afe9e896"
readonly expected_server_requests="fc063273c71e6310f5a4c1449a607364fcd11b8bf4c998d71fb780016df7b3ad"
readonly expected_server_notifications="322148beced81b06eafa74011a91ace9c3ef2bad9757d3e0e6c72369c52251fb"
readonly expected_checksums="1d9ef8a8fac6449c1ecfab293a18e15c777f2bbd41418dcc76434b697beae267"
readonly expected_artifact_catalog="dca01e63fe94a3961fc5d1ba847f642d23429717322e527f83bf5e596e608061"
readonly expected_upstream_license="d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc"
readonly expected_upstream_notice="9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915"
readonly workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly source_manifest="${workspace_root}/third_party/openinterpreter/SOURCE.toml"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-openinterpreter.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

curl --fail --location --silent --show-error \
  "${schema_root}/codex_app_server_protocol.v2.schemas.json" \
  --output "${work_dir}/app-server-v2.json"
curl --fail --location --silent --show-error \
  "${schema_root}/ServerRequest.json" \
  --output "${work_dir}/server-requests.json"
curl --fail --location --silent --show-error \
  "${schema_root}/ServerNotification.json" \
  --output "${work_dir}/server-notifications.json"
curl --fail --location --silent --show-error \
  "https://github.com/openinterpreter/openinterpreter/releases/download/${release}/codex-package_SHA256SUMS" \
  --output "${work_dir}/SHA256SUMS"
curl --fail --location --silent --show-error \
  "${source_root}/LICENSE" \
  --output "${work_dir}/LICENSE"
curl --fail --location --silent --show-error \
  "${source_root}/NOTICE" \
  --output "${work_dir}/NOTICE"

check_digest() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local actual
  actual="$(shasum -a 256 "${path}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "OpenInterpreter ${label} drift: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
}

require_manifest_value() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(awk -F ' = ' -v key="${key}" \
    '$1 == key { gsub(/^"|"$/, "", $2); print $2; exit }' \
    "${source_manifest}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "OpenInterpreter SOURCE.toml ${key} drift: expected ${expected}, got ${actual:-missing}" >&2
    exit 1
  fi
}

require_manifest_value "review_commit" "${commit}"
require_manifest_value "reference_release" "${release}"
require_manifest_value "upstream_license_sha256" "${expected_upstream_license}"
require_manifest_value "vendored_license_sha256" "${expected_upstream_license}"
require_manifest_value "upstream_notice_sha256" "${expected_upstream_notice}"
require_manifest_value "vendored_notice_sha256" "${expected_upstream_notice}"
require_manifest_value "release_checksum_manifest_sha256" "${expected_checksums}"
require_manifest_value "artifact_manifest_sha256" "${expected_artifact_catalog}"

check_digest "${work_dir}/app-server-v2.json" "${expected_schema}" "App Server schema"
check_digest "${work_dir}/server-requests.json" "${expected_server_requests}" "server-request schema"
check_digest "${work_dir}/server-notifications.json" "${expected_server_notifications}" "server-notification schema"
check_digest "${work_dir}/SHA256SUMS" "${expected_checksums}" "release checksum manifest"
check_digest "${work_dir}/LICENSE" "${expected_upstream_license}" "upstream license"
check_digest "${work_dir}/NOTICE" "${expected_upstream_notice}" "upstream notice"
check_digest "${workspace_root}/third_party/openinterpreter/ARTIFACTS.json" "${expected_artifact_catalog}" "local artifact catalog"
check_digest "${workspace_root}/third_party/openinterpreter/LICENSE" "${expected_upstream_license}" "vendored license"
check_digest "${workspace_root}/third_party/openinterpreter/NOTICE" "${expected_upstream_notice}" "vendored notice"

peeled_commit="$(git ls-remote "${repository}" "refs/tags/${release}^{}" | awk '{print $1}')"
if [[ "${peeled_commit}" != "${commit}" ]]; then
  echo "OpenInterpreter release tag drift: expected ${commit}, got ${peeled_commit:-missing}" >&2
  exit 1
fi

for method in item/commandExecution/requestApproval item/fileChange/requestApproval; do
  if ! jq -e --arg method "${method}" \
    '[.. | objects | .method? | .enum? // empty | .[]?] | any(. == $method)' \
    "${work_dir}/server-requests.json" >/dev/null; then
    echo "OpenInterpreter server-request method missing: ${method}" >&2
    exit 1
  fi
done

artifact_count="$(jq '.artifacts | length' "${workspace_root}/third_party/openinterpreter/ARTIFACTS.json")"
if [[ "${artifact_count}" != "6" ]]; then
  echo "OpenInterpreter artifact matrix must contain exactly six pinned release assets" >&2
  exit 1
fi
while IFS=$'\t' read -r archive digest; do
  if ! grep -Fqx "${digest}  ${archive}" "${work_dir}/SHA256SUMS"; then
    echo "OpenInterpreter artifact checksum missing from upstream manifest: ${archive}" >&2
    exit 1
  fi
done < <(jq -r '.artifacts[] | [.archive, .archiveSha256] | @tsv' \
  "${workspace_root}/third_party/openinterpreter/ARTIFACTS.json")

for method in thread/started turn/started item/started item/completed turn/completed; do
  if ! jq -e --arg method "${method}" \
    '[.. | objects | .method? | .enum? // empty | .[]?] | any(. == $method)' \
    "${work_dir}/server-notifications.json" >/dev/null; then
    echo "OpenInterpreter server-notification method missing: ${method}" >&2
    exit 1
  fi
done

echo "OpenInterpreter ${release} source, wire methods, schemas, and release checksums verified at ${commit}"
