#!/usr/bin/env bash
set -euo pipefail

readonly repository="https://github.com/openinterpreter/openinterpreter.git"
readonly release="rust-v0.0.34"
readonly commit="52a31019714294add53cafbc5268e1467b471263"
readonly source_root="https://raw.githubusercontent.com/openinterpreter/openinterpreter/${commit}"
readonly schema_root="https://raw.githubusercontent.com/openinterpreter/openinterpreter/${commit}/codex-rs/app-server-protocol/schema/json"
readonly expected_schema="f5d28066430a14cb5f7b98545fbff3683734ea6112a1e9944bf7f268afe9e896"
readonly expected_canonical_schema="f57b06a5622a3d406c90aa60a1889450b403dae79906810fe1bb1401e5ba1a48"
readonly expected_client_requests="fc5e94477d22634669295e36c00ab73a28129586a7c3c832291a808c89fe3010"
readonly expected_server_requests="fc063273c71e6310f5a4c1449a607364fcd11b8bf4c998d71fb780016df7b3ad"
readonly expected_server_notifications="322148beced81b06eafa74011a91ace9c3ef2bad9757d3e0e6c72369c52251fb"
readonly expected_checksums="1d9ef8a8fac6449c1ecfab293a18e15c777f2bbd41418dcc76434b697beae267"
readonly expected_artifact_catalog="dca01e63fe94a3961fc5d1ba847f642d23429717322e527f83bf5e596e608061"
readonly expected_upstream_license="d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc"
readonly expected_upstream_notice="9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915"
readonly workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly source_manifest="${workspace_root}/third_party/openinterpreter/SOURCE.toml"
readonly contract_summary="${HARTEVO_OPENINTERPRETER_CONTRACT_PATH:-${workspace_root}/contracts/openinterpreter/app-server-v2.methods.json}"
readonly adapter_source="${workspace_root}/hartevo-rs/runtime-adapter/src/lib.rs"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-openinterpreter.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

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

check_canonical_json_digest() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local actual
  actual="$(jq -S . "${path}" | shasum -a 256 | awk '{print $1}')"
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

require_contract_shape() {
  if ! jq -e '
    def unique_string_array:
      type == "array"
      and all(.[]; type == "string" and length > 0)
      and length == (unique | length);
    type == "object"
    and (keys == [
      "experimentalApi",
      "schema",
      "stableMethods",
      "stableNotifications",
      "stableServerRequests"
    ])
    and .schema == "hartevo.openinterpreter-contract/v1"
    and .experimentalApi == false
    and (.stableMethods | unique_string_array)
    and (.stableServerRequests | unique_string_array)
    and (.stableNotifications | unique_string_array)
  ' "${contract_summary}" >/dev/null; then
    echo "OpenInterpreter local frozen method summary is malformed" >&2
    exit 1
  fi
}

write_expected_set() {
  local output="$1"
  shift
  printf '%s\n' "$@" | LC_ALL=C sort >"${output}"
}

write_contract_set() {
  local field="$1"
  local output="$2"
  jq -er --arg field "${field}" '.[$field][]' "${contract_summary}" \
    | LC_ALL=C sort >"${output}"
}

write_schema_method_set() {
  local schema="$1"
  local output="$2"
  jq -er '[.. | objects | .method? | .enum? // empty | .[]?] | unique[]' \
    "${schema}" | LC_ALL=C sort >"${output}"
}

extract_global_method_literals() {
  local function_name="$1"
  local output="$2"
  awk -v signature="fn ${function_name}(method: &str) -> bool {" '
    $0 == signature { capture = 1 }
    capture { print }
    capture && $0 == "}" { complete = 1; exit }
    END { if (!capture || !complete) exit 1 }
  ' "${adapter_source}" \
    | grep -Eo '"[^"]+"' \
    | sed -e 's/^"//' -e 's/"$//' \
    | LC_ALL=C sort -u >"${output}"
}

extract_event_method_literals() {
  local output="$1"
  awk '
    $0 == "    pub fn from_method(method: &str) -> Self {" { capture = 1 }
    capture { print }
    capture && $0 == "    }" { complete = 1; exit }
    END { if (!capture || !complete) exit 1 }
  ' "${adapter_source}" \
    | grep -Eo '"[^"]+"' \
    | sed -e 's/^"//' -e 's/"$//' \
    | LC_ALL=C sort -u >"${output}"
}

require_exact_set() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if ! cmp -s "${expected}" "${actual}"; then
    echo "OpenInterpreter ${label} set drift" >&2
    diff -u "${expected}" "${actual}" >&2 || true
    exit 1
  fi
}

require_subset() {
  local subset="$1"
  local superset="$2"
  local label="$3"
  local missing
  missing="$(comm -23 "${subset}" "${superset}")"
  if [[ -n "${missing}" ]]; then
    echo "OpenInterpreter ${label} missing adopted methods:" >&2
    printf '%s\n' "${missing}" >&2
    exit 1
  fi
}

require_adapter_string_constant() {
  local name="$1"
  local expected="$2"
  local actual
  actual="$(awk -v name="${name}" '
    $0 ~ "^pub const " name ": &str" { capture = 1 }
    capture && match($0, /"[^"]+"/) {
      print substr($0, RSTART + 1, RLENGTH - 2)
      exit
    }
  ' "${adapter_source}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "OpenInterpreter adapter ${name} drift: expected ${expected}, got ${actual:-missing}" >&2
    exit 1
  fi
}

require_contract_shape

write_expected_set "${work_dir}/expected-client-methods" \
  initialize thread/start thread/resume turn/start turn/interrupt
write_expected_set "${work_dir}/expected-server-requests" \
  item/commandExecution/requestApproval item/fileChange/requestApproval
write_expected_set "${work_dir}/expected-server-notifications" \
  thread/started turn/started item/started item/agentMessage/delta item/completed turn/completed

write_contract_set stableMethods "${work_dir}/local-client-methods"
write_contract_set stableServerRequests "${work_dir}/local-server-requests"
write_contract_set stableNotifications "${work_dir}/local-server-notifications"

require_exact_set "${work_dir}/expected-client-methods" \
  "${work_dir}/local-client-methods" "local stableMethods"
require_exact_set "${work_dir}/expected-server-requests" \
  "${work_dir}/local-server-requests" "local stableServerRequests"
require_exact_set "${work_dir}/expected-server-notifications" \
  "${work_dir}/local-server-notifications" "local stableNotifications"

extract_global_method_literals is_stable_client_method \
  "${work_dir}/adapter-client-methods"
extract_global_method_literals is_stable_server_method \
  "${work_dir}/adapter-server-requests"
extract_event_method_literals "${work_dir}/adapter-event-methods"
require_subset "${work_dir}/adapter-server-requests" \
  "${work_dir}/adapter-event-methods" "adapter server-request classification"
comm -23 "${work_dir}/adapter-event-methods" \
  "${work_dir}/adapter-server-requests" >"${work_dir}/adapter-server-notifications"

require_exact_set "${work_dir}/local-client-methods" \
  "${work_dir}/adapter-client-methods" "contract/adapter client adoption"
require_exact_set "${work_dir}/local-server-requests" \
  "${work_dir}/adapter-server-requests" "contract/adapter server-request adoption"
require_exact_set "${work_dir}/local-server-notifications" \
  "${work_dir}/adapter-server-notifications" "contract/adapter notification adoption"

require_adapter_string_constant OPENINTERPRETER_COMMIT "${commit}"
require_adapter_string_constant OPENINTERPRETER_RELEASE "${release}"
require_adapter_string_constant APP_SERVER_SCHEMA_SHA256 "${expected_schema}"
if ! grep -Fq '"/../../contracts/openinterpreter/app-server-v2.methods.json"' \
  "${adapter_source}"; then
  echo "OpenInterpreter adapter no longer embeds the frozen method summary" >&2
  exit 1
fi

require_manifest_value "review_commit" "${commit}"
require_manifest_value "reference_release" "${release}"
require_manifest_value "schema_path" "codex-rs/app-server-protocol/schema/json/codex_app_server_protocol.v2.schemas.json"
require_manifest_value "schema_sha256" "${expected_schema}"
require_manifest_value "canonical_schema_sha256" "${expected_canonical_schema}"
require_manifest_value "server_request_schema_sha256" "${expected_server_requests}"
require_manifest_value "server_notification_schema_sha256" "${expected_server_notifications}"
require_manifest_value "contract_subset" "../../contracts/openinterpreter/app-server-v2.methods.json"
require_manifest_value "experimental_api" "false"
require_manifest_value "upstream_license_sha256" "${expected_upstream_license}"
require_manifest_value "vendored_license_sha256" "${expected_upstream_license}"
require_manifest_value "upstream_notice_sha256" "${expected_upstream_notice}"
require_manifest_value "vendored_notice_sha256" "${expected_upstream_notice}"
require_manifest_value "release_checksum_manifest_sha256" "${expected_checksums}"
require_manifest_value "artifact_manifest_sha256" "${expected_artifact_catalog}"

curl --fail --location --silent --show-error \
  "${schema_root}/codex_app_server_protocol.v2.schemas.json" \
  --output "${work_dir}/app-server-v2.json"
curl --fail --location --silent --show-error \
  "${schema_root}/ClientRequest.json" \
  --output "${work_dir}/client-requests.json"
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

check_digest "${work_dir}/app-server-v2.json" "${expected_schema}" "App Server schema"
check_canonical_json_digest "${work_dir}/app-server-v2.json" "${expected_canonical_schema}" "canonical App Server schema"
check_digest "${work_dir}/client-requests.json" "${expected_client_requests}" "client-request schema"
check_digest "${work_dir}/server-requests.json" "${expected_server_requests}" "server-request schema"
check_digest "${work_dir}/server-notifications.json" "${expected_server_notifications}" "server-notification schema"
check_digest "${work_dir}/SHA256SUMS" "${expected_checksums}" "release checksum manifest"
check_digest "${work_dir}/LICENSE" "${expected_upstream_license}" "upstream license"
check_digest "${work_dir}/NOTICE" "${expected_upstream_notice}" "upstream notice"
check_digest "${workspace_root}/third_party/openinterpreter/ARTIFACTS.json" "${expected_artifact_catalog}" "local artifact catalog"
check_digest "${workspace_root}/third_party/openinterpreter/LICENSE" "${expected_upstream_license}" "vendored license"
check_digest "${workspace_root}/third_party/openinterpreter/NOTICE" "${expected_upstream_notice}" "vendored notice"

write_schema_method_set "${work_dir}/client-requests.json" \
  "${work_dir}/upstream-client-methods"
write_schema_method_set "${work_dir}/server-requests.json" \
  "${work_dir}/upstream-server-requests"
write_schema_method_set "${work_dir}/server-notifications.json" \
  "${work_dir}/upstream-server-notifications"
require_subset "${work_dir}/local-client-methods" \
  "${work_dir}/upstream-client-methods" "pinned client-request schema"
require_subset "${work_dir}/local-server-requests" \
  "${work_dir}/upstream-server-requests" "pinned server-request schema"
require_subset "${work_dir}/local-server-notifications" \
  "${work_dir}/upstream-server-notifications" "pinned server-notification schema"

peeled_commit="$(git ls-remote "${repository}" "refs/tags/${release}^{}" | awk '{print $1}')"
if [[ "${peeled_commit}" != "${commit}" ]]; then
  echo "OpenInterpreter release tag drift: expected ${commit}, got ${peeled_commit:-missing}" >&2
  exit 1
fi

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

echo "OpenInterpreter ${release} local contract, adapter adoption, pinned schemas, source, and release checksums verified at ${commit}"
