#!/usr/bin/env bash
set -Eeuo pipefail

readonly receipt_schema="hartevo.dioxus-build-provenance/v1"
readonly self_test_schema="hartevo.dioxus-toolchain-gate-self-test/v1"
readonly workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly default_contract="${workspace_root}/contracts/toolchain/dioxus-cli-build.json"
readonly contract_path="${HARTEVO_DIOXUS_CONTRACT_PATH:-${default_contract}}"
readonly test_mode="${HARTEVO_DIOXUS_TEST_MODE:-0}"
readonly script_path="${workspace_root}/scripts/check-dioxus-toolchain.sh"

work_dir=""
contract_sha="unavailable"
host_os="unknown"
host_arch="unknown"
problem_emitted=false

cleanup() {
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    rm -rf "${work_dir}"
  fi
}

emit_problem() {
  local status="$1"
  local code="$2"
  local message="$3"
  local exit_code="$4"
  problem_emitted=true
  trap - ERR

  if command -v jq >/dev/null 2>&1; then
    jq -cn \
      --arg schema "${receipt_schema}" \
      --arg status "${status}" \
      --arg code "${code}" \
      --arg message "${message}" \
      --arg contractSha256 "${contract_sha}" \
      --arg hostOs "${host_os}" \
      --arg hostArch "${host_arch}" \
      '{
        schema: $schema,
        status: $status,
        code: $code,
        message: $message,
        contractSha256: $contractSha256,
        hostOs: $hostOs,
        hostArch: $hostArch
      }'
  else
    printf '%s\n' \
      "{\"schema\":\"${receipt_schema}\",\"status\":\"${status}\",\"code\":\"${code}\",\"message\":\"gate dependency unavailable\",\"contractSha256\":\"${contract_sha}\",\"hostOs\":\"${host_os}\",\"hostArch\":\"${host_arch}\"}"
  fi
  printf 'Dioxus toolchain gate: %s (%s)\n' "${message}" "${code}" >&2
  exit "${exit_code}"
}

unexpected_failure() {
  local exit_code="$1"
  local line="$2"
  if [[ "${problem_emitted}" != true ]]; then
    printf 'Unexpected Dioxus gate failure at line %s (status %s)\n' \
      "${line}" "${exit_code}" >&2
    emit_problem "FAIL" "INTERNAL_GATE_ERROR" \
      "the Dioxus provenance gate failed unexpectedly" 1
  fi
  exit "${exit_code}"
}

trap cleanup EXIT
trap 'unexpected_failure "$?" "${LINENO}"' ERR

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    emit_problem "BLOCKED_ENV" "BLOCKED_ENV_GATE_DEPENDENCY_MISSING" \
      "a required Dioxus gate dependency is unavailable" 2
  fi
}

require_test_override_scope() {
  local variable_name="$1"
  local value="$2"
  if [[ -n "${value}" && "${test_mode}" != "1" ]]; then
    printf 'Test-only override rejected: %s\n' "${variable_name}" >&2
    emit_problem "FAIL" "INVALID_ARGUMENT" \
      "a test-only Dioxus gate override was used outside self-test mode" 1
  fi
}

is_safe_relative_path() {
  local path="$1"
  [[ -n "${path}" && "${path}" != /* && "${path}" != ".." && \
    "${path}" != ../* && "${path}" != */../* && "${path}" != */.. ]]
}

validate_contract() {
  if [[ ! -f "${contract_path}" || -L "${contract_path}" ]]; then
    emit_problem "FAIL" "CONTRACT_INVALID" \
      "the Dioxus build contract is missing or is not a regular file" 1
  fi

  contract_sha="$(shasum -a 256 "${contract_path}" | awk '{print $1}')"

  if ! jq -e '
    . == {
      schema: "hartevo.dioxus-build-contract/v1",
      cli: {
        binary: "dx",
        package: "dioxus-cli",
        version: "0.7.10",
        versionExtraction: "first-semver-token"
      },
      host: {
        os: "Darwin",
        architectures: ["arm64"]
      },
      gate: {
        script: "scripts/check-dioxus-toolchain.sh",
        buildMode: "build",
        verifyReceiptMode: "verify-receipt",
        selfTestMode: "self-test"
      },
      build: {
        workingDirectory: ".",
        package: "hartevo-desktop",
        command: [
          "dx",
          "build",
          "--package",
          "hartevo-desktop",
          "--features",
          "bundle",
          "--locked"
        ],
        profile: "debug",
        defaultFeatures: ["desktop"],
        requestedFeatures: ["bundle"],
        allFeatures: false,
        noDefaultFeatures: false
      },
      provenanceInputs: [
        "Cargo.lock",
        "Cargo.toml",
        "Dioxus.toml",
        "hartevo-rs/desktop/Cargo.toml",
        "rust-toolchain.toml"
      ],
      sourceAssertions: [
        {
          path: "Cargo.toml",
          line: "dioxus = { version = \"=0.7.10\", default-features = false, features = [\"launch\", \"lib\"] }"
        },
        {
          path: "hartevo-rs/desktop/Cargo.toml",
          line: "default = [\"desktop\"]"
        },
        {
          path: "hartevo-rs/desktop/Cargo.toml",
          line: "bundle = []"
        },
        {
          path: "Dioxus.toml",
          line: "sub_package = \"hartevo-desktop\""
        },
        {
          path: "rust-toolchain.toml",
          line: "channel = \"1.95.0\""
        }
      ],
      artifact: {
        type: "macos-app-directory",
        path: "target/dx/hartevo-desktop/debug/macos/HartevoDesktop.app",
        requiredEntries: [
          {
            path: "Contents/Info.plist",
            type: "regular-file",
            nonEmpty: true,
            executable: false
          },
          {
            path: "Contents/MacOS/hartevo-desktop",
            type: "regular-file",
            nonEmpty: true,
            executable: true
          },
          {
            path: "Contents/Resources",
            type: "directory",
            nonEmpty: true
          }
        ],
        digest: {
          algorithm: "sha256-tree-manifest-v1",
          selection: ["regular-file"],
          pathEncoding: "lowercase-hex-of-relative-path-bytes",
          recordFormat: "F<TAB>pathHex<TAB>payloadSha256<TAB>payloadByteCount<LF>",
          ordering: "LC_ALL=C-sort-complete-record",
          regularFilePayload: "raw-file-bytes",
          pathComponents: "symbolic-links-rejected",
          symbolicLinks: "rejected",
          specialFileTypes: "rejected",
          directories: "excluded",
          extendedAttributes: "excluded",
          fileModes: "excluded-except-required-entry-assertions",
          readPasses: 2
        }
      },
      receipt: {
        schema: "hartevo.dioxus-build-provenance/v1",
        statusValues: {
          pass: "PASS",
          testOnly: "TEST_ONLY",
          blockedEnvironment: "BLOCKED_ENV",
          failure: "FAIL"
        },
        passCode: "DIOXUS_BUNDLE_VERIFIED",
        testOnlyCode: "DIOXUS_BUNDLE_FIXTURE_VERIFIED",
        evidenceClasses: {
          build: "REAL_DX_BUILD",
          fixture: "TEST_FIXTURE"
        },
        blockedEnvironmentCodes: [
          "BLOCKED_ENV_DX_MISSING",
          "BLOCKED_ENV_GATE_DEPENDENCY_MISSING",
          "BLOCKED_ENV_UNSUPPORTED_HOST"
        ],
        failureCodes: [
          "ARTIFACT_DIGEST_FAILED",
          "ARTIFACT_DIGEST_UNSTABLE",
          "ARTIFACT_ENTRY_MISMATCH",
          "ARTIFACT_MISSING",
          "ARTIFACT_TYPE_MISMATCH",
          "ARTIFACT_UNSUPPORTED_ENTRY",
          "CONTRACT_INVALID",
          "DX_BUILD_FAILED",
          "DX_BINARY_CHANGED",
          "DX_VERSION_MISMATCH",
          "DX_VERSION_UNREADABLE",
          "INTERNAL_GATE_ERROR",
          "INVALID_ARGUMENT",
          "RECEIPT_INVALID",
          "RECEIPT_PROVENANCE_MISMATCH",
          "SOURCE_ASSERTION_FAILED"
        ],
        passFields: [
          "artifactByteCount",
          "artifactDigest",
          "artifactDigestAlgorithm",
          "artifactFileCount",
          "artifactPath",
          "artifactType",
          "buildCommand",
          "cliBinarySha256",
          "cliVersion",
          "cliVersionOutputSha256",
          "code",
          "contractSha256",
          "defaultFeatures",
          "evidenceClass",
          "gateSha256",
          "hostArch",
          "hostOs",
          "inputDigests",
          "package",
          "profile",
          "requestedFeatures",
          "schema",
          "sourceCommit",
          "sourceDirty",
          "status",
          "testMode"
        ],
        problemFields: [
          "code",
          "contractSha256",
          "hostArch",
          "hostOs",
          "message",
          "schema",
          "status"
        ]
      }
    }
  ' "${contract_path}" >/dev/null; then
    emit_problem "FAIL" "CONTRACT_INVALID" \
      "the Dioxus build contract differs from the adopted frozen surface" 1
  fi
}

verify_source_assertions() {
  local path
  local expected_line
  local absolute_path

  while IFS=$'\t' read -r path expected_line; do
    if ! is_safe_relative_path "${path}"; then
      emit_problem "FAIL" "CONTRACT_INVALID" \
        "a Dioxus source assertion path is unsafe" 1
    fi
    absolute_path="${workspace_root}/${path}"
    if [[ ! -f "${absolute_path}" || -L "${absolute_path}" ]] || \
      ! grep -Fqx "${expected_line}" "${absolute_path}"; then
      printf 'Source assertion failed: %s :: %s\n' \
        "${path}" "${expected_line}" >&2
      emit_problem "FAIL" "SOURCE_ASSERTION_FAILED" \
        "a Dioxus build source assertion no longer matches the repository" 1
    fi
  done < <(jq -r '.sourceAssertions[] | [.path, .line] | @tsv' "${contract_path}")

  if [[ "${workspace_root}/$(jq -r '.gate.script' "${contract_path}")" != \
    "${script_path}" ]]; then
    emit_problem "FAIL" "SOURCE_ASSERTION_FAILED" \
      "the Dioxus gate is not running from its contracted repository path" 1
  fi
}

resolve_host() {
  local override_os="${HARTEVO_DIOXUS_TEST_HOST_OS:-}"
  local override_arch="${HARTEVO_DIOXUS_TEST_HOST_ARCH:-}"
  require_test_override_scope "HARTEVO_DIOXUS_TEST_HOST_OS" "${override_os}"
  require_test_override_scope "HARTEVO_DIOXUS_TEST_HOST_ARCH" "${override_arch}"

  host_os="${override_os:-$(uname -s)}"
  host_arch="${override_arch:-$(uname -m)}"

  if [[ "${host_os}" != "$(jq -r '.host.os' "${contract_path}")" ]] || \
    ! jq -e --arg arch "${host_arch}" \
      '.host.architectures | index($arch) != null' "${contract_path}" >/dev/null; then
    emit_problem "BLOCKED_ENV" "BLOCKED_ENV_UNSUPPORTED_HOST" \
      "the current host is outside the frozen Dioxus bundle matrix" 2
  fi
}

resolve_dx() {
  local override_dx="${HARTEVO_DIOXUS_TEST_DX_BIN:-}"
  local candidate
  require_test_override_scope "HARTEVO_DIOXUS_TEST_DX_BIN" "${override_dx}"

  if [[ -n "${override_dx}" ]]; then
    candidate="${override_dx}"
  else
    candidate="$(command -v dx 2>/dev/null || true)"
  fi

  if [[ -z "${candidate}" || ! -f "${candidate}" || ! -x "${candidate}" ]]; then
    emit_problem "BLOCKED_ENV" "BLOCKED_ENV_DX_MISSING" \
      "the pinned Dioxus CLI executable is unavailable" 2
  fi

  dx_binary="$(cd "$(dirname "${candidate}")" && pwd -P)/$(basename "${candidate}")"
}

verify_dx_version() {
  local expected_version
  expected_version="$(jq -r '.cli.version' "${contract_path}")"

  if ! dx_version_output="$("${dx_binary}" --version 2>&1)"; then
    emit_problem "FAIL" "DX_VERSION_UNREADABLE" \
      "the Dioxus CLI version command failed" 1
  fi

  dx_version="$(printf '%s\n' "${dx_version_output}" \
    | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
  if [[ -z "${dx_version}" ]]; then
    emit_problem "FAIL" "DX_VERSION_UNREADABLE" \
      "the Dioxus CLI version output contains no semantic version" 1
  fi
  if [[ "${dx_version}" != "${expected_version}" ]]; then
    printf 'Dioxus CLI version mismatch: expected %s, got %s\n' \
      "${expected_version}" "${dx_version}" >&2
    emit_problem "FAIL" "DX_VERSION_MISMATCH" \
      "the installed Dioxus CLI version differs from the frozen version" 1
  fi

  dx_version_output_sha="$(printf '%s' "${dx_version_output}" | shasum -a 256 \
    | awk '{print $1}')"
  dx_binary_sha_before="$(shasum -a 256 "${dx_binary}" | awk '{print $1}')"
}

run_build() {
  local command_parts=()
  local argument

  while IFS= read -r argument; do
    command_parts+=("${argument}")
  done < <(jq -r '.build.command[]' "${contract_path}")

  if ! (
    cd "${workspace_root}"
    "${dx_binary}" "${command_parts[@]:1}"
  ) >&2; then
    emit_problem "FAIL" "DX_BUILD_FAILED" \
      "the frozen Dioxus build command failed" 1
  fi
}

assert_no_symlink_path_components() {
  local relative_path="$1"
  local cursor="${workspace_root}"
  local component
  local components=()
  IFS='/' read -r -a components <<<"${relative_path}"
  for component in "${components[@]}"; do
    cursor="${cursor}/${component}"
    if [[ -L "${cursor}" ]]; then
      emit_problem "FAIL" "ARTIFACT_TYPE_MISMATCH" \
        "a Dioxus artifact path component is a symbolic link" 1
    fi
  done
}

resolve_artifact_root() {
  local override_root="${HARTEVO_DIOXUS_TEST_ARTIFACT_ROOT:-}"
  local relative_path
  require_test_override_scope "HARTEVO_DIOXUS_TEST_ARTIFACT_ROOT" "${override_root}"
  relative_path="$(jq -r '.artifact.path' "${contract_path}")"

  if ! is_safe_relative_path "${relative_path}"; then
    emit_problem "FAIL" "CONTRACT_INVALID" \
      "the Dioxus artifact path is unsafe" 1
  fi

  if [[ -n "${override_root}" ]]; then
    artifact_root="${override_root}"
  else
    assert_no_symlink_path_components "${relative_path}"
    artifact_root="${workspace_root}/${relative_path}"
  fi

  if [[ ! -e "${artifact_root}" ]]; then
    emit_problem "FAIL" "ARTIFACT_MISSING" \
      "the frozen Dioxus build produced no artifact at the contracted path" 1
  fi
  if [[ ! -d "${artifact_root}" || -L "${artifact_root}" ]]; then
    emit_problem "FAIL" "ARTIFACT_TYPE_MISMATCH" \
      "the Dioxus artifact is not the contracted app directory" 1
  fi
}

verify_required_entries() {
  local path
  local entry_type
  local non_empty
  local executable
  local entry

  while IFS=$'\t' read -r path entry_type non_empty executable; do
    if ! is_safe_relative_path "${path}"; then
      emit_problem "FAIL" "CONTRACT_INVALID" \
        "a required Dioxus artifact entry path is unsafe" 1
    fi
    entry="${artifact_root}/${path}"
    if [[ "${entry_type}" == "regular-file" ]]; then
      if [[ ! -f "${entry}" || -L "${entry}" ]]; then
        emit_problem "FAIL" "ARTIFACT_ENTRY_MISMATCH" \
          "a required Dioxus artifact file is missing or has the wrong type" 1
      fi
      if [[ "${non_empty}" == "true" && ! -s "${entry}" ]]; then
        emit_problem "FAIL" "ARTIFACT_ENTRY_MISMATCH" \
          "a required Dioxus artifact file is empty" 1
      fi
      if [[ "${executable}" == "true" && ! -x "${entry}" ]] || \
        [[ "${executable}" == "false" && -x "${entry}" ]]; then
        emit_problem "FAIL" "ARTIFACT_ENTRY_MISMATCH" \
          "a required Dioxus artifact file has the wrong executable mode" 1
      fi
    elif [[ "${entry_type}" == "directory" ]]; then
      if [[ ! -d "${entry}" || -L "${entry}" ]]; then
        emit_problem "FAIL" "ARTIFACT_ENTRY_MISMATCH" \
          "a required Dioxus artifact directory is missing or has the wrong type" 1
      fi
      if [[ "${non_empty}" == "true" ]] && \
        ! find "${entry}" -type f -print -quit | grep -q .; then
        emit_problem "FAIL" "ARTIFACT_ENTRY_MISMATCH" \
          "a required Dioxus artifact directory contains no regular file" 1
      fi
    else
      emit_problem "FAIL" "CONTRACT_INVALID" \
        "the Dioxus contract contains an unsupported required entry type" 1
    fi
  done < <(jq -r '
    .artifact.requiredEntries[]
    | [
        .path,
        .type,
        (.nonEmpty | tostring),
        (if has("executable") then (.executable | tostring) else "unset" end)
      ]
    | @tsv
  ' "${contract_path}")
}

write_tree_manifest() {
  local output="$1"
  local unsorted="${output}.unsorted"
  local file
  local relative_path
  local path_hex
  local payload_sha
  local payload_size

  : >"${unsorted}"
  while IFS= read -r -d '' file; do
    if [[ ! -f "${file}" || -L "${file}" ]]; then
      emit_problem "FAIL" "ARTIFACT_DIGEST_UNSTABLE" \
        "a Dioxus artifact entry changed type during digest collection" 1
    fi
    relative_path="${file#"${artifact_root}/"}"
    path_hex="$(printf '%s' "${relative_path}" | od -An -v -tx1 \
      | tr -d ' \n')"
    payload_sha="$(shasum -a 256 "${file}" | awk '{print $1}')"
    payload_size="$(wc -c <"${file}" | tr -d ' ')"
    if [[ ! -f "${file}" || -L "${file}" ]]; then
      emit_problem "FAIL" "ARTIFACT_DIGEST_UNSTABLE" \
        "a Dioxus artifact entry changed type during digest collection" 1
    fi
    printf 'F\t%s\t%s\t%s\n' \
      "${path_hex}" "${payload_sha}" "${payload_size}" >>"${unsorted}"
  done < <(find "${artifact_root}" -type f -print0)
  LC_ALL=C sort "${unsorted}" >"${output}"
}

digest_artifact() {
  local unsupported_entry
  local manifest_one="${work_dir}/artifact-manifest-one.tsv"
  local manifest_two="${work_dir}/artifact-manifest-two.tsv"
  local record_kind
  local path_hex
  local payload_sha
  local payload_size

  unsupported_entry="$(find "${artifact_root}" ! -type f ! -type d -print -quit)"
  if [[ -n "${unsupported_entry}" ]]; then
    emit_problem "FAIL" "ARTIFACT_UNSUPPORTED_ENTRY" \
      "the Dioxus artifact contains a symbolic link or special file" 1
  fi

  write_tree_manifest "${manifest_one}"
  write_tree_manifest "${manifest_two}"
  if ! cmp -s "${manifest_one}" "${manifest_two}"; then
    emit_problem "FAIL" "ARTIFACT_DIGEST_UNSTABLE" \
      "the Dioxus artifact changed while its digest was read back" 1
  fi
  if [[ ! -s "${manifest_one}" ]]; then
    emit_problem "FAIL" "ARTIFACT_DIGEST_FAILED" \
      "the Dioxus artifact contains no regular files to digest" 1
  fi

  artifact_digest="$(shasum -a 256 "${manifest_one}" | awk '{print $1}')"
  artifact_file_count=0
  artifact_byte_count=0
  while IFS=$'\t' read -r record_kind path_hex payload_sha payload_size; do
    if [[ "${record_kind}" != "F" || -z "${path_hex}" || \
      ! "${payload_sha}" =~ ^[0-9a-f]{64}$ || \
      ! "${payload_size}" =~ ^[0-9]+$ ]]; then
      emit_problem "FAIL" "ARTIFACT_DIGEST_FAILED" \
        "the Dioxus artifact manifest is malformed" 1
    fi
    artifact_file_count=$((artifact_file_count + 1))
    artifact_byte_count=$((artifact_byte_count + 10#${payload_size}))
  done <"${manifest_one}"
}

compute_input_digests() {
  local path
  local absolute_path
  local digest
  input_digests='{}'
  while IFS= read -r path; do
    if ! is_safe_relative_path "${path}"; then
      emit_problem "FAIL" "CONTRACT_INVALID" \
        "a Dioxus provenance input path is unsafe" 1
    fi
    absolute_path="${workspace_root}/${path}"
    if [[ ! -f "${absolute_path}" || -L "${absolute_path}" ]]; then
      emit_problem "FAIL" "SOURCE_ASSERTION_FAILED" \
        "a Dioxus provenance input is missing or has the wrong type" 1
    fi
    digest="$(shasum -a 256 "${absolute_path}" | awk '{print $1}')"
    input_digests="$(jq -c --arg path "${path}" --arg digest "${digest}" \
      '. + {($path): $digest}' <<<"${input_digests}")"
  done < <(jq -r '.provenanceInputs[]' "${contract_path}")
}

write_pass_receipt() {
  local output="$1"
  local source_commit
  local source_dirty
  local dx_binary_sha_after
  local build_command
  local default_features
  local requested_features
  local receipt_status
  local receipt_code
  local evidence_class
  local receipt_test_mode
  local gate_sha

  dx_binary_sha_after="$(shasum -a 256 "${dx_binary}" | awk '{print $1}')"
  if [[ "${dx_binary_sha_after}" != "${dx_binary_sha_before}" ]]; then
    emit_problem "FAIL" "DX_BINARY_CHANGED" \
      "the Dioxus CLI binary changed during provenance collection" 1
  fi

  source_commit="$(git -C "${workspace_root}" rev-parse HEAD)"
  if [[ -n "$(git -C "${workspace_root}" status --porcelain=v1)" ]]; then
    source_dirty=true
  else
    source_dirty=false
  fi
  build_command="$(jq -c '.build.command' "${contract_path}")"
  default_features="$(jq -c '.build.defaultFeatures' "${contract_path}")"
  requested_features="$(jq -c '.build.requestedFeatures' "${contract_path}")"
  gate_sha="$(shasum -a 256 "${script_path}" | awk '{print $1}')"
  if [[ "${test_mode}" == "1" ]]; then
    receipt_status="TEST_ONLY"
    receipt_code="DIOXUS_BUNDLE_FIXTURE_VERIFIED"
    evidence_class="TEST_FIXTURE"
    receipt_test_mode=true
  else
    receipt_status="PASS"
    receipt_code="DIOXUS_BUNDLE_VERIFIED"
    evidence_class="REAL_DX_BUILD"
    receipt_test_mode=false
  fi

  jq -cn \
    --arg schema "${receipt_schema}" \
    --arg status "${receipt_status}" \
    --arg code "${receipt_code}" \
    --arg evidenceClass "${evidence_class}" \
    --argjson testMode "${receipt_test_mode}" \
    --arg cliVersion "${dx_version}" \
    --arg cliVersionOutputSha256 "${dx_version_output_sha}" \
    --arg cliBinarySha256 "${dx_binary_sha_after}" \
    --arg package "$(jq -r '.build.package' "${contract_path}")" \
    --arg profile "$(jq -r '.build.profile' "${contract_path}")" \
    --arg artifactType "$(jq -r '.artifact.type' "${contract_path}")" \
    --arg artifactPath "$(jq -r '.artifact.path' "${contract_path}")" \
    --arg artifactDigestAlgorithm "$(jq -r '.artifact.digest.algorithm' "${contract_path}")" \
    --arg artifactDigest "${artifact_digest}" \
    --argjson artifactFileCount "${artifact_file_count}" \
    --argjson artifactByteCount "${artifact_byte_count}" \
    --arg contractSha256 "${contract_sha}" \
    --arg gateSha256 "${gate_sha}" \
    --arg sourceCommit "${source_commit}" \
    --argjson sourceDirty "${source_dirty}" \
    --arg hostOs "${host_os}" \
    --arg hostArch "${host_arch}" \
    --argjson buildCommand "${build_command}" \
    --argjson defaultFeatures "${default_features}" \
    --argjson requestedFeatures "${requested_features}" \
    --argjson inputDigests "${input_digests}" \
    '{
      schema: $schema,
      status: $status,
      code: $code,
      evidenceClass: $evidenceClass,
      testMode: $testMode,
      cliVersion: $cliVersion,
      cliVersionOutputSha256: $cliVersionOutputSha256,
      cliBinarySha256: $cliBinarySha256,
      package: $package,
      profile: $profile,
      buildCommand: $buildCommand,
      defaultFeatures: $defaultFeatures,
      requestedFeatures: $requestedFeatures,
      artifactType: $artifactType,
      artifactPath: $artifactPath,
      artifactDigestAlgorithm: $artifactDigestAlgorithm,
      artifactDigest: $artifactDigest,
      artifactFileCount: $artifactFileCount,
      artifactByteCount: $artifactByteCount,
      inputDigests: $inputDigests,
      contractSha256: $contractSha256,
      gateSha256: $gateSha256,
      sourceCommit: $sourceCommit,
      sourceDirty: $sourceDirty,
      hostOs: $hostOs,
      hostArch: $hostArch
    }' >"${output}"

  if ! jq -e --slurpfile contract "${contract_path}" '
    (keys == ($contract[0].receipt.passFields | sort))
    and .schema == $contract[0].receipt.schema
    and (
      (
        .testMode == false
        and .status == $contract[0].receipt.statusValues.pass
        and .code == $contract[0].receipt.passCode
        and .evidenceClass == $contract[0].receipt.evidenceClasses.build
      )
      or
      (
        .testMode == true
        and .status == $contract[0].receipt.statusValues.testOnly
        and .code == $contract[0].receipt.testOnlyCode
        and .evidenceClass == $contract[0].receipt.evidenceClasses.fixture
      )
    )
    and (.artifactDigest | test("^[0-9a-f]{64}$"))
    and (.contractSha256 | test("^[0-9a-f]{64}$"))
    and (.gateSha256 | test("^[0-9a-f]{64}$"))
    and (.cliBinarySha256 | test("^[0-9a-f]{64}$"))
    and (.cliVersionOutputSha256 | test("^[0-9a-f]{64}$"))
    and (.artifactFileCount > 0)
    and (.artifactByteCount > 0)
  ' "${output}" >/dev/null; then
    emit_problem "FAIL" "RECEIPT_INVALID" \
      "the generated Dioxus provenance receipt violates its contract" 1
  fi
}

verify_receipt() {
  local expected_receipt="$1"
  local actual_receipt="$2"
  local expected_canonical="${work_dir}/expected-receipt.canonical.json"
  local actual_canonical="${work_dir}/actual-receipt.canonical.json"

  if [[ ! -f "${expected_receipt}" || -L "${expected_receipt}" ]] || \
    ! jq -e --slurpfile contract "${contract_path}" '
      (keys == ($contract[0].receipt.passFields | sort))
      and .schema == $contract[0].receipt.schema
      and (
        (
          .testMode == false
          and .status == $contract[0].receipt.statusValues.pass
          and .code == $contract[0].receipt.passCode
          and .evidenceClass == $contract[0].receipt.evidenceClasses.build
        )
        or
        (
          .testMode == true
          and .status == $contract[0].receipt.statusValues.testOnly
          and .code == $contract[0].receipt.testOnlyCode
          and .evidenceClass == $contract[0].receipt.evidenceClasses.fixture
        )
      )
    ' "${expected_receipt}" >/dev/null; then
    emit_problem "FAIL" "RECEIPT_INVALID" \
      "the supplied Dioxus provenance receipt is missing or malformed" 1
  fi

  jq -S . "${expected_receipt}" >"${expected_canonical}"
  jq -S . "${actual_receipt}" >"${actual_canonical}"
  if ! cmp -s "${expected_canonical}" "${actual_canonical}"; then
    diff -u "${expected_canonical}" "${actual_canonical}" >&2 || true
    emit_problem "FAIL" "RECEIPT_PROVENANCE_MISMATCH" \
      "the exact Dioxus bundle no longer matches its provenance receipt" 1
  fi
}

child_test_environment() {
  env \
    HARTEVO_DIOXUS_TEST_MODE=1 \
    HARTEVO_DIOXUS_TEST_HOST_OS=Darwin \
    HARTEVO_DIOXUS_TEST_HOST_ARCH=arm64 \
    HARTEVO_DIOXUS_TEST_DX_BIN="$1" \
    HARTEVO_DIOXUS_TEST_ARTIFACT_ROOT="$2" \
    HARTEVO_DIOXUS_CONTRACT_PATH="$3" \
    "${script_path}" "${@:4}"
}

assert_problem_receipt() {
  local receipt="$1"
  local expected_status="$2"
  local expected_code="$3"
  if ! jq -e \
    --arg schema "${receipt_schema}" \
    --arg status "${expected_status}" \
    --arg code "${expected_code}" \
    '.schema == $schema and .status == $status and .code == $code' \
    "${receipt}" >/dev/null; then
    printf 'Unexpected problem receipt for %s/%s:\n' \
      "${expected_status}" "${expected_code}" >&2
    jq . "${receipt}" >&2 || true
    return 1
  fi
}

run_self_test() {
  local fixture_root="${work_dir}/fixture/HartevoDesktop.app"
  local fake_dx="${work_dir}/fake-dx"
  local wrong_dx="${work_dir}/wrong-dx"
  local mutated_contract="${work_dir}/mutated-contract.json"
  local pass_receipt="${work_dir}/pass-receipt.json"
  local problem_receipt="${work_dir}/problem-receipt.json"
  local problem_log="${work_dir}/problem.log"

  mkdir -p "${fixture_root}/Contents/MacOS" \
    "${fixture_root}/Contents/Resources/assets"
  printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>team.hartevo.desktop</string></dict></plist>' \
    >"${fixture_root}/Contents/Info.plist"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
    >"${fixture_root}/Contents/MacOS/hartevo-desktop"
  chmod +x "${fixture_root}/Contents/MacOS/hartevo-desktop"
  printf '%s\n' 'fixture-asset-v1' \
    >"${fixture_root}/Contents/Resources/assets/app.css"

  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'if [[ "${1:-}" == "--version" ]]; then' \
    '  printf "%s\n" "dioxus 0.7.10 (fixture)"' \
    '  exit 0' \
    'fi' \
    '[[ "$#" -eq 6 ]]' \
    '[[ "$1" == "build" && "$2" == "--package" && "$3" == "hartevo-desktop" ]]' \
    '[[ "$4" == "--features" && "$5" == "bundle" && "$6" == "--locked" ]]' \
    >"${fake_dx}"
  chmod +x "${fake_dx}"

  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == "--version" ]]; then printf "%s\n" "dioxus 0.7.9"; exit 0; fi' \
    'exit 0' >"${wrong_dx}"
  chmod +x "${wrong_dx}"

  child_test_environment "${fake_dx}" "${fixture_root}" "${contract_path}" \
    >"${pass_receipt}"
  jq -e '
    .status == "TEST_ONLY"
    and .code == "DIOXUS_BUNDLE_FIXTURE_VERIFIED"
    and .evidenceClass == "TEST_FIXTURE"
    and .testMode == true
  ' \
    "${pass_receipt}" >/dev/null
  child_test_environment "${fake_dx}" "${fixture_root}" "${contract_path}" \
    verify-receipt "${pass_receipt}" >/dev/null

  printf '%s\n' 'artifact-mutation' \
    >>"${fixture_root}/Contents/Resources/assets/app.css"
  if child_test_environment "${fake_dx}" "${fixture_root}" "${contract_path}" \
    verify-receipt "${pass_receipt}" >"${problem_receipt}" 2>"${problem_log}"; then
    printf 'Mutated artifact unexpectedly matched its receipt\n' >&2
    return 1
  fi
  assert_problem_receipt "${problem_receipt}" "FAIL" \
    "RECEIPT_PROVENANCE_MISMATCH"

  jq '.cli.version = "0.7.11"' "${contract_path}" >"${mutated_contract}"
  if child_test_environment "${fake_dx}" "${fixture_root}" "${mutated_contract}" \
    >"${problem_receipt}" 2>"${problem_log}"; then
    printf 'Mutated contract unexpectedly passed\n' >&2
    return 1
  fi
  assert_problem_receipt "${problem_receipt}" "FAIL" "CONTRACT_INVALID"

  if child_test_environment "${wrong_dx}" "${fixture_root}" "${contract_path}" \
    >"${problem_receipt}" 2>"${problem_log}"; then
    printf 'Wrong Dioxus CLI version unexpectedly passed\n' >&2
    return 1
  fi
  assert_problem_receipt "${problem_receipt}" "FAIL" "DX_VERSION_MISMATCH"

  if child_test_environment "${work_dir}/missing-dx" "${fixture_root}" \
    "${contract_path}" >"${problem_receipt}" 2>"${problem_log}"; then
    printf 'Missing Dioxus CLI unexpectedly passed\n' >&2
    return 1
  fi
  assert_problem_receipt "${problem_receipt}" "BLOCKED_ENV" \
    "BLOCKED_ENV_DX_MISSING"

  jq -cn \
    --arg schema "${self_test_schema}" \
    --arg status "PASS" \
    --arg contractSha256 "${contract_sha}" \
    '{
      schema: $schema,
      status: $status,
      contractSha256: $contractSha256,
      checks: [
        "fixture-receipt-is-test-only",
        "exact-receipt-readback",
        "artifact-mutation-rejected",
        "contract-mutation-rejected",
        "dx-version-mismatch-rejected",
        "dx-missing-blocked-nonzero"
      ]
    }'
}

main() {
  local mode="build"
  local receipt_to_verify=""
  local actual_receipt

  if [[ $# -gt 0 ]]; then
    mode="$1"
    shift
  fi
  case "${mode}" in
    build | self-test)
      if [[ $# -ne 0 ]]; then
        emit_problem "FAIL" "INVALID_ARGUMENT" \
          "the Dioxus gate received unexpected arguments" 1
      fi
      ;;
    verify-receipt)
      if [[ $# -ne 1 ]]; then
        emit_problem "FAIL" "INVALID_ARGUMENT" \
          "verify-receipt requires exactly one receipt path" 1
      fi
      receipt_to_verify="$1"
      ;;
    *)
      emit_problem "FAIL" "INVALID_ARGUMENT" \
        "the Dioxus gate mode is unsupported" 1
      ;;
  esac

  for dependency in jq shasum git find sort cmp od awk grep sed wc uname mktemp \
    diff env; do
    require_tool "${dependency}"
  done

  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-dioxus-gate.XXXXXX")"
  validate_contract
  verify_source_assertions

  if [[ "${mode}" == "self-test" ]]; then
    run_self_test
    return
  fi

  resolve_host
  resolve_dx
  verify_dx_version
  compute_input_digests
  if [[ "${mode}" == "build" ]]; then
    run_build
  fi
  resolve_artifact_root
  verify_required_entries
  digest_artifact

  actual_receipt="${work_dir}/actual-receipt.json"
  write_pass_receipt "${actual_receipt}"
  if [[ "${mode}" == "verify-receipt" ]]; then
    verify_receipt "${receipt_to_verify}" "${actual_receipt}"
  fi
  jq -c . "${actual_receipt}"
}

main "$@"
