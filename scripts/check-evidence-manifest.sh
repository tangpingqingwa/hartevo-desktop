#!/usr/bin/env bash
set -Eeuo pipefail

readonly verification_schema="hartevo.commit-bound-evidence-verification/v1"
readonly script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
readonly default_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly default_contract_path="${default_repo_root}/contracts/evidence/commit-bound-manifest.v1.json"

emit_shell_problem() {
  local status="$1"
  local code="$2"
  local message="$3"

  printf '{"schema":"%s","status":"%s","code":"%s","message":"%s","releaseDecision":"NOT_EVALUATED"}\n' \
    "${verification_schema}" "${status}" "${code}" "${message}"
}

fail_argument() {
  emit_shell_problem "FAIL" "INVALID_ARGUMENT" "$1"
  exit 1
}

readonly test_mode="${HARTEVO_EVIDENCE_TEST_MODE:-0}"
if [[ "${test_mode}" != "0" && "${test_mode}" != "1" ]]; then
  fail_argument "HARTEVO_EVIDENCE_TEST_MODE must be 0 or 1"
fi

if [[ "${test_mode}" != "1" ]] && \
  { [[ -n "${HARTEVO_EVIDENCE_TEST_REPO_ROOT+x}" ]] || \
    [[ -n "${HARTEVO_EVIDENCE_CONTRACT_PATH+x}" ]] || \
    [[ -n "${HARTEVO_EVIDENCE_TEST_PYTHON_BIN+x}" ]]; }; then
  fail_argument "test-only overrides require HARTEVO_EVIDENCE_TEST_MODE=1"
fi

readonly repo_root="${HARTEVO_EVIDENCE_TEST_REPO_ROOT:-${default_repo_root}}"
readonly contract_path="${HARTEVO_EVIDENCE_CONTRACT_PATH:-${default_contract_path}}"
readonly python_bin="${HARTEVO_EVIDENCE_TEST_PYTHON_BIN:-python3}"

if ! command -v git >/dev/null 2>&1; then
  emit_shell_problem "BLOCKED_ENV" "BLOCKED_ENV_GATE_DEPENDENCY_MISSING" \
    "required dependency git is unavailable"
  exit 2
fi
readonly git_bin="$(command -v git)"

if ! command -v mktemp >/dev/null 2>&1; then
  emit_shell_problem "BLOCKED_ENV" "BLOCKED_ENV_GATE_DEPENDENCY_MISSING" \
    "required dependency mktemp is unavailable"
  exit 2
fi

if [[ "${python_bin}" == */* ]]; then
  if [[ ! -x "${python_bin}" ]]; then
    emit_shell_problem "BLOCKED_ENV" "BLOCKED_ENV_GATE_DEPENDENCY_MISSING" \
      "required dependency python3 is unavailable"
    exit 2
  fi
elif ! command -v "${python_bin}" >/dev/null 2>&1; then
  emit_shell_problem "BLOCKED_ENV" "BLOCKED_ENV_GATE_DEPENDENCY_MISSING" \
    "required dependency python3 is unavailable"
  exit 2
fi

if [[ "$#" -lt 1 ]]; then
  fail_argument "mode is required"
fi

readonly mode="$1"
shift

manifest_commit=""
expected_source=""
expected_manifest_sha256=""
self_test_dir=""

case "${mode}" in
  verify)
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --manifest-commit)
          [[ "$#" -ge 2 && -z "${manifest_commit}" ]] || \
            fail_argument "--manifest-commit requires one unique value"
          manifest_commit="$2"
          shift 2
          ;;
        --expected-source)
          [[ "$#" -ge 2 && -z "${expected_source}" ]] || \
            fail_argument "--expected-source requires one unique value"
          expected_source="$2"
          shift 2
          ;;
        --expected-manifest-sha256)
          [[ "$#" -ge 2 && -z "${expected_manifest_sha256}" ]] || \
            fail_argument "--expected-manifest-sha256 requires one unique value"
          expected_manifest_sha256="$2"
          shift 2
          ;;
        *)
          fail_argument "unknown verify argument"
          ;;
      esac
    done
    [[ -n "${manifest_commit}" ]] || fail_argument "--manifest-commit is required"
    [[ -n "${expected_source}" ]] || fail_argument "--expected-source is required"
    [[ -n "${expected_manifest_sha256}" ]] || \
      fail_argument "--expected-manifest-sha256 is required"
    ;;
  self-test)
    [[ "$#" -eq 0 ]] || fail_argument "self-test accepts no arguments"
    if ! self_test_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-evidence-self-test.XXXXXX")"; then
      emit_shell_problem "BLOCKED_ENV" "BLOCKED_ENV_TEMP_DIRECTORY" \
        "unable to create self-test directory"
      exit 2
    fi
    cleanup_self_test_dir() {
      local leaf
      leaf="$(basename "${self_test_dir}")"
      if [[ -n "${self_test_dir}" && -d "${self_test_dir}" && \
        "${leaf}" == hartevo-evidence-self-test.* ]]; then
        rm -rf -- "${self_test_dir}"
      fi
    }
    trap cleanup_self_test_dir EXIT
    ;;
  *)
    fail_argument "mode must be verify or self-test"
    ;;
esac

set +e
"${python_bin}" - \
  "${script_path}" \
  "${mode}" \
  "${repo_root}" \
  "${contract_path}" \
  "${manifest_commit}" \
  "${expected_source}" \
  "${expected_manifest_sha256}" \
  "${test_mode}" \
  "${self_test_dir}" \
  "${git_bin}" <<'PY'
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


SCRIPT_PATH = sys.argv[1]
MODE = sys.argv[2]
REPO_ROOT = Path(sys.argv[3])
CONTRACT_PATH = Path(sys.argv[4])
MANIFEST_COMMIT = sys.argv[5]
EXPECTED_SOURCE = sys.argv[6]
EXPECTED_MANIFEST_SHA256 = sys.argv[7]
SHELL_TEST_MODE = sys.argv[8] == "1"
SELF_TEST_DIR = Path(sys.argv[9]) if sys.argv[9] else None
GIT_BIN = sys.argv[10]

CONTRACT_SHA256 = "e7639e21b0c993d7c526b6fc01b6b801386ea88eb4fa092315298195791890be"
CONTRACT_SCHEMA = "hartevo.commit-bound-evidence-contract/v1"
MANIFEST_SCHEMA = "hartevo.commit-bound-evidence-manifest/v1"
VERIFICATION_SCHEMA = "hartevo.commit-bound-evidence-verification/v1"
RELEASE_DECISION = "NOT_EVALUATED"
MANIFEST_PATH_PREFIX = "artifacts/evidence/commit-bound/"
REGULAR_BLOB_MODES = {"100644", "100755"}
ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ABSOLUTE_PATH_RE = re.compile(
    r"(?:(?<![:/A-Za-z0-9+.-])/(?!/)[A-Za-z0-9._-]+(?:/[^\s\"']*)?)"
    r"|(?:\b[A-Za-z]:\\[^\s\"']+)"
    r"|(?:(?![A-Za-z0-9])~/(?:[^\s\"']*))"
)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
HOSTNAME_RE = re.compile(
    r"(?i)(?:(?<![./A-Za-z0-9-])localhost\b|"
    r"(?<![./A-Za-z0-9-])(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"(?<![./A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+(?:app|com|corp|dev|home|internal|io|lan|local|net|org)\b)"
)
NETWORK_URL_RE = re.compile(r"(?i)\b(?:https?|ssh)://[^\s/@]+")
URL_USERINFO_RE = re.compile(r"(?i)\b(?:https?|ssh)://[^\s/:@]+:[^\s/@]+@[^\s/]+")
PEM_PRIVATE_KEY_RE = re.compile(
    "-----BEGIN "
    + r"(?:EC |OPENSSH |RSA )?"
    + "PRIVATE "
    + "KEY-----"
    + r"[\s\S]+?"
    + "-----END "
    + r"(?:EC |OPENSSH |RSA )?"
    + "PRIVATE "
    + "KEY-----"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)\b(?:access[_-]?token|api[_-]?key|auth[_-]?token|passwd|password|private[_-]?key|secret)\b"
    r"\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
)
ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9_+=]{32,}")
POSITIVE_STATUS_VALUES = {
    "COMPLETE",
    "COMPLETED",
    "OK",
    "PASS",
    "PASSED",
    "SUCCEEDED",
    "SUCCESS",
    "VERIFIED",
}
SUCCESS_BOOLEAN_KEYS = {
    "allassertionspassed",
    "allcheckspassed",
    "complete",
    "completed",
    "ok",
    "passed",
    "success",
    "successful",
    "succeeded",
    "valid",
    "verified",
}


class GateError(Exception):
    def __init__(self, code, message, status="FAIL"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class DuplicateKeyError(Exception):
    def __init__(self, key):
        super().__init__(key)
        self.key = key


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def problem(error):
    return {
        "schema": VERIFICATION_SCHEMA,
        "status": error.status,
        "code": error.code,
        "message": error.message,
        "releaseDecision": RELEASE_DECISION,
    }


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def load_json_unique(raw, duplicate_code, invalid_code, label):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GateError(invalid_code, label + " must be UTF-8 JSON")
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=parse_constant,
        )
    except DuplicateKeyError:
        raise GateError(duplicate_code, label + " contains a duplicate object key")
    except (ValueError, json.JSONDecodeError):
        raise GateError(invalid_code, label + " is not strict JSON")


def require_exact_keys(value, expected, code, label):
    if not isinstance(value, dict) or sorted(value.keys()) != sorted(expected):
        raise GateError(code, label + " fields do not match the frozen contract")


def require_string(value, code, label):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise GateError(code, label + " must be a non-empty string")


def require_identifier(value, code, label):
    require_string(value, code, label)
    if not ID_RE.fullmatch(value):
        raise GateError(code, label + " is not a canonical identifier")


def require_sha256(value, code, label):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise GateError(code, label + " must be a lowercase SHA-256 digest")


def check_ids(values, duplicate_code, unsorted_code, invalid_code, label):
    if not isinstance(values, list):
        raise GateError(invalid_code, label + " must be an array")
    for value in values:
        require_identifier(value, invalid_code, label + " entry")
    if len(values) != len(set(values)):
        raise GateError(duplicate_code, label + " contains duplicate identifiers")
    if values != sorted(values):
        raise GateError(unsorted_code, label + " must be sorted")


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    return -sum(
        (count / len(value)) * math.log(count / len(value), 2)
        for count in counts.values()
    )


def high_entropy_token(text):
    for match in ENTROPY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", token):
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_]{15,}(?:\+x)?", token):
            continue
        classes = sum(
            bool(re.search(pattern, token))
            for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[_+=]")
        )
        entropy = shannon_entropy(token)
        if classes >= 3 and entropy >= 3.5:
            return True
        if classes >= 2 and re.search(r"[0-9]", token) and entropy >= 4.0:
            return True
    return False


def scan_text(text, strict, code, label):
    if PEM_PRIVATE_KEY_RE.search(text):
        raise GateError(code, label + " contains private-key material")
    if URL_USERINFO_RE.search(text):
        raise GateError(code, label + " contains URL userinfo")
    if high_entropy_token(text):
        raise GateError(code, label + " contains a high-entropy token")
    if strict:
        if ABSOLUTE_PATH_RE.search(text):
            raise GateError(code, label + " contains an absolute or home path")
        if EMAIL_RE.search(text):
            raise GateError(code, label + " contains an email address")
        if HOSTNAME_RE.search(text) or NETWORK_URL_RE.search(text):
            raise GateError(code, label + " contains a host identifier")
    elif SECRET_ASSIGNMENT_RE.search(text):
        raise GateError(code, label + " contains a secret assignment")


def sensitive_key(key):
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    exact = {
        "authorization",
        "credential",
        "credentials",
        "email",
        "home",
        "homedir",
        "homedirectory",
        "host",
        "hostname",
        "password",
        "passwd",
        "secret",
        "token",
        "user",
        "username",
    }
    if normalized in exact:
        return True
    return normalized.endswith(("accesstoken", "apikey", "authtoken", "password", "secret", "token"))


def scan_json_strict(value, code, label):
    if isinstance(value, dict):
        for key, child in value.items():
            if sensitive_key(key):
                raise GateError(code, label + " contains a sensitive field")
            scan_json_strict(child, code, label)
    elif isinstance(value, list):
        for child in value:
            scan_json_strict(child, code, label)
    elif isinstance(value, str):
        scan_text(value, True, code, label)


def scan_evidence_semantics(value, expected_source, code, label):
    if isinstance(value, dict):
        if value.get("testMode") is True:
            raise GateError("ARTIFACT_TEST_ONLY", label + " is test-only evidence")
        if value.get("sourceDirty") is True:
            raise GateError("ARTIFACT_SOURCE_DIRTY", label + " records a dirty source")
        if (
            isinstance(value.get("sourceCommit"), str)
            and value["sourceCommit"] != expected_source
        ):
            raise GateError(
                "ARTIFACT_SOURCE_COMMIT_MISMATCH",
                label + " is bound to another source commit",
            )
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            if (
                normalized_key == "status"
                or normalized_key.endswith("status")
                or normalized_key in {"conclusion", "outcome", "result"}
            ):
                if not isinstance(child, str):
                    raise GateError(code, label + " contains a non-positive status-like value")
                normalized_status = re.sub(r"[^A-Z0-9]+", "_", child.strip().upper()).strip("_")
                if normalized_status not in POSITIVE_STATUS_VALUES:
                    raise GateError(code, label + " contains a non-positive status-like value")
            if (
                normalized_key in SUCCESS_BOOLEAN_KEYS
                or normalized_key.endswith("passed")
                or normalized_key.endswith("succeeded")
                or normalized_key.endswith("verified")
            ) and child is not True:
                raise GateError(
                    "ARTIFACT_NEGATIVE_ASSERTION",
                    label + " contains a false or malformed success assertion",
                )
            scan_evidence_semantics(child, expected_source, code, label)
    elif isinstance(value, list):
        for child in value:
            scan_evidence_semantics(child, expected_source, code, label)


def run_git(repo, arguments, input_bytes=None, check=True):
    process = subprocess.run(
        [GIT_BIN, "-C", str(repo)] + list(arguments),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode != 0:
        raise GateError("GIT_COMMAND_FAILED", "required Git object operation failed")
    return process


def git_text(repo, arguments):
    raw = run_git(repo, arguments).stdout
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise GateError("GIT_OUTPUT_INVALID", "Git returned non-UTF-8 metadata")


def git_object_type(repo, object_id, label):
    process = run_git(repo, ["cat-file", "-t", object_id], check=False)
    if process.returncode != 0:
        raise GateError(
            "BLOCKED_ENV_GIT_OBJECT_MISSING",
            label + " object is unavailable in this clone",
            status="BLOCKED_ENV",
        )
    try:
        return process.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        raise GateError("GIT_OUTPUT_INVALID", "Git returned invalid object metadata")


def ls_tree_entry(repo, commit_id, path, missing_code="ARTIFACT_GIT_BLOB_MISSING"):
    raw = run_git(repo, ["ls-tree", "-z", commit_id, "--", path]).stdout
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise GateError(missing_code, "tracked Git object is missing or ambiguous")
    header, raw_path = records[0].split(b"\t", 1)
    try:
        actual_path = raw_path.decode("utf-8")
        mode, object_type, object_id = header.decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError):
        raise GateError("GIT_OUTPUT_INVALID", "Git returned invalid tree metadata")
    if actual_path != path:
        raise GateError(missing_code, "tracked Git object path does not match")
    return mode, object_type, object_id


def git_blob(repo, object_id):
    if git_object_type(repo, object_id, "blob") != "blob":
        raise GateError("ARTIFACT_GIT_TYPE_INVALID", "tracked Git object is not a blob")
    return run_git(repo, ["cat-file", "blob", object_id]).stdout


def validate_contract(path):
    if not path.is_file() or path.is_symlink():
        raise GateError("CONTRACT_INVALID", "frozen evidence contract is missing or not a regular file")
    raw = path.read_bytes()
    contract = load_json_unique(
        raw,
        "CONTRACT_DUPLICATE_KEY",
        "CONTRACT_INVALID",
        "frozen evidence contract",
    )
    if sha256(raw) != CONTRACT_SHA256:
        raise GateError("CONTRACT_INVALID", "frozen evidence contract digest does not match the gate")
    if not isinstance(contract, dict) or contract.get("schemaVersion") != CONTRACT_SCHEMA:
        raise GateError("CONTRACT_INVALID", "frozen evidence contract schema does not match the gate")
    return contract


def repository_object_format(repo, contract):
    process = run_git(repo, ["rev-parse", "--is-inside-work-tree"], check=False)
    if process.returncode != 0 or process.stdout.strip() != b"true":
        raise GateError("GIT_REPOSITORY_INVALID", "repository root is not a Git worktree")
    value = git_text(repo, ["rev-parse", "--show-object-format"])
    lengths = contract["git"]["objectFormatHexLengths"]
    if value not in lengths:
        raise GateError(
            "BLOCKED_ENV_GIT_OBJECT_FORMAT",
            "repository object format is unsupported",
            status="BLOCKED_ENV",
        )
    return value, lengths[value]


def require_oid(value, length, code, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        raise GateError(code, label + " is not an exact repository object ID")


def validate_repo_path(path):
    require_string(path, "ARTIFACT_URI_INVALID", "artifact Git path")
    pure = PurePosixPath(path)
    if path.startswith("/") or "\\" in path or pure.as_posix() != path:
        raise GateError("ARTIFACT_URI_INVALID", "artifact Git path is not canonical")
    if not re.fullmatch(r"[A-Za-z0-9._+/-]+", path):
        raise GateError("ARTIFACT_URI_INVALID", "artifact Git path contains unsafe pathspec characters")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise GateError("ARTIFACT_URI_INVALID", "artifact Git path escapes the repository")
    if "target" in pure.parts:
        raise GateError("ARTIFACT_TARGET_FORBIDDEN", "target artifacts cannot be clone-verifiable evidence")
    return path


def verify_manifest_publication(repo, manifest_commit, expected_source, expected_digest, contract):
    object_format, oid_length = repository_object_format(repo, contract)
    require_oid(expected_source, oid_length, "EXPECTED_SOURCE_INVALID", "expected source")
    require_oid(manifest_commit, oid_length, "MANIFEST_COMMIT_INVALID", "manifest commit")
    require_sha256(expected_digest, "EXPECTED_MANIFEST_DIGEST_INVALID", "expected manifest digest")

    if git_object_type(repo, expected_source, "expected source") != "commit":
        raise GateError("EXPECTED_SOURCE_INVALID", "expected source object is not a commit")
    if git_object_type(repo, manifest_commit, "manifest commit") != "commit":
        raise GateError("MANIFEST_COMMIT_INVALID", "manifest object is not a commit")

    parent_line = git_text(repo, ["rev-list", "--parents", "-n", "1", manifest_commit]).split()
    if len(parent_line) != 2 or parent_line[1] != expected_source:
        raise GateError(
            "SOURCE_PARENT_MISMATCH",
            "manifest commit must have exactly the expected source as its direct parent",
        )

    path = MANIFEST_PATH_PREFIX + expected_source + ".json"
    source_entry = run_git(repo, ["ls-tree", "-z", expected_source, "--", path]).stdout
    if source_entry:
        raise GateError("MANIFEST_SELF_REFERENCE", "source commit already contains its own manifest path")

    changed = run_git(
        repo,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", expected_source, manifest_commit],
    ).stdout
    changed_paths = [item.decode("utf-8") for item in changed.split(b"\0") if item]
    if changed_paths != [path]:
        raise GateError(
            "MANIFEST_COMMIT_SCOPE_INVALID",
            "manifest commit must add only the derived manifest path",
        )

    mode, object_type, object_id = ls_tree_entry(
        repo,
        manifest_commit,
        path,
        missing_code="MANIFEST_GIT_BLOB_MISSING",
    )
    publication = contract["publication"]
    if mode != publication["manifestGitMode"] or object_type != publication["manifestGitType"]:
        raise GateError("MANIFEST_GIT_MODE_INVALID", "manifest must be a regular 100644 Git blob")
    raw = git_blob(repo, object_id)
    if sha256(raw) != expected_digest:
        raise GateError("MANIFEST_DIGEST_MISMATCH", "manifest Git blob digest does not match the expected digest")
    if manifest_commit.encode("ascii") in raw:
        raise GateError("MANIFEST_SELF_REFERENCE", "manifest embeds its own publication commit")
    return object_format, oid_length, path, raw


def validate_manifest_structure(manifest, expected_source, object_format, oid_length, path, repo, contract):
    manifest_contract = contract["manifest"]
    require_exact_keys(
        manifest,
        manifest_contract["topLevelFields"],
        "MANIFEST_FIELDS_INVALID",
        "manifest",
    )
    if manifest["schemaVersion"] != MANIFEST_SCHEMA:
        raise GateError("MANIFEST_SCHEMA_INVALID", "manifest schema version does not match")
    if manifest["manifestId"] != "commit-bound-" + expected_source:
        raise GateError("MANIFEST_ID_INVALID", "manifest ID is not source-bound")
    if manifest["verificationStatus"] != manifest_contract["verificationStatus"]:
        raise GateError("MANIFEST_STATUS_INVALID", "manifest verification status must be VERIFIED")
    if manifest["releaseDecision"] != RELEASE_DECISION:
        raise GateError("RELEASE_DECISION_INVALID", "manifest release decision must remain NOT_EVALUATED")

    source = manifest["source"]
    require_exact_keys(source, manifest_contract["sourceFields"], "SOURCE_FIELDS_INVALID", "source")
    source_tree = git_text(repo, ["rev-parse", expected_source + "^{tree}"])
    require_oid(source_tree, oid_length, "SOURCE_TREE_INVALID", "source tree")
    expected_source_object = {
        "repositoryUri": "git+repo://" + expected_source + "/",
        "objectFormat": object_format,
        "commit": expected_source,
        "tree": source_tree,
        "dirty": False,
    }
    if source != expected_source_object:
        raise GateError("SOURCE_BINDING_INVALID", "manifest source binding does not match Git objects")

    publication = manifest["publication"]
    require_exact_keys(
        publication,
        manifest_contract["publicationFields"],
        "PUBLICATION_FIELDS_INVALID",
        "publication",
    )
    expected_publication = {
        "mode": contract["publication"]["mode"],
        "path": path,
        "sourceRelation": contract["publication"]["sourceRelation"],
    }
    if publication != expected_publication:
        raise GateError("PUBLICATION_BINDING_INVALID", "manifest publication metadata does not match Git objects")

    environment = manifest["environment"]
    require_exact_keys(
        environment,
        manifest_contract["environmentFields"],
        "ENVIRONMENT_FIELDS_INVALID",
        "environment",
    )
    require_string(environment["os"], "ENVIRONMENT_INVALID", "environment OS")
    require_string(environment["architecture"], "ENVIRONMENT_INVALID", "environment architecture")
    if environment["isolation"] not in manifest_contract["environmentIsolationValues"]:
        raise GateError("ENVIRONMENT_INVALID", "environment isolation is not allowed")
    if environment["redaction"] != manifest_contract["environmentRedaction"]:
        raise GateError("ENVIRONMENT_INVALID", "environment redaction must be STRICT")

    build = manifest["build"]
    require_exact_keys(build, manifest_contract["buildFields"], "BUILD_FIELDS_INVALID", "build")
    commands = build["commands"]
    if not isinstance(commands, list) or not commands:
        raise GateError("BUILD_COMMANDS_INVALID", "build commands must be non-empty")
    command_ids = []
    for command in commands:
        require_exact_keys(command, manifest_contract["commandFields"], "BUILD_COMMAND_INVALID", "build command")
        require_identifier(command["id"], "BUILD_COMMAND_INVALID", "build command ID")
        command_ids.append(command["id"])
        argv = command["argv"]
        if not isinstance(argv, list) or not argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in argv
        ):
            raise GateError("BUILD_COMMAND_INVALID", "build command argv must contain non-empty strings")
    check_ids(
        command_ids,
        "BUILD_COMMAND_IDS_DUPLICATE",
        "BUILD_COMMAND_IDS_UNSORTED",
        "BUILD_COMMAND_INVALID",
        "build command IDs",
    )

    tools = build["tools"]
    if not isinstance(tools, list) or not tools:
        raise GateError("BUILD_TOOLS_INVALID", "build tools must be non-empty")
    tool_ids = []
    for tool in tools:
        require_exact_keys(tool, manifest_contract["toolFields"], "BUILD_TOOL_INVALID", "build tool")
        require_identifier(tool["id"], "BUILD_TOOL_INVALID", "build tool ID")
        require_string(tool["version"], "BUILD_TOOL_INVALID", "build tool version")
        require_sha256(tool["sha256"], "BUILD_TOOL_INVALID", "build tool digest")
        tool_ids.append(tool["id"])
    check_ids(
        tool_ids,
        "BUILD_TOOL_IDS_DUPLICATE",
        "BUILD_TOOL_IDS_UNSORTED",
        "BUILD_TOOL_INVALID",
        "build tool IDs",
    )

    check_ids(
        build["receiptArtifactIds"],
        "BUILD_RECEIPT_IDS_DUPLICATE",
        "BUILD_RECEIPT_IDS_UNSORTED",
        "BUILD_RECEIPT_IDS_INVALID",
        "build receipt artifact IDs",
    )
    if not build["receiptArtifactIds"]:
        raise GateError("BUILD_RECEIPT_IDS_INVALID", "build receipt artifact IDs must be non-empty")

    scan_json_strict(manifest, "MANIFEST_REDACTION_FAILED", "manifest")
    return source_tree


def validate_artifacts_and_claims(manifest, expected_source, oid_length, repo, contract):
    manifest_contract = contract["manifest"]
    artifact_contract = contract["artifacts"]
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise GateError("ARTIFACTS_INVALID", "artifacts must be a non-empty array")
    artifact_ids = []
    artifact_by_id = {}
    verified_artifacts = {}
    for artifact in artifacts:
        require_exact_keys(
            artifact,
            manifest_contract["artifactFields"],
            "ARTIFACT_FIELDS_INVALID",
            "artifact",
        )
        artifact_id = artifact["id"]
        require_identifier(artifact_id, "ARTIFACT_ID_INVALID", "artifact ID")
        artifact_ids.append(artifact_id)
        artifact_by_id[artifact_id] = artifact
        if artifact["kind"] not in artifact_contract["kinds"]:
            raise GateError("ARTIFACT_KIND_INVALID", "artifact kind is not allowed")
        if artifact["verificationClass"] not in artifact_contract["verificationClasses"]:
            raise GateError("ARTIFACT_CLASS_INVALID", "artifact verification class is not allowed")
        require_sha256(artifact["sha256"], "ARTIFACT_DIGEST_INVALID", "artifact digest")
        if (
            not isinstance(artifact["byteCount"], int)
            or isinstance(artifact["byteCount"], bool)
            or artifact["byteCount"] < 0
        ):
            raise GateError("ARTIFACT_SIZE_INVALID", "artifact byte count must be a non-negative integer")
        require_string(artifact["mediaType"], "ARTIFACT_MEDIA_TYPE_INVALID", "artifact media type")
        require_string(artifact["uri"], "ARTIFACT_URI_INVALID", "artifact URI")
    check_ids(
        artifact_ids,
        "ARTIFACT_IDS_DUPLICATE",
        "ARTIFACT_IDS_UNSORTED",
        "ARTIFACT_ID_INVALID",
        "artifact IDs",
    )

    for artifact in artifacts:
        artifact_id = artifact["id"]
        verification_class = artifact["verificationClass"]
        if verification_class == "SOURCE_COMMIT_BLOB":
            prefix = "git+repo://" + expected_source + "/"
            if not artifact["uri"].startswith(prefix):
                raise GateError("ARTIFACT_URI_INVALID", "source artifact URI is not bound to the expected commit")
            source_path = validate_repo_path(artifact["uri"][len(prefix):])
            mode, object_type, object_id = ls_tree_entry(repo, expected_source, source_path)
            require_oid(object_id, oid_length, "ARTIFACT_GIT_OBJECT_INVALID", "artifact Git blob")
            if mode not in REGULAR_BLOB_MODES or object_type != "blob":
                raise GateError("ARTIFACT_GIT_MODE_INVALID", "source artifact is not a regular Git blob")
            raw = git_blob(repo, object_id)
            if len(raw) != artifact["byteCount"]:
                raise GateError("ARTIFACT_SIZE_MISMATCH", "source artifact byte count does not match Git")
            if sha256(raw) != artifact["sha256"]:
                raise GateError("ARTIFACT_DIGEST_MISMATCH", "source artifact digest does not match Git")

            parsed_json = None
            if artifact["mediaType"] == "application/json":
                try:
                    parsed_json = load_json_unique(
                        raw,
                        "ARTIFACT_JSON_DUPLICATE_KEY",
                        "ARTIFACT_JSON_INVALID",
                        "JSON artifact",
                    )
                except GateError as error:
                    raise error
            elif artifact["mediaType"].startswith("text/"):
                try:
                    raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise GateError("ARTIFACT_TEXT_INVALID", "text artifact is not UTF-8")

            if artifact["kind"] in contract["redaction"]["strictArtifactKinds"]:
                if parsed_json is not None:
                    scan_json_strict(parsed_json, "ARTIFACT_REDACTION_FAILED", "evidence artifact")
                    scan_evidence_semantics(
                        parsed_json,
                        expected_source,
                        "ARTIFACT_NON_PASS_STATUS",
                        "evidence artifact",
                    )
                else:
                    try:
                        decoded = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        raise GateError("ARTIFACT_REDACTION_FAILED", "evidence artifact is not scannable UTF-8")
                    scan_text(decoded, True, "ARTIFACT_REDACTION_FAILED", "evidence artifact")
            elif artifact["kind"] in contract["redaction"]["sourceArtifactKinds"]:
                try:
                    decoded = raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise GateError("ARTIFACT_REDACTION_FAILED", "source artifact is not scannable UTF-8")
                scan_text(decoded, False, "ARTIFACT_REDACTION_FAILED", "source artifact")
            verified_artifacts[artifact_id] = {
                "mode": mode,
                "path": source_path,
                "mediaType": artifact["mediaType"],
            }
        else:
            if artifact["uri"] != "urn:sha256:" + artifact["sha256"]:
                raise GateError("ARTIFACT_URI_INVALID", "digest-only artifact URI does not match its digest")

    claims = manifest["claims"]
    if not isinstance(claims, list) or not claims:
        raise GateError("CLAIMS_INVALID", "claims must be a non-empty array")
    claim_ids = []
    referenced_artifacts = set(manifest["build"]["receiptArtifactIds"])
    required_count = 0
    for claim in claims:
        require_exact_keys(claim, manifest_contract["claimFields"], "CLAIM_FIELDS_INVALID", "claim")
        require_identifier(claim["id"], "CLAIM_ID_INVALID", "claim ID")
        claim_ids.append(claim["id"])
        if not isinstance(claim["required"], bool):
            raise GateError("CLAIM_REQUIRED_INVALID", "claim required flag must be boolean")
        check_ids(
            claim["artifactIds"],
            "CLAIM_ARTIFACT_IDS_DUPLICATE",
            "CLAIM_ARTIFACT_IDS_UNSORTED",
            "CLAIM_ARTIFACT_IDS_INVALID",
            "claim artifact IDs",
        )
        if not claim["artifactIds"]:
            raise GateError("CLAIM_ARTIFACT_IDS_INVALID", "claim artifact IDs must be non-empty")
        for artifact_id in claim["artifactIds"]:
            if artifact_id not in artifact_by_id:
                raise GateError("CLAIM_ARTIFACT_MISSING", "claim references an unknown artifact")
            referenced_artifacts.add(artifact_id)
            if claim["required"]:
                artifact = artifact_by_id[artifact_id]
                if artifact["verificationClass"] != "SOURCE_COMMIT_BLOB":
                    raise GateError(
                        "REQUIRED_CLAIM_INELIGIBLE",
                        "required claim references non-clone-verifiable evidence",
                    )
                media_type = artifact["mediaType"]
                if media_type != "application/json" and not media_type.startswith("text/"):
                    raise GateError(
                        "REQUIRED_CLAIM_INELIGIBLE",
                        "required claim references a non-JSON/text artifact",
                    )
                if artifact_id not in verified_artifacts:
                    raise GateError("REQUIRED_CLAIM_INELIGIBLE", "required claim artifact was not verified")
        if claim["required"]:
            required_count += 1

    check_ids(
        claim_ids,
        "CLAIM_IDS_DUPLICATE",
        "CLAIM_IDS_UNSORTED",
        "CLAIM_ID_INVALID",
        "claim IDs",
    )
    if required_count == 0:
        raise GateError("REQUIRED_CLAIM_MISSING", "at least one claim must be required")
    if referenced_artifacts != set(artifact_ids):
        raise GateError("ARTIFACT_ORPHANED", "every artifact must be referenced by a claim or build receipt")
    for artifact_id in manifest["build"]["receiptArtifactIds"]:
        if artifact_id not in artifact_by_id:
            raise GateError("BUILD_RECEIPT_ARTIFACT_MISSING", "build receipt references an unknown artifact")
        if artifact_by_id[artifact_id]["kind"] not in {
            "BUILD_RECEIPT",
            "EVIDENCE_PAYLOAD",
            "MACHINE_REPORT",
        }:
            raise GateError("BUILD_RECEIPT_ARTIFACT_INVALID", "build receipt reference has the wrong kind")
    return len(artifacts), len(claims), required_count


def verify(repo, contract_path, manifest_commit, expected_source, expected_digest, test_mode):
    contract = validate_contract(contract_path)
    object_format, oid_length, path, raw = verify_manifest_publication(
        repo,
        manifest_commit,
        expected_source,
        expected_digest,
        contract,
    )
    manifest = load_json_unique(
        raw,
        "MANIFEST_DUPLICATE_KEY",
        "MANIFEST_JSON_INVALID",
        "commit-bound manifest",
    )
    source_tree = validate_manifest_structure(
        manifest,
        expected_source,
        object_format,
        oid_length,
        path,
        repo,
        contract,
    )
    artifact_count, claim_count, required_claim_count = validate_artifacts_and_claims(
        manifest,
        expected_source,
        oid_length,
        repo,
        contract,
    )
    return {
        "schema": VERIFICATION_SCHEMA,
        "status": "VERIFIED",
        "code": "COMMIT_BOUND_MANIFEST_VERIFIED",
        "releaseDecision": RELEASE_DECISION,
        "testMode": bool(test_mode),
        "sourceCommit": expected_source,
        "sourceTree": source_tree,
        "manifestCommit": manifest_commit,
        "manifestPath": path,
        "manifestSha256": expected_digest,
        "contractSha256": CONTRACT_SHA256,
        "artifactCount": artifact_count,
        "claimCount": claim_count,
        "requiredClaimCount": required_claim_count,
    }


def test_git(repo, arguments, input_bytes=None):
    process = run_git(repo, arguments, input_bytes=input_bytes, check=False)
    if process.returncode != 0:
        raise AssertionError("self-test Git command failed")
    return process.stdout


def test_write(path, raw, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o755 if executable else 0o644)


def test_commit(repo, message, paths):
    test_git(repo, ["add", "--"] + paths)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": "2001-01-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2001-01-01T00:00:00+0000",
        }
    )
    process = subprocess.run(
        [GIT_BIN, "-C", str(repo), "commit", "-q", "--no-gpg-sign", "-m", message],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError("self-test Git commit failed")
    return git_text(repo, ["rev-parse", "HEAD"])


def test_checkout(repo, commit_id):
    if git_text(repo, ["status", "--porcelain=v1"]):
        raise AssertionError("self-test attempted checkout with a dirty fixture")
    test_git(repo, ["checkout", "-q", "--detach", commit_id])


def test_blob(repo, commit_id, path):
    mode, object_type, object_id = ls_tree_entry(repo, commit_id, path)
    if object_type != "blob":
        raise AssertionError("self-test expected a blob")
    return mode, git_blob(repo, object_id)


def test_artifact(repo, source, artifact_id, kind, path, media_type):
    _, raw = test_blob(repo, source, path)
    return {
        "id": artifact_id,
        "kind": kind,
        "uri": "git+repo://" + source + "/" + path,
        "sha256": sha256(raw),
        "byteCount": len(raw),
        "mediaType": media_type,
        "verificationClass": "SOURCE_COMMIT_BLOB",
    }


def test_manifest(repo, source, extra_artifacts=None):
    extra_artifacts = extra_artifacts or []
    object_format = git_text(repo, ["rev-parse", "--show-object-format"])
    tree = git_text(repo, ["rev-parse", source + "^{tree}"])
    base_artifacts = [
        test_artifact(repo, source, "artifact-contract", "CONTRACT", "contracts/fixture.json", "application/json"),
        {
            "id": "artifact-digest-only",
            "kind": "MACHINE_REPORT",
            "uri": "urn:sha256:" + sha256(b"context-only"),
            "sha256": sha256(b"context-only"),
            "byteCount": len(b"context-only"),
            "mediaType": "application/octet-stream",
            "verificationClass": "DIGEST_ONLY",
        },
        test_artifact(
            repo,
            source,
            "artifact-evidence",
            "EVIDENCE_PAYLOAD",
            "reports/evidence.json",
            "application/json",
        ),
        test_artifact(repo, source, "artifact-gate", "GATE_SOURCE", "scripts/fixture-gate.sh", "text/x-shellscript"),
    ]
    for artifact_id, kind, path, media_type in extra_artifacts:
        base_artifacts.append(test_artifact(repo, source, artifact_id, kind, path, media_type))
    artifacts = sorted(base_artifacts, key=lambda item: item["id"])
    clone_ids = sorted(
        artifact["id"]
        for artifact in artifacts
        if artifact["verificationClass"] == "SOURCE_COMMIT_BLOB"
    )
    return {
        "schemaVersion": MANIFEST_SCHEMA,
        "manifestId": "commit-bound-" + source,
        "verificationStatus": "VERIFIED",
        "releaseDecision": RELEASE_DECISION,
        "source": {
            "repositoryUri": "git+repo://" + source + "/",
            "objectFormat": object_format,
            "commit": source,
            "tree": tree,
            "dirty": False,
        },
        "publication": {
            "mode": "tracked-child-commit",
            "path": MANIFEST_PATH_PREFIX + source + ".json",
            "sourceRelation": "single-direct-parent",
        },
        "build": {
            "commands": [
                {"id": "build-fixture", "argv": ["cargo", "test", "--locked"]},
            ],
            "tools": [
                {
                    "id": "git",
                    "version": "test-fixture",
                    "sha256": sha256(b"git-test-fixture"),
                },
            ],
            "receiptArtifactIds": ["artifact-evidence"],
        },
        "environment": {
            "os": "test-os",
            "architecture": "test-arch",
            "isolation": "ephemeral",
            "redaction": "STRICT",
        },
        "claims": [
            {
                "id": "claim-clone-verifiable",
                "required": True,
                "artifactIds": clone_ids,
            },
            {
                "id": "claim-digest-context",
                "required": False,
                "artifactIds": ["artifact-digest-only"],
            },
        ],
        "artifacts": artifacts,
    }


def manifest_raw(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def commit_manifest(repo, source, raw, message):
    test_checkout(repo, source)
    path = MANIFEST_PATH_PREFIX + source + ".json"
    test_write(repo / path, raw)
    child = test_commit(repo, message, [path])
    return child, path, sha256(raw)


def source_variant(repo, base_source, path, raw, message, executable=False, symbolic_link=None):
    test_checkout(repo, base_source)
    destination = repo / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    if symbolic_link is not None:
        os.symlink(symbolic_link, destination)
    else:
        test_write(destination, raw, executable=executable)
    return test_commit(repo, message, [path])


def expect_gate_error(function, expected_code):
    try:
        function()
    except GateError as error:
        if error.code != expected_code:
            raise AssertionError(
                "expected self-test failure " + expected_code + " but received " + error.code
            )
        return
    raise AssertionError("expected self-test failure " + expected_code)


def run_self_test():
    if SELF_TEST_DIR is None or not SELF_TEST_DIR.is_dir():
        raise GateError("SELF_TEST_SETUP_FAILED", "self-test directory is unavailable")
    scan_text(
        Path(SCRIPT_PATH).read_text(encoding="utf-8"),
        False,
        "ARTIFACT_REDACTION_FAILED",
        "gate source",
    )
    scan_text(
        CONTRACT_PATH.read_text(encoding="utf-8"),
        False,
        "ARTIFACT_REDACTION_FAILED",
        "contract source",
    )
    entropy_canary = (
        "aB3_" + "dE4+" + "fG5=" + "hI6_" + "jK7+" + "lM8=" + "nO9_" + "pQ0+"
    )
    expect_gate_error(
        lambda: scan_text(
            entropy_canary,
            False,
            "ARTIFACT_REDACTION_FAILED",
            "source artifact",
        ),
        "ARTIFACT_REDACTION_FAILED",
    )
    pem_canary = (
        "-----BEGIN "
        + "PRIVATE "
        + "KEY-----\n"
        + entropy_canary
        + "\n-----END "
        + "PRIVATE "
        + "KEY-----"
    )
    expect_gate_error(
        lambda: scan_text(
            pem_canary,
            False,
            "ARTIFACT_REDACTION_FAILED",
            "source artifact",
        ),
        "ARTIFACT_REDACTION_FAILED",
    )
    userinfo_canary = "https" + "://fixture:" + "passphrase" + "@example.invalid"
    expect_gate_error(
        lambda: scan_text(
            userinfo_canary,
            False,
            "ARTIFACT_REDACTION_FAILED",
            "source artifact",
        ),
        "ARTIFACT_REDACTION_FAILED",
    )
    expect_gate_error(
        lambda: scan_json_strict(
            {"contact": "fixture" + "@" + "example.com"},
            "MANIFEST_REDACTION_FAILED",
            "strict payload",
        ),
        "MANIFEST_REDACTION_FAILED",
    )
    expect_gate_error(
        lambda: scan_json_strict(
            {"machine": "worker" + "." + "example.com"},
            "MANIFEST_REDACTION_FAILED",
            "strict payload",
        ),
        "MANIFEST_REDACTION_FAILED",
    )
    expect_gate_error(
        lambda: scan_json_strict(
            {"to" + "ken": "redacted"},
            "MANIFEST_REDACTION_FAILED",
            "strict payload",
        ),
        "MANIFEST_REDACTION_FAILED",
    )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"status": "BLOCKED_" + "ENV"},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "evidence artifact",
        ),
        "ARTIFACT_NON_PASS_STATUS",
    )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"testMode": True},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "evidence artifact",
        ),
        "ARTIFACT_TEST_ONLY",
    )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"schema": "hartevo.release-evidence/v2.3", "passed": False},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "release evidence artifact",
        ),
        "ARTIFACT_NEGATIVE_ASSERTION",
    )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"success": False},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "evidence artifact",
        ),
        "ARTIFACT_NEGATIVE_ASSERTION",
    )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"allAssertionsPassed": False},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "evidence artifact",
        ),
        "ARTIFACT_NEGATIVE_ASSERTION",
    )
    for rejected_status in ("INCONCLUSIVE", "NOT_RUN", "PARTIAL", "SKIPPED", "UNKNOWN"):
        expect_gate_error(
            lambda rejected_status=rejected_status: scan_evidence_semantics(
                {"status": rejected_status},
                "0" * 40,
                "ARTIFACT_NON_PASS_STATUS",
                "evidence artifact",
            ),
            "ARTIFACT_NON_PASS_STATUS",
        )
    expect_gate_error(
        lambda: scan_evidence_semantics(
            {"verificationStatus": "FAIL"},
            "0" * 40,
            "ARTIFACT_NON_PASS_STATUS",
            "evidence artifact",
        ),
        "ARTIFACT_NON_PASS_STATUS",
    )
    positive_source = "0" * 40
    positive_ev01 = {
        "schema": "hartevo.dioxus-build-provenance/v1",
        "status": "PASS",
        "code": "DIOXUS_BUNDLE_VERIFIED",
        "testMode": False,
        "evidenceClass": "REAL_DX_BUILD",
        "sourceCommit": positive_source,
        "sourceDirty": False,
        "artifactPath": "target/dx/hartevo-desktop/debug/macos/HartevoDesktop.app",
        "artifactDigest": "1" * 64,
        "artifactDigestAlgorithm": "sha256-tree-manifest-v1",
        "hostOs": "Darwin",
        "hostArch": "arm64",
        "passed": True,
        "success": True,
        "allAssertionsPassed": True,
    }
    scan_json_strict(
        positive_ev01,
        "ARTIFACT_REDACTION_FAILED",
        "EV-01 receipt fixture",
    )
    scan_evidence_semantics(
        positive_ev01,
        positive_source,
        "ARTIFACT_NON_PASS_STATUS",
        "EV-01 receipt fixture",
    )
    repo = SELF_TEST_DIR / "repo"
    repo.mkdir()
    test_git(repo, ["init", "-q"])
    test_git(repo, ["config", "user.name", "Hartevo Evidence Fixture"])
    test_git(repo, ["config", "user.email", "fixture@example.invalid"])
    test_git(repo, ["config", "commit.gpgsign", "false"])

    test_write(
        repo / "contracts/fixture.json",
        b'{"lexicalNonSecret":"Authorization","schema":"fixture/v1"}\n',
    )
    test_write(
        repo / "scripts/fixture-gate.sh",
        b"#!/usr/bin/env bash\nset -euo pipefail\nleft='not-a-'\nright='credential'\nprintf '%s\\n' \"${left}${right}\"\n",
        executable=True,
    )
    test_write(
        repo / "reports/evidence.json",
        b'{"records":3,"releaseDecision":"NOT_EVALUATED","result":"VERIFIED"}\n',
    )
    source = test_commit(
        repo,
        "fixture source",
        ["contracts/fixture.json", "scripts/fixture-gate.sh", "reports/evidence.json"],
    )
    base_manifest = test_manifest(repo, source)
    base_raw = manifest_raw(base_manifest)
    manifest_child, manifest_path, manifest_digest = commit_manifest(
        repo,
        source,
        base_raw,
        "publish fixture manifest",
    )
    verify(repo, CONTRACT_PATH, manifest_child, source, manifest_digest, True)

    shell_environment = os.environ.copy()
    shell_environment.update(
        {
            "HARTEVO_EVIDENCE_TEST_MODE": "1",
            "HARTEVO_EVIDENCE_TEST_REPO_ROOT": str(repo),
            "HARTEVO_EVIDENCE_CONTRACT_PATH": str(CONTRACT_PATH),
            "HARTEVO_EVIDENCE_TEST_PYTHON_BIN": sys.executable,
        }
    )
    shell_arguments = [
        SCRIPT_PATH,
        "verify",
        "--manifest-commit",
        manifest_child,
        "--expected-source",
        source,
        "--expected-manifest-sha256",
        manifest_digest,
    ]
    shell_verified = subprocess.run(
        shell_arguments,
        env=shell_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if shell_verified.returncode != 0:
        raise AssertionError("shell verify did not accept the Git-object fixture")
    shell_verified_value = load_json_unique(
        shell_verified.stdout,
        "SELF_TEST_OUTPUT_DUPLICATE_KEY",
        "SELF_TEST_OUTPUT_INVALID",
        "shell verification receipt",
    )
    if (
        shell_verified_value.get("status") != "VERIFIED"
        or shell_verified_value.get("releaseDecision") != RELEASE_DECISION
        or shell_verified_value.get("testMode") is not True
    ):
        raise AssertionError("shell verification receipt is invalid")

    mutated_shell_arguments = list(shell_arguments)
    mutated_shell_arguments[-1] = "0" * 64
    shell_rejected = subprocess.run(
        mutated_shell_arguments,
        env=shell_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if shell_rejected.returncode != 1:
        raise AssertionError("shell verify accepted a mutated expected digest")
    shell_rejected_value = load_json_unique(
        shell_rejected.stdout,
        "SELF_TEST_OUTPUT_DUPLICATE_KEY",
        "SELF_TEST_OUTPUT_INVALID",
        "shell rejection receipt",
    )
    if (
        shell_rejected_value.get("status") != "FAIL"
        or shell_rejected_value.get("code") != "MANIFEST_DIGEST_MISMATCH"
        or shell_rejected_value.get("releaseDecision") != RELEASE_DECISION
    ):
        raise AssertionError("shell mutation rejection receipt is invalid")

    test_write(repo / manifest_path, b'{"worktree":"must-not-be-read"}\n')
    verify(repo, CONTRACT_PATH, manifest_child, source, manifest_digest, True)
    test_git(repo, ["checkout-index", "-f", "--", manifest_path])

    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, manifest_child, source, "0" * 64, True),
        "MANIFEST_DIGEST_MISMATCH",
    )
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, manifest_child, manifest_child, manifest_digest, True),
        "SOURCE_PARENT_MISMATCH",
    )

    duplicate_raw = base_raw.rstrip()
    duplicate_raw = duplicate_raw[:-1] + (
        b',"schemaVersion":"' + MANIFEST_SCHEMA.encode("ascii") + b'"}\n'
    )
    duplicate_child, _, duplicate_digest = commit_manifest(
        repo,
        source,
        duplicate_raw,
        "duplicate manifest key",
    )
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, duplicate_child, source, duplicate_digest, True),
        "MANIFEST_DUPLICATE_KEY",
    )

    duplicate_ids = copy.deepcopy(base_manifest)
    duplicate_ids["artifacts"][1]["id"] = duplicate_ids["artifacts"][0]["id"]
    raw = manifest_raw(duplicate_ids)
    child, _, digest = commit_manifest(repo, source, raw, "duplicate artifact IDs")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "ARTIFACT_IDS_DUPLICATE",
    )

    unsorted_claims = copy.deepcopy(base_manifest)
    unsorted_claims["claims"].reverse()
    raw = manifest_raw(unsorted_claims)
    child, _, digest = commit_manifest(repo, source, raw, "unsorted claim IDs")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "CLAIM_IDS_UNSORTED",
    )

    required_digest = copy.deepcopy(base_manifest)
    required_digest["claims"][1]["required"] = True
    raw = manifest_raw(required_digest)
    child, _, digest = commit_manifest(repo, source, raw, "digest-only required claim")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "REQUIRED_CLAIM_INELIGIBLE",
    )

    for forbidden_class in ("BLOCKED_ENV", "FAIL", "TEST_ONLY"):
        forbidden_required = copy.deepcopy(base_manifest)
        forbidden_required["artifacts"][1]["verificationClass"] = forbidden_class
        forbidden_required["claims"][1]["required"] = True
        raw = manifest_raw(forbidden_required)
        child, _, digest = commit_manifest(
            repo,
            source,
            raw,
            "forbidden required class " + forbidden_class,
        )
        expect_gate_error(
            lambda child=child, digest=digest: verify(
                repo,
                CONTRACT_PATH,
                child,
                source,
                digest,
                True,
            ),
            "REQUIRED_CLAIM_INELIGIBLE",
        )

    target_artifact = copy.deepcopy(base_manifest)
    target_artifact["artifacts"][0]["uri"] = (
        "git+repo://" + source + "/target/raw-evidence.json"
    )
    raw = manifest_raw(target_artifact)
    child, _, digest = commit_manifest(repo, source, raw, "target artifact URI")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "ARTIFACT_TARGET_FORBIDDEN",
    )

    mutated_artifact_digest = copy.deepcopy(base_manifest)
    mutated_artifact_digest["artifacts"][0]["sha256"] = "0" * 64
    raw = manifest_raw(mutated_artifact_digest)
    child, _, digest = commit_manifest(repo, source, raw, "mutated artifact digest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "ARTIFACT_DIGEST_MISMATCH",
    )

    absolute_path = copy.deepcopy(base_manifest)
    absolute_path["build"]["commands"].append(
        {"id": "redaction-path", "argv": ["tool", "/Users/example/private"]}
    )
    raw = manifest_raw(absolute_path)
    child, _, digest = commit_manifest(repo, source, raw, "absolute path redaction")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, source, digest, True),
        "MANIFEST_REDACTION_FAILED",
    )

    sensitive_name = "api_" + "key"
    sensitive_value = "R4nd0m" * 8
    leaky_source_raw = (
        "#!/usr/bin/env bash\n" + sensitive_name + ' = "' + sensitive_value + '"\n'
    ).encode("utf-8")
    leaky_source = source_variant(
        repo,
        source,
        "scripts/leaky-source.sh",
        leaky_source_raw,
        "leaky source fixture",
        executable=True,
    )
    leaky_manifest = test_manifest(
        repo,
        leaky_source,
        [("artifact-leaky-source", "GATE_SOURCE", "scripts/leaky-source.sh", "text/x-shellscript")],
    )
    raw = manifest_raw(leaky_manifest)
    child, _, digest = commit_manifest(repo, leaky_source, raw, "leaky source manifest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, leaky_source, digest, True),
        "ARTIFACT_REDACTION_FAILED",
    )

    symlink_source = source_variant(
        repo,
        source,
        "links/fixture-link",
        b"",
        "symlink fixture",
        symbolic_link="../contracts/fixture.json",
    )
    symlink_manifest = test_manifest(
        repo,
        symlink_source,
        [("artifact-link", "SOURCE", "links/fixture-link", "text/plain")],
    )
    raw = manifest_raw(symlink_manifest)
    child, _, digest = commit_manifest(repo, symlink_source, raw, "symlink manifest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, symlink_source, digest, True),
        "ARTIFACT_GIT_MODE_INVALID",
    )

    duplicate_json_source = source_variant(
        repo,
        source,
        "reports/duplicate.json",
        b'{"result":"one","result":"two"}\n',
        "duplicate JSON fixture",
    )
    duplicate_json_manifest = test_manifest(
        repo,
        duplicate_json_source,
        [("artifact-duplicate-json", "EVIDENCE_PAYLOAD", "reports/duplicate.json", "application/json")],
    )
    raw = manifest_raw(duplicate_json_manifest)
    child, _, digest = commit_manifest(repo, duplicate_json_source, raw, "duplicate JSON manifest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, duplicate_json_source, digest, True),
        "ARTIFACT_JSON_DUPLICATE_KEY",
    )

    release_false_source = source_variant(
        repo,
        source,
        "reports/release-v2.3.json",
        manifest_raw({"schema": "hartevo.release-evidence/v2.3", "passed": False}),
        "Release v2.3 false fixture",
    )
    release_false_manifest = test_manifest(
        repo,
        release_false_source,
        [
            (
                "artifact-release-evidence",
                "EVIDENCE_PAYLOAD",
                "reports/release-v2.3.json",
                "application/json",
            )
        ],
    )
    raw = manifest_raw(release_false_manifest)
    child, _, digest = commit_manifest(
        repo,
        release_false_source,
        raw,
        "Release v2.3 false manifest",
    )
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, release_false_source, digest, True),
        "ARTIFACT_NEGATIVE_ASSERTION",
    )
    release_false_shell = subprocess.run(
        [
            SCRIPT_PATH,
            "verify",
            "--manifest-commit",
            child,
            "--expected-source",
            release_false_source,
            "--expected-manifest-sha256",
            digest,
        ],
        env=shell_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if release_false_shell.returncode != 1:
        raise AssertionError("Release v2.3 false evidence did not fail the shell gate")
    release_false_value = load_json_unique(
        release_false_shell.stdout,
        "SELF_TEST_OUTPUT_DUPLICATE_KEY",
        "SELF_TEST_OUTPUT_INVALID",
        "Release v2.3 rejection receipt",
    )
    if (
        release_false_value.get("status") != "FAIL"
        or release_false_value.get("code") != "ARTIFACT_NEGATIVE_ASSERTION"
        or release_false_value.get("releaseDecision") != RELEASE_DECISION
    ):
        raise AssertionError("Release v2.3 rejection receipt is invalid")

    other_oid = "0" * len(source)
    dirty_receipt = {
        "schema": "hartevo.dioxus-build-provenance/v1",
        "status": "PASS",
        "testMode": False,
        "sourceCommit": other_oid,
        "sourceDirty": True,
    }
    dirty_source = source_variant(
        repo,
        source,
        "reports/dioxus-receipt.json",
        manifest_raw(dirty_receipt),
        "dirty Dioxus receipt fixture",
    )
    dirty_manifest = test_manifest(
        repo,
        dirty_source,
        [("artifact-dioxus-receipt", "BUILD_RECEIPT", "reports/dioxus-receipt.json", "application/json")],
    )
    raw = manifest_raw(dirty_manifest)
    child, _, digest = commit_manifest(repo, dirty_source, raw, "dirty receipt manifest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, dirty_source, digest, True),
        "ARTIFACT_SOURCE_DIRTY",
    )

    mismatch_receipt = copy.deepcopy(dirty_receipt)
    mismatch_receipt["sourceDirty"] = False
    mismatch_source = source_variant(
        repo,
        source,
        "reports/dioxus-receipt.json",
        manifest_raw(mismatch_receipt),
        "mismatched Dioxus receipt fixture",
    )
    mismatch_manifest = test_manifest(
        repo,
        mismatch_source,
        [("artifact-dioxus-receipt", "BUILD_RECEIPT", "reports/dioxus-receipt.json", "application/json")],
    )
    raw = manifest_raw(mismatch_manifest)
    child, _, digest = commit_manifest(repo, mismatch_source, raw, "mismatched receipt manifest")
    expect_gate_error(
        lambda: verify(repo, CONTRACT_PATH, child, mismatch_source, digest, True),
        "ARTIFACT_SOURCE_COMMIT_MISMATCH",
    )

    mutated_contract_path = SELF_TEST_DIR / "mutated-contract.json"
    contract_value = load_json_unique(
        CONTRACT_PATH.read_bytes(),
        "CONTRACT_DUPLICATE_KEY",
        "CONTRACT_INVALID",
        "frozen evidence contract",
    )
    contract_value["contractVersion"] = "ev-02/mutated"
    test_write(mutated_contract_path, manifest_raw(contract_value))
    expect_gate_error(lambda: validate_contract(mutated_contract_path), "CONTRACT_INVALID")

    duplicate_contract_path = SELF_TEST_DIR / "duplicate-contract.json"
    contract_raw = CONTRACT_PATH.read_bytes().rstrip()
    duplicate_contract_raw = contract_raw[:-1] + (
        b',"schemaVersion":"' + CONTRACT_SCHEMA.encode("ascii") + b'"}\n'
    )
    test_write(duplicate_contract_path, duplicate_contract_raw)
    expect_gate_error(lambda: validate_contract(duplicate_contract_path), "CONTRACT_DUPLICATE_KEY")

    environment = shell_environment.copy()
    environment["HARTEVO_EVIDENCE_TEST_PYTHON_BIN"] = "hartevo-python-missing"
    blocked = subprocess.run(
        [
            SCRIPT_PATH,
            "verify",
            "--manifest-commit",
            manifest_child,
            "--expected-source",
            source,
            "--expected-manifest-sha256",
            manifest_digest,
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if blocked.returncode != 2:
        raise AssertionError("missing parser dependency did not return BLOCKED_ENV")
    blocked_value = json.loads(blocked.stdout.decode("utf-8"))
    if (
        blocked_value.get("status") != "BLOCKED_ENV"
        or blocked_value.get("code") != "BLOCKED_ENV_GATE_DEPENDENCY_MISSING"
        or blocked_value.get("releaseDecision") != RELEASE_DECISION
    ):
        raise AssertionError("missing parser dependency receipt is invalid")

    return {
        "schema": VERIFICATION_SCHEMA,
        "status": "VERIFIED",
        "code": "COMMIT_BOUND_MANIFEST_SELF_TEST_VERIFIED",
        "releaseDecision": RELEASE_DECISION,
        "testMode": True,
        "checks": sorted([
            "all-assertions-passed-false-rejected",
            "artifact-digest-mutation-rejected",
            "artifact-duplicate-json-key-rejected",
            "artifact-id-duplicate-rejected",
            "artifact-source-dirty-rejected",
            "artifact-source-mismatch-rejected",
            "blocked-evidence-status-rejected",
            "blocked-parser-dependency-nonzero",
            "contract-duplicate-key-rejected",
            "contract-mutation-rejected",
            "contract-source-redaction-safe",
            "digest-only-required-claim-rejected",
            "fail-required-claim-rejected",
            "gate-source-redaction-safe",
            "git-object-not-worktree-read",
            "inconclusive-status-rejected",
            "manifest-absolute-path-rejected",
            "manifest-digest-mutation-rejected",
            "manifest-duplicate-key-rejected",
            "manifest-source-parent-rejected",
            "not-run-status-rejected",
            "partial-status-rejected",
            "positive-ev01-pass-accepted",
            "release-v2-3-passed-false-rejected",
            "release-v2-3-shell-nonzero",
            "source-high-entropy-rejected",
            "source-pem-rejected",
            "shell-digest-mutation-nonzero",
            "shell-verify-positive",
            "source-secret-rejected",
            "source-url-userinfo-rejected",
            "strict-email-rejected",
            "strict-host-rejected",
            "strict-sensitive-field-rejected",
            "success-false-rejected",
            "symlink-artifact-rejected",
            "target-artifact-rejected",
            "test-only-required-claim-rejected",
            "test-only-evidence-rejected",
            "unsorted-claim-ids-rejected",
            "unknown-status-rejected",
            "blocked-env-required-claim-rejected",
            "skipped-status-rejected",
            "verification-status-fail-rejected",
        ]),
    }


try:
    if MODE == "verify":
        emit(
            verify(
                REPO_ROOT,
                CONTRACT_PATH,
                MANIFEST_COMMIT,
                EXPECTED_SOURCE,
                EXPECTED_MANIFEST_SHA256,
                SHELL_TEST_MODE,
            )
        )
    elif MODE == "self-test":
        emit(run_self_test())
    else:
        raise GateError("INVALID_ARGUMENT", "unknown gate mode")
except GateError as error:
    emit(problem(error))
    sys.exit(2 if error.status == "BLOCKED_ENV" else 1)
except Exception:
    emit(
        problem(
            GateError(
                "INTERNAL_GATE_ERROR",
                "unexpected evidence gate failure",
            )
        )
    )
    sys.exit(1)
PY
python_status=$?
set -e
exit "${python_status}"
