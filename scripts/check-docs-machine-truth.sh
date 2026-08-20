#!/usr/bin/env bash
set -euo pipefail

emit_blocked_env() {
  local code="$1"
  local message="$2"
  printf '{"code":"%s","message":"%s","releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.docs-machine-truth-verification/v1","status":"BLOCKED_ENV","testMode":false}\n' \
    "$code" "$message"
  exit 2
}

command -v git >/dev/null 2>&1 || emit_blocked_env "GIT_NOT_AVAILABLE" "git is required"
command -v python3 >/dev/null 2>&1 || emit_blocked_env "PYTHON_NOT_AVAILABLE" "python3 is required"
command -v bash >/dev/null 2>&1 || emit_blocked_env "BASH_NOT_AVAILABLE" "bash is required"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || \
  emit_blocked_env "REPOSITORY_NOT_AVAILABLE" "run inside the Hartevo Git worktree"
mode="${1:-}"

case "$mode" in
  verify|self-test) ;;
  *)
    printf '%s\n' \
      '{"code":"USAGE","message":"usage: check-docs-machine-truth.sh verify|self-test","releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.docs-machine-truth-verification/v1","status":"FAIL","testMode":false}'
    exit 2
    ;;
esac

python3 - "$repo_root" "$mode" <<'PY'
from __future__ import annotations

import copy
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


SCHEMA = "hartevo.docs-machine-truth-verification/v1"
MANIFEST_REL = "contracts/docs-machine-truth/claims.v1.json"
EXPECTED_SCHEMA_VERSION = "hartevo-docs-machine-truth/v1"
EXPECTED_NON_AUTHORITIES = ["testCount", "eLevel"]
REPO = Path(sys.argv[1]).resolve()
MODE = sys.argv[2]


class GateError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        claim_id: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.claim_id = claim_id
        self.source = source


def fail(
    code: str,
    message: str,
    *,
    claim_id: Optional[str] = None,
    source: Optional[str] = None,
) -> None:
    raise GateError(code, message, claim_id=claim_id, source=source)


def require(
    condition: bool,
    code: str,
    message: str,
    *,
    claim_id: Optional[str] = None,
    source: Optional[str] = None,
) -> None:
    if not condition:
        fail(code, message, claim_id=claim_id, source=source)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("DUPLICATE_OBJECT_KEY", f"duplicate object key: {key}")
        value[key] = item
    return value


def load_json(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail("INVALID_JSON", f"{label} is not strict UTF-8 JSON: {error}")
    require(isinstance(parsed, dict), "INVALID_JSON_ROOT", f"{label} root must be an object")
    return parsed


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual_set = set(value.keys())
    require(
        actual_set == expected_set,
        "MANIFEST_SHAPE_MISMATCH",
        f"{label} keys differ: expected {sorted(expected_set)}, got {sorted(actual_set)}",
    )


def nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, "MANIFEST_TYPE_MISMATCH", f"{label} must be a non-empty string")
    return value


def unique_string_list(value: Any, label: str) -> List[str]:
    require(isinstance(value, list), "MANIFEST_TYPE_MISMATCH", f"{label} must be an array")
    result = [nonempty_string(item, label) for item in value]
    require(len(result) == len(set(result)), "MANIFEST_DUPLICATE_VALUE", f"{label} contains duplicates")
    return result


def sanitize(message: str) -> str:
    return message.replace(str(REPO), "<repo>")


def regular_path(relative_path: str, *, label: str) -> Path:
    path = REPO / relative_path
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        fail("SOURCE_MISSING", f"{label} is missing: {relative_path}", source=relative_path)
        raise error
    require(
        stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
        "SOURCE_NOT_REGULAR",
        f"{label} must be a regular file: {relative_path}",
        source=relative_path,
    )
    return path


def read_text(relative_path: str, *, label: str) -> str:
    path = regular_path(relative_path, label=label)
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        fail("SOURCE_NOT_UTF8", f"{label} is not UTF-8: {relative_path}: {error}", source=relative_path)
        raise error


def read_json_file(relative_path: str, *, label: str) -> Dict[str, Any]:
    path = regular_path(relative_path, label=label)
    return load_json(path.read_bytes(), relative_path)


def decode_pointer_token(token: str) -> str:
    decoded: List[str] = []
    index = 0
    while index < len(token):
        if token[index] != "~":
            decoded.append(token[index])
            index += 1
            continue
        require(index + 1 < len(token) and token[index + 1] in {"0", "1"}, "JSON_POINTER_INVALID", f"invalid JSON pointer token: {token}")
        decoded.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def json_pointer_get(value: Any, pointer: str, *, label: str) -> Any:
    require(pointer == "" or pointer.startswith("/"), "JSON_POINTER_INVALID", f"{label} must start with /")
    current = value
    if pointer == "":
        return current
    for raw_token in pointer[1:].split("/"):
        token = decode_pointer_token(raw_token)
        if isinstance(current, dict):
            require(token in current, "JSON_POINTER_MISSING", f"{label} does not contain /{raw_token}")
            current = current[token]
        elif isinstance(current, list):
            require(token.isdigit(), "JSON_POINTER_INVALID", f"{label} array token is not an index: {token}")
            index = int(token)
            require(index < len(current), "JSON_POINTER_MISSING", f"{label} array index is out of range: {index}")
            current = current[index]
        else:
            fail("JSON_POINTER_MISSING", f"{label} cannot descend through scalar at /{raw_token}")
    return current


def source_label(source: Mapping[str, Any], *, fact_id: Optional[str] = None) -> str:
    kind = source.get("kind")
    if kind in {"json_pointer", "json_array_length"}:
        return f"{source['file']}#{source['pointer']}"
    if kind == "symbol_literal":
        return f"{source['file']}::{source['symbol']} literal {source['literal']!r}"
    if kind == "symbol_present":
        return f"{source['file']}::{source['symbol']}"
    if kind == "directory_literal_absent":
        return f"{source['directory']}/*{','.join(source['extensions'])} contains no {source['needle']!r}"
    if kind == "manifest_issue_urls":
        return f"{MANIFEST_REL}#{source['pointer']}"
    if kind == "derived_subtract":
        return f"derived {source['left']} - {source['right']}"
    return fact_id or "unknown source"


def validate_authority(manifest: Mapping[str, Any]) -> None:
    authority = manifest["authority"]
    exact_keys(authority, ["currentDocument", "beginMarker", "endMarker"], "authority")
    nonempty_string(authority["currentDocument"], "authority.currentDocument")
    nonempty_string(authority["beginMarker"], "authority.beginMarker")
    nonempty_string(authority["endMarker"], "authority.endMarker")
    require(
        authority["beginMarker"] != authority["endMarker"],
        "MANIFEST_SHAPE_MISMATCH",
        "authority markers must differ",
    )


def validate_issue_list(manifest: Mapping[str, Any]) -> None:
    issues = manifest["gm01Issues"]
    require(isinstance(issues, list) and issues, "MANIFEST_TYPE_MISMATCH", "gm01Issues must be a non-empty array")
    numbers: List[int] = []
    urls: List[str] = []
    for index, issue in enumerate(issues):
        exact_keys(issue, ["number", "url"], f"gm01Issues[{index}]")
        number = issue["number"]
        require(
            isinstance(number, int) and not isinstance(number, bool) and number > 0,
            "MANIFEST_TYPE_MISMATCH",
            f"gm01Issues[{index}].number must be a positive integer",
        )
        url = nonempty_string(issue["url"], f"gm01Issues[{index}].url")
        expected_url = f"https://github.com/tangpingqingwa/hartevo-desktop/issues/{number}"
        require(
            url == expected_url,
            "GM01_ISSUE_LINK_INVALID",
            f"GM-01 issue #{number} URL must be {expected_url}",
            source=f"{MANIFEST_REL}#/gm01Issues/{index}",
        )
        numbers.append(number)
        urls.append(url)
    require(numbers == sorted(numbers), "GM01_ISSUE_ORDER_INVALID", "gm01Issues must be sorted by issue number", source=f"{MANIFEST_REL}#/gm01Issues")
    require(len(numbers) == len(set(numbers)), "GM01_ISSUE_DUPLICATE", "gm01Issues contains duplicate issue numbers", source=f"{MANIFEST_REL}#/gm01Issues")
    require(len(urls) == len(set(urls)), "GM01_ISSUE_DUPLICATE", "gm01Issues contains duplicate URLs", source=f"{MANIFEST_REL}#/gm01Issues")


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    exact_keys(
        manifest,
        [
            "schemaVersion",
            "manifestId",
            "authority",
            "facts",
            "claims",
            "requiredClaimIds",
            "equalFactGroups",
            "gm01Issues",
            "nonAuthorities",
        ],
        "manifest",
    )
    require(manifest["schemaVersion"] == EXPECTED_SCHEMA_VERSION, "MANIFEST_SCHEMA_MISMATCH", f"manifest schemaVersion must be {EXPECTED_SCHEMA_VERSION}", source=MANIFEST_REL)
    nonempty_string(manifest["manifestId"], "manifest.manifestId")
    validate_authority(manifest)

    facts = manifest["facts"]
    require(isinstance(facts, list) and facts, "MANIFEST_TYPE_MISMATCH", "facts must be a non-empty array")
    fact_ids: List[str] = []
    for index, fact in enumerate(facts):
        exact_keys(fact, ["id", "source"], f"facts[{index}]")
        fact_id = nonempty_string(fact["id"], f"facts[{index}].id")
        require(fact_id not in fact_ids, "DUPLICATE_FACT_ID", f"fact ID is duplicated: {fact_id}", source=f"{MANIFEST_REL}#/facts/{index}")
        fact_ids.append(fact_id)
        require(isinstance(fact["source"], dict), "MANIFEST_TYPE_MISMATCH", f"facts[{index}].source must be an object")
        nonempty_string(fact["source"].get("kind"), f"facts[{index}].source.kind")

    claims = manifest["claims"]
    require(isinstance(claims, list) and claims, "MANIFEST_TYPE_MISMATCH", "claims must be a non-empty array")
    claim_ids: List[str] = []
    fact_id_set = set(fact_ids)
    for index, claim in enumerate(claims):
        exact_keys(claim, ["claimId", "factId", "status", "expectedValue"], f"claims[{index}]")
        claim_id = nonempty_string(claim["claimId"], f"claims[{index}].claimId")
        require(claim_id not in claim_ids, "DUPLICATE_CLAIM_ID", f"claim ID is duplicated: {claim_id}", claim_id=claim_id, source=f"{MANIFEST_REL}#/claims/{index}")
        claim_ids.append(claim_id)
        fact_id = nonempty_string(claim["factId"], f"claims[{index}].factId")
        require(fact_id in fact_id_set, "CLAIM_SOURCE_MISSING", f"claim {claim_id} references missing fact {fact_id}", claim_id=claim_id, source=f"{MANIFEST_REL}#/claims/{index}/factId")
        require(claim["status"] in {"current", "historical"}, "CLAIM_STATUS_INVALID", f"claim {claim_id} status must be current or historical", claim_id=claim_id, source=f"{MANIFEST_REL}#/claims/{index}/status")

    required_ids = unique_string_list(manifest["requiredClaimIds"], "requiredClaimIds")
    missing_ids = [claim_id for claim_id in required_ids if claim_id not in claim_ids]
    if missing_ids:
        claim_id = missing_ids[0]
        fail("CLAIM_MISSING", f"required claim {claim_id} is missing from manifest claims; add it and bind it to an authority fact", claim_id=claim_id, source=f"{MANIFEST_REL}#/claims")
    unexpected_ids = [claim_id for claim_id in claim_ids if claim_id not in required_ids]
    if unexpected_ids:
        claim_id = unexpected_ids[0]
        fail("CLAIM_UNEXPECTED", f"claim {claim_id} is not listed in requiredClaimIds; classify or remove it", claim_id=claim_id, source=f"{MANIFEST_REL}#/requiredClaimIds")

    groups = manifest["equalFactGroups"]
    require(isinstance(groups, list), "MANIFEST_TYPE_MISMATCH", "equalFactGroups must be an array")
    for index, group in enumerate(groups):
        values = unique_string_list(group, f"equalFactGroups[{index}]")
        require(len(values) >= 2, "MANIFEST_TYPE_MISMATCH", f"equalFactGroups[{index}] must compare at least two facts")
        for fact_id in values:
            require(fact_id in fact_id_set, "FACT_SOURCE_MISSING", f"equalFactGroups[{index}] references missing fact {fact_id}", source=f"{MANIFEST_REL}#/equalFactGroups/{index}")

    validate_issue_list(manifest)
    non_authorities = unique_string_list(manifest["nonAuthorities"], "nonAuthorities")
    require(
        non_authorities == EXPECTED_NON_AUTHORITIES,
        "NON_AUTHORITY_POLICY_DRIFT",
        f"nonAuthorities must remain exactly {EXPECTED_NON_AUTHORITIES}; test counts and E-levels are not machine-inferred",
        source=f"{MANIFEST_REL}#/nonAuthorities",
    )


def symbol_region(text: str, symbol: str, *, source: str) -> str:
    start = text.find(symbol)
    require(start >= 0, "SYMBOL_MISSING", f"symbol is missing: {symbol}", source=source)
    open_index = text.find("{", start + len(symbol))
    require(open_index >= 0, "SYMBOL_REGION_INVALID", f"symbol has no body: {symbol}", source=source)
    depth = 0
    quote: Optional[str] = None
    escaped = False
    line_comment = False
    block_comment = False
    index = open_index
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {"\"", "'"}:
            quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
        index += 1
    fail("SYMBOL_REGION_INVALID", f"symbol body is not balanced: {symbol}", source=source)
    return ""


def evaluate_symbol_literal(source: Mapping[str, Any]) -> bool:
    exact_keys(source, ["kind", "file", "symbol", "literal", "literalValue"], "symbol_literal source")
    file_path = nonempty_string(source["file"], "symbol_literal.file")
    symbol = nonempty_string(source["symbol"], "symbol_literal.symbol")
    literal = nonempty_string(source["literal"], "symbol_literal.literal")
    literal_value = source["literalValue"]
    require(isinstance(literal_value, bool), "MANIFEST_TYPE_MISMATCH", "symbol_literal.literalValue must be boolean")
    text = read_text(file_path, label="symbol source")
    symbol_count = text.count(symbol)
    source_ref = source_label(source)
    require(symbol_count == 1, "SYMBOL_DUPLICATE", f"symbol must occur exactly once, found {symbol_count}: {symbol}", source=source_ref)
    region = symbol_region(text, symbol, source=source_ref)
    literal_count = region.count(literal)
    require(literal_count == 1, "SYMBOL_LITERAL_DRIFT", f"symbol body must contain literal exactly once, found {literal_count}: {literal}", source=source_ref)
    return literal_value


def evaluate_source(source: Mapping[str, Any], manifest: Mapping[str, Any]) -> Any:
    kind = source.get("kind")
    if kind == "json_pointer":
        exact_keys(source, ["kind", "file", "pointer"], "json_pointer source")
        file_path = nonempty_string(source["file"], "json_pointer.file")
        pointer = nonempty_string(source["pointer"], "json_pointer.pointer")
        document = read_json_file(file_path, label="JSON authority")
        return json_pointer_get(document, pointer, label=source_label(source))
    if kind == "json_array_length":
        exact_keys(source, ["kind", "file", "pointer"], "json_array_length source")
        file_path = nonempty_string(source["file"], "json_array_length.file")
        pointer = nonempty_string(source["pointer"], "json_array_length.pointer")
        document = read_json_file(file_path, label="JSON authority")
        value = json_pointer_get(document, pointer, label=source_label(source))
        require(isinstance(value, list), "JSON_POINTER_TYPE_MISMATCH", f"{source_label(source)} must resolve to an array", source=source_label(source))
        return len(value)
    if kind == "derived_subtract":
        exact_keys(source, ["kind", "left", "right"], "derived_subtract source")
        return None
    if kind == "symbol_literal":
        return evaluate_symbol_literal(source)
    if kind == "symbol_present":
        exact_keys(source, ["kind", "file", "symbol", "minimumOccurrences"], "symbol_present source")
        file_path = nonempty_string(source["file"], "symbol_present.file")
        symbol = nonempty_string(source["symbol"], "symbol_present.symbol")
        minimum = source["minimumOccurrences"]
        require(isinstance(minimum, int) and not isinstance(minimum, bool) and minimum > 0, "MANIFEST_TYPE_MISMATCH", "symbol_present.minimumOccurrences must be a positive integer")
        text = read_text(file_path, label="symbol source")
        count = text.count(symbol)
        require(count >= minimum, "SYMBOL_MISSING", f"symbol {symbol!r} occurs {count} times, requires at least {minimum}", source=source_label(source))
        return True
    if kind == "directory_literal_absent":
        exact_keys(source, ["kind", "directory", "extensions", "needle"], "directory_literal_absent source")
        directory = nonempty_string(source["directory"], "directory_literal_absent.directory")
        extensions = unique_string_list(source["extensions"], "directory_literal_absent.extensions")
        needle = nonempty_string(source["needle"], "directory_literal_absent.needle")
        directory_path = REPO / directory
        require(directory_path.is_dir() and not directory_path.is_symlink(), "SOURCE_MISSING", f"symbol authority directory is missing: {directory}", source=directory)
        matches: List[str] = []
        for path in sorted(directory_path.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.suffix not in extensions:
                continue
            relative = path.relative_to(REPO).as_posix()
            text = path.read_text(encoding="utf-8")
            if needle in text:
                matches.append(relative)
        require(not matches, "SYMBOL_UNEXPECTED_PRESENT", f"unexpected Desktop caller literal {needle!r} found in {', '.join(matches)}", source=source_label(source))
        return False
    if kind == "manifest_issue_urls":
        exact_keys(source, ["kind", "pointer"], "manifest_issue_urls source")
        pointer = nonempty_string(source["pointer"], "manifest_issue_urls.pointer")
        issues = json_pointer_get(manifest, pointer, label=source_label(source))
        require(isinstance(issues, list), "MANIFEST_TYPE_MISMATCH", f"{source_label(source)} must resolve to an array", source=source_label(source))
        return [issue["url"] for issue in issues]
    fail("SOURCE_KIND_UNSUPPORTED", f"unsupported source kind: {kind}", source=source_label(source))
    return None


def evaluate_facts(manifest: Mapping[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Mapping[str, Any]]]:
    facts = {fact["id"]: fact for fact in manifest["facts"]}
    values: Dict[str, Any] = {}
    sources: Dict[str, Mapping[str, Any]] = {fact_id: fact["source"] for fact_id, fact in facts.items()}
    active: Set[str] = set()

    def evaluate(fact_id: str) -> Any:
        if fact_id in values:
            return values[fact_id]
        require(fact_id not in active, "FACT_CYCLE", f"fact dependency cycle includes {fact_id}", source=MANIFEST_REL)
        active.add(fact_id)
        source = facts[fact_id]["source"]
        if source["kind"] == "derived_subtract":
            left = evaluate(source["left"])
            right = evaluate(source["right"])
            require(isinstance(left, int) and not isinstance(left, bool), "DERIVED_TYPE_MISMATCH", f"derived left fact {source['left']} is not an integer", source=source_label(source))
            require(isinstance(right, int) and not isinstance(right, bool), "DERIVED_TYPE_MISMATCH", f"derived right fact {source['right']} is not an integer", source=source_label(source))
            value = left - right
        else:
            value = evaluate_source(source, manifest)
        active.remove(fact_id)
        values[fact_id] = value
        return value

    for fact_id in facts:
        evaluate(fact_id)
    return values, sources


def validate_equal_fact_groups(manifest: Mapping[str, Any], values: Mapping[str, Any], sources: Mapping[str, Mapping[str, Any]]) -> None:
    for index, group in enumerate(manifest["equalFactGroups"]):
        first_id = group[0]
        first_value = values[first_id]
        for fact_id in group[1:]:
            if values[fact_id] != first_value:
                fail(
                    "SOURCE_CONTRADICTORY",
                    f"authority facts {first_id}={first_value!r} and {fact_id}={values[fact_id]!r} disagree; update the stale authority or its pointer",
                    source=f"{source_label(sources[first_id], fact_id=first_id)} vs {source_label(sources[fact_id], fact_id=fact_id)}",
                )


def claim_map(manifest: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {claim["claimId"]: claim for claim in manifest["claims"]}


def validate_claim_values(
    manifest: Mapping[str, Any],
    values: Mapping[str, Any],
    sources: Mapping[str, Mapping[str, Any]],
) -> None:
    claims_by_fact: Dict[str, List[Mapping[str, Any]]] = {}
    for claim in manifest["claims"]:
        if claim["status"] != "current":
            continue
        claims_by_fact.setdefault(claim["factId"], []).append(claim)

    for fact_id, claims in claims_by_fact.items():
        first = claims[0]
        for claim in claims[1:]:
            if claim["expectedValue"] != first["expectedValue"]:
                fail(
                    "CLAIM_CONTRADICTORY",
                    f"claims {first['claimId']} and {claim['claimId']} give different values for fact {fact_id}; retain one current value and bind both to the same authority",
                    claim_id=claim["claimId"],
                    source=source_label(sources[fact_id], fact_id=fact_id),
                )

    for claim in manifest["claims"]:
        if claim["status"] != "current":
            continue
        fact_id = claim["factId"]
        source_ref = source_label(sources[fact_id], fact_id=fact_id)
        if claim["expectedValue"] != values[fact_id]:
            fail(
                "CLAIM_STALE",
                f"claim {claim['claimId']} says {claim['expectedValue']!r}, but machine authority resolves to {values[fact_id]!r}; update the claim from {source_ref}",
                claim_id=claim["claimId"],
                source=source_ref,
            )


def parse_projection(manifest: Mapping[str, Any], document_override: Optional[str] = None) -> Dict[str, Any]:
    authority = manifest["authority"]
    document_path = authority["currentDocument"]
    text = document_override if document_override is not None else read_text(document_path, label="current claims document")
    begin = authority["beginMarker"]
    end = authority["endMarker"]
    require(text.count(begin) == 1, "DOCUMENT_PROJECTION_MARKER_DRIFT", f"current claims document must contain begin marker exactly once", source=document_path)
    require(text.count(end) == 1, "DOCUMENT_PROJECTION_MARKER_DRIFT", f"current claims document must contain end marker exactly once", source=document_path)
    start = text.index(begin) + len(begin)
    finish = text.index(end, start)
    body = text[start:finish]
    prefix = "\n```json\n"
    suffix = "\n```\n"
    require(body.startswith(prefix) and body.endswith(suffix), "DOCUMENT_PROJECTION_FORMAT", "current claims projection must be one fenced JSON object between the markers", source=document_path)
    raw = body[len(prefix) : -len(suffix)]
    projection = load_json(raw.encode("utf-8"), f"{document_path} machine-truth projection")
    exact_keys(projection, ["manifest", "claims"], "document projection")
    require(projection["manifest"] == MANIFEST_REL, f"DOCUMENT_MANIFEST_POINTER_DRIFT", f"document projection must point to {MANIFEST_REL}", source=document_path)
    return projection


def validate_projection(
    manifest: Mapping[str, Any],
    projection: Mapping[str, Any],
    values: Mapping[str, Any],
    sources: Mapping[str, Mapping[str, Any]],
) -> None:
    projected_claims = projection["claims"]
    require(isinstance(projected_claims, list) and projected_claims, "DOCUMENT_PROJECTION_TYPE_MISMATCH", "document projection claims must be a non-empty array", source=manifest["authority"]["currentDocument"])
    projected_ids: List[str] = []
    by_id: Dict[str, Mapping[str, Any]] = {}
    for index, projected in enumerate(projected_claims):
        exact_keys(projected, ["claimId", "value"], f"document projection claims[{index}]")
        claim_id = nonempty_string(projected["claimId"], f"document projection claims[{index}].claimId")
        require(claim_id not in projected_ids, "DOCUMENT_CLAIM_DUPLICATE", f"document projection repeats claim {claim_id}; keep one structured claim entry", claim_id=claim_id, source=manifest["authority"]["currentDocument"])
        projected_ids.append(claim_id)
        by_id[claim_id] = projected

    required_ids = manifest["requiredClaimIds"]
    missing_ids = [claim_id for claim_id in required_ids if claim_id not in projected_ids]
    if missing_ids:
        claim_id = missing_ids[0]
        fail("DOCUMENT_CLAIM_MISSING", f"document projection is missing required claim {claim_id}; add one entry in the fenced JSON projection", claim_id=claim_id, source=manifest["authority"]["currentDocument"])
    unexpected_ids = [claim_id for claim_id in projected_ids if claim_id not in required_ids]
    if unexpected_ids:
        claim_id = unexpected_ids[0]
        fail("DOCUMENT_CLAIM_UNEXPECTED", f"document projection contains unregistered claim {claim_id}; bind it in the manifest or remove it", claim_id=claim_id, source=manifest["authority"]["currentDocument"])

    claims = claim_map(manifest)
    for claim_id in required_ids:
        claim = claims[claim_id]
        projected = by_id[claim_id]
        source_ref = source_label(sources[claim["factId"]], fact_id=claim["factId"])
        if projected["value"] != claim["expectedValue"] or projected["value"] != values[claim["factId"]]:
            fail(
                "DOCUMENT_CLAIM_STALE",
                f"document projection claim {claim_id} says {projected['value']!r}, but authority {source_ref} resolves to {values[claim['factId']]!r}; update the structured projection",
                claim_id=claim_id,
                source=source_ref,
            )


def verify_repository(
    *,
    manifest_override: Optional[Mapping[str, Any]] = None,
    projection_override: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    manifest_path = regular_path(MANIFEST_REL, label="machine-truth manifest")
    manifest_raw = manifest_path.read_bytes()
    manifest = dict(manifest_override) if manifest_override is not None else load_json(manifest_raw, MANIFEST_REL)
    validate_manifest(manifest)
    values, sources = evaluate_facts(manifest)
    validate_equal_fact_groups(manifest, values, sources)
    validate_claim_values(manifest, values, sources)
    projection = dict(projection_override) if projection_override is not None else parse_projection(manifest)
    validate_projection(manifest, projection, values, sources)
    return {
        "manifest": manifest,
        "manifestRawSha256": sha256(manifest_raw),
        "values": values,
    }


def expect_error(checks: List[str], check_id: str, expected_code: str, operation: Any) -> None:
    try:
        operation()
    except GateError as error:
        require(
            error.code == expected_code,
            "SELF_TEST_WRONG_FAILURE",
            f"{check_id} returned {error.code}, expected {expected_code}",
        )
        checks.append(check_id)
        return
    fail("SELF_TEST_FALSE_PASS", f"{check_id} unexpectedly passed")


def run_self_test() -> Dict[str, Any]:
    positive = verify_repository()
    manifest = copy.deepcopy(positive["manifest"])
    projection = parse_projection(manifest)
    checks = ["positive-current-repository"]
    target_claim_id = "DMT-REL-SCHEMA-01"

    stale_manifest = copy.deepcopy(manifest)
    for claim in stale_manifest["claims"]:
        if claim["claimId"] == target_claim_id:
            claim["expectedValue"] = "2.2.0"
            break
    expect_error(checks, "stale-claim", "CLAIM_STALE", lambda: verify_repository(manifest_override=stale_manifest))

    missing_manifest = copy.deepcopy(manifest)
    missing_manifest["claims"] = [claim for claim in missing_manifest["claims"] if claim["claimId"] != target_claim_id]
    expect_error(checks, "missing-claim", "CLAIM_MISSING", lambda: verify_repository(manifest_override=missing_manifest))

    contradictory_manifest = copy.deepcopy(manifest)
    contradictory_claim = copy.deepcopy(next(claim for claim in contradictory_manifest["claims"] if claim["claimId"] == target_claim_id))
    contradictory_claim["claimId"] = "DMT-SELF-TEST-CONTRADICTORY-01"
    contradictory_claim["expectedValue"] = "2.2.0"
    contradictory_manifest["claims"].append(contradictory_claim)
    contradictory_manifest["requiredClaimIds"].append(contradictory_claim["claimId"])
    expect_error(checks, "contradictory-claim", "CLAIM_CONTRADICTORY", lambda: verify_repository(manifest_override=contradictory_manifest))

    duplicate_manifest = copy.deepcopy(manifest)
    duplicate_manifest["claims"].append(copy.deepcopy(duplicate_manifest["claims"][0]))
    expect_error(checks, "duplicate-claim", "DUPLICATE_CLAIM_ID", lambda: verify_repository(manifest_override=duplicate_manifest))

    stale_projection = copy.deepcopy(projection)
    for projected in stale_projection["claims"]:
        if projected["claimId"] == target_claim_id:
            projected["value"] = "2.2.0"
            break
    expect_error(checks, "stale-document-claim", "DOCUMENT_CLAIM_STALE", lambda: verify_repository(projection_override=stale_projection))

    duplicate_projection = copy.deepcopy(projection)
    duplicate_projection["claims"].append(copy.deepcopy(duplicate_projection["claims"][0]))
    expect_error(checks, "duplicate-document-claim", "DOCUMENT_CLAIM_DUPLICATE", lambda: verify_repository(projection_override=duplicate_projection))

    checks.sort()
    require(len(checks) == len(set(checks)), "SELF_TEST_CHECK_DUPLICATE", "self-test checks must be unique")
    return {
        "checks": checks,
        "checksPassed": len(checks),
        "code": "DOCS_MACHINE_TRUTH_SELF_TEST_VERIFIED",
        "releaseDecision": "NOT_EVALUATED",
        "releasePassed": False,
        "schema": SCHEMA,
        "status": "VERIFIED",
        "testMode": True,
    }


def verify_payload(result: Mapping[str, Any]) -> Dict[str, Any]:
    manifest = result["manifest"]
    values = result["values"]
    return {
        "applicationRouteCount": values["application_route_count"],
        "claimCount": len(manifest["claims"]),
        "code": "DOCS_MACHINE_TRUTH_VERIFIED",
        "desktopExecutionHandle": values["desktop_execution_handle"],
        "desktopSubscription": values["desktop_subscription_caller"],
        "desktopSubscriptionApi": values["desktop_subscription_api"],
        "desktopSubscriptionScope": values["desktop_subscription_scope"],
        "desktopExecutionPaintState": values["desktop_execution_paint_state"],
        "desktopVm11EighthCaller": values["desktop_vm11_eighth_caller"],
        "gm01IssueUrls": values["gm01_issue_urls"],
        "handlerRegistryVersion": values["handler_registry_version"],
        "implementedApplicationHandlerCount": values["handler_count"],
        "manifestId": manifest["manifestId"],
        "manifestSha256": result["manifestRawSha256"],
        "notImplementedApplicationRouteCount": values["not_implemented_route_count"],
        "nonAuthorities": manifest["nonAuthorities"],
        "releaseDecision": "NOT_EVALUATED",
        "releaseEvidenceSchemaVersion": values["release_schema_contract"],
        "releasePassed": values["release_passed"],
        "schema": SCHEMA,
        "status": "VERIFIED",
        "testMode": False,
    }


def emit(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


try:
    if MODE == "verify":
        emit(verify_payload(verify_repository()))
    else:
        emit(run_self_test())
except GateError as error:
    payload: Dict[str, Any] = {
        "code": error.code,
        "message": sanitize(error.message),
        "releaseDecision": "NOT_EVALUATED",
        "releasePassed": False,
        "schema": SCHEMA,
        "status": "FAIL",
        "testMode": MODE == "self-test",
    }
    if error.claim_id is not None:
        payload["claimId"] = error.claim_id
    if error.source is not None:
        payload["source"] = sanitize(error.source)
    emit(payload)
    sys.exit(1)
except Exception as error:
    emit(
        {
            "code": "INTERNAL_ERROR",
            "message": sanitize(str(error)),
            "releaseDecision": "NOT_EVALUATED",
            "releasePassed": False,
            "schema": SCHEMA,
            "status": "FAIL",
            "testMode": MODE == "self-test",
        }
    )
    sys.exit(1)
PY
