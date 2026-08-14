#!/usr/bin/env python3
"""Content-free machine checks for plugin/capability documentation truth.

DOC-PLUGIN-TRUTH-01 deliberately keeps document claim matching small and
configuration-driven. Runtime truth comes from JSON pointers and exact source
symbols; the checker never turns prose into a registration, test count, or
evidence level.
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "hartevo.doc-plugin-truth-verification/v1"
CLAIMS_SCHEMA = "hartevo.doc-plugin-truth-claims/v1"
CHECKER = "DOC-PLUGIN-TRUTH-01"
DEFAULT_CLAIMS = Path(__file__).with_name("plugin-truth-claims.v1.json")


class TruthError(Exception):
    """A stable, content-free checker error."""

    def __init__(self, code: str, source: str | None = None):
        super().__init__(code)
        self.code = code
        self.source = source


def _unique_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TruthError("DUPLICATE_OBJECT_KEY")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise TruthError("AUTHORITY_SOURCE_UNREADABLE", path.as_posix()) from error
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs)
    except TruthError as error:
        raise TruthError(error.code, path.as_posix()) from error
    except (TypeError, json.JSONDecodeError) as error:
        raise TruthError("INVALID_JSON", path.as_posix()) from error


def ensure(condition: bool, code: str, source: str | None = None) -> None:
    if not condition:
        raise TruthError(code, source)


def relative_path(root: Path, value: str) -> Path:
    candidate = Path(value)
    ensure(not candidate.is_absolute(), "INVALID_AUTHORITY_PATH", value)
    ensure(".." not in candidate.parts, "INVALID_AUTHORITY_PATH", value)
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise TruthError("INVALID_AUTHORITY_PATH", value) from error
    return resolved


def pointer_get(value: Any, pointer: str, source: str) -> Any:
    ensure(pointer == "" or pointer.startswith("/"), "INVALID_JSON_POINTER", source)
    current = value
    if pointer == "":
        return current
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            ensure(token in current, "AUTHORITY_POINTER_MISSING", source)
            current = current[token]
        elif isinstance(current, list):
            ensure(token.isdigit(), "AUTHORITY_POINTER_MISSING", source)
            index = int(token)
            ensure(index < len(current), "AUTHORITY_POINTER_MISSING", source)
            current = current[index]
        else:
            raise TruthError("AUTHORITY_POINTER_MISSING", source)
    return current


def _string_list(value: Any, source: str, *, sorted_values: bool = False) -> list[str]:
    ensure(isinstance(value, list), "INVALID_CONFIG_TYPE", source)
    ensure(all(isinstance(item, str) and item for item in value), "INVALID_CONFIG_TYPE", source)
    result = list(value)
    ensure(len(result) == len(set(result)), "DUPLICATE_CONFIG_VALUE", source)
    if sorted_values:
        ensure(result == sorted(result), "UNSORTED_CONFIG_VALUE", source)
    return result


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], source: str) -> None:
    ensure(set(value) == set(expected), "CONFIG_SHAPE_MISMATCH", source)


def validate_config(config: Any) -> dict[str, Any]:
    ensure(isinstance(config, dict), "CONFIG_ROOT_NOT_OBJECT")
    _exact_keys(
        config,
        ("schema", "checker", "documentRoots", "facts", "claims", "requiredClaimIds", "exitCodes"),
        "claims-config",
    )
    ensure(config["schema"] == CLAIMS_SCHEMA, "CONFIG_SCHEMA_MISMATCH")
    ensure(config["checker"] == CHECKER, "CONFIG_CHECKER_MISMATCH")
    roots = _string_list(config["documentRoots"], "documentRoots", sorted_values=True)
    ensure(roots, "CONFIG_EMPTY_DOCUMENT_SCOPE")
    for root in roots:
        ensure(Path(root).is_absolute() is False and ".." not in Path(root).parts, "INVALID_AUTHORITY_PATH", root)

    facts = config["facts"]
    ensure(isinstance(facts, list) and facts, "CONFIG_EMPTY_FACTS")
    fact_ids: list[str] = []
    fact_kinds = {
        "json_pointer",
        "json_array_length",
        "json_count_where",
        "symbol_present",
        "repo_symbols_all_present",
        "repo_symbol_count",
        "repo_literal_count",
    }
    for fact in facts:
        ensure(isinstance(fact, dict), "CONFIG_SHAPE_MISMATCH", "facts")
        ensure(isinstance(fact.get("id"), str) and fact["id"], "CONFIG_ID_INVALID", "facts")
        fact_ids.append(fact["id"])
        kind = fact.get("kind")
        ensure(kind in fact_kinds, "CONFIG_KIND_INVALID", fact["id"])
        if kind in {"json_pointer", "json_array_length", "json_count_where"}:
            required = {"id", "kind", "file", "pointer"}
            if kind == "json_count_where":
                required |= {"field", "equals"}
            _exact_keys(fact, required, fact["id"])
            ensure(isinstance(fact["file"], str), "CONFIG_TYPE_INVALID", fact["id"])
            ensure(isinstance(fact["pointer"], str), "CONFIG_TYPE_INVALID", fact["id"])
            if kind == "json_count_where":
                ensure(isinstance(fact["field"], str) and fact["field"], "CONFIG_TYPE_INVALID", fact["id"])
        elif kind == "symbol_present":
            _exact_keys(fact, {"id", "kind", "file", "symbol"}, fact["id"])
            ensure(isinstance(fact["file"], str) and isinstance(fact["symbol"], str) and fact["symbol"], "CONFIG_TYPE_INVALID", fact["id"])
        elif kind == "repo_symbols_all_present":
            _exact_keys(fact, {"id", "kind", "roots", "symbols"}, fact["id"])
            _string_list(fact["roots"], fact["id"], sorted_values=True)
            _string_list(fact["symbols"], fact["id"], sorted_values=True)
        elif kind == "repo_symbol_count":
            _exact_keys(fact, {"id", "kind", "roots", "symbol"}, fact["id"])
            _string_list(fact["roots"], fact["id"], sorted_values=True)
            ensure(isinstance(fact["symbol"], str) and fact["symbol"], "CONFIG_TYPE_INVALID", fact["id"])
        elif kind == "repo_literal_count":
            _exact_keys(fact, {"id", "kind", "roots", "literal"}, fact["id"])
            _string_list(fact["roots"], fact["id"], sorted_values=True)
            ensure(isinstance(fact["literal"], str) and fact["literal"], "CONFIG_TYPE_INVALID", fact["id"])
    ensure(len(fact_ids) == len(set(fact_ids)), "DUPLICATE_FACT_ID")
    ensure(fact_ids == sorted(fact_ids), "UNSORTED_FACT_ID")

    claims = config["claims"]
    ensure(isinstance(claims, list) and claims, "CONFIG_EMPTY_CLAIMS")
    claim_ids: list[str] = []
    detectors = {
        "catalog_as_capability",
        "connected_status",
        "contradictory_connected",
        "fixed_surface",
        "irreversible_lifecycle",
        "model_visible_durable",
        "non_native_evidence",
        "parallel_registry",
        "plugin_components",
        "plugin_completion",
        "plugin_lifecycle",
        "provider_only",
        "ui_card_as_capability",
    }
    for claim in claims:
        ensure(isinstance(claim, dict), "CONFIG_SHAPE_MISMATCH", "claims")
        ensure(claim.get("kind") == "document", "CONFIG_KIND_INVALID", "claims")
        claim_id = claim.get("claimId")
        ensure(isinstance(claim_id, str) and claim_id, "CONFIG_ID_INVALID", "claims")
        claim_ids.append(claim_id)
        ensure(claim.get("detector") in detectors, "CONFIG_DETECTOR_INVALID", claim_id)
        authority = _string_list(claim.get("authority"), claim_id, sorted_values=True)
        ensure(authority and set(authority).issubset(set(fact_ids)), "MISSING_AUTHORITY_FACT", claim_id)
        ensure(isinstance(claim.get("code"), str) and claim["code"], "CONFIG_CODE_INVALID", claim_id)
        for key in (
            "matchAll",
            "matchAny",
            "assertionAny",
            "allowAny",
            "negativeAny",
            "fixtureScopeAll",
            "contradictionAny",
            "surfaceAny",
            "lifecycleAny",
            "irreversibleAny",
            "requiredAny",
            "qualifierAny",
        ):
            if key in claim:
                _string_list(claim[key], claim_id)
        if "maxDistance" in claim:
            ensure(isinstance(claim["maxDistance"], int) and claim["maxDistance"] > 0, "CONFIG_TYPE_INVALID", claim_id)
        if "conditions" in claim:
            ensure(isinstance(claim["conditions"], list), "CONFIG_TYPE_INVALID", claim_id)
            for condition in claim["conditions"]:
                ensure(isinstance(condition, dict), "CONFIG_TYPE_INVALID", claim_id)
                _exact_keys(condition, {"fact", "equals"}, claim_id)
                ensure(condition["fact"] in fact_ids, "MISSING_AUTHORITY_FACT", claim_id)
        if "requiredGroups" in claim:
            ensure(isinstance(claim["requiredGroups"], list) and claim["requiredGroups"], "CONFIG_TYPE_INVALID", claim_id)
            for group in claim["requiredGroups"]:
                _string_list(group, claim_id)
        if claim["detector"] == "catalog_as_capability":
            ensure("matchAll" in claim and "assertionAny" in claim and "allowAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "connected_status":
            ensure("matchAny" in claim and "negativeAny" in claim and "fixtureScopeAll" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "contradictory_connected":
            ensure("matchAny" in claim and "contradictionAny" in claim and "negativeAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "fixed_surface":
            ensure("surfaceAny" in claim and "assertionAny" in claim and "negativeAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "irreversible_lifecycle":
            ensure("matchAny" in claim and "irreversibleAny" in claim and "assertionAny" in claim and "negativeAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "model_visible_durable":
            ensure("matchAny" in claim and "assertionAny" in claim and "negativeAny" in claim and "conditions" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "non_native_evidence":
            ensure("qualifierAny" in claim and "assertionAny" in claim and "allowAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "parallel_registry":
            ensure("matchAny" in claim and "assertionAny" in claim and "negativeAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "plugin_components":
            ensure("matchAny" in claim and "assertionAny" in claim and "requiredGroups" in claim and "allowAny" in claim and "conditions" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "plugin_completion":
            ensure(
                "matchAny" in claim
                and "assertionAny" in claim
                and "negativeAny" in claim
                and "conditions" in claim,
                "CONFIG_RULE_INCOMPLETE",
                claim_id,
            )
        elif claim["detector"] == "provider_only":
            ensure("matchAny" in claim and "assertionAny" in claim and "negativeAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "ui_card_as_capability":
            ensure("matchAll" in claim and "maxDistance" in claim and "assertionAny" in claim and "allowAny" in claim, "CONFIG_RULE_INCOMPLETE", claim_id)
        elif claim["detector"] == "plugin_lifecycle":
            ensure(
                "matchAny" in claim
                and "lifecycleAny" in claim
                and "assertionAny" in claim
                and "negativeAny" in claim
                and "conditions" in claim,
                "CONFIG_RULE_INCOMPLETE",
                claim_id,
            )
    ensure(len(claim_ids) == len(set(claim_ids)), "DUPLICATE_CLAIM_ID")
    ensure(claim_ids == sorted(claim_ids), "UNSORTED_CLAIM_ID")
    required = _string_list(config["requiredClaimIds"], "requiredClaimIds", sorted_values=True)
    ensure(required == sorted(claim_ids), "MISSING_CLAIM")

    exit_codes = config["exitCodes"]
    ensure(isinstance(exit_codes, dict), "CONFIG_TYPE_INVALID", "exitCodes")
    _exact_keys(exit_codes, {"verified", "drift", "invalidInput", "checkerError", "usage"}, "exitCodes")
    ensure(
        exit_codes["verified"] == 0
        and exit_codes["drift"] == 10
        and exit_codes["invalidInput"] == 20
        and exit_codes["checkerError"] == 30
        and exit_codes["usage"] == 64,
        "EXIT_TAXONOMY_DRIFT",
    )
    return config


def fact_authority(fact: Mapping[str, Any]) -> str:
    kind = fact["kind"]
    if kind in {"json_pointer", "json_array_length", "json_count_where"}:
        return f"{fact['file']}#{fact['pointer']}"
    if kind == "symbol_present":
        return f"{fact['file']}::symbol:{fact['symbol']}"
    if kind in {"repo_symbols_all_present", "repo_symbol_count"}:
        return f"{','.join(fact['roots'])}::symbol:{'|'.join(fact.get('symbols', [fact.get('symbol', '')]))}"
    return f"{','.join(fact['roots'])}::literal:{fact['literal']}"


def repo_files(root: Path, roots: Sequence[str]) -> list[Path]:
    files: list[Path] = []
    for relative in roots:
        directory = relative_path(root, relative)
        ensure(directory.is_dir(), "AUTHORITY_SOURCE_MISSING", relative)
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or "target" in path.parts:
                continue
            if path.suffix.lower() in {".rs", ".json", ".toml"}:
                files.append(path)
    return sorted(set(files))


def token_count(text: str, token: str) -> int:
    if re.fullmatch(r"[A-Za-z0-9_]+", token):
        return len(re.findall(rf"\b{re.escape(token)}\b", text))
    return text.count(token)


def evaluate_fact(root: Path, fact: Mapping[str, Any]) -> Any:
    kind = fact["kind"]
    if kind in {"json_pointer", "json_array_length", "json_count_where"}:
        source = relative_path(root, fact["file"])
        document = load_json(source)
        value = pointer_get(document, fact["pointer"], fact_authority(fact))
        if kind == "json_pointer":
            return value
        ensure(isinstance(value, list), "AUTHORITY_VALUE_TYPE_MISMATCH", fact_authority(fact))
        if kind == "json_array_length":
            return len(value)
        return sum(isinstance(item, dict) and item.get(fact["field"]) == fact["equals"] for item in value)
    if kind == "symbol_present":
        source = relative_path(root, fact["file"])
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise TruthError("AUTHORITY_SOURCE_UNREADABLE", fact_authority(fact)) from error
        return fact["symbol"] in text
    files = repo_files(root, fact["roots"])
    if kind == "repo_symbols_all_present":
        return all(
            any(token_count(path.read_text(encoding="utf-8"), symbol) > 0 for path in files)
            for symbol in fact["symbols"]
        )
    if kind == "repo_symbol_count":
        pattern = re.compile(rf"\b(?:{fact['symbol']})\b", re.IGNORECASE)
        return sum(len(pattern.findall(path.read_text(encoding="utf-8"))) for path in files)
    return sum(path.read_text(encoding="utf-8").count(fact["literal"]) for path in files)


def evaluate_facts(root: Path, config: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    values: dict[str, Any] = {}
    authorities: dict[str, str] = {}
    for fact in config["facts"]:
        values[fact["id"]] = evaluate_fact(root, fact)
        authorities[fact["id"]] = fact_authority(fact)
    return values, authorities


@dataclass(frozen=True)
class Document:
    relative: str
    lines: tuple[str, ...]
    fence_by_line: tuple[str | None, ...]


def parse_document(relative: str, text: str) -> Document:
    lines = tuple(text.splitlines())
    fence_by_line: list[str | None] = [None] * len(lines)
    in_fence = False
    fence_start = -1
    for index, line in enumerate(lines):
        if re.match(r"^\s*```", line):
            if not in_fence:
                in_fence = True
                fence_start = index
                fence_by_line[index] = ""
            else:
                block = "\n".join(lines[fence_start : index + 1]).casefold()
                for block_index in range(fence_start, index + 1):
                    fence_by_line[block_index] = block
                in_fence = False
                fence_start = -1
        elif in_fence:
            fence_by_line[index] = ""
    if in_fence:
        block = "\n".join(lines[fence_start:]).casefold()
        for index in range(fence_start, len(lines)):
            fence_by_line[index] = block
    return Document(relative, lines, tuple(fence_by_line))


def read_documents(root: Path, config: Mapping[str, Any]) -> list[Document]:
    documents: list[Document] = []
    for relative_root in config["documentRoots"]:
        directory = relative_path(root, relative_root)
        ensure(directory.is_dir(), "DOCUMENT_ROOT_MISSING", relative_root)
        for path in sorted(directory.rglob("*.md")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise TruthError("DOCUMENT_UNREADABLE", path.as_posix()) from error
            documents.append(parse_document(path.relative_to(root).as_posix(), text))
    return sorted(documents, key=lambda document: document.relative)


def literal_match(text: str, term: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9_]+", term):
        return re.search(rf"\b{re.escape(term)}\b", text, re.IGNORECASE) is not None
    return term.casefold() in text.casefold()


def any_term(text: str, terms: Sequence[str]) -> bool:
    return any(literal_match(text, term) for term in terms)


def all_terms(text: str, terms: Sequence[str]) -> bool:
    return all(literal_match(text, term) for term in terms)


def term_positions(text: str, term: str) -> list[int]:
    folded = text.casefold()
    needle = term.casefold()
    if re.fullmatch(r"[A-Za-z0-9_]+", term):
        return [match.start() for match in re.finditer(rf"\b{re.escape(term)}\b", text, re.IGNORECASE)]
    positions: list[int] = []
    start = 0
    while True:
        found = folded.find(needle, start)
        if found < 0:
            return positions
        positions.append(found)
        start = found + max(1, len(needle))


def terms_near(text: str, terms: Sequence[str], max_distance: int) -> bool:
    positions = [term_positions(text, term) for term in terms]
    if any(not values for values in positions):
        return False
    return any(max(choice) - min(choice) <= max_distance for choice in itertools.product(*positions))


def conditions_hold(rule: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    return all(facts[condition["fact"]] == condition["equals"] for condition in rule.get("conditions", []))


def drift_record(claim: Mapping[str, Any], document: Document, line_number: int, authorities: Mapping[str, str]) -> dict[str, Any]:
    return {
        "claimId": claim["claimId"],
        "code": claim["code"],
        "document": document.relative,
        "line": line_number,
        "authority": [authorities[fact_id] for fact_id in claim["authority"]],
    }


def scan_documents(config: Mapping[str, Any], facts: Mapping[str, Any], authorities: Mapping[str, str], documents: Sequence[Document]) -> list[dict[str, Any]]:
    drifts: list[dict[str, Any]] = []
    contradictory_locations: set[tuple[str, int]] = set()

    for claim in config["claims"]:
        if claim["detector"] != "contradictory_connected" or not conditions_hold(claim, facts):
            continue
        for document in documents:
            for index, line in enumerate(document.lines):
                if any_term(line, claim["matchAny"]) and any_term(line, claim["contradictionAny"]) and not any_term(line, claim["negativeAny"]):
                    line_number = index + 1
                    contradictory_locations.add((document.relative, line_number))
                    drifts.append(drift_record(claim, document, line_number, authorities))

    for claim in config["claims"]:
        detector = claim["detector"]
        if not conditions_hold(claim, facts):
            continue
        for document in documents:
            for index, line in enumerate(document.lines):
                line_number = index + 1
                if detector == "contradictory_connected":
                    continue
                elif detector == "connected_status":
                    if (document.relative, line_number) in contradictory_locations:
                        continue
                    if not any_term(line, claim["matchAny"]):
                        continue
                    if any_term(line, claim["negativeAny"]):
                        continue
                    block = document.fence_by_line[index]
                    if block is not None and all_terms(block, claim["fixtureScopeAll"]):
                        continue
                    drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "catalog_as_capability":
                    if (
                        terms_near(line, claim["matchAll"], claim["maxDistance"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["allowAny"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "fixed_surface":
                    if any_term(line, claim["surfaceAny"]) and any_term(line, claim["assertionAny"]) and not any_term(line, claim["negativeAny"]):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "irreversible_lifecycle":
                    if (
                        any_term(line, claim["matchAny"])
                        and any_term(line, claim["irreversibleAny"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["negativeAny"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "model_visible_durable":
                    if (
                        any_term(line, claim["matchAny"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["negativeAny"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "non_native_evidence":
                    if any_term(line, claim["qualifierAny"]) and any_term(line, claim["assertionAny"]) and not any_term(line, claim["allowAny"]):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "parallel_registry":
                    if any_term(line, claim["matchAny"]) and any_term(line, claim["assertionAny"]) and not any_term(line, claim["negativeAny"]):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "plugin_components":
                    if (
                        any_term(line, claim["matchAny"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["allowAny"])
                        and not all(any_term(line, group) for group in claim["requiredGroups"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "plugin_completion":
                    if any_term(line, claim["matchAny"]) and any_term(line, claim["assertionAny"]) and not any_term(line, claim["negativeAny"]):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "plugin_lifecycle":
                    if (
                        any_term(line, claim["matchAny"])
                        and any_term(line, claim["lifecycleAny"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["negativeAny"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "provider_only":
                    if any_term(line, claim["matchAny"]) and any_term(line, claim["assertionAny"]) and not any_term(line, claim["negativeAny"]):
                        drifts.append(drift_record(claim, document, line_number, authorities))
                elif detector == "ui_card_as_capability":
                    if (
                        terms_near(line, claim["matchAll"], claim["maxDistance"])
                        and any_term(line, claim["assertionAny"])
                        and not any_term(line, claim["allowAny"])
                    ):
                        drifts.append(drift_record(claim, document, line_number, authorities))
    unique: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for drift in drifts:
        key = (drift["claimId"], drift["code"], drift["document"], drift["line"])
        unique[key] = drift
    return [unique[key] for key in sorted(unique)]


def verify(root: Path, config_path: Path, *, documents: Sequence[Document] | None = None) -> dict[str, Any]:
    config = validate_config(load_json(config_path))
    facts, authorities = evaluate_facts(root, config)
    docs = list(documents) if documents is not None else read_documents(root, config)
    drifts = scan_documents(config, facts, authorities, docs)
    status = "DRIFT" if drifts else "VERIFIED"
    exit_code = config["exitCodes"]["drift" if drifts else "verified"]
    return {
        "schema": SCHEMA,
        "checker": CHECKER,
        "status": status,
        "exitCode": exit_code,
        "testMode": False,
        "facts": {key: facts[key] for key in sorted(facts)},
        "summary": {
            "documents": len(docs),
            "lines": sum(len(document.lines) for document in docs),
            "claims": len(config["claims"]),
            "drifts": len(drifts),
        },
        "drifts": drifts,
    }


def synthetic_documents(text: str) -> list[Document]:
    return [parse_document("self-test/synthetic.md", text)]


def self_test(root: Path, config_path: Path) -> dict[str, Any]:
    config = validate_config(load_json(config_path))
    baseline = verify(root, config_path)
    ensure(baseline["status"] == "VERIFIED", "SELF_TEST_BASELINE_DRIFT")
    facts, authorities = evaluate_facts(root, config)
    ensure(facts["capability_catalog_entries"] == 48, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["provider_adapter_registration_count"] == 0, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["provider_catalog_connected_count"] == 0, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["plugin_composition_kernel"] is True, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["plugin_reversible_lifecycle"] is True, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["desktop_plugin_runtime_wiring_count"] == 0, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["plugin_durable_audit_log"] is False, "SELF_TEST_CURRENT_FACT_DRIFT")
    ensure(facts["current_evidence_release_passed"] is False, "SELF_TEST_RELEASE_ESCALATION")
    ensure(facts["current_evidence_release_decision"] == "NOT_EVALUATED", "SELF_TEST_RELEASE_ESCALATION")
    ensure(facts["current_evidence_mission_evidence_level_promoted"] is False, "SELF_TEST_RELEASE_ESCALATION")

    accepted = [
        """```yaml\nfixture: self-test\nentryState:\n  website: connected\n```""",
        "No real Probe means do not show Connected.",
        "Plugin SDK target: design a reversible lifecycle; not implemented.",
        "BLOCKED_ENV remains not a native production proof.",
        "Model-visible item is not durable and remains not proven.",
        "A parallel tool registry is prohibited; only one registry exists.",
        "Provider-only capability is not executable; it is contract-only.",
        "The UI card is not a capability; it is only metadata.",
    ]
    for text in accepted:
        ensure(not scan_documents(config, facts, authorities, synthetic_documents(text)), "SELF_TEST_POSITIVE_FAILED")

    cases = [
        ("The capability catalog is executable and registered as a production capability.", {"CATALOG_AS_CAPABILITY"}),
        ("Provider status: connected", {"CONNECTED_WITH_EMPTY_REGISTRY"}),
        ("Provider registrations: 0; status: connected.", {"CONTRADICTORY_CLAIM"}),
        ("The fixed dashboard is the central cockpit for plugin configuration.", {"FIXED_DASHBOARD_OR_COCKPIT"}),
        ("Fixture native provider passed as production evidence.", {"NON_NATIVE_EVIDENCE_ESCALATED"}),
        ("An ignored test passed as native production proof.", {"NON_NATIVE_EVIDENCE_ESCALATED"}),
        ("BLOCKED_ENV implementation is production native and release-ready.", {"NON_NATIVE_EVIDENCE_ESCALATED"}),
        ("Plugins are implemented and support a reversible mount/unmount lifecycle.", {"PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE"}),
        ("Plugins are implemented with provider and consumer components.", {"PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE"}),
        ("Plugins are implemented with service and consumer components.", {"PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE"}),
        ("Plugins are implemented with service and provider components.", {"PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE"}),
        ("Plugin mount is implemented and cannot unmount.", {"PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE", "IRREVERSIBLE_PLUGIN_MOUNT"}),
        ("A second tool registry is implemented and available.", {"PARALLEL_TOOL_REGISTRY"}),
        ("Model-visible plugin item is production available.", {"MODEL_VISIBLE_WITHOUT_DURABLE_LOG", "PLUGIN_KERNEL_COMPLETION_UNPROVEN", "PLUGIN_COMPOSITION_INCOMPLETE"}),
        ("Provider-only capability is production available.", {"PROVIDER_ONLY_AS_CAPABILITY"}),
        ("The UI card advertises an available capability.", {"UI_CARD_AS_CAPABILITY"}),
    ]
    checked: list[str] = []
    for text, expected_codes in cases:
        result = scan_documents(config, facts, authorities, synthetic_documents(text))
        actual_codes = {drift["code"] for drift in result}
        ensure(expected_codes.issubset(actual_codes), "SELF_TEST_NEGATIVE_FAILED")
        checked.extend(sorted(expected_codes))

    duplicate = copy.deepcopy(config)
    duplicate["claims"].append(copy.deepcopy(duplicate["claims"][0]))
    try:
        validate_config(duplicate)
    except TruthError as error:
        ensure(error.code == "DUPLICATE_CLAIM_ID", "SELF_TEST_DUPLICATE_TAXONOMY")
    else:
        raise TruthError("SELF_TEST_DUPLICATE_NOT_REJECTED")

    missing = copy.deepcopy(config)
    missing["claims"] = missing["claims"][:-1]
    try:
        validate_config(missing)
    except TruthError as error:
        ensure(error.code == "MISSING_CLAIM", "SELF_TEST_MISSING_TAXONOMY")
    else:
        raise TruthError("SELF_TEST_MISSING_NOT_REJECTED")

    return {
        "schema": SCHEMA,
        "checker": CHECKER,
        "status": "SELF_TEST_VERIFIED",
        "exitCode": config["exitCodes"]["verified"],
        "testMode": True,
        "checks": sorted(set(checked + ["POSITIVE_FIXTURE_SCOPE", "DUPLICATE_CLAIM_ID", "MISSING_CLAIM"])),
    }


def error_result(config_path: Path, status: str, code: int, error: TruthError, *, test_mode: bool) -> dict[str, Any]:
    item: dict[str, Any] = {"code": error.code}
    if error.source:
        item["source"] = error.source
    return {
        "schema": SCHEMA,
        "checker": CHECKER,
        "status": status,
        "exitCode": code,
        "testMode": test_mode,
        "config": config_path.name,
        "errors": [item],
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("verify", "self-test"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse_args(raw_args)
    except SystemExit:
        result = {
            "schema": SCHEMA,
            "checker": CHECKER,
            "status": "USAGE",
            "exitCode": 64,
            "testMode": False,
            "errors": [{"code": "USAGE"}],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 64

    root = (args.root or Path(__file__).resolve().parents[1]).resolve()
    config_path = args.claims.resolve()
    try:
        if args.mode == "self-test":
            result = self_test(root, config_path)
        else:
            result = verify(root, config_path)
    except TruthError as error:
        result = error_result(
            config_path,
            "SELF_TEST_FAILED" if args.mode == "self-test" else "INVALID_INPUT",
            30 if args.mode == "self-test" else 20,
            error,
            test_mode=args.mode == "self-test",
        )
    except Exception as error:  # pragma: no cover - defensive CLI boundary
        del error
        result = error_result(
            config_path,
            "CHECKER_ERROR",
            30,
            TruthError("UNEXPECTED_CHECKER_ERROR"),
            test_mode=args.mode == "self-test",
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return int(result["exitCode"])


if __name__ == "__main__":
    raise SystemExit(main())
