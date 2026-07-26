"""Strict, preview-only validation for local design-system usage rules.

This module deliberately has no Guardian-home dependency.  It parses explicit
inputs, produces a non-authoritative report, and never writes state.
"""

from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import (
    DuplicateJsonKeyError,
    canonical_json_bytes,
    decode_json_bytes,
    sha256_digest,
)


MAX_RULE_INPUT_BYTES = 1024 * 1024

RULE_CLASSES = frozenset({"machine", "judgment", "informative"})
SOURCE_TYPES = frozenset({"artifact", "figma_description"})
TARGET_KINDS = frozenset({"system", "category", "component", "icon", "token"})
SCOPES = frozenset({"widget_class", "compilation_unit"})
RELATIONS = frozenset({"sibling", "child", "descendant"})
PREDICATE_TYPES = frozenset(
    {
        "max_instances_per_scope",
        "forbidden_nesting",
        "required_companion",
        "allowed_parents",
        "variant_context",
        "forbidden_identity_in_scope",
    }
)
REPORT_REASON_CODES = frozenset(
    {
        "ok",
        "unmarked_text_ignored",
        "parse_failure",
        "unknown_predicate",
        "invalid_value",
        "duplicate_rule_id",
        "unknown_identity",
        "identity_not_assessed",
        "statement_missing",
        "statement_forbidden",
        "predicate_forbidden",
        "unknown_field",
        "input_too_large",
        "input_unavailable",
        "invalid_container",
        "duplicate_json_key",
        "missing_metadata",
        "invalid_json",
        "invalid_utf8",
        "invalid_identity_coverage",
        "invalid_source_type",
        "no_rule_markers",
    }
)

_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MARKER_HEADER_RE = re.compile(
    r"^\[dsg-rule id=([a-z][a-z0-9]*(?:[._-][a-z0-9]+)*) "
    r"class=(machine|judgment|informative)\]$"
)
_MARKER_CLOSE = "[/dsg-rule]"
_ROOT_FIELDS = frozenset(
    {"schemaVersion", "ruleId", "class", "predicate", "statement", "appliesTo", "provenance"}
)

_PREDICATE_FIELDS: dict[str, frozenset[str]] = {
    "max_instances_per_scope": frozenset({"type", "identity", "scope", "max"}),
    "forbidden_nesting": frozenset({"type", "outerIdentity", "innerIdentity"}),
    "required_companion": frozenset(
        {"type", "identity", "companionIdentity", "relation"}
    ),
    "allowed_parents": frozenset({"type", "identity", "parents"}),
    "variant_context": frozenset(
        {"type", "identity", "variant", "allowedScopes"}
    ),
    "forbidden_identity_in_scope": frozenset({"type", "identity", "scope"}),
}


class RuleValidationError(ValueError):
    """A non-sensitive rule-input failure with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"Rule validation failed: {reason_code}.")


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_RULE_INPUT_BYTES + 1)
    except OSError as error:
        raise RuleValidationError("input_unavailable") from error
    if len(payload) > MAX_RULE_INPUT_BYTES:
        raise RuleValidationError("input_too_large")
    return payload


def _decode_strict_json(payload: bytes) -> Any:
    try:
        value = decode_json_bytes(payload)
        canonical_json_bytes(value)
        return value
    except DuplicateJsonKeyError as error:
        raise RuleValidationError("duplicate_json_key") from error
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise RuleValidationError("invalid_json") from error


def load_rule_artifact(path: Path) -> list[dict[str, Any]]:
    """Read a bounded JSON-array artifact without disclosing its path/content."""

    value = _decode_strict_json(_read_bounded(Path(path)))
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuleValidationError("invalid_container")
    return value


def load_known_identities(path: Path) -> frozenset[str]:
    """Read an untrusted preview-only identity coverage list."""

    value = _decode_strict_json(_read_bounded(Path(path)))
    if (
        not isinstance(value, list)
        or any(not _is_identity(item) for item in value)
        or len(set(value)) != len(value)
    ):
        raise RuleValidationError("invalid_identity_coverage")
    return frozenset(value)


def load_description(path: Path) -> str:
    """Read one bounded UTF-8 description without exposing its path on failure."""

    payload = _read_bounded(Path(path))
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuleValidationError("invalid_utf8") from error


def _parse_scalar(value: str) -> object:
    if value.isdecimal():
        return int(value)
    if "," in value:
        items = value.split(",")
        if any(not item for item in items):
            raise RuleValidationError("parse_failure")
        return items
    return value


def _parse_machine_body(body: list[str]) -> dict[str, object]:
    nonempty = [line.strip() for line in body if line.strip()]
    if len(nonempty) != 1 or ":" not in nonempty[0]:
        raise RuleValidationError("parse_failure")
    predicate_name, arguments = nonempty[0].split(":", 1)
    predicate_name = predicate_name.strip()
    if predicate_name not in PREDICATE_TYPES:
        return {"type": predicate_name}
    try:
        tokens = shlex.split(arguments.strip(), posix=True)
    except ValueError as error:
        raise RuleValidationError("parse_failure") from error
    predicate: dict[str, object] = {"type": predicate_name}
    for token in tokens:
        if "=" not in token:
            raise RuleValidationError("parse_failure")
        key, value = token.split("=", 1)
        if not key or not value or key in predicate:
            raise RuleValidationError("parse_failure")
        predicate[key] = _parse_scalar(value)
    return predicate


def _parse_statement_body(body: list[str]) -> str:
    nonempty = [line.strip() for line in body if line.strip()]
    if not nonempty:
        raise RuleValidationError("statement_missing")
    if nonempty[0].startswith("statement:"):
        nonempty[0] = nonempty[0][len("statement:") :].strip()
    statement = "\n".join(nonempty).strip()
    if not statement:
        raise RuleValidationError("statement_missing")
    return statement


def parse_description_markers(
    text: str,
    *,
    host_kind: str,
    host_identity: str | None,
    figma: Mapping[str, object],
) -> list[dict[str, Any]]:
    """Parse exact marker blocks; ordinary prose becomes one warning only."""

    lines = text.splitlines()
    candidates: list[dict[str, Any]] = []
    ignored_context = False
    found_marker = False
    in_code_fence = False
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith("```"):
            ignored_context = True
            in_code_fence = not in_code_fence
            index += 1
            continue
        if in_code_fence:
            if line:
                ignored_context = True
            index += 1
            continue

        header = _MARKER_HEADER_RE.fullmatch(line)
        if header is None:
            if line.startswith("[dsg-rule") or line.startswith("[/dsg-rule"):
                candidates.append(
                    {"parseError": {"ruleId": None, "ruleClass": None, "reasonCode": "parse_failure"}}
                )
            elif line:
                ignored_context = True
            index += 1
            continue

        found_marker = True
        rule_id, rule_class = header.groups()
        body: list[str] = []
        cursor = index + 1
        depth = 1
        structural_error = False
        while cursor < len(lines):
            current = lines[cursor].strip()
            if _MARKER_HEADER_RE.fullmatch(current):
                structural_error = True
                depth += 1
            elif current == _MARKER_CLOSE:
                depth -= 1
                if depth == 0:
                    break
            elif current.startswith("[dsg-rule") or current.startswith("[/dsg-rule"):
                structural_error = True
            if depth == 1 and not structural_error:
                body.append(lines[cursor])
            cursor += 1

        if depth != 0 or structural_error:
            candidates.append(
                {
                    "parseError": {
                        "ruleId": rule_id,
                        "ruleClass": rule_class,
                        "reasonCode": "parse_failure",
                    }
                }
            )
            if depth != 0:
                break
            index = cursor + 1
            continue

        applies_to: dict[str, object] = {"kind": host_kind}
        if isinstance(host_kind, str) and host_kind in {"component", "icon", "token"}:
            applies_to["identity"] = host_identity
        elif host_kind == "category":
            applies_to["category"] = host_identity

        rule: dict[str, Any] = {
            "schemaVersion": 1,
            "ruleId": rule_id,
            "class": rule_class,
            "appliesTo": applies_to,
            "provenance": {
                "origin": "figma_description",
                "figma": dict(figma),
                "docRef": None,
            },
        }
        try:
            if rule_class == "machine":
                rule["predicate"] = _parse_machine_body(body)
            else:
                rule["statement"] = _parse_statement_body(body)
        except RuleValidationError as error:
            candidates.append(
                {
                    "parseError": {
                        "ruleId": rule_id,
                        "ruleClass": rule_class,
                        "reasonCode": error.reason_code,
                    }
                }
            )
        else:
            candidates.append(rule)
        index = cursor + 1

    if ignored_context:
        candidates.append(
            {"parseWarning": {"ruleId": None, "ruleClass": None, "reasonCode": "unmarked_text_ignored"}}
        )
    if not found_marker:
        candidates.append(
            {"parseError": {"ruleId": None, "ruleClass": None, "reasonCode": "no_rule_markers"}}
        )
    return candidates

def _is_bounded_string(value: object, max_length: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= max_length and bool(value.strip())


def _is_nonempty_string(value: object) -> bool:
    return _is_bounded_string(value, 4096)


def _is_identity(value: object) -> bool:
    return _is_bounded_string(value, 256)


def _valid_string_list(value: object, *, max_length: int = 4096) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(_is_bounded_string(item, max_length) for item in value)
        and len(set(value)) == len(value)
    )


def _validate_predicate(predicate: object) -> str | None:
    if not isinstance(predicate, dict):
        return "invalid_value"
    predicate_type = predicate.get("type")
    if not isinstance(predicate_type, str) or predicate_type not in PREDICATE_TYPES:
        return "unknown_predicate"
    expected = _PREDICATE_FIELDS[predicate_type]
    if set(predicate) != expected:
        return "unknown_field" if set(predicate) - expected else "invalid_value"

    if predicate_type == "max_instances_per_scope":
        if (
            not _is_identity(predicate["identity"])
            or not isinstance(predicate["scope"], str)
            or predicate["scope"] not in SCOPES
            or isinstance(predicate["max"], bool)
            or not isinstance(predicate["max"], int)
            or predicate["max"] < 0
        ):
            return "invalid_value"
    elif predicate_type == "forbidden_nesting":
        if not all(
            _is_identity(predicate[key])
            for key in ("outerIdentity", "innerIdentity")
        ):
            return "invalid_value"
    elif predicate_type == "required_companion":
        if (
            not _is_identity(predicate["identity"])
            or not _is_identity(predicate["companionIdentity"])
            or not isinstance(predicate["relation"], str)
            or predicate["relation"] not in RELATIONS
        ):
            return "invalid_value"
    elif predicate_type == "allowed_parents":
        if not _is_identity(predicate["identity"]) or not _valid_string_list(
            predicate["parents"], max_length=256
        ):
            return "invalid_value"
    elif predicate_type == "variant_context":
        if (
            not _is_identity(predicate["identity"])
            or not _is_nonempty_string(predicate["variant"])
            or not _valid_string_list(predicate["allowedScopes"])
            or any(scope not in SCOPES for scope in predicate["allowedScopes"])
        ):
            return "invalid_value"
    elif predicate_type == "forbidden_identity_in_scope":
        if (
            not _is_identity(predicate["identity"])
            or not isinstance(predicate["scope"], str)
            or predicate["scope"] not in SCOPES
        ):
            return "invalid_value"
    return None

def _validate_applies_to(value: object) -> str | None:
    if not isinstance(value, dict):
        return "invalid_value"
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in TARGET_KINDS:
        return "invalid_value"
    if kind == "system":
        expected = {"kind"}
    elif kind == "category":
        expected = {"kind", "category"}
        if not _is_nonempty_string(value.get("category")):
            return "invalid_value"
    else:
        expected = {"kind", "identity"}
        if not _is_identity(value.get("identity")):
            return "invalid_value"
    if set(value) != expected:
        return "unknown_field" if set(value) - expected else "invalid_value"
    return None


def _validate_figma(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"fileKey", "nodeId", "sourceVersion"}
        and all(_is_nonempty_string(value[key]) for key in value)
    )


def _validate_provenance(value: object) -> str | None:
    if not isinstance(value, dict):
        return "invalid_value"
    expected = {"origin", "figma", "docRef"}
    if set(value) != expected:
        return "unknown_field" if set(value) - expected else "invalid_value"
    origin = value.get("origin")
    if origin == "figma_description":
        if not _validate_figma(value.get("figma")) or value.get("docRef") is not None:
            return "invalid_value"
    elif origin == "team_artifact":
        if value.get("figma") is not None or not _is_nonempty_string(value.get("docRef")):
            return "invalid_value"
    else:
        return "invalid_value"
    return None


def _validate_rule(value: object) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(value, dict):
        return None, "invalid_value"
    unknown = set(value) - _ROOT_FIELDS
    if unknown:
        return None, "unknown_field"
    rule_class = value.get("class")
    required = {"schemaVersion", "ruleId", "class", "appliesTo", "provenance"}
    if rule_class == "machine":
        required.add("predicate")
        if "statement" in value:
            return None, "predicate_forbidden"
    elif isinstance(rule_class, str) and rule_class in {"judgment", "informative"}:
        required.add("statement")
        if "predicate" in value:
            return None, "predicate_forbidden"
    elif not isinstance(rule_class, str) or rule_class not in RULE_CLASSES:
        return None, "invalid_value"
    if set(value) != required:
        if set(value) - required:
            return None, "unknown_field"
        if isinstance(rule_class, str) and rule_class in {"judgment", "informative"} and "statement" not in value:
            return None, "statement_missing"
        return None, "invalid_value"
    if value.get("schemaVersion") != 1 or isinstance(value.get("schemaVersion"), bool):
        return None, "invalid_value"
    rule_id = value.get("ruleId")
    if (
        not isinstance(rule_id, str)
        or len(rule_id) > 127
        or _RULE_ID_RE.fullmatch(rule_id) is None
    ):
        return None, "invalid_value"
    applies_error = _validate_applies_to(value.get("appliesTo"))
    if applies_error:
        return None, applies_error
    provenance_error = _validate_provenance(value.get("provenance"))
    if provenance_error:
        return None, provenance_error
    if rule_class == "machine":
        predicate_error = _validate_predicate(value.get("predicate"))
        if predicate_error:
            return None, predicate_error
    elif not _is_nonempty_string(value.get("statement")):
        return None, "statement_missing"

    # Canonical round-trip creates a detached, JSON-only normalized value.
    normalized = decode_json_bytes(canonical_json_bytes(value))
    return normalized, None


def _referenced_identities(rule: Mapping[str, Any]) -> frozenset[str]:
    identities: set[str] = set()
    applies_to = rule["appliesTo"]
    if "identity" in applies_to:
        identities.add(applies_to["identity"])
    predicate = rule.get("predicate")
    if isinstance(predicate, dict):
        for key in ("identity", "outerIdentity", "innerIdentity", "companionIdentity"):
            value = predicate.get(key)
            if isinstance(value, str):
                identities.add(value)
        parents = predicate.get("parents")
        if isinstance(parents, list):
            identities.update(item for item in parents if isinstance(item, str))
    return frozenset(identities)


def _entry(
    rule_id: object,
    rule_class: object,
    tier: str,
    reason_code: str,
) -> dict[str, object]:
    safe_rule_id = (
        rule_id
        if isinstance(rule_id, str)
        and len(rule_id) <= 127
        and _RULE_ID_RE.fullmatch(rule_id) is not None
        else None
    )
    safe_rule_class = (
        rule_class
        if isinstance(rule_class, str) and rule_class in RULE_CLASSES
        else None
    )
    safe_tier = (
        tier
        if isinstance(tier, str) and tier in {"ok", "warning", "error", "not_assessed"}
        else "error"
    )
    safe_reason = (
        reason_code
        if isinstance(reason_code, str) and reason_code in REPORT_REASON_CODES
        else "invalid_value"
    )
    return {
        "ruleId": safe_rule_id,
        "ruleClass": safe_rule_class,
        "tier": safe_tier,
        "reasonCode": safe_reason,
    }

def invalid_report(source_type: str, reason_code: str) -> dict[str, object]:
    """Create a schema-shaped, non-sensitive invalid preview report."""

    return _build_report(
        source_type=(
            source_type
            if isinstance(source_type, str) and source_type in SOURCE_TYPES
            else "artifact"
        ),
        normalized_rules=[],
        entries=[_entry(None, None, "error", reason_code)],
        identity_coverage="not_assessed",
    )


def _build_report(
    *,
    source_type: str,
    normalized_rules: list[dict[str, Any]],
    entries: list[dict[str, object]],
    identity_coverage: str,
) -> dict[str, object]:
    ordered_rules = sorted(normalized_rules, key=lambda item: item["ruleId"])
    tier_order = {"error": 0, "not_assessed": 1, "warning": 2, "ok": 3}
    ordered_entries = sorted(
        entries,
        key=lambda item: (
            "" if item["ruleId"] is None else str(item["ruleId"]),
            "" if item["ruleClass"] is None else str(item["ruleClass"]),
            tier_order[str(item["tier"])],
            str(item["reasonCode"]),
        ),
    )
    counts = Counter(str(item["tier"]) for item in ordered_entries)
    if counts["error"]:
        status = "invalid"
    elif counts["not_assessed"]:
        status = "not_assessed"
    else:
        status = "allowed"
    return {
        "schemaVersion": 1,
        "status": status,
        "authority": "preview_only",
        "sourceType": source_type,
        "rulesDigest": sha256_digest(ordered_rules),
        "identityCoverage": identity_coverage,
        "summary": {
            "ok": counts["ok"],
            "warnings": counts["warning"],
            "errors": counts["error"],
            "notAssessed": counts["not_assessed"],
        },
        "entries": ordered_entries,
        "localChangesPerformed": False,
        "productionReady": False,
    }


def validate_rules(
    candidates: Iterable[dict[str, Any]],
    *,
    known_identities: frozenset[str] | None,
    source_type: str,
) -> dict[str, object]:
    """Validate and normalize candidates into one deterministic preview."""

    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES:
        raise RuleValidationError("invalid_source_type")
    if known_identities is not None and (
        not isinstance(known_identities, frozenset)
        or any(not _is_identity(identity) for identity in known_identities)
    ):
        raise RuleValidationError("invalid_identity_coverage")
    candidate_list = list(candidates)
    ids = [
        candidate.get("ruleId")
        for candidate in candidate_list
        if isinstance(candidate, dict) and isinstance(candidate.get("ruleId"), str)
    ]
    duplicate_ids = {rule_id for rule_id, count in Counter(ids).items() if count > 1}

    entries: list[dict[str, object]] = []
    normalized_rules: list[dict[str, Any]] = []
    if not candidate_list and known_identities is None:
        entries.append(_entry(None, None, "not_assessed", "identity_not_assessed"))
    for candidate in candidate_list:
        if (
            source_type == "figma_description"
            and isinstance(candidate, dict)
            and set(candidate) == {"parseWarning"}
        ):
            warning = candidate["parseWarning"]
            if isinstance(warning, dict):
                entries.append(
                    _entry(
                        warning.get("ruleId"),
                        warning.get("ruleClass"),
                        "warning",
                        str(warning.get("reasonCode", "parse_failure")),
                    )
                )
            else:
                entries.append(_entry(None, None, "error", "parse_failure"))
            continue
        if (
            source_type == "figma_description"
            and isinstance(candidate, dict)
            and set(candidate) == {"parseError"}
        ):
            error = candidate["parseError"]
            if isinstance(error, dict):
                entries.append(
                    _entry(
                        error.get("ruleId"),
                        error.get("ruleClass"),
                        "error",
                        str(error.get("reasonCode", "parse_failure")),
                    )
                )
            else:
                entries.append(_entry(None, None, "error", "parse_failure"))
            continue

        rule_id = candidate.get("ruleId") if isinstance(candidate, dict) else None
        rule_class = candidate.get("class") if isinstance(candidate, dict) else None
        if isinstance(rule_id, str) and rule_id in duplicate_ids:
            entries.append(_entry(rule_id, rule_class, "error", "duplicate_rule_id"))
            continue
        normalized, reason = _validate_rule(candidate)
        if reason is not None or normalized is None:
            entries.append(_entry(rule_id, rule_class, "error", reason or "invalid_value"))
            continue
        references = _referenced_identities(normalized)
        if known_identities is None:
            normalized_rules.append(normalized)
            entries.append(
                _entry(normalized["ruleId"], normalized["class"], "not_assessed", "identity_not_assessed")
            )
        elif references - known_identities:
            entries.append(
                _entry(normalized["ruleId"], normalized["class"], "error", "unknown_identity")
            )
        else:
            normalized_rules.append(normalized)
            entries.append(_entry(normalized["ruleId"], normalized["class"], "ok", "ok"))

    identity_coverage = "complete" if known_identities is not None else "not_assessed"
    report = _build_report(
        source_type=source_type,
        normalized_rules=normalized_rules,
        entries=entries,
        identity_coverage=identity_coverage,
    )
    return {
        "rules": sorted(normalized_rules, key=lambda item: item["ruleId"]),
        "report": report,
    }


__all__ = [
    "RuleValidationError",
    "invalid_report",
    "load_description",
    "load_known_identities",
    "load_rule_artifact",
    "parse_description_markers",
    "validate_rules",
]
