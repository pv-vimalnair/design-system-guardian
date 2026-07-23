"""Deterministic inline materialization for DTCG Resolver 2025.10."""

from __future__ import annotations

import copy
from typing import Any

from .dtcg import (
    DtcgValidationError,
    _lookup_pointer,
    resolve_token_document,
    validate_resolver_document,
)


def _is_token_declaration(value: Any) -> bool:
    return isinstance(value, dict) and ("$value" in value or "$ref" in value)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        existing = result.get(key)
        if _is_token_declaration(value) or _is_token_declaration(existing):
            result[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(existing, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _effective_reference(
    resolver_document: dict[str, Any],
    reference_object: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    reference = reference_object.get("$ref")
    if not isinstance(reference, str):
        raise DtcgValidationError("Resolver reference must be a string.")
    if not reference.startswith("#"):
        raise DtcgValidationError(
            f"Resolver external source {reference!r} was not materialized; source is incomplete."
        )
    target, segments = _lookup_pointer(resolver_document, reference)
    if not isinstance(target, dict):
        raise DtcgValidationError(f"Resolver reference target is not an object: {reference!r}.")
    effective = copy.deepcopy(target)
    for key, value in reference_object.items():
        if key != "$ref":
            # Resolver reference siblings are shallow overrides by specification.
            effective[key] = copy.deepcopy(value)
    return effective, segments


def materialize_resolver_tokens(
    base_document: dict[str, Any],
    resolver_document: dict[str, Any],
    inputs: dict[str, str] | None,
) -> dict[str, Any]:
    """Apply ordered, fully inlined resolver sources for one explicit context permutation."""

    if not isinstance(base_document, dict):
        raise DtcgValidationError("Base token document must be an object.")
    evidence = validate_resolver_document(resolver_document, inputs)
    selected = evidence["contexts"]
    merged: dict[str, Any] = copy.deepcopy(base_document)

    def expand_reference_source(
        source: dict[str, Any],
        stack: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        reference = source.get("$ref")
        if not isinstance(reference, str):
            raise DtcgValidationError("Resolver source reference must be a string.")
        if reference in stack:
            raise DtcgValidationError(
                f"Circular resolver source reference: {' -> '.join((*stack, reference))}."
            )
        effective, segments = _effective_reference(resolver_document, source)
        if segments and segments[0] == "modifiers":
            raise DtcgValidationError("Resolver sets and modifiers cannot reference modifiers.")
        if segments and segments[0] == "resolutionOrder":
            raise DtcgValidationError("Resolver references cannot target resolutionOrder.")
        if len(segments) == 2 and segments[0] == "sets":
            sources = effective.get("sources")
            if not isinstance(sources, list):
                raise DtcgValidationError(f"Resolver set reference has no sources: {reference!r}.")
            return expand_sources(sources, (*stack, reference))
        if "$ref" in effective:
            return expand_reference_source(effective, (*stack, reference))
        return [effective]

    def expand_sources(
        sources: list[dict[str, Any]],
        stack: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []
        for source in sources:
            if "$ref" in source:
                expanded.extend(expand_reference_source(source, stack))
            else:
                expanded.append(copy.deepcopy(source))
        return expanded

    def sources_for_order_item(item: dict[str, Any]) -> list[dict[str, Any]]:
        if "$ref" in item:
            effective, segments = _effective_reference(resolver_document, item)
            if len(segments) != 2 or segments[0] not in {"sets", "modifiers"}:
                raise DtcgValidationError(f"Unsupported resolver reference target: {item['$ref']!r}.")
            kind, name = segments
            if kind == "sets":
                return expand_sources(effective["sources"], (item["$ref"],))
            context = selected.get(name)
            if context is None:
                raise DtcgValidationError(f"No explicit context was resolved for modifier {name!r}.")
            return expand_sources(effective["contexts"][context], (item["$ref"],))
        item_type = item["type"]
        if item_type == "set":
            return expand_sources(item["sources"], ())
        name = item["name"]
        context = selected.get(name)
        if context is None:
            raise DtcgValidationError(f"No explicit context was resolved for inline modifier {name!r}.")
        return expand_sources(item["contexts"][context], ())

    for item in resolver_document["resolutionOrder"]:
        for source in sources_for_order_item(item):
            merged = _deep_merge(merged, source)
    return {"tokens": resolve_token_document(merged), "evidence": evidence}
