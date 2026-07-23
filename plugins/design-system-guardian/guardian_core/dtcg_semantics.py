"""Normative semantic sub-value types for DTCG 2025.10 composites."""

from __future__ import annotations

import re


_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def semantic_type_at_subpath(token_type: str, segments: list[str]) -> str | None:
    """Return the DTCG type carried by a composite property path, if one exists."""

    if not segments:
        return token_type if not token_type.startswith("_") else None
    head, tail = segments[0], segments[1:]
    if token_type == "shadow":
        if _ARRAY_INDEX.fullmatch(head):
            return semantic_type_at_subpath("_shadowObject", tail)
        return semantic_type_at_subpath("_shadowObject", segments)
    if token_type == "gradient":
        if _ARRAY_INDEX.fullmatch(head):
            return semantic_type_at_subpath("_gradientStop", tail)
        return None
    mappings: dict[str, dict[str, str | None]] = {
        "color": {
            "colorSpace": None,
            "components": "_colorComponents",
            "alpha": "number",
            "hex": None,
        },
        "dimension": {"value": "number", "unit": None},
        "duration": {"value": "number", "unit": None},
        "strokeStyle": {"dashArray": "_dimensionArray", "lineCap": None},
        "border": {"color": "color", "width": "dimension", "style": "strokeStyle"},
        "transition": {
            "duration": "duration",
            "delay": "duration",
            "timingFunction": "cubicBezier",
        },
        "typography": {
            "fontFamily": "fontFamily",
            "fontSize": "dimension",
            "fontWeight": "fontWeight",
            "letterSpacing": "dimension",
            "lineHeight": "number",
        },
        "_shadowObject": {
            "color": "color",
            "offsetX": "dimension",
            "offsetY": "dimension",
            "blur": "dimension",
            "spread": "dimension",
            "inset": None,
        },
        "_gradientStop": {"color": "color", "position": "number"},
    }
    if token_type in {"cubicBezier", "_colorComponents"}:
        next_type = "number" if _ARRAY_INDEX.fullmatch(head) else None
    elif token_type == "_dimensionArray":
        next_type = "dimension" if _ARRAY_INDEX.fullmatch(head) else None
    else:
        next_type = mappings.get(token_type, {}).get(head)
    if next_type is None:
        return None
    return semantic_type_at_subpath(next_type, tail)
