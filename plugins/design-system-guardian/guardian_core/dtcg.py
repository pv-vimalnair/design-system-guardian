"""Strict DTCG Format and Resolver 2025.10 validation."""

from __future__ import annotations

import copy
import math
import re
from typing import Any, Callable
from urllib.parse import unquote

from .dtcg_semantics import semantic_type_at_subpath


class DtcgValidationError(ValueError):
    """Raised when a token or resolver document is not strictly conforming."""


_TOKEN_KEYS = {"$value", "$ref", "$type", "$description", "$extensions", "$deprecated"}
_GROUP_KEYS = {"$type", "$description", "$extensions", "$deprecated", "$extends", "$ref"}
_FORMAT_SCHEMA_2025_10 = "https://www.designtokens.org/schemas/2025.10/format.json"
_ATOMIC_REFERENCE_TYPE = "atomic/untyped"
_KNOWN_TYPES = {
    "color",
    "dimension",
    "fontFamily",
    "fontWeight",
    "duration",
    "cubicBezier",
    "number",
    "strokeStyle",
    "border",
    "transition",
    "shadow",
    "gradient",
    "typography",
}
_CURLY_REFERENCE = re.compile(r"^\{([^{}]+)\}$")
_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_FONT_WEIGHTS = {
    "thin",
    "hairline",
    "extra-light",
    "ultra-light",
    "light",
    "normal",
    "regular",
    "book",
    "medium",
    "semi-bold",
    "demi-bold",
    "bold",
    "extra-bold",
    "ultra-bold",
    "black",
    "heavy",
    "extra-black",
    "ultra-black",
}
_STROKE_STYLES = {
    "solid",
    "dashed",
    "dotted",
    "double",
    "groove",
    "ridge",
    "outset",
    "inset",
}
_COLOR_SPACES = {
    "srgb",
    "srgb-linear",
    "hsl",
    "hwb",
    "lab",
    "lch",
    "oklab",
    "oklch",
    "display-p3",
    "a98-rgb",
    "prophoto-rgb",
    "rec2020",
    "xyz-d65",
    "xyz-d50",
}

ValuePath = tuple[str | int, ...]
ReferenceTypes = dict[ValuePath, str]


def _validate_name(name: str, *, root_token: bool = False) -> None:
    if not isinstance(name, str) or not name:
        raise DtcgValidationError("Token and group names must be non-empty strings.")
    if root_token and name == "$root":
        return
    if name.startswith("$") or any(character in name for character in ".{}"):
        raise DtcgValidationError(f"Invalid DTCG token or group name: {name!r}.")


def _validate_type(value: Any, path: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _KNOWN_TYPES:
        raise DtcgValidationError(f"Invalid or unsupported $type at {path}: {value!r}.")
    return value


def _validate_deprecated(value: Any, path: str) -> bool | str | None:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, str) and bool(value):
        return value
    raise DtcgValidationError(f"$deprecated at {path} must be a boolean or non-empty string.")


def _validate_metadata(
    node: dict[str, Any],
    path: str,
    *,
    token: bool,
    root: bool = False,
) -> None:
    allowed = _TOKEN_KEYS if token else _GROUP_KEYS
    if root:
        allowed = allowed | {"$schema"}
    for key in node:
        if key.startswith("$") and key not in allowed and not (not token and key == "$root"):
            raise DtcgValidationError(f"Unknown reserved property {key!r} at {path}.")
    if "$schema" in node and node["$schema"] != _FORMAT_SCHEMA_2025_10:
        raise DtcgValidationError(
            f"$schema at {path} must be exactly {_FORMAT_SCHEMA_2025_10!r}."
        )
    if "$description" in node and not isinstance(node["$description"], str):
        raise DtcgValidationError(f"$description at {path} must be a string.")
    if "$extensions" in node and not isinstance(node["$extensions"], dict):
        raise DtcgValidationError(f"$extensions at {path} must be an object.")
    _validate_type(node.get("$type"), path)
    _validate_deprecated(node.get("$deprecated"), path)


def _decode_pointer(pointer: str) -> list[str]:
    """Decode an RFC 6901 URI-fragment JSON Pointer."""

    if not isinstance(pointer, str) or not pointer.startswith("#"):
        raise DtcgValidationError("Internal JSON Pointer references must start with '#'.")
    fragment = pointer[1:]
    if fragment == "":
        return []
    if not fragment.startswith("/"):
        raise DtcgValidationError("Internal JSON Pointer references must start with '#/'.")
    for index, character in enumerate(fragment):
        if character == "%" and (
            index + 2 >= len(fragment)
            or any(item not in "0123456789abcdefABCDEF" for item in fragment[index + 1:index + 3])
        ):
            raise DtcgValidationError(f"Invalid percent escape in JSON Pointer: {pointer!r}.")
    try:
        decoded = unquote(fragment, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DtcgValidationError(f"Invalid UTF-8 escape in JSON Pointer: {pointer!r}.") from error
    segments: list[str] = []
    for raw_segment in decoded[1:].split("/"):
        position = 0
        while position < len(raw_segment):
            if raw_segment[position] == "~":
                if position + 1 >= len(raw_segment) or raw_segment[position + 1] not in "01":
                    raise DtcgValidationError(f"Invalid '~' escape in JSON Pointer: {pointer!r}.")
                position += 2
            else:
                position += 1
        segments.append(raw_segment.replace("~1", "/").replace("~0", "~"))
    return segments


def _lookup_pointer(document: Any, pointer: str) -> tuple[Any, list[str]]:
    segments = _decode_pointer(pointer)
    current: Any = document
    for segment in segments:
        if isinstance(current, dict):
            if segment not in current:
                raise DtcgValidationError(f"Unresolved JSON Pointer reference: {pointer!r}.")
            current = current[segment]
            continue
        if isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", segment):
                raise DtcgValidationError(
                    f"Invalid array index {segment!r} in JSON Pointer reference: {pointer!r}."
                )
            index = int(segment)
            if index >= len(current):
                raise DtcgValidationError(f"Unresolved JSON Pointer reference: {pointer!r}.")
            current = current[index]
            continue
        raise DtcgValidationError(f"Unresolved JSON Pointer reference: {pointer!r}.")
    return current, segments


def _encode_pointer(segments: list[str] | tuple[str, ...]) -> str:
    return "#/" + "/".join(segment.replace("~", "~0").replace("/", "~1") for segment in segments)


def _reference_path(reference: str) -> list[str]:
    match = _CURLY_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
    if match is None:
        raise DtcgValidationError(f"Invalid curly reference: {reference!r}.")
    path = match.group(1).split(".")
    if not path or any(not segment for segment in path):
        raise DtcgValidationError(f"Invalid curly reference: {reference!r}.")
    return path


def _group_target(document: dict[str, Any], reference: str) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(reference, str) and reference.startswith("#"):
        value, segments = _lookup_pointer(document, reference)
    else:
        segments = _reference_path(reference)
        value = document
        for segment in segments:
            if not isinstance(value, dict) or segment not in value:
                raise DtcgValidationError(f"Unresolved group extension: {reference!r}.")
            value = value[segment]
    if not isinstance(value, dict) or _node_is_token(document, value):
        raise DtcgValidationError(f"$extends must reference a group: {reference!r}.")
    return value, tuple(segments)


def _node_is_token(
    document: dict[str, Any],
    node: dict[str, Any],
    reference_stack: tuple[str, ...] = (),
) -> bool:
    """Classify a DTCG node without confusing normative group `$ref` with a token."""

    if "$value" in node:
        return True
    reference = node.get("$ref")
    if reference is None:
        return False
    if any(not key.startswith("$") for key in node):
        return False
    if not isinstance(reference, str) or not reference.startswith("#"):
        return True
    if reference in reference_stack:
        raise DtcgValidationError(
            f"Circular JSON Pointer reference: {' -> '.join((*reference_stack, reference))}."
        )
    target, segments = _lookup_pointer(document, reference)
    if "$value" in segments or not isinstance(target, dict):
        return True
    return _node_is_token(document, target, (*reference_stack, reference))


def _deep_merge(
    document: dict[str, Any],
    base: dict[str, Any],
    local: dict[str, Any],
) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in local.items():
        if key in {"$extends", "$ref"}:
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            if _node_is_token(document, value) or _node_is_token(document, merged[key]):
                merged[key] = copy.deepcopy(value)
            else:
                merged[key] = _deep_merge(document, merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _expand_group(
    document: dict[str, Any],
    group: dict[str, Any],
    group_path: tuple[str, ...],
    stack: tuple[tuple[str, ...], ...],
) -> dict[str, Any]:
    if group_path in stack:
        chain = " -> ".join(".".join(path) for path in (*stack, group_path))
        raise DtcgValidationError(f"Circular $extends reference: {chain}.")
    if "$extends" in group and "$ref" in group:
        raise DtcgValidationError(
            f"Group at {'.'.join(group_path)} cannot contain both $extends and $ref."
        )
    reference = group.get("$extends", group.get("$ref"))
    if reference is None:
        return copy.deepcopy(group)
    if not isinstance(reference, str):
        raise DtcgValidationError(f"$extends at {'.'.join(group_path)} must be a reference string.")
    target, target_path = _group_target(document, reference)
    expanded_target = _expand_group(document, target, target_path, (*stack, group_path))
    inherited_type = expanded_target.get("$type")
    local_type = group.get("$type")
    if inherited_type is not None and local_type is not None and inherited_type != local_type:
        raise DtcgValidationError(
            f"$extends type constraint mismatch at {'.'.join(group_path)}: "
            f"{inherited_type!r} versus {local_type!r}."
        )
    return _deep_merge(document, expanded_target, group)


def _pointer_token_identity(
    document: dict[str, Any],
    pointer: str,
    *,
    required: bool = True,
) -> str | None:
    value, segments = _lookup_pointer(document, pointer)
    token_segments = list(segments)
    if token_segments and token_segments[-1] == "$value":
        token_segments.pop()
        value, _ = _lookup_pointer(document, _encode_pointer(token_segments))
    if isinstance(value, dict) and ("$value" in value or "$ref" in value):
        if not token_segments or any(not isinstance(segment, str) for segment in token_segments):
            raise DtcgValidationError(f"JSON Pointer does not identify a named token: {pointer!r}.")
        return ".".join(token_segments)
    if required:
        raise DtcgValidationError(f"JSON Pointer does not identify a token or token $value: {pointer!r}.")
    return None


def _whole_alias_identity(document: dict[str, Any], token: dict[str, Any]) -> str | None:
    if "$ref" in token:
        if "$value" in token:
            raise DtcgValidationError("A token cannot contain both $value and $ref.")
        if not isinstance(token["$ref"], str):
            raise DtcgValidationError("A token $ref must be a JSON Pointer string.")
        return _pointer_token_identity(document, token["$ref"], required=False)
    value = token.get("$value")
    if isinstance(value, str):
        match = _CURLY_REFERENCE.fullmatch(value)
        return match.group(1) if match else None
    if isinstance(value, dict) and set(value) == {"$ref"}:
        if not isinstance(value["$ref"], str):
            raise DtcgValidationError("A property-level $ref must be a JSON Pointer string.")
        return _pointer_token_identity(document, value["$ref"], required=False)
    return None


def _flatten(
    document: dict[str, Any],
    group: dict[str, Any],
    path: tuple[str, ...],
    inherited_type: str | None,
    inherited_deprecated: bool | str | None,
    definitions: dict[str, dict[str, Any]],
) -> None:
    expanded = (
        _expand_group(document, group, path, ())
        if "$extends" in group or "$ref" in group and not _node_is_token(document, group)
        else group
    )
    _validate_metadata(
        expanded,
        ".".join(path) or "<root>",
        token=False,
        root=not path,
    )
    group_type = _validate_type(expanded.get("$type"), ".".join(path)) or inherited_type
    group_deprecated = (
        _validate_deprecated(expanded.get("$deprecated"), ".".join(path))
        if "$deprecated" in expanded
        else inherited_deprecated
    )
    for name, node in expanded.items():
        if name.startswith("$") and name != "$root":
            continue
        _validate_name(name, root_token=name == "$root")
        item_path = (*path, name)
        identity = ".".join(item_path)
        if not isinstance(node, dict):
            raise DtcgValidationError(f"Token or group {identity!r} must be an object.")
        is_token = _node_is_token(document, node)
        if is_token:
            _validate_metadata(node, identity, token=True)
            non_properties = [key for key in node if not key.startswith("$")]
            if non_properties:
                raise DtcgValidationError(
                    f"Token {identity!r} cannot also contain child tokens or groups: {non_properties!r}."
                )
            if "$value" in node and "$ref" in node:
                raise DtcgValidationError(f"Token {identity!r} cannot contain both $value and $ref.")
            alias = _whole_alias_identity(document, node)
            definitions[identity] = {
                "identity": identity,
                "rawValue": (
                    node.get("$value")
                    if "$value" in node
                    else {"$ref": node["$ref"]} if alias is None else None
                ),
                "declaredType": _validate_type(node.get("$type"), identity),
                "inheritedType": group_type,
                "alias": alias,
                "deprecatedValue": (
                    _validate_deprecated(node.get("$deprecated"), identity)
                    if "$deprecated" in node
                    else group_deprecated
                ),
                "description": node.get("$description"),
                "extensions": copy.deepcopy(node.get("$extensions", {})),
                "sourcePath": _encode_pointer(list(item_path)),
            }
        else:
            _flatten(document, node, item_path, group_type, group_deprecated, definitions)


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _expect_object(
    value: Any,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    identity: str,
    token_type: str,
    path: ValuePath,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DtcgValidationError(
            f"Value at {_display_value_path(identity, path)} must be an object for {token_type!r}."
        )
    missing = required - set(value)
    unknown = set(value) - required - set(optional)
    if missing or unknown:
        raise DtcgValidationError(
            f"Value at {_display_value_path(identity, path)} has invalid {token_type!r} members; "
            f"missing={sorted(missing)!r}, unknown={sorted(unknown)!r}."
        )
    return value


def _display_value_path(identity: str, path: ValuePath) -> str:
    suffix = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in path)
    return f"{identity}{suffix}"


def _expect_reference_type(
    references: ReferenceTypes,
    path: ValuePath,
    expected: str,
    identity: str,
) -> None:
    actual = references.get(path)
    if actual is not None and actual != expected:
        raise DtcgValidationError(
            f"Nested reference type mismatch at {_display_value_path(identity, path)}: "
            f"expected {expected!r}, got {actual!r}."
        )


def _expect_atomic_literal(
    references: ReferenceTypes,
    path: ValuePath,
    identity: str,
) -> None:
    actual = references.get(path)
    if actual is not None and actual != _ATOMIC_REFERENCE_TYPE:
        raise DtcgValidationError(
            f"Nested reference type mismatch at {_display_value_path(identity, path)}: "
            f"expected an atomic literal, got {actual!r}."
        )


def _validate_number(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "number", identity)
    if not _is_number(value):
        raise DtcgValidationError(f"Value at {_display_value_path(identity, path)} must be a number.")


def _validate_dimension(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "dimension", identity)
    item = _expect_object(
        value,
        required={"value", "unit"},
        identity=identity,
        token_type="dimension",
        path=path,
    )
    _validate_number(item["value"], identity, references, (*path, "value"))
    unit_path = (*path, "unit")
    _expect_atomic_literal(references, unit_path, identity)
    if item["unit"] not in {"px", "rem"}:
        raise DtcgValidationError(
            f"Dimension unit at {_display_value_path(identity, (*path, 'unit'))} must be 'px' or 'rem'."
        )


def _validate_duration(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "duration", identity)
    item = _expect_object(
        value,
        required={"value", "unit"},
        identity=identity,
        token_type="duration",
        path=path,
    )
    _validate_number(item["value"], identity, references, (*path, "value"))
    unit_path = (*path, "unit")
    _expect_atomic_literal(references, unit_path, identity)
    if item["unit"] not in {"ms", "s"}:
        raise DtcgValidationError(
            f"Duration unit at {_display_value_path(identity, (*path, 'unit'))} must be 'ms' or 's'."
        )


def _component_in_range(value: Any, low: float | None, high: float | None, *, high_open: bool = False) -> bool:
    if value == "none":
        return True
    if not _is_number(value):
        return False
    if low is not None and value < low:
        return False
    if high is not None and (value >= high if high_open else value > high):
        return False
    return True


def _validate_color(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "color", identity)
    item = _expect_object(
        value,
        required={"colorSpace", "components"},
        optional={"alpha", "hex"},
        identity=identity,
        token_type="color",
        path=path,
    )
    _expect_atomic_literal(references, (*path, "colorSpace"), identity)
    color_space = item["colorSpace"]
    components = item["components"]
    if color_space not in _COLOR_SPACES:
        raise DtcgValidationError(f"Unsupported color space at {_display_value_path(identity, path)}.")
    if not isinstance(components, list) or len(components) != 3:
        raise DtcgValidationError(
            f"Color components at {_display_value_path(identity, (*path, 'components'))} must contain 3 items."
        )
    zero_one = lambda component: _component_in_range(component, 0, 1)
    percentage = lambda component: _component_in_range(component, 0, 100)
    hue = lambda component: _component_in_range(component, 0, 360, high_open=True)
    unbounded = lambda component: component == "none" or _is_number(component)
    chroma = lambda component: _component_in_range(component, 0, None)
    if color_space in {
        "srgb", "srgb-linear", "display-p3", "a98-rgb", "prophoto-rgb",
        "rec2020", "xyz-d65", "xyz-d50",
    }:
        validators = (zero_one, zero_one, zero_one)
    elif color_space in {"hsl", "hwb"}:
        validators = (hue, percentage, percentage)
    elif color_space == "lab":
        validators = (percentage, unbounded, unbounded)
    elif color_space == "lch":
        validators = (percentage, chroma, hue)
    elif color_space == "oklab":
        validators = (zero_one, unbounded, unbounded)
    else:
        validators = (zero_one, chroma, hue)
    for index, (component, validator) in enumerate(zip(components, validators)):
        component_path = (*path, "components", index)
        if references.get(component_path) is not None:
            _expect_reference_type(references, component_path, "number", identity)
        if not validator(component):
            raise DtcgValidationError(
                f"Invalid {color_space!r} component at {_display_value_path(identity, component_path)}."
            )
    if "alpha" in item:
        alpha_path = (*path, "alpha")
        _expect_reference_type(references, alpha_path, "number", identity)
        if not _is_number(item["alpha"]) or not 0 <= item["alpha"] <= 1:
            raise DtcgValidationError(f"Color alpha at {_display_value_path(identity, alpha_path)} must be in [0, 1].")
    if "hex" in item:
        _expect_atomic_literal(references, (*path, "hex"), identity)
    if "hex" in item and (not isinstance(item["hex"], str) or not _HEX_COLOR.fullmatch(item["hex"])):
        raise DtcgValidationError(f"Color hex at {_display_value_path(identity, (*path, 'hex'))} is invalid.")


def _validate_font_family(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "fontFamily", identity)
    if isinstance(value, str) and value:
        return
    if isinstance(value, list) and value:
        for index, family in enumerate(value):
            family_path = (*path, index)
            _expect_reference_type(references, family_path, "fontFamily", identity)
            if not isinstance(family, str) or not family:
                break
        else:
            return
    raise DtcgValidationError(f"Font family value for {identity!r} is invalid.")


def _validate_font_weight(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "fontWeight", identity)
    if _is_number(value) and 1 <= value <= 1000:
        return
    if isinstance(value, str) and value in _FONT_WEIGHTS:
        return
    raise DtcgValidationError(f"Font weight value for {identity!r} is invalid.")


def _validate_cubic_bezier(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "cubicBezier", identity)
    if not isinstance(value, list) or len(value) != 4:
        raise DtcgValidationError(f"Cubic B?zier value for {identity!r} must contain four numbers.")
    for index, coordinate in enumerate(value):
        coordinate_path = (*path, index)
        _validate_number(coordinate, identity, references, coordinate_path)
        if index in {0, 2} and not 0 <= coordinate <= 1:
            raise DtcgValidationError(
                f"Cubic B?zier x coordinate at {_display_value_path(identity, coordinate_path)} must be in [0, 1]."
            )


def _validate_stroke_style(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "strokeStyle", identity)
    if isinstance(value, str):
        if value not in _STROKE_STYLES:
            raise DtcgValidationError(f"Stroke style for {identity!r} is invalid.")
        return
    item = _expect_object(
        value,
        required={"dashArray", "lineCap"},
        identity=identity,
        token_type="strokeStyle",
        path=path,
    )
    if not isinstance(item["dashArray"], list):
        raise DtcgValidationError(f"Stroke dashArray for {identity!r} must be an array.")
    for index, dash in enumerate(item["dashArray"]):
        _validate_dimension(dash, identity, references, (*path, "dashArray", index))
    _expect_atomic_literal(references, (*path, "lineCap"), identity)
    if item["lineCap"] not in {"round", "butt", "square"}:
        raise DtcgValidationError(f"Stroke lineCap for {identity!r} is invalid.")


def _validate_border(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "border", identity)
    item = _expect_object(
        value,
        required={"color", "width", "style"},
        identity=identity,
        token_type="border",
        path=path,
    )
    _validate_color(item["color"], identity, references, (*path, "color"))
    _validate_dimension(item["width"], identity, references, (*path, "width"))
    _validate_stroke_style(item["style"], identity, references, (*path, "style"))


def _validate_transition(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "transition", identity)
    item = _expect_object(
        value,
        required={"duration", "delay", "timingFunction"},
        identity=identity,
        token_type="transition",
        path=path,
    )
    _validate_duration(item["duration"], identity, references, (*path, "duration"))
    _validate_duration(item["delay"], identity, references, (*path, "delay"))
    _validate_cubic_bezier(item["timingFunction"], identity, references, (*path, "timingFunction"))


def _validate_shadow_object(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    item = _expect_object(
        value,
        required={"color", "offsetX", "offsetY", "blur", "spread"},
        optional={"inset"},
        identity=identity,
        token_type="shadow",
        path=path,
    )
    _validate_color(item["color"], identity, references, (*path, "color"))
    for property_name in ("offsetX", "offsetY", "blur", "spread"):
        _validate_dimension(item[property_name], identity, references, (*path, property_name))
    if "inset" in item:
        _expect_atomic_literal(references, (*path, "inset"), identity)
    if "inset" in item and not isinstance(item["inset"], bool):
        raise DtcgValidationError(f"Shadow inset for {identity!r} must be a boolean.")


def _validate_shadow(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "shadow", identity)
    if isinstance(value, list):
        for index, shadow in enumerate(value):
            shadow_path = (*path, index)
            if references.get(shadow_path) == "shadow" and isinstance(shadow, list):
                _validate_shadow(shadow, identity, references, shadow_path)
                continue
            _expect_reference_type(references, shadow_path, "shadow", identity)
            _validate_shadow_object(shadow, identity, references, shadow_path)
        return
    _validate_shadow_object(value, identity, references, path)


def _validate_gradient(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "gradient", identity)
    if not isinstance(value, list):
        raise DtcgValidationError(f"Gradient value for {identity!r} must be an array.")
    for index, stop in enumerate(value):
        stop_path = (*path, index)
        if references.get(stop_path) == "gradient" and isinstance(stop, list):
            _validate_gradient(stop, identity, references, stop_path)
            continue
        _expect_reference_type(references, stop_path, "gradient", identity)
        item = _expect_object(
            stop,
            required={"color", "position"},
            identity=identity,
            token_type="gradient stop",
            path=stop_path,
        )
        _validate_color(item["color"], identity, references, (*stop_path, "color"))
        _validate_number(item["position"], identity, references, (*stop_path, "position"))
        item["position"] = max(0, min(1, item["position"]))


def _validate_typography(
    value: Any,
    identity: str,
    references: ReferenceTypes,
    path: ValuePath,
) -> None:
    _expect_reference_type(references, path, "typography", identity)
    item = _expect_object(
        value,
        required={"fontFamily", "fontSize", "fontWeight", "letterSpacing", "lineHeight"},
        identity=identity,
        token_type="typography",
        path=path,
    )
    _validate_font_family(item["fontFamily"], identity, references, (*path, "fontFamily"))
    _validate_dimension(item["fontSize"], identity, references, (*path, "fontSize"))
    _validate_font_weight(item["fontWeight"], identity, references, (*path, "fontWeight"))
    _validate_dimension(item["letterSpacing"], identity, references, (*path, "letterSpacing"))
    _validate_number(item["lineHeight"], identity, references, (*path, "lineHeight"))


_TYPE_VALIDATORS: dict[str, Callable[[Any, str, ReferenceTypes, ValuePath], None]] = {
    "color": _validate_color,
    "dimension": _validate_dimension,
    "fontFamily": _validate_font_family,
    "fontWeight": _validate_font_weight,
    "duration": _validate_duration,
    "cubicBezier": _validate_cubic_bezier,
    "number": _validate_number,
    "strokeStyle": _validate_stroke_style,
    "border": _validate_border,
    "transition": _validate_transition,
    "shadow": _validate_shadow,
    "gradient": _validate_gradient,
    "typography": _validate_typography,
}


def _validate_value_for_type(
    value: Any,
    token_type: str,
    identity: str,
    references: ReferenceTypes,
) -> None:
    validator = _TYPE_VALIDATORS.get(token_type)
    if validator is None:
        raise DtcgValidationError(f"No complete validator is available for $type {token_type!r}.")
    validator(value, identity, references, ())


def resolve_token_document(document: Any) -> dict[str, dict[str, Any]]:
    """Validate and resolve one DTCG 2025.10 token document."""

    if not isinstance(document, dict):
        raise DtcgValidationError("A DTCG token document must be an object.")
    definitions: dict[str, dict[str, Any]] = {}
    _flatten(document, document, (), None, None, definitions)
    resolved: dict[str, dict[str, Any]] = {}

    def resolve(identity: str, stack: tuple[str, ...]) -> dict[str, Any]:
        if identity in resolved:
            return resolved[identity]
        if identity in stack:
            raise DtcgValidationError(f"Circular token alias: {' -> '.join((*stack, identity))}.")
        definition = definitions.get(identity)
        if definition is None:
            raise DtcgValidationError(f"Unresolved token alias: {identity!r}.")
        alias = definition["alias"]
        target = resolve(alias, (*stack, identity)) if alias else None
        token_type = definition["declaredType"]
        references: ReferenceTypes = {}
        if target is not None:
            if token_type is not None and token_type != target["type"]:
                raise DtcgValidationError(
                    f"Alias type mismatch for {identity!r}: {token_type!r} versus {target['type']!r}."
                )
            token_type = token_type or target["type"]
            value = copy.deepcopy(target["value"])
        else:
            token_type = token_type or definition["inheritedType"]

            def materialize(
                raw: Any,
                value_path: ValuePath,
                pointer_stack: tuple[str, ...],
            ) -> Any:
                if isinstance(raw, str):
                    match = _CURLY_REFERENCE.fullmatch(raw)
                    if match is None:
                        return raw
                    target_identity = ".".join(_reference_path(raw))
                    target_record = resolve(target_identity, (*stack, identity))
                    references[value_path] = target_record["type"]
                    return copy.deepcopy(target_record["value"])
                if isinstance(raw, list):
                    return [
                        materialize(item, (*value_path, index), pointer_stack)
                        for index, item in enumerate(raw)
                    ]
                if not isinstance(raw, dict):
                    return copy.deepcopy(raw)
                if "$ref" in raw:
                    if set(raw) != {"$ref"} or not isinstance(raw["$ref"], str):
                        raise DtcgValidationError(
                            f"Property-level reference at {_display_value_path(identity, value_path)} "
                            "must contain only a string $ref."
                        )
                    reference = raw["$ref"]
                    if reference in pointer_stack:
                        raise DtcgValidationError(
                            f"Circular JSON Pointer reference: {' -> '.join((*pointer_stack, reference))}."
                        )
                    target_value, pointer_segments = _lookup_pointer(document, reference)
                    target_identity = _pointer_token_identity(document, reference, required=False)
                    if target_identity is not None:
                        target_record = resolve(target_identity, (*stack, identity))
                        references[value_path] = target_record["type"]
                        return copy.deepcopy(target_record["value"])
                    reference_type = _ATOMIC_REFERENCE_TYPE
                    if "$value" in pointer_segments:
                        value_index = pointer_segments.index("$value")
                        container_identity = ".".join(pointer_segments[:value_index])
                        if container_identity in definitions:
                            container_record = resolve(container_identity, (*stack, identity))
                            semantic_type = semantic_type_at_subpath(
                                container_record["type"],
                                pointer_segments[value_index + 1:],
                            )
                            if semantic_type is not None:
                                reference_type = semantic_type
                    references[value_path] = reference_type
                    return materialize(target_value, value_path, (*pointer_stack, reference))
                return {
                    key: materialize(item, (*value_path, key), pointer_stack)
                    for key, item in raw.items()
                }

            value = materialize(definition["rawValue"], (), ())
        if token_type is None:
            raise DtcgValidationError(
                f"Token {identity!r} has no explicit, inherited, or alias-resolved type; "
                "type guessing is forbidden."
            )
        _validate_value_for_type(value, token_type, identity, references)
        deprecated_value = definition["deprecatedValue"]
        record = {
            "identity": identity,
            "type": token_type,
            "value": value,
            "alias": alias,
            "deprecated": deprecated_value is True or isinstance(deprecated_value, str),
            "deprecationReason": deprecated_value if isinstance(deprecated_value, str) else None,
            "description": definition["description"],
            "extensions": definition["extensions"],
            "sourcePath": definition["sourcePath"],
        }
        resolved[identity] = record
        return record

    for identity in definitions:
        resolve(identity, ())
    return {identity: resolved[identity] for identity in sorted(resolved)}


_SET_KEYS = {"sources", "description", "$extensions"}
_MODIFIER_KEYS = {"contexts", "default", "description", "$extensions"}
_INLINE_SET_KEYS = _SET_KEYS | {"name", "type"}
_INLINE_MODIFIER_KEYS = _MODIFIER_KEYS | {"name", "type"}


def _validate_resolver_name(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise DtcgValidationError(f"Resolver name at {path} must be a non-empty string.")
    return value


def _validate_exact_keys(value: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise DtcgValidationError(f"Unknown properties at {path}: {sorted(unknown)!r}.")


def _validate_resolver_metadata(value: dict[str, Any], path: str) -> None:
    if "description" in value and not isinstance(value["description"], str):
        raise DtcgValidationError(f"description at {path} must be a string.")
    if "$extensions" in value and not isinstance(value["$extensions"], dict):
        raise DtcgValidationError(f"$extensions at {path} must be an object.")


def _reference_object(value: dict[str, Any], path: str) -> tuple[str, dict[str, Any]]:
    reference = value.get("$ref")
    if not isinstance(reference, str) or not reference:
        raise DtcgValidationError(f"Resolver reference at {path} must be a non-empty string.")
    return reference, {key: copy.deepcopy(item) for key, item in value.items() if key != "$ref"}


def _reference_target(document: dict[str, Any], value: dict[str, Any], path: str) -> tuple[Any, list[str]] | None:
    reference, overrides = _reference_object(value, path)
    if not reference.startswith("#"):
        return None
    target, segments = _lookup_pointer(document, reference)
    if overrides:
        if not isinstance(target, dict):
            raise DtcgValidationError(f"Resolver reference override target at {path} must be an object.")
        target = copy.deepcopy(target)
        target.update(overrides)
    return target, segments


def _validate_source_array(
    value: Any,
    path: str,
    document: dict[str, Any],
    validate_set: Callable[[str, dict[str, Any], str, tuple[str, ...]], None],
    stack: tuple[str, ...],
    reference_stack: tuple[str, ...] = (),
) -> None:
    if not isinstance(value, list):
        raise DtcgValidationError(f"Resolver sources at {path} must be an array.")
    for index, source in enumerate(value):
        source_path = f"{path}[{index}]"
        if not isinstance(source, dict):
            raise DtcgValidationError(f"Resolver source {source_path} must be an object.")
        if "$ref" not in source:
            resolve_token_document(source)
            continue
        reference = source["$ref"]
        if isinstance(reference, str) and reference in reference_stack:
            raise DtcgValidationError(
                "Circular resolver source reference: "
                f"{' -> '.join((*reference_stack, reference))}."
            )
        next_reference_stack = (
            (*reference_stack, reference)
            if isinstance(reference, str)
            else reference_stack
        )
        result = _reference_target(document, source, source_path)
        if result is None:
            continue
        target, segments = result
        if segments and segments[0] == "modifiers":
            raise DtcgValidationError(
                f"Resolver sets and modifiers cannot reference a modifier at {source_path}."
            )
        if segments and segments[0] == "resolutionOrder":
            raise DtcgValidationError(f"Resolver references cannot target resolutionOrder at {source_path}.")
        if len(segments) == 2 and segments[0] == "sets":
            if not isinstance(target, dict):
                raise DtcgValidationError(f"Resolver set reference target at {source_path} is invalid.")
            canonical_path = f"sets.{segments[1]}"
            validate_set(segments[1], target, canonical_path, stack)
            continue
        if not isinstance(target, dict):
            raise DtcgValidationError(f"Resolver source reference target at {source_path} is not a token document.")
        if "$ref" in target:
            _validate_source_array(
                [target],
                source_path,
                document,
                validate_set,
                stack,
                next_reference_stack,
            )
        else:
            resolve_token_document(target)


def validate_resolver_document(document: Any, inputs: Any | None = None) -> dict[str, Any]:
    """Validate a Resolver 2025.10 document and one explicit context selection."""

    if not isinstance(document, dict):
        raise DtcgValidationError("A resolver document must be an object.")
    allowed = {"$schema", "$defs", "name", "version", "description", "sets", "modifiers", "resolutionOrder"}
    unknown = set(document) - allowed
    if unknown:
        raise DtcgValidationError(f"Unknown resolver properties: {sorted(unknown)!r}.")
    if document.get("version") != "2025.10":
        raise DtcgValidationError("Resolver version must be exactly '2025.10'.")
    for property_name in ("$schema", "name", "description"):
        if property_name in document and not isinstance(document[property_name], str):
            raise DtcgValidationError(f"Resolver {property_name} must be a string.")
    if "$defs" in document and not isinstance(document["$defs"], dict):
        raise DtcgValidationError("Resolver $defs must be an object when present.")
    order = document.get("resolutionOrder")
    if not isinstance(order, list):
        raise DtcgValidationError("Resolver resolutionOrder is required and must be an array.")
    sets = document.get("sets", {})
    modifiers = document.get("modifiers", {})
    if not isinstance(sets, dict) or not isinstance(modifiers, dict):
        raise DtcgValidationError("Resolver sets and modifiers must be objects.")

    def validate_set(name: str, item: dict[str, Any], path: str, stack: tuple[str, ...]) -> None:
        if path in stack:
            raise DtcgValidationError(f"Circular resolver set reference: {' -> '.join((*stack, path))}.")
        _validate_resolver_name(name, path)
        if not isinstance(item, dict):
            raise DtcgValidationError(f"Resolver set {name!r} must be an object.")
        _validate_exact_keys(item, _SET_KEYS, path)
        _validate_resolver_metadata(item, path)
        if "sources" not in item:
            raise DtcgValidationError(f"Resolver set {name!r} must contain sources.")
        _validate_source_array(item["sources"], f"{path}.sources", document, validate_set, (*stack, path))

    def validate_modifier(name: str, item: dict[str, Any], path: str) -> None:
        _validate_resolver_name(name, path)
        if not isinstance(item, dict):
            raise DtcgValidationError(f"Resolver modifier {name!r} must be an object.")
        _validate_exact_keys(item, _MODIFIER_KEYS, path)
        _validate_resolver_metadata(item, path)
        contexts = item.get("contexts")
        if not isinstance(contexts, dict) or not contexts:
            raise DtcgValidationError(f"Resolver modifier {name!r} must contain non-empty contexts.")
        for context_name, sources in contexts.items():
            _validate_resolver_name(context_name, f"{path}.contexts")
            _validate_source_array(
                sources,
                f"{path}.contexts.{context_name}",
                document,
                validate_set,
                (),
            )
        if "default" in item:
            if not isinstance(item["default"], str) or item["default"] not in contexts:
                raise DtcgValidationError(f"Resolver default for {name!r} is not a declared context.")

    for name, item in sets.items():
        _validate_resolver_name(name, "sets")
        validate_set(name, item, f"sets.{name}", ())
    for name, modifier in modifiers.items():
        _validate_resolver_name(name, "modifiers")
        validate_modifier(name, modifier, f"modifiers.{name}")

    inline_names: set[str] = set()
    input_modifiers: dict[str, dict[str, Any]] = dict(modifiers)
    for index, item in enumerate(order):
        path = f"resolutionOrder[{index}]"
        if not isinstance(item, dict):
            raise DtcgValidationError(f"{path} must be an object.")
        if "$ref" in item:
            result = _reference_target(document, item, path)
            if result is None:
                raise DtcgValidationError(f"{path} cannot use an external reference as an order item.")
            target, segments = result
            if len(segments) != 2 or segments[0] not in {"sets", "modifiers"}:
                raise DtcgValidationError(f"Invalid resolver reference target at {path}: {item['$ref']!r}.")
            name = segments[1]
            if not isinstance(target, dict):
                raise DtcgValidationError(f"Invalid resolver reference target at {path}: {item['$ref']!r}.")
            if segments[0] == "sets":
                validate_set(name, target, path, ())
            else:
                validate_modifier(name, target, path)
                input_modifiers[name] = target
            continue
        name = _validate_resolver_name(item.get("name"), path)
        item_type = item.get("type")
        if item_type not in {"set", "modifier"}:
            raise DtcgValidationError(f"{path}.type must be exactly 'set' or 'modifier'.")
        if name in inline_names:
            raise DtcgValidationError(f"duplicate inline resolver name in resolutionOrder: {name!r}.")
        inline_names.add(name)
        if item_type == "set":
            _validate_exact_keys(item, _INLINE_SET_KEYS, path)
            body = {key: value for key, value in item.items() if key not in {"name", "type"}}
            validate_set(name, body, path, ())
        else:
            _validate_exact_keys(item, _INLINE_MODIFIER_KEYS, path)
            body = {key: value for key, value in item.items() if key not in {"name", "type"}}
            validate_modifier(name, body, path)
            if name in input_modifiers and input_modifiers[name] != body:
                raise DtcgValidationError(f"Conflicting resolver modifier definitions for {name!r}.")
            input_modifiers[name] = body

    if inputs is None:
        selected: dict[str, str] = {}
    elif not isinstance(inputs, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in inputs.items()
    ):
        raise DtcgValidationError("Resolver inputs must be an object of string context values.")
    else:
        selected = dict(inputs)
    unknown_inputs = set(selected) - set(input_modifiers)
    if unknown_inputs:
        raise DtcgValidationError(f"Unknown resolver modifier inputs: {sorted(unknown_inputs)!r}.")
    for name, modifier in input_modifiers.items():
        if name not in selected:
            if "default" not in modifier:
                raise DtcgValidationError(f"Missing required resolver modifier input: {name!r}.")
            selected[name] = modifier["default"]
        if selected[name] not in modifier["contexts"]:
            raise DtcgValidationError(
                f"Invalid context {selected[name]!r} for resolver modifier {name!r}."
            )
    return {
        "version": "2025.10",
        "contexts": {name: selected[name] for name in sorted(selected)},
        "resolutionOrder": copy.deepcopy(order),
    }
