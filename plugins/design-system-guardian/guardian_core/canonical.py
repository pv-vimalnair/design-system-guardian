"""Canonical JSON and digest helpers used for sealed Guardian evidence."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable


class DuplicateJsonKeyError(ValueError):
    """Raised when JSON attempts last-key-wins ambiguity."""


def _object_without_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"Duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def decode_json_bytes(payload: bytes) -> Any:
    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_object_without_duplicate_keys,
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically and reject non-standard numeric values."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def sha256_digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> Any:
    return decode_json_bytes(path.read_bytes())


def read_canonical_json(path: Path) -> Any:
    payload = path.read_bytes()
    value = decode_json_bytes(payload)
    if canonical_json_bytes(value) != payload:
        raise ValueError(f"JSON file is not in canonical byte form: {path}")
    return value


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Replace a file atomically without leaving a partially written artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value))
