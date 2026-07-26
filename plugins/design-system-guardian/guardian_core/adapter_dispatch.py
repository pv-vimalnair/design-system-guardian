"""Small exact dispatch boundary for Guardian's supported adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import sha256_digest
from .contracts import ExitCode
from .figma_adapter import (
    build_figma_adapter_config,
    normalize_figma_observation,
)
from .flutter_config import _generate_flutter_adapter_config_at_home
from .preflight import load_run_pin
from .project_binding import verify_bound_project


SUPPORTED_ADAPTERS = frozenset({"figma", "flutter"})


class AdapterDispatchError(ValueError):
    """Raised when a selected profile cannot run the exact requested adapter."""

    exit_code = ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE


def select_adapter(profile: Any, requested: Any) -> str:
    if requested not in SUPPORTED_ADAPTERS:
        raise AdapterDispatchError("Guardian supports only the exact figma or flutter adapter.")
    if not isinstance(profile, dict) or not isinstance(profile.get("adapters"), dict):
        raise AdapterDispatchError("Selected profile adapter configuration is malformed.")
    if requested == "flutter":
        flutter = profile["adapters"].get("flutter")
        if not isinstance(flutter, dict) or flutter.get("enabled") is not True:
            raise AdapterDispatchError(
                "Flutter adapter is not exactly enabled by the selected profile."
            )
    else:
        figma = profile.get("figma")
        libraries = figma.get("allowlistedLibraryFiles") if isinstance(figma, dict) else None
        configured = profile["adapters"].get("figma")
        if configured is not None and (
            not isinstance(configured, dict) or configured.get("enabled") is not True
        ):
            raise AdapterDispatchError(
                "Figma adapter is explicitly disabled or malformed in the selected profile."
            )
        if not isinstance(libraries, list) or not libraries:
            raise AdapterDispatchError(
                "Figma adapter requires at least one exact allowlisted library file."
            )
    return str(requested)


def build_pinned_adapter_config(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
    adapter: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one run pin and derive only its selected adapter configuration."""

    context = load_run_pin(home, profile_id=profile_id, run_id=run_id)
    selected = select_adapter(context["profile"], adapter)
    if selected == "flutter":
        config = _generate_flutter_adapter_config_at_home(
            home,
            profile_id=profile_id,
            run_id=run_id,
        )
    else:
        config = build_figma_adapter_config(
            run_pin=context["pin"],
            verified_snapshot=context["snapshot"],
        )
    return context, config


def build_figma_runner_evidence(
    *,
    observation: dict[str, Any],
    run_pin: dict[str, Any],
    verified_snapshot: dict[str, Any],
    project_binding: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Normalize one observation and bind it to the selected local run workspace."""

    binding = verify_bound_project(project_binding)
    config = build_figma_adapter_config(
        run_pin=run_pin,
        verified_snapshot=verified_snapshot,
    )
    normalized = normalize_figma_observation(
        observation,
        run_pin=run_pin,
        verified_snapshot=verified_snapshot,
    )
    project = {
        "canonicalRoot": binding["canonicalRoot"],
        "rootIdentity": binding["rootIdentity"],
        "assessedTreeDigest": sha256_digest(
            {
                "adapter": "figma",
                "document": observation.get("document"),
                "analysis": observation.get("analysis"),
                "observations": observation.get("observations"),
            }
        ),
        "analysisInputsDigest": sha256_digest(
            {
                "adapter": "figma",
                "adapterVersion": observation.get("adapterVersion"),
                "configDigest": config["configDigest"],
                "collectorDigest": config["collectorDigest"],
            }
        ),
    }
    runner = {
        "schemaVersion": 1,
        "adapter": "figma",
        "adapterResult": observation,
        "normalizedAdapterResult": normalized,
        "project": project,
    }
    return runner, normalized, config


def verify_figma_runner_evidence(
    value: Any,
    *,
    run_pin: dict[str, Any],
    verified_snapshot: dict[str, Any],
    config_digest: str,
) -> dict[str, Any]:
    """Rebuild Figma runner evidence and reject replay, mutation, or source drift."""

    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "adapter",
        "adapterResult",
        "normalizedAdapterResult",
        "project",
    }:
        raise AdapterDispatchError("Figma runner evidence has unknown or missing fields.")
    if value.get("schemaVersion") != 1 or value.get("adapter") != "figma":
        raise AdapterDispatchError("Figma runner evidence version or adapter is invalid.")
    rebuilt, normalized, config = build_figma_runner_evidence(
        observation=value.get("adapterResult"),
        run_pin=run_pin,
        verified_snapshot=verified_snapshot,
        project_binding=run_pin.get("projectBinding"),
    )
    if config.get("configDigest") != config_digest:
        raise AdapterDispatchError("Figma runner config differs from finalization.")
    if value.get("normalizedAdapterResult") != normalized or value != rebuilt:
        raise AdapterDispatchError("Figma runner evidence differs from exact read-back.")
    return value


__all__ = [
    "SUPPORTED_ADAPTERS",
    "AdapterDispatchError",
    "build_figma_runner_evidence",
    "build_pinned_adapter_config",
    "select_adapter",
    "verify_figma_runner_evidence",
]
