"""Immutable additive v0.3.5 cases for Guardian weighted Elo.

The module uses only Python's standard library and synthetic public evidence.
Every case runs in the isolated Elo worker and writes, when needed, only below
its temporary directory.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


ACTIVE_CAPABILITIES = [
    {
        "predicate": "forbidden_identity_in_scope",
        "scope": "compilation_unit",
    },
    {
        "predicate": "max_instances_per_scope",
        "scope": "compilation_unit",
    },
]


@contextmanager
def _target_import(root: Path) -> Iterator[None]:
    assert (root / "guardian_core").is_dir()
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))
        for name in tuple(sys.modules):
            if name == "guardian_core" or name.startswith("guardian_core."):
                sys.modules.pop(name, None)


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def case_correctness_safe_rule_activation(root: Path) -> None:
    snapshot_schema = _json(root / "schemas" / "rule-activation-snapshot.schema.json")
    permission_schema = _json(root / "schemas" / "rule-activation-permission.schema.json")
    assert snapshot_schema["additionalProperties"] is False
    assert snapshot_schema["properties"]["schemaVersion"] == {"const": 2}
    assert snapshot_schema["properties"]["immutable"] == {"const": True}
    assert permission_schema["additionalProperties"] is False

    with _target_import(root):
        activation = importlib.import_module("guardian_core.rule_activation")
        assert callable(activation.preview_rule_activation)
        assert callable(activation.apply_rule_activation)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            before = _tree(home)
            blocked = False
            try:
                activation.preview_rule_activation(
                    home,
                    profile_id="synthetic-profile",
                    catalog_document={},
                )
            except Exception:
                blocked = True
            assert blocked
            assert _tree(home) == before


def case_reliability_v1_state_preserved(root: Path) -> None:
    profile = _json(root / "schemas" / "profile.schema.json")
    snapshot = _json(root / "schemas" / "snapshot.schema.json")
    flutter = _json(
        root
        / "adapters"
        / "flutter"
        / "contracts"
        / "flutter-adapter-config.schema.json"
    )
    assert profile["properties"]["schemaVersion"] == {"const": 1}
    assert snapshot["properties"]["schemaVersion"] == {"const": 1}
    assert flutter["properties"]["schemaVersion"] == {"const": 1}
    assert profile["additionalProperties"] is False
    assert snapshot["additionalProperties"] is False
    assert "rules" not in snapshot["properties"]

    with _target_import(root):
        paths = importlib.import_module("guardian_core.paths")
        synthetic_home = Path("synthetic-home").absolute()
        synthetic = paths.GuardianPaths(synthetic_home)
        assert synthetic.snapshots("synthetic-profile") == (
            synthetic_home
            / "profiles"
            / "synthetic-profile"
            / "snapshots"
        )


def case_coverage_first_predicate_pairs(root: Path) -> None:
    snapshot_schema = _json(root / "schemas" / "rule-activation-snapshot.schema.json")
    permission_schema = _json(root / "schemas" / "rule-activation-permission.schema.json")
    assert snapshot_schema["properties"]["activatedCapabilities"]["const"] == (
        ACTIVE_CAPABILITIES
    )
    assert permission_schema["$defs"]["capabilities"]["const"] == ACTIVE_CAPABILITIES

    with _target_import(root):
        rules = importlib.import_module("guardian_core.rules")
        flutter = importlib.import_module("guardian_core.flutter_config")
        assert flutter._ACTIVATED_USAGE_CAPABILITIES == ACTIVE_CAPABILITIES
        assert rules.PREDICATE_TYPES == {
            "max_instances_per_scope",
            "forbidden_nesting",
            "required_companion",
            "allowed_parents",
            "variant_context",
            "forbidden_identity_in_scope",
        }


def case_safety_permission_is_not_rule_approval(root: Path) -> None:
    permission_schema = _json(root / "schemas" / "rule-activation-permission.schema.json")
    snapshot_schema = _json(root / "schemas" / "rule-activation-snapshot.schema.json")
    permission = permission_schema["$defs"]["permission"]
    catalog = snapshot_schema["$defs"]["catalogEvidence"]
    assert permission["properties"]["granted"] == {"type": "boolean"}
    assert permission["properties"]["namespaceTarget"] == {
        "const": "rule-snapshots-v2"
    }
    assert "candidateRulesDigest" in permission["required"]
    assert "catalogAuthorityKeyId" in permission["required"]
    assert "approvalAttestation" in catalog["required"]
    assert "granted" not in catalog["properties"]

    with _target_import(root):
        activation = importlib.import_module("guardian_core.rule_activation")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            before = _tree(home)
            blocked = False
            try:
                activation.apply_rule_activation(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": "synthetic-profile",
                        "catalog": {},
                        "permission": {"granted": True},
                    },
                )
            except Exception:
                blocked = True
            assert blocked
            assert _tree(home) == before


def case_portability_no_downgrade(root: Path) -> None:
    installer_path = root / "scripts" / "install_agent_skills.py"
    spec = importlib.util.spec_from_file_location(
        "guardian_synthetic_installer_v5",
        installer_path,
    )
    assert spec is not None and spec.loader is not None
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)

    compare_semver = getattr(installer, "compare_semver", None)
    validate_replacement_versions = getattr(
        installer, "validate_replacement_versions", None
    )
    assert callable(compare_semver)
    assert callable(validate_replacement_versions)

    assert compare_semver("0.3.5", "0.3.4") > 0
    assert compare_semver("0.3.5", "0.3.5") == 0
    bindings = [
        (name, {"pluginVersion": "0.3.5"})
        for name in installer.SKILL_NAMES
    ]
    validate_replacement_versions("0.3.5", bindings)

    blocked = False
    try:
        validate_replacement_versions("0.3.4", bindings)
    except installer.InstallError:
        blocked = True
    assert blocked

    divergent = [
        (installer.SKILL_NAMES[0], {"pluginVersion": "0.3.5"}),
        (installer.SKILL_NAMES[1], {"pluginVersion": "0.3.4"}),
    ]
    blocked = False
    try:
        validate_replacement_versions("0.3.5", divergent)
    except installer.InstallError:
        blocked = True
    assert blocked
