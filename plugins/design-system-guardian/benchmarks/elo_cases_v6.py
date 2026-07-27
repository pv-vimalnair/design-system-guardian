"""Immutable additive v0.3.6 cases for Guardian weighted Elo.

The module uses only Python's standard library and privacy-safe synthetic
inputs. Every case runs in the isolated Elo worker and writes, when needed,
only below its temporary directory. Local scores, results, and history are not
part of this public suite.
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


PREDICATES = {
    "allowed_parents",
    "forbidden_identity_in_scope",
    "forbidden_nesting",
    "max_instances_per_scope",
    "required_companion",
    "variant_context",
}


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


def case_correctness_explicit_evaluator_v2(root: Path) -> None:
    permission = _json(root / "schemas" / "evaluator-upgrade-permission.schema.json")
    record = _json(root / "schemas" / "evaluator-authorization-record.schema.json")
    assert permission["additionalProperties"] is False
    assert permission["$defs"]["permission"]["properties"]["granted"] == {
        "type": "boolean"
    }
    assert permission["$defs"]["permission"]["properties"]["previousEvaluatorId"] == {
        "const": "guardian-flutter-usage-rules-v1"
    }
    assert permission["$defs"]["permission"]["properties"]["targetEvaluatorId"] == {
        "const": "guardian-flutter-usage-rules-v2"
    }
    assert record["properties"]["immutable"] == {"const": True}

    with _target_import(root):
        evaluator = importlib.import_module("guardian_core.evaluator_upgrade")
        assert callable(evaluator.preview_evaluator_upgrade)
        assert callable(evaluator.apply_evaluator_upgrade)
        assert evaluator.PREVIOUS_EVALUATOR_ID == "guardian-flutter-usage-rules-v1"
        assert evaluator.TARGET_EVALUATOR_ID == "guardian-flutter-usage-rules-v2"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            before = _tree(home)
            blocked = False
            try:
                evaluator.preview_evaluator_upgrade(
                    home,
                    profile_id="synthetic-profile",
                )
            except Exception:
                blocked = True
            assert blocked
            assert _tree(home) == before


def case_reliability_no_implicit_evaluator_upgrade(root: Path) -> None:
    with _target_import(root):
        activation = importlib.import_module("guardian_core.rule_activation")
        evaluator = importlib.import_module("guardian_core.evaluator_upgrade")
        assert activation.EVALUATOR_ID == evaluator.PREVIOUS_EVALUATOR_ID
        assert activation.EVALUATOR_ID != evaluator.TARGET_EVALUATOR_ID
        assert activation.ACTIVE_CAPABILITIES == [
            {
                "predicate": "forbidden_identity_in_scope",
                "scope": "compilation_unit",
            },
            {
                "predicate": "max_instances_per_scope",
                "scope": "compilation_unit",
            },
        ]
        assert evaluator.AUTHORIZATION_NAMESPACE == "evaluator-authorizations-v1"
        assert evaluator.EVALUATOR_CONTRACT_DIGEST

    activation_schema = _json(
        root / "schemas" / "rule-activation-permission.schema.json"
    )
    evaluator_schema = _json(
        root / "schemas" / "evaluator-upgrade-permission.schema.json"
    )
    assert "targetEvaluatorId" not in activation_schema["properties"]
    assert evaluator_schema["properties"]["permission"] == {
        "$ref": "#/$defs/permission"
    }


def case_coverage_six_predicates_two_scopes(root: Path) -> None:
    with _target_import(root):
        evaluator = importlib.import_module("guardian_core.evaluator_upgrade")
        capabilities = evaluator.EVALUATOR_CAPABILITY_MATRIX
        assert {item["predicate"] for item in capabilities["predicates"]} == PREDICATES
        assert capabilities["scopes"] == ["compilation_unit", "widget_class"]
        assert capabilities["relations"] == ["child", "descendant", "sibling"]
        supported = (
            {"type": "forbidden_identity_in_scope", "scope": "widget_class"},
            {"type": "max_instances_per_scope", "scope": "compilation_unit"},
            {"type": "forbidden_nesting"},
            {"type": "required_companion", "relation": "sibling"},
            {"type": "allowed_parents"},
            {
                "type": "variant_context",
                "allowedScopes": ["compilation_unit", "widget_class"],
            },
        )
        assert all(evaluator._v2_supports(predicate) for predicate in supported)
        assert not evaluator._v2_supports(
            {"type": "required_companion", "relation": "cousin"}
        )

    flutter_v3 = _json(
        root
        / "adapters"
        / "flutter"
        / "contracts"
        / "flutter-adapter-config-v3.schema.json"
    )
    assert flutter_v3["properties"]["schemaVersion"] == {"const": 3}
    rendered = json.dumps(flutter_v3, sort_keys=True)
    assert all(predicate in rendered for predicate in PREDICATES)
    assert "widget_class" in rendered


def case_safety_separate_usage_rules_lane(root: Path) -> None:
    audit = _json(root / "schemas" / "audit-result-v2.schema.json")
    lane = _json(root / "schemas" / "usage-rules-evidence.schema.json")
    assert {
        "designSystemLane",
        "usageRulesLane",
        "uxAccessibilityLane",
        "enforcementAuthorityLane",
    }.issubset(audit["required"])
    assert audit["properties"]["usageRulesLane"] == {"$ref": "#/$defs/usageRulesLane"}
    assert lane["additionalProperties"] is False
    assert "statement" not in json.dumps(lane, sort_keys=True)

    with _target_import(root):
        evaluator = importlib.import_module("guardian_core.evaluator_upgrade")
        private_rule = {
            "ruleId": "synthetic.private.rule",
            "class": "machine",
            "statement": "synthetic confidential prose must not be projected",
            "sourceLocator": {"fileKey": "synthetic-private-file"},
            "predicate": {"type": "forbidden_nesting"},
        }
        entry = evaluator._inventory_entry(
            private_rule,
            evaluator_state="authorized_v2",
        )
        assert entry == {
            "ruleId": "synthetic.private.rule",
            "ruleClass": "machine",
            "predicate": "forbidden_nesting",
            "capabilityStatus": "active",
            "reasonCode": "evaluator_capability_active",
        }
        rendered = json.dumps(entry, sort_keys=True)
        assert "confidential prose" not in rendered
        assert "synthetic-private-file" not in rendered


def case_portability_rule_list_reload_status(root: Path) -> None:
    installer_path = root / "scripts" / "install_agent_skills.py"
    spec = importlib.util.spec_from_file_location(
        "guardian_synthetic_installer_v6",
        installer_path,
    )
    assert spec is not None and spec.loader is not None
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    assert hasattr(installer, "parser")
    assert hasattr(installer, "installation_status")
    assert hasattr(installer, "HostRestartRequired")
    assert callable(installer.parser)
    assert callable(installer.installation_status)

    with _target_import(root):
        cli = importlib.import_module("guardian_core.cli")
        list_args = cli.build_parser().parse_args(
            ["rules", "list", "--profile", "synthetic-profile"]
        )
        preview_args = cli.build_parser().parse_args(
            ["rules", "upgrade", "preview", "--profile", "synthetic-profile"]
        )
        apply_args = cli.build_parser().parse_args(
            ["rules", "upgrade", "apply", "--input", "synthetic.json"]
        )
        assert list_args.rules_command == "list"
        assert preview_args.rules_upgrade_command == "preview"
        assert apply_args.rules_upgrade_command == "apply"

    parsed = installer.parser().parse_args(
        ["--target-root", "synthetic-skills", "--status"]
    )
    assert parsed.status is True
    assert parsed.python is None
    with tempfile.TemporaryDirectory() as directory:
        root_dir = Path(directory)
        target = root_dir / "skills"
        before = _tree(root_dir)
        status = installer.installation_status(target)
        assert status["status"] == "update_required"
        assert status["reasonCode"] == "guardian_not_installed"
        assert status["candidateVersion"] == "0.3.6"
        assert _tree(root_dir) == before
        restart = installer.HostRestartRequired(target)
        assert restart.status == "reload_required"
        assert restart.reason_code == "host_restart_required"
        assert restart.target_root == target.resolve()
