"""Immutable additive v0.3.4 cases for Guardian weighted Elo.

The module uses only Python's standard library and synthetic public fixtures.
Every case runs in the isolated Elo worker and writes, when needed, only below
its temporary directory.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Iterator


FIGMA = {
    "fileKey": "synthetic-library",
    "nodeId": "4:2",
    "sourceVersion": "17",
}
PRIMARY_IDENTITY = "Button/Primary"


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


def _machine_rule(rule_id: str, predicate: dict) -> dict:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "machine",
        "predicate": predicate,
        "appliesTo": {"kind": "system"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "synthetic-public-rules",
        },
    }


def _primary_rule() -> dict:
    return _machine_rule(
        "button-primary.max-per-widget",
        {
            "type": "max_instances_per_scope",
            "identity": PRIMARY_IDENTITY,
            "scope": "widget_class",
            "max": 1,
        },
    )


def _invoke_cli(cli: object, arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


def case_correctness_explicit_rules_fail_closed(root: Path) -> None:
    with _target_import(root):
        rules = importlib.import_module("guardian_core.rules")
        description = (
            "Synthetic ordinary description.\n"
            "[dsg-rule id=button-primary.max-per-widget class=machine]\n"
            "max_instances_per_scope: "
            "identity=Button/Primary scope=widget_class max=1\n"
            "[/dsg-rule]"
        )
        candidates = rules.parse_description_markers(
            description,
            host_kind="component",
            host_identity=PRIMARY_IDENTITY,
            figma=FIGMA,
        )
        allowed = rules.validate_rules(
            candidates,
            known_identities=frozenset({PRIMARY_IDENTITY}),
            source_type="figma_description",
        )
        assert allowed["report"]["status"] == "allowed"
        assert len(allowed["rules"]) == 1
        assert {
            item["reasonCode"] for item in allowed["report"]["entries"]
        } == {"ok", "unmarked_text_ignored"}

        unknown = _primary_rule()
        unknown["predicate"] = {
            "type": "allow_everything",
            "identity": PRIMARY_IDENTITY,
        }
        outside = _primary_rule()
        outside["ruleId"] = "rule.unknown-field"
        outside["closestBlue"] = True
        denied = rules.validate_rules(
            [unknown, outside],
            known_identities=frozenset({PRIMARY_IDENTITY}),
            source_type="artifact",
        )
        assert denied["report"]["status"] == "invalid"
        reasons = {item["reasonCode"] for item in denied["report"]["entries"]}
        assert {"unknown_predicate", "unknown_field"}.issubset(reasons)


def case_reliability_deterministic_rule_preview(root: Path) -> None:
    with _target_import(root):
        rules = importlib.import_module("guardian_core.rules")
        informative = {
            "schemaVersion": 1,
            "ruleId": "copy.sentence-case",
            "class": "informative",
            "statement": "Use sentence case in this synthetic example.",
            "appliesTo": {"kind": "system"},
            "provenance": {
                "origin": "team_artifact",
                "figma": None,
                "docRef": "synthetic-public-rules",
            },
        }
        first = rules.validate_rules(
            [informative, _primary_rule()],
            known_identities=frozenset({PRIMARY_IDENTITY}),
            source_type="artifact",
        )
        second = rules.validate_rules(
            [_primary_rule(), informative],
            known_identities=frozenset({PRIMARY_IDENTITY}),
            source_type="artifact",
        )
        assert first == second
        assert first["report"]["status"] == "allowed"
        assert first["report"]["summary"] == {
            "ok": 2,
            "warnings": 0,
            "errors": 0,
            "notAssessed": 0,
        }


def case_coverage_six_rule_predicates(root: Path) -> None:
    with _target_import(root):
        rules = importlib.import_module("guardian_core.rules")
        candidates = [
            _machine_rule(
                "rule.max-instances",
                {
                    "type": "max_instances_per_scope",
                    "identity": PRIMARY_IDENTITY,
                    "scope": "widget_class",
                    "max": 1,
                },
            ),
            _machine_rule(
                "rule.forbidden-nesting",
                {
                    "type": "forbidden_nesting",
                    "outerIdentity": "Card",
                    "innerIdentity": "Card",
                },
            ),
            _machine_rule(
                "rule.required-companion",
                {
                    "type": "required_companion",
                    "identity": "Input",
                    "companionIdentity": "Label",
                    "relation": "sibling",
                },
            ),
            _machine_rule(
                "rule.allowed-parents",
                {
                    "type": "allowed_parents",
                    "identity": "Row",
                    "parents": ["Table"],
                },
            ),
            _machine_rule(
                "rule.variant-context",
                {
                    "type": "variant_context",
                    "identity": PRIMARY_IDENTITY,
                    "variant": "Compact",
                    "allowedScopes": ["widget_class"],
                },
            ),
            _machine_rule(
                "rule.forbidden-in-scope",
                {
                    "type": "forbidden_identity_in_scope",
                    "identity": "Banner",
                    "scope": "compilation_unit",
                },
            ),
        ]
        identities = frozenset(
            {
                PRIMARY_IDENTITY,
                "Banner",
                "Card",
                "Input",
                "Label",
                "Row",
                "Table",
            }
        )
        result = rules.validate_rules(
            candidates,
            known_identities=identities,
            source_type="artifact",
        )
        assert result["report"]["status"] == "allowed"
        assert result["report"]["summary"]["ok"] == 6
        assert len(result["rules"]) == 6
        assert {
            item["predicate"]["type"] for item in result["rules"]
        } == {
            "max_instances_per_scope",
            "forbidden_nesting",
            "required_companion",
            "allowed_parents",
            "variant_context",
            "forbidden_identity_in_scope",
        }


def case_safety_rule_preview_nondisclosure(root: Path) -> None:
    with _target_import(root):
        rules = importlib.import_module("guardian_core.rules")
        statement = "Synthetic private wording must remain local."
        document_reference = "synthetic-local-only-reference"
        informative = {
            "schemaVersion": 1,
            "ruleId": "copy.private-guidance",
            "class": "informative",
            "statement": statement,
            "appliesTo": {"kind": "system"},
            "provenance": {
                "origin": "team_artifact",
                "figma": None,
                "docRef": document_reference,
            },
        }
        allowed = rules.validate_rules(
            [informative],
            known_identities=frozenset(),
            source_type="artifact",
        )
        report = allowed["report"]
        rendered = json.dumps(report, sort_keys=True)
        assert report["authority"] == "preview_only"
        assert report["localChangesPerformed"] is False
        assert report["productionReady"] is False
        assert statement not in rendered
        assert document_reference not in rendered

        unassessed = rules.validate_rules(
            [_primary_rule()],
            known_identities=None,
            source_type="artifact",
        )["report"]
        assert unassessed["status"] == "not_assessed"
        assert unassessed["identityCoverage"] == "not_assessed"
        assert unassessed["productionReady"] is False


def case_usability_rule_cli_contract(root: Path) -> None:
    with _target_import(root):
        cli = importlib.import_module("guardian_core.cli")
        assert hasattr(cli, "_rules_validate_command")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            artifact = base / "rules.json"
            identities = base / "identities.json"
            artifact.write_text(json.dumps([_primary_rule()]), encoding="utf-8")
            identities.write_text(json.dumps([PRIMARY_IDENTITY]), encoding="utf-8")
            before = {
                path.relative_to(base).as_posix(): path.read_bytes()
                for path in base.rglob("*")
                if path.is_file()
            }
            code, output, error = _invoke_cli(
                cli,
                [
                    "rules",
                    "validate",
                    "--format",
                    "artifact",
                    "--input",
                    str(artifact),
                    "--known-identities",
                    str(identities),
                ],
            )
            assert (code, error) == (0, "")
            report = json.loads(output)
            assert report["status"] == "allowed"
            assert report["authority"] == "preview_only"
            assert report["localChangesPerformed"] is False
            assert report["productionReady"] is False
            after = {
                path.relative_to(base).as_posix(): path.read_bytes()
                for path in base.rglob("*")
                if path.is_file()
            }
            assert after == before

            code, output, error = _invoke_cli(
                cli,
                [
                    "rules",
                    "validate",
                    "--format",
                    "artifact",
                    "--input",
                    str(artifact),
                ],
            )
            assert (code, error) == (4, "")
            assert json.loads(output)["status"] == "not_assessed"
