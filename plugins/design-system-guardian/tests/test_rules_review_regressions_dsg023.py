from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
FIGMA = {
    "fileKey": "synthetic-library",
    "nodeId": "4:2",
    "sourceVersion": "17",
}


def _informative_rule(*, rule_id: object = "copy.synthetic-guidance") -> dict:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "informative",
        "statement": "Synthetic guidance.",
        "appliesTo": {"kind": "system"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "synthetic-public-rules",
        },
    }


def _report_errors(report: dict) -> list:
    schema = json.loads(
        (ROOT / "schemas" / "rules-validation-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    return list(Draft202012Validator(schema).iter_errors(report))


def _invoke(arguments: list[str]) -> tuple[int, dict, str]:
    from guardian_core.cli import main

    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    return code, json.loads(stdout.getvalue()), stderr.getvalue()


class RulesReviewRegressionTest(unittest.TestCase):
    def test_invalid_rule_id_is_redacted_and_report_remains_schema_valid(self) -> None:
        from guardian_core.rules import validate_rules

        local_source_text = "SYNTHETIC LOCAL RULE TEXT WITH SPACES"
        report = validate_rules(
            [_informative_rule(rule_id=local_source_text)],
            known_identities=frozenset(),
            source_type="artifact",
        )["report"]

        self.assertEqual(_report_errors(report), [])
        self.assertNotIn(local_source_text, json.dumps(report, sort_keys=True))

    def test_empty_artifact_without_identity_coverage_is_not_assessed_exit_four(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "rules.json"
            artifact.write_text("[]", encoding="utf-8")
            code, report, error = _invoke(
                [
                    "rules",
                    "validate",
                    "--format",
                    "artifact",
                    "--input",
                    str(artifact),
                ]
            )

        self.assertEqual((code, error), (4, ""))
        self.assertEqual(report["status"], "not_assessed")
        self.assertEqual(report["identityCoverage"], "not_assessed")
        self.assertEqual(_report_errors(report), [])

    def test_malformed_marker_beside_valid_marker_fails_closed(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        description = (
            "[dsg-rule id=malformed.rule class=machine extra=yes]\n"
            "allow_everything: identity=Outside\n"
            "[/dsg-rule]\n"
            "[dsg-rule id=valid.rule class=informative]\n"
            "Synthetic guidance.\n"
            "[/dsg-rule]"
        )
        result = validate_rules(
            parse_description_markers(
                description,
                host_kind="system",
                host_identity="Synthetic/System",
                figma=FIGMA,
            ),
            known_identities=frozenset(),
            source_type="figma_description",
        )

        self.assertEqual(result["report"]["status"], "invalid")
        self.assertIn(
            "parse_failure",
            {entry["reasonCode"] for entry in result["report"]["entries"]},
        )

    def test_wrong_shaped_json_value_returns_safe_invalid_report(self) -> None:
        from guardian_core.rules import validate_rules

        candidate = _informative_rule()
        candidate["class"] = []
        try:
            report = validate_rules(
                [candidate],
                known_identities=frozenset(),
                source_type="artifact",
            )["report"]
        except Exception as error:  # The regression is an escaping implementation error.
            self.fail(f"wrong-shaped JSON escaped validation as {type(error).__name__}")

        self.assertEqual(report["status"], "invalid")
        self.assertEqual(_report_errors(report), [])

    def test_empty_comma_list_members_fail_closed(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        description = (
            "[dsg-rule id=parents.synthetic class=machine]\n"
            "allowed_parents: identity=Row parents=Table,,Card,\n"
            "[/dsg-rule]"
        )
        result = validate_rules(
            parse_description_markers(
                description,
                host_kind="system",
                host_identity="Synthetic/System",
                figma=FIGMA,
            ),
            known_identities=frozenset({"Row", "Table", "Card"}),
            source_type="figma_description",
        )

        self.assertEqual(result["report"]["status"], "invalid")
        self.assertEqual(result["rules"], [])

    def test_duplicate_entry_order_is_independent_of_candidate_order(self) -> None:
        from guardian_core.rules import validate_rules

        informative = _informative_rule(rule_id="same.synthetic-rule")
        judgment = {**informative, "class": "judgment"}
        first = validate_rules(
            [informative, judgment],
            known_identities=frozenset(),
            source_type="artifact",
        )["report"]
        second = validate_rules(
            [judgment, informative],
            known_identities=frozenset(),
            source_type="artifact",
        )["report"]

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
