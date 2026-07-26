from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


RULE = {
    "schemaVersion": 1,
    "ruleId": "button-primary.max-per-widget",
    "class": "machine",
    "predicate": {
        "type": "max_instances_per_scope",
        "identity": "Button/Primary",
        "scope": "widget_class",
        "max": 1,
    },
    "appliesTo": {"kind": "component", "identity": "Button/Primary"},
    "provenance": {"origin": "team_artifact", "figma": None, "docRef": "team-rules"},
}


def invoke(args: list[str]) -> tuple[int, str, str]:
    from guardian_core.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class RuleValidationCliTest(unittest.TestCase):
    def test_artifact_validation_passes_only_with_identity_coverage_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "rules.dsg.json"
            identities = root / "identities.json"
            artifact.write_text(json.dumps([RULE]), encoding="utf-8")
            identities.write_text(json.dumps(["Button/Primary"]), encoding="utf-8")
            before = {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}
            code, out, err = invoke([
                "rules", "validate", "--format", "artifact", "--input", str(artifact),
                "--known-identities", str(identities),
            ])
            self.assertEqual((code, err), (0, ""))
            report = json.loads(out)
            self.assertEqual(report["status"], "allowed")
            self.assertEqual(report["authority"], "preview_only")
            self.assertFalse(report["localChangesPerformed"])
            self.assertFalse(report["productionReady"])
            after = {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}
            self.assertEqual(after, before)

    def test_missing_identity_coverage_exits_four_and_invalid_rules_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "rules.dsg.json"
            artifact.write_text(json.dumps([RULE]), encoding="utf-8")
            code, out, err = invoke([
                "rules", "validate", "--format", "artifact", "--input", str(artifact),
            ])
            self.assertEqual((code, err), (4, ""))
            self.assertEqual(json.loads(out)["status"], "not_assessed")

            artifact.write_text(json.dumps([{**RULE, "inventedFallback": True}]), encoding="utf-8")
            code, out, err = invoke([
                "rules", "validate", "--format", "artifact", "--input", str(artifact),
            ])
            self.assertEqual((code, err), (2, ""))
            self.assertEqual(json.loads(out)["status"], "invalid")

    def test_figma_description_requires_exact_metadata_and_never_echoes_source_or_path(self) -> None:
        secret_text = "Internal instruction that must not appear."
        marker = (
            secret_text
            + "\n[dsg-rule id=button-primary.max-per-widget class=machine]\n"
            + "max_instances_per_scope: identity=Button/Primary scope=widget_class max=1\n"
            + "[/dsg-rule]"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            description = root / "private-description.txt"
            identities = root / "identities.json"
            description.write_text(marker, encoding="utf-8")
            identities.write_text(json.dumps(["Button/Primary"]), encoding="utf-8")

            missing_code, missing_out, _ = invoke([
                "rules", "validate", "--format", "figma-description",
                "--input", str(description), "--known-identities", str(identities),
            ])
            self.assertEqual(missing_code, 2)
            self.assertEqual(json.loads(missing_out)["status"], "invalid")

            code, out, err = invoke([
                "rules", "validate", "--format", "figma-description",
                "--input", str(description), "--known-identities", str(identities),
                "--host-kind", "component", "--host-identity", "Button/Primary",
                "--figma-file-key", "F1", "--figma-node-id", "1:2",
                "--figma-source-version", "v9",
            ])
            self.assertEqual((code, err), (0, ""))
            report = json.loads(out)
            self.assertEqual(report["sourceType"], "figma_description")
            rendered = json.dumps(report, sort_keys=True)
            self.assertNotIn(secret_text, rendered)
            self.assertNotIn(str(description), rendered)
            self.assertNotIn("F1", rendered)
            self.assertNotIn("1:2", rendered)

    def test_existing_command_surface_remains_available(self) -> None:
        from guardian_core.cli import build_parser

        parser = build_parser()
        for argv in (["doctor"], ["setup", "status"], ["elo", "show"]):
            with self.subTest(argv=argv):
                self.assertIsNotNone(parser.parse_args(argv).handler)


if __name__ == "__main__":
    unittest.main()
