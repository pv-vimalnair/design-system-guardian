from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RulesPublicationPrivacyTest(unittest.TestCase):
    def test_public_rule_fixtures_are_synthetic_and_contain_no_runtime_documents(self) -> None:
        forbidden = (
            "ExamplePrivateCompany",
            "ExamplePrivateProduct",
            ".design-system-guardian/profiles/",
            '"profileId"',
            '"snapshotId"',
            '"runId"',
        )
        paths = [
            ROOT / "benchmarks" / "elo_cases_v4.py",
            ROOT / "tests" / "test_rules_foundation_dsg018.py",
            ROOT / "tests" / "test_cli_rules_dsg018.py",
        ]
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                for marker in forbidden:
                    self.assertNotIn(marker, text)

    def test_judgment_elo_fixtures_use_only_synthetic_public_metadata(self) -> None:
        forbidden = (
            "ExamplePrivateCompany",
            "ExamplePrivateProduct",
            "PrivateReleaseCandidate",
            "/Users/",
            "@example.com",
        )
        paths = [
            ROOT / "benchmarks" / "elo_cases_v7.py",
        ]
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                for marker in forbidden:
                    self.assertNotIn(marker, text)

    def test_rule_source_runtime_directories_are_not_public_package_paths(self) -> None:
        for name in (
            "rules",
            "rule-sources",
            "validation-reports",
            "judgments",
            "decisions",
            "judgment-decisions",
            "decision-history",
        ):
            self.assertFalse((ROOT / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
