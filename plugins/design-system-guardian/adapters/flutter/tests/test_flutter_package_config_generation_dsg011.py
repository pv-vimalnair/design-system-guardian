from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.flutter_config import (
    FlutterConfigError,
    _generate_flutter_adapter_config_at_home,
)
from tests.test_flutter_config_dsg008 import (
    fully_mapped_catalog,
    provision_pin,
)


class FlutterPackageConfigGenerationTests(unittest.TestCase):
    def generate(self, root: Path, catalog: dict) -> dict:
        provision_pin(root, catalog)
        return _generate_flutter_adapter_config_at_home(
            root,
            profile_id="example-company",
            run_id="run-flutter-config",
        )

    def test_signed_mapping_digest_becomes_exact_approved_package(self) -> None:
        catalog = fully_mapped_catalog()
        catalog["sourceCut"]["repositoryCommit"] = "c" * 40
        with tempfile.TemporaryDirectory() as directory:
            config = self.generate(Path(directory), catalog)
        self.assertEqual(
            config["approvedPackages"],
            {
                "example_company_design_system": {
                    "contentDigest": "e" * 64,
                    "repositoryCommit": "c" * 40,
                }
            },
        )

    def test_one_package_cannot_claim_conflicting_content_digests(self) -> None:
        catalog = fully_mapped_catalog()
        catalog["sourceCut"]["repositoryCommit"] = "c" * 40
        catalog["registry"]["icons"][0]["codeMappings"][0]["sourceDigest"] = "f" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FlutterConfigError, "package|digest|agree"):
                self.generate(Path(directory), catalog)

    def test_repository_commit_must_be_full_lowercase_git_object_id(self) -> None:
        catalog = fully_mapped_catalog()
        catalog["sourceCut"]["repositoryCommit"] = "abc1234"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FlutterConfigError, "repositoryCommit"):
                self.generate(Path(directory), catalog)

    def test_component_variant_cannot_impersonate_another_package(self) -> None:
        catalog = fully_mapped_catalog()
        catalog["sourceCut"]["repositoryCommit"] = "c" * 40
        catalog["registry"]["components"][0]["variants"] = [
            "package:counterfeit/design.dart#MpButtonVariant.primary"
        ]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FlutterConfigError, "variant|package"):
                self.generate(Path(directory), catalog)


if __name__ == "__main__":
    unittest.main()
