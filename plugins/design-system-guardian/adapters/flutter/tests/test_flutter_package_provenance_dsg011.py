from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import unquote, urlparse


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from guardian_core.flutter_runner import (
    ATTESTATION_PREFIX,
    FlutterRunnerIntegrityError,
    run_flutter_analysis,
    verify_flutter_project_evidence,
)
from tests.flutter_authority_test_support import (
    create_test_dart_sdk,
    create_test_package,
    package_binding,
)


PACKAGE_ALGORITHM = "design-system-guardian.flutter-package-content.v1"


def independent_package_manifest(root: Path) -> list[dict[str, str]]:
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return files


def independent_content_digest(root: Path) -> str:
    return sha256_digest(
        {
            "schemaVersion": 1,
            "algorithm": PACKAGE_ALGORITHM,
            "files": independent_package_manifest(root),
        }
    )


class FlutterPackageProvenanceTests(unittest.TestCase):
    def make_package(
        self,
        root: Path,
        *,
        name: str = "example_company_design_system",
        marker: str = "approved",
    ) -> Path:
        (root / "lib").mkdir(parents=True)
        (root / "assets").mkdir()
        (root / "pubspec.yaml").write_text(
            f"name: {name}\nenvironment:\n  sdk: ^3.10.0\nflutter:\n  assets:\n    - assets/icon.svg\n",
            encoding="utf-8",
        )
        (root / "lib" / "design.dart").write_text(
            f"const packageMarker = '{marker}';\n",
            encoding="utf-8",
        )
        (root / "assets" / "icon.svg").write_text(
            f"<svg><title>{marker}</title></svg>\n",
            encoding="utf-8",
        )
        return root

    def make_product(
        self,
        root: Path,
        *,
        package_root: Path,
        flutter_root: Path,
        toolchain_binding: dict,
        approved_content_digest: str,
        package_name: str = "example_company_design_system",
        repository_commit: str = "c" * 40,
    ) -> tuple[Path, Path, dict, dict]:
        product = root / "product"
        (product / "lib").mkdir(parents=True)
        (product / ".dart_tool").mkdir()
        (product / "pubspec.yaml").write_text(
            "name: guarded_product\nenvironment:\n  sdk: ^3.10.0\n",
            encoding="utf-8",
        )
        (product / "lib" / "main.dart").write_text(
            f"import 'package:{package_name}/design.dart';\nvoid main() {{}}\n",
            encoding="utf-8",
        )
        package_config = {
            "configVersion": 2,
            "packages": [
                {
                    "name": "guarded_product",
                    "rootUri": "../",
                    "packageUri": "lib/",
                    "languageVersion": "3.10",
                },
                {
                    "name": "flutter",
                    "rootUri": flutter_root.resolve().as_uri() + "/",
                    "packageUri": "lib/",
                    "languageVersion": "3.10",
                },
                {
                    "name": package_name,
                    "rootUri": package_root.resolve().as_uri() + "/",
                    "packageUri": "lib/",
                    "languageVersion": "3.10",
                },
            ],
        }
        (product / ".dart_tool" / "package_config.json").write_bytes(
            canonical_json_bytes(package_config)
        )
        source_cut = {"figma": "v1"}
        config = {
            "schemaVersion": 1,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "profileId": "example-company",
            "policyDigest": "a" * 64,
            "snapshotId": "b" * 64,
            "sourceCutDigest": sha256_digest(source_cut),
            "toolchain": toolchain_binding,
            "requiredPackages": {"flutter": package_binding(flutter_root)},
            "approvedPackages": {
                package_name: {
                    "contentDigest": approved_content_digest,
                    "repositoryCommit": repository_commit,
                }
            },
            "approvedIdentities": {
                "colors": [
                    f"package:{package_name}/design.dart#AppColors.primary"
                ],
                "textStyles": [],
                "icons": [],
                "dimensions": [],
                "effects": [],
                "motion": [],
                "widgets": [],
            },
            "componentVariants": {},
        }
        config["configDigest"] = sha256_digest(config)
        config_path = root / "host" / "flutter-adapter.json"
        config_path.parent.mkdir(exist_ok=True)
        config_path.write_bytes(canonical_json_bytes(config))
        run_pin = {
            "schemaVersion": 1,
            "runId": "run-package-proof",
            "profileId": "example-company",
            "snapshotId": "b" * 64,
            "policyDigest": "a" * 64,
            "sourceCut": source_cut,
        }
        return product, config_path, config, run_pin

    @staticmethod
    def uri_path(value: str) -> Path:
        parsed = urlparse(value)
        candidate = unquote(parsed.path)
        if sys.platform == "win32" and len(candidate) >= 3 and candidate[0] == "/" and candidate[2] == ":":
            candidate = candidate[1:]
        return Path(candidate).resolve()

    def execute(
        self,
        root: Path,
        *,
        package_root: Path,
        approved_content_digest: str,
        mutate_during_analysis: bool = False,
    ) -> dict:
        dart, toolchain_binding = create_test_dart_sdk(root / "host" / "dart-sdk")
        flutter_root = create_test_package(
            root / "flutter-package", name="flutter", marker="framework"
        )
        product, config_path, config, run_pin = self.make_product(
            root,
            package_root=package_root,
            flutter_root=flutter_root,
            toolchain_binding=toolchain_binding,
            approved_content_digest=approved_content_digest,
        )

        def which(name: str) -> str | None:
            if name == "dart":
                return str(dart)
            return None

        def invoke(command, **kwargs):
            if "--version" in command:
                return subprocess.CompletedProcess(
                    command, 0, "Dart SDK version: 3.12.0", ""
                )
            stage = Path(kwargs["cwd"])
            staged_config = json.loads(
                (stage / ".dart_tool" / "package_config.json").read_text(
                    encoding="utf-8"
                )
            )
            entry = next(
                item
                for item in staged_config["packages"]
                if item["name"] == "example_company_design_system"
            )
            staged_package = self.uri_path(entry["rootUri"])
            self.assertNotEqual(staged_package, package_root.resolve())
            self.assertTrue(staged_package.is_relative_to(stage.resolve()))
            self.assertEqual(
                (staged_package / "lib" / "design.dart").read_text(
                    encoding="utf-8"
                ),
                (package_root / "lib" / "design.dart").read_text(
                    encoding="utf-8"
                ),
            )
            if mutate_during_analysis:
                (package_root / "lib" / "design.dart").write_text(
                    "const packageMarker = 'mutated-during-analysis';\n",
                    encoding="utf-8",
                )
            diagnostic = (
                "WARNING|STATIC_WARNING|"
                "design_system_guardian_flutter/guardian_compilation_unit_attestation|"
                f"{stage / 'lib' / 'main.dart'}|1|1|1|"
                f"{ATTESTATION_PREFIX}{config['configDigest']}"
            )
            return subprocess.CompletedProcess(command, 1, diagnostic + "\n", "")

        with mock.patch(
            "guardian_core.flutter_runner.shutil.which", side_effect=which
        ), mock.patch(
            "guardian_core.flutter_runner.subprocess.run", side_effect=invoke
        ):
            return run_flutter_analysis(
                project_root=product,
                adapter_config_path=config_path,
                run_pin=run_pin,
            )

    def test_approved_exact_package_is_copied_and_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = self.make_package(root / "approved-package")
            expected = independent_content_digest(package)
            evidence = self.execute(
                root,
                package_root=package,
                approved_content_digest=expected,
            )

            design_package = next(
                item for item in evidence["dependencies"]["packages"]
                if item["name"] == "example_company_design_system"
            )
            self.assertEqual(design_package["authority"], "catalog_approved")
            self.assertEqual(design_package["contentDigest"], expected)
            self.assertEqual(
                evidence["dependencies"]["digest"],
                sha256_digest(evidence["dependencies"]["packages"]),
            )
            self.assertEqual(
                verify_flutter_project_evidence(evidence), evidence["project"]
            )

    def test_package_config_path_override_with_counterfeit_same_uri_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = self.make_package(root / "approved-package")
            expected = independent_content_digest(approved)
            counterfeit = self.make_package(
                root / "counterfeit-package", marker="same-uri-counterfeit"
            )

            with self.assertRaisesRegex(
                FlutterRunnerIntegrityError, "contentDigest|content digest"
            ):
                self.execute(
                    root,
                    package_root=counterfeit,
                    approved_content_digest=expected,
                )

    def test_dependency_mutation_during_analysis_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = self.make_package(root / "approved-package")
            expected = independent_content_digest(package)
            with self.assertRaisesRegex(
                FlutterRunnerIntegrityError, "changed during analysis|dependency"
            ):
                self.execute(
                    root,
                    package_root=package,
                    approved_content_digest=expected,
                    mutate_during_analysis=True,
                )

    def test_excluded_cache_directory_cannot_hide_package_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = self.make_package(root / "approved-package")
            expected = independent_content_digest(package)
            (package / "build").mkdir()
            (package / "build" / "hidden-runtime.dart").write_text(
                "const hidden = true;\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                FlutterRunnerIntegrityError, "excluded|cache|artifact|directory"
            ):
                self.execute(
                    root,
                    package_root=package,
                    approved_content_digest=expected,
                )

    def test_dependency_mutation_before_finalization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = self.make_package(root / "approved-package")
            expected = independent_content_digest(package)
            evidence = self.execute(
                root,
                package_root=package,
                approved_content_digest=expected,
            )
            (package / "assets" / "icon.svg").write_text(
                "<svg><title>mutated-before-finalization</title></svg>\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                FlutterRunnerIntegrityError, "dependency|content|manifest"
            ):
                verify_flutter_project_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
