from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from guardian_core.flutter_runner import (
    ATTESTATION_PREFIX,
    FlutterRunnerIntegrityError,
    run_flutter_analysis,
)


SDK_ALGORITHM = "design-system-guardian.dart-sdk-content.v1"
PACKAGE_ALGORITHM = "design-system-guardian.flutter-package-content.v1"


def host_platform_id() -> str:
    operating_system = {
        "win32": "windows",
        "linux": "linux",
        "darwin": "macos",
    }[sys.platform]
    architecture = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }[platform.machine().lower()]
    return f"{operating_system}-{architecture}"


def file_manifest(root: Path) -> list[dict[str, str]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    ]


def sdk_digest(root: Path) -> str:
    return sha256_digest(
        {
            "schemaVersion": 1,
            "algorithm": SDK_ALGORITHM,
            "files": file_manifest(root),
        }
    )


def package_digest(root: Path) -> str:
    return sha256_digest(
        {
            "schemaVersion": 1,
            "algorithm": PACKAGE_ALGORITHM,
            "files": file_manifest(root),
        }
    )


class FlutterProfileToolchainTests(unittest.TestCase):
    def make_sdk(self, root: Path, *, marker: str) -> tuple[Path, str]:
        executable_relative = "bin/dart.exe" if os.name == "nt" else "bin/dart"
        executable = root / executable_relative
        executable.parent.mkdir(parents=True)
        executable.write_bytes(("dart-" + marker).encode("utf-8"))
        if os.name != "nt":
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        (root / "bin" / "snapshots").mkdir()
        (root / "bin" / "snapshots" / "analysis_server.dart.snapshot").write_bytes(
            ("analysis-server-" + marker).encode("utf-8")
        )
        (root / "lib" / "core").mkdir(parents=True)
        (root / "lib" / "core" / "core.dart").write_text(
            "library dart.core; // " + marker + "\n", encoding="utf-8"
        )
        (root / "version").write_text("3.11.0\n", encoding="utf-8")
        return executable, executable_relative

    def make_package(self, root: Path, *, name: str, marker: str) -> Path:
        (root / "lib").mkdir(parents=True)
        (root / "pubspec.yaml").write_text(
            f"name: {name}\nenvironment:\n  sdk: ^3.10.0\n",
            encoding="utf-8",
        )
        (root / "lib" / f"{name}.dart").write_text(
            f"const marker = '{marker}';\n", encoding="utf-8"
        )
        return root

    def make_project(
        self,
        root: Path,
        *,
        flutter_root: Path,
        design_root: Path | None = None,
    ) -> Path:
        project = root / "product"
        (project / "lib").mkdir(parents=True)
        (project / ".dart_tool").mkdir()
        (project / "pubspec.yaml").write_text(
            "name: guarded_product\nenvironment:\n  sdk: ^3.10.0\n",
            encoding="utf-8",
        )
        imports = ["import 'package:flutter/flutter.dart';"]
        packages = [
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
        ]
        if design_root is not None:
            imports.append("import 'package:approved_ds/approved_ds.dart';")
            packages.append(
                {
                    "name": "approved_ds",
                    "rootUri": design_root.resolve().as_uri() + "/",
                    "packageUri": "lib/",
                    "languageVersion": "3.10",
                }
            )
        (project / "lib" / "main.dart").write_text(
            "\n".join(imports) + "\nvoid main() {}\n", encoding="utf-8"
        )
        (project / ".dart_tool" / "package_config.json").write_bytes(
            canonical_json_bytes({"configVersion": 2, "packages": packages})
        )
        return project

    def make_config(
        self,
        root: Path,
        *,
        trusted_sdk: Path,
        executable_relative: str,
        trusted_flutter: Path,
        design_root: Path | None = None,
    ) -> tuple[Path, dict, dict]:
        source_cut = {"figma": "v1"}
        approved_packages = {}
        identities = {
            "colors": [],
            "textStyles": [],
            "icons": [],
            "dimensions": [],
            "effects": [],
            "motion": [],
            "widgets": [],
        }
        if design_root is not None:
            approved_packages["approved_ds"] = {
                "contentDigest": package_digest(design_root),
                "repositoryCommit": "d" * 40,
            }
            identities["colors"] = [
                "package:approved_ds/approved_ds.dart#ApprovedColors.primary"
            ]
        config = {
            "schemaVersion": 1,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "profileId": "example-company",
            "policyDigest": "a" * 64,
            "snapshotId": "b" * 64,
            "sourceCutDigest": sha256_digest(source_cut),
            "toolchain": {
                "platformId": host_platform_id(),
                "dartSdk": {
                    "contentDigest": sdk_digest(trusted_sdk),
                    "executableRelativePath": executable_relative,
                },
            },
            "requiredPackages": {
                "flutter": {
                    "contentDigest": package_digest(trusted_flutter),
                    "repositoryCommit": "f" * 40,
                }
            },
            "approvedPackages": approved_packages,
            "approvedIdentities": identities,
            "componentVariants": {},
        }
        config["configDigest"] = sha256_digest(config)
        config_path = root / "host" / "flutter-adapter.json"
        config_path.parent.mkdir(exist_ok=True)
        config_path.write_bytes(canonical_json_bytes(config))
        run_pin = {
            "schemaVersion": 1,
            "runId": "profile-bound-run",
            "profileId": "example-company",
            "snapshotId": "b" * 64,
            "policyDigest": "a" * 64,
            "sourceCut": source_cut,
        }
        return config_path, config, run_pin

    def test_path_planted_self_attesting_dart_is_not_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted_sdk = root / "trusted-sdk"
            _, executable_relative = self.make_sdk(trusted_sdk, marker="trusted")
            fake_sdk = root / "path-planted-sdk"
            fake_executable, _ = self.make_sdk(fake_sdk, marker="attacker")
            trusted_flutter = self.make_package(
                root / "trusted-flutter", name="flutter", marker="trusted"
            )
            project = self.make_project(root, flutter_root=trusted_flutter)
            config_path, config, run_pin = self.make_config(
                root,
                trusted_sdk=trusted_sdk,
                executable_relative=executable_relative,
                trusted_flutter=trusted_flutter,
            )

            def malicious_run(command, **kwargs):
                if "--version" in command:
                    return subprocess.CompletedProcess(
                        command, 0, "Dart SDK version: 3.11.0", ""
                    )
                stage = Path(kwargs["cwd"])
                attestation = (
                    "WARNING|STATIC_WARNING|"
                    "design_system_guardian_flutter/guardian_compilation_unit_attestation|"
                    f"{stage / 'lib' / 'main.dart'}|1|1|1|"
                    f"{ATTESTATION_PREFIX}{config['configDigest']}\n"
                )
                return subprocess.CompletedProcess(command, 0, attestation, "")

            with mock.patch(
                "guardian_core.flutter_runner.shutil.which",
                side_effect=lambda name: str(fake_executable) if name == "dart" else None,
            ), mock.patch(
                "guardian_core.flutter_runner.subprocess.run", side_effect=malicious_run
            ):
                with self.assertRaisesRegex(
                    FlutterRunnerIntegrityError,
                    "profile-bound Dart SDK|Dart SDK content",
                ):
                    run_flutter_analysis(
                        project_root=project,
                        adapter_config_path=config_path,
                        run_pin=run_pin,
                    )

    def test_counterfeit_flutter_is_rejected_with_empty_and_nonempty_design_mappings(self) -> None:
        for mapped in (False, True):
            with self.subTest(mapped=mapped), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                trusted_sdk = root / "trusted-sdk"
                trusted_executable, executable_relative = self.make_sdk(
                    trusted_sdk, marker="trusted"
                )
                trusted_flutter = self.make_package(
                    root / "trusted-flutter", name="flutter", marker="trusted"
                )
                counterfeit_flutter = self.make_package(
                    root / "counterfeit-flutter", name="flutter", marker="counterfeit"
                )
                design_root = (
                    self.make_package(
                        root / "approved-ds", name="approved_ds", marker="approved"
                    )
                    if mapped
                    else None
                )
                project = self.make_project(
                    root,
                    flutter_root=counterfeit_flutter,
                    design_root=design_root,
                )
                config_path, _, run_pin = self.make_config(
                    root,
                    trusted_sdk=trusted_sdk,
                    executable_relative=executable_relative,
                    trusted_flutter=trusted_flutter,
                    design_root=design_root,
                )
                with mock.patch(
                    "guardian_core.flutter_runner.shutil.which",
                    side_effect=lambda name: str(trusted_executable)
                    if name == "dart"
                    else None,
                ):
                    with self.assertRaisesRegex(
                        FlutterRunnerIntegrityError,
                        "required package|contentDigest|content digest",
                    ):
                        run_flutter_analysis(
                            project_root=project,
                            adapter_config_path=config_path,
                            run_pin=run_pin,
                        )


if __name__ == "__main__":
    unittest.main()
