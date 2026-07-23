from __future__ import annotations

import os
import stat
from pathlib import Path

from guardian_core.flutter_dependencies import package_file_manifest
from guardian_core.flutter_packages import package_content_digest
from guardian_core.flutter_toolchain import (
    current_platform_id,
    dart_sdk_content_digest,
    dart_sdk_file_manifest,
    expected_dart_executable,
)


def create_test_dart_sdk(root: Path, *, marker: str = "trusted") -> tuple[Path, dict]:
    platform_id = current_platform_id()
    executable_relative = expected_dart_executable(platform_id)
    executable = root / executable_relative
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(f"dart-{marker}".encode("utf-8"))
    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    (root / "bin" / "snapshots").mkdir(parents=True, exist_ok=True)
    (root / "bin" / "snapshots" / "analysis_server.dart.snapshot").write_bytes(
        f"snapshot-{marker}".encode("utf-8")
    )
    (root / "lib" / "core").mkdir(parents=True, exist_ok=True)
    (root / "lib" / "core" / "core.dart").write_text(
        f"library dart.core; // {marker}\n", encoding="utf-8"
    )
    files = dart_sdk_file_manifest(root, executable_relative_path=executable_relative)
    return executable, {
        "platformId": platform_id,
        "dartSdk": {
            "contentDigest": dart_sdk_content_digest(files),
            "executableRelativePath": executable_relative,
        },
    }


def create_test_package(
    root: Path,
    *,
    name: str,
    marker: str = "trusted",
) -> Path:
    (root / "lib").mkdir(parents=True, exist_ok=True)
    (root / "pubspec.yaml").write_text(
        f"name: {name}\nenvironment:\n  sdk: ^3.10.0\n",
        encoding="utf-8",
    )
    (root / "lib" / f"{name}.dart").write_text(
        f"const guardianMarker = '{marker}';\n", encoding="utf-8"
    )
    return root


def package_binding(root: Path, *, repository_commit: str = "f" * 40) -> dict:
    return {
        "contentDigest": package_content_digest(package_file_manifest(root)),
        "repositoryCommit": repository_commit,
    }
