import copy
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


def create_minimal_flutter_project(root: Path, *, name: str = "flutter-product") -> Path:
    project = (root / name).absolute()
    (project / "lib").mkdir(parents=True)
    (project / "pubspec.yaml").write_text(
        "name: guardian_test_product\nenvironment:\n  sdk: '>=3.10.0 <4.0.0'\n",
        encoding="utf-8",
        newline="\n",
    )
    (project / "lib" / "main.dart").write_text(
        "void main() {}\n",
        encoding="utf-8",
        newline="\n",
    )
    return project.resolve(strict=True)

def prepare_contract_runner_dependencies(project_root: Path) -> Path:
    """Provision analyzer inputs before a read-only audit assertion."""

    from guardian_core.canonical import canonical_json_bytes

    root = project_root.resolve(strict=True)
    flutter_root = root.parent / f".{root.name}-guardian-flutter-artifact"
    (flutter_root / "lib").mkdir(parents=True, exist_ok=True)
    (flutter_root / "pubspec.yaml").write_text("name: flutter\n", encoding="utf-8")
    (flutter_root / "lib" / "flutter.dart").write_text("library flutter;\n", encoding="utf-8")
    package_config = {"configVersion": 2, "packages": [
        {"name": "guardian_test_product", "rootUri": "../", "packageUri": "lib/"},
        {"name": "flutter", "rootUri": flutter_root.resolve().as_uri() + "/", "packageUri": "lib/"},
    ]}
    (root / ".dart_tool").mkdir(exist_ok=True)
    (root / ".dart_tool" / "package_config.json").write_bytes(canonical_json_bytes(package_config))
    return flutter_root



def contract_runner_evidence(
    *,
    project_root: Path,
    adapter_config_path: Path,
    run_pin: Mapping[str, Any],
    expected_sentinels: Sequence[Mapping[str, Any]] = (),
    mutate_adapter_result: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Return trusted-runner-shaped evidence over one real temporary project."""

    from guardian_core.canonical import read_canonical_json, sha256_digest
    from guardian_core.flutter_dependencies import (
        _root_identity as dependency_root_identity,
        package_file_manifest,
    )
    from guardian_core.flutter_packages import package_content_digest
    from guardian_core.flutter_runner import (
        _analysis_inputs,
        _git_commit,
        _root_identity,
        enumerate_relevant_dart_files,
    )
    from guardian_core.flutter_toolchain import (
        current_platform_id,
        dart_sdk_content_digest,
        dart_sdk_file_manifest,
        prepare_dart_sdk_artifact,
    )
    from tests.test_flutter_adapter_normalization_dsg003 import clean_flutter_result

    root = project_root.resolve(strict=True)
    config = read_canonical_json(adapter_config_path)
    flutter_root = prepare_contract_runner_dependencies(root)

    sdk_root = root.parent / f".{root.name}-guardian-dart-sdk"
    executable_relative = "bin/dart.exe" if os.name == "nt" else "bin/dart"
    executable = sdk_root / executable_relative
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"guardian-test-dart")
    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    (sdk_root / "bin" / "snapshots").mkdir(parents=True, exist_ok=True)
    (sdk_root / "bin" / "snapshots" / "analysis_server.dart.snapshot").write_bytes(b"snapshot")
    (sdk_root / "lib" / "core").mkdir(parents=True, exist_ok=True)
    (sdk_root / "lib" / "core" / "core.dart").write_text("library dart.core;\n", encoding="utf-8")
    sdk_files = dart_sdk_file_manifest(sdk_root, executable_relative_path=executable_relative)
    toolchain = prepare_dart_sdk_artifact(
        executable,
        binding={
            "platformId": current_platform_id(),
            "dartSdk": {
                "contentDigest": dart_sdk_content_digest(sdk_files),
                "executableRelativePath": executable_relative,
            },
        },
        product_root=root,
    )
    files = enumerate_relevant_dart_files(root)
    analysis_inputs = _analysis_inputs(root)
    adapter_result = clean_flutter_result(
        dict(run_pin), assessed_files=len(files), total_files=len(files)
    )
    adapter_result["binding"]["configDigest"] = config["configDigest"]
    if mutate_adapter_result is not None:
        mutate_adapter_result(adapter_result)

    sentinel_manifest = [copy.deepcopy(dict(item)) for item in expected_sentinels]
    package_files = package_file_manifest(flutter_root)
    dependency_items = [{
        "name": "flutter",
        "authority": "profile_required",
        "canonicalRoot": str(flutter_root.resolve(strict=True)),
        "rootIdentity": dependency_root_identity(flutter_root.resolve(strict=True)),
        "packageUri": "lib/",
        "contentDigest": package_content_digest(package_files),
        "repositoryCommit": "f" * 40,
        "files": package_files,
        "fileManifestDigest": sha256_digest(package_files),
    }]
    return {
        "schemaVersion": 1,
        "runner": "design-system-guardian-host",
        "runnerVersion": "0.1.0",
        "toolchain": toolchain,
        "project": {
            "canonicalRoot": str(root),
            "rootIdentity": _root_identity(root),
            "gitCommit": _git_commit(root),
            "files": files,
            "assessedTreeDigest": sha256_digest(files),
            "analysisInputs": analysis_inputs,
            "analysisInputsDigest": sha256_digest(analysis_inputs),
        },
        "analyzer": {
            "tool": "dart",
            "executablePath": "host-test-double",
            "executableSha256": "a" * 64,
            "versionOutputDigest": "b" * 64,
            "adapterBundleDigest": "c" * 64,
            "command": ["analyze", "--format", "machine"],
            "exitCode": 0,
            "nonGuardianDiagnosticsDigest": sha256_digest([]),
        },
        "dependencies": {
            "schemaVersion": 1,
            "algorithm": "design-system-guardian.flutter-package-content.v1",
            "scope": "complete_package_config_closure",
            "packages": dependency_items,
            "digest": sha256_digest(dependency_items),
        },
        "sentinelEvidenceDigest": sha256_digest(sentinel_manifest),
        "runPinDigest": sha256_digest(dict(run_pin)),
        "adapterResult": adapter_result,
    }


def runner_side_effect(
    mutate_adapter_result: Callable[[dict[str, Any]], None] | None = None,
) -> Callable[..., dict[str, Any]]:
    def run(**kwargs: Any) -> dict[str, Any]:
        return contract_runner_evidence(
            **kwargs,
            mutate_adapter_result=mutate_adapter_result,
        )

    return run
