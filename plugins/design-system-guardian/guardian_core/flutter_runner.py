"""Host-owned Flutter analyzer runner with complete compilation-unit proof.

The runner never accepts a caller-authored analyzer result. It hashes the
product sources, analyzes an external staging copy with the shipped Guardian
plugin, verifies one config-bound attestation per Dart unit, and only then
derives the adapter result consumed by the audit boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlparse

from .audit import AUDIT_CATEGORIES
from .canonical import canonical_json_bytes, read_canonical_json, sha256_digest
from .flutter_adapter import (
    FlutterAdapterIntegrityError,
    _validate_run_pin as _validate_adapter_run_pin,
)
from .contracts import ExitCode
from .flutter_dependencies import (
    FlutterDependencyIntegrityError,
    prepare_dependency_bundle,
    stage_dependency_bundle,
    verify_dependency_bundle,
)
from .flutter_packages import (
    FlutterPackageProvenanceError,
    validate_approved_package_bindings,
    validate_required_package_bindings,
)
from .flutter_toolchain import (
    FlutterToolchainIntegrityError,
    FlutterToolchainUnsupportedError,
    current_platform_id,
    prepare_dart_sdk_artifact,
    stage_dart_sdk_artifact,
    validate_toolchain_binding,
    verify_dart_sdk_evidence,
)
from .paths import is_link_or_reparse
from .project_binding import ProjectBindingError, observe_git_commit


ATTESTATION_PREFIX = "DSG_ATTESTATION_V1 configDigest="


class FlutterRunnerIntegrityError(ValueError):
    """The host could not prove complete, config-bound Flutter analysis."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


class FlutterRunnerUnsupportedError(FlutterRunnerIntegrityError):
    """A supported Dart/Flutter analyzer runtime is not available."""

    exit_code = ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE


_ADAPTER_VERSION = "0.1.0"
_RUNNER_VERSION = "0.1.0"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROFILE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_EXCLUDED_DIRECTORIES = {
    ".git",
    ".idea",
    ".pub-cache",
    "build",
    "coverage",
}
_CONFIG_V1_KEYS = {
    "schemaVersion",
    "adapter",
    "adapterVersion",
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "configDigest",
    "toolchain",
    "requiredPackages",
    "approvedPackages",
    "approvedIdentities",
    "componentVariants",
}
_CONFIG_V2_KEYS = _CONFIG_V1_KEYS | {
    "ruleSnapshotId",
    "rulesDigest",
    "activeUsageRules",
    "usageRuleCoverage",
}
_CONFIG_V3_KEYS = _CONFIG_V2_KEYS | {
    "runId",
    "evaluatorId",
    "evaluatorContractDigest",
    "authorizationDigest",
}
_USAGE_NOT_ASSESSED_CODE = "guardian_usage_rule_not_assessed"
_USAGE_NOT_ASSESSED_MESSAGE = re.compile(
    r"^DSG_USAGE_RULE_NOT_ASSESSED_V1 "
    r"ruleId=([a-z][a-z0-9]*(?:[._-][a-z0-9]+)*) "
    r"reasonCode=incomplete_construction_graph$"
)
_GUARDIAN_CODES = {
    "guardian_unapproved_visual_primitive": ("components",),
    "guardian_unapproved_widget": ("components",),
    "guardian_unapproved_component_variant": ("components",),
    "guardian_usage_rule": ("components",),
    "guardian_sentinel_present": ("components",),
    "guardian_unapproved_icon": ("icons",),
    "guardian_unapproved_color": ("colors",),
    "guardian_unapproved_text_style": ("typography",),
    "guardian_unapproved_dimension": ("spacing",),
    "guardian_unapproved_radius": ("radii",),
    "guardian_unapproved_effect": ("effects",),
    "guardian_unapproved_motion": ("motion",),
    "guardian_suppression_forbidden": AUDIT_CATEGORIES,
}
_SOURCE_IGNORE = re.compile(
    r"(?:ignore(?:_for_file)?\s*:).*?(?:design_system_guardian_flutter/|guardian_)",
    re.IGNORECASE,
)
_DIAGNOSTIC_DISABLE = re.compile(
    r"(?:guardian_[a-z0-9_]+|design_system_guardian_flutter)\s*:\s*(?:false|ignore)\b",
    re.IGNORECASE,
)
_BYPASS_MARKER = re.compile(r"guardian(?:\s*:\s*ignore|-ignore|_bypass)", re.IGNORECASE)
_SENTINEL_KINDS = {
    "icon": "package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingKind.icon",
    "color": "package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingKind.color",
    "textStyle": "package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingKind.textStyle",
    "component": "package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingKind.component",
    "token": "package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingKind.token",
}


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _regular_unredirected_file(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise FlutterRunnerIntegrityError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FlutterRunnerIntegrityError(f"{label} must be a regular file.")
    if is_link_or_reparse(path.expanduser().absolute()):
        raise FlutterRunnerIntegrityError(f"{label} may not be a link or reparse point.")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_root(project_root: Path) -> Path:
    try:
        root = project_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise FlutterRunnerIntegrityError(f"Flutter project root is unavailable: {error}") from error
    if not root.is_dir() or is_link_or_reparse(project_root.expanduser().absolute()):
        raise FlutterRunnerIntegrityError("Flutter project root must be an unredirected directory.")
    if not (root / "pubspec.yaml").is_file():
        raise FlutterRunnerIntegrityError("Flutter project root must contain pubspec.yaml.")
    return root


def enumerate_relevant_dart_files(project_root: Path) -> list[dict[str, str]]:
    """Return the exact, sorted SHA-256 inventory that analysis must attest."""

    root = _project_root(project_root)
    output: list[dict[str, str]] = []
    case_keys: set[str] = set()
    for directory, child_directories, names in os.walk(root, followlinks=False):
        current = Path(directory)
        for child in list(child_directories):
            candidate = current / child
            if child in _EXCLUDED_DIRECTORIES:
                child_directories.remove(child)
                continue
            if is_link_or_reparse(candidate):
                raise FlutterRunnerIntegrityError(
                    f"Relevant source traversal may not cross a link or reparse point: {candidate}"
                )
        child_directories.sort()
        for name in sorted(names):
            if not name.endswith(".dart"):
                continue
            path = current / name
            if is_link_or_reparse(path):
                raise FlutterRunnerIntegrityError(
                    f"Relevant Dart source may not be a link or reparse point: {path}"
                )
            relative = path.relative_to(root).as_posix()
            folded = relative.casefold()
            if folded in case_keys:
                raise FlutterRunnerIntegrityError("Relevant Dart paths collide under case folding.")
            case_keys.add(folded)
            output.append({"path": relative, "sha256": _sha256_file(path)})
    output.sort(key=lambda item: item["path"])
    if not output:
        raise FlutterRunnerIntegrityError("Flutter analysis requires at least one relevant Dart file.")
    return output


def _analysis_inputs(root: Path) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for relative in (
        ".dart_tool/package_config.json",
        ".dart_tool/package_graph.json",
        "analysis_options.yaml",
        "pubspec.lock",
        "pubspec.yaml",
    ):
        path = root / PurePosixPath(relative)
        if not path.exists():
            continue
        if is_link_or_reparse(path) or not path.is_file():
            raise FlutterRunnerIntegrityError(
                f"Analyzer-influencing input may not be redirected: {relative}"
            )
        output.append({"path": relative, "sha256": _sha256_file(path)})
    output.sort(key=lambda item: item["path"])
    if not any(item["path"] == "pubspec.yaml" for item in output):
        raise FlutterRunnerIntegrityError("Analyzer input manifest is missing pubspec.yaml.")
    return output


def _root_identity(root: Path) -> str:
    metadata = root.stat()
    return sha256_digest({"canonicalPath": os.path.normcase(str(root)), "device": metadata.st_dev, "inode": metadata.st_ino})

def _validate_config(path: Path, root: Path) -> tuple[dict[str, Any], bytes]:
    config_path = _regular_unredirected_file(path, "Flutter adapter config")
    if _within(config_path, root):
        raise FlutterRunnerIntegrityError("Flutter adapter config must be host-owned outside the product tree.")
    payload = config_path.read_bytes()
    try:
        config = read_canonical_json(config_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise FlutterRunnerIntegrityError(f"Flutter adapter config is not canonical JSON: {error}") from error
    if not isinstance(config, dict):
        raise FlutterRunnerIntegrityError("Flutter adapter config must be an object.")
    schema_version = config.get("schemaVersion")
    expected_keys = (
        _CONFIG_V1_KEYS
        if schema_version == 1
        else _CONFIG_V2_KEYS
        if schema_version == 2
        else _CONFIG_V3_KEYS
        if schema_version == 3
        else None
    )
    if expected_keys is None or set(config) != expected_keys:
        raise FlutterRunnerIntegrityError("Flutter adapter config has unknown or missing fields.")
    if config.get("adapter") != "flutter" or config.get("adapterVersion") != _ADAPTER_VERSION:
        raise FlutterRunnerIntegrityError("Flutter adapter config schema or version is unsupported.")
    if not isinstance(config.get("profileId"), str) or not _PROFILE.fullmatch(config["profileId"]):
        raise FlutterRunnerIntegrityError("Flutter adapter config profileId is invalid.")
    for field in ("policyDigest", "sourceCutDigest", "configDigest"):
        if not isinstance(config.get(field), str) or not _DIGEST.fullmatch(config[field]):
            raise FlutterRunnerIntegrityError(f"Flutter adapter config {field} is invalid.")
    unsigned = dict(config)
    claimed = unsigned.pop("configDigest")
    if sha256_digest(unsigned) != claimed:
        raise FlutterRunnerIntegrityError("Flutter adapter configDigest does not bind its canonical content.")
    try:
        approved_packages = validate_approved_package_bindings(
            config.get("approvedPackages"),
            config.get("approvedIdentities"),
            config.get("componentVariants"),
        )
        validate_required_package_bindings(
            config.get("requiredPackages"), approved_packages=approved_packages
        )
        toolchain = validate_toolchain_binding(config.get("toolchain"))
        if toolchain["platformId"] != current_platform_id():
            raise FlutterToolchainIntegrityError(
                "Flutter adapter toolchain does not match the current host platform."
            )
    except (FlutterPackageProvenanceError, FlutterToolchainIntegrityError, AttributeError, TypeError) as error:
        raise FlutterRunnerIntegrityError(
            f"Flutter adapter package provenance is invalid: {error}"
        ) from error
    if schema_version in {2, 3}:
        try:
            from .flutter_config import FlutterConfigError, _validate_config_document

            _validate_config_document(config)
        except FlutterConfigError as error:
            raise FlutterRunnerIntegrityError(
                f"Flutter adapter usage-rule configuration is invalid: {error}"
            ) from error
    return config, payload


def _validate_run_pin(run_pin: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    try:
        normalized_pin = _validate_adapter_run_pin(dict(run_pin))
    except (FlutterAdapterIntegrityError, TypeError, ValueError) as error:
        raise FlutterRunnerIntegrityError(
            f"Guardian run pin is invalid: {error}"
        ) from error
    run_pin = normalized_pin
    expected = {
        "profileId": config["profileId"],
        "snapshotId": config["snapshotId"],
        "policyDigest": config["policyDigest"],
    }
    for field, value in expected.items():
        if run_pin[field] != value:
            raise FlutterRunnerIntegrityError(f"Guardian run pin {field} differs from adapter config.")
    if sha256_digest(run_pin["sourceCut"]) != config["sourceCutDigest"]:
        raise FlutterRunnerIntegrityError("Guardian run pin sourceCut differs from adapter config.")
    if config.get("schemaVersion") == 3 and run_pin["runId"] != config["runId"]:
        raise FlutterRunnerIntegrityError(
            "Guardian run pin runId differs from evaluator-v2 adapter config."
        )
    return json.loads(canonical_json_bytes(dict(run_pin)))


def _sentinel_evidence(
    expectations: Sequence[Mapping[str, Any]], config: Mapping[str, Any]
) -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    identities: set[tuple[str, str]] = set()
    for item in expectations:
        if not isinstance(item, Mapping) or set(item) != {"requestId", "kind", "policyDigest"}:
            raise FlutterRunnerIntegrityError("Sentinel expectation has unknown or missing fields.")
        request_id = item.get("requestId")
        kind = item.get("kind")
        policy_digest = item.get("policyDigest")
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise FlutterRunnerIntegrityError("Sentinel expectation requestId is invalid.")
        if kind not in _SENTINEL_KINDS:
            raise FlutterRunnerIntegrityError("Sentinel expectation kind is invalid.")
        if policy_digest != config["policyDigest"]:
            raise FlutterRunnerIntegrityError("Sentinel expectation policyDigest differs from the pinned policy.")
        key = (request_id, str(kind))
        if key in identities:
            raise FlutterRunnerIntegrityError("Sentinel expectations contain a duplicate request and kind.")
        identities.add(key)
        entries.append(
            {
                "requestId": request_id,
                "kind": str(kind),
                "kindIdentity": _SENTINEL_KINDS[str(kind)],
                "policyDigest": policy_digest,
            }
        )
    entries.sort(key=lambda item: (item["requestId"], item["kind"]))
    return {
        "schemaVersion": 1,
        "configDigest": config["configDigest"],
        "policyDigest": config["policyDigest"],
        "sentinels": entries,
    }


def _scan_suppressions(root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    candidates: list[Path] = []
    for directory, child_directories, names in os.walk(root, followlinks=False):
        child_directories[:] = sorted(name for name in child_directories if name not in _EXCLUDED_DIRECTORIES)
        for name in sorted(names):
            path = Path(directory, name)
            if path.suffix == ".dart" or name == "analysis_options.yaml" or path.suffix in {".yaml", ".yml"}:
                candidates.append(path)
    for path in sorted(candidates, key=lambda item: item.relative_to(root).as_posix()):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            raise FlutterRunnerIntegrityError(f"Cannot scan suppression source {path}: {error}") from error
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(lines, start=1):
            if _SOURCE_IGNORE.search(line):
                kind = "source_ignore"
            elif _DIAGNOSTIC_DISABLE.search(line):
                kind = "diagnostic_disable"
            elif _BYPASS_MARKER.search(line):
                kind = "guardian_bypass_marker"
            else:
                continue
            findings.append({"path": relative, "line": line_number, "text": line.strip(), "kind": kind})
    findings.sort(key=lambda item: (item["path"], item["line"], item["text"]))
    return {"schemaVersion": 1, "method": "conservative_text_scan", "astProof": False, "findings": findings}


def _adapter_bundle() -> tuple[Path, str]:
    adapter = Path(__file__).resolve().parents[1] / "adapters" / "flutter"
    if not adapter.is_dir():
        raise FlutterRunnerIntegrityError("Shipped Flutter analyzer adapter is unavailable.")
    files: list[dict[str, str]] = []
    for path in sorted(adapter.rglob("*")):
        if not path.is_file() or any(part in {".dart_tool", "build", "__pycache__"} for part in path.parts):
            continue
        if is_link_or_reparse(path):
            raise FlutterRunnerIntegrityError("Shipped Flutter analyzer adapter may not contain redirected files.")
        files.append({"path": path.relative_to(adapter).as_posix(), "sha256": _sha256_file(path)})
    return adapter, sha256_digest(files)


def _select_analyzer(
    root: Path, binding: Mapping[str, Any]
) -> tuple[Path, dict[str, Any]]:
    """Use PATH only to discover an executable inside the exact profile-bound SDK."""

    value = shutil.which("dart")
    if value is None:
        raise FlutterRunnerUnsupportedError(
            "The profile-bound Dart analyzer executable is not discoverable on PATH."
        )
    try:
        evidence = prepare_dart_sdk_artifact(
            Path(value), binding=binding, product_root=root
        )
    except FlutterToolchainUnsupportedError as error:
        raise FlutterRunnerUnsupportedError(str(error)) from error
    except FlutterToolchainIntegrityError as error:
        raise FlutterRunnerIntegrityError(str(error)) from error
    canonical_executable = (
        Path(evidence["canonicalRoot"])
        / PurePosixPath(evidence["executableRelativePath"])
    )
    return canonical_executable, evidence


def _minimal_analyzer_environment(stage: Path, executable: Path) -> dict[str, str]:
    home = stage / ".guardian-runtime" / "home"
    cache = stage / ".guardian-runtime" / "pub-cache"
    temporary = stage / ".guardian-runtime" / "tmp"
    for directory in (home, cache, temporary):
        directory.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": str(executable.parent),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PUB_CACHE": str(cache),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "CI": "true",
        "DART_DISABLE_ANALYTICS": "true",
    }
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "COMSPEC", "SYSTEMDRIVE"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
    return environment


def _probe_analyzer_version(
    executable: Path, environment: Mapping[str, str]
) -> str:
    try:
        version = subprocess.run(
            [str(executable), "--version"],
            cwd=str(executable.parent),
            env=dict(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FlutterRunnerIntegrityError(
            f"Cannot execute staged profile-bound Dart analyzer version probe: {error}"
        ) from error
    version_text = (version.stdout + "\n" + version.stderr).strip()
    if version.returncode != 0 or not version_text:
        raise FlutterRunnerUnsupportedError(
            "Staged profile-bound Dart analyzer version probe is incompatible."
        )
    match = re.search(r"(?:Dart SDK version:|Dart)\s*(\d+)\.(\d+)", version_text, re.IGNORECASE)
    if match is None:
        raise FlutterRunnerUnsupportedError(
            "Staged profile-bound Dart runtime did not report a compatible version."
        )
    major, minor = (int(match.group(1)), int(match.group(2)))
    if (major, minor) < (3, 12):
        raise FlutterRunnerUnsupportedError("Dart 3.12 or newer is required by the stable Flutter 3.44 adapter line.")
    return sha256_digest(version_text.encode("utf-8"))


def _git_commit(root: Path) -> str | None:
    try:
        return observe_git_commit(root)
    except ProjectBindingError as error:
        raise FlutterRunnerIntegrityError(
            f"Cannot observe local Git metadata without executing Git: {error}"
        ) from error


def _stage_project(root: Path, stage: Path, files: Sequence[Mapping[str, str]], adapter: Path) -> None:
    for item in files:
        source = root / PurePosixPath(item["path"])
        destination = stage / PurePosixPath(item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for relative in ("pubspec.yaml", "pubspec.lock", ".dart_tool/package_config.json", ".dart_tool/package_graph.json"):
        source = root / PurePosixPath(relative)
        if source.is_file() and not is_link_or_reparse(source):
            destination = stage / PurePosixPath(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    original_options = root / "analysis_options.yaml"
    include = ""
    if original_options.is_file():
        shutil.copyfile(original_options, stage / "analysis_options.guardian-base.yaml")
        include = "include: analysis_options.guardian-base.yaml\n"
    diagnostics = "\n".join(
        f"      {code}: true" for code in sorted((*_GUARDIAN_CODES, _USAGE_NOT_ASSESSED_CODE, "guardian_compilation_unit_attestation", "guardian_invalid_config_binding"))
    )
    options = (
        include
        + "plugins:\n"
        + "  design_system_guardian_flutter:\n"
        + f"    path: {json.dumps(adapter.as_posix())}\n"
        + "    diagnostics:\n"
        + diagnostics
        + "\n"
    )
    (stage / "analysis_options.yaml").write_text(options, encoding="utf-8", newline="\n")


def _relative_diagnostic_path(value: str, stage: Path) -> str:
    candidate = value
    if value.startswith("file:"):
        parsed = urlparse(value)
        candidate = unquote(parsed.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", candidate):
            candidate = candidate[1:]
    path = Path(candidate)
    if not path.is_absolute():
        path = stage / path
    try:
        relative = path.resolve(strict=False).relative_to(stage.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as error:
        raise FlutterRunnerIntegrityError("Analyzer diagnostic path escapes the staged product.") from error
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or relative.startswith("./"):
        raise FlutterRunnerIntegrityError("Analyzer diagnostic path is not canonical.")
    return pure.as_posix()


def _parse_machine_output(
    output: str,
    *,
    stage: Path,
    files: Sequence[Mapping[str, str]],
    config_digest: str,
    allow_usage_markers: bool = False,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    expected_paths = {item["path"] for item in files}
    attestations: dict[str, int] = {}
    guardian: list[dict[str, Any]] = []
    usage_markers: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        fields = raw_line.split("|", 7)
        if len(fields) != 8:
            raise FlutterRunnerIntegrityError(
                "Analyzer machine output contains a malformed record."
            )
        (
            severity,
            diagnostic_type,
            raw_code,
            raw_path,
            line,
            column,
            length,
            message,
        ) = fields
        try:
            numeric = (int(line), int(column), int(length))
        except ValueError as error:
            raise FlutterRunnerIntegrityError(
                "Analyzer machine output location is malformed."
            ) from error
        if (
            severity not in {"INFO", "WARNING", "ERROR"}
            or numeric[0] < 1
            or numeric[1] < 1
            or numeric[2] < 0
        ):
            raise FlutterRunnerIntegrityError(
                "Analyzer machine output location or severity is invalid."
            )
        relative = _relative_diagnostic_path(raw_path, stage)
        code = raw_code.lower()
        record = {
            "severity": severity,
            "code": code,
            "path": relative,
            "line": numeric[0],
            "column": numeric[1],
            "length": numeric[2],
            "message": message,
        }
        namespace = "design_system_guardian_flutter/"
        if code == namespace + "guardian_compilation_unit_attestation":
            expected_message = ATTESTATION_PREFIX + config_digest
            if message != expected_message:
                raise FlutterRunnerIntegrityError(
                    "Compilation-unit attestation configDigest is mismatched."
                )
            if relative not in expected_paths:
                raise FlutterRunnerIntegrityError(
                    "Compilation-unit attestation names an unassessed file."
                )
            attestations[relative] = attestations.get(relative, 0) + 1
            if attestations[relative] != 1:
                raise FlutterRunnerIntegrityError(
                    "Compilation-unit attestation is duplicated."
                )
            continue
        if code.startswith(namespace):
            short = code[len(namespace) :]
            if short == "guardian_invalid_config_binding":
                raise FlutterRunnerIntegrityError(
                    "Analyzer reported invalid Guardian config binding."
                )
            if short == _USAGE_NOT_ASSESSED_CODE:
                if (
                    not allow_usage_markers
                    or _USAGE_NOT_ASSESSED_MESSAGE.fullmatch(message) is None
                ):
                    raise FlutterRunnerIntegrityError(
                        "Analyzer reported invalid usage-rule coverage evidence."
                    )
                record["code"] = short
                usage_markers.append(record)
                continue
            if short not in _GUARDIAN_CODES:
                raise FlutterRunnerIntegrityError(
                    f"Analyzer reported unknown Guardian diagnostic: {short}."
                )
            record["code"] = short
            guardian.append(record)
        else:
            record["diagnosticType"] = diagnostic_type
            other.append(record)
    missing = sorted(expected_paths - set(attestations))
    if missing:
        raise FlutterRunnerIntegrityError(
            "Compilation-unit attestation is missing for: " + ", ".join(missing)
        )
    if any(item["severity"] == "ERROR" for item in other):
        raise FlutterRunnerIntegrityError(
            "A non-Guardian analyzer error makes file coverage incomplete."
        )
    diagnostic_key = lambda item: (
        item["path"],
        item["line"],
        item["column"],
        item["code"],
        item["message"],
    )
    guardian.sort(key=diagnostic_key)
    usage_markers.sort(key=diagnostic_key)
    other.sort(key=canonical_json_bytes)
    return guardian, other, usage_markers


def _binding(config: Mapping[str, Any]) -> dict[str, str]:
    return {
        "profileId": config["profileId"],
        "policyDigest": config["policyDigest"],
        "snapshotId": config["snapshotId"],
        "sourceCutDigest": config["sourceCutDigest"],
        "configDigest": config["configDigest"],
    }


def run_flutter_analysis(
    *,
    project_root: Path,
    adapter_config_path: Path,
    run_pin: Mapping[str, Any],
    expected_sentinels: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Execute and attest one complete read-only Flutter product analysis."""

    root = _project_root(project_root)
    files = enumerate_relevant_dart_files(root)
    analysis_inputs = _analysis_inputs(root)
    config, config_bytes = _validate_config(adapter_config_path, root)
    normalized_pin = _validate_run_pin(run_pin, config)
    try:
        package_config, dependencies = prepare_dependency_bundle(
            root, config["approvedPackages"], config["requiredPackages"]
        )
    except FlutterDependencyIntegrityError as error:
        raise FlutterRunnerIntegrityError(str(error)) from error
    sentinel_evidence = _sentinel_evidence(expected_sentinels, config)
    suppression_scan = _scan_suppressions(root)
    adapter, adapter_digest = _adapter_bundle()
    discovered_executable, toolchain_evidence = _select_analyzer(
        root, config["toolchain"]
    )
    root_identity = _root_identity(root)
    git_commit_before = _git_commit(root)

    with tempfile.TemporaryDirectory(prefix="design-system-guardian-flutter-") as temporary:
        stage = Path(temporary).resolve(strict=True)
        if _within(stage, root) or _within(root, stage):
            raise FlutterRunnerIntegrityError("Host staging overlaps the product tree.")
        _stage_project(root, stage, files, adapter)
        try:
            stage_dependency_bundle(stage, package_config, dependencies)
            staged_executable = stage_dart_sdk_artifact(stage, toolchain_evidence)
        except (
            FlutterDependencyIntegrityError,
            FlutterToolchainIntegrityError,
        ) as error:
            raise FlutterRunnerIntegrityError(str(error)) from error
        host = stage / ".guardian-host"
        host.mkdir()
        staged_config = host / "flutter-adapter.json"
        staged_config.write_bytes(config_bytes)
        sentinel_path = host / "sentinel-evidence.json"
        sentinel_path.write_bytes(canonical_json_bytes(sentinel_evidence))
        environment = _minimal_analyzer_environment(stage, staged_executable)
        environment["DESIGN_SYSTEM_GUARDIAN_FLUTTER_CONFIG"] = str(staged_config)
        environment["DESIGN_SYSTEM_GUARDIAN_SENTINEL_EVIDENCE"] = str(sentinel_path)
        version_digest = _probe_analyzer_version(staged_executable, environment)
        command = [str(staged_executable), "analyze", "--format", "machine"]
        try:
            completed = subprocess.run(
                command,
                cwd=str(stage),
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FlutterRunnerIntegrityError(f"Host-owned Flutter analysis failed to execute: {error}") from error
        if completed.returncode < 0 or completed.returncode > 3:
            raise FlutterRunnerIntegrityError(
                "Dart analyzer exit code is outside the documented 0-3 range."
            )
        if completed.stderr.strip():
            raise FlutterRunnerIntegrityError("Dart analyzer wrote unexpected stderr; coverage is not trusted.")
        diagnostics, non_guardian, usage_markers = _parse_machine_output(
            completed.stdout,
            stage=stage,
            files=files,
            config_digest=config["configDigest"],
            allow_usage_markers=config.get("schemaVersion") == 3,
        )

    if enumerate_relevant_dart_files(root) != files:
        raise FlutterRunnerIntegrityError("Relevant Dart sources changed during analysis.")
    if _analysis_inputs(root) != analysis_inputs:
        raise FlutterRunnerIntegrityError("Analyzer-influencing input manifest changed during analysis.")
    try:
        verify_dependency_bundle(root, dependencies)
    except FlutterDependencyIntegrityError as error:
        raise FlutterRunnerIntegrityError(
            f"Governed dependency changed during analysis: {error}"
        ) from error
    try:
        verify_dart_sdk_evidence(toolchain_evidence, product_root=root)
    except FlutterToolchainIntegrityError as error:
        raise FlutterRunnerIntegrityError(
            f"Profile-bound Dart SDK changed during analysis: {error}"
        ) from error
    git_commit_after = _git_commit(root)
    if git_commit_after != git_commit_before:
        raise FlutterRunnerIntegrityError("Git commit changed during Flutter analysis.")
    if _regular_unredirected_file(adapter_config_path, "Flutter adapter config").read_bytes() != config_bytes:
        raise FlutterRunnerIntegrityError("Flutter adapter config changed during analysis.")

    counts = {category: 0 for category in AUDIT_CATEGORIES}
    for diagnostic in diagnostics:
        for category in _GUARDIAN_CODES[diagnostic["code"]]:
            counts[category] += 1
    usage_config_incomplete = (
        config.get("schemaVersion") in {2, 3}
        and config["usageRuleCoverage"]["status"] == "incomplete"
    )
    usage_runtime_incomplete = (
        config.get("schemaVersion") == 3 and bool(usage_markers)
    )
    usage_coverage_incomplete = (
        usage_config_incomplete or usage_runtime_incomplete
    )
    coverage = {
        category: {
            "status": (
                "not_assessed"
                if usage_coverage_incomplete and category == "components"
                else "allowed"
            ),
            "method": "dart_analyzer_ast",
            "diagnosticCount": counts[category],
        }
        for category in AUDIT_CATEGORIES
    }
    adapter_diagnostics = sorted(
        [*diagnostics, *usage_markers],
        key=lambda item: (
            item["path"],
            item["line"],
            item["column"],
            item["code"],
            item["message"],
        ),
    )
    production_ready = (
        not adapter_diagnostics
        and not suppression_scan["findings"]
        and not usage_coverage_incomplete
    )
    adapter_result = {
        "schemaVersion": 2 if config.get("schemaVersion") == 3 else 1,
        "adapter": "flutter",
        "adapterVersion": _ADAPTER_VERSION,
        "status": "not_assessed" if usage_coverage_incomplete else "allowed",
        "binding": _binding(config),
        "analysis": {
            "method": "dart_analyzer_ast",
            "complete": True,
            "assessedFiles": len(files),
            "totalFiles": len(files),
        },
        "diagnostics": adapter_diagnostics,
        "coverage": coverage,
        "suppressionScan": suppression_scan,
        "productionReady": production_ready,
    }
    return {
        "schemaVersion": 1,
        "runner": "design-system-guardian-host",
        "runnerVersion": _RUNNER_VERSION,
        "dependencies": dependencies,
        "toolchain": toolchain_evidence,
        "project": {
            "canonicalRoot": str(root),
            "rootIdentity": root_identity,
            "gitCommit": git_commit_before,
            "files": files,
            "assessedTreeDigest": sha256_digest(files),
            "analysisInputs": analysis_inputs,
            "analysisInputsDigest": sha256_digest(analysis_inputs),
        },
        "analyzer": {
            "tool": "dart",
            "executablePath": str(discovered_executable),
            "executableSha256": _sha256_file(discovered_executable),
            "versionOutputDigest": version_digest,
            "adapterBundleDigest": adapter_digest,
            "command": ["analyze", "--format", "machine"],
            "exitCode": completed.returncode,
            "nonGuardianDiagnosticsDigest": sha256_digest(non_guardian),
        },
        "sentinelEvidenceDigest": sha256_digest(sentinel_evidence),
        "runPinDigest": sha256_digest(normalized_pin),
        "adapterResult": adapter_result,
    }


def verify_flutter_project_evidence(runner_evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Revalidate sealed project evidence without writes or analyzer execution."""

    if not isinstance(runner_evidence, Mapping):
        raise FlutterRunnerIntegrityError("Flutter runner evidence must be an object.")
    project = runner_evidence.get("project")
    expected_keys = {
        "canonicalRoot",
        "rootIdentity",
        "gitCommit",
        "files",
        "assessedTreeDigest",
        "analysisInputs",
        "analysisInputsDigest",
    }
    if not isinstance(project, dict) or set(project) != expected_keys:
        raise FlutterRunnerIntegrityError("Flutter project evidence has unknown or missing fields.")
    canonical_root = project.get("canonicalRoot")
    if not isinstance(canonical_root, str) or not Path(canonical_root).is_absolute():
        raise FlutterRunnerIntegrityError("Flutter project evidence lacks an absolute canonical root.")
    root = _project_root(Path(canonical_root))
    if str(root) != canonical_root:
        raise FlutterRunnerIntegrityError("Flutter project canonical root was redirected or replayed.")
    files = enumerate_relevant_dart_files(root)
    inputs = _analysis_inputs(root)
    if files != project.get("files") or sha256_digest(files) != project.get("assessedTreeDigest"):
        raise FlutterRunnerIntegrityError("Relevant Dart source manifest changed after analysis.")
    if inputs != project.get("analysisInputs") or sha256_digest(inputs) != project.get("analysisInputsDigest"):
        raise FlutterRunnerIntegrityError("Analyzer-influencing input manifest changed after analysis.")
    if _root_identity(root) != project.get("rootIdentity"):
        raise FlutterRunnerIntegrityError("Flutter project root identity changed or was replayed.")
    if _git_commit(root) != project.get("gitCommit"):
        raise FlutterRunnerIntegrityError("Flutter project git commit changed after analysis.")
    try:
        verify_dependency_bundle(root, runner_evidence.get("dependencies"))
    except FlutterDependencyIntegrityError as error:
        raise FlutterRunnerIntegrityError(
            f"Flutter governed dependency evidence failed finalization recheck: {error}"
        ) from error
    try:
        verify_dart_sdk_evidence(
            runner_evidence.get("toolchain"), product_root=root
        )
    except FlutterToolchainIntegrityError as error:
        raise FlutterRunnerIntegrityError(
            f"Flutter Dart SDK evidence failed finalization recheck: {error}"
        ) from error
    return json.loads(canonical_json_bytes(project))


__all__ = [
    "ATTESTATION_PREFIX",
    "FlutterRunnerIntegrityError",
    "FlutterRunnerUnsupportedError",
    "enumerate_relevant_dart_files",
    "run_flutter_analysis",
    "verify_flutter_project_evidence",
]
