"""Trusted executable benchmarks and fully recomputed weighted Elo history."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import (
    atomic_write_json,
    read_canonical_json,
    read_json,
    sha256_digest,
)
from .paths import GuardianPaths, assert_guardian_storage_path, is_link_or_reparse
from .policy import EXPECTED_POLICY_SHA256, verify_policy_anchor
from .storage import exclusive_write_json, transaction_lock


ELO_MODEL = "guardian-weighted-elo-v1"
ELO_MIN = 1
ELO_MAX = 2000
ELO_EVALUATION_CAP = 200
ELO_WEIGHTS = {
    "correctness": 80,
    "reliability": 40,
    "coverage_usefulness": 30,
    "safety_privacy_integrity": 30,
    "portability_usability_performance": 20,
}

_PLUGIN_NAME = "design-system-guardian"
_CANONICAL_REPOSITORY = "pv-vimalnair/design-system-guardian"
_CANONICAL_PREFIX = "plugins/design-system-guardian/"
_API_ROOT = "https://api.github.com/repos/pv-vimalnair/design-system-guardian/"
_SUITE_KEYS = {"schemaVersion", "model", "suiteId", "suiteVersion", "caseModules", "achievements"}
_MODULE_KEYS = {"moduleId", "path", "moduleDigest", "workerDigest"}
_ACHIEVEMENT_KEYS = {
    "achievementId", "category", "weight", "caseModuleId", "caseFunction", "workerDigest"
}
_RESULT_KEYS = {
    "schemaVersion", "model", "resultAuthority", "overallStatus", "suiteDigest",
    "policyDigest", "runtimeDigest", "conditionDigest", "pluginName", "pluginVersion",
    "canonicalRepository", "sourceCommit", "sourceTree", "packageDigest", "cases",
    "authoritySeal",
}
_CASE_RESULT_KEYS = {
    "achievementId", "caseModuleId", "moduleDigest", "caseFunction", "workerDigest",
    "repetitions",
}
_REPETITION_KEYS = {"repetition", "status", "evidenceDigest"}
_ENTRY_KEYS = {
    "schemaVersion", "model", "ledgerId", "sequence", "previousEntryDigest", "entryDigest",
    "pluginName", "policyDigest", "suiteDigest", "suiteSnapshot", "runtimeDigest",
    "conditionDigest", "baselineResult", "candidateResult", "previousScore",
    "categoryDeltas", "delta", "score", "achievementIds", "newAchievementIds",
    "confirmedRegressionIds", "authoritySeal",
}
_HEAD_KEYS = {
    "schemaVersion", "model", "ledgerId", "sequence", "entryDigest", "score",
    "suiteDigest", "authoritySeal",
}
_MARKER_KEYS = {"schemaVersion", "model", "ledgerId", "authoritySeal"}
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PUBLIC_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_ACHIEVEMENT_ID = re.compile(r"^synthetic-[a-z0-9]+(?:-[a-z0-9]+)*$")
_CASE_FUNCTION = re.compile(r"^case_[a-z0-9]+(?:_[a-z0-9]+)*$")
_HISTORY_NAME = re.compile(r"^([0-9]{20})-([0-9a-f]{64})\.sealed\.json$")

_WORKER = """import importlib.util,pathlib,sys
p=pathlib.Path(sys.argv[1]); n=sys.argv[2]; r=pathlib.Path(sys.argv[3])
try:
 s=importlib.util.spec_from_file_location('_guardian_elo_cases',p)
 if s is None or s.loader is None: raise RuntimeError('loader unavailable')
 m=importlib.util.module_from_spec(s); s.loader.exec_module(m); getattr(m,n)(r)
except (AssertionError,FileNotFoundError,ModuleNotFoundError): raise SystemExit(1)
except BaseException: raise SystemExit(2)
raise SystemExit(0)
"""


def _worker_digest() -> str:
    return sha256_digest(
        {
            "script": _WORKER,
            "interpreterFlags": ["-I", "-B", "-c"],
            "statusProtocol": {"passed": 0, "assertion_failed": 1, "infrastructure": 2},
        }
    )

class EloIntegrityError(ValueError):
    """Raised when executable benchmark evidence or Elo history is invalid."""


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise EloIntegrityError(f"{field} must be an exact lowercase SHA-256 digest.")
    return value


def _validate_suite(value: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not isinstance(value, dict) or set(value) != _SUITE_KEYS:
        raise EloIntegrityError("Public Elo suite has unknown or missing fields.")
    if (
        value.get("schemaVersion") != 2
        or value.get("model") != ELO_MODEL
        or value.get("suiteId") != "guardian-public-synthetic-v1"
        or type(value.get("suiteVersion")) is not int
        or value["suiteVersion"] < 1
    ):
        raise EloIntegrityError("Public Elo suite identity or version is invalid.")
    modules = value.get("caseModules")
    if not isinstance(modules, list) or not modules:
        raise EloIntegrityError("Public Elo suite requires immutable case modules.")
    modules_by_id: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for module in modules:
        if not isinstance(module, dict) or set(module) != _MODULE_KEYS:
            raise EloIntegrityError("Public Elo case module has an invalid exact contract.")
        module_id = module.get("moduleId")
        module_path = module.get("path")
        if (
            not isinstance(module_id, str)
            or not re.fullmatch(r"guardian-public-cases-v[1-9][0-9]*", module_id)
            or module_id in modules_by_id
            or not isinstance(module_path, str)
            or not re.fullmatch(r"benchmarks/elo_cases_v[1-9][0-9]*\.py", module_path)
            or module_path in paths
        ):
            raise EloIntegrityError("Public Elo case module identity or path is invalid.")
        _require_digest(module.get("moduleDigest"), "moduleDigest")
        _require_digest(module.get("workerDigest"), "workerDigest")
        modules_by_id[module_id] = copy.deepcopy(module)
        paths.add(module_path)
    items = value.get("achievements")
    if not isinstance(items, list) or not items:
        raise EloIntegrityError("Public Elo suite requires executable achievements.")
    by_id: dict[str, dict[str, Any]] = {}
    functions: set[tuple[str, str]] = set()
    totals = {category: 0 for category in ELO_WEIGHTS}
    for item in items:
        if not isinstance(item, dict) or set(item) != _ACHIEVEMENT_KEYS:
            raise EloIntegrityError("Public Elo achievement has an invalid exact contract.")
        achievement_id = item.get("achievementId")
        category = item.get("category")
        weight = item.get("weight")
        module_id = item.get("caseModuleId")
        function = item.get("caseFunction")
        if (
            not isinstance(achievement_id, str)
            or len(achievement_id) > 127
            or not _ACHIEVEMENT_ID.fullmatch(achievement_id)
            or achievement_id in by_id
        ):
            raise EloIntegrityError("Public Elo achievement ID is invalid or duplicated.")
        if category not in ELO_WEIGHTS or type(weight) is not int or weight <= 0:
            raise EloIntegrityError("Public Elo category or weight is invalid.")
        if (
            module_id not in modules_by_id
            or not isinstance(function, str)
            or not _CASE_FUNCTION.fullmatch(function)
            or (module_id, function) in functions
            or item.get("workerDigest") != modules_by_id[module_id]["workerDigest"]
        ):
            raise EloIntegrityError("Public Elo module, function, or worker binding is invalid.")
        by_id[achievement_id] = copy.deepcopy(item)
        functions.add((module_id, function))
        totals[category] += weight
    if any(total <= 0 for total in totals.values()):
        raise EloIntegrityError("Every Elo category requires executable public coverage.")
    return copy.deepcopy(value), by_id


def _public_suite() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    root = Path(__file__).resolve().parents[1]
    path = root / "benchmarks" / "elo-suite.json"
    try:
        suite, by_id = _validate_suite(read_json(path))
        worker_digest = _worker_digest()
        for module in suite["caseModules"]:
            module_path = root / module["path"]
            if (
                not module_path.is_file()
                or is_link_or_reparse(module_path)
                or sha256_digest(module_path.read_bytes()) != module["moduleDigest"]
                or module["workerDigest"] != worker_digest
            ):
                raise EloIntegrityError("Public Elo module bytes or worker semantics changed.")
        return suite, by_id
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, EloIntegrityError):
            raise
        raise EloIntegrityError(f"Public Elo suite is unreadable: {error}") from error


def _validate_suite_transition(previous: Any, current: Any) -> None:
    previous_suite, previous_by_id = _validate_suite(previous)
    current_suite, current_by_id = _validate_suite(current)
    previous_modules = {item["moduleId"]: item for item in previous_suite["caseModules"]}
    current_modules = {item["moduleId"]: item for item in current_suite["caseModules"]}
    if current_suite["suiteVersion"] < previous_suite["suiteVersion"]:
        raise EloIntegrityError("Public Elo suite version cannot move backward.")
    if not set(previous_by_id).issubset(current_by_id) or not set(previous_modules).issubset(current_modules):
        raise EloIntegrityError("Public Elo suite cannot remove an accepted achievement or module.")
    changed = set(current_by_id) != set(previous_by_id) or set(current_modules) != set(previous_modules)
    if changed and current_suite["suiteVersion"] <= previous_suite["suiteVersion"]:
        raise EloIntegrityError("Additive Elo suite changes require a higher suite version.")
    for module_id, old in previous_modules.items():
        if current_modules[module_id] != old:
            raise EloIntegrityError("Public Elo suite cannot change accepted module or worker bytes.")
    frozen = ("category", "weight", "caseModuleId", "caseFunction", "workerDigest")
    for achievement_id, old in previous_by_id.items():
        if any(current_by_id[achievement_id][field] != old[field] for field in frozen):
            raise EloIntegrityError("Public Elo suite cannot change an accepted case binding.")


def _current_score() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "current-score.json"
    try:
        value = read_json(path)
    except (OSError, UnicodeError, ValueError) as error:
        raise EloIntegrityError(f"Public current-score contract is unreadable: {error}") from error
    expected = {
        "schemaVersion", "model", "score", "achievementIds", "suiteDigest",
        "suiteSnapshot", "bootstrapCandidate",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise EloIntegrityError("Public current-score contract has unknown or missing fields.")
    suite, _ = _public_suite()
    bootstrap_suite, _ = _validate_suite(value.get("suiteSnapshot"))
    _validate_suite_transition(bootstrap_suite, suite)
    bootstrap = value.get("bootstrapCandidate")
    if (
        value.get("schemaVersion") != 3
        or value.get("model") != ELO_MODEL
        or value.get("score") != ELO_MIN
        or value.get("achievementIds") != []
        or value.get("suiteDigest") != sha256_digest(bootstrap_suite)
        or not isinstance(bootstrap, dict)
        or set(bootstrap) != {"canonicalRepository", "pluginVersion", "sourceCommit", "sourceTree", "packageDigest"}
        or bootstrap.get("canonicalRepository") != _CANONICAL_REPOSITORY
        or bootstrap.get("pluginVersion") != "0.2.0"
        or bootstrap.get("sourceCommit") != "05f736facf2187af638cf0ea6cb3897c77711c06"
        or bootstrap.get("sourceTree") != "a1ed3e786c565bb8e75e5cf207b9c3bd99e631bd"
        or bootstrap.get("packageDigest") != "03461d79d04b5ab807476e0851d4a2b0570774ae4ad85800c713355aafd58fdd"
    ):
        raise EloIntegrityError("Public current-score contract does not bind the executable suite and bootstrap.")
    return copy.deepcopy(value)

def _git(target: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(target), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise EloIntegrityError("Benchmark target is not an exact readable committed Git package.")
    return result.stdout


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise EloIntegrityError("Canonical repository API redirects are forbidden.")


def _github_json(suffix: str) -> dict[str, Any]:
    if not re.fullmatch(r"(?:commits/[0-9a-f]{40}|git/trees/[0-9a-f]{40}\?recursive=1)", suffix):
        raise EloIntegrityError("Canonical repository API request is outside the pinned surface.")
    url = _API_ROOT + suffix
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "design-system-guardian-canonical-verifier/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with urllib.request.build_opener(_RejectRedirects()).open(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                raise EloIntegrityError("Canonical repository API response identity is invalid.")
            payload = response.read(32 * 1024 * 1024 + 1)
    except EloIntegrityError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise EloIntegrityError(f"Canonical repository API is unavailable: {error}") from error
    if len(payload) > 32 * 1024 * 1024:
        raise EloIntegrityError("Canonical repository API response exceeds the bounded size.")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise EloIntegrityError("Canonical repository API returned invalid JSON.") from error
    if not isinstance(value, dict):
        raise EloIntegrityError("Canonical repository API response must be an object.")
    return value


def _git_blob_digest(payload: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload).hexdigest()


def _local_package_files(target: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in sorted(target.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(target)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if path.is_dir():
            continue
        if not path.is_file() or is_link_or_reparse(path):
            raise EloIntegrityError("Benchmark package may contain only unredirected regular files.")
        name = relative.as_posix()
        if name in result:
            raise EloIntegrityError("Benchmark package path set is ambiguous.")
        try:
            result[name] = path.read_bytes()
        except OSError as error:
            raise EloIntegrityError(f"Benchmark package bytes are unreadable: {error}") from error
    if not result:
        raise EloIntegrityError("Benchmark target contains no package files.")
    return result


def _authenticate_canonical_target(
    target: Path,
    proposed_commit: str,
    *,
    fetch: Callable[[str], dict[str, Any]] = _github_json,
) -> dict[str, str]:
    if not _COMMIT.fullmatch(proposed_commit) or len(proposed_commit) != 40:
        raise EloIntegrityError("Benchmark target did not propose one full public Git commit.")
    try:
        commit = fetch(f"commits/{proposed_commit}")
    except EloIntegrityError:
        raise
    except BaseException as error:
        raise EloIntegrityError(f"Canonical commit evidence is unavailable: {error}") from error
    tree_value = commit.get("commit") if isinstance(commit.get("commit"), dict) else commit
    tree_ref = tree_value.get("tree") if isinstance(tree_value, dict) else None
    tree_sha = tree_ref.get("sha") if isinstance(tree_ref, dict) else None
    if commit.get("sha") != proposed_commit or not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
        raise EloIntegrityError("Canonical commit evidence is incomplete or mismatched.")
    try:
        tree = fetch(f"git/trees/{tree_sha}?recursive=1")
    except EloIntegrityError:
        raise
    except BaseException as error:
        raise EloIntegrityError(f"Canonical tree evidence is unavailable: {error}") from error
    if tree.get("sha") != tree_sha or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise EloIntegrityError("Canonical recursive tree evidence is incomplete or truncated.")
    remote: dict[str, str] = {}
    for item in tree["tree"]:
        if not isinstance(item, dict):
            raise EloIntegrityError("Canonical tree contains malformed evidence.")
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith(_CANONICAL_PREFIX):
            continue
        relative = path[len(_CANONICAL_PREFIX):]
        if not relative:
            continue
        kind = item.get("type")
        if kind == "tree":
            continue
        if (
            kind != "blob"
            or item.get("mode") not in {"100644", "100755"}
            or not isinstance(item.get("sha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", item["sha"])
            or relative in remote
        ):
            raise EloIntegrityError("Canonical package tree contains unsupported or duplicate entries.")
        remote[relative] = item["sha"]
    local = _local_package_files(target)
    if set(local) != set(remote):
        raise EloIntegrityError("Benchmark target path set differs from the canonical public package.")
    records: list[dict[str, str]] = []
    for name in sorted(local):
        payload = local[name]
        if _git_blob_digest(payload) != remote[name]:
            raise EloIntegrityError("Benchmark target bytes differ from the canonical public commit.")
        records.append({"path": name, "digest": sha256_digest(payload)})
    manifest = read_json(target / ".codex-plugin" / "plugin.json")
    if not isinstance(manifest, dict) or manifest.get("name") != _PLUGIN_NAME:
        raise EloIntegrityError("Benchmark package has the wrong public plugin identity.")
    version = manifest.get("version")
    if not isinstance(version, str) or len(version) > 31 or not _PUBLIC_VERSION.fullmatch(version):
        raise EloIntegrityError("Benchmark package must derive a bounded plain public version.")
    return {
        "canonicalRepository": _CANONICAL_REPOSITORY,
        "pluginVersion": version,
        "sourceCommit": proposed_commit,
        "sourceTree": tree_sha,
        "packageDigest": sha256_digest(records),
    }


def _target_identity(target_root: Path) -> dict[str, str]:
    try:
        target = target_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise EloIntegrityError(f"Benchmark target root is unavailable: {error}") from error
    if not target.is_dir() or any(is_link_or_reparse(path) for path in (target, *target.parents)):
        raise EloIntegrityError("Benchmark target root must be an unredirected directory.")
    proposed_commit = _git(target, "rev-parse", "HEAD").decode("ascii", "strict").strip()
    return _authenticate_canonical_target(target, proposed_commit)

def _runtime_digest() -> str:
    return sha256_digest(
        {
            "implementation": sys.implementation.name,
            "python": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
            "os": os.name,
            "machine": platform.machine().lower(),
            "workerDigest": _worker_digest(),
        }
    )


def _repetition_evidence(
    definition: dict[str, Any],
    module: dict[str, Any],
    condition_digest: str,
    package_digest: str,
    repetition: int,
    status_value: str,
) -> str:
    return sha256_digest(
        {
            "achievementId": definition["achievementId"],
            "caseModuleId": definition["caseModuleId"],
            "moduleDigest": module["moduleDigest"],
            "caseFunction": definition["caseFunction"],
            "workerDigest": definition["workerDigest"],
            "conditionDigest": condition_digest,
            "packageDigest": package_digest,
            "repetition": repetition,
            "status": status_value,
        }
    )

def _seal_result(home: Path, unsigned: dict[str, Any]) -> dict[str, Any]:
    try:
        seal = authority_seal(home, "elo-benchmark-result:v2", unsigned)
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Benchmark result authority is unavailable: {error}") from error
    return {**copy.deepcopy(unsigned), "authoritySeal": seal}


def benchmark_elo(home: Path, target_root: Path) -> dict[str, Any]:
    """Run every current immutable public case twice against one canonical package."""

    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    suite, _ = _public_suite()
    _current_score()
    target = target_root.expanduser().resolve(strict=True)
    identity = _target_identity(target)
    runtime_digest = _runtime_digest()
    suite_digest = sha256_digest(suite)
    condition_digest = sha256_digest(
        {
            "model": ELO_MODEL,
            "policyDigest": policy_digest,
            "runtimeDigest": runtime_digest,
            "suiteDigest": suite_digest,
        }
    )
    root = Path(__file__).resolve().parents[1]
    modules = {item["moduleId"]: item for item in suite["caseModules"]}
    case_results: list[dict[str, Any]] = []
    for item in suite["achievements"]:
        module = modules[item["caseModuleId"]]
        local_case_path = root / module["path"]
        repetitions: list[dict[str, Any]] = []
        for repetition in (1, 2):
            process = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    _WORKER,
                    str(local_case_path),
                    item["caseFunction"],
                    str(target),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if process.stdout or process.stderr or process.returncode not in {0, 1}:
                raise EloIntegrityError(
                    f"Executable Elo case infrastructure failed for {item['achievementId']}."
                )
            status_value = "passed" if process.returncode == 0 else "assertion_failed"
            repetitions.append(
                {
                    "repetition": repetition,
                    "status": status_value,
                    "evidenceDigest": _repetition_evidence(
                        item,
                        module,
                        condition_digest,
                        identity["packageDigest"],
                        repetition,
                        status_value,
                    ),
                }
            )
        case_results.append(
            {
                "achievementId": item["achievementId"],
                "caseModuleId": item["caseModuleId"],
                "moduleDigest": module["moduleDigest"],
                "caseFunction": item["caseFunction"],
                "workerDigest": item["workerDigest"],
                "repetitions": repetitions,
            }
        )
    return _seal_result(
        normalized_home,
        {
            "schemaVersion": 2,
            "model": ELO_MODEL,
            "resultAuthority": "local-guardian-v1",
            "overallStatus": "complete",
            "suiteDigest": suite_digest,
            "policyDigest": policy_digest,
            "runtimeDigest": runtime_digest,
            "conditionDigest": condition_digest,
            "pluginName": _PLUGIN_NAME,
            **identity,
            "cases": case_results,
        },
    )

def _verify_benchmark_result(
    home: Path, value: Any, suite: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        raise EloIntegrityError("Elo evaluation requires an exact sealed benchmark result.")
    unsigned = {key: copy.deepcopy(item) for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, "elo-benchmark-result:v2", unsigned, value.get("authoritySeal"))
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Benchmark result authority seal is invalid: {error}") from error
    if (
        value.get("schemaVersion") != 2
        or value.get("model") != ELO_MODEL
        or value.get("resultAuthority") != "local-guardian-v1"
        or value.get("overallStatus") != "complete"
        or value.get("pluginName") != _PLUGIN_NAME
        or value.get("canonicalRepository") != _CANONICAL_REPOSITORY
        or value.get("suiteDigest") != sha256_digest(suite)
        or value.get("policyDigest") != verify_policy_anchor(home)
    ):
        raise EloIntegrityError("Sealed benchmark result identity or binding is invalid.")
    for field in ("runtimeDigest", "conditionDigest", "packageDigest"):
        _require_digest(value.get(field), field)
    version = value.get("pluginVersion")
    if not isinstance(version, str) or len(version) > 31 or not _PUBLIC_VERSION.fullmatch(version):
        raise EloIntegrityError("Sealed benchmark result version is not a bounded public version.")
    if not isinstance(value.get("sourceCommit"), str) or not re.fullmatch(r"[0-9a-f]{40}", value["sourceCommit"]):
        raise EloIntegrityError("Sealed benchmark result commit is not full length.")
    if not isinstance(value.get("sourceTree"), str) or not re.fullmatch(r"[0-9a-f]{40}", value["sourceTree"]):
        raise EloIntegrityError("Sealed benchmark result tree is not full length.")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != len(suite["achievements"]):
        raise EloIntegrityError("Sealed benchmark result does not cover the exact public suite.")
    modules = {item["moduleId"]: item for item in suite["caseModules"]}
    for case, definition in zip(cases, suite["achievements"], strict=True):
        module = modules[definition["caseModuleId"]]
        if (
            not isinstance(case, dict)
            or set(case) != _CASE_RESULT_KEYS
            or case.get("achievementId") != definition["achievementId"]
            or case.get("caseModuleId") != definition["caseModuleId"]
            or case.get("moduleDigest") != module["moduleDigest"]
            or case.get("caseFunction") != definition["caseFunction"]
            or case.get("workerDigest") != definition["workerDigest"]
        ):
            raise EloIntegrityError("Sealed benchmark case identity differs from the public suite.")
        repetitions = case.get("repetitions")
        if not isinstance(repetitions, list) or len(repetitions) != 2:
            raise EloIntegrityError("Every benchmark case must contain exactly two repetitions.")
        for expected_repetition, repetition in enumerate(repetitions, start=1):
            if (
                not isinstance(repetition, dict)
                or set(repetition) != _REPETITION_KEYS
                or repetition.get("repetition") != expected_repetition
                or repetition.get("status") not in {"passed", "assertion_failed"}
            ):
                raise EloIntegrityError("Benchmark repetition evidence is invalid.")
            expected_digest = _repetition_evidence(
                definition,
                module,
                value["conditionDigest"],
                value["packageDigest"],
                expected_repetition,
                repetition["status"],
            )
            if repetition.get("evidenceDigest") != expected_digest:
                raise EloIntegrityError("Benchmark repetition evidence digest is false.")
    return copy.deepcopy(value)

def verify_benchmark_result(home: Path, value: Any) -> dict[str, Any]:
    suite, _ = _public_suite()
    return _verify_benchmark_result(home.expanduser().absolute(), value, suite)


def _case_statuses(result: dict[str, Any]) -> dict[str, tuple[str, str]]:
    return {
        item["achievementId"]: tuple(
            repetition["status"] for repetition in item["repetitions"]
        )
        for item in result["cases"]
    }


def _round_half_up(numerator: int, denominator: int) -> int:
    return (2 * numerator + denominator) // (2 * denominator)


def _bounded_score(previous_score: int, delta: int) -> int:
    return max(ELO_MIN, min(ELO_MAX, previous_score + delta))


def _version_tuple(value: str) -> tuple[int, int, int]:
    if not _PUBLIC_VERSION.fullmatch(value):
        raise EloIntegrityError("Elo continuity requires a plain public version.")
    return tuple(int(part) for part in value.split("."))


def _continuity_coordinates(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise EloIntegrityError("Elo continuity requires exact candidate coordinates.")
    fields = ("canonicalRepository", "pluginVersion", "sourceCommit", "sourceTree", "packageDigest")
    result = {field: value.get(field) for field in fields}
    if (
        result["canonicalRepository"] != _CANONICAL_REPOSITORY
        or not isinstance(result["pluginVersion"], str)
        or not isinstance(result["sourceCommit"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", result["sourceCommit"])
        or not isinstance(result["sourceTree"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", result["sourceTree"])
        or not isinstance(result["packageDigest"], str)
        or not _HEX_64.fullmatch(result["packageDigest"])
    ):
        raise EloIntegrityError("Elo continuity coordinates are invalid.")
    _version_tuple(result["pluginVersion"])
    return result


def _validate_continuity(
    previous: dict[str, Any] | None,
    current_score: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    baseline_coordinates = _continuity_coordinates(baseline)
    candidate_coordinates = _continuity_coordinates(candidate)
    expected = (
        _continuity_coordinates(current_score.get("bootstrapCandidate"))
        if previous is None
        else _continuity_coordinates(previous.get("candidateResult"))
    )
    if baseline_coordinates != expected:
        raise EloIntegrityError("Elo baseline does not continue from the accepted public candidate.")
    if (
        _version_tuple(candidate_coordinates["pluginVersion"])
        <= _version_tuple(baseline_coordinates["pluginVersion"])
        or candidate_coordinates["sourceCommit"] == baseline_coordinates["sourceCommit"]
        or candidate_coordinates["packageDigest"] == baseline_coordinates["packageDigest"]
    ):
        raise EloIntegrityError("Elo candidate must be a different newer canonical public package.")

def _derive_evaluation(
    previous_achievement_ids: list[str],
    previous_score: int,
    suite: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    _, by_id = _validate_suite(suite)
    baseline_statuses = _case_statuses(baseline)
    candidate_statuses = _case_statuses(candidate)
    baseline_passed = {
        achievement_id
        for achievement_id, statuses in baseline_statuses.items()
        if statuses == ("passed", "passed")
    }
    candidate_passed = {
        achievement_id
        for achievement_id, statuses in candidate_statuses.items()
        if statuses == ("passed", "passed")
    }
    historical = set(previous_achievement_ids)
    new_ids = (candidate_passed - baseline_passed) - historical
    lost = baseline_passed - candidate_passed
    confirmed = {
        achievement_id
        for achievement_id in lost
        if candidate_statuses[achievement_id] == ("assertion_failed", "assertion_failed")
    }
    unconfirmed = lost - confirmed
    category_deltas: dict[str, int] = {}
    for category, cap in ELO_WEIGHTS.items():
        total = sum(item["weight"] for item in by_id.values() if item["category"] == category)
        positive = sum(
            by_id[item]["weight"] for item in new_ids if by_id[item]["category"] == category
        )
        negative = sum(
            by_id[item]["weight"] for item in confirmed if by_id[item]["category"] == category
        )
        net = positive - negative
        magnitude = 0 if net == 0 else _round_half_up(cap * abs(net), total)
        category_delta = magnitude if net > 0 else -magnitude
        if unconfirmed and category_delta > 0:
            category_delta = 0
        category_deltas[category] = category_delta
    delta = max(-ELO_EVALUATION_CAP, min(ELO_EVALUATION_CAP, sum(category_deltas.values())))
    return {
        "previousScore": previous_score,
        "categoryDeltas": category_deltas,
        "delta": delta,
        "score": _bounded_score(previous_score, delta),
        "achievementIds": sorted(historical | baseline_passed | candidate_passed),
        "newAchievementIds": sorted(new_ids),
        "confirmedRegressionIds": sorted(confirmed),
    }


def _default_state() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "model": ELO_MODEL,
        "score": ELO_MIN,
        "sequence": 0,
        "entryDigest": None,
        "achievementIds": [],
    }


def _marker_path(home: Path) -> Path:
    return assert_guardian_storage_path(
        home, GuardianPaths(home).trust / "elo-ledger-init.sealed.json"
    )


def _verify_marker(home: Path, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _MARKER_KEYS:
        raise EloIntegrityError("Elo ledger initialization marker has unknown or missing fields.")
    unsigned = {key: copy.deepcopy(item) for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, "elo-ledger-init:v1", unsigned, value.get("authoritySeal"))
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Elo ledger initialization marker seal is invalid: {error}") from error
    if value.get("schemaVersion") != 1 or value.get("model") != ELO_MODEL:
        raise EloIntegrityError("Elo ledger initialization marker identity is invalid.")
    _require_digest(value.get("ledgerId"), "ledgerId")
    return copy.deepcopy(value)


def _initialize_marker(home: Path) -> dict[str, Any]:
    unsigned = {
        "schemaVersion": 1,
        "model": ELO_MODEL,
        "ledgerId": sha256_digest(os.urandom(32)),
    }
    marker = {
        **unsigned,
        "authoritySeal": authority_seal(home, "elo-ledger-init:v1", unsigned),
    }
    exclusive_write_json(home, _marker_path(home), marker)
    verified = _verify_marker(home, read_canonical_json(_marker_path(home)))
    if verified != marker:
        raise EloIntegrityError("Elo ledger initialization marker failed verification.")
    return marker

def _head_path(home: Path) -> Path:
    return assert_guardian_storage_path(home, GuardianPaths(home).trust / "elo-head.sealed.json")


def _verify_head(home: Path, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _HEAD_KEYS:
        raise EloIntegrityError("Protected Elo head has unknown or missing fields.")
    unsigned = {key: copy.deepcopy(item) for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, "elo-head:v1", unsigned, value.get("authoritySeal"))
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Protected Elo head seal is invalid: {error}") from error
    if (
        value.get("schemaVersion") != 1
        or value.get("model") != ELO_MODEL
        or type(value.get("sequence")) is not int
        or value["sequence"] < 1
        or type(value.get("score")) is not int
        or not ELO_MIN <= value["score"] <= ELO_MAX
    ):
        raise EloIntegrityError("Protected Elo head coordinates are invalid.")
    _require_digest(value.get("ledgerId"), "head.ledgerId")
    _require_digest(value.get("entryDigest"), "head.entryDigest")
    _require_digest(value.get("suiteDigest"), "head.suiteDigest")
    return copy.deepcopy(value)


def _write_head(home: Path, entry: dict[str, Any]) -> None:
    unsigned = {
        "schemaVersion": 1,
        "model": ELO_MODEL,
        "ledgerId": entry["ledgerId"],
        "sequence": entry["sequence"],
        "entryDigest": entry["entryDigest"],
        "score": entry["score"],
        "suiteDigest": entry["suiteDigest"],
    }
    head = {**unsigned, "authoritySeal": authority_seal(home, "elo-head:v1", unsigned)}
    atomic_write_json(_head_path(home), head)
    if _verify_head(home, read_canonical_json(_head_path(home))) != head:
        raise EloIntegrityError("Protected Elo head failed post-write verification.")


def _entry_digest(entry: dict[str, Any]) -> str:
    return sha256_digest(
        {key: copy.deepcopy(value) for key, value in entry.items() if key not in {"entryDigest", "authoritySeal"}}
    )


def _verify_entry(
    home: Path,
    path: Path,
    previous: dict[str, Any] | None,
    ledger_id: str,
) -> dict[str, Any]:
    try:
        entry = read_canonical_json(path)
    except (OSError, UnicodeError, ValueError) as error:
        raise EloIntegrityError(f"Elo entry is not canonical readable JSON: {error}") from error
    if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
        raise EloIntegrityError("Elo ledger entry has unknown or missing fields.")
    sequence = 1 if previous is None else previous["sequence"] + 1
    match = _HISTORY_NAME.fullmatch(path.name)
    if (
        entry.get("schemaVersion") != 2
        or entry.get("model") != ELO_MODEL
        or entry.get("sequence") != sequence
        or match is None
        or int(match.group(1)) != sequence
    ):
        raise EloIntegrityError("Elo ledger entry identity or sequence is invalid.")
    digest = _entry_digest(entry)
    if entry.get("entryDigest") != digest or match.group(2) != digest:
        raise EloIntegrityError("Elo ledger entry digest or filename is invalid.")
    unsigned = {key: copy.deepcopy(value) for key, value in entry.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, "elo-ledger:v2", unsigned, entry.get("authoritySeal"))
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Elo ledger entry seal is invalid: {error}") from error
    previous_digest = None if previous is None else previous["entryDigest"]
    previous_score = ELO_MIN if previous is None else previous["score"]
    previous_achievements = [] if previous is None else previous["achievementIds"]
    previous_suite = _current_score()["suiteSnapshot"] if previous is None else previous["suiteSnapshot"]
    suite, _ = _validate_suite(entry.get("suiteSnapshot"))
    _validate_suite_transition(previous_suite, suite)
    if (
        entry.get("ledgerId") != ledger_id
        or entry.get("previousEntryDigest") != previous_digest
        or entry.get("pluginName") != _PLUGIN_NAME
        or entry.get("policyDigest") != verify_policy_anchor(home)
        or entry.get("suiteDigest") != sha256_digest(suite)
    ):
        raise EloIntegrityError("Elo ledger chain, plugin, policy, or suite binding is invalid.")
    baseline = _verify_benchmark_result(home, entry.get("baselineResult"), suite)
    candidate = _verify_benchmark_result(home, entry.get("candidateResult"), suite)
    _validate_continuity(previous, _current_score(), baseline, candidate)
    for field in ("suiteDigest", "policyDigest", "runtimeDigest", "conditionDigest"):
        if baseline[field] != candidate[field] or entry.get(field) != candidate[field]:
            raise EloIntegrityError("Baseline, candidate, and ledger conditions must match exactly.")
    derived = _derive_evaluation(
        previous_achievements, previous_score, suite, baseline, candidate
    )
    for field, expected in derived.items():
        if entry.get(field) != expected:
            raise EloIntegrityError(f"Elo ledger {field} differs from fully recomputed evidence.")
    return copy.deepcopy(entry)


def _read_entries(home: Path) -> tuple[dict[str, Any], ...]:
    history = assert_guardian_storage_path(home, GuardianPaths(home).elo_history)
    head_path = _head_path(home)
    marker_path = _marker_path(home)
    marker_exists = marker_path.is_file()
    history_exists = history.is_dir()
    head_exists = head_path.is_file()
    if not marker_exists and not history_exists and not head_exists:
        return ()
    if not marker_exists:
        raise EloIntegrityError("Elo history or head exists without its create-once initialization marker.")
    marker = _verify_marker(home, read_canonical_json(marker_path))
    if not history_exists or not head_exists:
        raise EloIntegrityError("Elo initialization marker proves history or head deletion.")
    paths = sorted(history.iterdir(), key=lambda item: item.name)
    if not paths:
        raise EloIntegrityError("Elo initialization marker proves whole-history deletion.")
    entries: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file() or _HISTORY_NAME.fullmatch(path.name) is None:
            raise EloIntegrityError("Elo history contains an unknown artifact.")
        entries.append(
            _verify_entry(
                home,
                path,
                None if not entries else entries[-1],
                marker["ledgerId"],
            )
        )
    head = _verify_head(home, read_canonical_json(head_path))
    latest = entries[-1]
    if (
        head["ledgerId"] != marker["ledgerId"]
        or latest["ledgerId"] != marker["ledgerId"]
        or head["sequence"] != latest["sequence"]
        or head["entryDigest"] != latest["entryDigest"]
        or head["score"] != latest["score"]
        or head["suiteDigest"] != latest["suiteDigest"]
    ):
        raise EloIntegrityError("Protected Elo anchors detect deletion, truncation, or rollback.")
    return tuple(entries)

def read_elo_state(home: Path) -> dict[str, Any]:
    normalized_home = home.expanduser().absolute()
    entries = _read_entries(normalized_home)
    if not entries:
        return _default_state()
    latest = entries[-1]
    return {
        "schemaVersion": 2,
        "model": ELO_MODEL,
        "score": latest["score"],
        "sequence": latest["sequence"],
        "entryDigest": latest["entryDigest"],
        "achievementIds": copy.deepcopy(latest["achievementIds"]),
    }


def evaluate_elo(home: Path, baseline: Any, candidate: Any) -> dict[str, Any]:
    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    suite, _ = _public_suite()
    current_score = _current_score()
    baseline_result = _verify_benchmark_result(normalized_home, baseline, suite)
    candidate_result = _verify_benchmark_result(normalized_home, candidate, suite)
    for field in ("suiteDigest", "policyDigest", "runtimeDigest", "conditionDigest"):
        if baseline_result[field] != candidate_result[field]:
            raise EloIntegrityError(f"Baseline and candidate {field} values must match exactly.")
    lock_path = GuardianPaths(normalized_home).elo / "transaction.lock"
    with transaction_lock(
        normalized_home, lock_path, purpose="guardian-elo-lock-v2"
    ):
        entries = _read_entries(normalized_home)
        previous = None if not entries else entries[-1]
        _validate_continuity(previous, current_score, baseline_result, candidate_result)
        marker = (
            _initialize_marker(normalized_home)
            if previous is None
            else _verify_marker(normalized_home, read_canonical_json(_marker_path(normalized_home)))
        )
        previous_suite = current_score["suiteSnapshot"] if previous is None else previous["suiteSnapshot"]
        _validate_suite_transition(previous_suite, suite)
        previous_score = ELO_MIN if previous is None else previous["score"]
        previous_achievements = [] if previous is None else previous["achievementIds"]
        derived = _derive_evaluation(
            previous_achievements, previous_score, suite, baseline_result, candidate_result
        )
        payload = {
            "schemaVersion": 2,
            "model": ELO_MODEL,
            "ledgerId": marker["ledgerId"],
            "sequence": 1 if previous is None else previous["sequence"] + 1,
            "previousEntryDigest": None if previous is None else previous["entryDigest"],
            "pluginName": _PLUGIN_NAME,
            "policyDigest": policy_digest,
            "suiteDigest": sha256_digest(suite),
            "suiteSnapshot": suite,
            "runtimeDigest": candidate_result["runtimeDigest"],
            "conditionDigest": candidate_result["conditionDigest"],
            "baselineResult": baseline_result,
            "candidateResult": candidate_result,
            **derived,
        }
        digest = sha256_digest(payload)
        unsigned = {**payload, "entryDigest": digest}
        entry = {
            **unsigned,
            "authoritySeal": authority_seal(normalized_home, "elo-ledger:v2", unsigned),
        }
        path = GuardianPaths(normalized_home).elo_history / (
            f"{entry['sequence']:020d}-{digest}.sealed.json"
        )
        exclusive_write_json(normalized_home, path, entry)
        _write_head(normalized_home, entry)
        verified = _read_entries(normalized_home)
        if verified[-1] != entry:
            raise EloIntegrityError("Elo append failed complete semantic post-write verification.")
    return {
        "schemaVersion": 2,
        "model": ELO_MODEL,
        "ledgerId": entry["ledgerId"],
        "sequence": entry["sequence"],
        "entryDigest": digest,
        **derived,
    }
