"""Trusted executable benchmarks and fully recomputed weighted Elo history."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import (
    atomic_write_json,
    canonical_json_bytes,
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
_SUITE_KEYS = {"schemaVersion", "model", "suiteId", "suiteVersion", "achievements"}
_ACHIEVEMENT_KEYS = {
    "achievementId",
    "category",
    "weight",
    "caseFunction",
    "caseDigest",
}
_RESULT_KEYS = {
    "schemaVersion",
    "model",
    "resultAuthority",
    "overallStatus",
    "suiteDigest",
    "policyDigest",
    "runtimeDigest",
    "conditionDigest",
    "pluginName",
    "pluginVersion",
    "sourceCommit",
    "packageDigest",
    "cases",
    "authoritySeal",
}
_CASE_RESULT_KEYS = {"achievementId", "caseDigest", "repetitions"}
_REPETITION_KEYS = {"repetition", "status", "evidenceDigest"}
_ENTRY_KEYS = {
    "schemaVersion",
    "model",
    "sequence",
    "previousEntryDigest",
    "entryDigest",
    "pluginName",
    "policyDigest",
    "suiteDigest",
    "suiteSnapshot",
    "runtimeDigest",
    "conditionDigest",
    "baselineResult",
    "candidateResult",
    "previousScore",
    "categoryDeltas",
    "delta",
    "score",
    "achievementIds",
    "newAchievementIds",
    "confirmedRegressionIds",
    "authoritySeal",
}
_HEAD_KEYS = {
    "schemaVersion",
    "model",
    "sequence",
    "entryDigest",
    "score",
    "suiteDigest",
    "authoritySeal",
}
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
except AssertionError: raise SystemExit(1)
except BaseException: raise SystemExit(2)
raise SystemExit(0)
"""


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
        value.get("schemaVersion") != 1
        or value.get("model") != ELO_MODEL
        or value.get("suiteId") != "guardian-public-synthetic-v1"
        or type(value.get("suiteVersion")) is not int
        or value["suiteVersion"] < 1
    ):
        raise EloIntegrityError("Public Elo suite identity or version is invalid.")
    items = value.get("achievements")
    if not isinstance(items, list) or not items:
        raise EloIntegrityError("Public Elo suite requires executable achievements.")
    by_id: dict[str, dict[str, Any]] = {}
    functions: set[str] = set()
    totals = {category: 0 for category in ELO_WEIGHTS}
    for item in items:
        if not isinstance(item, dict) or set(item) != _ACHIEVEMENT_KEYS:
            raise EloIntegrityError("Public Elo achievement has an invalid exact contract.")
        achievement_id = item.get("achievementId")
        category = item.get("category")
        weight = item.get("weight")
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
            not isinstance(function, str)
            or not _CASE_FUNCTION.fullmatch(function)
            or function in functions
        ):
            raise EloIntegrityError("Public Elo case function is invalid or duplicated.")
        _require_digest(item.get("caseDigest"), "caseDigest")
        by_id[achievement_id] = copy.deepcopy(item)
        functions.add(function)
        totals[category] += weight
    if any(total <= 0 for total in totals.values()):
        raise EloIntegrityError("Every Elo category requires executable public coverage.")
    return copy.deepcopy(value), by_id


def _public_suite() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "elo-suite.json"
    try:
        return _validate_suite(read_json(path))
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, EloIntegrityError):
            raise
        raise EloIntegrityError(f"Public Elo suite is unreadable: {error}") from error


def _validate_suite_transition(previous: Any, current: Any) -> None:
    previous_suite, previous_by_id = _validate_suite(previous)
    current_suite, current_by_id = _validate_suite(current)
    if current_suite["suiteVersion"] < previous_suite["suiteVersion"]:
        raise EloIntegrityError("Public Elo suite version cannot move backward.")
    if not set(previous_by_id).issubset(current_by_id):
        raise EloIntegrityError("Public Elo suite cannot remove an accepted achievement.")
    if set(current_by_id) != set(previous_by_id) and current_suite["suiteVersion"] <= previous_suite["suiteVersion"]:
        raise EloIntegrityError("Additive Elo suite changes require a higher suite version.")
    for achievement_id, old in previous_by_id.items():
        new = current_by_id[achievement_id]
        if any(
            new[field] != old[field]
            for field in ("category", "weight", "caseFunction", "caseDigest")
        ):
            raise EloIntegrityError(
                "Public Elo suite cannot recategorize, reweight, or change an accepted case."
            )


def _current_score() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "current-score.json"
    try:
        value = read_json(path)
    except (OSError, UnicodeError, ValueError) as error:
        raise EloIntegrityError(f"Public current-score contract is unreadable: {error}") from error
    expected = {"schemaVersion", "model", "score", "achievementIds", "suiteDigest", "suiteSnapshot"}
    if not isinstance(value, dict) or set(value) != expected:
        raise EloIntegrityError("Public current-score contract has unknown or missing fields.")
    suite, _ = _public_suite()
    if (
        value.get("schemaVersion") != 2
        or value.get("model") != ELO_MODEL
        or value.get("score") != ELO_MIN
        or value.get("achievementIds") != []
        or value.get("suiteSnapshot") != suite
        or value.get("suiteDigest") != sha256_digest(suite)
    ):
        raise EloIntegrityError("Public current-score contract does not bind the executable suite.")
    return copy.deepcopy(value)


def _case_digests(path: Path) -> dict[str, str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError) as error:
        raise EloIntegrityError(f"Executable Elo cases are infrastructure-invalid: {error}") from error
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("case_"):
            result[node.name] = hashlib.sha256(
                ast.dump(node, annotate_fields=True, include_attributes=False).encode("utf-8")
            ).hexdigest()
    return result


def _verify_case_source(path: Path, suite: dict[str, Any]) -> None:
    digests = _case_digests(path)
    for item in suite["achievements"]:
        if digests.get(item["caseFunction"]) != item["caseDigest"]:
            raise EloIntegrityError(
                f"Executable Elo case infrastructure differs for {item['achievementId']}."
            )


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


def _target_identity(target_root: Path) -> dict[str, str]:
    try:
        target = target_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise EloIntegrityError(f"Benchmark target root is unavailable: {error}") from error
    if not target.is_dir() or any(is_link_or_reparse(path) for path in (target, *target.parents)):
        raise EloIntegrityError("Benchmark target root must be an unredirected directory.")
    git_root = Path(_git(target, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    try:
        relative_root = target.relative_to(git_root)
    except ValueError as error:
        raise EloIntegrityError("Benchmark target is outside its committed Git root.") from error
    pathspec = "." if not relative_root.parts else relative_root.as_posix()
    if _git(git_root, "status", "--porcelain=v1", "--untracked-files=all", "--", pathspec):
        raise EloIntegrityError("Benchmark target must be an exact clean committed package.")
    commit = _git(git_root, "rev-parse", "HEAD").decode("ascii").strip()
    if not _COMMIT.fullmatch(commit):
        raise EloIntegrityError("Benchmark target HEAD is not a full public commit digest.")
    tracked = _git(git_root, "ls-files", "-z", "--", pathspec).split(b"\0")
    records: list[dict[str, str]] = []
    for raw_name in tracked:
        if not raw_name:
            continue
        repository_name = raw_name.decode("utf-8")
        path = git_root / repository_name
        try:
            relative_name = path.relative_to(target).as_posix()
        except ValueError:
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(path):
            raise EloIntegrityError("Benchmark package may contain only tracked regular files.")
        records.append({"path": relative_name, "digest": sha256_digest(path.read_bytes())})
    if not records:
        raise EloIntegrityError("Benchmark target contains no committed package files.")
    manifest_path = target / ".codex-plugin" / "plugin.json"
    try:
        manifest = read_json(manifest_path)
    except (OSError, UnicodeError, ValueError) as error:
        raise EloIntegrityError(f"Benchmark package manifest is invalid: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("name") != _PLUGIN_NAME:
        raise EloIntegrityError("Benchmark package has the wrong public plugin identity.")
    version = manifest.get("version")
    if (
        not isinstance(version, str)
        or len(version) > 31
        or not _PUBLIC_VERSION.fullmatch(version)
    ):
        raise EloIntegrityError("Benchmark package must derive a bounded plain public version.")
    return {
        "pluginVersion": version,
        "sourceCommit": commit,
        "packageDigest": sha256_digest(sorted(records, key=lambda item: item["path"])),
    }


def _runtime_digest() -> str:
    return sha256_digest(
        {
            "implementation": sys.implementation.name,
            "python": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
            "os": os.name,
            "machine": platform.machine().lower(),
            "workerDigest": sha256_digest(_WORKER.encode("utf-8")),
        }
    )


def _repetition_evidence(
    achievement_id: str,
    case_digest: str,
    condition_digest: str,
    package_digest: str,
    repetition: int,
    status_value: str,
) -> str:
    return sha256_digest(
        {
            "achievementId": achievement_id,
            "caseDigest": case_digest,
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
    """Run every immutable public case twice against one clean committed package."""

    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    suite, _ = _public_suite()
    _current_score()
    local_case_path = Path(__file__).resolve().parents[1] / "benchmarks" / "elo_cases.py"
    _verify_case_source(local_case_path, suite)
    target = target_root.expanduser().resolve(strict=True)
    target_suite = read_json(target / "benchmarks" / "elo-suite.json")
    if target_suite != suite:
        raise EloIntegrityError("Benchmark target must carry the exact executable public suite.")
    _verify_case_source(target / "benchmarks" / "elo_cases.py", suite)
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
    case_results: list[dict[str, Any]] = []
    for item in suite["achievements"]:
        repetitions: list[dict[str, Any]] = []
        for repetition in (1, 2):
            process = subprocess.run(
                [
                    sys.executable,
                    "-I",
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
                        item["achievementId"],
                        item["caseDigest"],
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
                "caseDigest": item["caseDigest"],
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
        verify_authority_seal(
            home, "elo-benchmark-result:v2", unsigned, value.get("authoritySeal")
        )
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Benchmark result authority seal is invalid: {error}") from error
    if (
        value.get("schemaVersion") != 2
        or value.get("model") != ELO_MODEL
        or value.get("resultAuthority") != "local-guardian-v1"
        or value.get("overallStatus") != "complete"
        or value.get("pluginName") != _PLUGIN_NAME
        or value.get("suiteDigest") != sha256_digest(suite)
        or value.get("policyDigest") != verify_policy_anchor(home)
    ):
        raise EloIntegrityError("Sealed benchmark result identity or binding is invalid.")
    for field in ("runtimeDigest", "conditionDigest", "packageDigest"):
        _require_digest(value.get(field), field)
    version = value.get("pluginVersion")
    if not isinstance(version, str) or len(version) > 31 or not _PUBLIC_VERSION.fullmatch(version):
        raise EloIntegrityError("Sealed benchmark result version is not a bounded public version.")
    if not isinstance(value.get("sourceCommit"), str) or not _COMMIT.fullmatch(value["sourceCommit"]):
        raise EloIntegrityError("Sealed benchmark result commit is not full length.")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != len(suite["achievements"]):
        raise EloIntegrityError("Sealed benchmark result does not cover the exact public suite.")
    for case, definition in zip(cases, suite["achievements"], strict=True):
        if (
            not isinstance(case, dict)
            or set(case) != _CASE_RESULT_KEYS
            or case.get("achievementId") != definition["achievementId"]
            or case.get("caseDigest") != definition["caseDigest"]
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
                definition["achievementId"],
                definition["caseDigest"],
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
    _require_digest(value.get("entryDigest"), "head.entryDigest")
    _require_digest(value.get("suiteDigest"), "head.suiteDigest")
    return copy.deepcopy(value)


def _write_head(home: Path, entry: dict[str, Any]) -> None:
    unsigned = {
        "schemaVersion": 1,
        "model": ELO_MODEL,
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
        entry.get("previousEntryDigest") != previous_digest
        or entry.get("pluginName") != _PLUGIN_NAME
        or entry.get("policyDigest") != verify_policy_anchor(home)
        or entry.get("suiteDigest") != sha256_digest(suite)
    ):
        raise EloIntegrityError("Elo ledger chain, plugin, policy, or suite binding is invalid.")
    baseline = _verify_benchmark_result(home, entry.get("baselineResult"), suite)
    candidate = _verify_benchmark_result(home, entry.get("candidateResult"), suite)
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
    if not history.exists():
        if head_path.exists():
            raise EloIntegrityError("Protected Elo head proves whole-history deletion.")
        return ()
    paths = sorted(history.iterdir(), key=lambda item: item.name)
    if not paths:
        if head_path.exists():
            raise EloIntegrityError("Protected Elo head proves whole-history deletion.")
        return ()
    if not head_path.is_file():
        raise EloIntegrityError("Elo history exists without its separately protected head.")
    entries: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file() or _HISTORY_NAME.fullmatch(path.name) is None:
            raise EloIntegrityError("Elo history contains an unknown artifact.")
        entries.append(_verify_entry(home, path, None if not entries else entries[-1]))
    head = _verify_head(home, read_canonical_json(head_path))
    latest = entries[-1]
    if (
        head["sequence"] != latest["sequence"]
        or head["entryDigest"] != latest["entryDigest"]
        or head["score"] != latest["score"]
        or head["suiteDigest"] != latest["suiteDigest"]
    ):
        raise EloIntegrityError("Protected Elo head detects truncation or rollback.")
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
        previous_suite = _current_score()["suiteSnapshot"] if previous is None else previous["suiteSnapshot"]
        _validate_suite_transition(previous_suite, suite)
        previous_score = ELO_MIN if previous is None else previous["score"]
        previous_achievements = [] if previous is None else previous["achievementIds"]
        derived = _derive_evaluation(
            previous_achievements, previous_score, suite, baseline_result, candidate_result
        )
        payload = {
            "schemaVersion": 2,
            "model": ELO_MODEL,
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
        "sequence": entry["sequence"],
        "entryDigest": digest,
        **derived,
    }
