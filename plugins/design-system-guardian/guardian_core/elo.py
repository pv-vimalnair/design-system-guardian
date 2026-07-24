"""Deterministic public-benchmark Elo evaluation and sealed local history."""

from __future__ import annotations

import copy
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import read_canonical_json, read_json, sha256_digest
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path
from .policy import EXPECTED_POLICY_SHA256, verify_policy_anchor
from .storage import exclusive_write_json


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
PUBLIC_SUITE_DIGEST = "406b89f73c4d3906fc3a1be6c8aa26ed93c4245e387f12ff445a7c7966885cae"

_PLUGIN_NAME = "design-system-guardian"
_SUITE_KEYS = {"schemaVersion", "model", "suiteId", "achievements"}
_ACHIEVEMENT_KEYS = {"achievementId", "category", "weight"}
_RESULT_KEYS = {
    "schemaVersion",
    "model",
    "suiteDigest",
    "policyDigest",
    "runtimeDigest",
    "pluginVersion",
    "sourceCommit",
    "passedAchievementIds",
    "regressions",
}
_REGRESSION_KEYS = {
    "achievementId",
    "attribution",
    "conditionDigest",
    "reproductionDigests",
}
_ENTRY_KEYS = {
    "schemaVersion",
    "model",
    "sequence",
    "previousEntryDigest",
    "entryDigest",
    "pluginName",
    "policyDigest",
    "suiteDigest",
    "runtimeDigest",
    "baselineResultDigest",
    "candidateResultDigest",
    "baselineVersion",
    "candidateVersion",
    "baselineCommit",
    "candidateCommit",
    "previousScore",
    "categoryDeltas",
    "delta",
    "score",
    "achievementIds",
    "newAchievementIds",
    "confirmedRegressionIds",
    "authoritySeal",
}
_ATTRIBUTIONS = {"guardian", "external", "source", "project", "project_configuration"}
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_ACHIEVEMENT_ID = re.compile(r"^synthetic-[a-z0-9]+(?:-[a-z0-9]+)*$")
_HISTORY_NAME = re.compile(r"^([0-9]{20})-([0-9a-f]{64})\.sealed\.json$")


class EloIntegrityError(ValueError):
    """Raised when public benchmark evidence or local Elo history is invalid."""


def _default_state() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "model": ELO_MODEL,
        "score": ELO_MIN,
        "sequence": 0,
        "entryDigest": None,
        "achievementIds": [],
    }


def _public_suite() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "elo-suite.json"
    try:
        suite = read_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise EloIntegrityError(f"Public Elo suite is unreadable: {error}") from error
    if not isinstance(suite, dict) or set(suite) != _SUITE_KEYS:
        raise EloIntegrityError("Public Elo suite has unknown or missing fields.")
    if (
        suite.get("schemaVersion") != 1
        or suite.get("model") != ELO_MODEL
        or suite.get("suiteId") != "guardian-public-synthetic-v1"
    ):
        raise EloIntegrityError("Public Elo suite identity is invalid.")
    if sha256_digest(suite) != PUBLIC_SUITE_DIGEST:
        raise EloIntegrityError("Public Elo suite digest differs from guardian-weighted-elo-v1.")
    achievements = suite.get("achievements")
    if not isinstance(achievements, list) or not achievements:
        raise EloIntegrityError("Public Elo suite must contain synthetic achievements.")
    by_id: dict[str, dict[str, Any]] = {}
    totals = {category: 0 for category in ELO_WEIGHTS}
    for item in achievements:
        if not isinstance(item, dict) or set(item) != _ACHIEVEMENT_KEYS:
            raise EloIntegrityError("Public Elo achievement has an invalid exact contract.")
        achievement_id = item.get("achievementId")
        category = item.get("category")
        weight = item.get("weight")
        if (
            not isinstance(achievement_id, str)
            or len(achievement_id) > 127
            or not _ACHIEVEMENT_ID.fullmatch(achievement_id)
            or achievement_id in by_id
        ):
            raise EloIntegrityError("Public Elo achievement identity is invalid or duplicated.")
        if category not in ELO_WEIGHTS or type(weight) is not int or weight <= 0:
            raise EloIntegrityError("Public Elo achievement category or weight is invalid.")
        by_id[achievement_id] = copy.deepcopy(item)
        totals[category] += weight
    if any(total <= 0 for total in totals.values()):
        raise EloIntegrityError("Every weighted Elo category requires public benchmark coverage.")
    return copy.deepcopy(suite), by_id


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise EloIntegrityError(f"{field} must be an exact lowercase SHA-256 digest.")
    return value


def _validate_result(value: Any, achievements: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        raise EloIntegrityError("Elo benchmark result has unknown or missing fields.")
    if value.get("schemaVersion") != 1 or value.get("model") != ELO_MODEL:
        raise EloIntegrityError("Elo benchmark result uses an unsupported future model or schema.")
    if _require_digest(value.get("suiteDigest"), "suiteDigest") != PUBLIC_SUITE_DIGEST:
        raise EloIntegrityError("Elo benchmark result is not bound to the public synthetic suite.")
    if _require_digest(value.get("policyDigest"), "policyDigest") != EXPECTED_POLICY_SHA256:
        raise EloIntegrityError("Elo benchmark result is not bound to the immutable policy.")
    _require_digest(value.get("runtimeDigest"), "runtimeDigest")
    version = value.get("pluginVersion")
    commit = value.get("sourceCommit")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise EloIntegrityError("Elo benchmark result pluginVersion is not canonical SemVer.")
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise EloIntegrityError("Elo benchmark result sourceCommit must be a full commit digest.")
    passed = value.get("passedAchievementIds")
    if (
        not isinstance(passed, list)
        or any(not isinstance(item, str) or item not in achievements for item in passed)
        or passed != sorted(set(passed))
    ):
        raise EloIntegrityError("Passed achievement IDs must be unique, sorted public suite identities.")
    regressions = value.get("regressions")
    if not isinstance(regressions, list):
        raise EloIntegrityError("Elo regressions must be a fixed evidence array.")
    seen: set[str] = set()
    for regression in regressions:
        if not isinstance(regression, dict) or set(regression) != _REGRESSION_KEYS:
            raise EloIntegrityError("Elo regression evidence has unknown or missing fields.")
        achievement_id = regression.get("achievementId")
        attribution = regression.get("attribution")
        reproduction_digests = regression.get("reproductionDigests")
        if achievement_id not in achievements or achievement_id in seen:
            raise EloIntegrityError("Elo regression achievement identity is invalid or duplicated.")
        if attribution not in _ATTRIBUTIONS:
            raise EloIntegrityError("Elo regression attribution is not a fixed allowed value.")
        _require_digest(regression.get("conditionDigest"), "conditionDigest")
        if (
            not isinstance(reproduction_digests, list)
            or len(reproduction_digests) not in {1, 2}
            or reproduction_digests != sorted(set(reproduction_digests))
        ):
            raise EloIntegrityError("Regression evidence requires one or two distinct sorted reproductions.")
        for digest in reproduction_digests:
            _require_digest(digest, "reproductionDigest")
        seen.add(achievement_id)
    if [item["achievementId"] for item in regressions] != sorted(seen):
        raise EloIntegrityError("Elo regressions must be ordered by achievementId.")
    return copy.deepcopy(value)


def _bounded_score(previous_score: int, delta: int) -> int:
    if type(previous_score) is not int or type(delta) is not int:
        raise EloIntegrityError("Elo score arithmetic requires exact integers.")
    return max(ELO_MIN, min(ELO_MAX, previous_score + delta))


def _round_half_up(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise EloIntegrityError("Half-up Elo rounding requires non-negative bounded integers.")
    return (2 * numerator + denominator) // (2 * denominator)


def _entry_digest(entry_without_digest_or_seal: dict[str, Any]) -> str:
    return sha256_digest(entry_without_digest_or_seal)


def _unsigned_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in entry.items() if key != "authoritySeal"}


def _verify_entry(
    home: Path,
    path: Path,
    *,
    expected_sequence: int,
    previous_entry: dict[str, Any] | None,
) -> dict[str, Any]:
    try:
        entry = read_canonical_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise EloIntegrityError(f"Elo history is not canonical readable JSON: {error}") from error
    if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
        raise EloIntegrityError("Elo ledger entry has unknown or missing fields.")
    name_match = _HISTORY_NAME.fullmatch(path.name)
    if name_match is None or int(name_match.group(1)) != expected_sequence:
        raise EloIntegrityError("Elo ledger filename or sequence is invalid.")
    if entry.get("schemaVersion") != 1 or entry.get("model") != ELO_MODEL:
        raise EloIntegrityError("Elo ledger entry uses an unsupported future model or schema.")
    if type(entry.get("sequence")) is not int or entry["sequence"] != expected_sequence:
        raise EloIntegrityError("Elo ledger sequence is not contiguous.")
    digest_payload = {
        key: copy.deepcopy(value)
        for key, value in entry.items()
        if key not in {"entryDigest", "authoritySeal"}
    }
    expected_digest = _entry_digest(digest_payload)
    if entry.get("entryDigest") != expected_digest or name_match.group(2) != expected_digest:
        raise EloIntegrityError("Elo ledger digest or filename does not match its event.")
    try:
        verify_authority_seal(
            home,
            "elo-ledger:v1",
            _unsigned_entry(entry),
            entry.get("authoritySeal"),
        )
    except AuthorityIntegrityError as error:
        raise EloIntegrityError(f"Elo ledger authority seal is invalid: {error}") from error
    previous_digest = None if previous_entry is None else previous_entry["entryDigest"]
    previous_score = ELO_MIN if previous_entry is None else previous_entry["score"]
    previous_achievements = set() if previous_entry is None else set(previous_entry["achievementIds"])
    if entry.get("previousEntryDigest") != previous_digest:
        raise EloIntegrityError("Elo ledger previous-entry digest chain is broken.")
    if entry.get("previousScore") != previous_score:
        raise EloIntegrityError("Elo ledger previous score does not match its chain.")
    if entry.get("pluginName") != _PLUGIN_NAME:
        raise EloIntegrityError("Elo ledger plugin identity is invalid.")
    if entry.get("policyDigest") != verify_policy_anchor(home):
        raise EloIntegrityError("Elo ledger policy binding has changed.")
    _require_digest(entry.get("suiteDigest"), "suiteDigest")
    for field in ("runtimeDigest", "baselineResultDigest", "candidateResultDigest"):
        _require_digest(entry.get(field), field)
    for field in ("baselineVersion", "candidateVersion"):
        if not isinstance(entry.get(field), str) or not _SEMVER.fullmatch(entry[field]):
            raise EloIntegrityError("Elo ledger contains an invalid plugin version.")
    for field in ("baselineCommit", "candidateCommit"):
        if not isinstance(entry.get(field), str) or not _COMMIT.fullmatch(entry[field]):
            raise EloIntegrityError("Elo ledger contains an invalid source commit.")
    category_deltas = entry.get("categoryDeltas")
    if not isinstance(category_deltas, dict) or set(category_deltas) != set(ELO_WEIGHTS):
        raise EloIntegrityError("Elo ledger category deltas have an invalid exact contract.")
    for category, cap in ELO_WEIGHTS.items():
        value = category_deltas[category]
        if type(value) is not int or value < -cap or value > cap:
            raise EloIntegrityError("Elo ledger category delta exceeds its fixed cap.")
    delta = entry.get("delta")
    if (
        type(delta) is not int
        or delta < -ELO_EVALUATION_CAP
        or delta > ELO_EVALUATION_CAP
        or delta != sum(category_deltas.values())
    ):
        raise EloIntegrityError("Elo ledger release delta is invalid.")
    expected_score = _bounded_score(previous_score, delta)
    if entry.get("score") != expected_score:
        raise EloIntegrityError("Elo ledger score is outside bounds or inconsistent with its delta.")
    for field in ("achievementIds", "newAchievementIds", "confirmedRegressionIds"):
        values = entry.get(field)
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or any(not isinstance(item, str) or not _ACHIEVEMENT_ID.fullmatch(item) for item in values)
        ):
            raise EloIntegrityError("Elo ledger achievement evidence is invalid.")
    current_achievements = set(entry["achievementIds"])
    if not previous_achievements.issubset(current_achievements):
        raise EloIntegrityError("Elo ledger cannot remove a previously recorded achievement.")
    if not set(entry["newAchievementIds"]).issubset(current_achievements - previous_achievements):
        raise EloIntegrityError("Elo ledger new achievements are inconsistent with history.")
    if not set(entry["confirmedRegressionIds"]).issubset(current_achievements):
        raise EloIntegrityError("Elo ledger regression IDs are not public achievements.")
    return copy.deepcopy(entry)


def _read_entries(home: Path) -> tuple[dict[str, Any], ...]:
    normalized_home = home.expanduser().absolute()
    history_root = assert_guardian_storage_path(
        normalized_home, GuardianPaths(normalized_home).elo_history
    )
    if not history_root.exists():
        return ()
    if not history_root.is_dir():
        raise EloIntegrityError("Elo history path must be a directory.")
    paths = sorted(history_root.iterdir(), key=lambda item: item.name)
    if any(not item.is_file() or _HISTORY_NAME.fullmatch(item.name) is None for item in paths):
        raise EloIntegrityError("Elo history contains an unknown or redirected artifact.")
    entries: list[dict[str, Any]] = []
    for sequence, path in enumerate(paths, start=1):
        try:
            safe_path = assert_guardian_storage_path(normalized_home, path)
        except PathIntegrityError as error:
            raise EloIntegrityError(f"Elo history path is unsafe: {error}") from error
        entries.append(
            _verify_entry(
                normalized_home,
                safe_path,
                expected_sequence=sequence,
                previous_entry=None if not entries else entries[-1],
            )
        )
    return tuple(entries)


def read_elo_state(home: Path) -> dict[str, Any]:
    """Verify the complete ledger and return its non-private current projection."""

    entries = _read_entries(home)
    if not entries:
        return _default_state()
    latest = entries[-1]
    return {
        "schemaVersion": 1,
        "model": ELO_MODEL,
        "score": latest["score"],
        "sequence": latest["sequence"],
        "entryDigest": latest["entryDigest"],
        "achievementIds": copy.deepcopy(latest["achievementIds"]),
    }


@contextmanager
def _elo_transaction_lock(home: Path, *, timeout_seconds: float = 5.0) -> Iterator[None]:
    normalized_home = home.expanduser().absolute()
    lock_path = assert_guardian_storage_path(
        normalized_home, GuardianPaths(normalized_home).elo / "transaction.lock"
    )
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    descriptor = -1
    while True:
        try:
            descriptor = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            token = b"guardian-elo-transaction-v1\n"
            view = memoryview(token)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Elo transaction lock write did not make progress.")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            break
        except FileExistsError as error:
            if time.monotonic() >= deadline:
                raise EloIntegrityError("Elo ledger transaction is already in progress.") from error
            time.sleep(0.01)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            lock_path.unlink(missing_ok=True)
            raise
    try:
        if lock_path.read_bytes() != b"guardian-elo-transaction-v1\n":
            raise EloIntegrityError("Elo ledger transaction lock changed after acquisition.")
        yield
    finally:
        if not lock_path.is_file() or lock_path.read_bytes() != b"guardian-elo-transaction-v1\n":
            raise EloIntegrityError("Elo ledger transaction lock changed before release.")
        lock_path.unlink()


def evaluate_elo(home: Path, baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Compare exact public synthetic results and append one deterministic sealed event."""

    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    _, achievements = _public_suite()
    baseline_result = _validate_result(baseline, achievements)
    candidate_result = _validate_result(candidate, achievements)
    for field in ("suiteDigest", "policyDigest", "runtimeDigest"):
        if baseline_result[field] != candidate_result[field]:
            raise EloIntegrityError(f"Baseline and candidate {field} values must match exactly.")
    if baseline_result["policyDigest"] != policy_digest:
        raise EloIntegrityError("Benchmark results do not match the installed immutable policy.")

    baseline_passed = set(baseline_result["passedAchievementIds"])
    candidate_passed = set(candidate_result["passedAchievementIds"])
    lost = baseline_passed - candidate_passed
    regression_by_id = {
        item["achievementId"]: item for item in candidate_result["regressions"]
    }
    if not set(regression_by_id).issubset(lost):
        raise EloIntegrityError("Regression evidence may name only a lost baseline achievement.")

    with _elo_transaction_lock(normalized_home):
        entries = _read_entries(normalized_home)
        state = _default_state() if not entries else {
            "score": entries[-1]["score"],
            "sequence": entries[-1]["sequence"],
            "entryDigest": entries[-1]["entryDigest"],
            "achievementIds": copy.deepcopy(entries[-1]["achievementIds"]),
        }
        historical = set(state["achievementIds"])
        new_ids = (candidate_passed - baseline_passed) - historical
        confirmed_regression_ids: set[str] = set()
        unconfirmed_guardian_regression = False
        for achievement_id in lost:
            evidence = regression_by_id.get(achievement_id)
            if evidence is None:
                unconfirmed_guardian_regression = True
            elif evidence["attribution"] == "guardian":
                if len(evidence["reproductionDigests"]) == 2:
                    confirmed_regression_ids.add(achievement_id)
                else:
                    unconfirmed_guardian_regression = True

        category_deltas: dict[str, int] = {}
        for category, cap in ELO_WEIGHTS.items():
            total_weight = sum(
                item["weight"] for item in achievements.values() if item["category"] == category
            )
            positive_weight = sum(
                achievements[achievement_id]["weight"]
                for achievement_id in new_ids
                if achievements[achievement_id]["category"] == category
            )
            negative_weight = sum(
                achievements[achievement_id]["weight"]
                for achievement_id in confirmed_regression_ids
                if achievements[achievement_id]["category"] == category
            )
            net_weight = positive_weight - negative_weight
            if net_weight == 0:
                category_delta = 0
            else:
                magnitude = _round_half_up(cap * abs(net_weight), total_weight)
                category_delta = magnitude if net_weight > 0 else -magnitude
            if unconfirmed_guardian_regression and category_delta > 0:
                category_delta = 0
            category_deltas[category] = category_delta

        delta = max(
            -ELO_EVALUATION_CAP,
            min(ELO_EVALUATION_CAP, sum(category_deltas.values())),
        )
        previous_score = state["score"]
        score = _bounded_score(previous_score, delta)
        cumulative_achievements = sorted(
            historical | baseline_passed | candidate_passed
        )
        sequence = state["sequence"] + 1
        digest_payload = {
            "schemaVersion": 1,
            "model": ELO_MODEL,
            "sequence": sequence,
            "previousEntryDigest": state["entryDigest"],
            "pluginName": _PLUGIN_NAME,
            "policyDigest": policy_digest,
            "suiteDigest": PUBLIC_SUITE_DIGEST,
            "runtimeDigest": candidate_result["runtimeDigest"],
            "baselineResultDigest": sha256_digest(baseline_result),
            "candidateResultDigest": sha256_digest(candidate_result),
            "baselineVersion": baseline_result["pluginVersion"],
            "candidateVersion": candidate_result["pluginVersion"],
            "baselineCommit": baseline_result["sourceCommit"],
            "candidateCommit": candidate_result["sourceCommit"],
            "previousScore": previous_score,
            "categoryDeltas": category_deltas,
            "delta": delta,
            "score": score,
            "achievementIds": cumulative_achievements,
            "newAchievementIds": sorted(new_ids),
            "confirmedRegressionIds": sorted(confirmed_regression_ids),
        }
        entry_digest = _entry_digest(digest_payload)
        unsigned = {**digest_payload, "entryDigest": entry_digest}
        try:
            seal = authority_seal(normalized_home, "elo-ledger:v1", unsigned)
        except AuthorityIntegrityError as error:
            raise EloIntegrityError(f"Elo ledger authority is unavailable: {error}") from error
        entry = {**unsigned, "authoritySeal": seal}
        history_path = GuardianPaths(normalized_home).elo_history / (
            f"{sequence:020d}-{entry_digest}.sealed.json"
        )
        try:
            exclusive_write_json(normalized_home, history_path, entry)
        except FileExistsError as error:
            raise EloIntegrityError("Elo ledger event already exists; history is create-once.") from error
        verified = _read_entries(normalized_home)
        if not verified or verified[-1] != entry:
            raise EloIntegrityError("Elo ledger append failed post-write verification.")
    return {
        "schemaVersion": 1,
        "model": ELO_MODEL,
        "score": score,
        "previousScore": previous_score,
        "delta": delta,
        "categoryDeltas": copy.deepcopy(category_deltas),
        "sequence": sequence,
        "entryDigest": entry_digest,
        "achievementIds": copy.deepcopy(cumulative_achievements),
        "newAchievementIds": sorted(new_ids),
        "confirmedRegressionIds": sorted(confirmed_regression_ids),
    }
