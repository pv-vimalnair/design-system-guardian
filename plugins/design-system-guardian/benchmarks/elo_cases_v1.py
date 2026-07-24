"""Immutable stdlib-only behavioral cases for Guardian weighted Elo."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
AUDIT_LANES = (
    "components", "icons", "colors", "typography", "spacing", "radii", "effects", "motion"
)


def _read_json(path: Path) -> dict:
    assert path.is_file()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise AssertionError("required canonical JSON is unavailable") from error
    assert isinstance(value, dict)
    return value


@contextmanager
def _target_import(root: Path):
    assert (root / "guardian_core").is_dir()
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))
        for name in tuple(sys.modules):
            if name == "guardian_core" or name.startswith("guardian_core."):
                sys.modules.pop(name, None)


def _snapshot() -> dict:
    return {
        "profileId": "synthetic-public",
        "snapshotId": "a" * 64,
        "sourceState": "fresh",
        "sourceAvailable": True,
        "sourceComplete": True,
        "tokens": {
            "color.action.primary": {
                "identity": "color.action.primary",
                "type": "color",
                "approved": True,
                "deprecated": False,
                "provenance": {"published": True},
            }
        },
        "registry": {"components": [], "icons": []},
    }


def _resolve(root: Path, request: dict) -> dict:
    with _target_import(root):
        resolver = importlib.import_module("guardian_core.resolver")
        return resolver._resolve_verified_snapshot_identity(
            profile_id="synthetic-public",
            snapshot=_snapshot(),
            request=request,
            policy_digest=POLICY_DIGEST,
        )


def _run(root: Path, *arguments: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    script = root / "scripts" / "guardian.py"
    assert script.is_file()
    try:
        return subprocess.run(
            [sys.executable, "-B", str(script), *arguments],
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssertionError("bounded Guardian CLI execution failed") from error


def case_correctness_exact_identity(root: Path) -> None:
    exact = _resolve(root, {"kind": "token", "identity": "color.action.primary"})
    raw = _resolve(root, {"kind": "token", "value": "#3157D8"})
    assert exact["status"] == "allowed"
    assert exact["selectedIdentity"] == "color.action.primary"
    assert raw["status"] == "invalid" and raw["selectedIdentity"] is None


def case_correctness_fail_closed(root: Path) -> None:
    missing = _resolve(root, {"kind": "token", "identity": "color.unapproved"})
    unknown = _resolve(
        root,
        {"kind": "token", "identity": "color.action.primary", "fallback": "nearest"},
    )
    assert missing["status"] == "missing" and missing["sentinel"]["productionReady"] is False
    assert unknown["status"] == "invalid" and unknown["evidence"]["denyWins"] is True


def case_reliability_repeatability(root: Path) -> None:
    request = {"kind": "token", "identity": "color.action.primary"}
    first = json.dumps(_resolve(root, request), sort_keys=True, separators=(",", ":"))
    second = json.dumps(_resolve(root, request), sort_keys=True, separators=(",", ":"))
    assert first == second


def case_reliability_tamper_detection(root: Path) -> None:
    with _target_import(root):
        policy = importlib.import_module("guardian_core.policy")
        assert policy._verify_shipped_policy()
        original = policy.EXPECTED_POLICY_SHA256
        policy.EXPECTED_POLICY_SHA256 = "0" * 64
        try:
            try:
                policy._verify_shipped_policy()
            except policy.PolicyIntegrityError:
                pass
            else:
                raise AssertionError("policy tamper was accepted")
        finally:
            policy.EXPECTED_POLICY_SHA256 = original


def case_coverage_supported_lanes(root: Path) -> None:
    with _target_import(root):
        audit = importlib.import_module("guardian_core.audit")
        assert tuple(audit.AUDIT_CATEGORIES) == AUDIT_LANES
        assert set(audit._CATEGORY_KEYS) == {"status", "assessedItems", "totalItems"}


def case_coverage_useful_diagnostics(root: Path) -> None:
    with _target_import(root):
        post_run = importlib.import_module("guardian_core.post_run")
        expected = {
            "missing": "resolution_missing",
            "ambiguous": "resolution_ambiguous",
            "conflict": "resolution_conflict",
            "invalid": "resolution_invalid",
            "unsupported": "resolution_unsupported",
            "stale": "resolution_stale",
            "source_unavailable": "resolution_source_unavailable",
            "source_incomplete": "resolution_source_incomplete",
            "not_assessed": "resolution_not_assessed",
        }
        assert {key: value[0] for key, value in post_run._RESOLUTION_REASONS.items()} == expected


def case_safety_privacy_boundary(root: Path) -> None:
    with _target_import(root):
        installer = importlib.import_module("scripts.install_agent_skills")
        before = installer.package_digest(root)
        assert "profiles" not in installer.PACKAGE_ENTRIES
        assert "trust" not in installer.PACKAGE_ENTRIES
        assert before == installer.package_digest(root)
    suite_path = root / "benchmarks" / "elo-suite.json"
    assert suite_path.is_file()
    public = suite_path.read_text(encoding="utf-8")
    assert all(term not in public for term in ("profileId", "projectRoot", "company", "/Users/"))


def case_safety_policy_integrity(root: Path) -> None:
    with _target_import(root):
        canonical = importlib.import_module("guardian_core.canonical")
        policy = importlib.import_module("guardian_core.policy")
        assert policy.EXPECTED_POLICY_SHA256 == POLICY_DIGEST
        assert canonical.sha256_digest(policy.shipped_policy()) == POLICY_DIGEST


def case_portability_basic_host(root: Path) -> None:
    manifest = _read_json(root / ".codex-plugin" / "plugin.json")
    assert manifest["name"] == "design-system-guardian"
    assert manifest["skills"] == "./skills/"
    assert sorted(path.name for path in (root / "skills").iterdir() if (path / "SKILL.md").is_file()) == [
        "audit-design-system", "build-with-design-system"
    ]


def case_usability_cli_contract(root: Path) -> None:
    result = _run(root, "--help")
    assert result.returncode == 0 and not result.stderr
    for command in ("doctor", "resolve", "audit", "finalize", "self-check", "migrate"):
        assert command in result.stdout
    with tempfile.TemporaryDirectory() as directory:
        installed = Path(directory) / "skills"
        installer = root / "scripts" / "install_agent_skills.py"
        result = subprocess.run(
            [sys.executable, "-B", str(installer), "--target-root", str(installed), "--python", sys.executable],
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        assert result.returncode == 0
        assert sorted(path.name for path in installed.iterdir()) == [
            "audit-design-system", "build-with-design-system"
        ]


def case_performance_bounded_runtime(root: Path) -> None:
    started = time.monotonic()
    result = _run(root, "--help", timeout=10.0)
    assert result.returncode == 0 and time.monotonic() - started < 10.0
    assert len(result.stdout.encode("utf-8")) <= 65536
