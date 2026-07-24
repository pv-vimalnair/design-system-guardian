"""Immutable, generic public benchmark cases for Guardian Elo."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
CATEGORIES = {
    "correctness",
    "reliability",
    "coverage_usefulness",
    "safety_privacy_integrity",
    "portability_usability_performance",
}


def _json(root: Path, relative: str) -> dict:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def case_correctness_exact_identity(root: Path) -> None:
    assert _json(root, ".codex-plugin/plugin.json")["name"] == "design-system-guardian"


def case_correctness_fail_closed(root: Path) -> None:
    policy = _json(root, "policy/policy-v1.json")
    assert _canonical_digest(policy) == POLICY_DIGEST


def case_reliability_repeatability(root: Path) -> None:
    skills = sorted(path.name for path in (root / "skills").iterdir() if path.is_dir())
    assert skills == ["audit-design-system", "build-with-design-system"]


def case_reliability_tamper_detection(root: Path) -> None:
    for path in sorted((root / "schemas" / "evolution").glob("*.schema.json")):
        assert _json(root, path.relative_to(root).as_posix())["additionalProperties"] is False


def case_coverage_supported_lanes(root: Path) -> None:
    suite = _json(root, "benchmarks/elo-suite.json")
    assert {item["category"] for item in suite["achievements"]} == CATEGORIES


def case_coverage_useful_diagnostics(root: Path) -> None:
    suite = _json(root, "benchmarks/elo-suite.json")
    assert all(item["caseFunction"].startswith("case_") for item in suite["achievements"])


def case_safety_privacy_boundary(root: Path) -> None:
    text = (root / "benchmarks" / "elo-suite.json").read_text(encoding="utf-8")
    assert not re.search(r"profileId|projectRoot|company|[A-Za-z]:\\\\|/Users/", text)


def case_safety_policy_integrity(root: Path) -> None:
    assert "EXPECTED_POLICY_SHA256" not in (root / "policy" / "policy-v1.json").read_text(
        encoding="utf-8"
    )


def case_portability_basic_host(root: Path) -> None:
    manifest = _json(root, ".codex-plugin/plugin.json")
    assert manifest["skills"] == "./skills/"


def case_usability_cli_contract(root: Path) -> None:
    installer = (root / "scripts" / "install_agent_skills.py").read_text(encoding="utf-8")
    launcher = (root / "scripts" / "generic_skill_launcher.py").read_text(encoding="utf-8")
    assert '"benchmarks"' in installer and '"benchmarks"' in launcher


def case_performance_bounded_runtime(root: Path) -> None:
    suite = _json(root, "benchmarks/elo-suite.json")
    assert 1 <= len(suite["achievements"]) <= 64
    assert all(type(item["weight"]) is int and item["weight"] > 0 for item in suite["achievements"])
