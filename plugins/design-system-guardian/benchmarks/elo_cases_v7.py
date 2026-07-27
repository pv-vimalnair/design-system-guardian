"""Immutable additive v0.3.7 cases for Guardian weighted Elo.

The module uses only Python's standard library and privacy-safe synthetic
inputs. Every case runs in the isolated Elo worker and writes, when needed,
only below its temporary directory. Local scores, results, and history are not
part of this public suite.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def _target_import(root: Path) -> Iterator[None]:
    assert (root / "guardian_core").is_dir()
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))
        for name in tuple(sys.modules):
            if name == "guardian_core" or name.startswith("guardian_core."):
                sys.modules.pop(name, None)


def _support() -> object:
    return importlib.import_module("tests.test_judgment_decisions_dsg027")


def _patch() -> object:
    return importlib.import_module("unittest.mock").patch


def _assessment(context: dict, candidate_results: list[dict]) -> dict:
    builder = importlib.import_module("guardian_core.judgment_assessment")
    return builder.build_judgment_assessment(
        run_pin=context["runPin"],
        rule_snapshot=context["ruleSnapshot"],
        analysis_attestation=context["analysisAttestation"],
        audit_result=context["auditResult"],
        candidate_results=candidate_results,
    )


def _identity(context: dict) -> tuple[str, str]:
    pin = context["runPin"]
    return pin["profileId"], pin["runId"]


def _approval_bundle(
    profile: str,
    run: str,
    candidate: dict,
    permission_binding: dict,
) -> dict:
    return dict(
        schemaVersion=1,
        profileId=profile,
        runId=run,
        candidate=candidate,
        permission={**permission_binding, "granted": True},
    )


def _allowed_candidate() -> dict:
    return {
        "ruleId": "rule.system-balance",
        "targetId": None,
        "status": "allowed",
        "incompletenessReason": None,
        "findings": [],
    }


def case_correctness_complete_judgment_assessment(root: Path) -> None:
    with _target_import(root):
        support = _support()
        temporary, _, context = support.provision_home()
        try:
            assessment = _assessment(
                context,
                support.candidate()["candidateResults"],
            )
            assert assessment["complete"] is True
            assert assessment["rawStatus"] == "conflict"
            assert assessment["nonJudgmentBlockersClear"] is True
            conflicts = [
                finding
                for instance in assessment["instances"]
                if instance["rawStatus"] == "conflict"
                for finding in instance["findings"]
            ]
            assert conflicts
            assert all(item["findingId"].startswith("finding-") for item in conflicts)
        finally:
            temporary.cleanup()


def case_correctness_positive_judgment_approval(root: Path) -> None:
    with _target_import(root):
        support = _support()
        decisions = importlib.import_module("guardian_core.judgment_decisions")
        temporary, home, context = support.provision_home()
        try:
            profile, run = _identity(context)
            candidate = support.candidate()
            candidate["candidateResults"] = [_allowed_candidate()]
            with _patch()(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=context,
            ):
                preview = decisions.preview_judgment_decision(
                    home,
                    profile_id=profile,
                    run_id=run,
                    candidate=candidate,
                )
                assert preview["status"] == "permission_required"
                applied = decisions.apply_judgment_decision(
                    home,
                    _approval_bundle(
                        profile,
                        run,
                        candidate,
                        preview["permissionBinding"],
                    ),
                )
                assert applied["changed"] is True
                status = decisions.read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run,
                )
            assert status["status"] == "active"
            assert status["assessment"]["rawStatus"] == "allowed"
            assert status["effectiveProjection"]["effectiveStatus"] == "allowed"
        finally:
            temporary.cleanup()


def case_coverage_selected_judgment_exception(root: Path) -> None:
    with _target_import(root):
        support = _support()
        decisions = importlib.import_module("guardian_core.judgment_decisions")
        temporary, home, context = support.provision_home()
        try:
            profile, run = _identity(context)
            assessment = _assessment(
                context,
                support.candidate()["candidateResults"],
            )
            finding = next(
                finding
                for instance in assessment["instances"]
                if instance["rawStatus"] == "conflict"
                for finding in instance["findings"]
            )
            candidate = support.candidate(
                ids=[finding["findingId"]],
                all_conflicts=False,
            )
            with _patch()(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=context,
            ):
                preview = decisions.preview_judgment_decision(
                    home,
                    profile_id=profile,
                    run_id=run,
                    candidate=candidate,
                )
                decisions.apply_judgment_decision(
                    home,
                    _approval_bundle(
                        profile,
                        run,
                        candidate,
                        preview["permissionBinding"],
                    ),
                )
                status = decisions.read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run,
                )
            exceptions = [
                item
                for instance in status["effectiveProjection"]["instances"]
                for item in instance["appliedExceptions"]
            ]
            assert exceptions == [
                {
                    "findingId": finding["findingId"],
                    "label": "Passed through a user-approved exception",
                }
            ]
            assert status["effectiveProjection"]["effectiveStatus"] == "allowed"
        finally:
            temporary.cleanup()


def case_reliability_judgment_revocation(root: Path) -> None:
    with _target_import(root):
        support = _support()
        decisions = importlib.import_module("guardian_core.judgment_decisions")
        temporary, home, context = support.provision_home()
        try:
            profile, run = _identity(context)
            candidate = support.candidate()
            with _patch()(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=context,
            ):
                preview = decisions.preview_judgment_decision(
                    home,
                    profile_id=profile,
                    run_id=run,
                    candidate=candidate,
                )
                decisions.apply_judgment_decision(
                    home,
                    _approval_bundle(
                        profile,
                        run,
                        candidate,
                        preview["permissionBinding"],
                    ),
                )
                active = decisions.read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run,
                )
                revocation = dict(
                    schemaVersion=1,
                    profileId=profile,
                    runId=run,
                    permission={
                        **active["revocationPermissionBinding"],
                        "granted": True,
                    },
                )
                first = decisions.revoke_judgment_decision(home, revocation)
                second = decisions.revoke_judgment_decision(home, revocation)
                revoked = decisions.read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run,
                )
            assert first["changed"] is True
            assert second["changed"] is False
            assert revoked["status"] == "revoked"
            assert revoked["effectiveProjection"]["effectiveStatus"] == "conflict"
        finally:
            temporary.cleanup()


def case_reliability_judgment_replay_rejection(root: Path) -> None:
    with _target_import(root):
        support = _support()
        decisions = importlib.import_module("guardian_core.judgment_decisions")
        temporary, home, context = support.provision_home()
        try:
            profile, run = _identity(context)
            candidate = support.candidate()
            with _patch()(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=context,
            ):
                preview = decisions.preview_judgment_decision(
                    home,
                    profile_id=profile,
                    run_id=run,
                    candidate=candidate,
                )
                bundle = _approval_bundle(
                    profile,
                    run,
                    candidate,
                    preview["permissionBinding"],
                )
                decisions.apply_judgment_decision(home, bundle)
                replay = copy.deepcopy(bundle)
                replay["candidate"]["reason"] = "Synthetic divergent retry."
                rejected = False
                try:
                    decisions.apply_judgment_decision(home, replay)
                except decisions.JudgmentDecisionIntegrityError:
                    rejected = True
                assert rejected
                assert decisions.read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run,
                )["status"] == "active"
        finally:
            temporary.cleanup()


def case_safety_hard_lane_non_override(root: Path) -> None:
    with _target_import(root):
        support = _support()
        decisions = importlib.import_module("guardian_core.judgment_decisions")
        temporary, home, context = support.provision_home()
        try:
            blocked = copy.deepcopy(context)
            blocked["auditResult"]["designSystemLane"]["status"] = "invalid"
            blocked["analysisAttestation"]["auditResultDigest"] = (
                support.attested_audit_digest(blocked["auditResult"])
            )
            profile, run = _identity(blocked)
            with _patch()(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=blocked,
            ):
                rejected = False
                try:
                    decisions.preview_judgment_decision(
                        home,
                        profile_id=profile,
                        run_id=run,
                        candidate=support.candidate(),
                    )
                except decisions.JudgmentDecisionIntegrityError:
                    rejected = True
                assert rejected
            assert not (home / "profiles" / profile / "audits" / run).exists()
        finally:
            temporary.cleanup()


def case_safety_local_judgment_privacy(root: Path) -> None:
    repository_root = root.parents[1]
    checker_path = repository_root / "scripts" / "check_public_release.py"
    spec = importlib.util.spec_from_file_location(
        "guardian_synthetic_release_checker_v7",
        checker_path,
    )
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = checker
    try:
        spec.loader.exec_module(checker)
        assert {
            "findingId",
            "assessmentDigest",
            "decisionDigest",
            "evidenceDigest",
            "reason",
        }.issubset(checker.IDENTIFIER_KEYS)
        assert {
            "plugins/design-system-guardian/judgments/",
            "plugins/design-system-guardian/decisions/",
            "plugins/design-system-guardian/judgment-decisions/",
            "plugins/design-system-guardian/decision-history/",
        }.issubset(checker.RUNTIME_PREFIXES)
        synthetic_runtime = json.dumps(
            dict(
                profileId="synthetic-profile",
                runId="synthetic-run",
                assessmentDigest="a" * 64,
            )
        ).encode("utf-8")
        assert checker._runtime_json(
            synthetic_runtime,
            "plugins/design-system-guardian/docs/synthetic-runtime.json",
        )
        public_schema = json.dumps(
            {"properties": {"reason": {"type": "string"}}}
        ).encode("utf-8")
        assert not checker._runtime_json(
            public_schema,
            "plugins/design-system-guardian/schemas/synthetic.schema.json",
        )
        assert "telemetry" not in checker_path.read_text(encoding="utf-8").lower()
    finally:
        sys.modules.pop(spec.name, None)


def case_portability_four_judgment_commands(root: Path) -> None:
    with _target_import(root):
        cli = importlib.import_module("guardian_core.cli")
        parser = cli.build_parser()
        command_action = next(
            action
            for action in parser._actions
            if getattr(action, "dest", None) == "command"
        )
        assert "judgment" in command_action.choices
        judgment_parser = command_action.choices["judgment"]
        judgment_action = next(
            action
            for action in judgment_parser._actions
            if getattr(action, "dest", None) == "judgment_command"
        )
        assert {"preview", "apply", "status", "revoke"}.issubset(
            judgment_action.choices
        )
        commands = (
            (
                [
                    "judgment",
                    "preview",
                    "--profile",
                    "synthetic-profile",
                    "--run-id",
                    "synthetic-run",
                    "--input",
                    "synthetic.json",
                ],
                "preview",
            ),
            (
                ["judgment", "apply", "--input", "synthetic.json"],
                "apply",
            ),
            (
                [
                    "judgment",
                    "status",
                    "--profile",
                    "synthetic-profile",
                    "--run-id",
                    "synthetic-run",
                ],
                "status",
            ),
            (
                ["judgment", "revoke", "--input", "synthetic.json"],
                "revoke",
            ),
        )
        for arguments, expected in commands:
            parsed = parser.parse_args(arguments)
            assert parsed.command == "judgment"
            assert parsed.judgment_command == expected
            assert callable(parsed.handler)
