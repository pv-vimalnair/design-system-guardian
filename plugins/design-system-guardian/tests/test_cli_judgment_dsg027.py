from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardian_core.canonical import sha256_digest
from guardian_core.judgment_assessment import build_judgment_assessment
from tests.test_judgment_assessment_dsg027 import conflict_candidate, judgment_rule
from tests.test_judgment_decisions_dsg027 import candidate, provision_home


def invoke(home: Path, argv: list[str]) -> tuple[int, dict]:
    from guardian_core.cli import main

    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch("guardian_core.cli.default_guardian_home", return_value=home),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        code = main(argv)
    stream = stdout.getvalue() if stdout.getvalue() else stderr.getvalue()
    return code, json.loads(stream)


def write_json(path: Path, value: dict) -> None:
    from guardian_core.canonical import atomic_write_json

    atomic_write_json(path, value)


def file_state(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def multi_instance_candidate(context: dict) -> tuple[dict, list[str]]:
    context["ruleSnapshot"]["rules"].append(judgment_rule("rule.second-balance"))
    context["ruleSnapshot"]["rulesDigest"] = sha256_digest(
        context["ruleSnapshot"]["rules"]
    )
    first = conflict_candidate()
    second = copy.deepcopy(first)
    second["ruleId"] = "rule.second-balance"
    second["findings"][0]["explanation"] = (
        "The secondary hierarchy hides the completion state."
    )
    assessment = build_judgment_assessment(
        run_pin=context["runPin"],
        rule_snapshot=context["ruleSnapshot"],
        analysis_attestation=context["analysisAttestation"],
        audit_result=context["auditResult"],
        candidate_results=[first, second],
    )
    traversal_ids = [
        finding["findingId"]
        for instance in assessment["instances"]
        for finding in instance["findings"]
    ]
    return (
        {
            "candidateResults": [first, second],
            "selection": {"mode": "all_conflicts", "findingIds": []},
            "reason": "Accepted for this exact reviewed run.",
        },
        traversal_ids,
    )

class JudgmentCliTest(unittest.TestCase):
    def test_integrity_error_remains_value_error_with_bounded_write_state(self) -> None:
        from guardian_core.judgment_decisions import JudgmentDecisionIntegrityError

        unchanged = JudgmentDecisionIntegrityError("before write")
        changed = JudgmentDecisionIntegrityError(
            "after write", local_changes_performed=True
        )
        self.assertIsInstance(unchanged, ValueError)
        self.assertFalse(unchanged.local_changes_performed)
        self.assertTrue(changed.local_changes_performed)
        with self.assertRaises(TypeError):
            JudgmentDecisionIntegrityError(
                "invalid flag", local_changes_performed=1  # type: ignore[arg-type]
            )
    def test_exact_four_command_surface_is_registered(self) -> None:
        from guardian_core.cli import build_parser

        parser = build_parser()
        cases = (
            (
                ["judgment", "preview", "--profile", "profile", "--run-id", "run", "--input", "candidate.json"],
                "_judgment_preview_command",
            ),
            (["judgment", "apply", "--input", "granted.json"], "_judgment_apply_command"),
            (
                ["judgment", "status", "--profile", "profile", "--run-id", "run"],
                "_judgment_status_command",
            ),
            (["judgment", "revoke", "--input", "revocation.json"], "_judgment_revoke_command"),
        )
        for argv, handler_name in cases:
            with self.subTest(argv=argv):
                self.assertEqual(parser.parse_args(argv).handler.__name__, handler_name)

    def test_preview_apply_status_and_revoke_use_explicit_grants(self) -> None:
        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run = context["runPin"]["runId"]
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        write_json(candidate_path, candidate())

        before_preview = file_state(home)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            code, preview = invoke(
                home,
                [
                    "judgment",
                    "preview",
                    "--profile",
                    profile,
                    "--run-id",
                    run,
                    "--input",
                    str(candidate_path),
                ],
            )
        self.assertEqual(code, 4)
        self.assertEqual(file_state(home), before_preview)
        self.assertEqual(preview["status"], "permission_required")
        self.assertTrue(preview["permissionRequired"])
        self.assertEqual(
            preview["explanation"]["options"],
            ["Fix and evaluate again", "Approve this exact version anyway"],
        )
        self.assertIn("whatFailed", preview["explanation"]["findings"][0])
        self.assertIn("whyItMatters", preview["explanation"]["findings"][0])
        self.assertIn("recommendedCorrection", preview["explanation"]["findings"][0])

        denied_path = root / "denied.json"
        denied = {
            "schemaVersion": 1,
            "profileId": profile,
            "runId": run,
            "candidate": candidate(),
            "permission": {**preview["permissionBinding"], "granted": False},
        }
        write_json(denied_path, denied)
        before_denial = file_state(home)
        code, failure = invoke(home, ["judgment", "apply", "--input", str(denied_path)])
        self.assertEqual(code, 2)
        self.assertEqual(failure["status"], "invalid")
        self.assertFalse(failure["localChangesPerformed"])
        self.assertEqual(file_state(home), before_denial)

        granted = copy.deepcopy(denied)
        granted["permission"]["granted"] = True
        granted_path = root / "granted.json"
        write_json(granted_path, granted)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            code, applied = invoke(home, ["judgment", "apply", "--input", str(granted_path)])
        self.assertEqual(code, 0)
        self.assertTrue(applied["changed"])
        self.assertFalse(applied["productionReady"])

        before_status = file_state(home)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            code, status = invoke(
                home,
                ["judgment", "status", "--profile", profile, "--run-id", run],
            )
        self.assertEqual(code, 4)
        self.assertEqual(file_state(home), before_status)
        self.assertEqual(status["effectiveProjection"]["effectiveStatus"], "allowed")
        applied_exceptions = [
            exception
            for instance in status["effectiveProjection"]["instances"]
            for exception in instance["appliedExceptions"]
        ]
        self.assertEqual(
            applied_exceptions[0]["label"],
            "Passed through a user-approved exception",
        )
        self.assertIn("Passed through a user-approved exception", status["readableReport"])
        self.assertFalse(status["productionReady"])

        revocation_path = root / "revocation.json"
        write_json(
            revocation_path,
            {
                "schemaVersion": 1,
                "profileId": profile,
                "runId": run,
                "permission": {
                    **status["revocationPermissionBinding"],
                    "granted": True,
                },
            },
        )
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            code, revoked = invoke(
                home, ["judgment", "revoke", "--input", str(revocation_path)]
            )
        self.assertEqual(code, 0)
        self.assertEqual(revoked["status"], "revoked")
        self.assertFalse(revoked["productionReady"])

    def test_multi_instance_selection_renders_in_global_canonical_order(self) -> None:
        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run = context["runPin"]["runId"]
        root = Path(temporary.name)
        exact_candidate, traversal_ids = multi_instance_candidate(context)
        self.assertNotEqual(traversal_ids, sorted(traversal_ids))
        candidate_path = root / "multi-instance-candidate.json"
        write_json(candidate_path, exact_candidate)

        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview_code, preview = invoke(
                home,
                [
                    "judgment", "preview", "--profile", profile,
                    "--run-id", run, "--input", str(candidate_path),
                ],
            )
        self.assertEqual(preview_code, 4)
        grant_path = root / "multi-instance-grant.json"
        write_json(
            grant_path,
            {
                "schemaVersion": 1,
                "profileId": profile,
                "runId": run,
                "candidate": exact_candidate,
                "permission": {**preview["permissionBinding"], "granted": True},
            },
        )

        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            apply_code, applied = invoke(
                home, ["judgment", "apply", "--input", str(grant_path)]
            )
        self.assertEqual(apply_code, 0)
        self.assertTrue(applied["localChangesPerformed"])
        self.assertEqual(applied["effectiveProjection"]["effectiveStatus"], "allowed")
        self.assertIn(
            "Selected finding IDs: " + ", ".join(sorted(traversal_ids)),
            applied["readableReport"],
        )

        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            status_code, status = invoke(
                home, ["judgment", "status", "--profile", profile, "--run-id", run]
            )
        self.assertEqual(status_code, 4)
        self.assertEqual(status["effectiveProjection"]["effectiveStatus"], "allowed")
        self.assertIn(
            "Selected finding IDs: " + ", ".join(sorted(traversal_ids)),
            status["readableReport"],
        )

    def test_partial_apply_head_failure_reports_durable_writes_and_retries(self) -> None:
        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run = context["runPin"]["runId"]
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        write_json(candidate_path, candidate())
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            _, preview = invoke(
                home,
                [
                    "judgment", "preview", "--profile", profile,
                    "--run-id", run, "--input", str(candidate_path),
                ],
            )
        grant_path = root / "grant.json"
        write_json(
            grant_path,
            {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": True},
            },
        )
        sensitive = f"private reason and evidence at {root}"
        with (
            patch("guardian_core.judgment_decisions._reopen_context", return_value=context),
            patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError(sensitive),
            ),
        ):
            code, failure = invoke(
                home, ["judgment", "apply", "--input", str(grant_path)]
            )
        self.assertEqual(code, 2)
        self.assertTrue(failure["localChangesPerformed"])
        self.assertNotIn(sensitive, json.dumps(failure, sort_keys=True))
        audit = home / "profiles" / profile / "audits" / run
        self.assertTrue((audit / "judgment-assessment.sealed.json").is_file())
        self.assertEqual(len(list((audit / "judgment-history").glob("*.json"))), 1)
        self.assertFalse((audit / "current-judgment-history.json").exists())

        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            retry_code, retry = invoke(
                home, ["judgment", "apply", "--input", str(grant_path)]
            )
        self.assertEqual(retry_code, 0)
        self.assertTrue(retry["changed"])
        self.assertEqual(retry["status"], "active")

    def test_partial_revoke_head_failure_preserves_prefix_and_recovers(self) -> None:
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            _read_history,
        )

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run = context["runPin"]["runId"]
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        write_json(candidate_path, candidate())
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            _, preview = invoke(
                home,
                [
                    "judgment", "preview", "--profile", profile,
                    "--run-id", run, "--input", str(candidate_path),
                ],
            )
        grant_path = root / "grant.json"
        write_json(
            grant_path,
            {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": True},
            },
        )
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            apply_code, _ = invoke(
                home, ["judgment", "apply", "--input", str(grant_path)]
            )
        self.assertEqual(apply_code, 0)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            _, active = invoke(
                home, ["judgment", "status", "--profile", profile, "--run-id", run]
            )
        revoke_bundle = {
            "schemaVersion": 1,
            "profileId": profile,
            "runId": run,
            "permission": {
                **active["revocationPermissionBinding"],
                "granted": True,
            },
        }
        revoke_path = root / "revoke.json"
        write_json(revoke_path, revoke_bundle)
        audit = home / "profiles" / profile / "audits" / run
        history = audit / "judgment-history"
        head = audit / "current-judgment-history.json"
        records_before = sorted(history.glob("*.json"))
        self.assertEqual(len(records_before), 1)
        self.assertTrue(head.is_file())
        approval_before = records_before[0].read_bytes()
        head_before = head.read_bytes()
        sensitive = f"private reason and evidence at {root}"

        with (
            patch("guardian_core.judgment_decisions._reopen_context", return_value=context),
            patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError(sensitive),
            ),
        ):
            code, failure = invoke(
                home, ["judgment", "revoke", "--input", str(revoke_path)]
            )
        self.assertEqual(code, 2)
        self.assertTrue(failure["localChangesPerformed"])
        self.assertNotIn(sensitive, json.dumps(failure, sort_keys=True))
        records_after = sorted(history.glob("*.json"))
        self.assertEqual(len(records_after), 2)
        self.assertEqual(records_after[0].read_bytes(), approval_before)
        self.assertTrue(head.is_file())
        self.assertEqual(head.read_bytes(), head_before)
        with self.assertRaises(JudgmentDecisionIntegrityError):
            _read_history(home, profile, run)
        partial_records, partial_head = _read_history(
            home, profile, run, allow_partial=True
        )
        self.assertIsNone(partial_head)
        self.assertEqual(
            [record["recordType"] for record in partial_records],
            ["approval", "revocation"],
        )
        partial_bytes = {
            path.name: path.read_bytes() for path in records_after
        }

        divergent = copy.deepcopy(revoke_bundle)
        divergent["permission"]["runManifestDigest"] = "0" * 64
        divergent_path = root / "divergent-revoke.json"
        write_json(divergent_path, divergent)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            divergent_code, divergent_failure = invoke(
                home, ["judgment", "revoke", "--input", str(divergent_path)]
            )
        self.assertEqual(divergent_code, 2)
        self.assertFalse(divergent_failure["localChangesPerformed"])
        self.assertEqual(head.read_bytes(), head_before)
        self.assertEqual(
            {path.name: path.read_bytes() for path in sorted(history.glob("*.json"))},
            partial_bytes,
        )

        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            retry_code, retry = invoke(
                home, ["judgment", "revoke", "--input", str(revoke_path)]
            )
        self.assertEqual(retry_code, 0)
        self.assertTrue(retry["changed"])
        self.assertEqual(retry["status"], "revoked")
        self.assertNotEqual(head.read_bytes(), head_before)
        self.assertEqual(
            {path.name: path.read_bytes() for path in sorted(history.glob("*.json"))},
            partial_bytes,
        )

    def test_post_write_projection_failure_reports_applied_and_revoked_history(self) -> None:
        from guardian_core.judgment_decisions import read_judgment_status

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run = context["runPin"]["runId"]
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        write_json(candidate_path, candidate())
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            _, preview = invoke(
                home,
                [
                    "judgment", "preview", "--profile", profile,
                    "--run-id", run, "--input", str(candidate_path),
                ],
            )
        grant_path = root / "grant.json"
        write_json(
            grant_path,
            {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": True},
            },
        )
        with (
            patch("guardian_core.judgment_decisions._reopen_context", return_value=context),
            patch("guardian_core.cli.render_judgment_report", side_effect=ValueError("late failure")),
        ):
            apply_code, apply_failure = invoke(
                home, ["judgment", "apply", "--input", str(grant_path)]
            )
        self.assertEqual(apply_code, 2)
        self.assertTrue(apply_failure["localChangesPerformed"])
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            active = read_judgment_status(home, profile_id=profile, run_id=run)
        self.assertEqual(active["status"], "active")

        revoke_path = root / "revoke.json"
        write_json(
            revoke_path,
            {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "permission": {
                    **active["revocationPermissionBinding"], "granted": True,
                },
            },
        )
        with (
            patch("guardian_core.judgment_decisions._reopen_context", return_value=context),
            patch("guardian_core.cli.render_judgment_report", side_effect=ValueError("late failure")),
        ):
            revoke_code, revoke_failure = invoke(
                home, ["judgment", "revoke", "--input", str(revoke_path)]
            )
        self.assertEqual(revoke_code, 2)
        self.assertTrue(revoke_failure["localChangesPerformed"])
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            revoked = read_judgment_status(home, profile_id=profile, run_id=run)
        self.assertEqual(revoked["status"], "revoked")

    def test_status_exit_codes_keep_effective_result_separate_from_authority(self) -> None:
        from guardian_core.cli import _judgment_status_exit

        projection = {
            "rawStatus": "conflict",
            "effectiveStatus": "allowed",
            "instances": [{"effectiveStatus": "allowed"}],
            "enforcementAuthorityStatus": "not_assessed",
        }
        self.assertEqual(
            _judgment_status_exit({"effectiveProjection": projection, "productionReady": False}),
            4,
        )
        cases = (
            ("conflict", "allowed", False, 1),
            ("invalid", "allowed", False, 2),
            ("source_unavailable", "allowed", False, 3),
            ("not_assessed", "allowed", False, 4),
            ("allowed", "allowed", True, 0),
        )
        for effective, authority, ready, expected in cases:
            current = copy.deepcopy(projection)
            current["effectiveStatus"] = effective
            current["instances"] = [{"effectiveStatus": effective}]
            current["enforcementAuthorityStatus"] = authority
            with self.subTest(effective=effective, authority=authority):
                self.assertEqual(
                    _judgment_status_exit(
                        {"effectiveProjection": current, "productionReady": ready}
                    ),
                    expected,
                )

    def test_integrity_failures_are_redacted(self) -> None:
        from guardian_core.judgment_decisions import JudgmentDecisionIntegrityError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            sensitive_path = root / "private-company-candidate.json"
            secret_reason = "company-secret-reason"
            write_json(sensitive_path, candidate())
            with patch(
                "guardian_core.judgment_decisions.preview_judgment_decision",
                side_effect=JudgmentDecisionIntegrityError(
                    f"statement and evidence {secret_reason} at {sensitive_path}"
                ),
            ):
                code, failure = invoke(
                    home,
                    [
                        "judgment",
                        "preview",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-judgment",
                        "--input",
                        str(sensitive_path),
                    ],
                )
            rendered = json.dumps(failure, sort_keys=True)
            self.assertEqual(code, 2)
            self.assertEqual(failure["reasonCode"], "judgment_integrity_invalid")
            self.assertNotIn(secret_reason, rendered)
            self.assertNotIn(str(sensitive_path), rendered)
            self.assertNotIn("statement and evidence", rendered)


if __name__ == "__main__":
    unittest.main()
