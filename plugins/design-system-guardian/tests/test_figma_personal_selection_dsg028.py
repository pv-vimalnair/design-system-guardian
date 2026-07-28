from __future__ import annotations

import copy
import unittest

from tests.test_figma_adapter_dsg017 import (
    COLLECTOR_DIGEST,
    LIBRARY_FILE,
    LIBRARY_VERSION,
    WORKING_FILE,
    WORKING_VERSION,
    clean_observation,
    run_pin,
    snapshot,
    source_cut,
)


EXCLUDED_FILE = "figma-community-kit"


def personal_context() -> tuple[dict, dict]:
    pin = run_pin()
    pin.update(
        {
            "schemaVersion": 2,
            "profileId": "personal-" + "1" * 40,
            "authorityMode": "personal_local",
            "selectionDigest": "2" * 64,
            "targetFigmaFile": {
                "fileKey": WORKING_FILE,
                "version": WORKING_VERSION,
            },
            "libraryDecisions": [
                {
                    "fileKey": LIBRARY_FILE,
                    "version": LIBRARY_VERSION,
                    "published": True,
                    "decision": "use",
                },
                {
                    "fileKey": EXCLUDED_FILE,
                    "version": "8",
                    "published": True,
                    "decision": "do_not_use",
                },
            ],
            "selectedLibraryFileKeys": [LIBRARY_FILE],
            "excludedLibraryFileKeys": [EXCLUDED_FILE],
        }
    )
    verified_snapshot = snapshot()
    verified_snapshot["profileId"] = pin["profileId"]
    return pin, verified_snapshot


def personal_observation(pin: dict, verified_snapshot: dict) -> dict:
    from guardian_core.figma_adapter import build_figma_adapter_config

    observation = clean_observation()
    config = build_figma_adapter_config(
        run_pin=pin,
        verified_snapshot=verified_snapshot,
        collector_digest=COLLECTOR_DIGEST,
    )
    observation["binding"]["profileId"] = pin["profileId"]
    observation["binding"]["configDigest"] = config["configDigest"]
    return observation


class PersonalFigmaAssuranceTest(unittest.TestCase):
    def test_complete_caller_carried_observation_never_claims_allowed(self) -> None:
        from guardian_core.audit import adapter_audit_projection
        from guardian_core.figma_adapter import (
            build_figma_adapter_config,
            normalize_figma_observation,
        )

        pin, verified_snapshot = personal_context()
        config = build_figma_adapter_config(
            run_pin=pin,
            verified_snapshot=verified_snapshot,
            collector_digest=COLLECTOR_DIGEST,
        )
        self.assertEqual(config["authorityMode"], "personal_local")
        self.assertEqual(config["selectionDigest"], pin["selectionDigest"])
        self.assertEqual(config["targetFigmaFile"], pin["targetFigmaFile"])

        normalized = normalize_figma_observation(
            personal_observation(pin, verified_snapshot),
            run_pin=pin,
            verified_snapshot=verified_snapshot,
            collector_digest=COLLECTOR_DIGEST,
        )
        self.assertEqual(normalized["assuranceMode"], "personal_local")
        self.assertTrue(
            all(
                category["status"] == "not_assessed"
                for category in normalized["categories"].values()
            )
        )
        coverage, diagnostics = adapter_audit_projection(
            normalized,
            source_cut(),
            run_pin=pin,
        )
        self.assertEqual(diagnostics, [])
        self.assertTrue(
            all(
                category["status"] == "not_assessed"
                for category in coverage["categories"].values()
            )
        )
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["status"], "not_assessed")

    def test_matching_caller_carried_forgery_cannot_become_allowed(self) -> None:
        from guardian_core.audit import adapter_audit_projection
        from guardian_core.figma_adapter import normalize_figma_observation

        pin, verified_snapshot = personal_context()
        normalized = normalize_figma_observation(
            personal_observation(pin, verified_snapshot),
            run_pin=pin,
            verified_snapshot=verified_snapshot,
            collector_digest=COLLECTOR_DIGEST,
        )
        for category in normalized["categories"].values():
            category["status"] = "allowed"

        coverage, diagnostics = adapter_audit_projection(
            normalized,
            source_cut(),
            run_pin=pin,
        )

        self.assertEqual(diagnostics, [])
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["status"], "not_assessed")
        self.assertTrue(
            all(
                category["status"] == "not_assessed"
                for category in coverage["categories"].values()
            )
        )

    def test_unpublished_or_unknown_decision_fields_fail_closed(self) -> None:
        from guardian_core.figma_adapter import (
            FigmaAdapterIntegrityError,
            build_figma_adapter_config,
        )

        pin, verified_snapshot = personal_context()
        cases = []
        unpublished = copy.deepcopy(pin)
        unpublished["libraryDecisions"][0]["published"] = False
        cases.append(unpublished)
        unknown = copy.deepcopy(pin)
        unknown["libraryDecisions"][0]["unexpected"] = True
        cases.append(unknown)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(
                FigmaAdapterIntegrityError
            ):
                build_figma_adapter_config(
                    run_pin=changed,
                    verified_snapshot=verified_snapshot,
                    collector_digest=COLLECTOR_DIGEST,
                )

    def test_personal_assurance_cannot_be_self_asserted_without_personal_pin(self) -> None:
        from guardian_core.audit import AuditIntegrityError, adapter_audit_projection
        from guardian_core.figma_adapter import normalize_figma_observation

        personal_pin, verified_snapshot = personal_context()
        normalized = normalize_figma_observation(
            personal_observation(personal_pin, verified_snapshot),
            run_pin=personal_pin,
            verified_snapshot=verified_snapshot,
            collector_digest=COLLECTOR_DIGEST,
        )

        with self.assertRaises(AuditIntegrityError):
            adapter_audit_projection(normalized, source_cut())
        with self.assertRaises(AuditIntegrityError):
            adapter_audit_projection(
                normalized,
                source_cut(),
                run_pin=run_pin(),
            )

    def test_personal_readback_must_target_selected_working_file(self) -> None:
        from guardian_core.figma_adapter import (
            FigmaAdapterIntegrityError,
            normalize_figma_observation,
        )

        pin, verified_snapshot = personal_context()
        observation = personal_observation(pin, verified_snapshot)
        observation["document"].update(
            {
                "fileKey": LIBRARY_FILE,
                "sourceVersion": LIBRARY_VERSION,
            }
        )

        with self.assertRaisesRegex(
            FigmaAdapterIntegrityError,
            "selected target file",
        ):
            normalize_figma_observation(
                observation,
                run_pin=pin,
                verified_snapshot=verified_snapshot,
                collector_digest=COLLECTOR_DIGEST,
            )

    def test_personal_readback_cannot_be_empty(self) -> None:
        from guardian_core.figma_adapter import (
            FigmaAdapterIntegrityError,
            normalize_figma_observation,
        )

        pin, verified_snapshot = personal_context()
        observation = personal_observation(pin, verified_snapshot)
        observation["analysis"].update(
            {
                "assessedNodes": 0,
                "totalNodes": 0,
                "assessedFields": 0,
                "totalFields": 0,
            }
        )
        observation["observations"] = []

        with self.assertRaisesRegex(FigmaAdapterIntegrityError, "non-empty"):
            normalize_figma_observation(
                observation,
                run_pin=pin,
                verified_snapshot=verified_snapshot,
                collector_digest=COLLECTOR_DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
