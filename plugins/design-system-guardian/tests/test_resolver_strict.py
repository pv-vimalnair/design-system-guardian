

import copy
import unittest
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"


def ingested_snapshot() -> dict:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        return ingest_test_snapshot(Path(directory), sample_profile(), sample_catalog(), now=NOW)


class StrictResolverTest(unittest.TestCase):
    def setUp(self) -> None:
        clock = patch("guardian_core.resolver._utc_now", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def test_proven_missing_icon_gets_fixed_nonpromotable_sentinel(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        snapshot = ingested_snapshot()
        result = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=snapshot,
            request={"requestId": "req-icon-404", "kind": "icon", "identity": "icon.receipt"},
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["sentinel"]["namespace"], "design_system_guardian.sentinel.v1")
        self.assertEqual(result["sentinel"]["label"], "MISSING ICON")
        self.assertEqual(result["sentinel"]["requestId"], "req-icon-404")
        self.assertEqual(result["sentinel"]["policyDigest"], POLICY_DIGEST)
        self.assertFalse(result["sentinel"]["productionReady"])
        self.assertFalse(result["sentinel"]["automaticPromotion"])

    def test_offline_grace_can_use_existing_identity_but_cannot_prove_missing(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        snapshot = ingested_snapshot()
        offline = {**snapshot, "sourceState": "offline_grace", "sourceAvailable": False}
        existing = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=offline,
            request={"kind": "token", "identity": "color.action.primary"},
            policy_digest=POLICY_DIGEST,
        )
        missing = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=offline,
            request={"requestId": "req-offline", "kind": "icon", "identity": "icon.absent"},
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(existing["status"], "allowed")
        self.assertTrue(existing["evidence"]["degraded"])
        self.assertEqual(missing["status"], "source_unavailable")
        self.assertIsNone(missing["sentinel"])

    def test_registry_identity_variant_property_and_mapping_are_exact(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        snapshot = ingested_snapshot()
        request = {
            "kind": "component",
            "identity": "button.primary",
            "variant": "loading",
            "properties": {"size": "large"},
            "codeMapping": {"framework": "flutter", "symbol": "MpButton.primary"},
        }
        allowed = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=snapshot,
            request=request,
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(allowed["evidence"]["variant"], "loading")
        self.assertEqual(allowed["evidence"]["codeMapping"]["symbol"], "MpButton.primary")

        mutations = [
            {**request, "variant": "busy"},
            {**request, "properties": {"size": "extra-large"}},
            {**request, "codeMapping": {"framework": "flutter", "symbol": "MaterialButton"}},
            {**request, "identity": "Button.Primary"},
        ]
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                result = _resolve_verified_snapshot_identity(
                    profile_id="example-company",
                    snapshot=snapshot,
                    request=mutated,
                    policy_digest=POLICY_DIGEST,
                )
                self.assertNotEqual(result["status"], "allowed")

    def test_deprecated_and_candidate_records_are_not_allowed_for_new_selection(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        snapshot = ingested_snapshot()
        deprecated = copy.deepcopy(snapshot)
        deprecated["registry"]["icons"][0]["status"] = "deprecated"
        deprecated["registry"]["icons"][0]["deprecated"] = True
        result = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=deprecated,
            request={"kind": "icon", "identity": "icon.check", "variant": "default"},
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(result["status"], "conflict")
        self.assertIsNone(result["selectedIdentity"])

    def test_context_and_token_type_must_match_the_pinned_snapshot(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        snapshot = ingested_snapshot()
        base = {"kind": "token", "identity": "color.action.primary"}
        allowed = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=snapshot,
            request={**base, "tokenType": "color", "resolverContext": {"theme": "light"}},
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(allowed["status"], "allowed")
        for request in (
            {**base, "tokenType": "dimension"},
            {**base, "resolverContext": {"theme": "dark"}},
        ):
            with self.subTest(request=request):
                result = _resolve_verified_snapshot_identity(
                    profile_id="example-company",
                    snapshot=snapshot,
                    request=request,
                    policy_digest=POLICY_DIGEST,
                )
                self.assertEqual(result["status"], "invalid")

    def test_equal_value_literal_without_identity_is_invalid_not_allowed(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        result = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot=ingested_snapshot(),
            request={"kind": "token", "value": "#E6A700"},
            policy_digest=POLICY_DIGEST,
        )
        self.assertEqual(result["status"], "invalid")
        self.assertIsNone(result["selectedIdentity"])

    def test_public_resolver_loads_and_verifies_the_sealed_run_pin(self) -> None:
        import tempfile
        from pathlib import Path

        from guardian_core.preflight import preflight_snapshot
        from guardian_core.resolver import resolve_identity

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ingest_test_snapshot(home, sample_profile(), sample_catalog(), now=NOW)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="authoritative-resolver",
                    policy_digest=POLICY_DIGEST,
                    project_root=home,
                )
            with patch("guardian_core.resolver.default_guardian_home", return_value=home):
                result = resolve_identity(
                    profile_id="example-company",
                    run_id="authoritative-resolver",
                    request={
                        "kind": "token",
                        "identity": "color.action.primary",
                        "tokenType": "color",
                    },
                )
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["selectedIdentity"], "color.action.primary")

    def test_public_resolver_rejects_fabricated_snapshot_arguments(self) -> None:
        from guardian_core.resolver import resolve_identity

        fabricated = {
            "profileId": "example-company",
            "snapshotId": "a" * 64,
            "sourceState": "fresh",
            "sourceAvailable": True,
            "sourceComplete": True,
            "tokens": {
                "outside.nearest-blue": {
                    "approved": True,
                    "type": "color",
                    "provenance": {"published": True},
                }
            },
        }
        with self.assertRaises(TypeError):
            resolve_identity(
                profile_id="example-company",
                snapshot=fabricated,
                request={
                    "kind": "token",
                    "identity": "outside.nearest-blue",
                    "tokenType": "color",
                },
                policy_digest="b" * 64,
            )
