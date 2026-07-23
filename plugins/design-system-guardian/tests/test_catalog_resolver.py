import unittest
from datetime import datetime, timezone


class ExactResolutionSourceStateTest(unittest.TestCase):
    def test_fresh_complete_exact_identity_is_allowed_but_outage_is_not_missing(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        now = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
        request = {"kind": "token", "identity": "color.action.primary"}
        snapshot = {
            "profileId": "example-company",
            "snapshotId": "a" * 64,
            "createdAt": "2026-07-15T11:00:00Z",
            "sourceState": "fresh",
            "sourceAvailable": True,
            "sourceComplete": True,
            "tokens": {
                "color.action.primary": {
                    "identity": "color.action.primary",
                    "type": "color",
                    "value": {"colorSpace": "srgb", "components": [0.1, 0.2, 0.3], "alpha": 1},
                    "approved": True,
                    "deprecated": False,
                    "provenance": {"fileKey": "figma-brand", "published": True},
                }
            },
            "assets": [],
        }

        allowed = _resolve_verified_snapshot_identity(
            profile_id="example-company", snapshot=snapshot, request=request, policy_digest="f" * 64
        )
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(allowed["selectedIdentity"], "color.action.primary")

        unavailable = _resolve_verified_snapshot_identity(
            profile_id="example-company",
            snapshot={**snapshot, "sourceState": "source_unavailable", "sourceAvailable": False},
            request={"kind": "token", "identity": "color.not.in.catalog"},
            policy_digest="f" * 64,
        )
        self.assertEqual(unavailable["status"], "source_unavailable")
        self.assertIsNone(unavailable["sentinel"])


if __name__ == "__main__":
    unittest.main()
