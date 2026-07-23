import copy
import unittest
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
ALLOWLIST = {"figma-brand", "figma-product"}

def hint(event_id: str, file_key: str, asset_type: str) -> dict:
    return {"eventId": event_id, "eventType": "LIBRARY_PUBLISH", "fileKey": file_key, "assetType": asset_type, "eventTime": "2026-07-15T11:59:00Z"}

class ReconciliationTest(unittest.TestCase):
    def test_chunk_order_and_duplicates_produce_one_canonical_pending_state(self) -> None:
        from guardian_core.reconciliation import empty_reconciliation_state, record_publish_hint
        a = hint("evt-a", "figma-brand", "VARIABLE")
        b = hint("evt-b", "figma-brand", "COMPONENT")
        first = empty_reconciliation_state("example-company")
        first = record_publish_hint(first, a, received_at=T0, allowed_library_files=ALLOWLIST)
        first = record_publish_hint(first, b, received_at=T0 + timedelta(seconds=5), allowed_library_files=ALLOWLIST)
        first = record_publish_hint(first, a, received_at=T0, allowed_library_files=ALLOWLIST)
        second = empty_reconciliation_state("example-company")
        second = record_publish_hint(second, b, received_at=T0 + timedelta(seconds=5), allowed_library_files=ALLOWLIST)
        second = record_publish_hint(second, a, received_at=T0, allowed_library_files=ALLOWLIST)
        self.assertEqual(first, second)
        self.assertEqual(len(first["pendingHints"]), 2)
        self.assertTrue(first["pending"])

    def test_publish_chunks_are_invalidation_only_and_require_full_refetch(self) -> None:
        from guardian_core.reconciliation import empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        calls: list[tuple[str, object]] = []
        def refetch(request: dict) -> dict:
            calls.append(("refetch", copy.deepcopy(request)))
            self.assertTrue(request["requiresFullRefetch"])
            self.assertTrue(request["invalidationHintsOnly"])
            return {"sourceComplete": True, "sourceAvailable": True, "catalog": "full"}
        def validate(catalog: dict, request: dict) -> dict:
            calls.append(("validate", copy.deepcopy(catalog)))
            return {"sourceComplete": True, "sourceAvailable": True, "snapshotId": "a" * 64}
        def promote(candidate: dict) -> dict:
            calls.append(("promote", copy.deepcopy(candidate)))
            return {"snapshotId": candidate["snapshotId"], "promoted": True}
        result = reconcile_publish_hints(state, now=T0 + timedelta(seconds=30), refetch_full_catalog=refetch, validate_candidate=validate, promote_atomically=promote)
        self.assertEqual([name for name, _ in calls], ["refetch", "validate", "promote"])
        self.assertEqual(result["status"], "promoted")
        self.assertFalse(result["state"]["pending"])
        self.assertEqual(result["promotion"]["snapshotId"], "a" * 64)

    def test_debounce_does_not_refetch_or_promote_early(self) -> None:
        from guardian_core.reconciliation import empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        def forbidden(*_args):
            self.fail("callbacks must not run before debounce expires")
        result = reconcile_publish_hints(state, now=T0 + timedelta(seconds=29), refetch_full_catalog=forbidden, validate_candidate=forbidden, promote_atomically=forbidden)
        self.assertEqual(result, {"schemaVersion": 1, "status": "debouncing", "state": state, "request": None, "promotion": None})

    def test_failed_or_incomplete_refetch_never_consumes_pending_hints(self) -> None:
        from guardian_core.reconciliation import ReconciliationSourceError, empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        with self.assertRaises(ReconciliationSourceError) as raised:
            reconcile_publish_hints(state, now=T0 + timedelta(seconds=30), refetch_full_catalog=lambda _: {"sourceComplete": False, "sourceAvailable": True}, validate_candidate=lambda catalog, request: catalog, promote_atomically=lambda candidate: self.fail("must not promote incomplete source"))
        self.assertEqual(raised.exception.state, state)
        self.assertTrue(state["pending"])

    def test_refetch_transport_failure_is_source_unavailable_not_integrity(self) -> None:
        from guardian_core.contracts import ExitCode
        from guardian_core.reconciliation import ReconciliationSourceError, empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        def unavailable(_request):
            raise ConnectionError("figma unavailable")
        with self.assertRaises(ReconciliationSourceError) as raised:
            reconcile_publish_hints(state, now=T0 + timedelta(seconds=30), refetch_full_catalog=unavailable, validate_candidate=lambda *_: {}, promote_atomically=lambda _: {})
        self.assertEqual(raised.exception.exit_code, ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)
        self.assertEqual(raised.exception.state, state)

    def test_unallowlisted_library_and_non_publish_event_are_rejected(self) -> None:
        from guardian_core.reconciliation import ReconciliationIntegrityError, empty_reconciliation_state, record_publish_hint
        state = empty_reconciliation_state("example-company")
        wrong_type = hint("evt-a", "figma-brand", "VARIABLE")
        wrong_type["eventType"] = "FILE_UPDATE"
        for event in (hint("evt-x", "community-file", "VARIABLE"), wrong_type):
            with self.subTest(event=event), self.assertRaises(ReconciliationIntegrityError):
                record_publish_hint(state, event, received_at=T0, allowed_library_files=ALLOWLIST)

    def test_daily_backup_freshness_check_is_due_at_24_hours(self) -> None:
        from guardian_core.reconciliation import daily_freshness_check_due
        self.assertTrue(daily_freshness_check_due(last_checked_at=None, now=T0))
        self.assertFalse(daily_freshness_check_due(last_checked_at=T0, now=T0 + timedelta(hours=23, minutes=59)))
        self.assertTrue(daily_freshness_check_due(last_checked_at=T0, now=T0 + timedelta(hours=24)))

    def test_event_time_is_canonical_and_cannot_follow_trusted_receipt(self) -> None:
        from guardian_core.reconciliation import ReconciliationIntegrityError, empty_reconciliation_state, record_publish_hint
        state = empty_reconciliation_state("example-company")
        malformed = hint("evt-a", "figma-brand", "VARIABLE")
        malformed["eventTime"] = "not-a-time"
        future = hint("evt-b", "figma-brand", "VARIABLE")
        future["eventTime"] = "2026-07-15T12:00:01Z"
        for event in (malformed, future):
            with self.subTest(event=event), self.assertRaises(ReconciliationIntegrityError):
                record_publish_hint(state, event, received_at=T0, allowed_library_files=ALLOWLIST)

    def test_reconciliation_refuses_now_before_last_hint_receipt(self) -> None:
        from guardian_core.reconciliation import ReconciliationIntegrityError, empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        with self.assertRaises(ReconciliationIntegrityError):
            reconcile_publish_hints(state, now=T0 - timedelta(seconds=1), refetch_full_catalog=lambda _: {}, validate_candidate=lambda *_: {}, promote_atomically=lambda _: {})

    def test_control_flow_exceptions_are_never_swallowed(self) -> None:
        from guardian_core.reconciliation import empty_reconciliation_state, reconcile_publish_hints, record_publish_hint
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        def interrupt(_request):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            reconcile_publish_hints(state, now=T0 + timedelta(seconds=30), refetch_full_catalog=interrupt, validate_candidate=lambda *_: {}, promote_atomically=lambda _: {})

    def test_stored_hint_digest_is_reconstructed_before_reconciliation(self) -> None:
        from guardian_core.reconciliation import ReconciliationIntegrityError, empty_reconciliation_state, record_publish_hint, reconcile_publish_hints
        state = record_publish_hint(empty_reconciliation_state("example-company"), hint("evt-a", "figma-brand", "VARIABLE"), received_at=T0, allowed_library_files=ALLOWLIST)
        tampered = copy.deepcopy(state)
        tampered["pendingHints"][0]["fileKey"] = "figma-product"
        with self.assertRaises(ReconciliationIntegrityError):
            reconcile_publish_hints(tampered, now=T0 + timedelta(seconds=30), refetch_full_catalog=lambda _: self.fail("tampered state must fail before refetch"), validate_candidate=lambda *_: {}, promote_atomically=lambda _: {})

if __name__ == "__main__":
    unittest.main()
