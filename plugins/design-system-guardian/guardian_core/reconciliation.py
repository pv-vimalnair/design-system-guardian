"""Webhook invalidation-hint debounce and full-refetch reconciliation."""
from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .canonical import canonical_json_bytes, sha256_digest
from .contracts import ExitCode

_EVENT_KEYS = {"eventId", "eventType", "fileKey", "assetType", "eventTime"}
_STATE_KEYS = {"schemaVersion", "profileId", "pending", "pendingHints", "firstHintReceivedAt", "lastHintReceivedAt", "lastReconciledAt", "lastReconciledHintDigest"}
_HINT_KEYS = {"hintDigest", "eventId", "fileKey", "assetType", "eventTime"}
_HEX = re.compile(r"^[0-9a-f]{64}$")

class ReconciliationIntegrityError(ValueError):
    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY
    def __init__(self, message: str, *, state: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.state = copy.deepcopy(state)

class ReconciliationSourceError(ValueError):
    exit_code = ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE
    def __init__(self, message: str, *, state: dict[str, Any]) -> None:
        super().__init__(message)
        self.state = copy.deepcopy(state)

def _time(value: Any, field: str) -> tuple[datetime, str]:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReconciliationIntegrityError(f"{field} must be a timezone-aware datetime.")
    utc = value.astimezone(timezone.utc)
    return utc, utc.isoformat().replace("+00:00", "Z")

def _text_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ReconciliationIntegrityError(f"{field} must be a canonical timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReconciliationIntegrityError(f"{field} is invalid.") from error
    if parsed.tzinfo is None:
        raise ReconciliationIntegrityError(f"{field} requires an offset.")
    utc = parsed.astimezone(timezone.utc)
    if utc.isoformat().replace("+00:00", "Z") != value:
        raise ReconciliationIntegrityError(f"{field} is not canonical UTC.")
    return utc

def empty_reconciliation_state(profile_id: str) -> dict[str, Any]:
    if not isinstance(profile_id, str) or not profile_id:
        raise ReconciliationIntegrityError("profileId must be non-empty.")
    return {"schemaVersion": 1, "profileId": profile_id, "pending": False, "pendingHints": [], "firstHintReceivedAt": None, "lastHintReceivedAt": None, "lastReconciledAt": None, "lastReconciledHintDigest": None}

def _validated_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _STATE_KEYS or value.get("schemaVersion") != 1:
        raise ReconciliationIntegrityError("Reconciliation state has unknown, missing, or invalid fields.")
    if not isinstance(value.get("profileId"), str) or not value["profileId"] or not isinstance(value.get("pending"), bool) or not isinstance(value.get("pendingHints"), list):
        raise ReconciliationIntegrityError("Reconciliation state identity or pending evidence is invalid.")
    hints = []
    for item in value["pendingHints"]:
        if not isinstance(item, dict) or set(item) != _HINT_KEYS or not isinstance(item.get("hintDigest"), str) or not _HEX.fullmatch(item["hintDigest"]):
            raise ReconciliationIntegrityError("Pending hint evidence is malformed.")
        for field in ("eventId", "fileKey", "assetType", "eventTime"):
            if not isinstance(item.get(field), str) or not item[field]:
                raise ReconciliationIntegrityError("Pending hint identity evidence is malformed.")
        _text_time(item["eventTime"], "pendingHint.eventTime")
        reconstructed = {"eventId": item["eventId"], "eventType": "LIBRARY_PUBLISH", "fileKey": item["fileKey"], "assetType": item["assetType"], "eventTime": item["eventTime"]}
        if sha256_digest(reconstructed) != item["hintDigest"]:
            raise ReconciliationIntegrityError("Pending hint digest does not match reconstructed evidence.")
        hints.append(copy.deepcopy(item))
    hints.sort(key=canonical_json_bytes)
    if len({item["hintDigest"] for item in hints}) != len(hints):
        raise ReconciliationIntegrityError("Pending hint digests must be unique.")
    if value["pending"] != bool(hints):
        raise ReconciliationIntegrityError("Pending flag differs from pending hints.")
    first, last = value.get("firstHintReceivedAt"), value.get("lastHintReceivedAt")
    if hints:
        if first is None or last is None or _text_time(first, "firstHintReceivedAt") > _text_time(last, "lastHintReceivedAt"):
            raise ReconciliationIntegrityError("Pending hint receipt interval is invalid.")
    elif first is not None or last is not None:
        raise ReconciliationIntegrityError("Empty state cannot retain pending receipt times.")
    if value.get("lastReconciledAt") is not None:
        _text_time(value["lastReconciledAt"], "lastReconciledAt")
    digest = value.get("lastReconciledHintDigest")
    if digest is not None and (not isinstance(digest, str) or not _HEX.fullmatch(digest)):
        raise ReconciliationIntegrityError("lastReconciledHintDigest is malformed.")
    result = copy.deepcopy(value)
    result["pendingHints"] = hints
    return result

def record_publish_hint(state: dict[str, Any], event: dict[str, Any], *, received_at: datetime, allowed_library_files: set[str]) -> dict[str, Any]:
    current = _validated_state(state)
    if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
        raise ReconciliationIntegrityError("Publish hint has unknown or missing fields.", state=current)
    if event.get("eventType") != "LIBRARY_PUBLISH":
        raise ReconciliationIntegrityError("Only LIBRARY_PUBLISH is a reconciliation hint.", state=current)
    if not isinstance(allowed_library_files, set) or not allowed_library_files or any(not isinstance(item, str) or not item for item in allowed_library_files):
        raise ReconciliationIntegrityError("Allowed library files must be an explicit non-empty set.", state=current)
    if event.get("fileKey") not in allowed_library_files:
        raise ReconciliationIntegrityError("Publish hint is outside the selected profile allowlist.", state=current)
    for field in ("eventId", "fileKey", "assetType", "eventTime"):
        if not isinstance(event.get(field), str) or not event[field]:
            raise ReconciliationIntegrityError(f"Publish hint {field} must be non-empty.", state=current)
    received_time, received = _time(received_at, "receivedAt")
    event_time = _text_time(event["eventTime"], "eventTime")
    if event_time > received_time:
        raise ReconciliationIntegrityError("Publish eventTime cannot follow trusted receipt time.", state=current)
    digest = sha256_digest(event)
    hint = {"hintDigest": digest, "eventId": event["eventId"], "fileKey": event["fileKey"], "assetType": event["assetType"], "eventTime": event["eventTime"]}
    by_digest = {item["hintDigest"]: item for item in current["pendingHints"]}
    existing = by_digest.get(digest)
    if existing is not None and existing != hint:
        raise ReconciliationIntegrityError("A hint digest collision changed evidence.", state=current)
    by_digest[digest] = hint
    times = [received]
    if current["firstHintReceivedAt"] is not None:
        times.extend([current["firstHintReceivedAt"], current["lastHintReceivedAt"]])
    current.update({"pending": True, "pendingHints": sorted(by_digest.values(), key=canonical_json_bytes), "firstHintReceivedAt": min(times), "lastHintReceivedAt": max(times)})
    return current

def daily_freshness_check_due(*, last_checked_at: datetime | None, now: datetime) -> bool:
    current, _ = _time(now, "now")
    if last_checked_at is None:
        return True
    previous, _ = _time(last_checked_at, "lastCheckedAt")
    if previous > current:
        raise ReconciliationIntegrityError("lastCheckedAt cannot be in the future.")
    return current - previous >= timedelta(hours=24)

def reconcile_publish_hints(state: dict[str, Any], *, now: datetime, refetch_full_catalog: Callable[[dict[str, Any]], dict[str, Any]], validate_candidate: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]], promote_atomically: Callable[[dict[str, Any]], dict[str, Any]], debounce_seconds: int = 30) -> dict[str, Any]:
    current = _validated_state(state)
    current_time, current_text = _time(now, "now")
    if isinstance(debounce_seconds, bool) or not isinstance(debounce_seconds, int) or debounce_seconds < 1:
        raise ReconciliationIntegrityError("debounce_seconds must be a positive integer.", state=current)
    last_received = _text_time(current["lastHintReceivedAt"], "lastHintReceivedAt") if current["pending"] else None
    if last_received is not None and current_time < last_received:
        raise ReconciliationIntegrityError("Reconciliation time cannot precede the latest hint receipt.", state=current)
    if not current["pending"] or current_time < last_received + timedelta(seconds=debounce_seconds):
        return {"schemaVersion": 1, "status": "debouncing", "state": current, "request": None, "promotion": None}
    request = {"schemaVersion": 1, "profileId": current["profileId"], "requiresFullRefetch": True, "invalidationHintsOnly": True, "libraryFiles": sorted({item["fileKey"] for item in current["pendingHints"]}), "hintCount": len(current["pendingHints"]), "hintsDigest": sha256_digest(current["pendingHints"])}
    try:
        catalog = refetch_full_catalog(copy.deepcopy(request))
    except Exception as error:
        raise ReconciliationSourceError(
            f"Full catalog refetch is unavailable: {error}", state=current
        ) from error
    try:
        if not isinstance(catalog, dict) or catalog.get("sourceAvailable") is not True or catalog.get("sourceComplete") is not True:
            raise ReconciliationSourceError("Full refetch is unavailable or incomplete.", state=current)
        candidate = validate_candidate(copy.deepcopy(catalog), copy.deepcopy(request))
        if not isinstance(candidate, dict) or candidate.get("sourceAvailable") is not True or candidate.get("sourceComplete") is not True:
            raise ReconciliationSourceError("Validated candidate is unavailable or incomplete.", state=current)
        snapshot_id = candidate.get("snapshotId")
        if not isinstance(snapshot_id, str) or not _HEX.fullmatch(snapshot_id):
            raise ReconciliationIntegrityError("Validated candidate lacks an exact snapshotId.", state=current)
        promotion = promote_atomically(copy.deepcopy(candidate))
        if not isinstance(promotion, dict) or promotion.get("snapshotId") != snapshot_id or promotion.get("promoted") is not True:
            raise ReconciliationIntegrityError("Atomic promotion did not confirm the validated snapshot.", state=current)
    except (ReconciliationSourceError, ReconciliationIntegrityError):
        raise
    except Exception as error:
        raise ReconciliationIntegrityError(f"Reconciliation callback failed closed: {error}", state=current) from error
    completed = {"schemaVersion": 1, "profileId": current["profileId"], "pending": False, "pendingHints": [], "firstHintReceivedAt": None, "lastHintReceivedAt": None, "lastReconciledAt": current_text, "lastReconciledHintDigest": request["hintsDigest"]}
    return {"schemaVersion": 1, "status": "promoted", "state": completed, "request": request, "promotion": copy.deepcopy(promotion)}
