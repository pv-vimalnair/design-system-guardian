
"""Exact, deny-by-default catalog identity resolution."""

from __future__ import annotations

import re
from typing import Any

from .canonical import sha256_digest
from .clock import utc_now as _utc_now
from .contracts import ResolutionStatus
from .paths import default_guardian_home
from .policy import verify_policy_anchor
from .preflight import load_run_pin
from .sentinels import make_sentinel


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BLOCKING_SOURCE_STATES = {
    "source_unavailable": ResolutionStatus.SOURCE_UNAVAILABLE,
    "source_incomplete": ResolutionStatus.SOURCE_INCOMPLETE,
    "stale": ResolutionStatus.STALE,
}

def _result(
    *,
    status: ResolutionStatus,
    profile_id: str,
    snapshot_id: str | None,
    request: dict[str, Any],
    selected_identity: str | None = None,
    evidence: dict[str, Any] | None = None,
    sentinel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "status": status.value,
        "profileId": profile_id,
        "snapshotId": snapshot_id,
        "request": request,
        "selectedIdentity": selected_identity,
        "evidence": evidence or {},
        "sentinel": sentinel,
    }


def _effective_source_state(snapshot: dict[str, Any]) -> str | None:
    if "lastSuccessfulRefreshAt" in snapshot:
        try:
            from .snapshot import classify_source_state

            return str(classify_source_state(snapshot, now=_utc_now())["state"])
        except ValueError:
            return "invalid"
    value = snapshot.get("sourceState")
    return value if isinstance(value, str) else None


def _candidate_records(snapshot: dict[str, Any], kind: str, identity: str) -> list[dict[str, Any]]:
    if kind == "token":
        tokens = snapshot.get("tokens")
        candidate = tokens.get(identity) if isinstance(tokens, dict) else None
        return [candidate] if isinstance(candidate, dict) else []
    registry = snapshot.get("registry")
    plural = "components" if kind == "component" else "icons"
    records = registry.get(plural, []) if isinstance(registry, dict) else []
    if not isinstance(records, list):
        return []
    return [
        item
        for item in records
        if isinstance(item, dict) and item.get("kind") == kind and item.get("identity") == identity
    ]


def _sentinel_kind(kind: str, request: dict[str, Any]) -> str:
    if kind == "icon":
        return "icon"
    if kind == "component":
        return "component"
    token_type = request.get("tokenType")
    if token_type == "color":
        return "color"
    if token_type == "typography":
        return "textStyle"
    return "token"


def _missing_sentinel(
    *,
    profile_id: str,
    snapshot_id: str,
    request: dict[str, Any],
    policy_digest: str,
) -> dict[str, Any]:
    supplied_request_id = request.get("requestId")
    request_id = supplied_request_id if isinstance(supplied_request_id, str) and supplied_request_id else (
        "guardian-" + sha256_digest(
            {"profileId": profile_id, "snapshotId": snapshot_id, "request": request}
        )[:16]
    )
    return make_sentinel(
        kind=_sentinel_kind(str(request["kind"]), request),
        request_id=request_id,
        policy_digest=policy_digest,
    )


def _invalid(
    profile_id: str,
    snapshot_id: str | None,
    request: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    return _result(
        status=ResolutionStatus.INVALID,
        profile_id=profile_id,
        snapshot_id=snapshot_id,
        request=request,
        evidence={"reason": reason, "denyWins": True},
    )


def _validate_token_selection(
    candidate: dict[str, Any], snapshot: dict[str, Any], request: dict[str, Any]
) -> tuple[bool, str, dict[str, Any]]:
    token_type = request.get("tokenType")
    if token_type is not None and token_type != candidate.get("type"):
        return False, "token_type_mismatch", {}
    requested_context = request.get("resolverContext")
    resolver = snapshot.get("resolver")
    pinned_context = (
        resolver.get("evidence", {}).get("contexts") if isinstance(resolver, dict) else None
    )
    if requested_context is not None and requested_context != pinned_context:
        return False, "resolver_context_mismatch", {}
    return True, "", {
        "tokenType": candidate.get("type"),
        "resolverContext": pinned_context,
    }


def _validate_asset_selection(
    candidate: dict[str, Any], request: dict[str, Any]
) -> tuple[ResolutionStatus | None, str, dict[str, Any]]:
    variants = candidate.get("variants")
    variant = request.get("variant")
    if isinstance(variants, list) and variants:
        if not isinstance(variant, str) or variant not in variants:
            return ResolutionStatus.INVALID, "variant_not_exactly_approved", {}
    elif variant is not None:
        return ResolutionStatus.INVALID, "variant_not_registered", {}

    approved_properties = candidate.get("properties", {})
    requested_properties = request.get("properties", {})
    if not isinstance(approved_properties, dict) or not isinstance(requested_properties, dict):
        return ResolutionStatus.INVALID, "properties_must_be_exact_objects", {}
    if set(requested_properties) != set(approved_properties):
        return ResolutionStatus.INVALID, "all_registered_properties_must_be_selected_explicitly", {}
    for name, value in requested_properties.items():
        allowed_values = approved_properties.get(name)
        if not isinstance(value, str) or not isinstance(allowed_values, list) or value not in allowed_values:
            return ResolutionStatus.INVALID, "property_value_not_exactly_approved", {}

    selected_mapping: dict[str, Any] | None = None
    mapping_request = request.get("codeMapping")
    if mapping_request is not None:
        if not isinstance(mapping_request, dict) or set(mapping_request) != {"framework", "symbol"}:
            return ResolutionStatus.INVALID, "code_mapping_identity_is_malformed", {}
        matches = [
            mapping
            for mapping in candidate.get("codeMappings", [])
            if isinstance(mapping, dict)
            and mapping.get("framework") == mapping_request.get("framework")
            and mapping.get("symbol") == mapping_request.get("symbol")
        ]
        if len(matches) > 1:
            return ResolutionStatus.AMBIGUOUS, "multiple_exact_code_mappings", {}
        if not matches or matches[0].get("approved") is not True or matches[0].get("inferred") is True:
            return ResolutionStatus.INVALID, "code_mapping_not_explicitly_approved", {}
        selected_mapping = matches[0]
    return None, "", {
        "variant": variant,
        "properties": requested_properties,
        "codeMapping": selected_mapping,
    }


def _resolve_verified_snapshot_identity(
    *,
    profile_id: str,
    snapshot: dict[str, Any],
    request: dict[str, Any],
    policy_digest: str,
) -> dict[str, Any]:
    """Resolve only an exact approved identity from one pinned profile snapshot."""

    snapshot_id = snapshot.get("snapshotId")
    if not isinstance(request, dict):
        request = {}
    if not isinstance(policy_digest, str) or not _SHA256.fullmatch(policy_digest):
        return _invalid(profile_id, snapshot_id, request, "valid_policy_digest_required")
    if snapshot.get("profileId") != profile_id:
        return _result(
            status=ResolutionStatus.CONFLICT,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": "profile_mismatch", "denyWins": True},
        )

    source_state = _effective_source_state(snapshot)
    if source_state == "invalid":
        return _invalid(profile_id, snapshot_id, request, "invalid_freshness_evidence")
    blocking_status = _BLOCKING_SOURCE_STATES.get(source_state)
    if blocking_status is not None:
        return _result(
            status=blocking_status,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": source_state, "policyDigest": policy_digest},
        )
    if snapshot.get("sourceComplete") is not True:
        return _result(
            status=ResolutionStatus.SOURCE_INCOMPLETE,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": "source_incomplete", "policyDigest": policy_digest},
        )
    if snapshot.get("sourceAvailable") is False and source_state != "offline_grace":
        return _result(
            status=ResolutionStatus.SOURCE_UNAVAILABLE,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": "source_unavailable", "policyDigest": policy_digest},
        )

    identity = request.get("identity")
    kind = request.get("kind")
    if not isinstance(identity, str) or not identity or kind not in {"token", "component", "icon"}:
        return _invalid(profile_id, snapshot_id, request, "exact_kind_and_identity_required")
    allowed_fields = {"requestId", "kind", "identity"}
    if kind == "token":
        allowed_fields |= {"tokenType", "resolverContext"}
    else:
        allowed_fields |= {"variant", "properties", "codeMapping"}
    if set(request) - allowed_fields:
        return _invalid(profile_id, snapshot_id, request, "raw_values_or_unknown_selection_fields_are_forbidden")

    candidates = _candidate_records(snapshot, str(kind), identity)
    if len(candidates) > 1:
        return _result(
            status=ResolutionStatus.AMBIGUOUS,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": "multiple_exact_identities", "candidateCount": len(candidates)},
        )
    if not candidates:
        if source_state != "fresh" or snapshot.get("sourceAvailable") is not True:
            return _result(
                status=ResolutionStatus.SOURCE_UNAVAILABLE,
                profile_id=profile_id,
                snapshot_id=snapshot_id,
                request=request,
                evidence={"reason": "absence_not_proven_outside_fresh_available_snapshot"},
            )
        if not isinstance(snapshot_id, str):
            return _invalid(profile_id, snapshot_id, request, "pinned_snapshot_identity_required")
        sentinel = _missing_sentinel(
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            policy_digest=policy_digest,
        )
        return _result(
            status=ResolutionStatus.MISSING,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={
                "reason": "proven_absent_from_fresh_complete_snapshot",
                "productionReady": False,
            },
            sentinel=sentinel,
        )

    candidate = candidates[0]
    if candidate.get("deprecated") is True or candidate.get("status") == "deprecated":
        return _result(
            status=ResolutionStatus.CONFLICT,
            profile_id=profile_id,
            snapshot_id=snapshot_id,
            request=request,
            evidence={"reason": "identity_is_deprecated_for_new_selection"},
        )
    provenance = candidate.get("provenance", {})
    if candidate.get("approved") is not True or not isinstance(provenance, dict) or provenance.get("published") is not True:
        return _invalid(
            profile_id,
            snapshot_id,
            request,
            "identity_not_explicitly_approved_published_and_provenanced",
        )

    selection_evidence: dict[str, Any]
    if kind == "token":
        valid, reason, selection_evidence = _validate_token_selection(candidate, snapshot, request)
        if not valid:
            return _invalid(profile_id, snapshot_id, request, reason)
    else:
        status, reason, selection_evidence = _validate_asset_selection(candidate, request)
        if status is not None:
            return _result(
                status=status,
                profile_id=profile_id,
                snapshot_id=snapshot_id,
                request=request,
                evidence={"reason": reason, "denyWins": True},
            )
    return _result(
        status=ResolutionStatus.ALLOWED,
        profile_id=profile_id,
        snapshot_id=snapshot_id,
        request=request,
        selected_identity=identity,
        evidence={
            "match": "exact_identity",
            "policyDigest": policy_digest,
            "sourceState": source_state,
            "degraded": source_state == "offline_grace",
            "provenance": provenance,
            **selection_evidence,
        },
    )


def _resolve_pinned_identity_at_home(
    home: Any,
    *,
    profile_id: str,
    run_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Internal/test seam that still verifies one sealed run pin at the supplied home."""

    policy_digest = verify_policy_anchor(home)
    pinned = load_run_pin(
        home,
        profile_id=profile_id,
        run_id=run_id,
        policy_digest=policy_digest,
    )
    return _resolve_verified_snapshot_identity(
        profile_id=profile_id,
        snapshot=pinned["snapshot"],
        request=request,
        policy_digest=policy_digest,
    )


def resolve_identity(
    *,
    profile_id: str,
    run_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Resolve through the canonical host trust root and one verified sealed run pin."""

    return _resolve_pinned_identity_at_home(
        default_guardian_home(),
        profile_id=profile_id,
        run_id=run_id,
        request=request,
    )
