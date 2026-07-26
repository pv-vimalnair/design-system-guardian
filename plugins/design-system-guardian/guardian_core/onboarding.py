"""Permission-bound, local-only Guardian onboarding orchestration.

The portable CLI remains non-interactive. Agent hosts use the read-only preview
to explain one exact local setup operation, obtain the user's permission, and
only then call :func:`apply_onboarding` with the digest-bound bundle.
"""

from __future__ import annotations

import copy
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .canonical import sha256_digest
from .catalog_authority import (
    CatalogAuthorityError,
    read_catalog_authority_public_key,
    verify_pinned_catalog_authority,
)
from .clock import utc_now as _utc_now
from .errors import PolicyIntegrityError
from .paths import GuardianPaths, is_link_or_reparse
from .policy import (
    EXPECTED_POLICY_SHA256,
    _existing_anchor_state,
    install_policy_anchor,
    verify_policy_anchor,
)
from .profile import (
    ProfileValidationError,
    install_profile,
    load_profile,
    profile_path,
    validate_profile,
)
from .snapshot import (
    SnapshotValidationError,
    classify_source_state,
    ingest_snapshot,
    load_snapshot,
)


class OnboardingError(ValueError):
    """Raised when onboarding cannot preserve exact trust and profile identity."""


_BUNDLE_KEYS = {
    "schemaVersion",
    "catalogAuthorityPublicKey",
    "profile",
    "catalog",
    "permission",
}
_PERMISSION_BINDING_KEYS = {
    "schemaVersion",
    "policyDigest",
    "catalogAuthorityKeyId",
    "profileId",
    "profileDigest",
    "figmaAuthorityDigest",
    "catalogDocumentDigest",
}
_PERMISSION_KEYS = _PERMISSION_BINDING_KEYS | {"granted"}


def _authority_path(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise OnboardingError("Catalog authority public key path must be non-empty.")
    path = Path(value)
    if not path.is_absolute():
        raise OnboardingError("Catalog authority public key path must be absolute.")
    try:
        if is_link_or_reparse(path) or not path.is_file():
            raise OnboardingError(
                "Catalog authority public key must be an unredirected regular file."
            )
    except OSError as error:
        raise OnboardingError(
            f"Catalog authority public key cannot be inspected safely: {error}"
        ) from error
    return path


def _candidate_evidence(
    *,
    catalog_authority_public_key: Path,
    profile_document: Any,
    catalog_document: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    try:
        profile = validate_profile(profile_document)
    except ProfileValidationError as error:
        raise OnboardingError(f"Company profile is invalid: {error}") from error
    if not isinstance(catalog_document, dict):
        raise OnboardingError("Catalog onboarding input must be a JSON object.")
    catalog = copy.deepcopy(catalog_document)
    if catalog.get("profileId") != profile["profileId"]:
        raise OnboardingError(
            "Catalog profile identity differs from the one explicitly selected profile."
        )
    try:
        _, catalog_key_id = read_catalog_authority_public_key(
            catalog_authority_public_key
        )
    except CatalogAuthorityError as error:
        raise OnboardingError(f"Catalog authority is invalid: {error}") from error
    binding = {
        "schemaVersion": 1,
        "policyDigest": EXPECTED_POLICY_SHA256,
        "catalogAuthorityKeyId": catalog_key_id,
        "profileId": profile["profileId"],
        "profileDigest": sha256_digest(profile),
        "figmaAuthorityDigest": sha256_digest(profile["figma"]),
        "catalogDocumentDigest": sha256_digest(catalog),
    }
    return profile, catalog, binding, catalog_key_id


def prepare_onboarding_permission(
    *,
    catalog_authority_public_key: Path,
    profile_document: Any,
    catalog_document: Any,
) -> dict[str, Any]:
    """Describe one exact onboarding operation without writing local state.

    This validates the public key shape, company profile, and digest binding. The
    catalog's detached approval is verified during explicit apply, inside an
    isolated staging home, before any canonical Guardian home is promoted.
    """

    authority_path = _authority_path(str(catalog_authority_public_key))
    profile, _, binding, _ = _candidate_evidence(
        catalog_authority_public_key=authority_path,
        profile_document=profile_document,
        catalog_document=catalog_document,
    )
    figma = profile["figma"]
    return {
        "schemaVersion": 1,
        "status": "permission_required",
        "stage": "permission",
        "reasonCode": "onboarding_permission_required",
        "message": (
            "Guardian needs permission to register its protected rules and this "
            "exact company design-system authority locally."
        ),
        "permissionRequired": True,
        "localChangesPerformed": False,
        "permissionBinding": binding,
        "profile": {
            "profileId": profile["profileId"],
            "displayName": profile["displayName"],
        },
        "figmaAuthority": {
            "libraryFiles": copy.deepcopy(figma["allowlistedLibraryFiles"]),
            "workingFiles": copy.deepcopy(figma.get("allowlistedWorkingFiles", [])),
        },
    }


def validate_onboarding_bundle(document: Any) -> dict[str, Any]:
    """Validate one explicitly permitted, digest-bound local onboarding bundle."""

    if not isinstance(document, dict) or set(document) != _BUNDLE_KEYS:
        raise OnboardingError("Onboarding bundle has unknown or missing fields.")
    if document.get("schemaVersion") != 1:
        raise OnboardingError("Onboarding bundle schemaVersion must be exactly 1.")
    authority_path = _authority_path(document.get("catalogAuthorityPublicKey"))
    profile, catalog, binding, _ = _candidate_evidence(
        catalog_authority_public_key=authority_path,
        profile_document=document.get("profile"),
        catalog_document=document.get("catalog"),
    )
    permission = document.get("permission")
    if not isinstance(permission, dict) or set(permission) != _PERMISSION_KEYS:
        raise OnboardingError("Onboarding permission has unknown or missing fields.")
    if permission.get("granted") is not True:
        raise OnboardingError("Explicit onboarding permission was not granted.")
    supplied_binding = {
        key: copy.deepcopy(permission[key]) for key in _PERMISSION_BINDING_KEYS
    }
    if supplied_binding != binding:
        raise OnboardingError(
            "Onboarding permission does not match the exact policy, authority, profile, "
            "Figma allowlist, and catalog selected for apply."
        )
    return {
        "schemaVersion": 1,
        "catalogAuthorityPublicKey": authority_path,
        "profile": profile,
        "catalog": catalog,
        "permission": copy.deepcopy(permission),
    }


def _status(
    *,
    status: str,
    stage: str,
    reason_code: str,
    permission_required: bool,
    next_action: str,
    profile_id: str | None,
    policy_digest: str | None = None,
    catalog_authority_key_id: str | None = None,
    snapshot_id: str | None = None,
    source_state: str | None = None,
    degraded: bool = False,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "status": status,
        "stage": stage,
        "reasonCode": reason_code,
        "permissionRequired": permission_required,
        "nextAction": next_action,
        "localChangesPerformed": False,
        "ready": status == "ready",
        "profileId": profile_id,
        "policyDigest": policy_digest,
        "catalogAuthorityKeyId": catalog_authority_key_id,
        "snapshotId": snapshot_id,
        "sourceState": source_state,
        "degraded": degraded,
    }


def inspect_onboarding(home: Path, *, profile_id: str | None = None) -> dict[str, Any]:
    """Inspect setup readiness without creating directories or changing evidence."""

    normalized_home = home.expanduser().absolute()
    paths = GuardianPaths(normalized_home)
    try:
        anchor_state = _existing_anchor_state(paths)
    except OSError as error:
        raise OnboardingError(f"Guardian trust state cannot be inspected: {error}") from error
    if anchor_state == "absent":
        return _status(
            status="setup_required",
            stage="policy",
            reason_code="policy_anchor_missing",
            permission_required=True,
            next_action="request_onboarding_permission",
            profile_id=profile_id,
            policy_digest=EXPECTED_POLICY_SHA256,
        )
    if anchor_state in {"partial", "incompatible"}:
        return _status(
            status="invalid",
            stage="policy",
            reason_code=f"policy_anchor_{anchor_state}",
            permission_required=False,
            next_action="request_trust_recovery",
            profile_id=profile_id,
        )
    try:
        policy_digest = verify_policy_anchor(normalized_home)
        _, catalog_key_id = verify_pinned_catalog_authority(normalized_home)
    except (CatalogAuthorityError, PolicyIntegrityError, ValueError, OSError) as error:
        return _status(
            status="invalid",
            stage="policy",
            reason_code="policy_anchor_invalid",
            permission_required=False,
            next_action="request_trust_recovery",
            profile_id=profile_id,
        ) | {"message": str(error)}
    if profile_id is None:
        return _status(
            status="setup_required",
            stage="profile",
            reason_code="explicit_profile_required",
            permission_required=True,
            next_action="select_one_company_profile",
            profile_id=None,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        )
    try:
        selected_profile_path = profile_path(normalized_home, profile_id)
    except (ProfileValidationError, ValueError) as error:
        return _status(
            status="invalid",
            stage="profile",
            reason_code="profile_identity_invalid",
            permission_required=False,
            next_action="correct_profile_identity",
            profile_id=profile_id,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        ) | {"message": str(error)}
    if not selected_profile_path.exists():
        return _status(
            status="setup_required",
            stage="profile",
            reason_code="profile_missing",
            permission_required=True,
            next_action="request_onboarding_permission",
            profile_id=profile_id,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        )
    try:
        profile = load_profile(normalized_home, profile_id)
    except (ProfileValidationError, ValueError, OSError) as error:
        return _status(
            status="invalid",
            stage="profile",
            reason_code="profile_invalid",
            permission_required=False,
            next_action="request_profile_recovery",
            profile_id=profile_id,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        ) | {"message": str(error)}
    pointer = paths.profile(profile_id) / "current-snapshot.json"
    if not pointer.exists():
        return _status(
            status="setup_required",
            stage="snapshot",
            reason_code="snapshot_missing",
            permission_required=True,
            next_action="refresh_and_approve_catalog",
            profile_id=profile_id,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        )
    try:
        snapshot = load_snapshot(normalized_home, profile_id)
        freshness = classify_source_state(snapshot, now=_utc_now())
    except (SnapshotValidationError, ValueError, OSError) as error:
        return _status(
            status="invalid",
            stage="snapshot",
            reason_code="snapshot_invalid",
            permission_required=False,
            next_action="request_snapshot_recovery",
            profile_id=profile_id,
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
        ) | {"message": str(error)}
    source_state = freshness["state"]
    if source_state in {"fresh", "offline_grace"}:
        return _status(
            status="ready",
            stage="ready",
            reason_code="onboarding_complete",
            permission_required=False,
            next_action="continue_guardian_workflow",
            profile_id=profile["profileId"],
            policy_digest=policy_digest,
            catalog_authority_key_id=catalog_key_id,
            snapshot_id=snapshot["snapshotId"],
            source_state=source_state,
            degraded=source_state == "offline_grace",
        )
    return _status(
        status=source_state,
        stage="snapshot",
        reason_code=f"snapshot_{source_state}",
        permission_required=False,
        next_action="refresh_catalog_source",
        profile_id=profile["profileId"],
        policy_digest=policy_digest,
        catalog_authority_key_id=catalog_key_id,
        snapshot_id=snapshot["snapshotId"],
        source_state=source_state,
    )


def _apply_components(home: Path, bundle: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    public_key = bundle["catalogAuthorityPublicKey"]
    profile = bundle["profile"]
    permission = bundle["permission"]
    installation = install_policy_anchor(
        home,
        catalog_authority_public_key=public_key,
    )
    if installation.catalog_authority_key_id != permission["catalogAuthorityKeyId"]:
        raise OnboardingError(
            "Installed catalog authority differs from the permission-bound authority."
        )
    selected_profile_path = profile_path(home, profile["profileId"])
    profile_created = False
    if selected_profile_path.exists():
        existing_profile = load_profile(home, profile["profileId"])
        if existing_profile != profile:
            raise OnboardingError(
                "An installed profile revision differs from the permission-bound profile; "
                "onboarding will not replace it silently."
            )
    else:
        install_profile(home, profile)
        profile_created = True
    pointer = GuardianPaths(home).profile(profile["profileId"]) / "current-snapshot.json"
    previous_snapshot_id: str | None = None
    if pointer.exists():
        previous_snapshot_id = load_snapshot(home, profile["profileId"])["snapshotId"]
    snapshot = ingest_snapshot(home, profile, bundle["catalog"])
    changed = (
        installation.created
        or profile_created
        or previous_snapshot_id != snapshot["snapshotId"]
    )
    return snapshot, changed


def _result(
    snapshot: dict[str, Any],
    *,
    changed: bool,
    fresh_home_promoted: bool,
) -> dict[str, Any]:
    source_state = snapshot["sourceState"]
    ready = source_state in {"fresh", "offline_grace"}
    return {
        "schemaVersion": 1,
        "status": "allowed" if ready else source_state,
        "stage": "ready" if ready else "snapshot",
        "reasonCode": "onboarding_complete" if ready else f"snapshot_{source_state}",
        "permissionRequired": False,
        "nextAction": "continue_guardian_workflow" if ready else "refresh_catalog_source",
        "localChangesPerformed": changed,
        "freshHomePromoted": fresh_home_promoted,
        "ready": ready,
        "profileId": snapshot["profileId"],
        "profileDigest": snapshot["profileDigest"],
        "policyDigest": snapshot["policyDigest"],
        "snapshotId": snapshot["snapshotId"],
        "sourceState": source_state,
        "degraded": source_state == "offline_grace",
    }


def _existing_home_is_empty(home: Path) -> bool:
    try:
        return home.is_dir() and not any(home.iterdir())
    except OSError as error:
        raise OnboardingError(f"Guardian home cannot be inspected safely: {error}") from error


def apply_onboarding(home: Path, document: Any) -> dict[str, Any]:
    """Apply one explicit local permission without changing plugin or product source.

    A fresh canonical home is fully assembled in a same-parent staging directory
    and promoted by rename only after policy, profile, external catalog approval,
    snapshot validation, and sealing all succeed. Existing trusted homes use the
    idempotent create-once and immutable promotion primitives directly.
    """

    bundle = validate_onboarding_bundle(document)
    normalized_home = home.expanduser().absolute()
    empty_target = False
    if normalized_home.exists():
        try:
            if is_link_or_reparse(normalized_home) or not normalized_home.is_dir():
                raise OnboardingError(
                    "Canonical Guardian home must be an unredirected directory."
                )
        except OSError as error:
            raise OnboardingError(
                f"Canonical Guardian home cannot be inspected safely: {error}"
            ) from error
        paths = GuardianPaths(normalized_home)
        anchor_state = _existing_anchor_state(paths)
        if anchor_state == "absent":
            empty_target = _existing_home_is_empty(normalized_home)
            if not empty_target:
                raise OnboardingError(
                    "A non-empty Guardian home without complete trust evidence cannot be enrolled."
                )
        elif anchor_state in {"partial", "incompatible"}:
            raise OnboardingError(
                "Existing partial or incompatible trust requires reviewed recovery; onboarding "
                "will not repair or overwrite it."
            )
        else:
            try:
                snapshot, changed = _apply_components(normalized_home, bundle)
                return _result(
                    snapshot,
                    changed=changed,
                    fresh_home_promoted=False,
                )
            except OnboardingError:
                raise
            except (
                CatalogAuthorityError,
                PolicyIntegrityError,
                ProfileValidationError,
                SnapshotValidationError,
                ValueError,
                OSError,
            ) as error:
                raise OnboardingError(f"Guardian onboarding failed safely: {error}") from error

    parent = normalized_home.parent
    try:
        if not parent.is_dir() or is_link_or_reparse(parent):
            raise OnboardingError(
                "Canonical Guardian home parent must be an existing unredirected directory."
            )
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{normalized_home.name}.onboarding.",
                dir=parent,
            )
        )
    except OnboardingError:
        raise
    except OSError as error:
        raise OnboardingError(f"Guardian onboarding staging failed: {error}") from error
    promoted = False
    removed_empty_target = False
    try:
        snapshot, _ = _apply_components(stage, bundle)
        try:
            if empty_target:
                normalized_home.rmdir()
                removed_empty_target = True
            os.rename(stage, normalized_home)
            promoted = True
        except OSError as error:
            if removed_empty_target and not normalized_home.exists():
                try:
                    normalized_home.mkdir()
                except OSError:
                    pass
            raise OnboardingError(
                f"Guardian onboarding could not atomically promote verified local state: {error}"
            ) from error
        verify_policy_anchor(normalized_home)
        stored_profile = load_profile(normalized_home, snapshot["profileId"])
        if stored_profile != bundle["profile"]:
            raise OnboardingError(
                "Promoted onboarding profile differs from the permission-bound profile."
            )
        promoted_snapshot = load_snapshot(
            normalized_home,
            snapshot["profileId"],
            snapshot["snapshotId"],
        )
        return _result(
            promoted_snapshot,
            changed=True,
            fresh_home_promoted=True,
        )
    except OnboardingError:
        raise
    except (
        CatalogAuthorityError,
        PolicyIntegrityError,
        ProfileValidationError,
        SnapshotValidationError,
        ValueError,
        OSError,
    ) as error:
        raise OnboardingError(f"Guardian onboarding failed safely: {error}") from error
    finally:
        if not promoted and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)

__all__ = [
    "OnboardingError",
    "apply_onboarding",
    "inspect_onboarding",
    "prepare_onboarding_permission",
    "validate_onboarding_bundle",
]
