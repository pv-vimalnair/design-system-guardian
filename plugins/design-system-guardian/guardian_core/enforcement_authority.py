"""Build-bound protected enforcement authority contract.

The personal-plugin build deliberately ships without a protected provider.
No environment variable, executable lookup, import hook, caller parameter, or
plugin-local seal can activate one. A future reviewed host/CI build must link a
provider and an externally monotonic catalog head before this lane can become
``allowed``.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping, Protocol

from .contracts import ExitCode


class EnforcementAuthorityIntegrityError(ValueError):
    """Raised when local evidence claims protected production authority."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


class ProtectedEnforcementAuthority(Protocol):
    """Future host/CI protocol; no implementation is linked in v0.1."""

    def verify(
        self,
        *,
        run_manifest: Mapping[str, Any],
        external_catalog_head: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


# This build-time literal is intentionally not configurable at runtime. Merely
# changing it is insufficient: a reviewed provider binding and external
# monotonic-head verifier must be compiled into a later release together.
_PROTECTED_PROVIDER_COMPILED = False
_UNAVAILABLE_LANE = {
    "schemaVersion": 1,
    "status": "not_assessed",
    "provider": None,
    "attestation": None,
}


def enforcement_authority_lane() -> dict[str, Any]:
    """Return the only production-authority result supported by this build."""

    if _PROTECTED_PROVIDER_COMPILED:
        raise EnforcementAuthorityIntegrityError(
            "This build has no reviewed protected provider or external monotonic catalog head."
        )
    return copy.deepcopy(_UNAVAILABLE_LANE)


def canonicalize_enforcement_authority_lane(value: Any) -> dict[str, Any]:
    """Reject local/caller claims and return the build-canonical lane."""

    canonical = enforcement_authority_lane()
    if value != canonical:
        raise EnforcementAuthorityIntegrityError(
            "Protected enforcement authority cannot be supplied by plugin-local or caller evidence."
        )
    return canonical


__all__ = [
    "EnforcementAuthorityIntegrityError",
    "ProtectedEnforcementAuthority",
    "canonicalize_enforcement_authority_lane",
    "enforcement_authority_lane",
]
