"""Fail-closed contract for the canonical external release-head authority.

The private pilot intentionally ships only the protocol and an unconditional
compile-time blocker: it has no resolver, loader, or configurable production
provider. A future reviewed Guardian code release must integrate one fixed host
adapter (not one supplied by an agent or caller), authenticate the latest
authority-signed head, and implement monotonic compare-and-swap backed by
independently preserved/WORM storage.
"""

from __future__ import annotations

from typing import Any, NoReturn, Protocol, runtime_checkable


class ExternalReleaseHeadUnavailable(RuntimeError):
    """Raised because this build has no integrated rollback-resistant head provider."""


@runtime_checkable
class CanonicalReleaseHeadProvider(Protocol):
    """Required host adapter; local files and caller-selected paths do not qualify."""

    @property
    def provider_id(self) -> str: ...

    def read_latest(self, channel: str) -> dict[str, Any] | None: ...

    def read_checkpoint(self, checkpoint_digest: str) -> dict[str, Any]: ...

    def compare_and_swap(
        self,
        channel: str,
        expected_checkpoint_digest: str | None,
        proposed_head: dict[str, Any],
    ) -> dict[str, Any]: ...


def block_unimplemented_canonical_release_head_provider() -> NoReturn:
    """Unconditionally block every production channel operation in this release.

    Do not replace this with an environment variable, arbitrary filesystem path,
    in-process memory store, or caller-provided JSON. Those options permit replay
    of an older signed head and therefore cannot authorize a trusted channel read.
    """

    raise ExternalReleaseHeadUnavailable(
        "This private-pilot build has no integrated external/WORM release-head provider; "
        "trusted channel reads, promotions, and restorations are blocked."
    )
