"""Shared secure Guardian provisioning for direct API tests."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
)


def catalog_authority_public_key_path(home: Path) -> Path:
    """Materialize only the default test authority's public key for bootstrap."""

    home.mkdir(parents=True, exist_ok=True)
    path = home / "catalog-authority-input.pem"
    if path.exists():
        if path.read_bytes() != DEFAULT_TEST_CATALOG_AUTHORITY.public_pem:
            raise AssertionError("Test catalog authority public key fixture was changed.")
    else:
        path.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    return path


def install_test_context(home: Path, profile: dict[str, Any]) -> str:
    """Install both distinct authorities and one explicitly selected profile."""

    from guardian_core.policy import install_policy_anchor
    from guardian_core.profile import install_profile

    public_key = catalog_authority_public_key_path(home)
    policy_digest = install_policy_anchor(
        home,
        catalog_authority_public_key=public_key,
    ).digest
    install_profile(home, profile)
    return policy_digest


def signed_test_catalog(
    catalog: dict[str, Any],
    profile: dict[str, Any],
    *,
    now: datetime,
    sequence: int = 1,
) -> dict[str, Any]:
    """Produce detached approval evidence using the test-only private authority."""

    return attest_catalog(catalog, profile, sequence=sequence, issued_at=now)


def ingest_test_snapshot(
    home: Path,
    profile: dict[str, Any],
    catalog: dict[str, Any],
    *,
    now: datetime,
    sequence: int = 1,
) -> dict[str, Any]:
    """Provision trust/profile and invoke production with a test-patched clock."""

    from guardian_core.snapshot import ingest_snapshot

    install_test_context(home, profile)
    approved = signed_test_catalog(catalog, profile, now=now, sequence=sequence)
    with patch("guardian_core.snapshot._utc_now", return_value=now):
        return ingest_snapshot(home, profile, approved)
