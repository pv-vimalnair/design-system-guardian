"""Test-only Ed25519 catalog authority and signing helpers."""

from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from guardian_core.policy import EXPECTED_POLICY_SHA256


CATALOG_APPROVAL_DOMAIN = "design-system-guardian.catalog-approval.v1"


@dataclass(frozen=True)
class TestCatalogAuthority:
    private_key: Ed25519PrivateKey
    public_pem: bytes
    key_id: str


def new_test_catalog_authority() -> TestCatalogAuthority:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TestCatalogAuthority(private_key, public_pem, hashlib.sha256(public_der).hexdigest())


DEFAULT_TEST_CATALOG_AUTHORITY = new_test_catalog_authority()


def attest_catalog(
    catalog: dict[str, Any],
    profile: dict[str, Any],
    *,
    sequence: int = 1,
    issued_at: datetime,
    authority: TestCatalogAuthority = DEFAULT_TEST_CATALOG_AUTHORITY,
) -> dict[str, Any]:
    document = copy.deepcopy(catalog)
    document.pop("approvalAttestation", None)
    metadata = {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "keyId": authority.key_id,
        "sequence": sequence,
        "issuedAt": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    payload = canonical_json_bytes(
        {
            "domain": CATALOG_APPROVAL_DOMAIN,
            "policyDigest": EXPECTED_POLICY_SHA256,
            "profileDigest": sha256_digest(profile),
            "attestation": metadata,
            "catalog": document,
        }
    )
    document["approvalAttestation"] = {
        **metadata,
        "signature": base64.b64encode(authority.private_key.sign(payload)).decode("ascii"),
    }
    return document
