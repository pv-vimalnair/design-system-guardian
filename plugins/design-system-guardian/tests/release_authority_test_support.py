"""Test-only Ed25519 release authority and detached signing helpers."""

from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True)
class TestReleaseAuthority:
    private_key: Ed25519PrivateKey
    public_pem: bytes
    key_id: str


def new_test_release_authority() -> TestReleaseAuthority:
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
    return TestReleaseAuthority(
        private_key=private_key,
        public_pem=public_pem,
        key_id=hashlib.sha256(public_der).hexdigest(),
    )


DEFAULT_TEST_RELEASE_AUTHORITY = new_test_release_authority()


def release_public_key_path(
    home: Path,
    authority: TestReleaseAuthority = DEFAULT_TEST_RELEASE_AUTHORITY,
) -> Path:
    path = home / f"release-authority-{authority.key_id}.pem"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(authority.public_pem)
    return path


def sign_release_manifest(
    manifest: dict[str, Any],
    authority: TestReleaseAuthority = DEFAULT_TEST_RELEASE_AUTHORITY,
) -> dict[str, Any]:
    from guardian_core.release import release_signing_payload

    document = copy.deepcopy(manifest)
    document["authority"] = {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "keyId": authority.key_id,
    }
    payload = release_signing_payload(document)
    document["authority"]["signature"] = base64.b64encode(
        authority.private_key.sign(payload)
    ).decode("ascii")
    return document
