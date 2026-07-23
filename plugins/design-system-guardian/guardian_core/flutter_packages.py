"""Normative Flutter package identity and content provenance for Guardian v0.1."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .canonical import sha256_digest


TOKEN_CODE_CONNECT_EXTENSION = "org.design-system-guardian.code-connect"
PACKAGE_CONTENT_ALGORITHM = "design-system-guardian.flutter-package-content.v1"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PACKAGE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_ELEMENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*$")
_RESERVED_PACKAGES = {"flutter", "design_system_guardian_flutter"}
_MAPPING_KEYS = {"framework", "symbol", "approved", "inferred", "sourceDigest"}


class FlutterPackageProvenanceError(ValueError):
    """Signed mapping/package evidence is malformed, ambiguous, or impersonated."""


def valid_package_name(value: Any) -> bool:
    return isinstance(value, str) and _PACKAGE_NAME.fullmatch(value) is not None


def valid_repository_commit(value: Any) -> bool:
    return isinstance(value, str) and _REPOSITORY_COMMIT.fullmatch(value) is not None


def package_name_from_identity(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("package:"):
        raise FlutterPackageProvenanceError(
            f"{label} must be an exact package: analyzer identity."
        )
    hash_index = value.find("#")
    if hash_index <= len("package:") or hash_index == len(value) - 1:
        raise FlutterPackageProvenanceError(f"{label} is not a canonical code identity.")
    uri = value[len("package:") : hash_index]
    element = value[hash_index + 1 :]
    if value.find("#", hash_index + 1) != -1 or _ELEMENT.fullmatch(element) is None:
        raise FlutterPackageProvenanceError(f"{label} has a malformed element identity.")
    if any(marker in uri for marker in ("\\", "%", "?", ":")):
        raise FlutterPackageProvenanceError(f"{label} contains package URI impersonation syntax.")
    pure = PurePosixPath(uri)
    if pure.is_absolute() or len(pure.parts) < 2 or pure.as_posix() != uri:
        raise FlutterPackageProvenanceError(f"{label} has a non-canonical package URI path.")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise FlutterPackageProvenanceError(f"{label} package URI may not traverse paths.")
    package_name = pure.parts[0]
    if not valid_package_name(package_name) or package_name in _RESERVED_PACKAGES:
        raise FlutterPackageProvenanceError(
            f"{label} selects a forbidden or malformed package namespace."
        )
    return package_name


def package_content_digest(files: Sequence[Mapping[str, str]]) -> str:
    """Digest the sorted complete package file manifest using the v0.1 contract."""

    return sha256_digest(
        {
            "schemaVersion": 1,
            "algorithm": PACKAGE_CONTENT_ALGORITHM,
            "files": list(files),
        }
    )


def _flutter_mappings(snapshot: Mapping[str, Any]):
    tokens = snapshot.get("tokens")
    if not isinstance(tokens, dict):
        raise FlutterPackageProvenanceError("Verified snapshot tokens are malformed.")
    for token_identity in sorted(tokens):
        token = tokens[token_identity]
        if not isinstance(token, dict):
            raise FlutterPackageProvenanceError(
                f"Verified token {token_identity!r} is malformed."
            )
        extensions = token.get("extensions")
        if not isinstance(extensions, dict):
            continue
        guardian = extensions.get(TOKEN_CODE_CONNECT_EXTENSION)
        if guardian is None:
            continue
        if not isinstance(guardian, dict) or set(guardian) != {"codeMappings"}:
            raise FlutterPackageProvenanceError(
                f"Token {token_identity!r} has malformed Code Connect evidence."
            )
        mappings = guardian.get("codeMappings")
        if not isinstance(mappings, list):
            raise FlutterPackageProvenanceError(
                f"Token {token_identity!r} codeMappings must be an array."
            )
        for index, mapping in enumerate(mappings):
            yield mapping, f"token {token_identity!r} codeMappings[{index}]"

    registry = snapshot.get("registry")
    if not isinstance(registry, dict):
        raise FlutterPackageProvenanceError("Verified snapshot registry is malformed.")
    for plural in ("components", "icons"):
        assets = registry.get(plural)
        if not isinstance(assets, list):
            raise FlutterPackageProvenanceError(f"registry.{plural} must be an array.")
        for index, asset in enumerate(assets):
            if not isinstance(asset, dict) or not isinstance(asset.get("codeMappings"), list):
                raise FlutterPackageProvenanceError(
                    f"registry.{plural}[{index}] Code Connect evidence is malformed."
                )
            for mapping_index, mapping in enumerate(asset["codeMappings"]):
                yield mapping, f"registry.{plural}[{index}].codeMappings[{mapping_index}]"


def derive_approved_packages(
    snapshot: Mapping[str, Any],
    approved_identities: Mapping[str, Sequence[str]],
    component_variants: Mapping[str, Mapping[str, Sequence[str]]],
    *,
    repository_commit: Any,
) -> dict[str, dict[str, str]]:
    """Give signed mapping sourceDigest its normative package-content meaning."""

    package_digests: dict[str, str] = {}
    symbol_packages: dict[str, str] = {}
    for mapping, label in _flutter_mappings(snapshot):
        if not isinstance(mapping, dict) or set(mapping) != _MAPPING_KEYS:
            raise FlutterPackageProvenanceError(f"{label} is malformed.")
        if mapping.get("framework") != "flutter":
            continue
        if mapping.get("approved") is not True or mapping.get("inferred") is not False:
            raise FlutterPackageProvenanceError(
                f"{label} is not exact approved Code Connect evidence."
            )
        symbol = mapping.get("symbol")
        digest = mapping.get("sourceDigest")
        package_name = package_name_from_identity(symbol, label=f"{label}.symbol")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise FlutterPackageProvenanceError(
                f"{label}.sourceDigest must be a canonical package content digest."
            )
        previous = package_digests.get(package_name)
        if previous is not None and previous != digest:
            raise FlutterPackageProvenanceError(
                f"All mappings in package {package_name!r} must agree on one content digest."
            )
        package_digests[package_name] = digest
        existing_package = symbol_packages.get(symbol)
        if existing_package is not None and existing_package != package_name:
            raise FlutterPackageProvenanceError(
                f"Code identity {symbol!r} has conflicting package provenance."
            )
        symbol_packages[symbol] = package_name

    used_packages: set[str] = set()
    for category in sorted(approved_identities):
        values = approved_identities[category]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise FlutterPackageProvenanceError(
                f"approvedIdentities.{category} is malformed."
            )
        for index, identity in enumerate(values):
            package_name = package_name_from_identity(
                identity, label=f"approvedIdentities.{category}[{index}]"
            )
            if symbol_packages.get(identity) != package_name:
                raise FlutterPackageProvenanceError(
                    f"Approved identity {identity!r} lacks matching signed package evidence."
                )
            used_packages.add(package_name)

    for widget, properties in component_variants.items():
        widget_package = package_name_from_identity(
            widget, label="componentVariants widget"
        )
        if symbol_packages.get(widget) != widget_package:
            raise FlutterPackageProvenanceError(
                f"Component {widget!r} lacks matching signed package evidence."
            )
        for property_name, values in properties.items():
            for index, identity in enumerate(values):
                variant_package = package_name_from_identity(
                    identity,
                    label=f"componentVariants.{widget}.{property_name}[{index}]",
                )
                if variant_package != widget_package:
                    raise FlutterPackageProvenanceError(
                        f"Component variant {identity!r} impersonates a different package."
                    )
        used_packages.add(widget_package)

    if used_packages != set(package_digests):
        raise FlutterPackageProvenanceError(
            "Approved package provenance must be used exactly by the generated allowlist."
        )
    if used_packages and not valid_repository_commit(repository_commit):
        raise FlutterPackageProvenanceError(
            "sourceCut.repositoryCommit must be a full 40- or 64-character lowercase object id."
        )
    return {
        package_name: {
            "contentDigest": package_digests[package_name],
            "repositoryCommit": repository_commit,
        }
        for package_name in sorted(package_digests)
    }


def validate_approved_package_bindings(
    approved_packages: Any,
    approved_identities: Mapping[str, Sequence[str]],
    component_variants: Mapping[str, Mapping[str, Sequence[str]]],
) -> dict[str, dict[str, str]]:
    if not isinstance(approved_packages, dict):
        raise FlutterPackageProvenanceError("approvedPackages must be an object.")
    normalized: dict[str, dict[str, str]] = {}
    for package_name in sorted(approved_packages):
        item = approved_packages[package_name]
        if (
            not valid_package_name(package_name)
            or package_name in _RESERVED_PACKAGES
            or not isinstance(item, dict)
            or set(item) != {"contentDigest", "repositoryCommit"}
            or not isinstance(item.get("contentDigest"), str)
            or _DIGEST.fullmatch(item["contentDigest"]) is None
            or not valid_repository_commit(item.get("repositoryCommit"))
        ):
            raise FlutterPackageProvenanceError(
                f"approvedPackages.{package_name} is malformed or forbidden."
            )
        normalized[package_name] = dict(item)

    used: set[str] = set()
    for category, identities in approved_identities.items():
        for index, identity in enumerate(identities):
            package_name = package_name_from_identity(
                identity, label=f"approvedIdentities.{category}[{index}]"
            )
            if package_name not in normalized:
                raise FlutterPackageProvenanceError(
                    f"Approved identity {identity!r} has no approved package binding."
                )
            used.add(package_name)
    for widget, properties in component_variants.items():
        widget_package = package_name_from_identity(widget, label="componentVariants widget")
        if widget_package not in normalized:
            raise FlutterPackageProvenanceError(
                f"Component {widget!r} has no approved package binding."
            )
        for property_name, identities in properties.items():
            for index, identity in enumerate(identities):
                variant_package = package_name_from_identity(
                    identity,
                    label=f"componentVariants.{widget}.{property_name}[{index}]",
                )
                if variant_package != widget_package:
                    raise FlutterPackageProvenanceError(
                        f"Component variant {identity!r} impersonates another package."
                    )
        used.add(widget_package)
    if used != set(normalized):
        raise FlutterPackageProvenanceError(
            "approvedPackages must exactly equal packages used by approved identities."
        )
    return normalized


def validate_required_package_bindings(
    required_packages: Any,
    *,
    approved_packages: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """Validate profile-owned semantic packages without making them visual identities."""

    if not isinstance(required_packages, dict):
        raise FlutterPackageProvenanceError("requiredPackages must be an object.")
    if "flutter" not in required_packages:
        raise FlutterPackageProvenanceError(
            "requiredPackages must contain the profile-bound flutter package."
        )
    normalized: dict[str, dict[str, str]] = {}
    for package_name in sorted(required_packages):
        item = required_packages[package_name]
        if not valid_package_name(package_name) or package_name == "design_system_guardian_flutter":
            raise FlutterPackageProvenanceError(
                f"requiredPackages.{package_name} is malformed or forbidden."
            )
        if (
            not isinstance(item, dict)
            or set(item) != {"contentDigest", "repositoryCommit"}
            or not isinstance(item.get("contentDigest"), str)
            or _DIGEST.fullmatch(item["contentDigest"]) is None
            or not valid_repository_commit(item.get("repositoryCommit"))
        ):
            raise FlutterPackageProvenanceError(
                f"requiredPackages.{package_name} is malformed."
            )
        normalized[package_name] = dict(item)
    if approved_packages is not None and set(normalized) & set(approved_packages):
        raise FlutterPackageProvenanceError(
            "Required semantic packages and approved visual packages must be disjoint."
        )
    return normalized


__all__ = [
    "FlutterPackageProvenanceError",
    "PACKAGE_CONTENT_ALGORITHM",
    "derive_approved_packages",
    "package_content_digest",
    "package_name_from_identity",
    "valid_package_name",
    "valid_repository_commit",
    "validate_approved_package_bindings",
    "validate_required_package_bindings",
]
