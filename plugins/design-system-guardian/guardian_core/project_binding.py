"""Explicit, adapter-neutral binding to the product checkout selected at preflight."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .canonical import sha256_digest
from .contracts import ExitCode
from .paths import is_link_or_reparse


class ProjectBindingError(ValueError):
    """Raised when a run is redirected to another project or project revision."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_BINDING_KEYS = {"canonicalRoot", "rootIdentity", "gitCommit"}
_EVIDENCE_KEYS = {
    "canonicalRoot",
    "rootIdentity",
    "gitCommit",
    "assessedTreeDigest",
    "analysisInputsDigest",
}


def _canonical_root(project_root: Path | str) -> Path:
    if not isinstance(project_root, (Path, str)) or not str(project_root):
        raise ProjectBindingError("An explicit non-empty project root is required.")
    supplied = Path(project_root).expanduser().absolute()
    try:
        if is_link_or_reparse(supplied):
            raise ProjectBindingError("The intended project root may not be a link or reparse point.")
        root = supplied.resolve(strict=True)
    except OSError as error:
        raise ProjectBindingError(f"The intended project root is unavailable: {error}") from error
    if not root.is_dir():
        raise ProjectBindingError("The intended project root must be a directory.")
    return root


def _root_identity(root: Path) -> str:
    metadata = root.stat()
    return sha256_digest(
        {
            "canonicalPath": os.path.normcase(str(root)),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    )


def _read_small_text(path: Path, label: str) -> str:
    try:
        if is_link_or_reparse(path) or not path.is_file():
            raise ProjectBindingError(f"{label} must be an unredirected regular file.")
        payload = path.read_bytes()
    except OSError as error:
        raise ProjectBindingError(f"{label} cannot be read safely: {error}") from error
    if len(payload) > 1024 * 1024:
        raise ProjectBindingError(f"{label} is unexpectedly large.")
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProjectBindingError(f"{label} must contain ASCII Git metadata.") from error


def _safe_ref(ref: str) -> PurePosixPath:
    path = PurePosixPath(ref)
    if not ref.startswith("refs/") or path.is_absolute() or ".." in path.parts:
        raise ProjectBindingError("Git HEAD contains an unsafe symbolic reference.")
    return path


def _git_directory(root: Path) -> Path | None:
    marker = root / ".git"
    if not marker.exists():
        return None
    if is_link_or_reparse(marker):
        raise ProjectBindingError("Git metadata may not be a link or reparse point.")
    if marker.is_dir():
        return marker.resolve(strict=True)
    if not marker.is_file():
        raise ProjectBindingError("Git metadata must be a directory or worktree pointer file.")
    pointer = _read_small_text(marker, "Git worktree pointer").strip()
    if not pointer.startswith("gitdir: "):
        raise ProjectBindingError("Git worktree pointer is malformed.")
    candidate = Path(pointer[8:])
    if not candidate.is_absolute():
        candidate = marker.parent / candidate
    try:
        git_dir = candidate.resolve(strict=True)
    except OSError as error:
        raise ProjectBindingError(f"Git worktree directory is unavailable: {error}") from error
    if not git_dir.is_dir() or is_link_or_reparse(git_dir):
        raise ProjectBindingError("Git worktree directory must be an unredirected directory.")
    return git_dir


def _common_git_directory(git_dir: Path) -> Path:
    marker = git_dir / "commondir"
    if not marker.exists():
        return git_dir
    relative = _read_small_text(marker, "Git common-directory pointer").strip()
    if not relative:
        raise ProjectBindingError("Git common-directory pointer is empty.")
    candidate = Path(relative)
    if not candidate.is_absolute():
        candidate = git_dir / candidate
    try:
        common = candidate.resolve(strict=True)
    except OSError as error:
        raise ProjectBindingError(f"Git common directory is unavailable: {error}") from error
    if not common.is_dir() or is_link_or_reparse(common):
        raise ProjectBindingError("Git common directory must be an unredirected directory.")
    return common


def _commit_from_ref(git_dir: Path, ref: PurePosixPath) -> str | None:
    common = _common_git_directory(git_dir)
    candidates = (git_dir / Path(*ref.parts), common / Path(*ref.parts))
    for candidate in candidates:
        if not candidate.exists():
            continue
        value = _read_small_text(candidate, "Git reference").strip()
        if not _GIT_COMMIT.fullmatch(value):
            raise ProjectBindingError("Git reference does not contain a full object ID.")
        return value
    packed = common / "packed-refs"
    if packed.exists():
        for line in _read_small_text(packed, "Git packed references").splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            fields = line.split(" ", 1)
            if len(fields) == 2 and fields[1] == ref.as_posix():
                if not _GIT_COMMIT.fullmatch(fields[0]):
                    raise ProjectBindingError("Packed Git reference has an invalid object ID.")
                return fields[0]
    return None


def observe_git_commit(root: Path) -> str | None:
    """Read a local Git object ID without invoking ambient Git.

    This is a visibility and consistency observation. It is not a claim that
    the commit is trusted, signed, reachable from a remote, or clean.
    """

    git_dir = _git_directory(root)
    if git_dir is None:
        return None
    head = _read_small_text(git_dir / "HEAD", "Git HEAD").strip()
    if _GIT_COMMIT.fullmatch(head):
        return head
    if head.startswith("ref: "):
        return _commit_from_ref(git_dir, _safe_ref(head[5:]))
    raise ProjectBindingError("Git HEAD is malformed.")


def validate_project_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_KEYS:
        raise ProjectBindingError("Project binding has unknown or missing fields.")
    canonical_root = value.get("canonicalRoot")
    if not isinstance(canonical_root, str) or not Path(canonical_root).is_absolute():
        raise ProjectBindingError("Project binding canonicalRoot must be an absolute path.")
    root_identity = value.get("rootIdentity")
    if not isinstance(root_identity, str) or not _DIGEST.fullmatch(root_identity):
        raise ProjectBindingError("Project binding rootIdentity must be a SHA-256 digest.")
    git_commit = value.get("gitCommit")
    if git_commit is not None and (
        not isinstance(git_commit, str) or not _GIT_COMMIT.fullmatch(git_commit)
    ):
        raise ProjectBindingError("Project binding gitCommit must be a full local object ID or null.")
    return copy.deepcopy(value)


def capture_project_binding(project_root: Path | str) -> dict[str, Any]:
    root = _canonical_root(project_root)
    return {
        "canonicalRoot": str(root),
        "rootIdentity": _root_identity(root),
        "gitCommit": observe_git_commit(root),
    }


def verify_bound_project(binding: Any) -> dict[str, Any]:
    normalized = validate_project_binding(binding)
    current = capture_project_binding(normalized["canonicalRoot"])
    if current != normalized:
        raise ProjectBindingError(
            "The intended project root identity or local Git observation changed; run preflight again."
        )
    return normalized


def require_requested_project(binding: Any, requested_root: Path | str) -> dict[str, Any]:
    normalized = verify_bound_project(binding)
    requested = capture_project_binding(requested_root)
    if requested != normalized:
        raise ProjectBindingError(
            "Audit projectRoot does not match the intended project bound during preflight."
        )
    return normalized


def validate_project_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _EVIDENCE_KEYS:
        raise ProjectBindingError("Project evidence has unknown or missing fields.")
    binding = validate_project_binding(
        {key: value[key] for key in _BINDING_KEYS}
    )
    for field in ("assessedTreeDigest", "analysisInputsDigest"):
        digest = value.get(field)
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ProjectBindingError(f"Project evidence {field} must be a SHA-256 digest.")
    return {**binding, "assessedTreeDigest": value["assessedTreeDigest"], "analysisInputsDigest": value["analysisInputsDigest"]}


def project_evidence_from_runner(
    binding: Any,
    runner_project: Any,
) -> dict[str, Any]:
    normalized_binding = verify_bound_project(binding)
    if not isinstance(runner_project, Mapping):
        raise ProjectBindingError("Trusted runner evidence has no project object.")
    evidence = {
        "canonicalRoot": runner_project.get("canonicalRoot"),
        "rootIdentity": runner_project.get("rootIdentity"),
        "gitCommit": normalized_binding["gitCommit"],
        "assessedTreeDigest": runner_project.get("assessedTreeDigest"),
        "analysisInputsDigest": runner_project.get("analysisInputsDigest"),
    }
    normalized_evidence = validate_project_evidence(evidence)
    if {key: normalized_evidence[key] for key in _BINDING_KEYS} != normalized_binding:
        raise ProjectBindingError(
            "Trusted analysis evidence is not for the intended project bound during preflight."
        )
    return normalized_evidence


def project_evidence_matches_binding(evidence: Any, binding: Any) -> dict[str, Any]:
    normalized_evidence = validate_project_evidence(evidence)
    normalized_binding = verify_bound_project(binding)
    if {key: normalized_evidence[key] for key in _BINDING_KEYS} != normalized_binding:
        raise ProjectBindingError("Audit project evidence differs from the preflight binding.")
    return normalized_evidence


__all__ = [
    "ProjectBindingError",
    "capture_project_binding",
    "observe_git_commit",
    "project_evidence_from_runner",
    "project_evidence_matches_binding",
    "require_requested_project",
    "validate_project_binding",
    "validate_project_evidence",
    "verify_bound_project",
]
