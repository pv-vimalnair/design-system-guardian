#!/usr/bin/env python3
"""Fail-closed public release inspection for Design System Guardian."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable


BOOTSTRAP_COMMIT = "05f736facf2187af638cf0ea6cb3897c77711c06"
CANONICAL_REPOSITORY = "pv-vimalnair/design-system-guardian"
API_ROOT = f"https://api.github.com/repos/{CANONICAL_REPOSITORY}/"
PACKAGE_PREFIX = "plugins/design-system-guardian/"
SUITE_PATH = PACKAGE_PREFIX + "benchmarks/elo-suite.json"
ELO_SOURCE_PATH = PACKAGE_PREFIX + "guardian_core/elo.py"
PUBLIC_POLICY_PATH = PACKAGE_PREFIX + "policy/policy-v1.json"
ALLOWED_EXACT = {
    ".gitattributes",
    ".gitignore",
    "LICENSE",
    "README.md",
    "kimi.plugin.json",
    "scripts/check_public_release.py",
}
ALLOWED_PREFIXES = (
    ".agents/",
    ".claude-plugin/",
    ".github/",
    PACKAGE_PREFIX,
)
RUNTIME_PREFIXES = tuple(
    PACKAGE_PREFIX + name + "/"
    for name in ("profiles", "snapshots", "catalogs", "runs", "trust", "authorities")
)
RUNTIME_JSON_KEYS = {"profileId", "snapshotId", "runId"}
IDENTIFIER_KEYS = {
    "profileId",
    "companyId",
    "fileKey",
    "nodeId",
    "assetKey",
    "snapshotId",
    "displayName",
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{24,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{24,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bfigd_[A-Za-z0-9_-]{20,}\b"),
)
WINDOWS_HOME = re.compile(rb"(?i)\b[A-Z]:\\Users\\([^\\\r\n]+)\\")
UNIX_HOME = re.compile(rb"/(?:home|Users)/([^/\s]+)/")
ROOT_HOME = re.compile(rb"(?<![A-Za-z0-9_])/" + rb"root/")
SYNTHETIC_HOME_NAMES = {b"example", b"example person", b"fixture", b"test", b"user", b"username"}


class PublicReleaseError(RuntimeError):
    """The release checker could not establish a trustworthy result."""


@dataclass(frozen=True)
class ReleaseResult:
    ok: bool
    codes: tuple[str, ...]

    def __post_init__(self) -> None:
        normalized = tuple(sorted(set(self.codes)))
        object.__setattr__(self, "codes", normalized)
        object.__setattr__(self, "ok", not normalized)


def render_result(result: ReleaseResult) -> str:
    if result.ok:
        return "PASS clean-public-release"
    return f"FAIL clean-public-release [{','.join(result.codes)}]"


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise PublicReleaseError("Git evidence is unavailable or invalid.")
    return completed.stdout


def _full_commit(root: Path, value: str) -> str:
    commit = _git(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    try:
        decoded = commit.decode("ascii", "strict").strip()
    except UnicodeError as error:
        raise PublicReleaseError("Git returned a non-ASCII commit identity.") from error
    if not HEX_40.fullmatch(decoded):
        raise PublicReleaseError("The release must bind one full lowercase Git commit.")
    return decoded


def _tree_entries(root: Path, commit: str) -> list[tuple[str, str, str, str]]:
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii", "strict").split(" ")
            path = encoded_path.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as error:
            raise PublicReleaseError("The committed tree contains malformed metadata.") from error
        entries.append((mode, object_type, object_id, path))
    return entries


def _blob(root: Path, object_id: str) -> bytes:
    return _git(root, "cat-file", "blob", object_id)


def _allowed_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in parts):
        return False
    if path in ALLOWED_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in ALLOWED_PREFIXES)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & 0x400)


def _runtime_json(payload: bytes, path: str) -> bool:
    if not path.endswith(".json"):
        return False
    relative = path.removeprefix(PACKAGE_PREFIX)
    if relative.startswith(("schemas/", "tests/", "benchmarks/", "policy/", "sentinels/", "assets/")):
        return False
    if relative in (".codex-plugin/plugin.json", ".claude-plugin/plugin.json"):
        return False
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and RUNTIME_JSON_KEYS.issubset(value)


def _contains_absolute_home(payload: bytes) -> bool:
    if ROOT_HOME.search(payload):
        return True
    for match in WINDOWS_HOME.finditer(payload):
        if match.group(1).strip().lower() not in SYNTHETIC_HOME_NAMES:
            return True
    for match in UNIX_HOME.finditer(payload):
        if match.group(1).strip().lower() not in SYNTHETIC_HOME_NAMES:
            return True
    return False


def _scan_tree(root: Path, commit: str) -> tuple[set[str], dict[str, bytes]]:
    codes: set[str] = set()
    public_blobs: dict[str, bytes] = {}
    for mode, object_type, object_id, path in _tree_entries(root, commit):
        if mode not in {"100644", "100755"} or object_type != "blob":
            codes.add("unsupported_git_mode")
            continue
        if not _allowed_path(path):
            codes.add("path_not_allowed")
        payload = _blob(root, object_id)
        public_blobs[path] = payload
        if path.startswith(RUNTIME_PREFIXES) or "/.design-system-guardian/" in f"/{path}/":
            codes.add("runtime_state")
        if _runtime_json(payload, path):
            codes.add("runtime_state")
        if _contains_absolute_home(payload):
            codes.add("absolute_home")
        if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
            codes.add("secret_material")
    return codes, public_blobs


def _walk_identifiers(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in IDENTIFIER_KEYS and isinstance(item, str) and len(item.strip()) >= 8:
                yield item.strip()
            yield from _walk_identifiers(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_identifiers(item)


def _public_blob_path(key: str) -> str:
    prefix, separator, remainder = key.partition(":")
    return remainder if separator and HEX_40.fullmatch(prefix) else key


def _semantic_public_identifiers(public_blobs: dict[str, bytes]) -> set[str]:
    values: set[str] = set()
    for key, payload in public_blobs.items():
        if not _public_blob_path(key).endswith(".json"):
            continue
        try:
            document = json.loads(payload.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        values.update(_walk_identifiers(document))
    return values


def _scan_local_matches(local_home: Path, public_blobs: dict[str, bytes]) -> set[str]:
    codes: set[str] = set()
    if not local_home.exists():
        return codes
    if not local_home.is_dir() or _is_link_or_reparse(local_home):
        return {"local_state_unavailable"}
    public_hashes = {
        hashlib.sha256(payload).digest()
        for key, payload in public_blobs.items()
        if _public_blob_path(key) != PUBLIC_POLICY_PATH
    }
    public_identifiers = _semantic_public_identifiers(public_blobs)
    local_identifiers: set[str] = set()
    walk_errors: list[OSError] = []

    def record_walk_error(error: OSError) -> None:
        walk_errors.append(error)

    for current, directory_names, file_names in os.walk(
        local_home,
        topdown=True,
        followlinks=False,
        onerror=record_walk_error,
    ):
        current_path = Path(current)
        for name in list(directory_names):
            directory = current_path / name
            if _is_link_or_reparse(directory):
                codes.add("local_state_unavailable")
                directory_names.remove(name)
        for name in file_names:
            path = current_path / name
            if _is_link_or_reparse(path) or not path.is_file():
                codes.add("local_state_unavailable")
                continue
            try:
                relative = path.relative_to(local_home).as_posix()
                payload = path.read_bytes()
            except OSError:
                codes.add("local_state_unavailable")
                continue
            if relative != "trust/policy-v1.json" and hashlib.sha256(payload).digest() in public_hashes:
                codes.add("local_file_match")
            if path.suffix.lower() == ".json":
                try:
                    document = json.loads(payload.decode("utf-8", "strict"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                local_identifiers.update(_walk_identifiers(document))
    if walk_errors:
        codes.add("local_state_unavailable")
    if local_identifiers.intersection(public_identifiers):
        codes.add("local_identifier_match")
    elif local_identifiers:
        encoded = {identifier.encode("utf-8") for identifier in local_identifiers}
        if any(any(identifier in payload for identifier in encoded) for payload in public_blobs.values()):
            codes.add("local_identifier_match")
    return codes

def _batch_blobs(root: Path, object_ids: list[str]) -> dict[str, bytes]:
    if not object_ids:
        return {}
    completed = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=root,
        input=("\n".join(object_ids) + "\n").encode("ascii"),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise PublicReleaseError("Historical Git objects are unavailable.")
    stream = io.BytesIO(completed.stdout)
    blobs: dict[str, bytes] = {}
    for requested in object_ids:
        header = stream.readline().rstrip(b"\n")
        parts = header.split(b" ")
        if len(parts) != 3:
            raise PublicReleaseError("Historical Git object metadata is invalid.")
        object_id, object_type, encoded_size = parts
        if object_id.decode("ascii", "strict") != requested:
            raise PublicReleaseError("Historical Git object identity changed.")
        try:
            size = int(encoded_size)
        except ValueError as error:
            raise PublicReleaseError("Historical Git object size is invalid.") from error
        payload = stream.read(size)
        if len(payload) != size or stream.read(1) != b"\n":
            raise PublicReleaseError("Historical Git object is truncated.")
        if object_type == b"blob":
            blobs[requested] = payload
    return blobs


def _history_evidence(root: Path, commit: str) -> tuple[set[str], dict[str, bytes]]:
    codes: set[str] = set()
    raw_changes = _git(root, "log", "--format=", "--raw", "-z", "--no-renames", commit)
    tokens = [token for token in raw_changes.split(b"\0") if token]
    for index in range(0, len(tokens), 2):
        if index + 1 >= len(tokens):
            raise PublicReleaseError("Historical Git change evidence is malformed.")
        try:
            metadata = tokens[index].decode("ascii", "strict").split(" ")
            path = tokens[index + 1].decode("utf-8", "strict")
        except UnicodeError as error:
            raise PublicReleaseError("Historical Git change evidence is invalid.") from error
        if len(metadata) < 5:
            raise PublicReleaseError("Historical Git change evidence is malformed.")
        old_mode, new_mode = metadata[0].removeprefix(":"), metadata[1]
        if any(mode not in {"000000", "100644", "100755"} for mode in (old_mode, new_mode)):
            codes.add("history_violation")
        if not _allowed_path(path):
            codes.add("history_violation")

    object_paths: dict[str, set[str]] = {}
    for line in _git(root, "rev-list", "--objects", commit).splitlines():
        if b" " not in line:
            continue
        encoded_id, encoded_path = line.split(b" ", 1)
        try:
            object_id = encoded_id.decode("ascii", "strict")
            path = encoded_path.decode("utf-8", "strict")
        except UnicodeError as error:
            raise PublicReleaseError("Historical Git object identity is invalid.") from error
        object_paths.setdefault(object_id, set()).add(path)
    historical_blobs: dict[str, bytes] = {}
    for object_id, payload in _batch_blobs(root, sorted(object_paths)).items():
        for path in object_paths[object_id]:
            historical_blobs[f"{object_id}:{path}"] = payload
            if not _allowed_path(path):
                codes.add("history_violation")
            if path.startswith(RUNTIME_PREFIXES) or "/.design-system-guardian/" in f"/{path}/":
                codes.add("history_violation")
            if _runtime_json(payload, path) or _contains_absolute_home(payload):
                codes.add("history_violation")
            if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
                codes.add("history_violation")
    return codes, historical_blobs

ELO_MODEL = "guardian-weighted-elo-v1"
ELO_CATEGORIES = {
    "correctness",
    "reliability",
    "coverage_usefulness",
    "safety_privacy_integrity",
    "portability_usability_performance",
}
SUITE_KEYS = {"schemaVersion", "model", "suiteId", "suiteVersion", "caseModules", "achievements"}
MODULE_KEYS = {"moduleId", "path", "moduleDigest", "workerDigest"}
ACHIEVEMENT_KEYS = {
    "achievementId", "category", "weight", "caseModuleId", "caseFunction", "workerDigest"
}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ACHIEVEMENT_ID = re.compile(r"^synthetic-[a-z0-9]+(?:-[a-z0-9]+)*$")
CASE_FUNCTION = re.compile(r"^case_[a-z0-9]+(?:_[a-z0-9]+)*$")


def _validate_suite(value: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not isinstance(value, dict) or set(value) != SUITE_KEYS:
        raise PublicReleaseError("Public Elo suite has an invalid exact contract.")
    if (
        value.get("schemaVersion") != 2
        or value.get("model") != ELO_MODEL
        or value.get("suiteId") != "guardian-public-synthetic-v1"
        or type(value.get("suiteVersion")) is not int
        or value["suiteVersion"] < 1
    ):
        raise PublicReleaseError("Public Elo suite identity is invalid.")
    modules = value.get("caseModules")
    if not isinstance(modules, list) or not modules:
        raise PublicReleaseError("Public Elo suite has no immutable modules.")
    modules_by_id: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for module in modules:
        if not isinstance(module, dict) or set(module) != MODULE_KEYS:
            raise PublicReleaseError("Public Elo module contract is invalid.")
        module_id, module_path = module.get("moduleId"), module.get("path")
        if (
            not isinstance(module_id, str)
            or not re.fullmatch(r"guardian-public-cases-v[1-9][0-9]*", module_id)
            or module_id in modules_by_id
            or not isinstance(module_path, str)
            or not re.fullmatch(r"benchmarks/elo_cases_v[1-9][0-9]*\.py", module_path)
            or module_path in paths
            or not isinstance(module.get("moduleDigest"), str)
            or not HEX_64.fullmatch(module["moduleDigest"])
            or not isinstance(module.get("workerDigest"), str)
            or not HEX_64.fullmatch(module["workerDigest"])
        ):
            raise PublicReleaseError("Public Elo module identity is invalid.")
        modules_by_id[module_id] = module
        paths.add(module_path)
    achievements = value.get("achievements")
    if not isinstance(achievements, list) or not achievements:
        raise PublicReleaseError("Public Elo suite has no achievements.")
    by_id: dict[str, dict[str, Any]] = {}
    functions: set[tuple[str, str]] = set()
    covered: set[str] = set()
    for item in achievements:
        if not isinstance(item, dict) or set(item) != ACHIEVEMENT_KEYS:
            raise PublicReleaseError("Public Elo achievement contract is invalid.")
        achievement_id = item.get("achievementId")
        category, weight = item.get("category"), item.get("weight")
        module_id, function = item.get("caseModuleId"), item.get("caseFunction")
        if (
            not isinstance(achievement_id, str)
            or len(achievement_id) > 127
            or not ACHIEVEMENT_ID.fullmatch(achievement_id)
            or achievement_id in by_id
            or category not in ELO_CATEGORIES
            or type(weight) is not int
            or weight <= 0
            or module_id not in modules_by_id
            or not isinstance(function, str)
            or not CASE_FUNCTION.fullmatch(function)
            or (module_id, function) in functions
            or item.get("workerDigest") != modules_by_id[module_id]["workerDigest"]
        ):
            raise PublicReleaseError("Public Elo achievement binding is invalid.")
        by_id[achievement_id] = item
        functions.add((module_id, function))
        covered.add(category)
    if covered != ELO_CATEGORIES:
        raise PublicReleaseError("Public Elo category coverage is incomplete.")
    return value, by_id


def validate_prior_suite_transition(previous: Any, current: Any) -> None:
    previous_suite, previous_by_id = _validate_suite(previous)
    current_suite, current_by_id = _validate_suite(current)
    previous_modules = {item["moduleId"]: item for item in previous_suite["caseModules"]}
    current_modules = {item["moduleId"]: item for item in current_suite["caseModules"]}
    if current_suite["suiteVersion"] < previous_suite["suiteVersion"]:
        raise PublicReleaseError("Public Elo suite version moved backward.")
    if not set(previous_by_id).issubset(current_by_id) or not set(previous_modules).issubset(current_modules):
        raise PublicReleaseError("Public Elo suite removed accepted evidence.")
    changed = set(current_by_id) != set(previous_by_id) or set(current_modules) != set(previous_modules)
    if changed and current_suite["suiteVersion"] <= previous_suite["suiteVersion"]:
        raise PublicReleaseError("Additive Elo evidence requires a higher suite version.")
    for module_id, old in previous_modules.items():
        if current_modules[module_id] != old:
            raise PublicReleaseError("Accepted Elo module or worker bytes changed.")
    frozen = ("category", "weight", "caseModuleId", "caseFunction", "workerDigest")
    for achievement_id, old in previous_by_id.items():
        if any(current_by_id[achievement_id][field] != old[field] for field in frozen):
            raise PublicReleaseError("Accepted Elo case binding changed.")


def _worker_digest_from_source(source: bytes) -> str:
    try:
        tree = ast.parse(source.decode("utf-8", "strict"))
    except (UnicodeError, SyntaxError) as error:
        raise PublicReleaseError("Public Elo worker source is invalid.") from error
    script: str | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_WORKER" for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                script = node.value.value
            break
    if script is None:
        raise PublicReleaseError("Public Elo worker source is missing.")
    contract = {
        "script": script,
        "interpreterFlags": ["-I", "-B", "-c"],
        "statusProtocol": {"passed": 0, "assertion_failed": 1, "infrastructure": 2},
    }
    canonical = json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def bootstrap_without_prior_suite_allowed(prior_commit: str) -> bool:
    return prior_commit == BOOTSTRAP_COMMIT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise PublicReleaseError("Canonical GitHub redirects are forbidden.")


def _github_request(suffix: str) -> dict[str, Any]:
    if not re.fullmatch(
        r"(?:commits/(?:main|[0-9a-f]{40})|git/trees/[0-9a-f]{40}\?recursive=1|git/blobs/[0-9a-f]{40})",
        suffix,
    ):
        raise PublicReleaseError("GitHub request is outside the fixed canonical repository surface.")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "design-system-guardian-public-release/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        if token != token.strip() or len(token) > 1024 or any(ord(character) < 33 for character in token):
            raise PublicReleaseError("GitHub token evidence is malformed.")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API_ROOT + suffix, headers=headers, method="GET")
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != API_ROOT + suffix:
                raise PublicReleaseError("Canonical GitHub evidence is unavailable.")
            value = json.loads(response.read().decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as error:
        if isinstance(error, PublicReleaseError):
            raise
        raise PublicReleaseError("Canonical GitHub evidence is unavailable.") from error
    if not isinstance(value, dict):
        raise PublicReleaseError("Canonical GitHub evidence has the wrong shape.")
    return value


def _remote_blob(value: dict[str, Any]) -> bytes:
    if value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise PublicReleaseError("Canonical GitHub blob evidence has the wrong shape.")
    try:
        return base64.b64decode(value["content"], validate=True)
    except (ValueError, TypeError) as error:
        raise PublicReleaseError("Canonical GitHub blob evidence is invalid.") from error


def _remote_package_tree(
    commit: str,
    fetch: Callable[[str], dict[str, Any]],
) -> tuple[dict[str, str], dict[str, Any]]:
    commit_value = fetch(f"commits/{commit}")
    tree = commit_value.get("commit", {}).get("tree", {}) if isinstance(commit_value.get("commit"), dict) else {}
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    if not isinstance(tree_sha, str) or not HEX_40.fullmatch(tree_sha):
        raise PublicReleaseError("Canonical GitHub commit tree is invalid.")
    tree_value = fetch(f"git/trees/{tree_sha}?recursive=1")
    if tree_value.get("truncated") is not False or not isinstance(tree_value.get("tree"), list):
        raise PublicReleaseError("Canonical GitHub tree is incomplete.")
    paths: dict[str, str] = {}
    for item in tree_value["tree"]:
        if not isinstance(item, dict):
            raise PublicReleaseError("Canonical GitHub tree is invalid.")
        path, mode, object_type, sha = item.get("path"), item.get("mode"), item.get("type"), item.get("sha")
        if isinstance(path, str) and path.startswith(PACKAGE_PREFIX):
            if mode == "040000" and object_type == "tree":
                continue
            if mode not in {"100644", "100755"} or object_type != "blob" or not isinstance(sha, str):
                raise PublicReleaseError("Canonical prior package contains an unsupported object.")
            paths[path] = sha
    return paths, commit_value


def _validate_suite_files(
    suite: dict[str, Any],
    get_blob: Callable[[str], bytes],
    expected_worker_digest: str,
) -> None:
    validate_prior_suite_transition(suite, suite)
    modules = suite.get("caseModules")
    if not isinstance(modules, list):
        raise PublicReleaseError("Public suite modules are invalid.")
    for module in modules:
        if not isinstance(module, dict):
            raise PublicReleaseError("Public suite module is invalid.")
        module_path = PACKAGE_PREFIX + str(module.get("path", ""))
        if hashlib.sha256(get_blob(module_path)).hexdigest() != module.get("moduleDigest"):
            raise PublicReleaseError("Public suite module bytes do not match their digest.")
        if expected_worker_digest != module.get("workerDigest"):
            raise PublicReleaseError("Public suite worker semantics do not match their digest.")


def check_public_prior_suite(
    root: Path,
    candidate_commit: str,
    *,
    fetch: Callable[[str], dict[str, Any]] = _github_request,
) -> None:
    main = fetch("commits/main")
    main_sha = main.get("sha")
    if not isinstance(main_sha, str) or not HEX_40.fullmatch(main_sha):
        raise PublicReleaseError("Canonical public main identity is invalid.")
    if main_sha == candidate_commit:
        candidate = fetch(f"commits/{candidate_commit}")
        parents = candidate.get("parents")
        if not isinstance(parents, list) or not parents or not isinstance(parents[0], dict):
            raise PublicReleaseError("Published candidate has no authenticated prior commit.")
        prior_commit = parents[0].get("sha")
    else:
        prior_commit = main_sha
    if not isinstance(prior_commit, str) or not HEX_40.fullmatch(prior_commit):
        raise PublicReleaseError("Canonical prior public commit is invalid.")

    prior_paths, _ = _remote_package_tree(prior_commit, fetch)
    current_entries = {path: object_id for _, _, object_id, path in _tree_entries(root, candidate_commit)}
    if SUITE_PATH not in current_entries:
        raise PublicReleaseError("Candidate has no public Elo suite.")

    def current_blob(path: str) -> bytes:
        object_id = current_entries.get(path)
        if object_id is None:
            raise PublicReleaseError("Candidate Elo evidence is incomplete.")
        return _blob(root, object_id)

    try:
        current_suite = json.loads(current_blob(SUITE_PATH).decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PublicReleaseError("Candidate Elo suite is invalid.") from error
    if not isinstance(current_suite, dict):
        raise PublicReleaseError("Candidate Elo suite is invalid.")
    _validate_suite_files(current_suite, current_blob, _worker_digest_from_source(current_blob(ELO_SOURCE_PATH)))

    if SUITE_PATH not in prior_paths:
        if not bootstrap_without_prior_suite_allowed(prior_commit):
            raise PublicReleaseError("A non-bootstrap public release has no prior Elo suite.")
        return

    def prior_blob(path: str) -> bytes:
        sha = prior_paths.get(path)
        if sha is None:
            raise PublicReleaseError("Prior public Elo evidence is incomplete.")
        return _remote_blob(fetch(f"git/blobs/{sha}"))

    try:
        prior_suite = json.loads(prior_blob(SUITE_PATH).decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PublicReleaseError("Prior public Elo suite is invalid.") from error
    if not isinstance(prior_suite, dict):
        raise PublicReleaseError("Prior public Elo suite is invalid.")
    _validate_suite_files(prior_suite, prior_blob, _worker_digest_from_source(prior_blob(ELO_SOURCE_PATH)))
    validate_prior_suite_transition(prior_suite, current_suite)


def check_public_release(
    repository_root: Path,
    *,
    history: bool,
    local_home: Path | None,
    require_clean: bool,
    check_prior_suite: bool,
    commit: str = "HEAD",
) -> ReleaseResult:
    root = repository_root.expanduser().resolve(strict=True)
    if not root.is_dir() or not (root / ".git").exists():
        raise PublicReleaseError("Repository root is unavailable.")
    full_commit = _full_commit(root, commit)
    codes, public_blobs = _scan_tree(root, full_commit)
    if require_clean and _git(root, "status", "--porcelain", "--untracked-files=all").strip():
        codes.add("dirty_tree")
    release_blobs = dict(public_blobs)
    if history:
        history_codes, historical_blobs = _history_evidence(root, full_commit)
        codes.update(history_codes)
        release_blobs.update(historical_blobs)
    if local_home is not None:
        codes.update(_scan_local_matches(local_home.expanduser(), release_blobs))
    if check_prior_suite:
        try:
            check_public_prior_suite(root, full_commit)
        except PublicReleaseError:
            codes.add("prior_suite_unverified")
    return ReleaseResult(not codes, tuple(codes))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--history", action="store_true")
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Run structural/history validation without account-local comparison.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    local_home = None if args.ci else Path.home() / ".design-system-guardian"
    try:
        result = check_public_release(
            args.repository_root,
            history=args.history,
            local_home=local_home,
            require_clean=True,
            check_prior_suite=True,
            commit=args.commit,
        )
    except (OSError, PublicReleaseError) as error:
        print("ERROR clean-public-release [evidence_unavailable]", file=sys.stderr)
        return 2
    print(render_result(result))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
