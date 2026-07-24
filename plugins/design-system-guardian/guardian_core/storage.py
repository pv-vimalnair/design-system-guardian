"""Contained writes and fail-closed profile transaction locks."""

from __future__ import annotations

import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .canonical import atomic_write_json, canonical_json_bytes
from .paths import GuardianPaths, assert_guardian_storage_path


def contained_atomic_write_json(home: Path, path: Path, value: Any) -> None:
    target = assert_guardian_storage_path(home, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(home, target)
    atomic_write_json(target, value)
    assert_guardian_storage_path(home, target)


def exclusive_write_json(home: Path, path: Path, value: Any) -> None:
    """Create canonical JSON exactly once; never replace an existing path."""

    target = assert_guardian_storage_path(home, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(home, target)
    payload = canonical_json_bytes(value)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    created = True
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Exclusive artifact write did not make progress.")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        descriptor = -1
        if created:
            target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    assert_guardian_storage_path(home, target)
    if target.read_bytes() != payload:
        raise OSError("Exclusive artifact bytes changed during creation.")


@contextmanager
def transaction_lock(
    home: Path,
    lock_path: Path,
    *,
    purpose: str,
    timeout_seconds: float = 5.0,
) -> Iterator[None]:
    """Acquire one nonce-bearing create-once host-state transaction lock."""

    if timeout_seconds <= 0:
        raise ValueError("Transaction lock timeout must be positive.")
    if not purpose or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in purpose):
        raise ValueError("Transaction lock purpose must be lowercase ASCII words.")
    normalized_home = home.expanduser().absolute()
    target = assert_guardian_storage_path(normalized_home, lock_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(normalized_home, target)
    token = (
        f"{purpose}:{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex}\n"
    ).encode("ascii")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                view = memoryview(token)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("Transaction lock write did not make progress.")
                    view = view[written:]
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor)
                descriptor = -1
                if target.is_file() and target.read_bytes() == token:
                    target.unlink()
                raise
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            break
        except FileExistsError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Transaction lock is already held; Guardian will not break or bypass it."
                ) from error
            time.sleep(min(0.01, remaining))

    try:
        assert_guardian_storage_path(normalized_home, target)
        if target.read_bytes() != token:
            raise OSError("Transaction lock changed after acquisition.")
        yield
    finally:
        assert_guardian_storage_path(normalized_home, target)
        if not target.is_file() or target.read_bytes() != token:
            raise OSError("Transaction lock changed before release; it was not removed.")
        target.unlink()
        assert_guardian_storage_path(normalized_home, target)


@contextmanager
def profile_transaction_lock(
    home: Path,
    profile_id: str,
    *,
    timeout_seconds: float = 5.0,
) -> Iterator[None]:
    """Serialize profile promotion and pinning without breaking stale locks."""

    normalized_home = home.expanduser().absolute()
    lock_path = GuardianPaths(normalized_home).profile(profile_id) / "transaction.lock"
    with transaction_lock(
        normalized_home,
        lock_path,
        purpose="guardian-profile-lock-v1",
        timeout_seconds=timeout_seconds,
    ):
        yield
