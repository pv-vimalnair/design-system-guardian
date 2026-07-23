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
def profile_transaction_lock(
    home: Path,
    profile_id: str,
    *,
    timeout_seconds: float = 5.0,
) -> Iterator[None]:
    """Serialize profile promotion and pinning without ever breaking stale locks.

    A lock left by a crashed process deliberately blocks until an operator
    inspects it. Guardian must not guess that a trust-boundary lock is stale.
    """

    if timeout_seconds <= 0:
        raise ValueError("Profile transaction lock timeout must be positive.")
    normalized_home = home.expanduser().absolute()
    lock_path = GuardianPaths(normalized_home).profile(profile_id) / "transaction.lock"
    lock_path = assert_guardian_storage_path(normalized_home, lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(normalized_home, lock_path)
    token = (
        f"guardian-profile-lock-v1:{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex}\n"
    ).encode("ascii")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            descriptor = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                view = memoryview(token)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("Profile transaction lock write did not make progress.")
                    view = view[written:]
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor)
                descriptor = -1
                lock_path.unlink(missing_ok=True)
                raise
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            break
        except FileExistsError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Profile transaction lock is already held; Guardian will not break or bypass it."
                ) from error
            time.sleep(min(0.01, remaining))

    try:
        assert_guardian_storage_path(normalized_home, lock_path)
        if lock_path.read_bytes() != token:
            raise OSError("Profile transaction lock changed after acquisition.")
        yield
    finally:
        assert_guardian_storage_path(normalized_home, lock_path)
        if not lock_path.is_file() or lock_path.read_bytes() != token:
            raise OSError("Profile transaction lock changed before release; it was not removed.")
        lock_path.unlink()
        assert_guardian_storage_path(normalized_home, lock_path)
