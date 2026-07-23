"""Trusted runtime clock boundary.

Public Guardian interfaces never accept caller-supplied assessment time. Tests may
patch the private aliases imported by individual modules.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the host's timezone-aware UTC system time."""

    return datetime.now(timezone.utc)
