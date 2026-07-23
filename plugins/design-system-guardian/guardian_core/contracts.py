"""Stable public contracts shared by Guardian commands and adapters."""

from enum import Enum, IntEnum


class ExitCode(IntEnum):
    """Portable Guardian process exit codes."""

    PASS = 0
    VIOLATION_OR_SENTINEL = 1
    INVALID_POLICY_CONFIG_OR_INTEGRITY = 2
    SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE = 3
    UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE = 4


class ResolutionStatus(str, Enum):
    """The only status values allowed in canonical Guardian evidence."""

    ALLOWED = "allowed"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    CONFLICT = "conflict"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    STALE = "stale"
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_INCOMPLETE = "source_incomplete"
    NOT_ASSESSED = "not_assessed"
