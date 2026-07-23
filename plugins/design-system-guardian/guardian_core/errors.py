"""Typed failures with stable process and evidence semantics."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ExitCode, ResolutionStatus


@dataclass(eq=False)
class GuardianError(Exception):
    message: str
    exit_code: ExitCode
    status: ResolutionStatus

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def evidence(self) -> dict[str, object]:
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "status": self.status.value,
        }


class PolicyIntegrityError(GuardianError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message=message,
            exit_code=ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY,
            status=ResolutionStatus.INVALID,
        )


class UnsupportedCommandError(GuardianError):
    def __init__(self, command: str) -> None:
        super().__init__(
            message=f"The {command!r} command is not implemented in this plugin build.",
            exit_code=ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE,
            status=ResolutionStatus.UNSUPPORTED,
        )
