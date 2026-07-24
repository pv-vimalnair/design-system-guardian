"""Reserved immutable additive-case module used to prove cross-version execution."""

from pathlib import Path


def case_additive_elo_runtime(root: Path) -> None:
    assert (root / "guardian_core" / "elo.py").is_file()
