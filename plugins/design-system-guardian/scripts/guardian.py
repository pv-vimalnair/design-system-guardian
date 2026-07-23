#!/usr/bin/env python3
"""Run Guardian directly from an unpacked plugin."""

from __future__ import annotations

import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
