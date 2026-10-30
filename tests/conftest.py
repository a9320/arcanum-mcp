"""Test path setup: local package + the engine checkout (same as MCP server resolution).

The engine is not on PyPI yet; tests look for `ARCA_SPARK_PATH` first, then a sibling
`arcanum-spark` checkout, and skip engine-backed tests if neither exists.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SPARK = os.environ.get("ARCA_SPARK_PATH") or str(ROOT.parent / "arcanum-spark")
if Path(SPARK).is_dir():
    os.environ.setdefault("ARCA_SPARK_PATH", SPARK)
    if SPARK not in sys.path:
        sys.path.insert(0, SPARK)