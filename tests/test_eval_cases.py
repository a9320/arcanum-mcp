"""Guards for the routing case set: shape, distribution, and no local paths.

The case file lives in a public repo, so it must stay path-free and self-describing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CASES_PATH = Path(__file__).resolve().parents[1] / "eval" / "routing_cases.json"


def _load() -> dict:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def test_case_file_is_valid_and_unique():
    data = _load()
    cases = data["cases"]
    assert data["runs_per_case"] >= 3, "instability needs at least 3 runs per case"
    assert 8 <= len(cases) <= 20
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids))


def test_expected_tools_are_known_and_negatives_exist():
    cases = _load()["cases"]
    allowed = {"pitax_scan", "code_audit", "none"}
    assert {c["expected_tool"] for c in cases} <= allowed
    assert sum(1 for c in cases if c["expected_tool"] == "none") >= 3
    assert sum(1 for c in cases if c["expected_tool"] == "pitax_scan") >= 3
    assert sum(1 for c in cases if c["expected_tool"] == "code_audit") >= 2


def test_prompts_do_not_leak_local_paths():
    cases = _load()["cases"]
    leaked = [
        c["id"] for c in cases
        if re.search(r"[A-Za-z]:\\\\|[A-Za-z]:\\", c.get("prompt", ""))
    ]
    assert not leaked, f"absolute local paths in public case file: {leaked}"