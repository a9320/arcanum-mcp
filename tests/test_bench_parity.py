"""pitax_bench 51 例同源一致性验收（2026-11-05 P1-B）。

"MCP 检出质量锚在主仓基准上"：逐例还原 arcanum-spark `eval/pitax_bench/cases.jsonl`
的（相对路径, 文本）形态，走 `code_audit(path=...)` 扫描——**与 CLI 同一检测面路由**
（路径名决定 T-46/N-06/T-51 规则面），断言 expected 规则逐例命中、负例零命中。
这是"用例不糊弄"的最硬形式：MCP 不用自己的用例自证，直接对主仓基准负责。

基准缺席（无 ARCA_SPARK_PATH 兄弟仓）时整文件 skip。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not importlib.util.find_spec("codeark"),
    reason="codeark engine not importable (set ARCA_SPARK_PATH or install the spark extra)",
)

from arcanum_mcp import server as srv  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_BENCH = _ROOT.parent / "arcanum-spark" / "eval" / "pitax_bench" / "cases.jsonl"

pytestmark = [
    pytestmark,
    pytest.mark.skipif(not _BENCH.exists(), reason=f"pitax_bench not found: {_BENCH}"),
]


def _load_cases() -> list[dict]:
    return [json.loads(line) for line in _BENCH.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def bench_cases() -> list[dict]:
    cases = _load_cases()
    assert len(cases) >= 50, f"基准规模异常（期望 ~51 例，实际 {len(cases)}）"
    return cases


def test_bench_case_count_matches_ledger(bench_cases):
    """规模对账：51 例（strict 100%/FP0 的对外口径基线）。"""
    pos = sum(1 for c in bench_cases if c["kind"] == "pos")
    neg = sum(1 for c in bench_cases if c["kind"] == "neg")
    assert (len(bench_cases), pos, neg) == (51, 36, 15)


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["id"])
def test_bench_case_parity(case, tmp_path):
    """单例：还原 (path, text) → code_audit 单文件目录扫描 → expected 逐条命中。"""
    # bench 的 path 是相对路径（决定规则路由面），必须还原目录结构
    target = tmp_path / case["path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(case["text"], encoding="utf-8")

    out = srv.code_audit(path=str(tmp_path))
    found_rules = {
        token.strip().rstrip(":") for token in out.replace("]", " ").split() if token.startswith("PIT-")
    }
    if case["kind"] == "pos":
        for rule in case["expect"]:
            assert rule in found_rules, (
                f"{case['id']}: expected {rule} not reported (got {sorted(found_rules)})"
            )
    else:
        assert "no PITAX findings" in out, (
            f"{case['id']}: negative case produced findings — parity broken"
        )
