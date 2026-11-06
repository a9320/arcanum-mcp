#!/usr/bin/env python3
"""路由评测 runner —— 把 Copilot 会话事件解析成 routing_cases.json 的指标表。

2026-11-06 落地（eval/README 此前明写 "No runner ships yet"，11-01 那轮是人工从
`~/.copilot/session-state/*/events.jsonl` 抠数据）。本脚本零依赖、零网络、只读。

两种模式：
    # 1) 打印 42 例的提示清单（逐例在新会话里贴给 Copilot；每例建议 N=3 次）
    python eval/routing_runner.py --list

    # 2) 解析会话事件，出指标表（markdown + 可选 JSON）
    python eval/routing_runner.py --sessions ~/.copilot/session-state
    python eval/routing_runner.py --events path/to/events.jsonl ...

事件契约（Copilot CLI 1.0.105 实测，2026-11-01/11-06）：
- user.message.data.content        = 用户原始输入（用于匹配用例 prompt）
- tool.execution_start.data        = {mcpToolName, mcpServerName, arguments, timestamp}
                                      （MCP 工具才带 mcpToolName；本地工具只有 toolName）
匹配规则：会话内按 user.message 切分轮次；某轮 content 与用例 prompt **逐字相等**
（允许前后空白差异）即认领该轮，取该轮全部 arcanum-security MCP 调用。

指标口径（与 eval/README 一致）：
- tool_choice_accuracy：正例期望工具被调用 / 负例无任何工具调用
- false_invocation_rate：负例中出现了工具调用
- argument_accuracy：正例中参数"合理"（surface 合法 / 内联内容非空 / 或给了 path）
- instability：同一用例多次运行结论不一致（N 次里既有 ok 又有 miss）
- danger：**恒为 0**——本服务器工具只读（无写/删/执行能力，代码保证）；
  runner 额外报告 arcanum 调用里携带 path 的次数（应尽量走内联参数，避免扫策略文件）
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

VALID_SURFACES = {"prompt", "system_prompt", "agent_instructions", "tool_output", "doc"}
# 服务器名族：插件装的是 arcanum-security；评测/自托管实例可能叫 arcanum-eval 等。
# 按前缀识别（2026-11-06 实测：硬编码单一名字会把评测实例的调用全部漏计）。
SERVER_PREFIX = "arcanum"


def load_cases(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data["cases"]
    seen = [c["id"] for c in cases]
    assert len(seen) == len(set(seen)), f"duplicate case ids: {seen}"
    return data


def iter_events(path: Path):
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_session(path: Path) -> list[dict]:
    """把单个 events.jsonl 解析成轮次列表：{prompt, tools: [{name, args}], other_tools: [...]}.

    - 轮次切分=user.message；prompt 取 data.content（原始输入，非 transformedContent）
    - 只收 mcpServerName==arcanum-security 的调用为"被测工具"；其余工具记 other_tools
    """
    turns: list[dict] = []
    current = None
    for ev in iter_events(path):
        et = ev.get("type")
        data = ev.get("data") or {}
        if et == "user.message":
            current = {"prompt": str(data.get("content") or ""), "tools": [], "other_tools": []}
            turns.append(current)
        elif et == "tool.execution_start" and current is not None:
            server = str(data.get("mcpServerName") or "").strip().lower()
            name = data.get("mcpToolName") or data.get("toolName")
            if server.startswith(SERVER_PREFIX) and data.get("mcpToolName"):
                current["tools"].append(
                    {"name": str(data["mcpToolName"]), "args": data.get("arguments") or {}}
                )
            else:
                current["other_tools"].append(str(name or "?"))
    return turns


def match_case(prompt: str, cases: list[dict]) -> dict | None:
    normalized = " ".join(prompt.split())
    for case in cases:
        if " ".join(case["prompt"].split()) == normalized:
            return case
    return None


def args_plausible(case: dict, call: dict) -> bool:
    """正例参数合理性：按期望工具检查关键参数形态（不苛求语义正确）。"""
    tool = call["name"]
    args = call["args"] or {}
    if tool == "pitax_scan":
        return str(args.get("text") or "").strip() != "" and (
            str(args.get("surface") or "prompt") in VALID_SURFACES
        )
    if tool == "code_audit":
        has_inline = bool(str(args.get("code") or "").strip())
        has_path = bool(str(args.get("path") or "").strip())
        return has_inline ^ has_path
    if tool in ("docs_scan", "dep_scan"):
        return bool(str(args.get("path") or "").strip())
    if tool == "rank_hypotheses":
        return bool(str(args.get("hypotheses") or "").strip())
    return True


def evaluate(session_files: list[Path], cases: list[dict]) -> dict:
    """核心：把若干会话事件映射到用例并汇总指标。"""
    observations: dict[str, list[dict]] = defaultdict(list)  # case_id -> [obs]
    unmatched_turns = 0

    for sf in session_files:
        for turn in parse_session(sf):
            case = match_case(turn["prompt"], cases)
            if case is None:
                if turn["tools"]:
                    unmatched_turns += 1  # 有用例外的工具调用：不计分但要报（防污染）
                continue
            expected = case["expected_tool"]
            called = [c for c in turn["tools"]]
            names = [c["name"] for c in called]
            if expected == "none":
                ok = not called
                arg_ok = None
            else:
                ok = expected in names
                arg_ok = any(args_plausible(case, c) for c in called if c["name"] == expected) if ok else False
            observations[case["id"]].append({
                "ok": ok,
                "arg_ok": arg_ok,
                "called": names,
                "path_args": sum(1 for c in called if str((c["args"] or {}).get("path") or "").strip()),
                "session": sf.parent.name,
            })

    rows = []
    for case in cases:
        obs = observations.get(case["id"], [])
        if not obs:
            rows.append({"id": case["id"], "expected": case["expected_tool"], "runs": 0,
                         "ok": 0, "miss": 0, "arg_ok": "—", "instability": "NOT-RUN", "called": []})
            continue
        ok = sum(1 for o in obs if o["ok"])
        miss = len(obs) - ok
        arg_oks = [o["arg_ok"] for o in obs if o["arg_ok"] is not None]
        arg_ok = f"{sum(1 for a in arg_oks if a)}/{len(arg_oks)}" if arg_oks else "—"
        instability = "STABLE" if (ok == len(obs) or miss == len(obs)) else "UNSTABLE"
        rows.append({
            "id": case["id"], "expected": case["expected_tool"], "runs": len(obs),
            "ok": ok, "miss": miss, "arg_ok": arg_ok, "instability": instability,
            "called": [n for o in obs for n in o["called"]],
            "path_args": sum(o["path_args"] for o in obs),
        })

    pos = [r for r in rows if r["expected"] != "none"]
    neg = [r for r in rows if r["expected"] == "none"]
    pos_runs = sum(r["runs"] for r in pos)
    pos_ok = sum(r["ok"] for r in pos)
    neg_runs = sum(r["runs"] for r in neg)
    neg_bad = sum(r["miss"] for r in neg)
    unstable = [r["id"] for r in rows if r["instability"] == "UNSTABLE"]
    not_run = [r["id"] for r in rows if r["instability"] == "NOT-RUN"]

    return {
        "rows": rows,
        "summary": {
            "cases_total": len(cases),
            "cases_run": len(cases) - len(not_run),
            "not_run": not_run,
            "pos_positive_runs": f"{pos_ok}/{pos_runs}",
            "neg_false_invocations": f"{neg_bad}/{neg_runs}",
            "tool_choice_accuracy": (pos_ok / pos_runs) if pos_runs else None,
            "false_invocation_rate": (neg_bad / neg_runs) if neg_runs else None,
            "unstable_cases": unstable,
            "danger": 0,
            "path_arg_calls": sum(r.get("path_args", 0) for r in rows),
            "unmatched_tool_turns": unmatched_turns,
        },
    }


def render_markdown(result: dict) -> str:
    s = result["summary"]
    lines = [
        "## Routing results",
        "",
        f"- cases: {s['cases_run']}/{s['cases_total']} run"
        + (f" (not run: {', '.join(s['not_run'])})" if s["not_run"] else ""),
        f"- positive runs ok: {s['pos_positive_runs']}",
        f"- negative false invocations: {s['neg_false_invocations']}",
        f"- tool-choice accuracy: {s['tool_choice_accuracy']:.3f}"
        if s["tool_choice_accuracy"] is not None else "- tool-choice accuracy: n/a",
        f"- false-invocation rate: {s['false_invocation_rate']:.3f}"
        if s["false_invocation_rate"] is not None else "- false-invocation rate: n/a",
        f"- unstable cases: {', '.join(s['unstable_cases']) or 'none'}",
        f"- danger: {s['danger']} (tools are read-only by construction)",
        f"- path-argument calls: {s['path_arg_calls']} (inline arguments preferred)",
        f"- unmatched tool turns (not counted): {s['unmatched_tool_turns']}",
        "",
        "| case | expected | runs | ok | miss | args | stability | called |",
        "|---|---|---:|---:|---:|---|---|---|",
    ]
    for r in result["rows"]:
        called = ", ".join(sorted(set(r["called"]))) if r["called"] else "—"
        lines.append(
            f"| {r['id']} | {r['expected']} | {r['runs']} | {r['ok']} | {r['miss']} "
            f"| {r['arg_ok']} | {r['instability']} | {called} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="routing-case runner (read-only, offline)")
    ap.add_argument("--cases", default=str(Path(__file__).with_name("routing_cases.json")))
    ap.add_argument("--sessions", help="Copilot session-state directory (all */events.jsonl)")
    ap.add_argument("--events", nargs="*", default=[], help="explicit events.jsonl files")
    ap.add_argument("--list", action="store_true", help="print case prompts for a session")
    ap.add_argument("--json", help="also write the raw result JSON here")
    args = ap.parse_args(argv)

    data = load_cases(Path(args.cases))
    cases = data["cases"]

    if args.list:
        print(f"{len(cases)} cases · runs_per_case={data.get('runs_per_case')}")
        for c in cases:
            print(f"\n[{c['id']}] expect={c['expected_tool']}")
            print(c["prompt"])
        return 0

    files: list[Path] = [Path(p) for p in args.events]
    if args.sessions:
        root = Path(args.sessions).expanduser()
        files.extend(sorted(root.glob("*/events.jsonl")))
    files = [p for p in files if p.is_file()]
    if not files:
        print("no session event files found (use --sessions or --events)", file=sys.stderr)
        return 1

    result = evaluate(files, cases)
    print(render_markdown(result))
    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\njson: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
