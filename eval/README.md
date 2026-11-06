# Tool-routing evaluation (v0.2)

Does the model call the right tool, with the right arguments, every time? Tool
descriptions decide that, so they need a test, not an opinion.

## Method

- 42 cases (`routing_cases.json`) over five tools: `pitax_scan` (PS), `code_audit` (CA),
  `docs_scan` (DS), `dep_scan` (DP), `rank_hypotheses` (RH), plus negatives (N, no tool).
- Each case runs **N=3**; a case is unstable if the three runs disagree.
- Metrics: tool-choice accuracy, false-invocation rate (negatives), argument
  accuracy, instability, and **danger = 0** (no tool call that writes, deletes, or
  executes scanned content).
- Provenance: methodology adapted from an internal Tianxi `ai-content-guard` 30×3
  trigger harness (pos/neg labels, N=3 stability, danger=0 gate). Prompts here are new
  and path-free; the harness code and the original fixtures are not copied.

## Why N=3

Single runs overstate quality: the same prompt can flip between two tools. The Tianxi
line learned this the hard way (one case passed 20/21 only because a single run
happened to sequence its calls correctly). Report instability, not just accuracy.

## Running it

`eval/routing_runner.py` (ships since 2026-11-06) — zero-dependency, read-only,
offline. It drives the case set and parses Copilot CLI session events
(`~/.copilot/session-state/*/events.jsonl`) into the metric table. Two modes:

```bash
# 1) print the case prompts to paste into a session (one case per fresh session, N=3)
python eval/routing_runner.py --list

# 2) score finished sessions (markdown table; --json for the raw record)
python eval/routing_runner.py --sessions ~/.copilot/session-state
```

Manual scoring stays valid for other clients — the per-case shape is:

```text
case  run1  run2  run3   choice  args  notes
PS04  ok    ok    ok     3/3     ok    tool-return injection
N02   none  none  none   3/3     —     correctly not invoked
```

Details the runner enforces: turns are split by `user.message`; only calls whose
`mcpServerName` starts with `arcanum` count as tool choices (plugin installs use
`arcanum-security`, self-hosted/eval instances may use other `arcanum-*` names; local
tools like `bash` are reported separately and never scored); cases whose prompt did not appear are marked
NOT-RUN and stay out of the denominator; a case with mixed outcomes across runs is
UNSTABLE; tool calls in turns that match no case are counted as
`unmatched_tool_turns` (contamination guard, not scored); `danger` is 0 by
construction (the server's tools are read-only) and path-argument calls are reported
verbatim. A `--list` run against the 42-case set is the fastest way to see whether a
new host's routing is worth measuring.

## Reading the results

- `pitax_scan` should fire on texts *about* injection (the user pastes something) and
  on the server's own tool returns. If it fires on negative controls, the description
  is too greedy; if it misses PS04, the phrase "tool output" is not pulling its weight.
- `code_audit` should not fire on prose questions ("解释一下什么是 SQL 注入") — that is
  the boundary between "scan this artifact" and "teach me".