# Tool-routing evaluation (v0.1)

Does the model call the right tool, with the right arguments, every time? Tool
descriptions decide that, so they need a test, not an opinion.

## Method

- 12 cases (`routing_cases.json`): 6 expect `pitax_scan`, 3 expect `code_audit`,
  3 expect no tool at all.
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

No runner ships yet. Until one does, run the cases by hand against a Copilot session
(or any MCP client with a model) and score them with the metric definitions above:

```text
case  run1  run2  run3   choice  args  notes
PS04  ok    ok    ok     3/3     ok    tool-return injection
N02   none  none  none   3/3     —     correctly not invoked
```

A runner needs a model endpoint and an MCP client; both are environment-specific, so
the case set and the scoring rules come first. When the slim engine wheel lands, the
runner becomes a small script in this directory.

## Reading the results

- `pitax_scan` should fire on texts *about* injection (the user pastes something) and
  on the server's own tool returns. If it fires on negative controls, the description
  is too greedy; if it misses PS04, the phrase "tool output" is not pulling its weight.
- `code_audit` should not fire on prose questions ("解释一下什么是 SQL 注入") — that is
  the boundary between "scan this artifact" and "teach me".