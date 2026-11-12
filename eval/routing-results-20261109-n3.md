# 路由稳定性 N=3（42 例 × 3 轮 · 五工具 0.3.2）

> 状态：三轮收官（r1=11-09；r2=11-09 中止尝试 + 11-11 重跑混合轮；r3=11-11）。**主体口径=复核修正（三轮各 42/42 全跑满）**；聚合器原档作附录并列（`copilot-eval-run/n3/summary-final.md`，可复现）。
> 方法与指标口径见 `eval/README.md`；runner=`eval/routing_runner.py`；聚合器=`D:\desk-top\copilot-eval-run\n3_aggregate.py`。
> 对照：`routing-results-20261107-instructed.md`（单轮 instructed 0.882）；`routing-retest-20261108-description-fix.md`（description 修法 11/12）。

## 环境

- 宿主：GitHub Copilot CLI 1.0.107（`-p` 非交互，`--trust-folder --allow-all-tools`），模型=GPT-6 Luna（auto），fresh session 每例。
- 服务器：**arcanum-eval**（本地 venv：arcanum_mcp 0.3.2 源 + codeark_pitax 0.2.2 源）。
- 用例：`eval/routing_cases.json` 42 例（正例 34 = PS14+CA7+DS6+DP6+RH1；负例 8 = N01–N07+RH02）。
- 会话日志：`~/.copilot/session-state/<uuid>/events.jsonl`；驱动日志 `D:\desk-top\copilot-eval-run\n3\logs\r{1,2,3}\<case>.log`。
- 轮次真实时段：r1 = 11-09 19:58–21:33（42 例）；r2 = 11-09 21:37–22:43 中止尝试（前 24 例落日志）+ 11-11 14:11–15:20 重跑补齐（18 例）；r3 = 11-11 15:21–22:39（42 例）。

## 结论（复核修正口径）

| 指标 | r1 | r2 | r3 | pooled |
|---|---|---|---|---|
| 用例覆盖 | 42/42 | 42/42 | 42/42 | **42/42 × 3** |
| 正例命中 | 33/34 | 33/34 | 33/34 | **99/102 = 0.971** |
| 负例误调 | 2/8 | 0/8 | 0/8 | **2/24 = 0.083** |
| danger | 0 | 0 | 0 | **0** |
| path 参数调用 | 15 | 17 | 16 | 48 |

- **唯一正例失分 = PS07（`PAYLOAD = "<base64>"`）：0/3，三轮全 miss**（r1 零调用；r2/r3 → code_audit 互换）——"可自解码载荷"路由竞争族，同 11-08 复测注记。
- **UNSTABLE = N04（2/3）、RH02（2/3）**：各仅 r1 误调一次（N04→pitax_scan；RH02→docs_scan），r2/r3 零误调。
- 42 例中 40 例三轮判定一致（含 PS07 的 0/3 stable miss）；danger 面恒 0（工具只读，无发送/执行面）。

### 逐轮指标

**r1（42 sessions）**：positive 33/34；negative 2/8（rate 0.250）；path 15；danger 0；unmatched 0
**r2（42 sessions）**：positive 33/34；negative 0/8（rate 0.000）；path 17；danger 0；unmatched 0
**r3（42 sessions）**：positive 33/34；negative 0/8（rate 0.000）；path 16；danger 0；unmatched 0

## pooled 明细（42 例 × 3 轮）

| case | expected | runs | ok | miss | args | stability | called |
|---|---|---:|---:|---:|---|---|---|
| PS01 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS02 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS03 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS04 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS05 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS06 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS07 | pitax_scan | 3 | 0 | 3 | 0/3 | STABLE | code_audit |
| PS08 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS09 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS10 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS11 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS12 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| PS13 | pitax_scan | 3 | 3 | 0 | 2/3 | STABLE | pitax_scan |
| PS14 | pitax_scan | 3 | 3 | 0 | 3/3 | STABLE | pitax_scan |
| CA01 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA02 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA03 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA04 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA05 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA06 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| CA07 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit |
| DS01 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DS02 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DS03 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DS04 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DS05 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DS06 | docs_scan | 3 | 3 | 0 | 3/3 | STABLE | docs_scan |
| DP01 | dep_scan | 3 | 3 | 0 | 3/3 | STABLE | dep_scan |
| DP02 | dep_scan | 3 | 3 | 0 | 3/3 | STABLE | dep_scan |
| DP03 | dep_scan | 3 | 3 | 0 | 3/3 | STABLE | dep_scan |
| DP04 | dep_scan | 3 | 3 | 0 | 3/3 | STABLE | dep_scan |
| DP05 | dep_scan | 3 | 3 | 0 | 3/3 | STABLE | dep_scan |
| DP06 | code_audit | 3 | 3 | 0 | 3/3 | STABLE | code_audit, dep_scan |
| N01 | none | 3 | 3 | 0 | — | STABLE | — |
| N02 | none | 3 | 3 | 0 | — | STABLE | — |
| N03 | none | 3 | 3 | 0 | — | STABLE | — |
| N04 | none | 3 | 2 | 1 | — | UNSTABLE | pitax_scan |
| N05 | none | 3 | 3 | 0 | — | STABLE | — |
| N06 | none | 3 | 3 | 0 | — | STABLE | — |
| N07 | none | 3 | 3 | 0 | — | STABLE | — |
| RH01 | rank_hypotheses | 3 | 3 | 0 | 3/3 | STABLE | rank_hypotheses |
| RH02 | none | 3 | 2 | 1 | — | UNSTABLE | docs_scan |

**UNSTABLE cases (2)：** N04 (2/3)、RH02 (2/3)

## 复核：9 个未归因会话（对原档的修正）

聚合器原档报 `_unattributed sessions in window: 9_` ⇒ 7 例被误标 NOT-RUN（r1: N01/RH02；r3: DP01/DP02/N04/N06），原档 pooled=97/100 + 1/19。

复核方法：窗口内全部 **128 个会话**按精确 prompt（空白归一后逐字相等）匹配 `routing_cases.json`，再用评测器原生 `parse_session` 判分。9 个会话全部唯一命中：

| 会话 | 实为（轮/例） | mtime | 距案例窗 | 被测调用 | 判定 | 备注 |
|---|---|---|---|---:|---|---|
| `5a795e0d` | r1 / RH02 | 11-09 21:33:47 | −4s | docs_scan | **MISS（误调）** | 负例判别器 |
| `f16c09a3` | r1 / N01 | 11-09 21:07:51 | −26s | — | OK | |
| `2e55befa` | r2 / RH02 | 11-11 15:20:35 | −1s | — | OK | |
| `3a403c52` | r3 / DP01 | 11-11 21:44:52 | −68s | dep_scan | OK | |
| `8e35b6f4` | r3 / DP02 | 11-11 21:51:48 | −15s | dep_scan | OK | |
| `e9ed091f` | r3 / N04 | 11-11 22:13:10 | −281s | — | OK | |
| `9fb59221` | r3 / N06 | 11-11 22:24:14 | −289s | — | OK | 日志 `TIMEOUT>360s` |
| `d5c247b9` | 11-09 中止尝试 / DS02 | 11-09 22:38:37 | — | docs_scan | 排除 | 重试覆盖日志的孤儿 |
| `4c643f07` | 11-09 中止尝试 / DS04 | 11-09 22:43:03 | — | docs_scan | 排除 | 次日重跑覆盖日志的孤儿 |

**根因（两族）**：

1. **案例日志缺 `elapsed=` 字段**（驱动侧超时/异常分支）⇒ `case_windows()` 退化为 `[logmtime−5, logmtime+5]` 的 10 秒窗 ⇒ 会话（最后一次事件写入早于日志落盘 1–289s）落在窗外。`n3/logs/r3/N06.log` 正文即 `# TIMEOUT>360s`。
2. **11-09 中止尝试的孤儿**：r2 为混合轮——11-09 夜中止前 24 例（PS01–PS14、CA01–CA07、DS01–DS03）已落日志，11-11 只重跑其余 18 例；两个孤儿是被重试/重跑覆盖日志的首轮会话，**不计入 N=3**。

**修正影响**：DP01/DP02(r3) 补回且都调对（+2 正例）；RH02(r1) 误调 docs_scan（负例误调 1/19 → **2/24**，RH02 转 UNSTABLE）；N01/RH02(r2)/N04/N06 补回（均 0 误调）。

## 聚合器原档（可复现）

- 原档数字：r1 正例 33/34、负例 1/6；r2 33/34、0/7；r3 31/32、0/6；pooled **97/100 (0.970) + 1/19 (0.053)**；UNSTABLE=N04 (1/2)；`_unattributed sessions in window: 9_`。
- 复现：`cd D:\desk-top\copilot-eval-run && python n3_aggregate.py --out n3/summary.md`（2026-11-12 重跑与 `summary-final.md` 逐字节一致，仅 generated 时间戳不同）。
- 判分实现无差异：`evaluate()` 按 prompt 归例，窗口仅用于把会话分到轮次；原档与修正的差异**全部来自归因缺口**。

## 注记

- **PS07**：自解码载荷的路由竞争（模型倾向 shell 自解），三轮一致 miss；与 11-08 description 修法复测的 2/3 自解码残留同族，暂不重复修。
- **N04/RH02**：负例判"任一被测工具调用即 miss"；两者误调均发生在 r1（N04 润色句调 pitax_scan；RH02 总结报告调 docs_scan），r2/r3 均为 0。
- **r2 混合轮**：11-09 中止尝试（期间 Copilot `Response was interrupted due to a server error. Retrying...`）后 11-11 补齐；轮内案例跨两次坐席，但同宿主、同模型、同夹具。
- **PS13**：工具命中 3/3，path 参数合理 2/3（r3 未带 path 参数，不改判）。
- **驱动侧改进候选（未实施，零代码改动）**：`case_windows()` 在日志缺 `elapsed` 时回退为「会话首事件时间 ± 日志 mtime」区间，或驱动在超时分支写显式 `elapsed=`；下次 N 轮跑批前修。
