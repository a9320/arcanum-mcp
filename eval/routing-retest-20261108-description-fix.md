# description 修法复测 2026-11-08（预注册：4 例 ×3 fresh sessions）

> 背景：instructed 轮（`routing-results-20261107-instructed.md`）4 例 miss 的归因修法落地
> （mcp `0d62cd6`：code_audit 明示代码/注释内载荷归我；pitax_scan 补"能自解码也要跑工具"）。
> 本轮=单变量复测：同环境同构，唯一差异=新 description。92 passed 无回归，venv 重装生效。

## 结果：11/12 = 0.917（这 4 例在 instructed 轮为 0/4）

| case | instructed 轮 | 复测 r1 | r2 | r3 | 判定 |
|---|---|---|---|---|---|
| CA03（注释内 base64） | →pitax_scan 互换 | code_audit ✓ | code_audit ✓ | code_audit ✓ | **3/3 STABLE 翻正** |
| CA05（零宽字符注释） | 零调用（自答对但违规） | code_audit ✓ | code_audit ✓ | code_audit ✓ | **3/3 STABLE 翻正** |
| CA06（跨行注释覆盖） | →pitax_scan 互换（两轮持续） | code_audit ✓ | code_audit ✓ | code_audit ✓ | **3/3 STABLE 翻正** |
| PS07（`PAYLOAD = "<base64>"`） | 零调用（shell 自解码） | **零调用（自解码残留）** | code_audit→pitax_scan ✓ | pitax_scan ✓ | 2/3 UNSTABLE |

- **修法判定（预注册 ≥2/3 翻正=有效）：4/4 达标；3 例 STABLE，1 例 UNSTABLE 但净改善。**
- CA06 是隐式→instructed 两轮都没治好的"最顽固"例，description 一行治好且 3/3 稳定。
- PS07 残留 1/3 自解码：政策明文+description 双层下仍出现——**候选结论：该行为两层文本治不干净，
  与外评①同理属权限层问题（宿主须把"安全判断必须走工具"做成硬约束）**；另 r2 先 code_audit 后
  pitax_scan（`PAYLOAD = ...` 形似代码，code_audit 新触发词把它拉了一把，最终仍走到 pitax_scan）。

## 环境注记（如实）

- r1 会话头=`Auto selected GPT-6 Luna`，r2/r3=`Copilot Fusion selected GPT-6 Luna`——
  **宿主模型选择模式中途变化**，为非受控变量；各轮工具调用均已按事件事实计分，跨轮对比带此注记。
- 12 会话全程零 danger、零 path 参数调用、零 unmatched turns；耗时 17–114s/例。

## 口径

- 本轮不并入 Round A/B 对照表（n=3 vs n=1、形态差异），作为 0.3.0 发布前的修法验证独立记账。
- N=3 全量稳定性轮建议放到发版形态冻结后一次跑（此时 description 已定稿，一轮投入两用：k/3 + 发布数据）。
