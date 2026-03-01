## Why

`risk-boundary-manual-one-by-one-2026h1` 已完成 `1..102` 逐篇人工筛选。去重后真正落在 `safe-fs-tools` 边界内的事项只剩 5 个：

- `T01` 对抗语料回归集
- `T02` 高风险操作分层
- `T03` 审计与拒绝原因字段统一
- `T04` secrets 扫描门禁
- `T05` 边界文档与部署基线

当前需要从“参考筛选”进入“工程排期”，避免继续做超边界事项。

## What Changes

新增一个执行型变更包，按 `policy/ops/cli/tests/docs` 直接落地：

1. `T01`：补充对抗语料与回归测试矩阵。
2. `T02`：在 CLI 增加高风险写操作的显式确认档位（默认安全）。
3. `T03`：统一拒绝/失败审计字段与错误原因码映射。
4. `T04`：引入 `pre-commit + CI` secrets 扫描门禁（含 baseline）。
5. `T05`：补齐边界文档，明确“非 OS 沙箱 + 建议外层隔离”。

## Capabilities

### New Capabilities

- `adversarial-regression-suite`：路径越界、编码绕过、secret 读取诱导、提示词越界输入回归。
- `high-risk-confirmation-tier`：高风险写操作确认档位（默认不放开）。
- `audit-reason-schema`：统一 `reason_code/risk_tag/policy_rule` 字段。
- `repo-secret-gate`：提交前与 CI secrets 扫描。

### Modified Capabilities

- `cli-contract`：高风险确认参数与稳定错误输出增强。
- `policy-docs`：边界声明、部署建议、非目标清单更新。

## Impact

预期变更文件范围：

- `tests/`：新增/扩展 T01 对抗回归样例。
- `src/error.rs`
- `src/ops/context.rs`
- `src/ops/write.rs`
- `src/ops/patch.rs`
- `src/ops/delete.rs`
- `src/ops/move_path.rs`
- `src/ops/copy_file.rs`
- `cli/src/main.rs`
- `cli/src/command_exec.rs`
- `cli/src/error.rs`
- `.github/workflows/ci.yml`
- `githooks/pre-commit`
- `docs/security-guide.md`
- `docs/policy-reference.md`
- `docs/operations-reference.md`

## Schedule

绝对日期排期（2026 H1）：

1. `P0`（2026-03-02 ~ 2026-03-13）
- 完成 `T05`（文档边界）与 `T04` 设计评审。
- 产出 secrets 门禁实施方案（工具、基线、失败策略）。

2. `P1`（2026-03-16 ~ 2026-04-03）
- 落地 `T04`：`pre-commit + CI` secrets 扫描。
- 落地 `T01` 第一批回归用例（路径越界、编码绕过、secret deny）。

3. `P2`（2026-04-06 ~ 2026-04-24）
- 落地 `T02`：高风险写操作确认档位（CLI）。
- 落地 `T03`：统一审计字段与错误原因码。

4. `P3`（2026-04-27 ~ 2026-05-15）
- 扩展 `T01` 第二批语料（提示词诱导越界、组合绕过）。
- 跨平台回归（Linux/Windows/macOS）与文档收尾。

## Out of Scope

- OS 内核级沙箱实现（Landlock/容器/虚机）。
- 供应链平台治理、版权治理、组织流程治理。
- 代理/下载/内容分发类业务能力。
