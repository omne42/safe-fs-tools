## Why

`wsl-docs/05-references/safe-fs-tools/reference.md` 汇总了大量候选能力，但 `safe-fs-tools` 当前真实实现已经覆盖了其中一大批基础项（root 边界、权限闸门、deny/redaction、limits、跨平台路径校验、稳定错误码、较完整测试矩阵）。

真正仍阻塞 Agent 生产接入的，不是“再加一层概念”，而是以下可执行缺口：

1. 缺少可落盘、可回放的决策审计链（当前只有错误和结果，没有统一 `decision_trace`）。
2. 高风险写操作缺少标准化 `preflight/dry-run` 与确认机制。
3. 并发改写缺少 CAS/版本前置条件，存在静默覆盖风险。
4. 缺少官方 Agent 策略档位与模板，导致接入方重复造策略轮子。
5. 错误契约虽有 `error.code`，但缺少“可重试性/修复建议”层，自动恢复能力不足。

同时需要严格遵守当前仓库安全边界：这是进程内策略层，不是 OS sandbox（见 `safe-fs-tools/SECURITY.md`）。

## What Changes

本变更聚焦“2026H1 真正要做”的 5 个能力包，并按阶段排期交付：

1. 审计与可解释性最小闭环（decision trace + append-only audit）。
2. 高风险写操作双阶段流程（preflight -> execute）。
3. 并发改写防丢失（`expected_version` / `conflict`）。
4. Agent 官方策略模板化（只读/受限写入/高风险升级）。
5. 机器可恢复错误契约增强（subcode + retryable + remediation）。

不在本期内引入与仓库定位不匹配的重型机制（如组织级身份信任链、供应链争议处置流、OS 级隔离实现）。

## Capabilities

### New Capabilities

- `decision-trace-audit`: 每次操作生成结构化决策记录；支持可选 append-only 审计落盘（JSONL）。
- `mutating-op-preflight`: 为 `write/patch/delete/move/copy_file` 提供 `preflight`/`dry-run` 结果与风险摘要。
- `optimistic-concurrency-guard`: 为写类操作引入 `expected_version`，冲突返回稳定 `conflict` 错误。
- `agent-policy-profiles`: 提供官方三档策略模板与示例（只读审查、受限写入、高风险升级）。
- `error-contract-v2`: 在现有 `error.code` 之上补充 `subcode`、`retryable`、`remediation`。

### Modified Capabilities

- `policy-schema`: 增加审计、preflight、profile 相关配置项（保持默认向后兼容）。
- `filesystem-operations`: 写类操作支持 preflight 输出与可选 CAS 前置条件。
- `cli-contract`: 新增 preflight 入口与错误结构字段（保持旧字段可用）。
- `docs-and-examples`: 新增 Agent 接入模板、最小权限示例与迁移说明。

## Impact

主要影响模块：

- `safe-fs-tools/src/policy.rs`
- `safe-fs-tools/src/ops/context.rs`
- `safe-fs-tools/src/ops/write.rs`
- `safe-fs-tools/src/ops/patch.rs`
- `safe-fs-tools/src/ops/delete.rs`
- `safe-fs-tools/src/ops/move_path.rs`
- `safe-fs-tools/src/ops/copy_file.rs`
- `safe-fs-tools/cli/src/main.rs`
- `safe-fs-tools/cli/src/command_exec.rs`
- `safe-fs-tools/cli/src/error.rs`
- `safe-fs-tools/docs/policy-reference.md`
- `safe-fs-tools/docs/operations-reference.md`
- `safe-fs-tools/docs/cli-reference.md`

排期（绝对日期）：

1. `P0`（2026-03-02 ~ 2026-03-27）
   - `decision-trace-audit` 最小可用版
   - `agent-policy-profiles`（模板 + 文档 + 示例策略文件）
   - `error-contract-v2` 第一版（subcode/retryable）
2. `P1`（2026-03-30 ~ 2026-04-24）
   - `mutating-op-preflight`（库 + CLI）
   - 写类操作统一风险摘要输出
3. `P1`（2026-04-27 ~ 2026-05-22）
   - `optimistic-concurrency-guard`（`write/patch/delete`）
   - `conflict` 错误码与回归测试
4. `P2`（2026-05-25 ~ 2026-06-19）
   - `move/copy_file` 并发语义补齐
   - 集成文档、迁移指南、压测与回归补完

本期非目标（明确不排期）：

- 组织级 `human_root_id/trust_chain_id` 身份链路体系
- 供应链争议响应流程、SBOM 合规编排
- OS 内核级隔离能力（Landlock/MicroVM 等）在本仓库内实现
- 跨 root move/copy 的新语义扩展（保持当前单 root 约束）
