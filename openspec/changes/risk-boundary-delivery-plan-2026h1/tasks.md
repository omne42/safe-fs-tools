## TODO List

### P0 (2026-03-02 ~ 2026-03-13)

- [x] T05: 在 `docs/security-guide.md` 增加“非 OS 沙箱”与部署隔离基线章节。
- [x] T05: 在 `docs/policy-reference.md` 增加“非目标范围”与高风险场景处理边界。
- [x] T04: 选型并确定 secrets 扫描工具与 baseline 策略。
- [x] T04: 定义 CI 失败策略（阻断/告警）和轮换流程。

### P1 (2026-03-16 ~ 2026-04-03)

- [x] T04: 在 `githooks/pre-commit` 集成 secrets 扫描。
- [x] T04: 在 `.github/workflows/ci.yml` 增加 secrets 扫描步骤。
- [x] T01: 新增路径越界与编码绕过对抗样例到 `tests/`。
- [x] T01: 新增 secret deny 诱导读取回归样例到 `tests/secrets.rs` 或 `tests/new_ops.rs`。

### P2 (2026-04-06 ~ 2026-04-24)

- [x] T02: 在 `cli/src/main.rs` 增加高风险操作确认档位参数。
- [x] T02: 在 `cli/src/command_exec.rs` 对写类操作应用确认档位逻辑。
- [x] T03: 在 `src/error.rs` 统一拒绝原因码映射并补测试。
- [x] T03: 在 `src/ops/context.rs` 统一审计字段结构（`reason_code/risk_tag/policy_rule`）。

### P3 (2026-04-27 ~ 2026-05-15)

- [x] T01: 补第二批组合绕过语料与回归测试。
- [x] T02/T03: Linux/Windows/macOS 三平台回归跑通。
- [x] T04: 新增 `trufflehog` 定时二级扫描 workflow（默认 warning-only，可配置阻断）并固定校验和。
- [x] T04: 产出 `secrets-secondary-summary.json` 结构化报告并补 secrets 值班 runbook。
- [x] T04: findings>0 时支持可选自动创建/更新跟踪 issue（可配置开关）。
- [x] T05: 更新 `docs/operations-reference.md` 与 `docs/cli-reference.md` 示例。
- [x] 形成一版发布说明，明确“新增能力 + 兼容性影响 + 非目标项”。
