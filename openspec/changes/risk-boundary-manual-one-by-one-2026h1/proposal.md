## Why

本提案用于记录 `wsl-docs/05-references/safe-fs-tools/02-资源/风险边界与合规` 的逐篇人工筛选结果。

约束：
- 从第 1 篇开始，逐篇读取。
- 每看完一篇立即在本文件追加记录（不在临时文件）。
- 仅保留对 `safe-fs-tools` 真正可落地且合规的事项。
- 边界判定：必须能直接落在 `policy/ops/cli/tests/docs`，内容版权治理、外部供应链平台治理等超边界事项不纳入。

## What Changes

- 形成“去重后的真正要做事项池”。
- 在本文件中清除所有“跳过/不纳入/阻塞”项目，仅保留需处理项目清单（`8/102`，已清除 `94` 条）。

## Capabilities

### New Capabilities

- `manual-one-by-one-review-log`: 逐篇人工记录与可追溯筛选日志。

### Modified Capabilities

- 暂无（待逐篇记录完成后再归纳）。

## Impact

- 输出文件：`safe-fs-tools/openspec/changes/risk-boundary-manual-one-by-one-2026h1/proposal.md`

## safe-fs-tools 真实边界基线（先验）

以下边界来自仓库实证，后续逐篇记录必须以此为硬约束：

- 这是“进程内策略层”，不是 OS 沙箱：`safe-fs-tools/SECURITY.md`。
- 已有能力边界是文件系统操作与策略校验：`safe-fs-tools/src/lib.rs`、`safe-fs-tools/src/policy.rs`、`safe-fs-tools/src/ops/`。
- CLI 已存在且按策略执行，不是缺 CLI：`safe-fs-tools/cli/src/main.rs`、`safe-fs-tools/cli/src/command_exec.rs`。
- 真实可落地点限定为：
  - `policy`：root/mode/permissions/limits/secrets/traversal/paths。
  - `ops`：路径解析、越界拒绝、写操作前置校验、限额执行。
  - `cli`：参数约束、错误码/错误脱敏、输入大小上限与 no-follow 读取。
  - `tests`：权限、越界、平台差异、限额、秘密规则回归。
  - `docs`：威胁模型、部署建议、非目标声明。
- 明确不纳入：
  - 内容版权/平台运营治理（不属于文件系统策略实现层）。
  - 网络可达性/镜像运维流程（除非直接影响本仓库 policy/ops/cli）。
  - “语义内容审查”类需求（超出当前仓库职责）。

## 去重后的真正要做事项（持续更新）

| 事项ID | 真正要做的事 |
|---|---|
| T01 | 建立对抗语料回归集（路径越权、编码绕过、敏感读取、提示词诱导越界）。 |
| T02 | 建立高风险操作分层（默认只读、显式授权、必要时人工确认）。 |
| T03 | 统一审计与拒绝原因字段（命中规则、拒绝原因码、风险标签）。 |
| T04 | 仓库机密扫描门禁（pre-commit + CI，含 baseline 与轮换流程）。 |
| T05 | 文档边界规范化（高风险仅说明边界）+ 部署隔离基线（明确非 OS 沙箱）。 |

## 逐篇人工记录（清理后：仅保留需处理项目）

记录原则：
- 从第 1 篇重新开始。
- 每篇必须包含真实仓库证据（至少到具体文件/机制），不是只看 README 的泛化结论。
- 只记录可落在 `safe-fs-tools` 的 `policy/ops/cli/tests/docs` 范围。
- 所有“跳过/不纳入/阻塞”条目已从当前清单移除。

| 序号 | 参考仓库 | 真实仓库证据（文件/实现） | 结论 | 映射事项ID（去重） | 落地到 safe-fs-tools |
|---|---|---|---|---|---|
| 1 | Awesome-Hacking | `wsl-docs/.tmp/repos/Awesome-Hacking/README.md` 提供可复用的安全语料分类入口（含 `SecLists`、`PayloadsAllTheThings`）；其余为列表维护流程。 | 部分保留 | T01 | 仅用于 `tests/` 的防御性负例语料分类，不引入其他治理项。 |
| 2 | BiliTools | `wsl-docs/.tmp/repos/BiliTools/src-tauri/capabilities/default.json` 的权限白名单机制；`src-tauri/src/storage/config.rs` 的键级写入白名单。两点都可直接映射到“操作前置校验”。 | 部分保留 | T02,T03 | `policy/ops` 只吸收“默认拒绝+显式放行+结构化拒绝原因”；不吸收其业务层流程。 |
| 5 | ClashMetaForAndroid | `.github/workflows/build-pre-release.yaml` 与 `build-release.yaml` 将 `signing.properties` 写入后直接 `cat` 到日志，这是可直接转化为 `safe-fs-tools` CI 风险用例的反例。其 Android 组件实现本身超边界。 | 部分保留 | T04 | 仅纳入 `ops/CI` 的“日志敏感字段泄漏”检测与 secret-scan 门禁；其余不纳入。 |
| 19 | L1B3RT4S | `wsl-docs/.tmp/repos/L1B3RT4S/*.mkd` 提供大量越狱/诱导提示样本。仅有一项可迁移价值：作为“提示词诱导越界”的负向测试语料来源。 | 部分保留 | T01 | 仅用于 `tests/` 构建 prompt-induced 越界回归样本；不引入其业务语义和原始模板到产品文档。 |
| 29 | PayloadsAllTheThings | `wsl-docs/.tmp/repos/PayloadsAllTheThings/README.md` 与章节目录（如 `Directory Traversal/`、`Encoding Transformations/`、`Prompt Injection/`）可直接作为防御性负例语料来源。 | 部分保留 | T01 | 仅纳入 `tests/` 的越界/绕过输入回归语料，不引入攻击执行步骤。 |
| 33 | SecLists | `wsl-docs/.tmp/repos/SecLists/README.md` 与分类目录（`Payloads/`、`Pattern-Matching/`、`Passwords/`、`Fuzzing/`）可直接作为防御性词表语料。 | 部分保留 | T01 | 仅用于 `tests/` 的越界/敏感命中回归语料与拒绝路径验证。 |
| 62 | gitleaks（Git 凭据与敏感信息扫描工具） | 已逐篇读取参考文档；已完整 clone 实仓 `wsl-docs/.tmp/repos/gitleaks`（`HEAD=8d1f98c`）。`cmd/root.go` 与 `cmd/git.go` 提供 `git/dir/stdin` 扫描入口、`--baseline-path`、`--report-format sarif/json` 等能力；`detect/detect.go` 实现规则匹配与 `.gitleaksignore` 处理；`report/sarif.go` 提供审计格式输出；`.pre-commit-hooks.yaml` 与 `.github/workflows/gitleaks.yml` 给出提交前和 CI 集成方式。对照 `safe-fs-tools/.github/workflows/ci.yml` 与 `safe-fs-tools/githooks/pre-commit`，当前仓库尚未建立同类 secrets 扫描门禁。 | 部分保留 | T04 | 仅纳入 `ops/CI` 的“机密扫描门禁（pre-commit + CI + baseline）”；不引入其与文件策略无关的其他发布能力。 |
| 94 | trufflehog（机密泄漏检测工具） | 已逐篇读取参考文档；对应实仓 `wsl-docs/.tmp/repos/trufflehog`（`HEAD=041f07e`）。`README.md` 明确其核心是 secrets 发现/分类/验证；`.pre-commit-hooks.yaml` 提供提交前扫描入口；`.github/workflows/secrets.yml` 展示 PR/主分支 secrets 扫描门禁（`--results=verified`）；`pkg/detectors/*` 为多类型凭据检测实现。对照 `safe-fs-tools/.github/workflows/ci.yml` 与 `safe-fs-tools/githooks/pre-commit`，本仓库仍缺统一 secrets 门禁。 | 部分保留 | T04 | 与序号62（gitleaks）同一事项池去重：保留“pre-commit + CI + baseline/轮换”的仓库机密扫描门禁，不引入其与文件策略无关能力。 |
