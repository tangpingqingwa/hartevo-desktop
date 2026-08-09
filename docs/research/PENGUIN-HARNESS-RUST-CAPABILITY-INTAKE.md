# PenguinHarness → Hartevo Rust Harness Lab 能力引入清单

状态：**Accepted**
版本：1.0
日期：2026-08-09
发布基线：`Prism-Shadow/penguin-harness@v0.2.1`（commit `88916880ebc6394e96b7b78106bbf1621b7db6f6`）
代码审查基线：`047505dccc0cc16ad92be11011347d635f33ceb0`（2026-08-07）

## 1. 决策

PenguinHarness 不作为 Hartevo 的第二个 Agent Runtime，也不进入桌面出货依赖。它被纳入为 **Harness Engineering Reference**，重点用于建立 Hartevo 的低成本模型适配、Harness 候选生成、冻结 Benchmark、可追溯评测、版本快照和安全晋升机制。

当前上游分工因此是：

| 来源 | 在 Hartevo 中的定位 |
| --- | --- |
| OpenInterpreter | Rust Agent Runtime、Provider/Model/Harness、工具、沙箱与 App Server 主基座 |
| Hermes Agent | 长期 Agent、桌面体验、自治可靠性和跨系统能力参考 |
| PenguinHarness | Harness Lab、极简工具面、Trace/Eval、候选优化与版本晋升参考 |
| Hartevo Domain Kernel | Project、Mission、Truth、Consent、Effect、Outcome 的唯一事实源 |

所有落地实现保持 Rust + Dioxus。PenguinHarness 的 TypeScript Core、Hono Server、React Web、Electron Desktop 和 Node runtime 不进入 Hartevo 产品。

## 2. 审查事实

PenguinHarness v0.2.1 是 Apache-2.0 项目，当前是 TypeScript/pnpm monorepo，主要包包括 `core`、`server`、`web`、`desktop`、`cli`、`skills` 和 `docs`。

在固定的主分支审查 commit 上：

- 代码主体是 TypeScript，审查到 605 个 TS/TSX 文件。
- 审查到 177 个 test/spec 文件；该 commit 的 Linux 与 Windows CI 均通过。
- `core` 以 Human / LLM / Environment 三边界组织 ReAct loop。
- `OmniMessage` 同时承担运行时消息、流式协议和 append-only Trace 格式。
- 运行时支持并发 Tool execution、按原 Tool call 顺序回送结果、mid-run steering、interrupt carry-over、重连、压缩、Subagent 和 per-tool approval。
- Agent 的 Prompt、Skill、Runtime 配置、Benchmark 和 Snapshot 都以可编辑文件保存；Trace 是恢复的事实源。
- Self-Improvement 通过 Skills 编排 Builder、Target Agent、Evaluator 与 Optimizer，执行 Benchmark Freeze、Formal Baseline、候选编辑、评测、快照和回滚。
- v0.2.1 Desktop 是 Electron 薄壳，复用 Hono Server 与 React Web，不适合直接进入 Rust Desktop。

其 README 宣称在特定数据分析与代码任务上以显著更低成本达到很高质量，但公开 Roadmap 仍把“发布 Benchmark Suite”列为未完成项。因此这些数字只能视为待复现实验主张，不能直接成为 Hartevo 的模型或基座选型证据。

## 3. 最值得吸收的工程机制

### 3.1 极简、稳定的模型工具面

PenguinHarness 用少量低层工具和统一的 Environment framing 降低开放模型调用负担。单个 Tool 实现只负责输出内容；超时、截断、错误转消息、最终 complete output、恢复文件和协议闭合由框架统一处理。

Hartevo 应将这一原则用于 `HarnessProfile`：面向某个模型暴露最小、稳定、能完成 Mission 的工具 schema，而不是把全部 MCP/Connector 能力塞给模型。

### 3.2 三接口边界

Human、LLM、Environment 的分离有助于把模型适配与工具执行从 Loop 中拿出去。Hartevo 不复制其 ContextEngine，但应保持对应边界：

- Dioxus/Application 是 User Intent 与 Steering 边界。
- OpenInterpreter Runtime Adapter 是 LLM/Harness 边界。
- Capability Gateway 与 Effect Broker 是 Environment/External Effect 边界。

### 3.3 流式消息与错误收敛

其 `start → delta → stop → complete` discipline、六类 stop reason、Tool call/output 配对、错误不抛入 Loop、并发执行但有序回送等机制值得纳入 Hartevo Runtime Event Contract。

但 Hartevo 不新增 OmniMessage 作为第二 wire protocol：Runtime 层使用固定的 OpenInterpreter App Server schema，产品层使用 Hartevo-owned Domain Event。需要的只是明确的 Adapter 投影与契约测试。

### 3.4 Trace、恢复与可观测性

Append-only Trace、Session replay、Subagent pointer、Token/Cost、Compaction 和 Approval event 对 Harness 调试很有价值。Hartevo 应把它提升为统一 Product Trace：既包含 Runtime item，也包含 Mission、Evidence、Effect、Receipt、Verification 和 Outcome。

### 3.5 Benchmark 驱动的自我改进

PenguinHarness 最有差异化的部分是闭环：

```text
需求
→ Agent/Harness 初始版本
→ 设计并冻结 Benchmark
→ Formal Baseline
→ 从失败 Trace 生成有界 Candidate
→ 多 Case / 多 Run 评测
→ 只保留更优版本
→ Snapshot / Rollback
```

Hartevo 应将其重构为 Harness Candidate Lab，候选可以修改：

- System instructions 与 Growth Harness prompt。
- Tool description、schema、可见工具集合与调用约束。
- Context assembly、Evidence policy 和模型/Provider/Harness 路由。
- Skill、Planner preset 与恢复策略。

候选不得修改 Mission Fixture、私有 Rubric、确定性 Oracle、零容忍安全规则或生产凭据。

## 4. Rust 能力引入矩阵

| PenguinHarness 机制 | Hartevo Rust 归属 | 决策 | 阶段 |
| --- | --- | --- | --- |
| Minimal tool surface | `runtime-adapter/harness-profile` | 按 Model × Mission 生成最小 Tool/Capability schema | H0 |
| Human / LLM / Environment boundary | `application` / `runtime-adapter` / `capability-gateway` | 采用边界，不复制 ContextEngine | H0 |
| Streaming discipline | `protocol/runtime-event` | 建立 start/delta/stop/complete、pairing 和 terminal reason 契约 | H0 |
| Error convergence | `runtime-adapter` + `capability-gateway` | 所有失败转 typed event；恢复策略由错误类别决定 | H0 |
| Append-only Trace | `storage/product-trace` | 扩展为 Runtime + Domain + Effect 统一追踪 | H0 |
| Frozen Benchmark revision | `eval/benchmark-registry` | Case/Fixture/Rubric/Oracle 全部 digest 固定 | H0 |
| Private rubric isolation | `eval/runner` | Target、Optimizer 不可读取私有标准 | H0 |
| Agent State snapshot | `eval/candidate-registry` | 打包 Harness/Prompt/Skill/Config，不包含 Secret | H0 |
| Goal loop | `application/mission-runner` | 吸收多轮持续、预算和恢复；完成由业务 Oracle 判定 | H1 |
| Mid-run steering | `application` + `runtime-adapter` | 与 Hermes redirect 统一成 Mission Steering Command | H1 |
| Concurrent tools + ordered feedback | `capability-gateway` | 仅并行无依赖的 Read/Compute；Effect 仍按策略串行或幂等 | H1 |
| Background command/subagent session | `runtime-adapter` + `application/worker` | 持久化 Worker lease、事件和恢复，不依赖父上下文存活 | H1 |
| Trace browser / evaluation center | `ui/eval-console` | 展示失败 Case、状态 Diff、成本、证据与候选对比 | H1 |
| Builder / Evaluator / Optimizer roles | `eval/harness-lab` | 使用独立身份、上下文、权限和数据可见性 | H2 |
| Candidate strict-improvement loop | `eval/promotion-engine` | 改为质量、安全、成本、延迟与稳定性的多约束晋升 | H2 |
| One-sentence Agent Builder | `application/specialist-builder` | 从 Mission 生成临时 Specialist/Harness 草案，经 Eval 后启用 | H3 |

## 5. 必须修正后再吸收的部分

### 5.1 模型不能声明业务完成

Penguin Goal Mode 让模型写 `GOAL.yaml status=complete|blocked`。这种控制信道适合防止模型安静退出，但不能证明增长业务完成。

Hartevo 可保留“显式终止声明 + budget + round cap”，最终状态必须由以下组合决定：

- Domain State 与 Checkpoint。
- Work Product 验收。
- Effect Receipt 与 Verification。
- Outcome/Attribution。
- 用户确认或确定性业务 Oracle。

### 5.2 Score 必须由系统复算

Penguin 文档明确说明 Scoreboard 聚合值由模型写入，Server 不复算；其首个 Candidate 的多 Run 平均还会与单 Run Formal Baseline 直接比较。Hartevo 不采用这两个合同。

Hartevo 要求：

- 同一 Run matrix、Seed policy、Provider mode 与预算比较 Baseline/Candidate。
- 确定性与可复算指标由 Rust Result Engine 计算。
- Judge 只返回受限维度评价，不能自行写最终分数。
- 样本不足时结果是 `INCONCLUSIVE`，不能因为均值略高就晋升。
- 晋升同时满足质量非劣、安全零回退、成本/延迟预算和稳定性门槛。

### 5.3 自我修改必须进入候选隔离区

Optimizer 不得直接编辑当前生产 Agent/Harness。所有改变先进入 immutable Candidate Bundle，在临时 Workspace 和模拟 Provider 中执行；通过 Gate 后由 Promotion Engine 签名晋升，保留立即回滚版本。

### 5.4 文件不是业务数据库

可编辑 Agent State、Skill 和 Trace 使用文件很透明，但 Hartevo Project 的 Truth、CRM、Consent、Effect 和 Outcome 继续由 typed SQLite/Event Store 管理。文件只适合 Prompt、Skill、Harness manifest、Fixture、Artifact 和可导出快照。

### 5.5 Secret 不进入项目配置

Penguin 使用权限为 0600 的 TOML 保存 Vault 与模型凭据。Hartevo 仍使用 OS keyring 和不透明 Credential Reference；尤其在 Windows 上不能把 POSIX mode 视为充分保护。

### 5.6 自动重试必须按 Effect Class

Penguin Runtime 会对多类 LLM failure 自动重连。Hartevo 可以对无副作用的模型请求和读取安全重试，但不能自动重试不确定的发布、触达、花费、付款或 CRM 写入。

## 6. Hartevo Harness Candidate Lab

建议在 `hartevo-rs/eval` 内建立以下核心对象：

```text
HarnessProfile
BenchmarkSuite
BenchmarkRevision
FrozenCase
RunMatrix
CandidateBundle
EvaluationRun
EvaluationAggregate
PromotionDecision
RollbackPointer
```

标准流程：

1. 将 Mission Catalog、World Fixture、Rubric 与 Oracle 冻结为 `BenchmarkRevision`。
2. 使用一致的 Run matrix 建立正式 Baseline，不用一张成功截图或单次 Run。
3. Optimizer 读取最小化失败 Trace，但不可见私有 Rubric 和 holdout Case。
4. 生成有界 `CandidateBundle`，列出变更假设、影响文件、预计收益和风险。
5. Target 在隔离 Workspace 运行；Evaluator 只能产生原始观察、受限 Judge 维度和 Trace link。
6. Rust Result Engine 复算指标并形成 `EvaluationAggregate`。
7. Promotion Engine 应用质量、安全、成本、延迟和稳定性 Gate。
8. 通过的 Candidate 先进入 canary catalog，再成为默认 Harness；失败则保留证据并回滚。

这使“低成本开源模型接近强模型”从宣传语变成每个 Hartevo Mission 都能复算的版本化事实。

## 7. 与现有质量合同的关系

PenguinHarness 的 Benchmark 是 Agent/Harness 层测试，不替代 Hartevo Vertical Mission Harness。正确嵌套关系是：

```text
Penguin-inspired Candidate Lab
  └─ 生成并比较 Harness / Prompt / Skill / Route 候选
      └─ Hartevo Mission Harness
          └─ 在版本化业务世界中判定 Work Product、Effect 与 Outcome
```

工具调用率、通用 coding 分数或 Agent 自评不能替代 MGCR、VBOR、LCR、Effect Safety 和 Outcome 指标。

## 8. 许可证与来源

PenguinHarness 采用 Apache-2.0。Hartevo 默认根据公开协议和机制独立实现 Rust 版本。若选择性移植具体源码或算法，必须：

- 固定来源 commit 与文件路径。
- 保留 Apache-2.0 LICENSE、适用版权与相关 notices。
- 记录 Rust 落地文件、修改说明和测试。
- 审查其第三方依赖来源；不能把 Penguin 发布包中捆绑的 Node/MinGit 等二进制视为 Hartevo 依赖。

禁止整体机械翻译 TypeScript monorepo，或同时运行 Penguin Server 与 OpenInterpreter App Server。

## 9. 主要依据

- [PenguinHarness repository](https://github.com/Prism-Shadow/penguin-harness)
- [v0.2.1 release](https://github.com/Prism-Shadow/penguin-harness/releases/tag/v0.2.1)
- [Architecture](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/architecture.en.md)
- [Agent loop](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/agent-loop.en.md)
- [Core interfaces](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/interfaces.en.md)
- [OmniMessage](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/omni-message.en.md)
- [Sessions and traces](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/sessions-and-traces.en.md)
- [Goal mode](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/goal-mode.en.md)
- [Self-improvement](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/self-improvement.en.md)
- [Skills](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/packages/docs/content/skills.en.md)
- [Apache-2.0 License](https://github.com/Prism-Shadow/penguin-harness/blob/v0.2.1/LICENSE)
