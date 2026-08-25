# Prime Agent → Hartevo Rust Context Fabric 能力引入清单

状态：**Accepted**
版本：1.0
日期：2026-08-10
稳定发布审查基线：`PrimeIntellect-ai/prime-agent@v0.7.1`（commit `95afd319a78ae017a41241d50b013d656a0685ce`）
代码审查基线：`PrimeIntellect-ai/prime-agent@a18809e00ea30638584d87b3afea7285a9d7296c`

## 1. 决策

Prime Agent 此前没有进入 Hartevo Desktop 的正式文档、架构所有权或实施清单。本次把它纳入为 **Context Fabric / Long-Horizon Runtime Reference**。

它不成为第二个 Agent Runtime，不取代 Rust OpenInterpreter，不把 TypeScript/Node、Python/IPython、Prime Agent daemon 或 TUI 带入 Hartevo 出货产品。Hartevo 吸收的是以下架构机制，并在 Hartevo-owned Rust crates 中重新建模：

- 把大上下文从单一 Prompt 外置成持久工作状态；
- 为子任务生成最小、可审计的 Context Capsule，而不是复制完整历史；
- 用可恢复 Worker Graph 承载并行、后台和跨日工作；
- 通过 append-only 轨迹、结构化压缩和 Continuation Ledger 恢复任务；
- 把可复用经验作为受控 Harness Candidate，而不是让生产 Agent 自改写；
- 使用有界队列、租约、代际和快照实现 detach / reattach / recovery。

本次结论是：**值得吸收，而且应成为 Hartevo 长周期 Mission 的核心基础设施之一；但必须以 Project、Mission、Truth、Consent、Effect 和 Outcome 为上层事实，而不是把 Prime Agent Session 或 Python namespace 提升为产品主状态。**

## 2. 它与现有参考源的关系

| 参考源 | Hartevo 中的唯一位置 |
| --- | --- |
| OpenInterpreter | 主 Agent Runtime、Provider / Model / Harness、工具、沙箱和 App Server |
| Hermes Agent | 长期 Agent 体验、redirect、调度、恢复、消息与自治可靠性 |
| PenguinHarness | Harness Candidate Lab、Trace、冻结 Benchmark、评测与安全晋升 |
| Ego Lite | Browser Workspace、登录复用、语义自动化与人机控制权交接 |
| Prime Agent | 外置上下文、持久工作集、Context Branch、Worker Graph 与长任务连续性 |
| Hartevo | Project / Mission / Truth / Consent / Effect / Receipt / Verification / Outcome 的唯一领域事实源 |

重叠能力必须合并：

- Prime Agent goal、heartbeat、schedule 和 autonomous mode 归入 Hermes-inspired Mission Scheduler，不建立第二调度器。
- Prime Agent Continual Harness 归入 Penguin-inspired Candidate Lab，不建立可直接修改生产 Harness 的旁路。
- Prime Agent child session 归入 Hartevo Worker Registry，不变成新的 Mission、Project 或用户会话。
- Prime Agent compaction 与 Hermes micro-compaction 统一为 Context Fabric 的分层压缩合同。

## 3. 已核验的上游事实

### 3.1 工程与许可证

- 项目是基于 `pi-mono` 的 TypeScript/Node monorepo，主要包包括 `agent`、`ai`、`coding-agent` 和 `tui`，另有 Python `prime-agent-runtime`。
- 审查 commit 约有 912 个 TypeScript/TSX 文件、23 个 Python 文件和 419 个测试文件；这些数量只描述审查范围，不代表 Hartevo 完成度。
- 最新稳定 Release 为 `v0.7.1`；当前 `main` 审查 commit 晚于该 Release，新增内容必须继续按固定 commit 审查。
- 项目使用 MIT License。Hartevo 默认根据公开机制独立实现 Rust 版本；若未来选择性移植具体源码，必须固定文件与 commit，并保留版权和许可证通知。

### 3.2 运行架构

Prime Agent 把交互客户端、daemon supervisor、session worker、AgentSession、IPython kernel、Provider 和 JSONL session storage 分开：

```text
TUI / Headless Client
  ↕ versioned local protocol
Daemon Supervisor
  ├─ Catalog Process
  └─ Session Worker
       ├─ Root AgentSession
       ├─ Scheduler
       ├─ Persistent IPython Kernel
       └─ Retained Child AgentSessions
```

- 客户端可以退出，resident worker 继续运行；恢复时用 generation、sequence cursor 和 snapshot 重建视图。
- 每个持久 Session 通过文件路径 lease 防止并发写同一 JSONL。
- mutating command 使用 `clientId + commandId` 和 append-only journal；不确定副作用不会自动重放。
- snapshot、replay、attachment backpressure 和 worker crash recovery 都有明确边界。
- worker 与 kernel 的进程隔离只用于生命周期和故障收敛，**不是安全沙箱**。

### 3.3 RLM 与持久工作状态

Prime Agent 默认向模型提供持久 IPython 环境，模型把 Prompt、文件结果、解析对象、函数、导入和子代理句柄保存在变量中。`rlm(...)` 通过 typed host request 请求 TypeScript Host 建立 child AgentSession：

- Parent 当前窗口只保留调度所需信息；大量材料留在外部工作状态或文件中。
- Child 只接收它所需的局部 Prompt，拥有独立上下文和 Session 目录。
- spawn 返回 admission handle，不等待答案；结果通过显式 agent message 或文件回流。
- Parent-scoped child registry 可跨 compaction、kernel restart 和 parent restore 保存。
- child usage 会独立核算，并回写 parent assistant turn 的归因记录。

Python 只是模型面对的控制环境；Provider 调用、Agent Loop、child 生命周期、usage 与 authoritative state 仍由 TypeScript Host 控制。这个“模型可编程、Host 掌握事实和权限”的边界值得吸收。

### 3.4 压缩、分支与 Session 轨迹

Prime Agent 的 JSONL Session 使用 `id / parentId` 形成树。自动 compaction 在上下文接近阈值时：

1. 保留最近工作窗口；
2. 将更早轨迹生成结构化摘要；
3. 记录 `firstKeptEntryId`、压缩前 Token 和文件操作；
4. append 新 compaction entry，不覆盖原始历史；
5. 恢复时使用摘要加未压缩尾部重建模型上下文。

离开分支时可以生成 branch summary，把被放弃分支的关键结果带到新分支。其默认摘要结构包含 Goal、Constraints、Progress、Key Decisions、Next Steps、Critical Context 和文件清单。

这比“不断把全部聊天塞回模型”更有长上下文潜力，但默认 LLM 摘要仍可能丢失事实、证据关系和领域不变量，不能直接成为 Hartevo 的 Truth 或业务恢复合同。

### 3.5 Continual Harness

Prime Agent 将 supplemental prompt、memory、skill description 和 subagent specification 保存为 session-local 或 global harness state。`/refine` 独立回顾轨迹，生成小范围 create / update / delete proposal，记录 evidence、before / after snapshot 和 refinement history，并支持 rollback；immutable base system prompt 不被改写。

这是可审阅的在线经验沉淀机制，但其 Host 可以直接应用 proposal。Hartevo 不能允许生产 Agent 根据当前轨迹直接改变自己的生产 Prompt、Skill、权限或 Gate。

### 3.6 长周期机制

Prime Agent 将以下能力放在同一 Session Worker 内：

- persistent goal；
- heartbeat 与 schedule；
- bounded autonomous continuation；
- direct agent-to-agent message；
- retained subagent；
- daemon detach / reattach；
- kernel namespace snapshot；
- automatic compaction。

这些机制共同带来长上下文潜力。它不是“模型获得无限 Token”，而是**模型窗口变小、外部状态变强、任务可以分支并恢复**。

## 4. Hartevo 目标架构：Rust Context Fabric

### 4.1 五层上下文

```text
L0 Active Model Window
   当前目标、最近事件、必要工具结果和下一步

L1 Typed Working Set
   结构化变量、查询结果、候选对象、草稿引用和局部计划

L2 Mission Continuation Ledger
   Goal、Constraint、Decision、Task、Pending Effect、Checkpoint、Outcome

L3 Context Branch / Worker Graph
   每个并行任务的最小 Context Capsule、状态、产物和回流合同

L4 Project Truth & Durable Memory
   有来源、版本、权限、时效和删除语义的长期事实与经验候选
```

模型上下文只是 L0 投影。L1–L4 均由 Hartevo Rust Domain / Application / Storage 拥有，并能在更换模型、Provider、OpenInterpreter Thread、进程或设备后重建。

### 4.2 核心对象

| 对象 | 必须包含 | 所有权 |
| --- | --- | --- |
| `ContextWorkspace` | project、mission、generation、budget、policy | `application/context-fabric` |
| `WorkingSet` | typed values、artifact refs、TTL、provenance | `storage/context-store` |
| `ContextCapsule` | child goal、required facts、constraints、capabilities、budget、return contract | `application/context-fabric` |
| `ContextBranch` | parent、fork reason、scope、status、merge policy | `application/worker-registry` |
| `WorkerHandle` | worker id、lease、generation、runtime mapping、usage | `application/worker-registry` |
| `ContextCheckpoint` | durable state revision、open work、pending effects、resume cursor | `storage/checkpoint` |
| `CompactionRecord` | source range、summary、retained invariants、provenance、model/config | `storage/context-store` |
| `ContinuationLedger` | goal、constraints、decisions、tasks、blockers、next actions | `domain/mission` |
| `HarnessCandidateState` | proposal、evidence、benchmark revision、risk、rollback | `eval/harness-lab` |
| `ContextBudget` | tokens、cost、latency、branch/depth limits、PII policy | `application/context-fabric` |

### 4.3 Context Capsule 合同

每个 Worker 只获得完成局部任务必需的 Capsule：

```text
Identity: tenant / project / mission / task / worker generation
Goal: 一个可判定的局部目标
Facts: 有版本和来源的必要事实引用
Constraints: 市场、语言、受众、预算、禁用动作、审批策略
Capabilities: parent authority 的严格子集
Budget: token / cost / time / depth / concurrency
Inputs: Work Product、Evidence、文件和查询快照引用
Return: typed result、evidence、uncertainty、artifacts、next recommendation
```

Child 不继承 parent 的完整 Prompt、Secret、Connection、Browser Profile 或 Effect 权限。它的 authority 永远不能超过 parent 与当前 Mission Scope 的交集。

### 4.4 Typed Host Bridge

Prime Agent 用 Python function → typed host request 把状态和权限留在 Host。Hartevo 应采用相同思想，但用 Rust typed capability：

- 模型只能调用版本化 Capability Schema；
- `ContextWorkspace`、Goal、Effect、Approval、Worker Registry 和 Credential 均由 Rust Host 权威管理；
- 需要低往返时，允许受限的 typed action plan 或 WASM component，不执行模型生成的任意 Python、Node 或 shell program；
- 所有 Host response 都携带 project、mission、generation、provenance 和 policy decision。

### 4.5 Worker Graph，不是 Session 产品模型

Prime Agent 的 retained subagent 对 Hartevo 很有价值，但产品层应这样映射：

```text
Mission
  ├─ Task A → Worker generation 3 → Runtime Thread x
  ├─ Task B → Worker generation 1 → Runtime Thread y
  └─ Task C → Browser / Connector worker
```

用户看到 Mission、任务、进度、证据和产物；不会学习 RLM、IPython、child session 或 kernel。总调度可展示“3 个任务并行”“竞品证据已回流”“达人筛选等待连接”，并允许定向调整、暂停或重新分配。

## 5. Rust 能力引入矩阵

| Prime Agent 机制 | Hartevo Rust 归属 | 决策 | 阶段 |
| --- | --- | --- | --- |
| Prompt-as-variable | `context-fabric/working-set` | 改为 typed Working Set，不依赖 Python namespace | C0 |
| Persistent REPL state | `context-store` | 只保存可验证 typed value、artifact ref 与 checkpoint | C0 |
| Automatic compaction | `context-fabric/assembler` | 采用 append-only、可回放、保留不变量的分层压缩 | C0 |
| Session tree / branch summary | `context-fabric/branch` | 采用 Context Branch 与显式 merge/abandon record | C1 |
| RLM child agent | `worker-registry` + `runtime-adapter` | 采用有界 Worker Graph 与 Context Capsule | C1 |
| Parent-scoped child registry | `worker-registry` | 采用持久 worker identity、lease、generation、usage | C1 |
| Direct A2A messaging | `application/message-router` | 与 Hermes messaging 合并；typed、项目隔离、有界队列 | C1 |
| Daemon detach / reattach | `runtime-supervisor` | 吸收 generation、cursor、snapshot、backpressure 和 recovery | C1 |
| Goal / heartbeat / schedules | `mission-scheduler` | 与 Hermes 长期任务机制合并，不复制调度器 | C1 |
| Autonomous budgets | `mission-budget` | 采用 token/cost/time/turn budget；完成由业务 Oracle 判定 | C1 |
| Continual Harness | `eval/harness-lab` | 仅生成 Candidate，接入 Penguin 评测、签名晋升与回滚 | C2 |
| Executable Python skills | `capability-gateway` | 不引入；Rust/WASM/隔离进程 + manifest + provenance | C2 |
| Kernel dill snapshot | 无直接采用 | 仅作思路参考；不用不可信 pickle 作为业务恢复 | 拒绝 |
| Prime Agent daemon / TUI | 无 | 不进入出货依赖，不形成第二 Runtime/UI | 拒绝 |

## 6. 必须修正的上游边界

### 6.1 任意 Python 执行

Prime Agent 明确执行模型生成的 Python、shell magic 和项目命令，并继承用户 OS 权限。Hartevo 面向真实社媒、邮件、CRM、达人、广告和付款身份，不能原样采用。

生产默认只允许 typed Rust Capability。动态代码必须进入独立 sandbox，使用只读/临时 Workspace、网络 allowlist、无 Secret 环境和明确资源上限；任何外部写入仍由 Effect Broker 完成。

### 6.2 Kernel snapshot 不是持久事实

Prime Agent 使用 `dill` 对顶层变量逐个 best-effort 序列化，默认最大 256 MiB；文件、socket、GPU tensor 等不可序列化对象会被跳过。这适合恢复便利，不适合作为业务真相：

- Hartevo checkpoint 只接受版本化 typed schema；
- 不信任 pickle/dill，也不把任意对象反序列化进生产进程；
- 未持久对象必须在 manifest 中显式列出，恢复后重新计算或报告缺口；
- Project Truth、Pending Effect、Approval 和 Consent 不依赖模型工作内存。

### 6.3 LLM 摘要不能覆盖不变量

Prime Agent 默认会截断长工具结果后再交给模型摘要。Hartevo 的压缩必须把以下对象放入不可丢失区：

- Goal、KPI、市场、受众、语言、预算、Stop Condition；
- 用户纠正、已确认事实、冲突和来源；
- Consent、Approval、禁止动作和能力 Scope；
- Pending / uncertain Effect、Receipt、Verification；
- Work Product version、采用状态和未完成 Task；
- 分支来源、Worker authority、成本和回流合同。

摘要可以压缩说明，不能修改这些 typed records。每次压缩都要保存 source range、summary model/config、provenance coverage 和 invariant diff。

### 6.4 Self-improvement 只能产生候选

`/refine` 的 evidence-backed edit、local/global scope、history、snapshot 和 rollback 值得吸收，但 Hartevo 增加以下围栏：

1. 生产 Agent 只写 `HarnessCandidateState`，不改 active bundle；
2. Candidate 不能修改 Capability permission、Effect policy、Rubric、Oracle 或 Release Gate；
3. Penguin-inspired Evaluator 在冻结 Benchmark 上复算；
4. 安全、业务、成本和回归 Gate 全部通过后由 Promotion Engine 签名；
5. 上线保留版本、来源、影响范围、canary 和立即回滚；
6. Project-local 经验不会静默晋升为 tenant/global memory。

### 6.5 A2A 与自治不能扩大权限

- child 的 Project、Mission、Capability、数据和 Effect Scope 必须是 parent 的子集；
- 消息传递不携带 Secret、Cookie、Provider Header 或未授权 PII；
- `auto`、`steer`、`follow_up` 等交付语义需要 idempotency、bounded queue 和 generation fencing；
- heartbeat 与 schedule 只触发新的受控 Mission continuation，不重放不确定 Effect；
- 达到 token/time/turn limit 只表示停止，不表示 Mission 完成。

### 6.6 Session 不等于 Mission

Prime Agent 的 Session、Goal 和 child registry 适合 coding/research agent，但 Hartevo Mission 可以跨多日、模型、Provider、OpenInterpreter Thread、Browser Workspace 和 Connector Worker。运行轨迹可以替换，Mission continuity 不能依赖某个 Session 存活。

## 7. 产品交互落点

Context Fabric 不新增一个要求用户学习的“RLM”或“Context”主导航：

- **总调度：** 展示 Mission 级进度、并行任务、等待项、压缩后的连续说明和下一步；所有 Worker 结果自动回流。
- **任务：** 可展开“正在研究 / 已完成 / 等待输入”的 Worker 分支、证据和产物；默认收起技术细节。
- **通知：** 跨项目收纳 Worker 完成、等待审批、连接失效、预算与恢复事件。
- **能力栈：** 只在高级诊断中显示某次任务用了哪些 Runtime、Model、Harness、Worker 和 Context revision。
- **自然语言入口：** 用户可以直接说“让竞品研究继续跑，但达人建联先停”“只保留日本市场证据”，系统将其编译为 Mission Steering、Worker 和 Context Branch 操作。

用户切换项目、任务或工作面时，界面从同一 `ContextWorkspace` 投影；不会新建割裂会话，也不要求手工复制上下文。

## 8. 质量 Gate

Prime Agent-inspired 机制进入生产前至少满足：

1. Compaction 后 Goal、Constraint、用户纠正、Evidence lineage、Pending Effect 和 Stop Condition 丢失为 `0`。
2. Context Capsule 的跨项目、跨租户、越权 Capability 和 Secret 泄漏为 `0`。
3. child authority 大于 parent authority 为 `0`；旧 generation Worker 回流被拒绝率为 `100%`。
4. 同一 Mission 跨模型、Provider、Runtime crash、Desktop restart 和 compaction 的恢复成功率达到 `≥ 99.5%`。
5. Branch merge 不产生重复 Effect、事实静默覆盖或 Work Product 版本倒退。
6. 不确定外部 Effect 自动重放为 `0`。
7. Harness Candidate 未经冻结 Benchmark、确定性 Oracle、回归和安全 Gate 直接上线为 `0`。
8. 用户界面中的 RLM、IPython、kernel、private thread / child id 等内部术语泄漏为 `0`。
9. Context budget、child usage、Provider cost 和任务归因可复算。
10. 原始轨迹、压缩记录、Worker 消息和 Candidate edit 均可重放和审计。

## 9. 实施顺序

### C0：Context Foundation

当前状态（2026-08-11）：本地领域/SQLCipher/Application C0 基础切片已实现 `WorkingSet`、append-only `ContinuationLedger`、typed `ContextInvariantBlock`、append-only `CompactionRecord`、原子 `ContextCheckpoint`、TTL/stale dependency 拒绝和 schema v26 迁移/故障注入证据。schema v29 的 Context Assembler 已把当前 Foundation、Checkpoint、Capsule authority、Branch lineage、Worker lease、数据策略、material digest 和预算确定性组装为短生命周期 Runtime envelope，并只原子持久化 content-free Manifest/Event/Outbox；dispatch 前再逐帧验证 transient envelope 与 Manifest。本地生产形态的 Context Material Store 已以 Project key/version + AES-GCM、不可变 `cas://sha256`、canonical file snapshot 与冻结 query JSON 替代测试 Map resolver，并覆盖旧 key 读取、symlink escape、错 scope、tamper 和 no-plaintext-at-rest。Digest-pinned Hugging Face tokenizer 已冻结 provider/model/model revision、artifact digest、special-token 策略、request overhead 和输入上限，覆盖 artifact swap/malformed/profile drift，并在 Application durable dispatch 前绑定 runtime provider/model；schema v31 以 hash-only normalized projection 对 profile 缺失/篡改失败关闭并回填 schema-v2 Manifest。schema v28 Runtime Recovery 把 Checkpoint 与 Fake Runtime generation/Thread rebuild 绑定，schema v30 Runtime Turn 进一步实现 durable dispatch permit、exact stream identity、local approval、interrupt、terminal evidence、拒绝/timeout/no-replay 和 active-turn fence。Application startup gate 现以 SQLCipher `IMMEDIATE` 事务全表校验 Runtime Turn record/projection/evidence，将未发出 Turn 确定性失败、可能已发出的 Turn 冻结为 `uncertain`，并在完成前禁止任何 Runtime spawn/dispatch。Dioxus 选中项目后的 keyring→CAS 解锁/内容会话 到已实现 keyring→CAS 会话的接线、CAS 删除传播/重加密/内容扫描、生产 tokenizer artifact registry、Provider model-revision 证明、真实 OpenInterpreter、spawn→ledger 孤儿进程清扫、process-kill/断电与 PostgreSQL 等价性仍未完成，因此 C0 不能标记为产品出口完成。

状态补充（2026-08-12）：schema v39 已在 spawn 前保存私有 `RuntimeProcessClaim`，并以 pinned Runtime 唯一 launch 副本、PID/start epoch/executable/runtime digest 和私有 token/路径标记精确恢复。真实遗忘 coordinator handle、Claim cleanup/Recovery update 提交间隙、幂等 replay、marker 伪造拒绝和两个真实 OpenInterpreter smoke 已通过；无法检查时为 `BLOCKED_ENV` 且不按 PID 猜杀。上段未完成项中的“真实 OpenInterpreter”和“spawn→ledger 孤儿进程清扫”已由该 macOS 本地 E2 子集取代，但 credentialed success、外部 process-kill/断电、Windows 与 PostgreSQL 等价性仍未完成，因此 C0 仍不能标记为产品出口完成。

Scheduler 状态补充（2026-08-12）：schema v40～v47 已实现本地 durable Mission Scheduler/route E2：interval/event/hybrid cadence、Outcome+Schedule、signed inbound+signal、lease/cycle/expiry/Dead Letter 都具备 SQLCipher 单事务与 crash-gap 回归；旧 generation 被 fencing，raw owner/token 不进入公开证据。Catalog v10 为 123 个 Checkpoint 冻结 Capability、executor、Oracle 与 completion policy；legacy route 可审计但不可完成。v47 只事务性 rebuild `mission_checkpoints.route_completion_policy` CHECK 并加入 `effect_readback_v2`，保留旧行/约束/index；碰撞时 table/index/data/ledger 整体回滚且清理后可重试。VM-08 v4 的该 policy 仍是 E1：ReceiptCandidate 必须关联独立、只读 credential 的 account readback 与 canonical field diff，Receipt/corroboration/verified Effect/generic completion 单独均不能完成，合同不授予 adapter/Provider/产品验证 authority。Application selector 原子启动 next route，通用 Human route 只能通过 Mission/Checkpoint/Conversation 双 CAS 的确认命令完成并 handoff；VM-11 `continue_stop_scale_test` 另以冻结 Outcome Review/source fence 与结构化 Continue/Stop/Scale/Test decision 原子推进。独立 Application Handler Registry v8 当前注册 VM-11 `event_ingest`、`normalize_dedupe_order`、`identity_chain`、`mission_specific_kpi`、`attribution_and_unattributed`、`refund_commission_payout_recalc`、`outcome_review` 与 `next-contract-or-valid-terminal`。前七条保持来源 fence、严格 verification/规范化 projection、精确身份传递闭包、父 Mission/Operating Contract 继承、typed KPI Oracle、无因果宣称的 verified-identity/non-direct/first-touch/Unattributed Oracle、不可变订单/跨期退款/按 Supply Class 分权的 Commission 与 verified payout 对账 Oracle，以及按原币种冻结 KPI/归因/结算/Effect 成本/预算且不做隐式 FX、ROI、因果或自动决策的 Outcome Review。第八条绑定 action/decision/parent-contract/route revisions：Stop typed terminal 并跳过 `candidate_learning`，Continue 只复用 exact frozen parent contract，Scale/Test 保持 `WaitingUser` 等待完整 replacement contract 授权；exact replay 零新增 Event/Outbox，drift/generic completion 失败关闭。当前机器合同为 8/52、其余 44 条 `NOT_IMPLEMENTED`；第八条现有 Desktop caller/UI wiring，仍不是十二条 Mission 的完整原生 UI Journey。Runtime `item/agentMessage/delta` 仍使用 v46 私有链、重组校验和故障回滚；c71061e 无真实 Dioxus delta 投影是绑定旧 commit 的历史事实。该切片仍没有 OS wake/sleep-resume、Cell leader/多 Worker、公平调度、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human route、redirect、原生 revise/requeue UI 或 PostgreSQL 等价性；Release Evidence 仍为 `passed: false`，不能据此把 C1 或 Mission E3 标记完成。

- `ContextWorkspace`、`WorkingSet`、`ContinuationLedger`、`ContextCheckpoint` 和 schema migration。
- schema v35 已把 local wrapping-reference Registry 与 Keyring/attachment/rotation 原子提交；Application-owned Context session 从 Project+Device 解析 exact envelope/ref、经 OS Secret Store 解包 active/历史 key 并把裸 key 限定在 zeroizing session 内。跨 SQLCipher 重启、轮换、历史缺钥降级、active 缺钥、错设备、撤销和 projection tamper 已覆盖；这仍不是 Dioxus 解锁 Journey、Windows 实机或丢失设备历史 handoff。
- Context Assembler 的本地确定性组装、项目作用域 encrypted CAS/File/Query resolver、digest-pinned tokenizer、runtime provider/model binding、content-free evidence、Fake/真实 credentialless Runtime、Process Claim cleanup 与 Turn startup reconciliation 已实现；继续补签名生产 tokenizer artifact registry、Provider model-revision 证明、CAS 删除传播/重加密/内容扫描、credentialed OpenInterpreter、外部 process-kill/断电、Windows 与跨后端恢复；不可丢失 typed invariant block 与 append-only `CompactionRecord` 保持权威输入。
- OpenInterpreter Thread / Turn 只作为 Context 投影，支持切换 Runtime generation 后重建。

### C1：Worker Graph

当前状态（2026-08-12）：本地领域/SQLCipher/Application C1 切片已实现 parent-scoped `WorkerHandle`、capability/budget/usage 继承、claimed Capsule 执行权、有界严格顺序 Mailbox、detach/reattach epoch fencing 与 typed single-use Branch merge。schema v27～v31 覆盖 Collaboration、Runtime Recovery/Turn 与 tokenizer projection；startup scan 会冻结遗留状态。schema v40～v47 与 Catalog v10 又补齐本地 Scheduler、123 条 Capability/executor/Oracle/policy route、route-aware Desktop selection、一个 VM-07 Human confirmation 原子 handoff、VM-11 structured decision、Runtime delta 私有持久链、E1 `effect_readback_v2` typed persistence/generic-completion refusal，以及 VM-11 event-ingest/normalize/identity-chain/mission-specific-kpi/attribution/settlement-reconciliation/outcome-review/next-contract-or-valid-terminal 八条 source-fenced Application handler。第八条在 Domain/Storage/Application 实现 Stop typed terminal、Continue exact-parent reuse、Scale/Test `WaitingUser` 与 exact replay，并已有 Desktop caller/UI wiring。生产级 OS/Cell Scheduler、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human route、真实 Dioxus delta 投影、redirect、credentialed crash/provider switch、Provider model-revision、跨进程并发/`loom`、process-kill/断电和 PostgreSQL 等价性仍未完成，因此 C1 不能标记为产品出口完成。

状态补充（2026-08-12）：C1 的启动顺序已变为 Process Claim reconciliation→Recovery attempt crash-gap repair→Runtime Turn full-ledger reconciliation→Mission Schedule expiry reconciliation；active/blocked Claim 会阻止重复 Runtime。macOS 本地 pinned Runtime orphan cleanup 与本地 cadence/event Scheduler 已有 E2，但生产级 OS/Cell wake/leader、自动 Runtime/Browser handoff、redirect、credentialed crash/provider switch、跨进程并发/`loom`、外部 process-kill/断电、Windows 与 PostgreSQL 等价性仍未完成。

- `ContextCapsule`、`ContextBranch`、`WorkerHandle`、lease、generation、budget 和 usage attribution。
- 把现有 Hermes-inspired 本地 message router/Scheduler 从已冻结 route、Desktop selector、窄 Human confirmation handler 与 VM-11 event-ingest/normalize/identity-chain/mission-specific-kpi/attribution/settlement-reconciliation/outcome-review/next-contract-or-valid-terminal 八条 handler 扩展到 OS wake/sleep-resume、Cell leader/多 Worker 公平调度、heartbeat、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human route、其他 route 的完成回写、handoff 与 redirect。
- detach / reattach、snapshot cursor、bounded backpressure、worker crash 与 provider switch 测试。

### C2：Continual Harness Candidate

- 将 trajectory lesson、prompt note、memory 和 subagent recipe 统一为 Candidate Bundle。
- 接入 Penguin-inspired frozen Benchmark、Evaluator / Optimizer isolation、Promotion 和 rollback。
- 建立 project / tenant / global scope policy、PII 清理、保留期和删除传播。

### C3：长周期 Mission Pilot

- 在跨周增长循环、达人研究、渠道监控和 CRM 跟进中验证。
- 完成上下文预算、成本、压缩准确性、恢复和多 Worker 规模测试。
- 只有通过 Hartevo Mission Eval 后，才能声明“长上下文”或“长期自治”能力。

## 10. 不做什么

- 不把 Prime Agent fork 成 Hartevo Runtime。
- 不运行 Prime Agent daemon、TUI、IPython kernel 或 Python skills。
- 不把“支持更长任务”宣传成模型有无限上下文。
- 不让模型自行修改生产 Prompt、Skill、权限、Oracle 或 Release Gate。
- 不把 Session JSONL、Python variable、child agent result 或 LLM summary 当作 Project Truth。
- 不整体机械翻译 TypeScript/Python 源码后声称为 Hartevo 原创。
- 不把进程隔离描述为安全沙箱。
- 不把 Prime-RL 或 Verifiers 的能力误写成 prime-agent 仓库已经内置；相关项目如需吸收必须另行审查。

## 11. 主要依据

- [Prime Agent repository](https://github.com/PrimeIntellect-ai/prime-agent)
- [Prime Agent v0.7.1 release](https://github.com/PrimeIntellect-ai/prime-agent/releases/tag/v0.7.1)
- [代码审查 commit](https://github.com/PrimeIntellect-ai/prime-agent/tree/a18809e00ea30638584d87b3afea7285a9d7296c)
- [RLM programming model](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/rlm.md)
- [RLM runtime architecture](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/rlm-runtime.md)
- [Architecture overview](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/architecture.md)
- [Daemon architecture](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/daemon.md)
- [Compaction and branch summarization](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/compaction.md)
- [Long-running agents](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/packages/coding-agent/docs/long-running-agents.md)
- [MIT License](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/LICENSE)
