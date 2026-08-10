# Hartevo Desktop 当前架构合同

状态：**Accepted**
版本：2.2
日期：2026-08-10

本文定义 Rust Hartevo Desktop 的组件所有权、进程边界、数据流和安全不变量。产品行为以交互规格与 v12 原型为准；上游采用理由以 Rust/OpenInterpreter RFC 为准。

## 1. 架构目标

Hartevo Desktop 必须把自然语言目标持续推进为可验证的业务结果：

```text
自然语言目标
→ Mission Contract
→ 动态能力子图与任务队列
→ 研究、证据和 Work Product
→ Approval 与受控 Effect
→ Provider Receipt
→ 独立 Verification
→ Outcome 与下一轮决策
```

架构同时满足：

- Rust-first，产品逻辑不依赖 Node 或 JavaScript 运行时。
- Local-first，创建项目不隐含上传。
- 一个项目只有一个持续总调度关系，工作面共享 Mission State。
- Agent Runtime 可升级，但不能拥有 Hartevo 业务事实。
- 外部写入始终经过领域权限、审批、幂等和验证。

## 2. 产品与领域层级

```text
User / Organization
  └─ Promotional Project
       ├─ Truth Graph and Memory
       ├─ Connection Scope and Consent
       ├─ Approval and Effect Policy
       ├─ Mission
       │    ├─ Tasks and Runtime Threads
       │    ├─ Work Products and Evidence
       │    └─ Effects / Receipts / Verification / Outcomes
       └─ Local Files and Optional Sync
```

- Project 是宣发单位和数据隔离边界。
- Mission 是业务目标、约束、连续运行和结果判断边界。
- Task 是可调度的工作单元，不等于独立会话。
- Runtime Thread 是执行轨迹，可被替换、压缩或重建，不是业务主键。
- Work Surface 是同一 Mission 的结构化视图，不拥有独立 Agent 状态。

## 3. 进程拓扑

```text
┌─────────────────────────────────────────────────────────────┐
│ Hartevo Desktop · Rust + Dioxus                            │
│                                                             │
│  UI State ─ Application Service ─ Domain Kernel             │
│                       │              │                       │
│                 Context Fabric       │                       │
│                       │              ├─ SQLite / Event Log   │
│                       │              ├─ Effect Broker        │
│                       │              └─ Sync Projection      │
│                       │                                      │
│                 Runtime Adapter                              │
│                       │ stdio JSON-RPC v2                    │
└───────────────────────┼──────────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ OpenInterpreter App Server · Rust child process             │
│ Provider / Model / Harness / Agent Loop / Tools / Sandbox   │
└─────────────────────────────────────────────────────────────┘

External adapters: Browser/Computer · Connectors · Hartevo Cloud
```

首版不开放本地 WebSocket 监听。Runtime Adapter 通过 stdio 启动、鉴权、监管和恢复 child process。

## 4. 组件所有权

### 4.1 Dioxus Desktop Shell

负责：

- 窗口、系统菜单、通知、快捷键、更新和桌面生命周期。
- Project、Mission、Task、Work Product、连接、审批和设置体验。
- 常驻自然语言 Composer 与模型、推理强度、速度选择。
- 把 Rust application state 渲染为 Hartevo 工作面。
- 文件夹选择、拖放、剪贴板和辅助功能。

不负责：

- 直接执行 Provider 写操作。
- 保存真实凭据。
- 以 UI 临时状态替代领域事实。
- 把 Runtime 私有 item 直接当作业务完成状态。

### 4.2 Application Service

连接 UI、Domain Kernel 和 Runtime Adapter：

- 接受用户命令并建立或修改 Mission Contract。
- 生成读模型和下一步建议。
- 把 Runtime stream 投影为 Live Work。
- 协调 interrupt、redirect、resume、model switch 和 approval。
- 保证所有工作面订阅同一个 Project/Mission state。

### 4.3 Hartevo Domain Kernel

唯一业务事实源，负责：

- User、Organization、Project、Membership 和租户隔离。
- Truth、Evidence、Mission、Task、Work Product 和 Adoption。
- Connection Scope、Consent、Approval Policy 和 Capability Registry。
- CRM、Inbox、Creator、Partner、Affiliate、Campaign 和关系生命周期。
- Effect、Idempotency、Receipt、Verification、Outcome 和 Attribution。

Agent 建议只能通过领域命令改变状态；已验证事实不能被一段模型输出直接覆盖。

### 4.4 Project Store

本地 SQLite 与 append-only event log 负责：

- Project、Mission 和 Work Product 元数据。
- Runtime mapping、checkpoint 和 crash recovery。
- 可重建的读模型、索引和缓存。
- Connection reference，不保存明文 secret。
- Sync outbox 和 conflict metadata。

用户可见文件继续留在所选项目目录；内部数据库位置、备份和迁移必须明确记录。

### 4.5 OpenInterpreter Runtime Adapter

通过 App Server v2 映射：

- initialize、thread start/read/resume/archive。
- turn start/steer/interrupt。
- streamed message、reasoning summary、plan、command、file change 和 tool progress。
- command/file permission request。
- Provider、Model、Harness、Reasoning Effort 和 Service Tier。
- MCP、Skills、Plugins、Hooks 和 runtime status。

Adapter 维护独立映射：

```text
project_id + mission_id + runtime_generation
↔ runtime_thread_id + runtime_turn_id + schema_digest
```

OpenInterpreter 不拥有 Project、Mission、Consent、Effect 或 Outcome。

### 4.6 Capability Gateway

只向 Runtime 暴露类型化的最小能力：

- 读取当前 Project 的版本化上下文。
- 查询经过 Scope 过滤的 Truth、Evidence 和关系。
- 创建草稿、建议和待审批 Effect。
- 读取 Work Product 状态和验证结果。

工具 schema 必须版本化。模型不能获得数据库句柄、Provider token 或任意跨项目查询能力。

### 4.7 Effect Broker

所有外部业务副作用的唯一入口：

- 社媒发布与互动。
- 邮件发送和序列推进。
- CRM 写入、联系人更新和 Deal 操作。
- 达人/Partner 建联和联盟动作。
- 广告预算、付款和其他高风险动作。

每个 Effect 必须包含 Project、Mission、Actor、Capability、Scope、Consent、Approval、Idempotency Key、Cost Boundary 和 Expiry。执行后保存 Receipt，由独立 Verifier 判断真实结果。

### 4.8 Browser / Computer Adapter

负责：

- `BrowserProfile`：绑定 Tenant、Project、账号身份与 OS keyring credential reference；默认使用 Project-bound managed profile，不默认控制用户主浏览器 Profile。
- `BrowserWorkspace`：绑定 Project、Mission、Profile 与标签集合；恢复同一 Mission 时优先复用原 Workspace，不生成新的业务会话。
- `BrowserControlLease`：`agent_controlled`、`user_controlled`、`paused`、`completed` 与 `closed` 状态；每次交接递增 generation。
- `SemanticSnapshot`：通过 AX/DOM/iframe 信息生成脱敏语义视图、短期 element ref 与稳定 locator 候选。
- `BrowserActionBatch`：执行可中断的 observe、resolve、act、wait、verify typed action，不运行模型生成的任意 Node.js。
- `BrowserRecipePackage`：按域名、账号、UI 版本、Scope、Effect class 和签名管理可复用站点经验。
- 截图、可见 readback、下载、上传、CAPTCHA、MFA 和人工接管。
- 页面级动作前复核目标域名、账号、Project、Mission、Scope、Snapshot generation 与 Control Lease。

人工接管提交后，Browser Host 必须拒绝旧 lease 中所有未开始的点击、键盘、上传、页面脚本与 browser fetch；Agent 只能在用户明确“交还 Hartevo 继续”后通过 compare-and-swap 获得新 lease。只查看 Agent 页面不会隐式接管。

潜在外部写入即使通过页面 JavaScript、raw CDP、浏览器身份 fetch 或 Recipe 发起，也必须先建立 Pending Effect，经 Effect Broker 执行。Browser tool success 只产生 `BrowserReceipt` 候选，仍需独立 Verification。

### 4.9 Connector Workers

确定性 Rust worker 负责：

- OAuth、API、Webhook、轮询和增量同步。
- Provider-specific rate limit、retry 和 cursor。
- Email、CRM、social、affiliate、analytics 和 commerce adapter。
- Receipt 标准化、Verification 和状态投影。

不确定的外部写入、付款或可能重复触达不能自动重试。

### 4.10 Context Fabric 与 Worker Registry

Context Fabric 是 Hartevo-owned Rust application/storage 组件，负责把长周期 Mission 的上下文从单一模型窗口外置为可持久化、可压缩、可分支和可恢复的状态：

- `ContextWorkspace`：绑定 Project、Mission、runtime generation、Context Budget 和数据策略。
- `WorkingSet`：保存 typed value、Evidence / Work Product reference、查询快照、TTL 和 provenance。
- `ContinuationLedger`：保存 Goal、KPI、Constraint、Decision、用户纠正、Task、Blocker、Pending Effect 和下一步。
- `ContextCapsule`：只向一个 Worker 投影完成局部任务必需的事实、约束、能力、预算和 return contract。
- `ContextBranch`：记录 fork 原因、parent、scope、status、merge / abandon policy 与 lineage。
- `WorkerRegistry`：保存 worker identity、lease、generation、runtime mapping、usage 和 result status。
- `ContextCheckpoint`：保存恢复所需的领域 revision、open work、Effect 状态和 stream cursor。
- `CompactionRecord`：append-only 保存 source range、结构化摘要、不可丢失不变量、provenance coverage、模型和配置。

Context Fabric 不拥有 Project Truth、Consent、Approval、Effect、Receipt、Verification 或 Outcome。它引用 Domain Kernel 的版本化对象，模型窗口、LLM 摘要、Runtime Thread、Session JSONL、Python variable 或 child result 都不能直接覆盖领域事实。

Worker Graph 属于一个 Mission 的执行投影：Task 可以映射为不同模型、Provider、OpenInterpreter Thread、Browser 或 Connector Worker；用户仍只看到 Mission、任务、证据、产物和等待状态。child 的 Project、Mission、Capability、数据、Secret 和 Effect authority 必须是 parent authority 与当前 Mission Scope 的严格子集。

Prime Agent-inspired goal、heartbeat、schedule、message 和 retained worker 与 Hermes-inspired 长期调度统一实现；Continual Harness 只生成 Penguin-inspired `HarnessCandidateState`，不能直接修改 active Harness、权限、Rubric、Oracle 或 Release Gate。完整采用边界见 [Prime Agent → Hartevo Rust Context Fabric 能力引入清单](../research/PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md)。

## 5. Runtime 与 Domain 双层审批

```text
Local execution approval
  └─ 文件、命令、进程、网络和 workspace 边界

Business effect approval
  └─ 发送、发布、花费、CRM 写入、触达和付款边界
```

- 两层审批可以同时出现。
- Runtime approval 通过，不代表业务 Effect 被批准。
- Effect approval 通过，不代表可以突破本地 sandbox。
- UI 必须说明批准对象、范围、成本、有效期和可撤销性。

## 6. 模型运行配置

运行配置由五部分组成：

```text
Provider + Model + Harness + Reasoning Effort + Service Tier
```

- Provider 决定 endpoint、auth 和 wire API。
- Model 决定上下文、模态和能力。
- Harness 决定模型面对的 prompt、tools 和消息形状。
- Reasoning Effort 只使用模型声明支持的值。
- Service Tier 表达速度/成本通道；不支持时隐藏。

Hartevo 保存的是用户可理解的 preset 与底层版本化配置，不把“快速/深度”硬编码成某个永久模型。

## 7. 本地与云数据边界

项目支持：已有本地文件夹、新建本地文件夹、本地加密同步、云端工作区。

### 本地至少保存

- Project identity、storage mode 和 workspace roots。
- Mission、Task、Work Product、Evidence 和 runtime mapping。
- 本地 event log、索引、缓存与恢复 checkpoint。
- 不含明文 secret 的 Connection reference。

### 操作系统安全存储

- OAuth refresh token、API key、Cookie encryption key 和本地 child token。
- 每个 secret 绑定 account、project scope、provider 和 rotation metadata。

### 云端可选保存

- 组织、成员和共享 Project state。
- 用户选择同步的 Work Product、Evidence 和领域事件。
- 团队审批、Effect、Receipt、Verification 和审计记录。

创建项目、登录账户或连接 Provider 都不自动开启文件上传。

## 8. 核心事件流

1. 用户在项目总调度输入目标或修正方向。
2. Application Service 调用 Domain Kernel 建立或更新 Mission Contract。
3. Domain Kernel 生成当前 Project Context、Capability Scope 和待执行 Task。
4. Context Fabric 建立或恢复 `ContextWorkspace`，从 Continuation Ledger、Working Set 和 Project Truth 组装有界 Context Capsule。
5. Runtime Adapter 创建或恢复 OpenInterpreter Thread；并行任务通过 Worker Registry 获得独立 lease、generation、budget 和 Capsule。
6. Runtime stream 持续转为 Live Work；Worker 结果、任务与工作面自动同步并保留 lineage。
7. 研究和草稿直接形成 Evidence / Work Product 候选；压缩只生成 append-only record，不覆盖 typed invariant。
8. 外部动作先成为 Pending Effect，由 Effect Broker 检查 Scope、Consent、Policy、Approval 和幂等。
9. Connector 或 Browser 执行后写入 Receipt；Verifier 独立验证。
10. Outcome 和 Attribution 回流 Truth Graph，生成 Continue、Stop、Scale 或 Test 决策。

连接缺失只阻塞依赖该连接的 Task，不阻塞研究、草稿和其他可执行工作。

## 9. 崩溃与恢复

- Desktop 启动时先恢复 Project Store，再启动 Runtime child。
- 每个 stream item 先进入有界 inbox，再更新 UI projection。
- Runtime 崩溃不丢失 Mission、Work Product 或已经提交的 Effect。
- 未知状态的外部 Effect进入 `verification_required`，不得盲目重放。
- Thread resume 失败时可以创建新 runtime generation，但必须保留 Mission continuity。
- 模型切换创建新的可审计 runtime config，不改写既有证据来源。
- Context Workspace、Continuation Ledger、Worker Registry 和 Compaction Record 先于 Runtime 恢复；不可恢复的临时 Working Set 项必须显式列为缺口并重算，不能静默假装存在。
- 旧 generation Worker、过期 lease 或分支回流不能覆盖新状态；其结果只能进入冲突审阅或被拒绝。

## 10. 安全不变量

- Secret 不进入 Prompt、普通日志、项目文件、同步包或 Git。
- Runtime 只能访问当前 Project 明确授权的 workspace roots。
- 跨 Project 的联系人、Consent、私有事实和连接默认隔离。
- Connection 成功不等于允许外部动作。
- Tool success 不等于业务成功。
- Provider accepted 不等于发布、送达或付款完成。
- 所有外部 Effect 必须可审计、唯一执行并独立验证。
- Harness、Skill、Plugin、Hook 和 MCP server 都是供应链执行资产，必须有来源、版本、权限和信任状态。
- 模型生成的任意 Python、Node、shell program 和不可信 pickle/dill 不进入默认 Context 或 Capability 执行路径。
- Compaction 不得丢失 Goal、Constraint、用户纠正、Evidence lineage、Consent、Approval、Pending Effect、Stop Condition 或 Work Product version。
- Worker / Subagent authority 不能超过 parent 与 Mission Scope，且不能跨 Project 静默传递上下文。
- Harness 自我改进只产生 Candidate；生产版本必须经过冻结 Benchmark、确定性 Oracle、安全回归、签名晋升和回滚合同。
- UI 不展示私有 chain-of-thought；只展示可公开的 reasoning summary、证据和操作理由。

## 11. 版本合同

每次构建记录：

- `hartevo_desktop_version`
- `hartevo_domain_schema_version`
- `hartevo_protocol_version`
- `openinterpreter_commit`
- `openinterpreter_release`
- `app_server_schema_digest`
- `provider_catalog_version`
- `harness_catalog_version`
- `mission_catalog_version`
- `context_fabric_schema_version`
- `compaction_policy_version`
- `ui_component_license_manifest_digest`

上游升级必须通过 Runtime Adapter contract test、Mission smoke test、安全回归和 UI event snapshot。

## 12. 首个工程切片完成条件

首个切片必须完成一条受控 Mission：

1. 从已有本地文件夹或新建项目开始。
2. 自然语言目标被编译成可审阅 Mission Contract。
3. Rust Shell 启动 OpenInterpreter App Server 并接收流式状态。
4. 至少两个工作面共享同一 Mission State。
5. 产生可编辑 Work Product 与可追溯 Evidence。
6. 一个真实低风险外部动作经过双层审批后唯一执行。
7. Receipt 与独立 Verification 可见。
8. Outcome 回流并生成下一步决策。
9. 对应 Mission Eval 可重放并通过 Release Gate。
