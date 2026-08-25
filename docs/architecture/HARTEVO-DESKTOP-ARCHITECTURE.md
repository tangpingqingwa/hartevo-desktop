# Hartevo Desktop 当前架构合同

状态：**Accepted**
版本：2.7
日期：2026-08-11

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
- 一个项目只有一个持续总调度关系，每条 Mission 有持久 Conversation；二者和所有工作面共享唯一 Mission/Truth/Effect State。
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
- CRM、Inbox、Creator、Partner、Affiliate、Campaign、Creator Hiring/Candidate/Listing/Invitation/Application/Award、Creator Task/Bounty、Deliverable/Review/Dispute 和关系生命周期。
- Effect、Idempotency、Receipt、Verification、Outcome 和 Attribution。

Agent 建议只能通过领域命令改变状态；已验证事实不能被一段模型输出直接覆盖。

### 4.4 Project Store

本地 SQLite 与 append-only event log 负责：

- Project、Mission 和 Work Product 元数据。
- Runtime mapping、checkpoint 和 crash recovery。
- 可重建的读模型、索引和缓存。
- Connection reference，不保存明文 secret。
- Sync outbox 和 conflict metadata。
- `DesktopDataPlane` 将 canonical 私有 data root 的 digest 绑定到 OS Secret Store 中唯一安装 SQLCipher key；首次数据库/密钥创建只能来自用户显式初始化。已有数据库缺 key、替换 key、symlink root/database 均失败关闭且不改写密文。启动依次完成 Runtime Process Claim/Recovery/Turn reconciliation 与 Mission Schedule 合同到期 reconciliation，全部成功后才经 `ApplicationService::desktop_inventory` 投影 Project、Mission 与 Keyring readiness；Dioxus 页面不直接读库、不保存 demo state，也不能制造 Receipt、Verification 或 Completed。
- `DesktopDataPlane::resume_mission_runtime_os` 只针对现有 Mission：Application 先读取最新完整性校验后的 Recovery/Turn。`Prepared` recovery 在同 generation 继续 bounded retry；`Failed` recovery 先以一个事务退役 Branch/Lease/Capsule/Handle，再创建 successor generation；`Attached` 且 Turn 为 `Failed|Interrupted` 时只恢复原 durable Thread。active/`Uncertain`/`Completed` Turn 禁止自动重放。Runtime 完成最多创建带 Manifest 的可审阅草稿，不能改变 Mission 业务终态或产生外部 Effect。
- `DesktopDataPlane::runtime_text_stream_with/os` 是独立于 metadata inventory 的只读私有正文边界：先用当前 Device secret 打开 exact Project Context，再按 Project/Mission 读取最新 Runtime Turn 与完整性校验后的 SQLCipher delta chain。Dioxus 只监测当前选中 scope，重启/重新选择可 replay，active submit/retry 期间以 100ms polling 更新 append-stable 段落；scope 变化或查询失败立即隐藏正文，terminal draft 仅在正文精确一致时去重，follow-latest/unseen 不持久化也不扩大 Runtime authority。新 Catalog Mission 的 blocking Application 调用仍未提前暴露 exact Mission handle，所以首轮 execution-time subscription、durable reconnect cursor，以及真实高密度 process/artifact/capability 投影尚未建立。
- 个人项目采用 user-owned Recovery Kit 两阶段 onboarding：UI 只在 zeroizing 短期状态中生成并一次性展示 32-byte/64-hex key；用户确认已离线保存后，Application 才建立 `PersonalE2ee` Device+Recovery envelopes、把 Device wrapping key 写入 OS Secret Store、持久化首个 Mission。Recovery key 不被 Hartevo 或 OS Vault 托管。若在 Project 创建后中断，重启只显示 `NotProvisioned`，用户用保存的 Kit 显式完成；已配置项目拒绝重复 provisioning。若当前项目 Device secret 后续丢失，UI 保留 metadata、清空 preview 并阻断写入；用户可用同一 Kit 经 exact revision/idempotency 的持久 Attachment Saga 增加 distinct successor Device identity，错误 Kit 零副作用，旧 envelope 不覆盖，Context 重开后才恢复 preview/Mission。
- schema v47 继承 v35 project-local `project_key_secret_references`，并依次加入 v36 MissionDefinition/Checkpoint DAG、v37 MissionConversation、v38 exact Runtime Turn private-message ledger、v39 Runtime Process Claim/cleanup ledger、v40 future-cycle Mission Schedule ledger、v41 `expired` 终态、v42 Checkpoint Capability/executor、v43 Checkpoint Oracle/completion policy、v44 Human confirmation message constraint、v45 VM-11 Outcome Review/source-fence/structured Human decision ledger、v46 Runtime private text delta ledger，以及 v47 对 `mission_checkpoints.route_completion_policy` CHECK 的事务性 rebuild。v47 只增加 `effect_readback_v2` allow-list 值，保留既有 15 列、PK/UNIQUE/FK、状态/完成约束和 `mission_checkpoint_state_idx`。完整 `SecretReference`、Conversation/Runtime 正文、Runtime delta、launch token/path、process identity 与 Scheduler 私有 lease token 仅进入 SQLCipher 私有 record；normalized projection 只保存 scope、digest、version、状态和计数。metadata inventory 会清空 Mission 标题、目标、Conversation 正文、Outcome 与 Work Product preview；exact `ProjectContextMaterialSession` 才能生成可读投影。Keyring 创建、recipient/Worker envelope、设备附加与 revoke+rotate 都把新 envelope 和 binding 放进同一事务。Application-owned session 按当前 Project/Device 读取 exact binding、从 OS Secret Store 解包 active key，再装入仍可用的历史版本；调用者只能操作 encrypted CAS，不能取得裸 key。active 引用/secret 缺失、错设备、已撤销 envelope、AEAD 或 projection 篡改失败关闭；仅历史 secret 缺失时保留 active session 并公开 degraded version 集合。
- schema v34 在 v33 `BrowserFileGrant` 与 v32 `BrowserProfile`、`BrowserWorkspace`、Tab、append-only Control Transition 上新增 project-local Browser Recipe Trust Key、immutable Candidate/Release、append-only Activation 和 CAS Head。Browser credential reference、完整 File Grant、Recipe 公钥/签名/Manifest/评测记录与 Runtime 私有 ID 只在 SQLCipher 私有 record；规范化列、Event、Outbox 与 Debug 不保存源路径、文件名、正文、raw claim、credential、签名或 Manifest。Profile/Workspace/账号身份、revision、lease generation、Tab、transition、File Grant 或 Recipe projection/head 缺失/篡改均失败关闭。File Grant 的 prepare/claim/terminal 与 Recipe install/revoke/register/activate 都和 Event/Outbox 使用 CAS 原子提交；Broker 按数据库先提交、文件状态后 commit 的顺序恢复，`Leased` 不自动重放；Recipe 恢复按历史时间重放签名链，当前派发再验证 active head 与 key revocation。Working Set 的正文只存在加密 CAS；Continuation entry append-only；Compaction/Checkpoint 从当前 Mission 与全部 Project Truth 重建并绑定不可丢失 invariant。Context Assembler 先复核 Foundation、Checkpoint、Capsule revision/authority、Branch lineage、Worker lease、material digest、classification、预算和 digest-pinned tokenizer profile，再逐帧证明 transient `RuntimeContextEnvelope` 与持久 Manifest 完全一致。Runtime Turn scope 冻结 Assembly、Capsule、Branch、Lease、Handle attachment epoch、Recovery revision、process instance、Thread、runtime provider/model 和 mapping digest；agent message 与 exact evidence 同事务写入 v38 私有 ledger，durable dispatch、local approval/interrupt、`Uncertain` 零重放与 content-free Event/Outbox 边界不变。v15→v16 直到 v37→v38 的每段迁移均有加密备份或幂等安装证据；v26 安装 Context Foundation，v27 安装 Context Collaboration，v28 安装 Runtime Recovery，v29 安装 Context Assembly，v30 安装 Runtime Turn attempt/evidence，v31 安装 tokenizer profile hash-only projection并回填 schema-v2 Manifest，v32 安装 Browser Profile/Workspace/Tab/Control Transition，v33 安装 Browser File Grant，v34 安装 Browser Recipe Trust/Candidate/Release/Activation/Head，v35 安装本地 wrapping-reference Registry，v36 安装 MissionDefinition DAG，v37 安装 MissionConversation，v38 安装 Runtime private message；旧 migration fixture 会先删除所有更高版本表再重放，避免残留 schema 造成假通过。
- v38→v39 幂等安装 `runtime_process_claims`；spawn 前 Claim、Recovery+Claim spawn CAS、cleanup append 与 projection tamper 都有 SQLCipher 回归。启动扫描还覆盖 terminal Claim 已提交而 Recovery 仍停在同 attempt 的崩溃间隙，推进 bounded retry 后不重复使用旧 Claim 主键。
- v39→v40 幂等安装 `mission_schedules`，v40→v41 增加 `expired`，v41→v42 增加 nullable route capability/executor，v42→v43 增加 nullable Oracle/policy 并将 legacy 行保留为无完成权限，v43→v44 rebuild Conversation constraint 并保留旧消息，v44→v45 安装 Outcome Review/source-fence/structured decision ledger，v45→v46 安装 Runtime delta/evidence/private-message ledger，v46→v47 事务性 rebuild `mission_checkpoints` 的 policy CHECK。联合迁移覆盖 fresh、v44/v45 顺序经过 v46→v47、既有 v46 policy/行保留、typed `effect_readback_v2` save/reopen，以及碰撞时 table/index/data/ledger 整体回滚、无 v47 migration 记录和清理后重试。Catalog v10 的 123 个 route 顺序与 DAG 完全一致，Capability/Oracle 并集分别必须等于 Mission authority/Oracle；Runtime route 强制 WorkProduct。Effect Broker route 的 completion policy 只能是 `verified_effect` 或 `effect_readback_v2`：前者要求真实 independently verified Effect；后者是 VM-08 v4 的 E1 route，写阶段只形成 ReceiptCandidate，还必须以独立 `marketplace.read`、只读 credential、Receipt correlation 与 canonical target field diff 完成专用 readback proof。ReceiptCandidate、corroboration、已验证 Effect 或 generic completion 单独均不能完成，伪造持久 completion 也失败关闭；合同不授予 adapter/Provider/产品业务验证 claim authority。所有 route 强制 Operating State。Task/Checkpoint/Event/Outbox 原子推进，Scheduler 不猜 Capability。Application dispatch selector 原子启动下一个 Ready route；通用 Human confirmation 把用户确认、Conversation、Checkpoint、旧/新 Task 与 Event 绑定双 CAS；VM-11 `continue_stop_scale_test` 另以冻结 Review/source fence、Continue/Stop/Scale/Test、actor/rationale/idempotency 与双 CAS 原子记录结构化决定。通用 completion API 均拒绝绕过。Application Handler Registry 是另一条生产 allow-list：v8 除 `vm11.event_ingest/v2`、`vm11.normalize-dedupe-order/v1`、`vm11.identity-chain/v1`、`vm11.mission-specific-kpi/v1`、`vm11.attribution-and-unattributed/v1`、`vm11.refund-commission-payout-recalc/v1` 与 `vm11.outcome-review/v1` 外，还要求 `vm11.next-contract-or-valid-terminal/v1` 同时存在于机器合同与二进制。前两条以 Outcome Ledger source revision fence 和 Mission CAS 原子生成结构化 Oracle proof并复算完整来源验证、event/provider-source 去重、稳定事件顺序及订单/退款投影；第三条把 Connection、Confirmed IdentityLink、Person/Company/Partner、Opportunity/Buying Committee 的精确传递闭包与 Outcome normalization 分成独立 Oracle sources，并在同一 SQL 事务逐记录 fence revision；第四条绑定显式父 Mission、继承 Operating Contract，并以合同窗口、当前身份闭包、验证 cutoff 和 typed count/minor-unit Money 复算 KPI；第五条要求 source-verified 触点，只有独立验证且精确绑定 provider/Receipt/payload 的 Effect 可获得 VerifiedIdentity 优先级，否则使用 last-non-direct，同时保留 first-touch/Unattributed 且禁止因果宣称；第六条保留原订单、跨期退款和当前 refund-set Commission revision，按 Supply Class 隔离官方网络事实与 Hartevo 重算，并只用独立核验到账事实做 partner/currency/provider 对账。父 Mission、触点 Mission、Outcome、Identity、Partner policy 与 Effect support revisions 均与 VM-11 CAS 同事务。第八条进一步绑定 action、decision digest、父 Mission revision/contract digest 与当前 route revision：Stop 形成 typed `Completed` 并把 `candidate_learning` 标为 `Skipped`；Continue 只复用仍为当前的冻结父合同并启动既有合法下一 Checkpoint；Scale/Test 保持当前 route 为 `WaitingUser`，等待完整 revised/experiment contract 的独立授权，不从 action 合成合同。exact replay 不追加 Event/Outbox，任一 source drift 失败关闭。当前机器合同覆盖 8/52，其余 44 条显示 `NOT_IMPLEMENTED`，旧 Catalog digest 显示 `BLOCKED_CATALOG_REVISION`。Desktop 只在 Runtime+Ready 时构造 Runtime command，且尚无第八 handler 的 caller/UI wiring。Catalog cadence 编译为 interval/event/hybrid Schedule；Outcome+Schedule、signed inbound+signal、Schedule claim+Mission cycle start 都是单事务。该实现是本地 E2；OS wake/sleep-resume、Cell leader/多 Worker、公平调度、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human route、redirect 和手工 revise/requeue UI 尚未完成。

用户可见文件继续留在所选项目目录；内部数据库位置、备份和迁移必须明确记录。

### 4.4a Cloud Cell Store

US/EU Cell 使用独立 PostgreSQL 数据库和 `hartevo-cloud-storage`：

- 数据库启动时绑定唯一 `us|eu` Cell，tenant 注册、项目、对象版本、Event 和 Outbox 全部使用 `cell + tenant + project` 复合作用域；
- tenant 表强制 Row Level Security，事务用参数化 `set_config` 注入 tenant/Cell，上层过滤与 RLS 同时生效；运行角色不得具有 superuser 或 `BYPASSRLS`；
- 个人项目正文只接受带 key version、12-byte nonce、AAD digest 和 ciphertext digest 的认证密文；Cloud API 没有 plaintext body 类型；
- Cell schema v4 继承 v3 的 RLS/FORCE RLS 设备公钥、keyring bootstrap、handoff Grant/Revocation/Claim/Consumption、Effect fence/rate-limit/terminal recovery，并增加 reconciliation head/attempt；只接受公钥、密文、范围、revision 和 digest，不接受设备私钥、Project key 或项目正文；
- 每次同步变更在同一事务写 append-only object version、CAS head、Domain Event、Outbox 和 idempotency ledger；同 key 不同 digest 必须拒绝；
- 终态 ContextCapsule 的 tombstone 是当前唯一开放的删除类型；Cell 在同一事务把 head 置为永久 tombstone，并清除该对象更早的 version、Event、Outbox 与 mutation 密文。精确 idempotency replay 保留，任何后续 upsert 或 object-kind rebinding 永久拒绝；
- Outbox 用 `FOR UPDATE SKIP LOCKED`、lease generation 和精确 owner/generation ACK；旧 generation 不能确认新租约；
- PostgreSQL L2 必须在非超级用户真实数据库运行 migration、RLS、跨 tenant 隔离、CAS、幂等和 lease takeover。缺环境显示 `BLOCKED_ENV`。

### 4.4b Project Key 与本地—Cell 同步协调

- `PersonalE2ee` 要求 Device 与用户自持 Recovery envelope；`TeamEnvelope` 要求至少一个可用 Member/Device envelope。数据库只保存认证加密后的 Project key，不保存明文 key 或 wrapping key。
- LocalEncryptedSync 项目必须由用户显式选择 US 或 EU；选择进入 Project revision 后不可原地切换，迁区必须走独立 export/import/re-encryption 流程。选择、首个 ProjectMetadata 密文和 durable 注册请求同一 SQLCipher 事务提交。
- 增加成员/设备、切换远程执行、签发 Worker envelope、撤销和轮换都要求 `actor_id + authorization evidence digest`，且授权 envelope 必须是当前可用的 Device/Member；Worker 与 Recovery envelope 不能管理 keyring。
- 团队项目只有显式 opt-in 才能获得 Worker envelope。Worker key 最长 15 分钟且绑定 tenant/project/worker/key version；opt-out、成员/设备撤销和内容密钥轮换会撤销现存 Worker envelope。
- 撤销长期 recipient 与生成新内容密钥 envelope 在同一个 keyring revision/CAS 中提交；新版本不得再次包给被撤销 recipient，旧 revision 不能覆盖新状态。
- 新设备附加不是直接改写 keyring：AuthorizedRecipient 与 Personal Recovery 两条路径先持久化 exact `DeviceAttachment`（来源 recipient、目标 device、key version、期望 keyring revision、sealed envelope、intent/idempotency digest），再以单一 CAS 原子提交 keyring 新 revision 与 Applied；崩溃后只能复用原 Prepared envelope，同 key 改意图或旧 revision 进入 Conflict，冲突孤儿 OS Secret 必须补偿删除。Recovery 只允许 PersonalE2ee 专用入口，不能获得成员管理、远程执行或轮换权限。
- 无共享 recipient 或 Recovery secret 的新设备使用公钥 handoff：目标设备生成 X25519 私钥并只写 OS Secret Store，发布可轮换/永久撤销的版本化公钥；来源设备以临时 X25519、HKDF-SHA256 和 AES-256-GCM 加密 Project key。Grant 的 AAD/digest 精确绑定 tenant/project/mode、来源 envelope、来源 `ProjectKeyring::canonical_digest`、目标 device/public-key version、目标 keyring revision 和有效期，Cell 不能替换同 revision 的 keyring manifest。
- Handoff 必须按 `Claim → 本地 decrypt/DeviceAttachment CAS → 发布 exact next-revision bootstrap → Consumption` 执行。Claim 与 Revocation 在同一 Grant 行锁下竞争；已 Claim 不可撤销，未 Claim 或过期 Grant 不得本地附加；Claim 后允许在 24 小时恢复窗口内完成，但同一 Grant 只能 Consumption 一次。随机 ephemeral key/nonce 和 request JSON 在 SQLCipher Prepared ledger 中 exact 重放，私钥和 Project key 永不进入该账本。
- Push coordinator 先从当前可用 envelope 解开 Project key，用 Cell、tenant、project、object kind/id、目标 revision、key version 与 tombstone 构造 AAD，再持久化 exact ciphertext request 后联网。相同 idempotency + keyed plaintext-intent digest 返回已保存请求；同 key 改变意图拒绝，避免随机 nonce 造成第二个外部动作。
- 删除协调器不接受通用 null tombstone。它生成带 tenant/project/object/kind、causal prior revision、删除代际、actor 和授权证据 digest 的强类型 `DeletionTombstone`；只有 Accepted/Cancelled/Expired ContextCapsule 可进入该路径。本地投影、旧 outbound/inbound ciphertext 与 deletion ledger 同一事务提交；普通 outbound/inbound 在发现 ledger 后必须拒绝复活。传播表面 LocalProjection、EncryptedCell、ContextDerived、Cache、Replay、ObjectStorage 独立记账，未完成表面不得折叠成“删除完成”。worker-managed 表面使用 durable claim/heartbeat/retry/dead-letter；只有当前 lease generation 提交的 exact-scope `DeletionPropagationReceipt`，且 pre/post scan digest 有效、matched=deleted、residual=0，才能单调晋升表面状态。
- Cloud applied revision 或 optimistic conflict 必须回写本地 operation ledger；瞬时网络错误保留 Prepared 请求供 exact replay。Pull 先持久化 exact ciphertext，再使用对象原 key version 和同一 AAD 从落盘副本解密；仍获授权的 recipient 可读历史版本，被撤销 recipient 失败关闭。
- 明文同步体使用版本化 `SyncDocument`，重复声明 tenant/project/object/kind 并与认证 AAD 交叉校验。ProjectMetadata、ProjectTruth、Mission、WorkProduct、Conversation、ConnectionMetadata、CreatorWork、OutcomeLedger 与 ContextCapsule typed projector 在同一 SQLCipher 事务更新规范化 aggregate 与 inbound head。ContextCapsule snapshot 只携带精确 Truth revision 与 typed 引用，并把 capability/budget/data policy 限制为 Workspace 与 Mission authority 的子集；Branch lineage、lease/generation、authority digest 和 return contract 必须精确一致，旧 generation 或本地分叉不能覆盖。OutcomeLedger snapshot 仍是精确传递引用闭包并强制来源—身份—订单—退款—佣金链。Conversation 与 CreatorWork 继续分别验证完整控制/Consent 链和雇佣—交付—Review—付款链。只有当前本地 aggregate revision 等于上次远端 projection revision 才能前进，否则进入持久 `Conflict` 并保留本地状态。
- Project 注册只有远端 `create_project` 返回 revision 1 并回写本地 Applied 后，普通 mutation 才能 dispatch；不同 Cell、Conflict 或仅 Prepared 均失败关闭。瞬时网络错误保留原注册密文供 exact retry。
- Cell 选择只能通过注册 Saga 内部的 Project CAS 落盘；公开的通用 Project create/save/update 路径拒绝预选或改变 Cell，底层 sync prepare/stage 同样要求 exact Cell 的 Applied registration，避免 Application 下方出现绕行路径。
- Effect claim 的持久状态先进入共享纯决策函数；除“无记录”外任何状态都不返回 Provider execution permit。Broker 先做 `context=None` 的 recovery probe；无 ledger 时只返回 `AuthorizationRequired` 且不写 quota/idempotency/attempt，随后才允许 fresh authorization claim。Receipt 后允许崩溃恢复 verification，但每次新的 verification lease 都提升 generation，SQL 更新只接受当前最大 generation。Provider rejection 或 Verification 直接返回带首次 execution start 的 typed durable evidence。Provider `uncertain` 只能由无执行权限的 `EffectReconciler` 持只读 reconciliation lease 查询：ReceiptFound 转 verification-only，NotExecuted 要求新的 Effect/Approval，StillUncertain 按冻结 policy 退避并最终 Dead Letter，ProviderRejected 只投影失败；旧 generation 和 policy 扩张失败关闭。
- L1 用随机动作序列验证 Keyring、Registration、Inbound Head、Truth、Partner、IdentityLink、Connection、Consent、Conversation/Campaign/Opportunity、CreatorWork、Outcome、ContextCapsule/WorkerLease、WorkerMailbox、Runtime Recovery 与 Outbox 的单调、原子、不可变和 CAS 不变量，并用 `loom` 枚举两个竞争 claimant 的所有受支持调度；这些测试不将 SQLite/PostgreSQL 真实故障环境误报为已覆盖。
- 当前实现证据仍停在 E2。repair 前 checkpoint 的全工作区记录为 492 passed、0 failed、4 ignored；对应 Catalog Snapshot/Schema/VS-01、严格 Clippy 与 Dioxus bundle 门禁见 Current Worktree Evidence。DOC-47 未在 repair 后生成新测试计数或 Catalog digest。绑定旧 commit 的 Release Evidence 2.2 baseline 保持 `passed: false`，其中 7/52 是该历史快照，不能替代当前 v8 Registry 的机器合同事实 8/52、44 条 `NOT_IMPLEMENTED`。Desktop 协调器可在同一 Mission 内重试 Prepared recovery、原子退役耗尽 generation、创建 successor generation，并通过 `thread/resume` 恢复已绑定 Thread；`Uncertain` 与 `Completed` Turn 均抑制重放。完成消息只形成可审阅草稿，并与 Assistant Conversation、Work Product/Manifest 和 Context 终态原子提交。v39 的本地测试证明 spawn-before-ledger Claim、精确孤儿回收和提交间隙恢复；v40～v47 的定向证据覆盖 cadence/cycle/lease/expiry/dead-letter、123 个 Capability/executor/Oracle/policy route、Human confirmation 双 CAS、VM-11 结构化 Human decision、Runtime delta 私有链/重组/迁移、`effect_readback_v2` typed persistence/generic-completion refusal，以及 VM-11 `event_ingest → normalize_dedupe_order → identity_chain → mission_specific_kpi → attribution_and_unattributed → refund_commission_payout_recalc → outcome_review → next_contract_or_valid_terminal` 的八次 source-fenced proof。第八条把 Stop 收束为 typed terminal、Continue 约束为 exact frozen parent contract、Scale/Test 约束为 `WaitingUser` 授权边界；完成与原子 next-route 均不构造错误的 Runtime/Effect。Desktop 现另有 exact Project/Mission-gated Runtime private-text 只读投影、重启 replay、terminal draft 去重与本地 follow-unseen，以及 VM-11 第八 handler 的 Desktop data-plane caller、Mission composer 窗口动作与 data-plane Journey。该证据仍不包含 credentialed Runtime success、生产 tokenizer/model-revision、生产级 OS/Cell Scheduler、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human route、新 Catalog Mission 首轮 execution-time handle/subscription、durable pause/resume/reconnect cursor、真实高密度 process/artifact/capability 投影、Provider readback/Verification、外部 process-kill/整机断电、PostgreSQL 等价性、Windows/多平台原生矩阵或十二条 Mission 的 Dioxus E3 Journey。

- Desktop crate 在 repair 前 checkpoint 记录有 37 个默认测试，除既有安装密钥/SQLCipher、Recovery、Catalog、Runtime、Schedule 与诚实投影外，覆盖 exact Project/Mission-gated Runtime private-text read-only query、redacted Debug、重启稳定性、append-stable paragraph/terminal dedupe 与 Dioxus stream contract，并继续覆盖 VM-07 Human Checkpoint 原子确认→下一 Runtime route，以及 VM-11 empty-ledger block→source-verified `event_ingest`→独立 `normalize_dedupe_order`→精确 `identity_chain`→父 Mission `mission_specific_kpi`→诚实 `attribution_and_unattributed`→非空订单 `refund_commission_payout_recalc`→确定性 `outcome_review`→Human `continue_stop_scale_test`；这七条 Desktop-integrated Application handler 都证明不构造错误 executor 的 Runtime 或 Effect。第八条 `next_contract_or_valid_terminal` 现另有 Desktop data-plane caller、Mission composer 窗口动作与 data-plane Journey：generic Application completion 继续失败关闭，Stop typed terminal、exact replay 与零 Runtime/Effect 由该 Journey 证明。最终全工作区计数必须由新的 clean checkpoint 门禁生成；Dioxus bundle、窗口视觉/AX 与 native Keychain 必须分别取证，任何宿主阻塞都保持 `BLOCKED_ENV`。该切片仍为 E2，不构成 VM-00/VM-07/VM-11 E3。

### 4.5 OpenInterpreter Runtime Adapter

当前冻结的 App Server v2 子集只映射：

- client request：`initialize`、`thread/start`、`thread/resume`、`turn/start`、`turn/interrupt`；
- server request：`item/commandExecution/requestApproval`、`item/fileChange/requestApproval`；
- notification：`thread/started`、`turn/started`、`item/started`、`item/agentMessage/delta`、`item/completed`、`turn/completed`。

未在固定 schema 中的 thread read/archive、turn steer、Provider/Model/Harness 配置、MCP/Skill/Plugin/Hook 与更细 item 类型当前均不是已实现声明；新增方法必须先更新冻结合同和 digest，再通过 adapter contract test。

Supervisor 以 newline-delimited JSON-RPC 启动绝对且 canonical 的程序/工作目录，清空父环境后只继承路径、locale 和临时目录白名单，再加入显式且经过注入变量检查的配置。stdout/stderr 由两个独立有界 reader 消费；单行最大值、deferred event 数和 channel 容量都有硬上限。stdout 必须匹配 pending request 或合法 server request/notification；未知 response、重复 server request ID、非法 envelope 和超长行都会把本 generation 标记为 poisoned。stderr 和 malformed payload 只向外暴露 byte count、category、SHA-256 digest 与 truncated 标志，不暴露原文。

子进程仍使用 `command-group` 管理 Unix process group/Windows Job Object；Fake Runtime 覆盖 correlation、backpressure、环境清洗、健康、`thread/start|resume`、approval/interrupt 和后代清理。当前 revision 另用冻结的真实 OpenInterpreter 二进制在隔离 home 中证明 credentialless adapter/Application 失败关闭，不伪造 Work Product 或 Mission 完成；Desktop coordinator 的确定性 Journey 证明同 generation retry、耗尽 authority 原子退役、successor generation、bound-thread resume、私有 draft 原子采用和 pre-Turn steering 撤权。v39 在 spawn 前持久化私有 Process Claim；pinned Runtime 每 Claim 使用唯一 launch 副本，启动恢复同时验证 PID/start epoch/executable/runtime digest 与私有 token/唯一路径标记，再以 descendant-first 有界终止。测试覆盖真实遗忘 process handle、Claim cleanup/Recovery update 提交间隙、幂等 replay 与无 launch residue；检查或终止失败保持 `Blocked`，不按 PID 猜杀、不启动第二个 Runtime。credentialed success、Windows Job Object 实机、provider/model switch、外部 process-kill/断电、PostgreSQL 等价性和完整 Mission continuity 仍未取得证据。

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
- 达人/Partner 建联、Creator Task 发布/接受、Deliverable 上传/Review、联盟和 Payout 动作。
- 广告预算、付款和其他高风险动作。

每个 Effect 必须包含 Project、Mission、Actor、Capability、Scope、Consent、Approval、Idempotency Key、Cost Boundary 和 Expiry。执行后保存 Receipt，由独立 Verifier 判断真实结果。

Approval 的 permission digest 同时覆盖完整 Policy 配置与当时的授权证据；仅修改相同 version 下的额度、能力或 rate-limit 配置也会使旧审批失效。Approval 自身的 `valid_until` 必须精确等于 Operating Contract 审批时长、Effect expiry 和 Contract expiry 的最早值；缺失该字段的 legacy snapshot 按已过期失败关闭，Effect 尚未过期也不能延长 Approval。SQLCipher 执行 claim 把 Connection、Consent、Conversation control 与 CreatorContact 的精确 revision/generation 作为 fence，在同一个 `IMMEDIATE` 事务内重验 fence、按 tenant/project/provider/account/capability/policy/rule 固定窗口占用 quota，并创建 idempotency/attempt。授权先变化则 claim 失败；claim 先提交则该 dispatch 在线性化点有效。denied claim 只写 rate-limit decision，不写 idempotency 或 execution attempt。若进程在 durable Receipt/Provider terminal/Verification 已提交而 Mission snapshot 尚未保存时崩溃，recovery probe 以首次 execution start 证明原 dispatch 位于精确 Approval 窗口，然后只投影 Receipt→Verification、Provider rejection→Failed、Provider uncertainty→VerificationRequired 或已落盘的 rejected/inconclusive/confirmed Verification；当前 Approval、Connection 或 Consent 后来失效不会授权第二次 Provider 写入。真正的 Provider `uncertain` 只进入独立 reconciliation 账本：Reconciler API 没有执行 lease/审批参数，ReceiptFound 还要通过原 dispatch window 与 digest 检查才获得 verification lease；NotExecuted、ProviderRejected、重试耗尽和 Dead Letter 都是不可自动重放的显式终态。Receipt/Verification/reconciliation scope、状态、时间或 digest 不一致时在新 lease 前失败关闭。Cell schema v4 和 `PostgresCellStore` 已实现同一状态机及 RLS/Team-only 执行边界，并有非超级用户 CI 合同验证双连接串行、reconciliation lease 竞争与重连恢复；当前开发机仍无真实 PostgreSQL L2，且本 revision 的 CI Evidence 尚未回填，因此不能据此宣称 Cell Effect 已完整实现。

Conversation 回复额外绑定 `conversation_id + person_id + provider + connection_id + account_id + message/content + authorization evidence + control_generation + prepared scope digest`。准备消息与创建 Mission Effect 必须在同一 SQLCipher 事务提交；人工接管或暂停递增 generation，并在同一事务把 Conversation 待发记录和对应 Mission Effect 取消。只有带 evidence digest 的显式恢复能回到 Agent control；Resolved、Closed 与 DeadLetter 会再次 fence generation，不能恢复或外发。Effect Broker 在审批和 Provider 执行前都重读 guard；审批后接管必须在 claim/Provider 调用前失败关闭。Provider 接受状态不确定时，Mission 进入 `VerificationRequired`、消息进入带原 Effect ID 的 `Uncertain`，后续自动回复和自动重放都被冻结，直到显式 reconcile。Sent 只有在 Receipt、provider event digest 与独立 Confirmed Verification 精确一致时成立。

Creator 定向邀请额外绑定 `hiring_id + creator_id + partner_id + invitation scope digest + contact-permission evidence digest`。Effect 获批不冻结联系许可：Broker 在 Provider 调用前必须重载 Hiring、Candidate、Invitation 和当前 Partner permission，任何撤回、换号、换候选或 scope 漂移都失败关闭。Creator Application 只能引用已独立验证的 Invitation 或 Listing；用户 Award 是不可伪造的持久领域事实，绑定唯一 Application、Offer digest 和选择证据。Creator Task Store 在创建任务时重新读取该 Award，结构相似但未持久化的 payload 不能越过雇佣阶段。Payout `uncertain` 的专用 Application 路径在查账前重验 Award→Task→Deliverable→Review→Funding/Account/Amount 全链；ReceiptFound 和独立 Verification 成立后，Mission Effect、Creator Payout、`contract_usage_granted` 与双份审计事件在同一 SQLCipher 事务 CAS，精确重复投影直接返回现有付款而不新增记录。

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

当前 Browser B0 已实现 Rust `browser-adapter` 的 Project/Mission/Profile/账号作用域、append-only lease generation、typed Action/Snapshot、确定性 Fake Browser Host、Effect executor、SQLCipher v32 投影和 Application takeover/continue/restart Journey。B1a 另有受管理 Chromium Host：canonical executable/profile binding、私有 marker 与 OS lock、清洗环境、无 TCP debug port 的 Unix remote-debugging pipe、有界 frame/stderr 和窄 CDP allowlist；测试专用 mock keychain 模式必须显式开启，生产默认不使用。导航 manifest 由 `url`/IDNA canonicalize 后固定为最多 64 个 exact HTTPS origin，target 是 policy 授权后才能构造的 opaque capability，fragment target 先行拒绝；同一 Tab 不允许静默换 policy。Host 在导航前调用 `Emulation.setScriptExecutionDisabled`，再用 Fetch Request-stage fence 对主请求、redirect、iframe 与子资源逐项重验 live lease/exact origin；完成必须观察相同 frame+loader 的 `load` 与 `networkIdle`，readback 最终 URL，并发行只含 digest、计数与 generation 的 Navigation Receipt。每次导航先作废旧 Snapshot/ref；每次 AX 观察前后也核对 root frame ID、loader ID 与 URL，发现页面自主变化便单调推进 document generation 并拒绝旧观察。Stable locator 是不可序列化的一小时 capability，精确绑定 Workspace/Tab/Identity/Origin/Policy 与 canonical accessible role/name；Debug/Resolution 只出现 selector/evidence digest，当前 AX 中必须恰好一次匹配，重复 label 不会被标成 unique。AX `ignored=false` 仍不等同 viewport 可见或 hit-test 安全，故真实 Host 的 AX ref 保持 `visible=false`。B1b 不把该标志直接翻转，而是在 exact Effect 执行内重新验证最新 Snapshot 和 AX candidate，读取目标 DOM 子树并拒绝 disabled/hidden/inert，滚动后取得 content quad 与 CSS visual viewport，只在遵守 pointer-events 的 `DOM.getNodeForLocation` 命中目标或其子节点、frame/URL/lease 再次相同后，发送一次 `Input.dispatchMouseEvent` pressed/released。B1c 的文本输入只接受空白、可编辑、非密码的 text/email/search/tel/url/textarea：cleartext 仅驻留 `Zeroizing` buffer，不进入 Action/Debug/Receipt；执行重验 live AX/DOM/geometry/hit-test/lease，`DOM.focus` 后以 `Input.insertText` 输入，并删除 AX 原值后只比较 digest。窄 B2 文件选择要求 exact leased File Grant 和复核后的 staged digest/type/size/scanner evidence，目标必须为可见启用的 `<input type=file>` 且 `accept` 相容；`DOM.setFileInputFiles` 请求为敏感零化 buffer，AX 只产出 selection digest。Action payload 绑定完整 locator resolution 与内容/Grant digest；tamper 和重复 executor 使用在输入前拒绝。发送开始后的错误保守标为 `uncertain`，成功 Click/Text/File evidence 只含 digest/generation 且固定 `business_verified=false`；File Grant 保持 `Leased`，本地选择既不消费 Grant，也不代表 Provider 已上传、表单已提交或交付已完成。跨 origin 请求、下载、dialog/file chooser 或 lease 过期均失败关闭。Fetch pause 可能发生在浏览器 speculative DNS/TCP 之后，因此合同只声明阻止非许可 HTTP request dispatch，不声明零网络建连。schema v33 File Broker 进一步绑定 Project root、路径/类型/大小/scanner evidence、exact lease/payload/claim、跨进程 lock、单次消费和重启 reconciliation。Signed Recipe 基础使用独立 Candidate/Production Ed25519 key purpose；Promotion 固定 V1/V2、安全、污染、回滚和审批证据，Registry 只允许 immutable version 与单调 CAS activation。schema v34 将 Trust Key 安装/撤销、immutable Candidate/Release、append-only Activation 和 CAS Head 持久化到 project-local SQLCipher；完整公钥、签名 Manifest 与 eval evidence 只在加密 record，Event/Outbox 只留 digest。恢复按 authored/promoted/activated 历史时间验证签名链，当前派发再重验 active head 和 key revocation；head rollback、projection tamper、陈旧 CAS 和缺记录失败关闭。Prepared Plan 把 release/activation、selector Resolution、policy、typed Action 和 exact Effect payload 一起绑定；Application 还先复核 Mission capability，并从当前 Fake Host World 解析 locator。恢复后 Recipe-aware Executor 在派发前重新验证 active release、key revocation、Resolution 和 Effect，普通 Executor 默认拒绝 Recipe Batch。Host 在每条动作前重验 live lease；Click、键盘、上传和 authenticated fetch 的风险等级不能由调用方降为 read-only，`PageScript`/raw `Protocol` 仍未纳入任何已签名 Recipe step，因此一律拒绝。接管后持久化失败会保持 Host 在更严格的 user-controlled 状态并返回显式 reconciliation error；交还先持久化授权，Host 失败时同样保持 live Host 收紧。该证据只计 Browser 组件 E2；active-script/authenticated navigation、Profile Cookie、登录/MFA、通用键盘、非空字段替换、密码输入、跨动作恢复、截图、生产 scanner、Recipe 生产 root-key 管理/轮换、Cell/跨设备同步、首个真实 Provider Recipe、真实 Chromium Recipe smoke、真实 Provider upload/readback/独立 Verification、Windows 实机和 Dioxus Browser UI 仍未实现。

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

当前 C0 实现进一步规定：Working Set replace 使用 CAS revision；TTL 到期保留为显式 `Expired`，不能被 assembler 静默选入；Continuation 只允许在当前 Mission revision 上追加且历史前缀不可改写；Compaction source range/ordinal 单调，模型、route 与配置以 digest 冻结；Checkpoint 必须与同事务 Compaction 的 invariant 完全相同。摘要正文无权补齐或改变 typed invariant，任何 Goal/Constraint/Truth correction/Pending Effect/Receipt/Verification 差异都会失败关闭。

当前 Context Assembler 本地 E2 实现把上述合同落实为两种不同对象：只在调用期间存在、可交给 Runtime 的 `RuntimeContextEnvelope`，以及可持久化但不含正文的 `ContextAssemblyManifest`。组装顺序固定为 Foundation/Invariant、Checkpoint/Continuation、授权 Truth/Evidence/Work Product/Effect、文件或查询快照、最后才是可选对话与工具引用；每个 frame 都受 Capsule data policy、digest、TTL、byte/token budget 和当前 authority revision 约束。相同 assembly ID 只允许精确重放，同一逻辑输入在缺失 material 后恢复时可以创建新的 evidence ID，避免把首次阻塞永久缓存成成功。

当前 C1 本地实现进一步规定：`WorkerHandle` 绑定 Capsule/Branch/Lease、parent worker、generation、attachment epoch、runtime mapping、能力、预算、累计用量和 cursor；child 能力与预算只能缩小。只有 `Claimed|ResultSubmitted` Capsule 允许 Worker 消费消息或记用量。Mailbox 是容量不超过 1024 的严格顺序队列，每次只能有一个 in-flight；detach 后 reattach 必须提升 attachment epoch，旧 epoch claim 被重排且无权 ACK。Handle cursor、Mailbox header、规范化 Message 与 Event 同事务推进，注入 Mailbox update 故障时全量回滚。Accepted child Capsule 先原子完成 Branch/Handle，再由显式 typed merge 把 result/evidence digest 追加进 Continuation；merge 不获得 Mission、Truth、Work Product 或 Effect 写权限。

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
