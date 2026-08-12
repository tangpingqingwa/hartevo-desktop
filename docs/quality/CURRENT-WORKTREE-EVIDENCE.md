# Current Worktree Evidence

状态：**开发机快照，不是 Release Evidence**
观测时间：2026-08-12
Commit：以 `git rev-parse HEAD` 返回的 checkpoint commit 为准；文档不内嵌自身 SHA，避免自引用改变提交内容

本文件只记录当前工作树实际执行过的证据。任何较早文档中的测试数量快照均以本文件为准；机器生成的 Release baseline 仍是 `passed: false`，因此不得把这里的本地通过解释为 Mission E3、Provider E4、GA 或 E5。

## 自动门禁

- `cargo fmt --all`：通过。
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`：通过。
- `cargo test --workspace --all-targets --all-features --locked`：**473 passed、0 failed、4 ignored**。这里的 473 是 Rust 测试数，与 Dataset Registry 的 420 个 Mission Case 是两个独立计数。
- 四个默认忽略的环境测试随后逐个显式运行并通过：
  - 真实 OpenInterpreter adapter、隔离 home、无凭据失败关闭；
  - 真实 OpenInterpreter Application Journey，持久记录失败且不伪造完成；
  - 真实 Chrome remote-debugging pipe/AX Journey；
  - Application→SQLCipher→Chrome takeover/restart/continue Journey。
- 本轮使用冻结 release 的 `open-interpreter-package-aarch64-apple-darwin.tar.gz`；archive SHA-256 `78f1b18e…bd411` 与 entrypoint SHA-256 `7a9499f7…bd8` 均精确匹配 Artifact Catalog。最终 mission-specific-KPI worktree 以两个独立 Home 显式重跑；adapter 真实测试在 118.54s 通过，Application 真实测试又在新 Home 中于 140.98s 通过；只证明无凭据失败关闭，不证明 credentialed success。测试后未发现 `.hartevo-runtime-launches` 子项。真实 Chrome pipe/AX 测试在 4.11s 通过；最终 Application takeover/restart Journey 于 1.14s 再次通过。Chrome 测试均使用独立临时 Profile 和显式 mock keychain，不读取用户 Chrome Profile 或钥匙串。测试产生的 230MB 冻结包与两个隔离 Home 已移动到系统废纸篓，可恢复且不留在工作区。
- `bash scripts/check-openinterpreter-schema.sh`：上游 `rust-v0.0.34` source、wire method、schema、checksum、LICENSE 与 NOTICE 通过；脚本还把 `SOURCE.toml` 的 commit/release/上游与 vendored digest 反向校验。此前 checkpoint 中 vendored 文件内容与声明 digest 不一致，本 worktree 已改为逐字节固定 pinned upstream LICENSE/NOTICE，不能再靠修改常量掩盖来源漂移。
- `cargo run -p hartevo-eval --locked -- validate-assets` 与 `catalog validate`：12 Mission、48 Capability、39 Provider、420 Mission Case、180 横切 Case 闭合；Catalog Snapshot v2 digest 为 `53e656a292011fb279b3df34e8a15bcd956944b2e4d224822384df9c631fa7d4`。同一快照机器可读地报告 52 条 Application route 中有 5 条 registered/compiled handler、47 条 `NOT_IMPLEMENTED`。
- Catalog export、Release Evidence 2.2 的诚实失败 baseline 与 VS-01 replay 均可生成；VS-01 replay 通过，baseline 必须明确为 `passed: false`，十二条 Mission 均为 `not_implemented`，并显式保存 `applicationHandlerRegistryVersion=desktop-2026-08-12-v5`、`5/52 implemented` 与 `47 NOT_IMPLEMENTED`。
- `dx build --package hartevo-desktop`：通过并生成 macOS `.app` bundle；工作区根存在 Desktop 与 Eval 两个 binary，因此禁止依赖 `dx` 猜测目标。
- `cargo check -p hartevo-runtime-adapter --all-targets --target {x86_64,aarch64}-pc-windows-msvc --locked`：两个 Windows 架构均通过，证明当前 `command-group`/Job Object 条件编译分支可由 Rust 编译器检查；这不是 Windows 实机或全产品构建证据。

## 本轮新增 Checkpoint Oracle、Human/Application handler 与 durable route 证据

- SQLCipher 当前为 schema v44：v40 新增 normalized `mission_schedules` ledger，v41 增加 `expired` 终态，v42 为 `mission_checkpoints` 增加精确 `route_capability_id` 与 `route_executor`，v43 再保存 `route_oracle_ids_json` 与 `route_completion_policy`，v44 扩展 Conversation message 约束以允许仅属于 user+Human route 的 `checkpoint_confirmation`。v42 legacy route 迁移后保持 identity 可审计但没有完成权限；部分 v43 route 行失败关闭。v43/v44 都有加密迁移备份、保留旧行和幂等 reopen 测试。
- Catalog v10 为 VM-00～VM-11 的 123 个 Checkpoint 按 DAG 顺序逐一绑定 Capability、`application|runtime|effect_broker|human` executor、精确 Oracle 子集和 `deterministic_evidence|work_product|verified_effect|human_confirmation` completion policy。route Capability 并集必须与 Mission authority 精确相等，route Oracle 并集必须与 Mission Oracle 精确相等；Runtime route 强制 `work_product`，Effect Broker route 强制 `effect`，所有 route 强制 `operating_state`。
- Domain completion 不再接受“任意 Mission Oracle + 任意 digest”：contracted route 必须提交完全相等的 Oracle 集；WorkProduct Oracle 必须引用 Mission 中真实 Work Product；VerifiedEffect 必须引用已独立验证 Effect；当前 Running Task Capability 必须与 route 完全一致。legacy unbound route 可以读取但永远不能完成。
- Human route 只能通过 `ConfirmHumanMissionCheckpoint`：命令同时绑定 Mission revision、Checkpoint revision、Conversation revision、Catalog/route/Oracle digest、非空用户陈述和精确 WorkProduct 集。通用 begin/complete API 对 Human route 返回 typed 拒绝，不能绕过确认。Conversation message、Checkpoint verification/completion、旧 Task completion、下一 route Task start、Domain Event/Outbox 在一个 SQLCipher 事务提交；故障注入证明任一点失败时四类状态一起回滚，exact replay 不增加 revision，payload swap 被拒绝。
- Desktop 对当前 Human+Running+`human_confirmation` route 显示 exact Checkpoint/Oracle、真实 WorkProduct 多选和阻塞原因；提交后只调用 Application Human handler，不发现或构造 Runtime，也不执行 Provider。VM-07 data-plane Journey 证明 `product_market_budget_constraints` 完成后只进入 `evidence_plan / research.discover / work_product`，Conversation 增加一条 `CHECKPOINT_CONFIRMATION`，Runtime/Effect ledger 都没有活动；Dioxus build 已通过。该 Journey 尚无原生窗口/键盘/AX 实机回放，仍是 E2。
- `/contracts/application-handlers/catalog.v1.json` 是生产 Application handler allow-list；Catalog 校验 registration 必须与 Mission/version/Checkpoint/Capability/completion policy/Oracle 精确一致，Catalog Snapshot v2 和 Release Evidence 2.2 同时导出 implemented 与 `NOT_IMPLEMENTED` 数量。当前 `vm11.event_ingest/v2`、`vm11.normalize-dedupe-order/v1`、`vm11.identity-chain/v1`、`vm11.mission-specific-kpi/v1` 与 `vm11.attribution-and-unattributed/v1` 注册，机器覆盖为 5/52；其余 47 条不会因 Catalog 已有路由就被解释为实现完成。Registry 逐 sourceKind 声明 Oracle binding；运行时要求每种来源恰好一份并逐项相等，代码读取了未声明来源、漏读来源或在来源之间调换 Oracle 责任都会失败关闭。
- VM-11 `event_ingest` 通过 `ExecuteApplicationMissionCheckpoint` 读取规范化 Outcome Ledger，而不是接受调用者自报 digest。Mission contract、Checkpoint operating state 与 Outcome Ledger 三类 source 各保存 revision、projection digest 和精确 Oracle；三类 Oracle 并集必须与 route 完全相等。`normalize_dedupe_order` 再独立构造 `OutcomeNormalizationProjection`：要求所有事件满足当前 source-verification contract，复算 event ID/provider-source 唯一性，按 occurred/received/provider/source/id 建立稳定顺序，并独立 digest 订单/退款 projection；Mission 只保存 content-free digest/count，不保存 provider source ID 或 payload。Application completion 的结构化 proof 存在既有加密 `completion_json` 中，因此 SQL schema 仍为 v44；serde default 保持旧行可读，持久 reload/sync 重新校验 scope、revision 与 digest。
- VM-11 `identity_chain` 再从同一 normalized ledger 精确加载被引用的 Connection、IdentityLink、Person、Company、Partner 与 Opportunity，不读取项目全量身份记录来掩盖断链。Domain Oracle 要求链接当前为 `Confirmed`、外部 provider/account 一致、Subject/Buying Committee/Partner 关系闭合，并让 Refund/Commission 继承已验证原订单身份；任何多余、缺失或不一致记录都会失败。Outcome normalization、identity closure 与 Checkpoint state 分成三类 source 和明确 Oracle 责任。完成事务同时 fence Outcome Ledger 与每个支持记录 revision；“缺失记录”的 absence 也能被 fence，防止 sync/recovery race 固化过期阻塞。
- VM-11 `mission_specific_kpi` 不接受本 Mission 或 UI 自报数字：Operating Contract 新增不可变 `parentMissionId`，Catalog 启动要求父 Mission 与 VM-11 同项目、非 VM-11、由同一当前 Catalog revision 编译，且 mode/market/language/audience/timezone/budget/KPI 完全继承；旧 Catalog 父合同即使业务字段相同也原子拒绝且不创建半成品 VM-11。Domain Oracle 只统计父 Mission 合同窗口内、在观察时刻前已接收且已验证的 Outcome；退款和佣金继承原订单 Mission，CRM Stage 永远不能映射为 Revenue。Count 使用整数，金额使用 `minor_units:ISO` + `Money`，支持 `at_least|at_most`，币种冲突、未知 KPI、无父 Mission Outcome、未来回调或身份闭包漂移都形成 typed block。父 Mission revision、Outcome Ledger 和全部当前 Identity support 与 Mission CAS 在同一事务 fence；证据只保存窗口、计数和 digest，不保存来源正文或 ID。
- VM-11 `attribution_and_unattributed` 只从父 Mission 合同窗口内、观察 cutoff 前已收到并 source-verified 的触点计算运营归因。经独立 Verification 的 Effect 必须与触点 Mission、effect ID、provider/account、Receipt request digest、provider identity 及 link/coupon payload digest 精确闭合，才可获得 `VerifiedIdentity` 优先级；否则只允许最新 `NonDirect` 作为运营主视图，并独立保留 first-touch 与显式/合成 `Unattributed`。所有结果固定 `causalClaim=false`。重复触点、同权威冲突、旧版无 verification 记录、错误 Effect/readback、窗口或支持 Mission 漂移都形成 typed block；父 Mission、所有触点 Mission、Identity support 与 Outcome revision 在完成事务中一起 fence。Mission evidence 只保存 normalization、Effect-support 和 Attribution projection digest 与计数。
- Outcome Ledger revision fence、Mission CAS、Checkpoint completion、下一 Ready route/Task、Domain Event 与 Outbox 在同一 SQLCipher 事务。故障注入证明来源在读取后变化会整体回滚；空 ledger 只进入可恢复 block，exact block/completion replay 不增加 revision；`uncertain` 或无事件不能自造 Outcome。v17 迁移兼容仍允许旧 event 被审计读取，但 Application 严格边界会将缺 source verification 的旧记录隔离为 `outcome_source_unverified`，绝不升级为完成。跨 tenant scope 替换、source projection digest/sourceKinds 篡改与通用 completion API 均失败关闭。
- Desktop 新建非 VM-11 Mission 时必须显式提交 metric/baseline/target/unit/direction；VM-11 改为从同项目已存在的非 VM-11 Catalog Mission 中选择父 Mission，后端重新加载并继承合同，忽略重复表单值。data-plane Journey 证明 empty-ledger block→真实父 Mission source-verified Lead 与签名 Order→原子完成 `event_ingest`→独立完成 `normalize_dedupe_order`→精确完成 `identity_chain`→确定性完成 `mission_specific_kpi`→为无合法触点的真实订单生成非空 `Unattributed` 投影→在 `refund_commission_payout_recalc` 明确 `NOT_IMPLEMENTED`；五个 handler 都不构造 Runtime/Effect。Application Journey 另注入真实签名订单和 source-verified non-direct 触点，重算非空 Attribution projection，并证明 exact replay。只有 Lead/Meeting/Stage、没有可寻址订单的父 Mission 会得到 `attribution_source_orders_unavailable` typed block，绝不以空投影完成。旧 Catalog Mission 仍显示 `BLOCKED_CATALOG_REVISION`，未注册 route 不推进 revision；Confirmed→Conflicted 会得到 durable `identity_link_unconfirmed`、exact replay 不重复写、重新确认后可从新 dispatch 恢复。
- Application 启动首 Checkpoint、人工推进后续 Checkpoint 和 Scheduler 下一周期都从当前 route 取 Capability，不再使用数组首项或 `BTreeSet` 字典序猜测。Checkpoint、对应 Running Task、Domain Event 与 Outbox 由同一 SQLCipher 事务提交；故障注入在新 Task insert 处 abort 时，Checkpoint revision、旧 Task、Event/Outbox 全部回滚，exact retry 只产生一个新 Task。
- `dispatch_current_mission_checkpoint` 会对 DAG 暴露的下一个 `Ready` 节点复用上述原子边界，并返回 mission/checkpoint revision、cycle、Capability、executor 与 readiness 的 content-free dispatch proof；Running route 的重复 dispatch 不增加 Task、Event 或 revision。Desktop 只在 executor=`runtime` 且 state=`ready` 时进入 Context/OpenInterpreter；VM-07 Human route 的测试注入了一个“若构造即 panic”的可用 Runtime，结果仍只返回 `CheckpointRouted`，证明非 Runtime route 不会因 Runtime 已配置而跨 executor 执行。
- legacy unbound route 只可审计读取；Scheduler 会以不可重试 `InvalidTrigger` 原子形成 `DeadLetter + Mission Partial`，不会猜 Capability 或重放外部 Effect。本地 Runtime Context 只接受 executor=`runtime`；VM-00 等 application/human/effect-broker Checkpoint 在任何 Context/Worker 写入前返回 typed `LocalRuntimeCheckpointExecutorMismatch`。
- Cadence 不再以“continuous 就假设 24h”代替：`interval`、`event_driven`、`interval_or_event` 分别验证 interval/topic shape。interval 以 anchor 对齐、不随执行漂移；纯 interval 的下一 due 已越过 Contract 时，当前 Outcome 合法收束为 `Completed`；hybrid 仍保留截止前被事件唤醒的最后窗口。
- 每个连续 Outcome 与 exact next-cycle Schedule 在同一事务提交；Schedule 只能为 outcome history 的 n→n+1。Catalog Mission 开始下一周期前要求上一 Checkpoint DAG 全终结，再只重置该 DAG，首 Checkpoint 进入 attempt 1，不能跳 cycle 或从页面直接绕过 due time。
- signed inbound Conversation 首次插入与 `conversation.inbound` Schedule signal 在同一事务；故障注入在 Schedule update 处 abort 时，Conversation message、signal 和两类 Event 全部回滚。重复 inbound 不生成第二个 signal。
- claim/heartbeat/failure/start 全部要求 exact owner/token digest、lease generation、有效期和 CAS revision；stale proof 不增加 failure 或 revision。`run_due_mission_scheduler_once` 的随机 token 只在 zeroizing 内存中存在，调用者与事件均不可见。
- `Schedule Triggered + Mission Running cycle n` 在同一事务；`Schedule Expired + Mission Completed` 在 Desktop 启动和 scheduler tick 前幂等原子 reconciliation；非重试错误或第五次过期 lease 则原子形成 `DeadLetter + Mission Partial`。所有终止事件明确 `externalEffectReplayed=false`，不会留下“Schedule 已终态但 Mission 仍显示 Scheduled”的假状态。
- Desktop Mission card 读取 Application projection，显示 cycle、trigger、Schedule 状态、signal、generation、到期时间和 failure count；`Scheduled` 不再提供页面级直接启动旁路。Desktop reopen 测试证明合同边界先 reconciliation 后投影，第二次重开 revision 不变。
- 对应 Domain、Storage、Application、Desktop、Runtime 并发与迁移测试已计入 473 passed；严格 Clippy 为零告警。这只支持本地 Scheduler/route/Human-confirmation 与五条 Application handler 的 E2。OS wake/sleep-resume、跨进程/Cell leader、多 Worker 公平调度、其余 47 条 Application handler、Effect Broker/Browser handler、其余 Human route 完成回写、redirect、远程 Postgres 等价性和十二条 Mission 的真实 Dioxus 周期 Journey 仍未实现或未证明。

## Catalog Conversation、Runtime draft 与进程恢复证据

- schema v36 保存机器可读 MissionDefinition/Checkpoint DAG，v37 保存 MissionConversation，v38 保存与 exact Runtime Turn evidence sequence/generation 绑定的 `runtime_turn_private_messages`，v39 新增 `runtime_process_claims`；它们由当前 v42 继续继承。完整 launch token、canonical launch path 与 exact process identity 只进入 SQLCipher 私有 record；规范化投影、Event、Outbox、Debug 与 Desktop UI 只保留 digest、状态和有界计数。
- Desktop 从 Catalog 精确启动 VM-00～VM-11，持久化 Operating Contract、首个 Checkpoint 与同一 Mission Conversation；后续 correction/steering 继续同一个 Mission，不创建第二套业务状态。
- Runtime `agentMessage` 与对应 content-free Turn evidence 在一个 SQLCipher 事务提交。完成时，私有消息只能由 exact Turn ID 取回；Work Product、Manifest、Assistant `RuntimeDraft` 消息、Capsule Accepted、Branch/Handle Completed 与 Lease Released 在一个事务原子可见，崩溃重放不重复生成产物或事件。
- 同一 Mission 的 Runtime 启动失败会在同一 generation 内按持久 recovery revision 有界重试。
- 三次进程恢复失败耗尽后，Branch、Lease、Capsule 与 WorkerHandle 由一个事务原子退役；重复调用退役命令只得到同一投影，不产生第二个退役事件。
- 下一次安全重试创建 generation 2，不创建第二个 Mission；完成消息只形成可审阅 `runtime_draft`，Mission 继续保持 `Running`，外部 Effect 数量为 0。
- 已绑定 thread 的 Turn 失败后使用 `thread/resume` 在同一 Mission、同一 generation 恢复；失败 Turn 的文本不会成为 Work Product。
- `Uncertain`、其他 active Turn 与 `Completed` Turn 都抑制自动重放；Dioxus 只对 `Prepared/Failed` recovery 或 `Failed/Interrupted` Turn 显示安全重试入口。
- 新用户 correction/steering 在落盘前会撤销上一用户代际。现覆盖三种 pre-Turn 崩溃窗口：只有 Context、Prepared Recovery 无 Turn、Attached Recovery 无 Turn；以及 Failed/Interrupted/Uncertain/Completed Turn。Branch、Lease、Capsule、Handle 与空 Mailbox 由 CAS 事务统一终止，旧进程后续写入失败关闭；Catalog Runtime 投影只显示最新用户消息代际。
- v39 在 spawn 前先提交 `RuntimeProcessClaim::Prepared`；正式 pinned Runtime 每个 Claim 使用 token-digest 命名的唯一可执行副本，spawn 后再把 PID、进程启动 epoch、可执行路径 digest 与 runtime instance digest 同 Recovery 原子提交。启动恢复必须同时匹配 exact identity 与私有 token/唯一路径标记，按 descendant-first 有界终止；若无法检查或终止则持久化 `Blocked` 并返回 `BLOCKED_ENV`，绝不退化为 PID-only kill 或启动第二个 Runtime。
- 启动恢复同时扫描“活跃 Claim”和“已经清理、但 Recovery 仍停在同一 process attempt”的提交间隙；后者会追加 `CoordinatorRestart` failure 并推进 attempt。真实子进程测试覆盖遗忘 coordinator handle、精确回收、attempt 1→2，以及 Claim cleanup 已提交而 Recovery 尚未提交的二次崩溃后 attempt 2→3；重复启动扫描为幂等。Desktop 只显示 `Prepared|Spawned|Terminated|Exited|Blocked` 与 cleanup 次数，不暴露 PID、令牌或路径。
- 两个真实 OpenInterpreter smoke 已在 v39 唯一启动副本路径上再次通过；退出后工作区与隔离 Home 均无 `.hartevo-runtime-launches` 子项。Runtime launch root 的首次并发创建改为原子 `create_dir`，`AlreadyExists` 后重新验证目录/拒绝 symlink；8 线程回归与两个并发 cleanup 测试通过。未固定 hash 的 Fake Runtime 仍只用于协议测试，不被声明为生产安全进程身份。
- Runtime executable path、Thread/Turn 私有 ID 与草稿正文不进入 Domain Event/Outbox；测试明确检查 `/usr/bin/false` 和失败/成功正文均未出现在事件 JSON。

这些证据仍是 Desktop/Application/SQLCipher/真实本地 Runtime/Scheduler 的 E2 切片，不是完整 Mission E3：总调度已能选择精确 executor，Human confirmation 有一个真实 VM-07 原子 handler，Application 有 VM-11 `event_ingest`、`normalize_dedupe_order`、`identity_chain`、`mission_specific_kpi` 与 `attribution_and_unattributed` 五条 handler；其余 47 条 Application route、Effect Broker/Browser handler、其余 Human Checkpoint、自动 handoff、OS/Cell 远程调度、redirect、十二条 Mission 的完整 UI Journey、Provider readback/Verification 与跨平台安装证据仍然缺失。

## 环境阻塞与未覆盖项

- 当前 macOS host 没有有效 codesigning identity（`security find-identity -v -p codesigning` 为 0）。显式设置 `HARTEVO_RUN_NATIVE_KEYRING_SMOKE=1` 后，真实写入在 `OsSecretStore::put` 返回 `BackendUnavailable`；Data Protection Keychain 缺 entitlement，legacy login Keychain 也不可写。生产构建不会伪造 Team ID、entitlement 或静默使用测试 keychain，原生显式初始化保持 `BLOCKED_ENV`。
- Computer Use 对当前 `.app` 的 exact revision 读取返回“Mac is locked”；不绕过锁屏。此前初始窗口 AX/视觉证据不能替代当前 revision 的 Mission Conversation、Catalog 路由与 Runtime retry UI 实机证据。
- 本机没有 `HARTEVO_TEST_POSTGRES_URL`，PostgreSQL/US-EU Cell live contract 保持 `BLOCKED_ENV`。
- Windows ARM64/x64、macOS x64、Linux x64 安装/更新/回滚与原生 UI 矩阵尚未实测。macOS 主机上的 Windows 全工作区交叉检查已尝试，但在项目代码之前被外部 C 工具链阻断：`ring` 的 MSVC 目标找不到 Windows C SDK 的 `assert.h`，vendored OpenSSL 也拒绝使用 Darwin Perl 生成 Windows Makefile；因此全工作区 Windows 构建保持 `BLOCKED_ENV`，不能由上面的 Runtime Adapter 窄检查替代。
- Credentialed OpenInterpreter success、真实模型 Provider、provider/model switch、外部 `SIGKILL`/整机断电故障注入、Windows Job Object 实机与 PostgreSQL Context/Runtime 等价性尚未完成。当前孤儿进程回收只证明 macOS 本地 pinned Runtime 的受控 coordinator-handle 丢失与提交间隙，不外推为这些平台/断电场景。
- 真实 Provider 账号、OAuth/KYC、签名/公证、Canary、12 租户 30/90 天 cohort 仍需外部环境和时间证据。

## 结论

当前 Goal 必须保持 active。现有证据支持继续开发 Wave 2/3 的 Runtime/Desktop 基础，但不满足任何 Mission E3、GA 或 E5 的完成定义。
