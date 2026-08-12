# Hartevo Desktop

Hartevo Desktop 是面向增长负责人、品牌经营者和代理团队的 Agent-native Growth AI OS 工作入口。用户用自然语言表达业务目标，Hartevo 在同一项目总调度中持续协调研究、证据、创作、渠道、CRM、达人与联盟、审批、外部动作和结果验证。

当前仓库状态：**Wave 0 机器合同已实现，Wave 1 领域/存储/安全主干与 Wave 2 Runtime/Context/Browser 基础切片正在开发；VM-00～VM-11 均达到 E1，尚无任何 Mission 达到 E3。**
当前交互版本：**Desktop v13**
技术基座：**Rust + OpenInterpreter App Server + Dioxus Desktop + Hartevo Domain Kernel**

当前工作树的可复核测试、实机证据与 `BLOCKED_ENV` 项统一记录在 [Current Worktree Evidence](./docs/quality/CURRENT-WORKTREE-EVIDENCE.md)；较早段落中的数字快照若有冲突，以该文件和机器生成的 Release Evidence 为准。

当前本地持久化版本为 **SQLCipher schema v46**。Desktop 已用 OS Secret Store 中按 canonical data-root 绑定的安装密钥显式初始化/重开 SQLCipher；已有数据库缺密钥、替换密钥或 symlink data root 都失败关闭，绝不静默重绑。Dioxus 的 Project/Mission 列表来自 `ApplicationService::desktop_inventory`，旧 demo Receipt、Verification、Completed 与假项目状态已经移除。个人项目 onboarding 会先生成只在 zeroizing UI state 中短暂存在的一次性 Recovery Kit，要求用户确认离线保存后才创建 `PersonalE2ee` Keyring 与首个持久 Mission；Recovery secret 不进入 SQLCipher 或 OS Vault，中断留下的 `NotProvisioned` 项目可由用户保存的 Kit 显式恢复。v35 Registry 只保存完整 `SecretReference`、不保存任何 wrapping/content key；v36 保存 Catalog-bound MissionDefinition/Checkpoint DAG，v37 保存同一 Mission 的持久 Conversation，v38 保存与 exact Runtime Turn evidence/generation 绑定的私有 agent message，v39 保存 spawn 前 Process Claim、exact process identity 与 append-only cleanup evidence，v40 新增 future-cycle Mission Schedule/lease/event signal ledger，v41 把自然合同到期固化为独立 `expired` 终态，v42 为每个 Checkpoint 持久化精确 Capability 与 `application|runtime|effect_broker|human` executor 路由，v43 增加 route Oracle 与 completion policy，v44 允许受约束的 user `checkpoint_confirmation` Conversation message，v45 保存 VM-11 Outcome Review、来源 fence 与结构化 Human decision，v46 保存 Runtime `item/agentMessage/delta` 私有增量链。完整 Runtime/Scheduler token、launch path、Thread/Turn ID 与 Runtime 正文只留在 SQLCipher 密文 record 或进程内 zeroizing buffer。`ApplicationService::open_project_context_material_session` 只接受 Project/Device 身份并向调用者提供 encrypted CAS 会话，不返回裸密钥。Desktop inventory 默认只载入状态和计数，标题、目标、Conversation 正文与 WorkProduct preview 均为空；只有 exact Project/Device Context session 成功后，Application 才生成已校验的可读投影。设备 wrapping secret 丢失时仍显示 Project/Mission 元数据，但正文为空、新 Mission 被阻断并显示 `RECOVERY_REQUIRED`；个人项目此时可在 Dioxus 粘贴用户自持 Kit，经持久 Attachment Saga 生成独立 successor Device envelope，错误 Kit 零副作用，只有 Context 重开后才恢复正文、preview 与 Mission 写入。旧 envelope 不会被覆盖。active key 缺失、错设备、已撤销设备、reference/projection 篡改均失败关闭，历史 key 缺失只显式列为 degraded。当前证据仍是 Desktop data-plane/Application/SQLCipher E2：任意 encrypted CAS 正文/file/query 浏览与编辑、原生窗口 AX/视觉回归、真实双设备 UI、Windows Credential Manager、整机丢失后的数据库恢复、历史密钥 handoff、CAS 删除传播/重加密/内容扫描仍未完成。

VS-01 已覆盖 Simulator 驱动的 Mission→Evidence→Work Product→Approval→Effect→Receipt→Verification→Outcome 闭环，但不连接生产账号。Runtime adapter/Application 已用冻结的真实 OpenInterpreter `rust-v0.0.34` 二进制在隔离 home 中显式验证无凭据失败关闭：失败进入持久 Recovery/Turn，不能产生草稿、业务完成或 Effect；Fake Runtime 继续覆盖成功 stream、approval/interrupt、协议中毒与恢复。真实 credentialed model success、Provider model-revision、crash/provider switch、Scheduler 和完整 Mission continuity 尚未证明。

Desktop 现在从机器 Catalog 精确启动 VM-00～VM-11，并把 Operating Contract、Checkpoint、Conversation、Context、Runtime Process Claim/Recovery/Turn、Work Product 与 Outcome 保持在同一 Domain。Runtime 的私有 `agentMessage`、`item/agentMessage/delta` 与 content-free evidence 同事务持久化；delta 逐项绑定 Thread/Turn/item、stream/evidence sequence、累计字节和 chain digest，重排、拼接、篡改与完成正文不一致都会失败关闭或冻结 `Uncertain`。完成草稿的 Work Product/Manifest、Assistant Conversation message、Capsule/Branch/Handle/Lease 终态也同事务提交；公开 Event/Outbox/Debug 不含正文。用户 correction/steering 会先撤销上一用户代际，覆盖“仅 Context”“Prepared Recovery 无 Turn”“Attached Recovery 无 Turn”和终态 Turn 四类边界；旧代际不会再出现在当前 Runtime 投影中。v39 在 spawn 前提交 Claim，pinned Runtime 使用每 Claim 唯一 launch 副本；启动恢复只有在 PID、start epoch、executable/runtime digest 与私有 token/唯一路径标记同时匹配时才按后代优先有界清理。无法安全检查或终止时保持 `Blocked` 并禁止第二次启动，不会按 PID 猜杀。Desktop 仅投影 Claim 状态与 cleanup 次数，不暴露 PID、令牌或路径。当前 `DesktopDataPlane` 会先证明当前 Device 能打开 exact Project Context，再按 Project/Mission 读取最新 Runtime Turn 的 SQLCipher delta chain；Dioxus 只对当前选择的精确 scope 做只读刷新，重启或重新选择可重放持久正文，terminal `RuntimeDraft` 精确去重，follow-latest/unseen 只保留为本地 UI 状态。新 Catalog Mission 的首轮 blocking Application 调用尚未在执行期返回 exact Mission handle，因此该首轮不能在调用返回前逐增量绘制；durable command-handle/subscription、pause/resume/reconnect cursor 和真实高密度 process/artifact/capability 投影仍未实现。该切片仍是 E2，不能把视觉 fixture、正文投影或本地 replay 称为 Mission E3，Release Evidence 继续为 `passed: false`。

v40～v46 还实现了本地 durable Mission Scheduler 与精确 Checkpoint 路由的 E2 切片：连续型 Outcome 与下一周期 Schedule 同一事务；interval、event-driven 与 interval-or-event cadence 被强类型化；Conversation signed inbound 与首次事件 signal 同一事务；claim/heartbeat/failure 只接受 exact owner/token digest、generation 与 lease；Catalog 周期只按 n→n+1 重置已终结 DAG。Catalog v10 的 123 个 Checkpoint 均按 DAG 顺序绑定 Capability、executor、精确 Oracle 子集与 completion policy，Application 创建/推进的 Task 必须匹配当前路由；Task/Checkpoint/Event/Outbox 原子提交，旧的未绑定定义只可审计读取，Scheduler 会 `DeadLetter + Partial` 而不会猜 Capability。本地 Runtime 只接受 executor=`runtime`。`dispatch_current_mission_checkpoint` 会把 DAG 中下一个 `Ready` 节点连同 exact Task 原子启动，并返回 revision-fenced proof；Desktop 只有在 Runtime+Ready 时进入 OpenInterpreter。Human route 现在有两个窄而真实的边界：VM-07 `ConfirmHumanMissionCheckpoint` 把用户陈述、双 revision CAS、可选 WorkProduct、完成和下一 route Task 放在同一事务；VM-11 结构化 Outcome decision 把冻结 Review/source fence、Continue/Stop/Scale/Test、actor/rationale/idempotency、私有 Conversation message、Checkpoint、下一 Task、Event/Outbox 原子绑定。两者都不能被通用 completion API 绕过，也不执行 Provider。Application Handler Registry 则只允许 Catalog 与当前二进制同时注册的 handler 执行；当前 VM-11 七条 handler 已覆盖 event ingest、normalization、identity chain、typed KPI、attribution、settlement reconciliation 和 deterministic outcome review。第七条把父合同、KPI、归因、结算、已验证 Effect 支出、pending Effect 计数和 unresolved cost exposure 冻结为分币种 Review，显式保留 target gap、Unattributed、outstanding settlement、pending Effect、预算超限和无 FX caveat，固定 `causalStatus=not_claimed`、`roiStatus=not_calculated`，且只能 handoff 到 Human `continue_stop_scale_test`，不能替用户选动作。用户决定完成后只进入 `next_contract_or_valid_terminal`；该 Application route 尚未实现，不能把决定本身冒充新合同或合法终态。父 Mission、触点 Mission、Outcome、Identity、Partner policy 与所有 Effect support revision 都在 Mission CAS 事务中 fence。迁移可读但缺失当前来源验证的旧事件、未确认身份、重复触点、争议身份、伪造 Effect、stale commission、重复/超额 payout、settlement authority 混用或 Review source tamper 只会阻塞。其他 45 条 Application route 显示 `NOT_IMPLEMENTED`，旧 Catalog digest 显示 `BLOCKED_CATALOG_REVISION`。合同到期原子形成 `Schedule Expired + Mission Completed`，非重试故障或第五次租约过期原子形成 `DeadLetter + Mission Partial`。该实现尚不是生产 Scheduler 或 Mission E3：还没有 OS wake/sleep-resume、Cell 多 Worker/leader、公平调度、其余 45 条 Application handler、Effect Broker/Browser handler、其余 Human Checkpoint、redirect 或十二条 Mission 的完整原生 UI Journey。

Wave 0 已建立 12 Mission、48 Capability、39 Provider 的双向 Catalog，并确定性物化 240 V0、120 个只暴露 metadata 的 V1、60 个只暴露 metadata 的 V2 和 180 个横切 Case。VM-06 v2 把 Creator Work 作为可独立运行的 `campaign` 或长期 `continuous_relationship`：Hiring/Invitation or Listing/Application/User Award/Funding Reservation/Task/Bounty/真实 Deliverable/Review/Verified Payout/Usage Entitlement 进入同一追踪链。Release Baseline 固定失败关闭，因此 E1 合同数量不能被误报成业务完成度。

Wave 1 当前已落地 Money/Truth/Identity/Consent、达人候选—动态联系许可—已验证邀请/悬赏发布—应聘—用户选中雇佣—任务—交付—Review—精确付款（含 `uncertain` 只读查账后 Mission/CreatorWork 原子投影）、Conversation/Campaign/Buying Committee/Opportunity、签名 Webhook 去重、精确 Consent 与频次、人工接管 generation lock、回复 Effect 的事务性绑定与 `uncertain` 冻结、Outcome/Attribution/退款佣金重算、最小授权 ContextCapsule、正式 Mission 周期状态机、SQLCipher 规范化存储、事务性 Event/Outbox、Effect lease/reconcile、审批授权 revision fence、durable fixed-window rate limit，以及 Receipt/Provider terminal/Verification 的 crash-gap 恢复，另有 OS 原生凭据后端、个人/团队 envelope key 和 US/EU Cell PostgreSQL 加密同步主干。

schema v34 延续 v32 的 Project/Mission-bound `BrowserProfile`、`BrowserWorkspace`、Tab 与 append-only Control Lease history、v33 `BrowserFileGrant`，并新增 project-local Signed Recipe Trust Key、immutable Candidate/Release、append-only Activation 和 CAS Head。Credential reference、完整 File Grant、公钥、签名 Manifest 与评测记录只存在 SQLCipher 私有 record；Recipe/Event/Outbox 只投影 key/recipe/provider/capability/evidence digest、版本和生命周期，不复制签名或 Manifest。B0 Fake Host 继续证明每动作 lease 重验、接管硬停、风险不可降级、Effect-bound 写动作和 Receipt≠Verification，并能从确定性 World 经过当前 lease、policy、snapshot、origin、Prompt Risk 和唯一可见 selector 生成 Locator Resolution，不由 Application 伪造。B1a 现另有 Unix/macOS `ManagedChromiumHost`：固定可执行文件身份、私有 Profile marker/OS lock、清洗环境、无 TCP debug port 的 Chromium remote-debugging pipe、request correlation、有界且 drop 时清零的 NUL frame、受限 stderr、窄 CDP allowlist、`about:blank` Target attach 和 AX tree 脱敏归一化。生产 API 只接受 canonical exact-origin HTTPS manifest；导航前禁用页面脚本，所有 HTTP(S) 主请求、重定向与子资源均经 Fetch fence 重验 live lease 和 origin，随后绑定 exact frame/loader 的 `load`+`networkIdle`、最终 URL readback、document generation 与 digest-only Receipt。AX 观察前后再次核对 frame/loader/URL，自动页面变化会单调推进 generation 并作废旧 ref；一小时 in-memory stable locator 精确绑定 Workspace/Tab/Identity/Origin/Policy 与 accessible role/name，明文不进入 Serialize/Debug，零匹配和重复匹配分别失败关闭。B1b 已把唯一语义目标接到单动作、精确 Effect-bound click：执行时重新核对最新 Snapshot/AX、DOM 子树和禁用/隐藏属性，滚动后取得 content quad 与 CSS visual viewport，在遵守 `pointer-events` 的顶层 hit-test 命中目标或其子节点后，再核对 frame/URL/lease 才发送 `mousePressed`/`mouseReleased`。B1c 进一步增加 exact Effect-bound semantic text input：只接受空白、可见、唯一、非只读的 `input|textarea`，拒绝密码与不支持类型，按 UTF-16 `maxlength` 限制；cleartext 只存在不可序列化、不可复制、drop 清零的临时对象和清零的 pipe buffer，Action/Receipt/Debug 只保留嵌套摘要，`DOM.focus` 后用 `Input.insertText`，再从已去除目标明文的 AX tree 比较值摘要。B2 的窄 managed file selection 把已经扫描并持久 claim 的 `BrowserFileGrant/FileUploadHandle` 绑定 exact file-input、`accept`、DOM/viewport/hit-test、lease 与 Effect，使用 `DOM.setFileInputFiles` 后只确认本地 selection 变化；Grant 仍保持 `Leased`，不把选择文件误报为 Provider 上传。AX ref 仍诚实保持 `visible=false`；输入开始后的任何错误都进入 `uncertain`，三类成功 Receipt 均固定 `business_verified=false`。真实环境 smoke 已验证 test-only loopback 导航、脚本未执行、跨页面 stable locator 重解析、歧义拒绝、跨 origin redirect 在 HTTP request dispatch 前被阻断，以及审批文本插入/AX readback、扫描后文件选择/AX readback、审批 click 的真实同源表单提交与有界 readback；Application smoke 另贯通 SQLCipher→Chrome pipe→takeover→应用重开→显式 continue。macOS 测试显式使用 mock keychain，生产默认不能静默降级。

Signed Browser Recipe 已进入 project-local SQLCipher E2：Candidate publisher 与 Production release 使用不同 Ed25519 key purpose；Manifest 固定 provider/origin/capability/effect class/typed steps，Promotion 必须绑定冻结 V1≥9/10、V2≥4/5、安全、污染审计、回滚和审批证据。schema v34 把 Trust Key 安装/撤销、immutable Candidate/Release、append-only Activation 与 CAS Head 原子写入，迁移前创建加密 v33 backup；完整公钥、签名和评测记录只留密文 record，审计面只留 digest。恢复会在 Candidate authored、Release promoted、Activation activated 的历史时点重放签名链，并在当前派发时再次验证 active head 与 key revocation；回滚 head、投影篡改、陈旧 CAS、撤销和缺记录均失败关闭。Application 还会核对 Mission capability，重新从 Fake Browser World 解析 locator，生成 Prepared Plan，并经过 exact Effect 派发；普通 Executor 对 Recipe Batch 默认拒绝。当前仅证明本地 project Registry 和 Fake Host，尚无 Cell/跨设备 Recipe 同步、生产 root-key 管理/轮换、真实 Provider Recipe、跨动作游标或真实 Chromium Recipe smoke。

File Broker 已具备项目根路径与 symlink escape 检查、Unix `O_NOFOLLOW`、大小/魔数/主动内容检查、必需 scanner verdict、只读 staged blob、exact payload/lease/claim、单次消费、跨进程 OS lock、schema v33 CAS/Event/Outbox 和重启时 orphan/终态残留清理；`FileUploadHandle::validate_for` 会在 Host 调用前后重新散列 staged 文件并核对 Grant/Claim/Workspace/Lease。数据库先提交 claim/终态，再把内存授权或文件删除提交；中间失败进入 reconciliation，`Leased` 不自动重放。当前 scanner 仍是测试替身；Windows reparse-point/pipe 实机、active-script/authenticated navigation、真实 Cookie/登录/MFA、密码/替换语义与 raw keyboard shortcut、跨多动作持久游标、截图、Recipe 的生产 key lifecycle/Cell 同步/真实 Provider 流程、真实 Provider 表单提交/上传 readback/独立 Verification 和 Dioxus Browser UI 均未完成。Fetch fence 只证明未向非许可 origin 派发 HTTP 请求，不声称阻止浏览器 speculative DNS/TCP 建连；当前 click/text/file-selection 也只适用于 script-disabled、同源、单一语义目标。因此这些证据仍只计 Browser 组件 E2，不是 Mission E3。

schema v46 完整继承 v35 及此前的 US/EU Cell 注册 Saga、Outcome 来源证明、Context Workspace/Branch/Worker Lease/Capsule、删除/传播、设备附加与 claim-first key bootstrap、Identity 决策历史、Effect rate-limit/reconciliation、Context Foundation/Collaboration、Runtime Recovery/Turn、content-free Assembly、tokenizer hash-only projection 和 Browser File Grant；并增加 v36 MissionDefinition DAG、v37 MissionConversation、v38 Runtime private-message ledger、v39 Runtime Process Claim/cleanup ledger、v40 Mission Schedule ledger、v41 expiry terminal migration、v42 Checkpoint Capability/executor、v43 Checkpoint Oracle/completion policy、v44 Human confirmation message constraint、v45 Outcome Review/Human decision ledger 与 v46 Runtime private text delta ledger。联合迁移门禁覆盖 fresh、v44→v45→v46、既有 v45→v46 和失败回滚。版本化 `SyncDocument` 仍以 AAD、tenant/project/object/kind 认证九类 typed projector；Outcome 的订单、退款、付款、身份与归因链继续要求可复算来源证明，事件历史不可改写，本地分叉与 support 写入仍由 savepoint 原子回滚。

Conversation snapshot 自包含 Person/Company、精确 provider/connection/account、Consent 和 Mission Effect 链；CreatorWork bundle 绑定全部候选身份、Awarded Hiring、Task/Deliverable/Review/Payout 及精确 Effect/Receipt/Verification。ContextCapsule 只投影 Mission Task 必需的精确 Truth revision、typed 输入引用、能力子集、子预算、数据策略、Branch lineage、lease/generation 和 return contract；不携带凭据、Connection token、Browser Profile、父 Prompt 或直接 Effect 执行权。Context Foundation 的 Working Set 只保存加密 CAS/typed reference、digest、TTL、classification 和 provenance；Continuation 只追加 typed entry。每次 Compaction 都从当前 Mission 与全部当前 Project Truth 重建不可丢失 invariant，Checkpoint 精确绑定 Working Set/Continuation revision、Compaction、worker graph、cursor 和 trace tail；二者同事务落盘，摘要不能补写 Goal、约束、用户纠正、Pending/`uncertain` Effect、Receipt 或 Verification。Context Assembler 以当前 Foundation、Checkpoint、Capsule authority、Branch lineage、Worker lease、冻结 tokenizer profile 和最小数据策略确定性组装短生命周期 Runtime envelope；required 缺失/过期/预算溢出、artifact digest 替换、profile 漂移或 runtime provider/model 错配均失败关闭，optional 缺口显式记账。Context Assembly ledger 不持久化 prompt 或摘要正文；Runtime Recovery/Turn/Process Claim 的规范化与审计面只保存 digest 和有界计数，v38 私有 message record 则保存 Work Product 恢复所需正文并与 exact Turn evidence 绑定。C1 本地切片新增 parent-scoped `WorkerHandle`、token/cost/usage 上限、有界 Mailbox、严格顺序 cursor、detach/reattach attachment epoch fence 和 typed child Branch merge；未 claim Capsule 的 Worker 无权消费消息或记用量，旧 epoch 无权 ACK，merge 只能把已接受的 typed result 追加进 Continuation，不能直接改写 Mission/Truth/Effect。schema v15→v16、v16→v17、v17→v18、v18→v19、v19→v20、v20→v21、v21→v22、v22→v23、v23→v24、v24→v25、v25→v26、v26→v27、v27→v28、v28→v29、v29→v30、v30→v31、v31→v32、v32→v33、v33→v34、v34→v35、v35→v36、v36→v37、v37→v38 与 v38→v39 均有迁移前加密备份或幂等安装证据；v19 中已有的未完成删除会回填传播 job。无法唯一恢复旧 Conversation Connection 的记录进入 Dead Letter，缺少来源证明的旧 Outcome 可检查但不能被静默升级为 verified 或跨加密同步边界。Effect claim、reconciliation、keyring、项目注册、删除传播 lease、设备附加 Saga、bootstrap operation、Context Checkpoint、Worker Mailbox、Runtime Recovery、Runtime Process Claim、Context Assembly、Runtime Turn、Runtime private message、Browser Workspace、Browser File Grant、Browser Recipe Head 和入站 head 继续由确定性不变量约束。

schema v21 首个安全删除范围仍仅为终态 `ContextCapsule`：强类型 tombstone 绑定 tenant/project/object/kind、前置 revision、删除代际、actor 与授权证据 digest；准备删除时同事务移除 Capsule 及不再共享的 Lease/Branch/Workspace、清除旧本地同步密文并写入永久防复活账本。Cell 只保留墓碑 revision，删除旧 version/event/outbox/mutation 密文图，墓碑后的 upsert 和对象 kind 替换均失败关闭。六个传播表面中 Local、Context 与当前无对象正文的 ObjectStorage 已有证据，Cell 在远端 receipt 后置为 Applied；Cache 与 Replay 会生成 durable job，并用 lease/heartbeat/generation、退避/dead-letter 和不可变 `DeletionPropagationReceipt` 约束清理。回执必须与 tombstone 精确同域、pre/post inventory digest 可追溯、删除数与匹配数一致且复核残留为 0，旧 generation 不能完成当前 job。仓库尚无真实 Cache/Replay 内容库与生产清理 adapter，所以实际记录默认仍保持 Pending；测试 simulator 的回执只证明合同，不能宣称生产删除传播完成。其他 SyncObjectKind 仍为保留边界阻断。

当前 worktree 的全量 Rust 回归为 **492 passed、0 failed、4 ignored**。Catalog Snapshot v2 digest 为 `0955d8873f065882795a39d26c3d9b178892c4f9b1d6e3ba91d9bbd765959dcc`，机器报告 Application handler `7/52 implemented、45 NOT_IMPLEMENTED`；绑定 c71061e 的 Release Evidence 2.2 baseline 为 `passed: false`，十二条 Mission 均为 E1/`not_implemented`，V0/V1/V2、横切、E4 与 E5 执行证据均为 0。VM-11 本地链现到 `event_ingest → normalize_dedupe_order → identity_chain → mission_specific_kpi → attribution_and_unattributed → refund_commission_payout_recalc → outcome_review → Human continue_stop_scale_test`，Review 按币种冻结 KPI、归因、结算、已验证 Effect 支出、pending Effect 计数、unresolved cost exposure 与预算状态；没有合法 FX 时不汇总 ROI，也不替用户选择动作。Human 决定后仍停在未实现的 `next_contract_or_valid_terminal`，所以没有合法循环或终态。四个默认忽略的真实环境测试（2 个 OpenInterpreter、2 个 Chrome）也已在当前 revision 逐条显式通过；这些仍只证明本地 E2。credentialed OpenInterpreter、Windows 实机、native Keychain、签名身份、PostgreSQL live、原生视觉/AX 与完整 Mission continuity 的限制不变，缺环境时保持 `BLOCKED_ENV`。完整明细见 [Current Worktree Evidence](./docs/quality/CURRENT-WORKTREE-EVIDENCE.md)。

`dx build --package hartevo-desktop` 已生成当前 macOS `.app`。此前初始窗口曾获得 AX/视觉读回且显式初始化诚实显示 `BLOCKED_ENV`；本轮 exact revision 的 Computer Use 读取仍明确返回 Mac locked，生产初始化也受 codesigning/Keychain 环境阻塞。当前 revision 的原生视觉、键盘、缩放和无障碍证据因此保持 `BLOCKED_ENV`；bundle 与 Rust tests 不能替代 L3。

## 开始阅读

只需要按下面顺序阅读，不需要查找其他 Hartevo 历史文档：

1. [PRODUCT.md](./PRODUCT.md)：产品用户、目的、边界、品牌和设计原则。
2. [macOS 开发与 Bootstrap](./DEVELOPMENT.md)：在新 Mac 上认证、克隆、准备 Rust/Dioxus 环境并完成首个工程 PR。
3. [Rust 与 OpenInterpreter 基座 RFC](./docs/product/HARTEVO-DESKTOP-RUST-OPENINTERPRETER-RFC.md)：对上游的技术审查、采用边界、Rust 栈、仓库策略和实施路线。
4. [Hermes v0.20 Rust 能力引入清单](./docs/research/HERMES-AGENT-V0.20-RUST-CAPABILITY-INTAKE.md)：哪些 Hermes 前沿机制应由 Hartevo 用 Rust 重构，哪些不能照搬。
5. [PenguinHarness Rust Harness Lab 引入清单](./docs/research/PENGUIN-HARNESS-RUST-CAPABILITY-INTAKE.md)：怎样吸收其极简工具面、Trace、Benchmark 与自我改进闭环，并修正不适合业务 Agent 的部分。
6. [Ego Lite Rust Browser Workspace 引入清单](./docs/research/EGO-LITE-RUST-BROWSER-WORKSPACE-INTAKE.md)：怎样吸收 Agent 专属浏览空间、登录复用、语义快照和人机接管，并修正闭源内核、任意脚本与 Profile 越界风险。
7. [Prime Agent Rust Context Fabric 引入清单](./docs/research/PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md)：怎样吸收其外置上下文、持久工作集、Context Branch、Worker Graph 与 Continual Harness，并修正任意 Python 执行和无边界自改写风险。
8. [Desktop 交互规格](./docs/product/HARTEVO-DESKTOP-INTERACTION-SPEC.md)：当前冻结的产品层级、信息架构和完整交互。
9. [Desktop 当前架构](./docs/architecture/HARTEVO-DESKTOP-ARCHITECTURE.md)：组件所有权、数据流、本地与云边界、安全不变量。
10. [Agent UI 组件采用规范](./docs/design/AI-AGENT-UI-COMPONENT-GUIDE.md)：如何在 Dioxus 中参考 AI CSS，并处理授权、状态语义和可访问性。
11. [质量与 Eval 入口](./docs/quality/README.md)：怎样证明 Mission 真正完成，而不只是界面或工具存在。
12. [可交互原型](./prototype/index.html)：当前产品行为的最终视觉和交互参考。
13. [Validation Ladder](./docs/quality/DEVELOPMENT-VALIDATION-LADDER.md)：从 L0 到 E5 的强制验证顺序。
14. [Dataset Registry](./docs/quality/DATASET-REGISTRY-AND-ISOLATION.md)：420+180 Case 和 V1/V2 隔离边界。

## 运行与验收

仓库固定 Rust `1.95.0`、Dioxus `0.7.10`。在根目录执行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p hartevo-cloud-storage -- --nocapture
bash scripts/check-openinterpreter-schema.sh
cargo run -p hartevo-eval -- catalog validate
cargo run -p hartevo-eval -- catalog export --output target/eval/catalog-v1.json
cargo run -p hartevo-eval -- evidence baseline --commit "$(git rev-parse HEAD)" --output target/eval/release-baseline.json
cargo run -p hartevo-eval -- run --mission VS-01 --output target/eval/vs-01.json
dx build --package hartevo-desktop
```

构建产物位于 `target/dx/hartevo-desktop/debug/macos/HartevoDesktop.app`。交互开发使用 `dx serve --package hartevo-desktop`；完整环境说明见 [DEVELOPMENT.md](./DEVELOPMENT.md)。

## 当前冻结的产品决策

- 产品层级是：用户 / 组织 → 宣发项目 → Mission → Effect、Receipt、Verification 与 Outcome。
- 每个项目只有一个持续存在的总调度关系，并为每条 Mission 保留持久会话；总调度、Mission 会话和业务工作面共享唯一 Domain State，不产生割裂事实或权限。
- 任务与 Mission 是主要工作对象，模块只是结构化工作面。
- 自然语言入口常驻；模型、推理强度和速度从同一入口配置。
- 切换项目后默认进入该项目总调度，并同步切换任务、事实、连接、审批与长期记忆。
- Desktop 本地优先；项目可以位于已有文件夹、新建本地文件夹、本地加密同步或云工作区。
- 连接成功不等于允许执行；外部动作仍受 Scope、Consent、Approval 与 Effect Policy 控制。
- Provider 返回成功不等于业务成功；必须保留 Receipt、Verification 和 Outcome。
- 长上下文不是无限 Prompt；Context Fabric 用持久工作集、Continuation Ledger、Context Capsule 和可恢复 Worker Graph 保持 Mission 连续。
- 遇到艰难技术瓶颈时，从用户目标、领域不变量与真实边界重新推导；允许重构抽象和创新架构，不把上游实现或当前框架习惯误当成不可改变的约束。

## 仓库结构

```text
hartevo-desktop/
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  Dioxus.toml
  README.md
  PRODUCT.md
  DEVELOPMENT.md
  hartevo-rs/
    application/
    catalog/
    cloud-storage/
    desktop/
    domain-kernel/
    effect-broker/
    eval/
    runtime-adapter/
    storage/
  config/
  contracts/openinterpreter/
  contracts/missions/
  contracts/capabilities/
  contracts/providers/
  contracts/datasets/
  contracts/release-evidence/
  scripts/
  third_party/openinterpreter/
  .github/workflows/
  docs/
    SOURCE-OF-TRUTH.md
    product/
      HARTEVO-DESKTOP-RUST-OPENINTERPRETER-RFC.md
      HARTEVO-DESKTOP-INTERACTION-SPEC.md
    architecture/
      HARTEVO-DESKTOP-ARCHITECTURE.md
    design/
      AI-AGENT-UI-COMPONENT-GUIDE.md
    research/
      EGO-LITE-RUST-BROWSER-WORKSPACE-INTAKE.md
      HERMES-AGENT-V0.20-RUST-CAPABILITY-INTAKE.md
      PENGUIN-HARNESS-RUST-CAPABILITY-INTAKE.md
      PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md
    quality/
      README.md
      HARTEVO-HARNESS-ENGINEERING-ROADMAP.md
      HARTEVO-EVAL-SCENARIO-CATALOG.md
      HARTEVO-COMPLETION-METRICS-SCORECARD.md
      PRODUCT-SLO-AND-EVAL-GATES.md
  prototype/
    README.md
    index.html
    hartevo-logo-mark.png
```

## 未收录的材料

本仓库只收录当前产品、交互、架构和质量合同。历史部署快照、会话交接、过期架构、早期原型、过程截图和生产账号资料均留在原项目，不进入本仓库，也不构成 Hartevo Desktop 的事实源。

## 下一阶段

1. 把 Cell schema v4 的公钥/bootstrap/grant/claim/revoke/consume 与 Effect fence/rate-limit/reconciliation typed API 接到部署后的 Control Plane HTTP/OIDC 边界，完成真实双设备 Dioxus Journey、整机丢失/历史 key 轮换恢复 UI、Windows Credential Manager 实机矩阵和 PostgreSQL/SQLCipher 双后端故障恢复一致性；同时把真实 Cache/Replay/Trace 内容库接入现有 purge job/receipt 合同并完成各对象保留/删除矩阵。
2. Context C0/C1、Context Assembler、Runtime Recovery/Process Claim/Turn、durable Mission Scheduler 与 Browser B0/B1a/B1b/B1c/B2-narrow 本地切片已覆盖 Working Set/Continuation/typed invariant/Compaction/Checkpoint、项目作用域 encrypted CAS/File/Query snapshot resolver、digest-pinned tokenizer、runtime provider/model identity binding、最小授权且预算有界的 Runtime envelope、content-free Assembly Manifest、typed Branch merge、Worker usage、bounded Mailbox、detach/reattach epoch fencing、checkpoint/config/thread/process identity binding、bounded retry、exact turn dispatch/stream/local approval/interrupt、startup full-ledger reconciliation、`uncertain` 零重放、cadence/event signal/lease generation、123 个 Checkpoint→Capability/executor/Oracle/policy 路由、route-aware Desktop selection、Human confirmation 原子 handoff、Application handler allow-list，以及 VM-11 event-ingest/normalization/identity/KPI/attribution/settlement/outcome-review 七条多来源 fence。Browser 目前证明 typed Workspace/Profile/Lease/Action、Fake Host、真实 pipe/AX、script-disabled exact-origin navigation、stable semantic locator、单一 Effect-bound semantic click、受控空白文本输入、File Broker→真实 file-input 本地选择、接管恢复、durable File Grant 与 project-local durable Signed Recipe；下一步把当前 exact Device Context session 从 Manifest preview 扩展到任意 encrypted CAS 正文/file/query 浏览、编辑与采用，并补删除传播/重加密/内容扫描，建立正式支持模型的签名 tokenizer artifact registry 和 Provider model-revision 证明，接入 credentialed OpenInterpreter，再补生产 Scheduler 的 OS wake/sleep-resume、Cell 多 Worker/leader、其余 45 条 Application handler、Effect Broker/Browser handler、其余 Human Checkpoint、完成回写与 redirect，以及 provider switch、跨进程并发/`loom`、外部进程 kill/整机断电恢复和 Windows Job Object 实机，最后补 SQLCipher/PostgreSQL 跨后端并发与恢复等价性。真实 PostgreSQL 环境缺失时继续显示 `BLOCKED_ENV`。
3. Wave 2 继续完成真实 OpenInterpreter、Context Fabric 的生产 adapter/dispatch、Browser 的跨平台 active-script/authenticated navigation、密码/替换语义与 raw keyboard、真实 Provider 文件提交/readback、截图/登录、跨动作持久恢复与独立 Verification，以及可执行 Mission Harness。
