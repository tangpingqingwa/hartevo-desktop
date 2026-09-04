# Hartevo Security、Privacy 与 Threat Model

状态：**Target Contract**

## 1. 保护资产

- Tenant、Project、Mission、Project Truth、Context Capsule、Memory 和 Work Product；
- OAuth refresh token、API key、Cookie、Browser Profile、E2EE 与团队 envelope key；
- Approval、Effect、Receipt、Verification、Order、Refund、Commission、Payout；
- Partner/Creator Identity、Contact Permission、Hiring Offer/Listing/Invitation/Application/Award、Task/Bounty、Deliverable、Review、使用权和 Dispute；
- V1/V2 私有评测内容、Judge 样本、签名插件/Recipe/Harness 和发布密钥。

## 2. 信任边界

1. 用户设备与 OS Keychain/Credential Manager；
2. Desktop UI、Application Service、Domain Kernel、Runtime 子进程和 Browser Host；
3. 个人密文 Sync 与团队 opt-in remote execution；
4. US/EU Control Plane 与 Cell；
5. 外部 Provider、Webhook、Partner/Creator 和上传文件；
6. 隔离 Evaluator、V1/V2 Store 和 Candidate Lab；
7. Build、签名、公证和 Update Repository。

## 3. 主要威胁与强制控制

| 威胁 | 控制 |
| --- | --- |
| 跨 Tenant/Project 数据混淆 | 所有 ID、查询、事件、Context、Browser Profile 和对象路径带 Tenant/Project；数据库 RLS/复合键；负向隔离测试 |
| Secret/PII 泄漏 | OS/Vault Secret Store、结构化 redaction、默认不记录正文/Headers/Cookies、日志扫描和 7/90 天保留 |
| Desktop 丢失/替换安装 key、静默重绑已有数据库，或把 Recovery Kit 托管进 SQLCipher/OS Vault/诊断 | 安装 SecretReference 绑定 canonical data-root digest；数据库存在而 key 缺失、错误 key、data-root/database symlink 一律失败关闭且不得重写密文。Recovery Kit 只在 zeroizing UI/SecretBytes/KeyMaterial 中短暂存在，Debug 固定 redacted；用户确认离线保存后才建立 Recovery envelope，持久层只保存密封 envelope，OS Vault 只保存 Device wrapping key。中断项目显式为 `NotProvisioned`，不得伪装 Ready 或自动生成替代 Recovery key。通用 Desktop inventory 只读取 WorkProduct 元数据；只有 exact Project/Device Context session 可装配 preview，设备 wrapping secret 丢失时 preview 必须为空且新 Mission 必须被阻断。个人恢复必须绑定 exact Project/keyring revision/idempotency 与用户确认 digest；错误 Kit 零 Secret/Keyring 副作用，成功时新增 distinct successor Device envelope 而不覆盖旧 envelope，并在 Context AEAD 重开后才解锁内容 |
| Prompt Injection 扩权 | 工具输出视为不可信数据；Capability allowlist、Context Capsule 最小化、Effect Policy 不接受内容内指令 |
| Approval 被偷换或以 Effect expiry 冒充审批有效期 | 完整 canonical payload digest、账号/对象/受众/资产/金额/计划/Consent/policy 绑定；Approval `valid_until` 必须精确取 Contract `validity_seconds`、Effect expiry 与 Contract expiry 的最早值，legacy 缺字段立即按过期处理，Broker 在 durable claim 前独立拒绝过期 Approval |
| 审批后 Policy 配置或授权记录发生 TOCTOU 漂移 | Approval permission digest 绑定完整 Policy digest 和 Connection/Consent/Conversation/CreatorContact evidence+revision fence；Provider 前的 durable claim 获取 SQLCipher `IMMEDIATE` write lock，在同一事务重验 revision/generation 后才允许写 quota reservation、idempotency 与 attempt；先提交的撤销/接管/permission change 使旧 claim 失败关闭 |
| 重复或不确定付款/发布 | durable idempotency、attempt ledger、`uncertain` 只 reconcile、独立 readback |
| 把 `uncertain` 当成失败自动重放，或用 reconciliation 偷渡新的 Provider 执行权 | ExecutionLease 与 ReconciliationLease 使用不同强类型；Reconciler API 不接收审批、授权上下文或 execute 能力。首次 claim 冻结 policy/max attempts/retry delay，owner+generation+attempt CAS 防旧 Worker 写入；ReceiptFound 只发 verification lease，NotExecuted 要求新 Effect/Approval，StillUncertain 有界退避并 Dead Letter，terminal projection 永不回到 fresh execution |
| Durable Effect 已提交但 Mission snapshot 未保存，重启后因 Approval/Connection 已失效而重放 Provider | Broker 先执行无授权且不写 ledger/quota 的 recovery probe；只有不存在任何 durable state 才能进入 fresh authorization claim。Receipt、Provider rejection/uncertainty 与 Verification 都返回首次 execution start，Domain 只在该时间位于原 Approval 窗口时投影；后续撤销或过期不能授予第二次 Provider write |
| 篡改 durable Receipt/Verification 状态、scope、digest 或时间以伪造成功/失败 | SQLCipher recovery 解码后交叉校验 ledger status 与 Verification status、Provider/request/response digest、Receipt ID、独立 verifier、evidence digest 和单调时间；不一致在创建 verification lease 和 Mission projection 前失败关闭。Provider rejected、Provider uncertain、Verification rejected/inconclusive/confirmed 使用不同 typed claim，不能互相降级或冒充 |
| 并发 Worker 绕过 Provider/账号/Capability 限额 | rate-limit scope 绑定 tenant/project/provider/account/capability/policy/rule/config digest；固定窗口 bucket 用事务串行和 revision CAS 计数，reservation 与首次 execution claim 原子提交，denied 只留 decision audit 且窗口结束前不执行 Provider。SQLCipher 已有本地 E2；Cell schema v4/typed API 使用 project advisory lock、RLS、Team-only opt-in 和相同 bucket/reservation/decision 合同，双独立连接争抢唯一 quota 与 reconciliation lease 的测试已接入非超级用户/NOBYPASSRLS CI，并断言仅一条 execution ledger/一条 denied audit、旧 reconciliation generation 不能提交；本机缺少 `HARTEVO_TEST_POSTGRES_URL` 时仍为 `BLOCKED_ENV`，在该 revision 的 live CI 证据落盘前不能提升远程 E2 |
| Browser Profile/Cookie 越界、调用方把写动作伪装成只读，或人工接管后旧队列继续动作 | Browser B0 以 tenant/project/mission/profile/provider/account 精确作用域、append-only CAS lease generation 和每动作 live revalidation 失败关闭；Click、键盘、上传与 authenticated fetch 固定为潜在外部写入并要求 exact Effect payload digest，调用方不能降级。Signed Recipe 使用独立 Candidate/Production Ed25519 key purpose、V1/V2/安全/污染/回滚 Promotion gate、immutable version、CAS activation 与 exact selector/policy/action/Effect binding；schema v34 把完整 Trust/Candidate/Release/Activation 放入 project-local SQLCipher 私有 record，Event/Outbox 只保存 digest。恢复按历史授权时点验证签名链，当前派发再读取 active head 和 key revocation；head rollback、projection tamper、陈旧 CAS、缺记录和撤销均失败关闭，普通 Executor 对 Recipe Batch 默认拒绝。`PageScript`/raw `Protocol` 不属于当前签名 step allowlist，继续禁用。Credential reference、Recipe 公钥/签名 Manifest/eval evidence 只在 SQLCipher 私有 record，Event/Outbox/Debug 不复制这些敏感内容。接管先硬停 Host，持久化失败也保持 restrictive；交还先持久化新授权，Host 失败不放宽 live control。B1a 真实 Chromium Host 使用 canonical executable、私有 Profile marker/OS lock、清洗环境、无 TCP debug port 的 Unix pipe、窄 CDP allowlist 和有界脱敏 AX；测试 mock keychain 必须显式开启且生产默认拒绝。导航 target 必须来自 canonical exact-origin HTTPS policy；同 Tab policy 不可替换，页面脚本先禁用，HTTP(S) 请求逐项经过 Fetch+live lease fence，跨 origin redirect、download、dialog/file chooser 与最终 URL 漂移失败关闭，旧 Snapshot/ref 在发出导航前失效。AX 观察前后复核 frame/loader/URL；stable locator 明文不序列化/不调试输出，绑定当前 Workspace/Tab/Identity/Origin/Policy 与短期有效期，零匹配、重复匹配或 Prompt Injection 都拒绝。AX 暴露不被当作 viewport visibility，真实 ref 保持 `visible=false`。B1b semantic click 仅接受单动作 exact Effect，并在输入前复核 AX/DOM/geometry/hit-test/frame/URL/lease。B1c 文本输入仅允许空白、可编辑、非密码字段；cleartext 和敏感 CDP frame 使用 `Zeroizing` buffer，Action/Debug/Receipt 只留 digest，`DOM.focus` 后的 focused AX 和输入后的值 digest 均须匹配。窄 B2 文件选择只允许 exact leased File Grant、复核后的 staged blob 与 accept 相容的 `<input type=file>`；`DOM.setFileInputFiles` 后只保存 AX selection digest，Grant 保持 `Leased`。tamper 与旧 Snapshot 在输入前拒绝；任何输入派发开始后的错误均为 `uncertain` 且 executor 不可复用。成功 evidence 固定 `business_verified=false`，文件已选择不等于 Provider 已上传、表单已提交或交付完成；Fetch fence 也不被表述成零 speculative DNS/TCP。File Broker 把 canonical Project root、文件 digest/类型/大小/scanner evidence、live lease、payload 和 single-use claim 绑定 schema v33，数据库先提交并在重启时 fail-closed reconcile。当前仍缺完整 Cookie/Profile/登录/MFA、active-script/authenticated navigation、通用键盘、非空字段替换、密码输入、跨动作恢复、截图、生产扫描、Recipe 生产 root-key provisioning/rotation、Cell/跨设备同步、首个真实 Provider Recipe、真实 Chromium Recipe smoke、Provider upload/readback/独立 Verification 与 Windows 实机 |
| Worker/Branch/Runtime/Scheduler 过期写入、executor 混淆或伪造 Checkpoint 完成 | Worker/Branch/Capsule 继续以 token digest、generation、revision、lineage、attachment epoch、strict cursor、预算与有界 Mailbox 失败关闭；Runtime 继续以清洗环境、correlation、protocol poison、Process Claim、exact process identity/token marker 和 bounded retry 阻断旧代际与 PID 猜杀。schema v40～v47 把 Schedule、Capability/executor、Oracle/policy、Human confirmation、VM-11 structured decision、Runtime private delta 与 policy CHECK 分层持久化；v47 事务性 rebuild `mission_checkpoints`，只把 `effect_readback_v2` 加入 allow-list，碰撞失败时 table/index/data/ledger 整体回滚且可清理后重试。Catalog v10 的 123 个 route 必须 Capability/Oracle 并集闭合；Runtime route 要求真实 WorkProduct。Effect route 的 `verified_effect` 必须引用 independently verified Effect；E1 `effect_readback_v2` 还要求 ReceiptCandidate 关联独立、只读 credential 的 account readback 与 canonical field diff，Receipt、corroboration、已验证 Effect 或 generic completion 单独均不能完成，伪造持久完成失败关闭。legacy route 可审计但不能完成。通用 Human route 只能通过 Mission+Checkpoint+Conversation revision 与 route digest 绑定的原子命令；VM-11 decision 还必须绑定冻结 Review/source fence、Continue/Stop/Scale/Test、actor/rationale/idempotency，并原子进入下一 Task。Application route 还要求 Registry+二进制双注册和当前 Catalog digest；v9 新增 VM-00 `vm00.local-project-identity/v1`，以同事务 Project revision fence 约束本地 `identity.resolve`；VM-11 `event_ingest`、`normalize_dedupe_order`、`identity_chain`、`mission_specific_kpi`、`attribution_and_unattributed`、`refund_commission_payout_recalc`、`outcome_review` 与 `next-contract-or-valid-terminal` 的 Mission/Checkpoint/Outcome/Identity/父 Mission/触点 Mission/Effect support/Partner policy proof、来源 fence、Checkpoint、next Task、Event/Outbox 同事务，actual sourceKinds 与逐来源 Oracle 责任必须等于 Registry。第三条 handler 要求 Connection、Confirmed IdentityLink、Person/Company/Partner、Opportunity/Buying Committee 是精确闭包，外部 provider/account 一致，退款/佣金只继承已验证原订单身份；第四条要求显式父 Mission、完全继承合同，并按合同窗口、验证 cutoff、当前身份闭包和 `minor_units:ISO` 复算 KPI；第五条只允许 source-verified touchpoint，VerifiedIdentity 必须绑定已批准、已 Receipt、独立确认的精确 Effect/provider/payload，否则只使用 last-non-direct，并始终保留 first-touch/Unattributed、禁止因果宣称；第六条保持订单不可变、退款独立和 current refund-set Commission revision，按 Supply Class 隔离网络事实与 Hartevo 重算，并且只把 independently verified payout 当作到账事实按 partner/currency/provider 对账，不越权宣称付款已授权；第七条把 KPI、归因、结算、已验证 Effect 支出、pending Effect 计数和 unresolved cost exposure 与预算绑定同一父 Mission/ledger/cutoff，并按原币种独立复算，不允许隐式 FX、ROI、因果或自动 Continue/Stop/Scale/Test；每个来源 revision 逐条 fence。第八条精确绑定 action、decision digest、父 Mission revision/contract digest 与 route revision：Stop 原子形成 typed terminal 并跳过 `candidate_learning`，Continue 只复用 exact frozen parent contract，Scale/Test 保持 `WaitingUser` 等待完整 replacement contract 授权；exact replay 不增加 Event/Outbox，drift 失败关闭。该第八条现有 Desktop caller/UI wiring，仍不构成十二条 Mission 的完整原生 UI Journey。迁移可读的未验证来源、未确认链接、错账号、父合同漂移、未知 KPI、币种冲突、重复/争议归因、伪造 Effect、stale commission、重复/超额/错币种 payout、settlement authority 混用、scope/digest tamper 和 stale source 都不能升级为完成，机器合同当前为 9/52，其他 43 条明确 `NOT_IMPLEMENTED`。旧 lease 不能追加 failure 或启动新 cycle，`uncertain` 不重放外部 Effect。仍缺 credentialed Runtime、生产 OS/Cell Scheduler、其余 43 条 Application handler、Effect Broker/Browser handler、其余 Human route、真实 Dioxus delta 投影、外部 `SIGKILL`/整机断电、Windows Job Object 与 PostgreSQL 等价性；Release Evidence 仍为 `passed: false`，Mission E-level 不提升 |
| Context Capsule 夹带父 Prompt、Secret、额外 Fact、越权 Capability/预算或伪造 Worker 结果 | Capsule schema 只允许 typed 引用与摘要；精确 Fact revision/classification 闭包；Capability/Budget/Data Policy 必须是 Mission/Workspace 子集；Branch lineage、lease token digest、generation、authority digest 与 return contract 全量复核；旧 generation、本地分叉和中途 support 冲突失败关闭并回滚 |
| Compaction 摘要删除或改写 Goal、用户纠正、Pending/`uncertain` Effect 或证据链 | 摘要正文不具备权威性；`ContextInvariantBlock` 从当前 Mission 与全部当前 Project Truth 确定性重建，并覆盖 Contract、Task、Truth correction chain、Evidence、Work Product、Effect exact scope、Approval、Receipt、Verification 与 Outcome。Compaction/Checkpoint invariant 必须逐字段相同并同事务提交；篡改、陈旧 revision 或 checkpoint crash-gap 全部失败关闭 |
| Working Set 把 Secret/PII 写入 Event/Trace，或把过期项继续投喂模型 | Working Set 领域类型不含正文，只允许受限 scheme 的 encrypted-CAS/typed reference、digest、byte length、classification、provenance 和 TTL；Event 只记录计数/摘要。TTL 到期显式投影 `Expired`，后续 Assembler 必须报缺口或重算 |
| Context Assembler 夹带未授权正文、使用陈旧 authority、CAS/Tokenizer artifact 被替换、错模型计费、把 optional gap 冒充 Ready，或把完整 prompt 落盘 | schema v29～v31 Assembler 在调用 resolver 前复核当前 Mission/Workspace/Capsule/Branch/WorkerLease/Checkpoint/Foundation 的 exact revision 与 lineage；项目作用域 resolver 仅接受小写 `cas://sha256`，以 Project key/version 的 AES-GCM AAD 绑定 tenant/project/plaintext digest，canonical file snapshot 拒绝绝对路径、`..`、`.hartevo` 和任何 symlink，query 先冻结 typed JSON。错 scope、旧 key 缺失、ciphertext tamper 或非 UTF-8 全部失败关闭；material 解引用后再复算 digest/byte length，required 缺失、过期、篡改或预算溢出失败关闭，optional omission 显式记入 gap。Tokenizer JSON 必须匹配冻结 SHA-256；profile 绑定 provider/model/model revision、special-token 策略、request overhead 和输入上限，组装期间 profile 漂移失败，overhead 只计入最终 prompt。Application 在 durable dispatch 前比较 runtime 返回的 provider/model；schema v31 以 hash-only normalized projection 检查 profile 缺失/篡改并迁移回填 schema-v2 Manifest，schema-v1 只可审计。dispatch 前逐帧比对 envelope 与 Manifest 的 ID、顺序、classification、content/prompt digest、字节/token 数、profile digest 和 gap。只有短生命周期 `RuntimeContextEnvelope` 含正文；encrypted CAS、SQLCipher Manifest、Domain Event、Outbox 与 Debug 不含正文；Dioxus 选中项目后的 keyring→CAS 解锁/内容会话 接线、CAS 删除传播/重加密/内容扫描、生产 tokenizer artifact registry 和 Provider model-revision 证明仍是未完成边界 |
| 重启漏扫 Runtime Turn，或篡改 normalized status 释放 active-turn fence 后重放 | 新 Application 默认禁止 Runtime spawn、dispatch、observe、approval 和 interrupt；只有 SQLCipher `IMMEDIATE` startup reconciliation 成功后才开放。扫描不按 status 过滤，而是加载全部 Turn 并逐条比对完整 record、41 列 projection 与 evidence；Prepared 证明未派发后进入 Failed，Dispatching/Running/Approval/Interrupt 保守冻结为 `uncertain`。任一篡改或 Event/Outbox 故障使整批回滚；重放不重复 evidence，active 查询也重新加载完整 record，不信任可篡改索引。报告只返回有界计数与 sequence，不暴露 Thread/Turn ID |
| Runtime Turn 在 durable intent 前写入、错配 Thread/Turn、审批/中断重放，或把 stdout/item/命令正文写入审计 | schema v30 `RuntimeTurnAttempt` 冻结 Assembly/Capsule/Branch/Lease/Handle/Recovery/process/Thread/mapping authority closure；`Prepared→Dispatching` 必须先提交才允许 `turn/start`，local approval 与 interrupt 同样先持久化 exact request/decision digest。每个 notification 重验 Thread/Turn identity；明确拒绝为 `Failed`，写后 timeout/exit/protocol failure 为 `Uncertain`，每 Worker 唯一 active-turn fence 禁止新 Turn。原始 Thread/Turn ID 仅在 SQLCipher 私有 record 与 live mapping 中，Event/Outbox/Debug 只含 digest、status、sequence 和有界计数；故障注入证明 state/evidence/event/outbox 全回滚 |
| Worker/Recovery key 越权管理 | key-admin 命令绑定 actor/evidence，并实际解开当前 Device/Member envelope；recipient reference 再校验 tenant/project/kind/id |
| Desktop 重启后猜测 wrapping-key 引用、把引用当密钥落盘、用错设备/旧 envelope 解包，或轮换后把旧 CAS 误标为新 key | schema v35 只在 SQLCipher 保存 immutable envelope→完整 `SecretReference` binding，credential/recipient projection 只留 digest；Keyring 创建、授权、附加和轮换与 binding 同事务，故障全回滚。Application 以 Project+Device 选择当前可用 envelope，从 OS Secret Store 取 wrapping key并做 exact AAD unwrap；裸 key 只存在 zeroizing 对象/session。active reference/secret 缺失、错设备、撤销、binding/AEAD 篡改均阻断；历史 key 缺失显式 degraded，immutable CAS replay 返回实际落盘 key version，不伪装成当前版本 |
| 伪造新设备、错误 Recovery secret、重放附加意图或冲突后残留可用设备密钥 | DeviceAttachment 绑定 tenant/project/mode/source/target device/key version/期望 keyring revision 与 exact intent/idempotency digest；授权来源必须实际 unwrap 当前 Project key，Personal Recovery 走独立非管理入口；Prepared envelope 跨重启复用，keyring+Applied 原子 CAS，冲突补偿删除孤儿 OS Secret |
| Cell 替换 keyring、伪造目标公钥、撤销/认领竞态或设备私钥落入同步账本 | Handoff Grant 的 AAD/digest 绑定 source envelope 与 `ProjectKeyring::canonical_digest`、目标 device/public-key version、修订和有效期；版本化公钥可轮换且撤销永久；Claim/Revocation 使用同一 PostgreSQL 行锁，未 Claim 禁止本地附加；必须 attach→publish next bootstrap 后才 Consumption。X25519 私钥只进 OS Secret Store，SQLCipher 敏感字段扫描拒绝 private/recovery/token/cookie，Cell 仅保存公钥、密文和摘要 |
| 成员撤销后仍可读新内容 | recipient revoke 与内容密钥轮换同一 CAS revision；新版本排除被撤销 recipient，并同时撤销短期 Worker envelope |
| 随机 nonce 导致同步幂等失效 | 网络前持久化 exact ciphertext request；keyed plaintext-intent digest 判定语义重放；同 key 改 payload 失败关闭 |
| 密文跨 Cell/对象/revision 重放 | AES-GCM AAD 绑定 cell/tenant/project/object kind/id/revision/key version/tombstone，读取时校验 request/ciphertext digest |
| 删除后旧密文、旧 Outbox、过期清理 worker 或离线设备把对象复活 | 强类型 DeletionTombstone 绑定 causal prior revision、删除代际、actor/授权证据 digest；SQLCipher 原子清理投影/旧同步密文并保留永久 deletion ledger；Cell 仅保留 tombstone revision 并拒绝后续 upsert/kind-rebind；入站旧 revision 在 ledger 前失败关闭。Cache/Replay 使用 durable lease/generation 和 exact-scope receipt，旧 generation、matched≠deleted 或 residual>0 均拒绝；真实内容 adapter 未完成时状态保持 Pending |
| Pull 覆盖本地未同步修改 | inbound head 保存上次 projection revision；typed projector 只在本地仍处于该 revision 时 CAS 前进，否则持久化 Conflict 并保留本地状态 |
| 设备本地路径随 ProjectMetadata 泄漏 | 同步使用不含 `workspace_roots` 的专用 snapshot；入站投影覆盖本机已有路径，密文解开前后均校验 tenant/project/Cell/revision |
| 伪造或跳跃 Truth 纠正链 | ProjectTruth projector 只接受实际本地 head 的精确前序 version + digest；缺链、跳版或本地分叉进入持久 Conflict |
| IdentityLink 通过 revision+1 改写外部身份、确认者或历史证据 | Proposed/Confirmed/Conflicted/Rejected 的每次决定只追加 actor、SHA-256 evidence digest 与单调时间；Storage 从前一 revision 重放一条合法决定，低置信确认、跳跃、Rejected 终态重入和 identity body rewrite 全部失败关闭；v23 只迁移可证明的 legacy Confirmed 记录 |
| Work Product 正文、依赖或采用状态被局部偷换 | Manifest digest 同时绑定 Mission、产品 revision、Fact/Evidence/Task 依赖、artifact/file/preview digest、可编辑范围和采用状态；Manifest 与 Mission/Event/Outbox 同事务 CAS，任一字段变化生成新版本 |
| 伪造 Connection snapshot 冒充 Connected | restore/projector 重算账号、required/granted scopes、Probe outcome、有效期、credential expiry 与 evidence；本地状态只能按 `begin_probe → apply_probe` 或单次 revoke 从前一 revision 精确重放，valid-looking no-op revision 也拒绝；凭据不进入 ConnectionMetadata，撤销清空 scopes，本地撤销后的旧远端 branch 只能进入 Conflict |
| Consent scope 偷换、Campaign Receipt 改写、Opportunity 跳 Stage 或把 Forecast 当 Revenue | Consent 只能按 exact scope withdraw/expire；Campaign 的发送与 Receipt append-only、recipient suppression 单步重放且 terminal 不可重入；Opportunity Buying Committee/Forecast/Stage 每 revision 只接受一个命令，Stage 沿显式前进图，Forecast 不存在 Revenue 字段；SQLCipher CAS 拒绝“合法快照式”的组合改写 |
| 伪造 Conversation 身份/账号、Webhook、Consent、发送 readback 或抢回人工控制 | Conversation snapshot 同时绑定 Person/Company、gateway/provider/connection/account、签名 route、Consent evidence、Mission Effect scope、Receipt/provider event digest 与独立 Verification；每个 revision 只能重放一个领域命令，终态拒绝新入站。pause/handoff/terminal state 提升 generation，旧 lease 不能外发；本地控制分叉进入 Conflict，support 数据由 savepoint 原子回滚 |
| CreatorWork 密文只带 Task、伪造付款证据或留下半截身份链 | 同步 bundle 必须包含每个 Candidate 的 Partner/Person/Company、Awarded Hiring 与完整 Task；重新核验 Mission Effect/Receipt/独立 Verification，并只重放一个合法状态命令；身份/Hiring/Task 投影置于 savepoint，失败先全部回滚再提交 Conflict |
| Provider `200 OK`、伪造账号或改写历史 Outcome 冒充收入/付款 | OutcomeLedger 事件绑定 exact provider/Connection/Account、签名 Webhook 或独立 readback；Order 必须绑定 Confirmed IdentityLink。同步只携精确引用闭包，每个 revision 只重放一个命令，旧事件不可改写，退款追加为反向事件并重算 Commission；support/ledger 在同一 savepoint，旧本地分支不能被覆盖 |
| 项目被静默注册到错误 Cell | US/EU 由有 Device/Member key 的用户命令显式选择并成为不可变 Project revision；注册 request、Cell 和授权证据 digest 持久绑定，普通写入前重查 Applied |
| 通用 Project 写 API 绕过 Cell 注册 Saga | create/save/update 拒绝预选或改变 Cell；只有注册事务内部 CAS 可以首次写入 Cell |
| 调用底层 Storage sync API 绕过注册检查 | SQLCipher 的 outbound prepare 与 inbound stage 都重查项目为 `local_encrypted_sync`、项目 Cell 精确匹配且 registration 为 Applied；未注册或错 Cell 在写 ledger 前失败关闭 |
| Receipt 后旧 verifier 抢写结果 | 每次恢复 verification 提升 attempt generation；SQL 只接受该 Effect 当前最大 generation，旧 lease 返回 `LeaseLost` |
| 恶意网页或附件 | semantic snapshot 与协议白名单；File Broker 已实现 Project 路径、symlink、类型、大小、主动内容、scanner verdict、只读 staged blob、single-use claim，以及 exact leased Grant 到受管理 file input 的本地选择与二次校验。选择后 Grant 保持 `Leased`，不会冒充上传或消费完成；当前 scanner 仍仅为测试替身，生产恶意文件引擎、隔离预览、Provider upload/readback 与 Windows reparse-point 实机仍为未完成 Gate |
| 私有 Benchmark 泄漏 | 独立身份/存储/网络策略、Target 读取计数 0、泄漏即轮换 revision |
| 未签名自我改进 | Candidate-only、冻结 Benchmark、人工/策略晋升、签名和可回滚版本 |
| Update 供应链 | SBOM、依赖审计、可重现 metadata、平台签名、公证、TUF-like metadata 和 rollback protection |

## 4. Creator Work 特有威胁

- Creator 冒名或收款账户不一致：Identity/KYC/Connected Account 必须一致，高风险合并人工确认。
- 公开候选被擅自触达：公开发现只生成 `research_only` Candidate；没有当前 Contact Permission 不得准备或执行邀请。
- 审批后撤回许可仍被发送：Invitation Effect 绑定 permission evidence，但执行前必须重新读取当前 Partner；撤回、换号或 scope 漂移在 Provider 调用前失败关闭。
- 伪造应聘来源：Application 只能来自独立 readback 已验证的 Invitation 或 Listing；草稿、Provider `200 OK`、搜索结果或 Agent 文本不构成合法来源。
- 达人通过应聘偷换悬赏：Application 绑定冻结 Offer digest 和原金额/币种；Offer 变化废止旧申请并要求新 revision。
- Agent 或前端伪造“用户已雇佣”：Award 只由用户选择命令生成并持久化，绑定唯一 Application、Creator/Partner、Offer digest 和选择证据；创建 Task 时必须重读并精确匹配。
- 用户发布任务后偷换要求：Creator 接受后 Task Contract revision 锁定；变更需双方重新接受。
- 空文件或伪造交付触发付款：Deliverable 必须可访问、有 digest、扫描结果、类型和使用权声明；用户 Review 接受前禁止 Payout。
- 资金预留被冒充法律托管：只保存并展示 Provider 可验证的 reservation/prefunding/payment-ready 事实；没有单独法务与 Provider 合同不得使用 escrow 声明。
- Review 访问被冒充合同使用权：安全交付物先为 `evaluation_only`；用户接受后为 `accepted_awaiting_verified_payout`，只有匹配 Deliverable digest 的付款独立验证后才成为 `contract_usage_granted`。`uncertain` 查到的 Receipt 必须同时匹配原 Award/Task/Review/金额/账号，并在同一 SQLCipher 事务更新 Mission Effect、Creator Payout、使用权和审计事件；任一 CAS 失败全部回滚。
- Review 后替换文件：Approval 绑定 Deliverable revision/digest，变更立即失效。
- 另一设备伪造雇佣、Review 或付款快照：CreatorWork 同步必须携带并验证完整身份—Hiring—Task—Mission evidence 链；缺失 Candidate Identity、Receipt 不匹配、非独立 Verification、非法 revision 跳转和本地 FundingReservation 分叉一律拒绝或进入 Conflict。
- 重复或超额付款：每个 milestone 使用唯一 idempotency key、minor units、累计上限和 Settlement Ledger。
- 版权、肖像或第三方素材不明：交付必须声明来源、许可和用途；缺失则阻塞 Review/付款。
- 争议或 chargeback 改写历史：原 Task、Deliverable、Acceptance 和 Payment 不可变；Dispute/Refund 为关联事件。
- 恶意交付感染用户设备：上传先进入隔离对象存储和扫描，未通过不提供直接打开或下载。

## 5. 数据分类与保留

| 类别 | 示例 | 默认处理 |
| --- | --- | --- |
| Secret | Token、Cookie、私钥 | 不进入业务数据库/日志；只存 Secret Store |
| Restricted | 项目正文、联系人、Deliverable | 本地/E2EE 或团队 envelope encryption；按项目删除 |
| Audit | Approval、Receipt、Verification、Payout | 90 天，法律/争议 hold 需显式记录 |
| Operations | 延迟、错误码、容量 | 去标识，7 天 |
| Eval Private | V1/V2、Judge gold | 隔离身份、存储和访问审计 |

删除请求传播到本地缓存、Cloud、Context Capsule、Memory、Replay 和对象存储；法律/付款争议保留例外必须有范围、原因和到期时间。

Project key、wrapping key 和同步正文不得进入 Event、Outbox、Audit、Trace 或错误消息。Key administration audit 只记录 actor、授权证据 digest、recipient reference digest、版本和结果；同步账本只记录 keyed intent digest、请求 digest、认证密文与 CAS metadata。keyed intent digest 必须使用 Project key 派生的 HMAC，不能用裸 SHA-256 暴露低熵正文的字典猜测面。

## 6. 零容忍发布事件

跨租户、Secret/PII/Project key 泄漏、Context Capsule 扩权或旧 generation 回流、Compaction 丢失/改写 typed invariant、未授权 key-admin、成员撤销后仍获得新密钥、Approval bypass、重复外部 Effect、`uncertain` 自动重放、错误金额/币种/Consent/Attribution、人工接管后外发、公开 Creator 候选自动触达、联系许可撤回后仍外发、无已验证来源的 Application、伪造 Hiring Award、Creator 未接受交付即付款、私有 Benchmark 泄漏、未签名生产晋升均立即冻结发布并创建安全事件。
