# Hartevo Deployment、DR、Observability 与 Signed Updates

状态：**Target Contract**

## 1. 部署形态

- Desktop：macOS ARM64/x64、Windows ARM64/x64；Linux x64 compatibility。
- Local：SQLCipher、OS Secret Store、受控 Runtime/Browser 子进程和本地 Outbox。
- SaaS：Global Control Plane 只保存必要的路由/订阅 metadata；业务执行进入 tenant 所选 US/EU Cell。
- Self-hosted：Docker Compose 用于开发和单机验证；Helm 用于通用集群安装。客户定制 air-gapped 部署另立项目。

## 2. Cell 组件

- Control/API、Cell Worker、Scheduler/Webhook、PostgreSQL、对象存储、OpenBao/Vault-compatible Secret Store；
- OpenTelemetry trace/metric/log pipeline；
- GitOps/Helm release、NetworkPolicy、Pod Security、资源配额和 tenant fairness；
- 初版使用 PostgreSQL durable Outbox/Lease，不引入 Redis/Kafka/NATS。

## 3. 数据与密钥

- 个人项目默认本地执行；同步内容为服务端不可读密文。
- 团队远程执行必须项目显式 opt-in；Worker 获取最长 15 分钟、绑定 tenant/project/worker/key-version 的最小范围 execution key，opt-out 或轮换立即撤销。
- 成员/设备撤销与 Project content key 轮换使用一个 keyring CAS revision；只有当前 Device/Member envelope 可携授权证据执行管理，Recovery/Worker 不具备管理权。
- schema v35 的 local wrapping-reference Registry 参与 Keyring/attachment/rotation 同一 SQLCipher 事务；v34 升级先创建加密备份，旧数据库不能从 digest 猜回完整引用，缺 binding 时必须显示重新授权/恢复，而不是尝试错误 key。Desktop session 重开时逐个验证 binding projection、credential digest、envelope availability 和 AEAD；active key 缺失阻断，历史 key 缺失进入显式 degraded。Dioxus 已使用该 session 门禁 Manifest preview，并可为个人项目从 Recovery Kit 附加 successor Device identity。会话 drop 经 `KeyMaterial` 清零内存；当前证据不包括进程崩溃后的物理内存取证、任意 encrypted CAS 正文/file/query UI、Windows 实机、整机丢失或历史 key handoff。
- Desktop 安装 SQLCipher key 只在用户显式首次初始化时生成，并以 canonical data-root digest 作用域写入 OS Secret Store；重启只读取既有 key。数据库存在但 key 丢失/被替换时停止，不得生成新 key 覆盖。个人项目 Recovery Kit 由用户离线保管，Hartevo/OS Vault 不 escrow；Project 已创建但 Keyring 未提交时保留 `NotProvisioned` 恢复入口。已配置项目的 Device secret 丢失时 Project/Mission 元数据仍可见，但 WorkProduct preview 被清空、Mission 写入被阻断并进入 `RECOVERY_REQUIRED`；该 UI 可用 Kit 原子附加 distinct successor Device envelope，错误 Kit 不产生 Secret/Keyring 变更，成功重开 Context 后才解锁。当前 DR 证明覆盖同机重启、无效 Kit 零副作用、重复 provisioning 拒绝、内容投影失败关闭与同安装项目 Device secret 恢复；尚未覆盖丢失整台设备后的 SQLCipher/物理介质备份、Windows Credential Manager 或跨设备恢复演练。
- Desktop 当前使用 SQLCipher schema v44，并继承 Cell 注册/密文同步、删除、密钥、Effect、Context、Browser、Runtime 与 Mission Schedule 的既有 DR 合同。v42 保存 Checkpoint Capability/executor；v43 保存 Oracle/completion policy；v44 保存受约束的 Human confirmation message。v42 legacy route 迁移后可审计但不可完成；v43/v44 均先创建加密备份、保留旧行并验证幂等 reopen。
- Application 启动仍先精确 reconcile v39 Process Claim 与 Runtime Turn，再关闭到期 Schedule；无法检查进程时持久化 `Blocked`/`BLOCKED_ENV`，可能已派发的 Turn 冻结 `uncertain`，任何路径都不按 PID 猜杀或自动重放外部 Effect。Process/Browser/Scheduler 私有 token、路径、credential 与正文只在 SQLCipher 私有 record 或 zeroizing buffer，Event/Outbox/Debug/UI 仅保留 digest、状态和有界计数。
- Catalog v10 route 恢复必须重验 exact Capability/executor/Oracle/policy。Human route 只能通过双 revision CAS 命令，把 Conversation、Checkpoint、旧/新 Task 与 Event/Outbox 原子提交；通用完成入口不能绕过。Application handler 还必须同时存在于版本化 Registry 与当前二进制，并匹配 Mission Catalog digest；当前只有 VM-11 event_ingest，来源 revision fence 与 Mission CAS 同事务，其他 51 条为 `NOT_IMPLEMENTED`。故障注入覆盖 route、Human message、Application source、Task 与 Event 整体回滚。未覆盖 credentialed Runtime、active-script/authenticated Provider、Windows pipe/reparse/Job Object、生产 scanner、Provider readback/Verification、外部 process-kill/整机断电、真实 PostgreSQL DR、OS/Cell Scheduler、其余 51 条 Application handler、Effect Broker/Browser handler、其余 Human route 与跨后端等价性；无 `HARTEVO_TEST_POSTGRES_URL` 时保持 `BLOCKED_ENV`。
- Signed Browser Recipe 的 Trust Key 安装/撤销、immutable Candidate/Release、append-only Activation 和 CAS Head 已由 schema v34 持久化。启动恢复按 Candidate authored、Release promoted、Activation activated 的历史时间验证签名链，并在当前派发前重新读取 active head、release key revocation、Mission capability、当前 locator Resolution 和 exact Effect；普通 Executor 不接受 Recipe Batch。head rollback、projection tamper、陈旧 CAS、缺记录与撤销全部失败关闭。当前仍只证明单设备 project-local SQLCipher；生产 root-key 授权/轮换、Cell/跨设备同步、真实 Provider Recipe 与真实 Chromium Recipe smoke 未实现，因此这些路径继续显示 `NOT_IMPLEMENTED` 或 `BLOCKED_ENV`，不能从本地 Batch 摘要推断远程授权。
- US/EU Cell 的数据库、对象存储、备份、Secret 和遥测相互隔离。
- 日本市场不等同日本数据驻留；租户必须明确选择 US 或 EU。

## 4. Migration 与 Rollback

- Cloud migration 采用 expand→dual-read/write（必要时）→backfill→verify→contract；Canary 期间不执行不可逆 contract。
- Desktop migration 前创建带 schema/catalog digest 的本地备份；迁移幂等，失败恢复旧数据库和旧应用版本。
- Event schema 向后兼容至少一个稳定 Desktop 版本；旧客户端写入不支持的状态时明确要求升级。
- Provider、Mission、Plugin、Recipe 和 Harness 均可按签名版本回滚，不修改历史 Receipt/Outcome。

## 5. DR 目标与演练

初始目标合同：

- Control Plane/Cell 业务 metadata：RPO≤5 分钟，RTO≤60 分钟；
- 审计 Event/Receipt：已确认写入不允许静默丢失；
- 本地个人数据：以用户加密备份/恢复密钥为恢复边界，服务端不能解密代恢复；
- Provider Effect：灾难恢复后先 reconcile，再决定是否允许显式重试。
- 加密 Sync：Prepared ledger 是 push 重放事实源，inbound version/head 是 pull 重放事实源；远端 Applied/Conflict 与本地 operation revision 对账。不得重新加密产生第二个请求来猜测前次写入结果，也不得用远端 head 覆盖已偏离 projection revision 的本地 aggregate。
- ContextCapsule 的 Local/Context/Cell 删除路径与 Cache/Replay durable 调度已有 E2 replay，但真实 Cache/Replay 内容 adapter 尚未实现，实际传播仍为 Pending；其他对象的删除/保留矩阵也未开放。这些部分在 DR 中必须显示 `NOT_IMPLEMENTED`，不能把墓碑、job 或 simulator receipt 冒充全表面生产删除完成。新设备 attach/recovery/public-key handoff 已能在 SQLCipher 重启后 exact 恢复 Prepared Saga，Personal Recovery 会实际 unwrap 同一 Project key，claim-first 路径也会先取得远端 Claim、再本地附加并生成 next bootstrap/Consumption；但部署后的 Control Plane HTTP/OIDC、真实 PostgreSQL replay、双设备 Dioxus Journey、整机丢失/历史 key 轮换恢复 UI 和 Windows 实机尚未完成，不得将该 E2 组件证据冒充完整跨设备恢复。Context Worker backpressure、epoch fencing、typed merge 与 compaction 目前只有同进程 SQLCipher E2；process-kill、provider switch、Scheduler 和跨后端恢复仍为 `NOT_IMPLEMENTED`/`BLOCKED_ENV`。

每个 GA 候选必须演练：单 Pod/Worker 失败、数据库主切换、对象存储暂不可用、Cell 整体不可用、过期 lease、10k Outbox、回滚镜像和 Desktop 数据库恢复。

## 6. Observability

所有 span/event 绑定 tenant pseudonym、project/mission/run/checkpoint/effect/provider ID 和 monotonic sequence，但不记录正文、Secret、Cookie、直接 PII 或私有评测内容。

必备 Dashboard：

- Mission MGCR/VBOR/LCR、Checkpoint failure、NOT_IMPLEMENTED/BLOCKED_ENV；
- Provider success/refusal/429/5xx/uncertain/reconcile、scope 和 cost；
- Outbox depth/age、lease reclaim、dead letter、Webhook lag；
- Context compaction/resume、Worker generation、Browser handoff；
- Approval→Receipt→Verification、Creator Deliverable→Review→Payout；
- 延迟、容量、错误预算、单位 Mission/Work Product 成本。

## 7. Signed Updates

- Alpha、Beta、Stable 使用独立 channel metadata；应用只接受同 channel 或用户显式切换。
- macOS 使用 Developer ID 签名、公证和 stapling；Windows 使用受信代码签名并验证 ARM64/x64 installer。
- Update metadata 采用 TUF-like root/targets/snapshot/timestamp 角色、threshold key 和 rollback/freeze protection。
- 构建输出包含 Commit、Cargo.lock、SBOM、Catalog/Schema digest、签名身份和 provenance。
- 更新前验证本地迁移可回滚；签名、digest、版本单调性或目标架构不符即拒绝安装。

## 8. Support 与 Break-glass

- Support 默认只能查看去标识运行状态和用户主动分享的 Replay Pack。
- 内容访问采用 tenant/user 显式授权、短时、只读、全审计；生产 Secret 和私有 Eval 永不通过 Support 暴露。
- Break-glass 必须双人批准、自动到期并产生安全事件；不能用于绕过 Consent、Approval、Payout 或数据驻留。
