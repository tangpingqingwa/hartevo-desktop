# Hartevo Desktop 开发与 macOS Bootstrap

- 状态：**Current（工程交接入口）**
- 适用：从一台全新 macOS 机器接手 Hartevo Desktop，并完成首个 Bootstrap R0 PR
- 最后审查：2026-08-12

当前 revision 的命令结果、真实 OpenInterpreter/Chrome smoke 与宿主环境阻塞统一见 [Current Worktree Evidence](./docs/quality/CURRENT-WORKTREE-EVIDENCE.md)。旧数字快照不得覆盖该证据文件或机器生成的 Release Evidence。

## 1. 先确认仓库所处阶段

仓库现在包含产品与质量合同、冻结原型、可编译的 Bootstrap R0 Rust workspace，以及 Wave 0 机器 Catalog。首个受控垂直切片 VS-01 已能从自然语言 Mission 合同运行到 Evidence、Work Product、Approval、Effect、Receipt、Verification 与 Outcome，并输出确定性 Eval 报告。

当前边界：

- SQLCipher 当前为 schema v47：v35 local wrapping-reference Registry 只保存完整 `SecretReference` 与 immutable envelope binding，不保存 wrapping/content key；v36～v42 依次保存 MissionDefinition/Checkpoint DAG、MissionConversation、exact Runtime private message、Process Claim/cleanup、Mission Schedule、`expired` 终态与 Checkpoint Capability/executor；v43 增加 route Oracle/completion policy，v44 增加受约束的 user `checkpoint_confirmation`，v45 保存 VM-11 Outcome Review、逐来源 fence 与结构化 Human decision，v46 保存 Runtime `item/agentMessage/delta` 私有增量链；v47 事务性重建 `mission_checkpoints` 并只为 `route_completion_policy` CHECK 增加 `effect_readback_v2`，既有列、key/FK/UNIQUE、状态/完成约束与索引保持不变。完整 Runtime/Scheduler token、launch path、Thread/Turn ID 与正文只在 SQLCipher 密文 record 或进程内 zeroizing buffer，Event/Outbox/Debug 仅含 digest、状态和计数。Application-owned Context CAS session 以 Project+Device 从 Registry→OS Secret Store→Envelope AEAD 装配 active/历史 key，临时 key 由 `SecretBytes`/`KeyMaterial`/session drop 清零，调用者不接触裸密钥。metadata inventory 清空 Mission 标题、目标、Conversation 正文、Outcome 与 preview，只有 exact Device session 才生成可读投影。重启、轮换、历史 key 缺失降级、active key 缺失、错设备、撤销、fresh/v44/v45→v46→v47、既有 v46→v47 policy/行保留、碰撞失败整事务回滚/无 v47 ledger/清理后重试和投影篡改已有 E2 回归；迁移账本顺序各有唯一 `record_migration(45)`、`record_migration(46)`、`record_migration(47)`。真实双设备 UI、Windows Credential Manager、整机丢失/历史 key handoff、CAS 删除/重加密/扫描仍未完成；
- `cargo`、`dx build`、`dx serve` 与 Eval Runner 已可执行；
- VM-00～VM-11、48 Capability、39 Provider、420 Mission Case metadata 和 180 横切 Case 已由 `hartevo-catalog` 双向校验；它们当前只证明 E1；
- OpenInterpreter `rust-v0.0.34` 的 commit、schema、checksum 和稳定 stdio 方法已冻结；schema gate 已包含 `item/agentMessage/delta`。真实二进制在两个独立测试中证明隔离 home、无凭据失败关闭，以及 Application 持久失败而不伪造完成。Fake Runtime 进一步证明 delta 的 exact Thread/Turn/item/sequence/chain 持久化、重排/篡改拒绝、完成正文精确重组与 `Uncertain` 冻结；公开 Event/Outbox/Debug 不含正文。v39 对 pinned Runtime 为每个 durable Claim 创建唯一 launch 副本，启动时以 PID+start epoch+executable/runtime digest 和私有 token/路径标记精确回收；无法检查时保持 `Blocked`，不按 PID 猜杀。真实子进程回归覆盖 coordinator handle 丢失、后代优先回收、Recovery attempt 推进和 Claim-cleanup/Recovery-update 提交间隙，两个真实 OpenInterpreter smoke 也在该路径上通过且无 launch residue。Fake Runtime 继续证明成功 stream、local approval、interrupt 与协议恢复；同 Mission coordinator 还证明 generation retry/retirement/replacement、bound-thread resume、私有 draft 原子采用，以及无 Recovery/Prepared Recovery/Attached Recovery 三类 pre-Turn steering 撤权。Runtime Adapter 的 Windows x64/ARM64 条件编译已分别通过；macOS 主机上的全工作区 Windows 交叉构建仍被 Windows C SDK/Windows Perl+OpenSSL 工具链阻断。正式模型 artifact/model-revision、credentialed success、provider switch、外部 process-kill/断电、Windows 实机和完整 Mission continuity 未完成。
- 仓库尚未携带或构建真实 `codex-app-server` 二进制，VS-01 使用受控 Provider Simulator，不连接生产账号、不产生真实外部写入；
- Browser B0/B1a/B1b/B1c/B2-narrow 已具备 Project/Mission-bound Workspace、CAS handoff、真实 Chrome pipe/AX、exact-origin navigation、stable locator、Effect-bound click/空白非密码 text/local file selection 和 Application takeover/restart/continue；真实 Chrome smoke 使用显式 `MacOsMockForTest`/`--use-mock-keychain`，不会读取或重建用户 Chrome 钥匙串，也不构成生产 Keychain 证据。当前 OS Secret Store 生产路径优先 Data Protection Keychain 并在 release 缺 entitlement 时失败关闭；本机无有效 signing identity，protected backend 返回 missing entitlement，legacy login Keychain 也不可写，因此初始化保持 `BLOCKED_ENV`。Windows Credential Manager、authenticated browser、密码/替换/raw keyboard、生产 scanner、真实 Provider upload/readback/Verification 和 Dioxus Browser UI 未完成。
- Signed Browser Recipe 的 project-local E2 已实现：Candidate/Production 两类 Ed25519 key、V1/V2+安全+污染+回滚 Promotion gate、immutable Registry、单调版本与 CAS activation、selector/policy/action/Effect exact binding，以及恢复后派发时的 active release、revocation、Resolution 和 Effect 重验。schema v34 以 SQLCipher 保存 Trust Key/Candidate/Release/Activation/Head，Event/Outbox 只含 digest；迁移备份、重启、head rollback、projection tamper、陈旧 CAS、key revocation 与 Application→Fake Host→Effect Journey 均有证据。普通 Executor 遇到 Recipe Batch 默认拒绝。Cell/跨设备同步、生产 root-key provisioning/rotation、真实 Provider Recipe 与真实 Chromium Recipe smoke 未完成。
- US/EU Cell PostgreSQL 加密同步、RLS、CAS 和 durable Outbox 已有实现与 CI L2 replay；本机没有隔离 PostgreSQL 时明确报告 `BLOCKED_ENV`，不能用 schema 静态测试冒充实机通过。
- 本地 SQLCipher schema v33 在 v32 Browser Profile/Workspace/Tab/Control Transition 上新增 `BrowserFileGrant`。File Broker 只接受 canonical Project root 内的非 symlink 文件，验证大小、魔数/主动内容、scanner clean evidence、exact lease/payload/claim，并把私有 staged blob 绑定 durable OS lock；Unix 使用 `O_NOFOLLOW`。Grant 的准备、claim、terminal 与 Event/Outbox 由 SQLCipher CAS 原子提交，完整 record 留在密文列，规范化与审计面不含源路径、文件名、正文或原始 claim ID。重启恢复 Prepared/Leased，清除 crash orphan 和 terminal residue；缺失/篡改只进入 reconciliation，Leased 不自动重放。`FileUploadHandle::validate_for` 在真实 Host 选择文件前后重算 staged digest 并核对 Grant/Claim/Workspace/Lease；`DOM.setFileInputFiles` 成功与 AX selection 变化仍只产生 Browser Receipt，不完成 Grant、不删除 blob。当前 scanner 仅为测试替身，Windows reparse-point 强化、真实 Provider submit/upload/readback 仍未完成。既有 Assembler/Runtime/Browser Workspace 的 durable intent、`Uncertain` 零重放、content-free evidence 和故障回滚边界保持不变。
- Desktop 不再维护 demo store：启动只在用户显式操作后生成安装 SQLCipher key，并从 OS Secret Store→SQLCipher→Application inventory 重建 Project/Mission；已有数据库缺失/替换 key 或 data-root symlink 均失败关闭。个人项目先显示一次性 zeroizing Recovery Kit，用户确认离线保存后才创建 Personal E2EE Keyring 与首个持久 Mission；Kit 不写入数据库或 OS Vault。中断后的 `NotProvisioned` 项目有显式恢复入口。通用 inventory 只读取 WorkProduct 元数据；exact Project/Device Context session 成功后才装配带已校验 Manifest preview 的投影，设备 secret 丢失时保留数量但清空 preview、阻断新 Mission 并显示 `RECOVERY_REQUIRED`。Dioxus 的恢复卡用用户自持 Kit 建立 distinct successor Device envelope，错误 Kit 不改 Keyring/SecretStore，Context 重开成功后才恢复 preview 与写入。当前证据是 data-plane/Application/Dioxus 编译与确定性重启 E2；原生窗口 AX/视觉、任意 encrypted CAS 正文/file/query 浏览与编辑、整机/跨设备恢复和完整 Mission L3 仍未证明。
- Runtime private-text Desktop 边界现以 exact Project/Mission 和当前 Device Context 失败关闭地读取 SQLCipher delta chain，并在 Dioxus 对已选 Mission 做只读刷新、重启/重新选择 replay、terminal draft 精确去重与本地 follow-unseen。新 Catalog Mission 的首轮 blocking Application 调用仍未提前返回 exact Mission handle，故 execution-time subscription、durable reconnect cursor，以及真实高密度 process/artifact/capability 投影仍未完成；该切片保持 E2，Release Evidence 仍为 `passed: false`。
- 本地 durable Mission Scheduler 与 Checkpoint route 已进入 E2：连续 Outcome+Schedule、signed inbound Conversation+event signal、Schedule+Mission cycle start、expiry/dead-letter+Mission terminal 均为 SQLCipher 原子事务；interval/event/hybrid cadence、anchor、exact n→n+1 DAG reset、owner/token digest、generation、heartbeat、五次失败预算与 stale lease 均失败关闭。Catalog v10 的 123 个 Checkpoint 逐一绑定 Capability、`application|runtime|effect_broker|human` executor、Oracle 子集与 completion policy；Task/Checkpoint/Event/Outbox 同事务推进，legacy route 只能审计且不能完成。VM-08 v4 的 `listing_write_readback` 使用 E1 `effect_readback_v2`：写 Effect 只给 ReceiptCandidate，机器合同把专用完成的前提冻结为关联该候选的独立 `marketplace.read`、只读 credential 与 canonical field diff；当前 generic completion、已验证 Effect、ReceiptCandidate 或 corroboration 单独都失败关闭，且合同明确不给 adapter/Provider/产品业务验证 claim authority。Application 会把下一个 `Ready` Checkpoint 与 exact Task 原子推进到 Running 并返回 revision-fenced dispatch proof。Human 边界已有 VM-07 通用确认和 VM-11 结构化 Continue/Stop/Scale/Test decision；后者原子绑定冻结 Review/source fence、双 CAS、actor/rationale/idempotency、私有 Conversation message、下一 Task、Event/Outbox。v8 Application Handler Registry 现有八条 VM-11 handler：原七条加 `next-contract-or-valid-terminal/v1`，机器合同覆盖 8/52。该 route 绑定 action/decision/parent contract/revisions；Stop 原子形成 typed `Completed` 并跳过 `candidate_learning`，Continue 只复用仍为当前的冻结父合同并进入合法下一步，Scale/Test 保持 `WaitingUser` 等待另行批准完整 revised/experiment contract，exact replay 零新增 Event/Outbox。generic completion 与 drift 均失败关闭；第八 handler 尚无 Desktop caller/UI wiring。其余 44 条明确 `NOT_IMPLEMENTED`，旧 Catalog digest 明确 `BLOCKED_CATALOG_REVISION`，两者都不运行 Runtime。Desktop 重开先做 Runtime reconciliation，再幂等关闭合同到期 Schedule。它尚未提供 OS wake/sleep-resume、Cell leader/多 Worker、公平调度、其余 44 条 Application handler、Effect Broker/Browser handler、其余 Human Checkpoint、redirect 或 Mission E3 原生 UI。
- repair 前 checkpoint 的全工作区全特性门禁为 **492 passed、0 failed、4 ignored**；四个默认忽略的真实环境测试（2 个 OpenInterpreter、2 个 Chrome）当时已逐个显式运行并单独记录。该历史 checkpoint 的严格 Clippy、格式、OpenInterpreter source/license/notice/schema/checksum、Catalog/Asset/VS-01 replay 均通过；Catalog Snapshot v2 digest 为 `0955d8873f065882795a39d26c3d9b178892c4f9b1d6e3ba91d9bbd765959dcc`。绑定 c71061e 的 Release Evidence 2.2 baseline 是另一份明确的历史失败证据：`passed: false`，报告 `7/52 Application handlers implemented、45 NOT_IMPLEMENTED`，并把十二 Mission、V0/V1/V2、横切、E4 与 E5 缺口保持为 0。DOC-47 未在 repair 后重跑全工作区或生成新 Catalog digest/test count；当前只按机器合同确认 Registry v8 为 8/52、44 条 `NOT_IMPLEMENTED`。Catalog Conversation、Runtime stream/draft、process Claim、Checkpoint Oracle/policy、Human/Application handler、dispatch proof 与 future-cycle Schedule 状态贯穿同一 Mission；成功只产生可审阅草稿、来源校验后的 Checkpoint proof、结构化用户决定或 route-specific typed resolution，Mission 不会被模型自报完成。Release Evidence 仍为 `passed: false`，Mission E-level 不提升。Cell live gate、显式 native Keychain smoke 与原生窗口复验若缺环境则保持 `BLOCKED_ENV`。
- 团队/个人 keyring 已覆盖成员、设备、Recovery 与短期 Worker envelope、撤销/轮换、exact attachment Saga 和 X25519 claim-first handoff；私钥只进入 OS Secret Store，远端 Claim 前禁止解密。当前 macOS Data Protection Keychain 因缺 codesigning entitlement 为 `BLOCKED_ENV`，legacy login Keychain 也不可写；不得把测试内存后端或 Chrome mock-keychain 当作生产凭据证据。Control Plane HTTP/OIDC、真实双设备 UI、整机恢复、Windows Credential Manager 与完整跨平台矩阵仍未完成。
- L1 的 `proptest`/`loom` 继续覆盖 Keyring、同步、Effect、Truth/Identity/Relationship、CreatorWork/Outcome、Context/Runtime 与 Outbox。Browser 默认门禁包含 48 个 adapter 测试，真实 Chrome smoke 单独显式运行；Runtime 另覆盖 coordinator restart、full-record/projection/evidence 校验、startup gate、同 generation 重试、耗尽 generation 原子退役、successor generation、`thread/resume` 与 replay suppression。跨平台浏览器并发、Windows 实机、authenticated flow、生产 scanner/Recipe keys、真实 Provider upload/readback/Verification 与 Mission E3 仍未完成。
- VM-05/09/10 共用的 Conversation、Campaign、Buying Committee 与 Opportunity 已有规范化 SQLCipher 投影和 Application replay；回复 Effect 绑定 exact gateway/provider/connection/account/person/content/Consent/control generation，人工接管或暂停在同一事务取消待发 Effect，`uncertain` 写入被冻结且不会自动重放。Conversation 的全部控制/终态修订已进入 Team E2EE outbound→authenticated inbound replay，伪造 readback、伪造独立 Verification 和本地控制分叉都会失败关闭。这仍是 E2，不是 Dioxus E3 或真实 Gmail/Outlook E4。
- VM-06 已有规范化 Creator Hiring/Task/Deliverable/Review/Payout 投影和 Application replay：公开候选只能研究；邀请必须重读当前联系许可；应聘必须来自已独立验证的邀请或悬赏发布；用户 Award 锁定申请、Offer digest 和选择证据；后续 Task 与付款不能伪造或绕过该 Award。Manifest v2 同时支持一次性 `campaign` 与长期 `continuous_relationship`，显式加入 Funding Reservation 和 Deliverable Entitlement；安全交付物先是 `evaluation_only`，接受后等待独立验证付款，只有匹配 digest 的已验证 Payout 才产生 `contract_usage_granted`，且 reservation 不得冒充法定 escrow。Payout `uncertain` 由无执行权的只读 reconciliation 查账，ReceiptFound 经独立 Verification 后把 Mission、Payout、使用权和审计事件原子 CAS；精确重放不增加付款记录。这仍是 E2，不是双边 Creator UI E3、真实网络/Stripe Connect E4 或 E5 经营证据。

不要从旧目录、聊天附件或其他 Hartevo 仓库复制历史代码。当前远程仓库是 Desktop 产品线唯一工程起点。

## 2. 新 Mac 的最小环境

### 2.1 Apple 开发工具

安装 Command Line Tools：

```bash
xcode-select --install
xcode-select -p
git --version
clang --version
```

Dioxus Desktop 官方说明 macOS 本地开发没有额外平台依赖。首个 Shell 与本地调试只要求 Rust 工具链和正常可用的系统 WebView。进入签名、公证、安装包和自动更新阶段前，再安装完整 Xcode 并单独记录 Apple Developer 身份与发布流程；不要把个人签名凭据提交到仓库。

### 2.2 GitHub 私有仓库身份

`tangpingqingwa/hartevo-desktop` 是私有仓库。先在 GitHub CLI 或 SSH 中完成有权限账号的认证。推荐使用 GitHub CLI：

如果新 Mac 尚未安装 `gh`，按 GitHub CLI 官方安装说明安装；Homebrew 只是可选安装方式，不是 Hartevo 构建依赖。

```bash
gh auth login
gh auth status
gh repo clone tangpingqingwa/hartevo-desktop
cd hartevo-desktop
```

如果使用 SSH，可以改为：

```bash
git clone git@github.com:tangpingqingwa/hartevo-desktop.git
cd hartevo-desktop
```

### 2.3 Rust 与 Dioxus

使用 Rust 官方 `rustup`，不要使用系统包管理器维护另一套并行 Rust：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup --version
cargo --version
```

当前固定审查的 OpenInterpreter 提交使用 Rust `1.95.0`，组件为 `clippy`、`rustfmt` 和 `rust-src`。Bootstrap R0 必须在仓库根目录提交自己的 `rust-toolchain.toml`；在该文件合并前，可先安装兼容工具链用于上游验证：

```bash
rustup toolchain install 1.95.0 --component clippy --component rustfmt --component rust-src
```

当前采用 Dioxus `0.7.10`。CLI 也必须固定版本，不能静默跟随最新 alpha 或未来 minor：

```bash
cargo install dioxus-cli --version 0.7.10 --locked
rustup toolchain install nightly --profile minimal
dx --version
dx doctor
```

应用与所有 Hartevo crates 仍由仓库固定的稳定 Rust `1.95.0` 编译。Dioxus CLI 0.7.10 会用 nightly 的 Cargo unit graph 发现构建单元，因此 desktop bundle/serve 需要可用的最小 nightly 工具链；nightly 不进入产品运行时依赖。若本机从源码安装 CLI 时缺少 OpenSSL/libgit2，请安装相应开发库，或使用启用 vendored OpenSSL/libgit2 的同版本 CLI 构建。

## 3. 克隆后的完整性检查

```bash
git switch main
git pull --ff-only origin main
git status --short
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

验收条件：

- `git status --short` 没有输出；
- `git rev-parse HEAD` 与 `git ls-remote` 输出的远程 `main` SHA 相同；
- `README.md`、`PRODUCT.md`、`DEVELOPMENT.md`、`docs/` 与 `prototype/` 均存在。

直接打开当前冻结原型：

```bash
open prototype/index.html
```

若浏览器限制 `file://` 且机器已经安装 Python 3，可在仓库根目录临时执行：

```bash
python3 -m http.server 8000 --directory prototype
open http://127.0.0.1:8000
```

Python 这里只是可选的静态原型预览手段，不是 Hartevo 产品运行时或出货依赖。

## 4. 开工前只读这些事实源

按 [README](./README.md) 的“开始阅读”顺序完成阅读。发生冲突时遵守 [事实源规则](./docs/SOURCE-OF-TRUTH.md)，尤其注意：

- OpenInterpreter 是 Agent Runtime 与 App Server 基座，不拥有 Hartevo 业务事实；
- Hartevo-owned 实现使用 Rust + Dioxus，不引入第二套 Electron/React/Python Agent Core；
- Mission、Task、Truth、Work Product、Effect、Receipt、Verification 和 Outcome 由 Domain Kernel 持有；
- 连接成功不等于允许发布、发送、花费或写 CRM；所有外部动作经过 Effect Broker；
- Hermes、PenguinHarness、Ego Lite 和 Prime Agent 只按各自 Intake 文档吸收机制，不复制其运行时或绕过 Hartevo 权限边界；
- AI CSS 只用于研究交互问题；不得复制付费源码、CSS、SVG 或高度近似实现。

## 5. 艰难问题与第一性原理

> 遇到艰难险阻，不要受限；从第一性原理出发，解决难关，创新架构。

这里的“不受限”是指不受既有实现、上游习惯、框架默认路径和历史偶然选择束缚。遇到关键难题时，不能只堆超时、重试、兼容分支或临时胶水，也不能因为某个开源基座没有提供能力就降低 Hartevo 的产品目标。按以下顺序处理：

1. 重新写出用户最终要达成的结果，以及不能破坏的领域、安全和权限不变量；
2. 用最小可复现 Case、Trace、性能数据或协议记录描述真实失败，不凭印象争论；
3. 区分硬约束与假设：操作系统、协议、物理资源和已验证法规是约束；上游目录、当前抽象、流行做法和“以前一直这样”只是候选方案；
4. 同时比较修复现有实现、替换抽象、拆分进程/状态所有权、重写 Rust 组件和设计新架构，而不是只优化眼前代码；
5. 在隔离分支做最小 Spike，用 Mission 完成度、安全、恢复、延迟、成本和可维护性共同评估；
6. 把结论写入 RFC/架构文档，保留被否决方案、迁移与回滚路径，并把故障固化为永久 Contract Test 或 Eval Fixture；
7. 如果证据证明当前子系统违反第一性原则或无法达到产品合同，应主动重构边界，不能因沉没成本继续堆补丁。

以下边界不可用“创新”绕过：用户 Consent 与 Approval、Effect Broker、安全与隐私、许可证和来源历史、跨项目隔离、确定性业务状态、私有 Benchmark 隔离及 Release Gate。真正的创新必须扩大产品能力，同时让权限、证据和失败恢复更加清晰。

## 6. Bootstrap R0 实现范围

从同步后的 `main` 创建独立分支：

```bash
git switch -c bootstrap/macos-r0
```

当前 `bootstrap/macos-r0` 分支已经交付：

1. 根目录 `rust-toolchain.toml`、Cargo workspace、`Cargo.lock`、格式化与 lint 策略；
2. 独立的 `hartevo-rs/` workspace/zone，以及最小 `desktop`、`domain-kernel`、`runtime-adapter`、`effect-broker` crate；
3. Dioxus Desktop Shell、Hartevo 品牌 token、Application-owned Project/Mission inventory、显式 SQLCipher 初始化、用户自持 Recovery Kit 个人项目 onboarding，以及诚实的 `NOT_IMPLEMENTED`/`BLOCKED_ENV` 状态；
4. OpenInterpreter 来源 manifest、Apache-2.0 `LICENSE`/`NOTICE`、固定 release/commit 与 schema digest；
5. App Server stable schema snapshot、digest、initialize/stream/interrupt/approval/resume 契约测试；实验 API 必须单独标注，不能混入稳定协议；
6. macOS CI：format、clippy、unit test、schema drift、Desktop smoke 与 VS-01 replay；
7. 本地配置示例与 Secret 规则；真实 Token、Cookie、OAuth refresh token 和签名证书不得进入 Git；
8. SQLite 项目快照、append-only Mission event log、跨项目隔离，以及确定性 VS-01 Eval 报告。

真实 OpenInterpreter 源码/二进制并未复制进本仓库；当前采用可审计来源 manifest + 固定 schema + 协议组合。引入真实 App Server 时必须保留上游历史或使用可审计 vendor zone，并单独补充进程级集成测试。

### 6.1 OpenInterpreter intake 的第一步

只添加和核验上游，不在命令行临时复制源码快照：

```bash
git remote add openinterpreter-upstream https://github.com/openinterpreter/openinterpreter.git
git fetch openinterpreter-upstream --tags
git cat-file -t 984acc698cd038885ecb0b82721402b01e11a5ad
git tag -l rust-v0.0.34
```

审查基线是提交 `984acc698cd038885ecb0b82721402b01e11a5ad`，公开稳定参考是 `rust-v0.0.34`。二者不自动等价于最终 R0 pin；PR 必须先比较 App Server schema、Harness 行为、安全测试和 macOS 构建。具体采用保留完整历史的 subtree、vendor zone 或其他可审计方式，应在 Bootstrap PR 中显式说明；禁止无来源复制和 `--squash` 后丢失升级依据。

## 7. 当前验收命令

以下命令已在 2026-08-10 的 Apple Silicon macOS 环境验证：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test -p hartevo-cloud-storage --locked -- --nocapture
bash scripts/check-openinterpreter-schema.sh
cargo run -p hartevo-eval --locked -- catalog validate
cargo run -p hartevo-eval --locked -- catalog export --output target/eval/catalog-v1.json
cargo run -p hartevo-eval --locked -- evidence baseline --commit "$(git rev-parse HEAD)" --output target/eval/release-baseline.json
cargo run -p hartevo-eval --locked -- run --mission VS-01 --output target/eval/vs-01.json
bash scripts/check-distribution.sh self-test
bash scripts/check-distribution.sh gate --output target/distribution --ci-status LOCAL_SCOPED
cargo run -p hartevo-eval --locked -- distribution validate --gate target/distribution/gate.json --commit "$(git rev-parse HEAD)"
dx doctor
bash scripts/check-dioxus-toolchain.sh self-test
mkdir -p target/evidence
bash scripts/check-dioxus-toolchain.sh build > target/evidence/dioxus-build-provenance.json
bash scripts/check-dioxus-toolchain.sh verify-receipt target/evidence/dioxus-build-provenance.json
dx serve --package hartevo-desktop
```

Dioxus bundle gate 以 [`contracts/toolchain/dioxus-cli-build.json`](./contracts/toolchain/dioxus-cli-build.json) 固定 CLI `0.7.10`、Desktop package、命令、feature 与 `.app` 目录结构；每次 build 对 bundle 内全部常规文件的相对路径、内容 SHA-256 和字节数生成确定性 tree digest，并输出本次 provenance receipt。`self-test` 只使用临时 fixture/fake CLI，不执行真实构建；正式 `build` 或 `verify-receipt` 遇到 CLI 缺失、版本错误、命令失败、产物漂移或 digest 回读不一致均以非零退出，`BLOCKED_ENV` receipt 也不能作为通过证据。

DIST-01 distribution gate 只生成当前 `HEAD` 绑定的 manifest、CycloneDX SBOM、TUF-like signed update metadata、rollback authorization check、默认关闭的 content-free telemetry 和 restore-drill report；它会保留 `releaseDecision: NOT_EVALUATED`、`releaseReady: false` 与 `nativeEvidence: NOT_PROVEN`。没有 GitHub Actions 执行权时用 `--ci-status CI_NOT_EXECUTED`，不得把账单/权限失败伪装成通过；`LOCAL_SCOPED` 只表示本机等价检查。测试签名密钥、SQLite/SQLCipher simulator 和 `BLOCKED_ENV` 结果都不会计入产品完成或 release evidence。

OpenInterpreter 边界的当前验证命令为：

```bash
cargo test -p hartevo-runtime-adapter
bash scripts/check-openinterpreter-schema.sh
```

Browser 真实环境 smoke 默认保持 `ignored`，必须显式指定受审查的 Chrome 可执行文件；macOS 用例只在 headless 测试模式加入 Chromium 官方测试开关 `--use-mock-keychain`，不读取、创建或重置用户 Chrome 钥匙串：

```bash
HARTEVO_TEST_CHROME_BINARY="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" cargo test -p hartevo-browser-adapter --locked real_chromium_pipe_health_and_ax_smoke -- --ignored
HARTEVO_TEST_CHROME_BINARY="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" cargo test -p hartevo-application --locked real_chromium_application_handoff_and_restart_smoke -- --ignored
```

第一条命令还证明受管理私有 Profile 上 test-only loopback 的 script-disabled exact-origin 导航、同源 AX readback、document generation 更新、stable locator 跨页面重解析和歧义拒绝、跨 origin redirect 在 HTTP request dispatch 前失败关闭，以及精确 Effect-bound semantic text input、File Broker→file-input selection、semantic click 的 DOM/viewport/hit-test/focus/AX readback、真实同源表单提交、单次使用和异步 readback；第二条证明 Application takeover/restart/continue。两者都覆盖进程组清理。它们不证明 active-script/authenticated navigation、真实账号登录、Cookie 迁移、密码/替换/raw keyboard、真实 Provider 文件提交、零 speculative DNS/TCP、生产写入或独立在线 Verification。实现使用 Chromium 官方的 [`Page.navigate`/frame/lifecycle`](https://chromedevtools.github.io/devtools-protocol/tot/Page/)、[`Accessibility.getFullAXTree`](https://chromedevtools.github.io/devtools-protocol/tot/Accessibility/)、[`DOM.focus`/geometry/hit-test/`setFileInputFiles`](https://chromedevtools.github.io/devtools-protocol/tot/DOM/)、[`Input.insertText`/`dispatchMouseEvent`](https://chromedevtools.github.io/devtools-protocol/tot/Input/) 与 [`Emulation.setScriptExecutionDisabled`](https://chromedevtools.github.io/devtools-protocol/tot/Emulation/) 合同。

`cargo run -p codex-app-server` 当前不是有效命令，因为真实上游 binary 尚未进入 workspace。已验证环境为 Apple Silicon `aarch64-apple-darwin`、Rust `1.95.0`、Dioxus CLI `0.7.10`；Intel macOS、Windows、Linux、签名与公证尚未验证。合并前仍必须由 CI 和一台干净 macOS 机器复跑，不能只依赖开发者已有环境。

## 8. 分支与提交纪律

- `main` 始终保持可克隆、文档无冲突和已声明命令可复现；
- 上游升级使用 `upstream-intake/<date>-<sha>`，不直接在 `main` 拉取；
- 功能分支以 `feature/`、`fix/`、`eval/` 或 `docs/` 开头；
- 不提交 `.env`、账号数据库、浏览器 Profile、下载文件、Eval 私有 Holdout 或生产 Replay 原文；
- 每个“完成”声明必须链接代码、测试、Commit 和可重放证据；Target Contract 本身不是完成证明。

## 9. 官方依据

- [Apple：安装 Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools)
- [GitHub CLI 安装说明](https://cli.github.com/manual/installation)
- [Rust/Cargo 官方安装说明](https://doc.rust-lang.org/stable/cargo/getting-started/installation.html)
- [Dioxus 0.7 Getting Started 与 macOS 依赖](https://dioxuslabs.com/learn/0.7/getting_started/)
- [Dioxus v0.7.10](https://github.com/DioxusLabs/dioxus/releases/tag/v0.7.10)
- [OpenInterpreter Rust v0.0.34](https://github.com/openinterpreter/openinterpreter/releases/tag/rust-v0.0.34)
- [固定 OpenInterpreter 审查提交](https://github.com/openinterpreter/openinterpreter/tree/984acc698cd038885ecb0b82721402b01e11a5ad)
- [Chromium：`--use-mock-keychain` 仅供测试、防止阻塞式钥匙串对话框](https://chromium.googlesource.com/chromium/chromium/+/master/chrome/common/chrome_switches.cc)
