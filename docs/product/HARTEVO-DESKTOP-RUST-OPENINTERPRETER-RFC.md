# Hartevo Desktop Rust 与 OpenInterpreter 基座 RFC

状态：**Accepted**
版本：1.1
日期：2026-08-09
审查基线：`openinterpreter/openinterpreter@984acc698cd038885ecb0b82721402b01e11a5ad`

## 1. 决策

Hartevo Desktop 采用 Rust-first 架构：产品代码、桌面 Shell、领域内核、本地协议、运行时适配、外部动作治理、持久化和 Eval Harness 均以 Rust 实现。静态 CSS、图标和操作系统 WebView 属于呈现资产，不引入 React、Vue、Svelte 或 Node 运行时。

主技术基座采用新版 Rust OpenInterpreter。它是基于 OpenAI Codex 演进的 Rust Agent Runtime，重点解决开放模型、低成本模型、多 Provider、模型专用 Harness、Codex 协议兼容和跨平台本地执行。

桌面 UI 使用 Dioxus Desktop，以 Rust/RSX 编写组件并通过 HTML/CSS 渲染。AI CSS 只作为 Agent 交互问题与公开演示的研究参考。Hartevo 不购买其 Personal 或 Enterprise license，不复制其付费源码、CSS、SVG 或高度近似实现；全部产品组件根据 Hartevo 需求独立设计并以 Rust/Dioxus 实现。

这项决策是本仓库唯一有效的技术基座；被替代方案不在当前文档集中保留，避免形成双基座。

## 2. 对 OpenInterpreter 的核验结论

审查对象不是经典 Python OpenInterpreter。当前主仓库已经切换为新的 Rust 产品：

- 代码主体为 Rust，审查时 GitHub 语言统计约 44.9 MB Rust。
- `codex-rs` 包含约 130 个 Workspace member、138 份 Cargo manifest、2,835 个 Rust 源文件、153 份 Bazel build 文件。
- 仓库保留 Codex App Server、Exec、MCP、Skills、Plugins、Hooks、审批、沙箱、会话、子代理和跨平台执行能力。
- OpenInterpreter 新增 Provider / Model / Harness 三层分离，并提供 Kimi Code、DeepSeek TUI、Qwen Code、Claude Code、SWE-agent、Minimal 等模型适配面。
- App Server 提供 `interpreter/provider/*`、`interpreter/model/*`、`interpreter/harness/*`，并保留 Codex `thread`、`turn`、流式 item、审批和状态协议。
- 支持 Responses、Chat Completions 和 Anthropic Messages 三种 wire API；模型元数据包含 reasoning effort、service tier、输入模态和能力信息。
- 支持 macOS、Linux/WSL 和 Windows 的本地沙箱与审批策略。
- 支持 ACP，因此可以被结构化客户端使用，而不是抓取 TUI 文本。
- 许可证为 Apache-2.0，并带有 OpenAI Codex NOTICE；派生项目必须保留许可证和通知。

“Rust 构建整个产品”在本 RFC 中指：所有 Hartevo-owned 产品逻辑和出货运行时使用 Rust。OpenInterpreter 上游并非全仓 100% Rust，仍包含 Python/TypeScript SDK、生成脚本、Shell、PowerShell 和 Bazel/Starlark。它们不进入 Hartevo Desktop 运行时，但可能参与上游构建和代码生成。若要求连构建工具与上游 SDK 都不得出现非 Rust 源码，则 OpenInterpreter 不满足该约束，需要放弃本基座。

### 2.1 证明它适合作为运行时基座的部分

1. **开放模型 Harness 是一等能力。** Harness 会改变 system prompt、工具 schema、消息转换、请求形状和响应后处理，而不是只换 base URL。
2. **模型控制符合当前产品设计。** Provider、Model、Reasoning Effort 和 Service Tier 已进入结构化协议，可直接支撑 Hartevo Composer 的模型、推理强度和速度选择。
3. **本地执行成熟。** 文件、Shell、Patch、MCP、Skills、Hooks、沙箱、审批和恢复已经形成可测试的 Rust 系统。
4. **App Server 是合适的隔离层。** Hartevo 可以通过本地 JSON-RPC 使用运行时，避免直接侵入体积庞大的 `codex-core`。
5. **上游仍在吸收 Codex。** OpenInterpreter 的贡献规范明确要求通用修复优先进入 OpenAI Codex，再通过 upstream sync 到达 OpenInterpreter。

### 2.2 它不能直接替代 Hartevo 的部分

1. **它是 coding-agent runtime，不是增长业务内核。** 核心对象仍是 cwd、workspace root、thread、turn、tool item 和文件/命令执行。
2. **TUI 不是目标 Desktop。** 仓库没有可直接换皮为 Hartevo 的成熟增长业务 GUI；`desktop_app` 代码只是安装/打开既有桌面应用的辅助逻辑。
3. **本地审批不等于业务审批。** 命令和文件审批不能覆盖发邮件、发布社媒、广告花费、CRM 写入、联盟付款和重复触达风险。
4. **开放模型优化主要针对 coding。** “接近 Codex”必须用 Hartevo Mission Eval 重新证明，不能从代码任务表现外推到增长经营。
5. **上游很大且变化快。** 直接在 `codex-core` 堆叠业务逻辑会快速失去上游同步能力。
6. **App Server 的一部分字段仍是 experimental。** Hartevo 必须固定 schema digest，并在升级前跑契约测试。

## 3. 产品对象与运行时对象的边界

| Hartevo 对象 | OpenInterpreter 对象 | 约束 |
| --- | --- | --- |
| User / Organization | Account / runtime home | 账户不是租户业务事实源 |
| Promotional Project | cwd + runtime workspace roots + config profile | Project 拥有 Truth、连接、审批与成果；cwd 只是执行范围 |
| Mission | 一个或多个 Thread lineage | Mission 可跨线程、模型、设备和多日运行 |
| Task | Turn、plan item 或 child agent job | Runtime task 只是一种执行投影 |
| Work Product | Agent item、文件或 Artifact | 必须登记为领域对象并绑定来源、版本和采用状态 |
| Approval | Command/File approval + Hartevo Effect approval | 两层审批不能互相替代 |
| Effect / Receipt / Verification | Tool call / tool result | Tool 成功不等于外部业务结果成功 |
| Outcome / Attribution | 无直接等价物 | 由 Hartevo Domain Kernel 独占 |

禁止把 `threadId`、`turnId`、私有 tool name 或 harness ID 暴露成 Hartevo 业务主键。

## 4. 目标技术栈

| 层 | 技术 | 选择理由 |
| --- | --- | --- |
| Desktop UI | Rust + Dioxus Desktop 0.7.x + RSX + plain CSS | 保持 Rust UI；兼容 HTML/CSS 设计资产；跨平台打包与系统访问；上游为 MIT/Apache-2.0 双许可 |
| Desktop state | Rust signals + typed application state | Project、Mission 和运行时流式状态不经过 JS bridge |
| Domain Kernel | 独立 Rust crates | 领域事实不进入 OpenInterpreter 私有 core |
| Local storage | SQLite + typed migrations | 本地优先、事务、可重放事件、离线项目 |
| Optional cloud | Hartevo Cloud API + encrypted sync adapter | 创建项目不隐含上传 |
| Agent Runtime | Pinned OpenInterpreter App Server | 开放模型 Harness、Codex 协议、工具、Skills、MCP、沙箱 |
| Runtime transport | child process + stdio JSON-RPC v2 | 本地、无监听端口、崩溃隔离、可升级、边界清晰 |
| Credentials | OS keyring，通过 Rust keyring adapter | Secret 不进入项目、Prompt、日志或 UI state |
| Effect execution | Rust Effect Broker + typed provider workers | 幂等、审批、回执、验证和重试策略 |
| Browser work | 受控 Browser/Computer adapter | Profile、人工接管、验证码和登录状态独立治理 |
| Eval | Rust Mission Harness + provider simulators | 同一类型和状态机可用于产品与验收 |

### 4.1 为什么不是 Tauri + React

Tauri 本身很好，但典型方案仍需要 JavaScript UI 运行时。当前目标明确要求 Rust 构建整个产品，同时希望复用 plain CSS Agent 组件。Dioxus Desktop 在 Rust 中提供 HTML/CSS、状态管理、桌面打包和系统能力，更符合这两个约束。

### 4.2 为什么不是纯原生绘制 UI

Slint、Iced 或 WGPU/Skia 可以避免 WebView，但会失去 AI CSS 的可移植价值，也会显著增加富文本、流式内容、表格、引用、Diff 和可访问性实现成本。首版不为渲染纯度牺牲产品速度。

## 5. 进程与信任边界

```text
Hartevo Desktop (Rust + Dioxus)
├─ Hartevo Domain Kernel
├─ Project / Mission Store
├─ Effect Broker
├─ Runtime Supervisor
│   └─ OpenInterpreter App Server (Rust child, stdio JSON-RPC)
├─ Browser / Computer Adapter
├─ Connector Workers
└─ Sync Adapter
```

- Desktop 进程拥有用户体验和 Hartevo 领域状态。
- OpenInterpreter child 拥有模型请求、Agent loop、工具执行、local sandbox 和 runtime thread。
- Runtime 只能看到当前 Project 明确授予的 workspace roots 和动态工具。
- Effect Broker 独占外部写入能力；模型不能直接拿到社媒、邮件、CRM、广告或付款凭据。
- Browser/Computer Adapter 独占登录 Profile 和人工接管状态。
- 不在本地开放未认证 WebSocket；首版只使用 stdio。远程 Worker 必须经过独立身份、TLS 和租约设计。

## 6. Hartevo-owned Rust Workspace

建议新增独立 `hartevo-rs/` Cargo workspace，不把业务代码塞进 OpenInterpreter 的 `codex-core`：

```text
hartevo-rs/
  desktop/                 # Dioxus Desktop entrypoint
  ui/                      # Hartevo components and design tokens
  application/             # commands, queries, orchestrator projections
  domain/                  # Project, Mission, Truth, CRM, Partner, Outcome
  storage/                 # SQLite, migrations, event log
  protocol/                # Hartevo-owned DTO and event schema
  runtime-adapter/         # App Server supervisor and JSON-RPC mapping
  capability-gateway/      # typed tools exposed to the runtime
  effect-broker/           # approval, idempotency, receipt, verification
  connector-sdk/           # provider contracts
  browser-adapter/         # browser/computer boundary
  sync/                    # optional encrypted sync
  eval/                    # Mission fixtures, journey runner and oracle
```

OpenInterpreter 源码保留在清晰的 upstream zone。首版通过协议组合，不直接依赖内部 private crates；确需修改上游时，先判断是否应提交 OpenInterpreter 或 Codex 上游。

## 7. Keep / Wrap / Replace / Add

| OpenInterpreter 能力 | 决策 | Hartevo 用法 |
| --- | --- | --- |
| App Server v2 / Exec 协议 | Keep | Runtime Adapter 的主边界 |
| Provider / Model / Harness catalog | Keep + Wrap | 在 Composer 中展示经过 Hartevo 策略筛选的选项 |
| Kimi / DeepSeek / Qwen / Claude / Minimal harness | Keep | 作为候选运行配置，必须经 Mission Eval |
| Thread / Turn / Item streaming | Wrap | 投影为 Mission live work，不成为领域事实 |
| Sandbox / local approvals | Keep | 管理文件和命令风险 |
| MCP / Skills / Plugins / Hooks | Wrap | 进入 Capability Registry、信任和项目 Scope |
| Keyring store | Keep / Adapt | 统一到 Hartevo credential reference |
| TUI | Keep for diagnostics | 不作为最终产品 UI |
| Codex branding、coding-only prompts | Replace | 使用 Hartevo 品牌和增长 Mission context |
| Account / rate-limit UI | Wrap / Replace | 映射到 Hartevo 账户、组织和用量 |
| Growth Domain Kernel | Add | Hartevo 唯一事实源 |
| Effect Broker / Verification | Add | 外部业务副作用治理 |
| Dioxus Desktop Shell | Add | 当前冻结交互的 Rust 实现 |
| Mission Harness | Add | 证明低成本模型在增长任务上的真实能力 |

## 8. 模型、推理强度与速度

Composer 不展示一个脱离 Provider 的静态模型表，而是消费运行时的结构化能力：

1. Provider 负责 endpoint、auth 和 wire API。
2. Model 负责上下文、模态和支持的 reasoning control。
3. Harness 负责 prompt、tools、message conversion 和 response handling。
4. Reasoning Effort 只显示模型真正支持的值。
5. Speed 映射为 service tier、路由策略或成本/延迟 preset，不能伪造模型不支持的参数。

Hartevo 提供面向用户的预设，例如“快速整理”“平衡执行”“深度研究”，但必须在详情中显示实际 Provider、Model、Harness、Effort、Service Tier、预计成本和数据去向。

## 9. 低成本模型验证策略

OpenInterpreter 的 Harness 是候选策略，不是质量承诺。每个 Provider/Model/Harness 组合必须在 Hartevo Mission Catalog 上得到版本化结果：

- Goal / Constraint 保真率。
- Tool selection 与参数正确率。
- 长任务恢复和 Replan。
- Evidence 与 Work Product 质量。
- Approval、Consent 和 Effect 安全。
- Receipt / Verification / Outcome 完整度。
- 首 Token、总时长、Token、Provider 成本和人工返工。

同一模型至少比较 `native`、推荐 Harness 和 Hartevo Growth Harness。只有在质量、成本和安全同时达到 Gate 时，才进入默认模型列表。

## 10. AI CSS 采用边界

AI CSS 当前提供 14 个 Agent UI 组件，覆盖思考状态、工具动作、文本、引用、代码、任务列表、表格和 Composer；9 个免费，其余需要一次性授权。组件提供 React、Vue、Svelte 源码和 plain CSS，没有 Tailwind 依赖。

Hartevo 不购买 AI CSS 许可证。采用边界是：

- 研究这些组件解决了什么交互问题，例如信息密度、状态转换、动效、折叠、引用和结果呈现。
- 从 Hartevo 的 Mission、Task、Evidence、Effect、Receipt 和 Work Product 状态模型出发，独立完成产品设计与 Rust/Dioxus 实现。
- AI Agent Input、Thinking State、Thinking + Reasoning、Orbs、Text Response、Streaming Text、Code Block、Task List、Data Table 可作为公开参考；若直接使用其明确免费的代码或资产，必须单独完成来源与商用条款审查。
- Web Search、File Diff、Image Generation、Inline Citations、Comparison Table 仅允许参考公开功能说明和演示表达的交互目标，不得获取、复制或改写其付费源码、CSS、SVG。
- 不制作与付费组件高度近似、可被视为派生复制品的实现；同类能力必须具有 Hartevo 自己的业务语义、信息架构、状态和视觉表达。
- 改变“不购买许可证”的决策必须经过新的 RFC，不得由开发者、设计师或依赖升级隐式改变。
- 所有组件必须重新映射 Hartevo 品牌 token、中文排版、业务状态、WCAG 2.2 AA 和 reduced motion。

## 11. 仓库与上游策略

当前 `hartevo-desktop` 仓库继续作为产品主仓库。代码导入前执行一次独立 bootstrap PR：

1. 添加 `openinterpreter-upstream` remote，并记录审查 commit、release、Apache-2.0、NOTICE 和源码来源。
2. 保留 OpenInterpreter 完整历史或可审计的 subtree 历史；不复制无来源源码快照。
3. `main` 只接受通过协议契约和 Mission smoke test 的上游 intake。
4. 使用 `upstream-intake/<date>-<sha>` 隔离升级。
5. Hartevo-owned crates 与 upstream zone 分开，禁止顺手修改 `codex-core`。
6. 每次升级记录 App Server schema digest、Provider catalog version、Harness behavior diff 和安全回归。
7. Hartevo 只跟踪 OpenInterpreter 上游；OpenInterpreter 与 Codex 的同步由其上游维护，避免双重 rebase。

审查 commit 是工程研究基线，不自动等同于生产发布 pin。首个 bootstrap PR 必须在 release tag 与当前 commit 之间做兼容性测试，再确定 R0 的固定版本。

## 12. 安全不变量

- OpenInterpreter 的 local approval 不能批准 Hartevo external Effect。
- Connection 成功不等于允许发送、发布、花费或写 CRM。
- Provider tool result 不等于业务成功，必须有独立 Receipt 与 Verification。
- Secret、Cookie、OAuth refresh token 和 API key 不进入 Prompt、项目文件、同步包或普通日志。
- Runtime thread 只能绑定一个 Project execution scope；跨项目复用必须显式授权。
- 不确定的外部写入、付款和可能重复的触达禁止自动重试。
- Harness prompt、第三方 Skill、Plugin 和 Hook 都按可执行供应链资产审查。
- AI CSS 付费源码、CSS、SVG 及其派生复制品不得进入 Git 历史。

## 13. 首个 90 天路线

### 阶段 A：Bootstrap（第 1–2 周）

- 引入 OpenInterpreter 历史与许可证。
- 建立 `hartevo-rs` workspace、Dioxus Shell 和 CI。
- 用 Rust Runtime Adapter 启动 `interpreter app-server`，完成 initialize、thread、turn、stream、interrupt、approval。
- 固定 JSON-RPC schema digest 和进程恢复测试。

### 阶段 B：Project / Mission vertical slice（第 3–5 周）

- SQLite Project、Mission、Task、Work Product 和 event log。
- 本地文件夹选择、workspace roots、OS keyring 和项目 Scope。
- 自然语言目标编译、共享 Mission State 和总调度。
- Composer 模型、推理强度、速度与 Harness 映射。

### 阶段 C：Growth capability 与 Effect（第 6–9 周）

- Research、Evidence、Content、CRM/Creator 的首批 typed capability。
- Effect Broker、审批、幂等、Receipt 和 Verification。
- 参考公开交互问题，独立实现 Hartevo Agent UI primitives 并完成品牌 token 化。
- 至少两种低成本模型和一个强模型的 Mission Eval。

### 阶段 D：受控 Pilot（第 10–13 周）

- 一条真实但低风险的外部动作闭环。
- 断网、崩溃、重启、取消、redirect、模型切换和长任务恢复。
- 签名、自动更新、SBOM、NOTICE、依赖审计和安装包。
- Mission Eval、SLO、错误预算和 Go/No-go 评审。

## 14. Go / No-go

满足以下条件才正式进入产品实现：

- OpenInterpreter App Server 可在 Windows、macOS、Linux 由 Rust Shell 稳定监管。
- 不修改 `codex-core` 即可完成模型选择、stream、approval、interrupt 和 resume。
- Dioxus 能达到冻结原型的关键交互与可访问性要求。
- 一个低成本模型组合在首批 Hartevo Mission 上达到最低质量 Gate。
- Domain Kernel 和 Effect Broker 保持独立，不需要把业务事实写入 runtime thread。
- 上游 intake 可在可接受的工程时间内完成。

若 App Server 协议不足，优先向 OpenInterpreter 上游增加通用协议，不在 Hartevo 中建立私有深叉。若 Dioxus 无法满足关键交互，再单独通过 RFC 评估 Tauri + Web frontend；不得静默混入第二套 UI 技术栈。

## 15. 主要依据

- [OpenInterpreter repository](https://github.com/openinterpreter/openinterpreter)
- [审查 commit](https://github.com/openinterpreter/openinterpreter/tree/984acc698cd038885ecb0b82721402b01e11a5ad)
- [Rust release v0.0.34](https://github.com/openinterpreter/openinterpreter/releases/tag/rust-v0.0.34)
- [Harness 设计](https://github.com/openinterpreter/openinterpreter/blob/984acc698cd038885ecb0b82721402b01e11a5ad/docs/harness.md)
- [Provider 与模型](https://github.com/openinterpreter/openinterpreter/blob/984acc698cd038885ecb0b82721402b01e11a5ad/docs/providers.md)
- [App Server](https://github.com/openinterpreter/openinterpreter/blob/984acc698cd038885ecb0b82721402b01e11a5ad/docs/app-server.md)
- [Sandbox 与审批](https://github.com/openinterpreter/openinterpreter/blob/984acc698cd038885ecb0b82721402b01e11a5ad/docs/sandbox.md)
- [Apache-2.0 License](https://github.com/openinterpreter/openinterpreter/blob/984acc698cd038885ecb0b82721402b01e11a5ad/LICENSE)
- [Dioxus v0.7.10](https://github.com/DioxusLabs/dioxus/releases/tag/v0.7.10)
- [AI CSS component index](https://www.aicss.dev/llms.txt)
- [AI CSS pricing and usage terms](https://www.aicss.dev/pricing)
