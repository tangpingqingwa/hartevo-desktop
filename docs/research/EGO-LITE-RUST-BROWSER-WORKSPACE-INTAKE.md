# Ego Lite → Hartevo Rust Browser Workspace 能力引入清单

状态：**Accepted**
版本：1.0
日期：2026-08-10
稳定标签基线：`citrolabs/ego-lite@v1.2.5`（commit `fd3aae7146cf6c9c52014a9752f411bf9978ae93`）
最新 beta 标签：`v1.3.1-beta.4`（commit `53443440b2c96859a0c9371f9733a97caa955019`；与当前 `main` 已分叉）
主分支审查基线：`c46a439e7fbad90ad33dbea6c6af329b6009809f`（2026-08-10）

## 1. 决策

Ego Lite 被纳入为 **Browser Workspace / Human Handoff Reference**，不是 Hartevo 的第四套 Agent Runtime，也不是直接出货依赖。Hartevo 吸收它在 Agent 专属浏览空间、登录状态复用、用户与 Agent 控制权交接、语义快照、稳定定位、批量浏览器动作和站点经验包方面的机制，并在 Hartevo-owned Rust `browser-adapter` 中独立实现。

当前上游分工固定为：

| 来源 | 在 Hartevo 中的定位 |
| --- | --- |
| OpenInterpreter | Rust Agent Runtime、Provider/Model/Harness、工具、沙箱与 App Server 主基座 |
| Hermes Agent | 长期 Agent、桌面体验、自治可靠性和跨系统能力参考 |
| PenguinHarness | Harness Lab、极简工具面、Trace/Eval、候选优化与版本晋升参考 |
| Ego Lite | Browser Workspace、语义/视觉自动化、登录复用与人机控制权交接参考 |
| Hartevo Domain Kernel | Project、Mission、Truth、Consent、Effect、Outcome 的唯一事实源 |

Ego Lite 的 TypeScript/Node harness、下载版 Chromium 应用和其私有 `globalThis.ego` runtime 不进入 Hartevo Desktop。不会同时运行 Ego Lite 与 Hartevo Browser Host，也不会把其 Task Space 当成新的业务任务或会话系统。

## 2. 审查事实

### 2.1 公开仓库不等于完整浏览器

公开仓库包含 MIT 许可的 `ego-browser` Agent Skill、TypeScript/JavaScript helper harness、站点 learnings、测试和构建脚本。仓库自己的工程说明明确指出：真正提供 tabs、Task Spaces、增强 snapshot 和 CDP bridge 的 Ego Lite App 是闭源应用，不在该仓库中；公开 helper 通过 `globalThis.ego` 调用它。

因此：

- 公开代码可以作为协议、交互和实现研究对象。
- 无法从该仓库审计浏览器内核、Profile 加密、Task Space 隔离和增强 snapshot 的完整实现。
- 仓库 MIT License 不能被自动外推为下载版浏览器二进制的源码许可。
- Hartevo 不以闭源 Ego Lite App 为必要依赖，也不声称已经获得其私有 runtime 源码。

### 2.2 当前产品与工程成熟度

在固定审查 commit 上：

- GitHub 语言统计以 JavaScript、TypeScript 为主；运行时要求 Node.js 22+。
- 官方 README 当前声明只支持 macOS，Windows 与 Linux 位于 Roadmap。
- Task Space 拥有独立标签集合，并默认继承当前用户登录状态；所有权状态包含 `agent`、`agentDelegatedToUser` 和 `user`。
- helper 提供页面导航、语义 snapshot、截图、定位器、键鼠、上传下载、CDP、浏览器上下文 fetch、Task Space 生命周期和站点 learnings。
- 当前主分支 CI 的 `test` job 通过。本地 Windows 审查中 299 个测试通过，站点 learnings validator 通过。
- 标准 `npm ci` prepare 与 `npm run validate:site-skills` 使用 POSIX shell/env 语法，在 Windows PowerShell/cmd 下不能原样执行；这与其当前 macOS 产品范围一致，但证明它不适合作为 Hartevo 的跨平台直接依赖。
- 仓库有稳定和 beta Git tag，但审查时 GitHub `releases/latest` 没有可用 Release 对象，最新 beta 与当前 `main` 也已分叉。生产版本不能根据 README metadata、package version 或 `latest` tag 猜测，必须固定 commit。

README 中“最高 2.5× 更快”和更低 Token 的对比是上游在四个任务上的产品主张。仓库没有提供足以替代 Hartevo Mission Harness 的完整独立基准合同，因此不能将这些数字作为架构或发布证据。

## 3. 最值得吸收的机制

### 3.1 Mission-bound Browser Workspace

Ego Lite 的 Task Space 把 Agent 标签与用户普通标签分开，并在多轮 Agent 执行间复用同一空间。Hartevo 应将其提升为与 Project、Mission 和登录身份绑定的 `BrowserWorkspace`：

```text
Project
  └─ BrowserProfile (account identity + cookie boundary)
       └─ BrowserWorkspace (mission-bound tabs + control lease)
            ├─ BrowserTab
            ├─ SemanticSnapshot
            ├─ BrowserActionBatch
            └─ BrowserReceipt / Verification
```

Workspace 是 Mission 的执行资源，不是新会话，不拥有 Truth、Consent、Approval 或 Outcome。任务修正、重试和验证应恢复原 Workspace；只有新 Mission、Profile 不兼容或原空间不可恢复时才创建新空间。

### 3.2 独占控制权与硬停止

Ego Lite 把用户接管建模成一等状态：当用户控制 Task Space 时，Agent 操作失败，并被要求停止重试、等待用户明确继续。这比“Agent 仍在后台点击，只在 UI 显示人工接管”可靠得多。

Hartevo 应采用带版本的独占租约：

```text
agent_controlled
  ── handoff / user_takeover ──> user_controlled
user_controlled
  ── explicit_continue + compare-and-swap ──> agent_controlled
agent_controlled | user_controlled
  ── pause ──> paused
paused
  ── resume with fresh lease ──> agent_controlled | user_controlled
* ── verified completion ──> completed ──> closed | kept_for_user
```

任何控制权变化都必须递增 `lease_generation`。Agent 的每个动作批次携带 `workspace_id + lease_id + generation`；用户接管提交后，旧租约的后续动作必须在 Browser Host 边界被拒绝，而不是依赖 Prompt 自觉停止。

### 3.3 语义快照、短期 Ref 与稳定定位

Ego Lite 的 snapshot 同时返回压缩文本、`backendNodeId` ref 和稳定 locator 候选。临时 `@N` ref 只对最近一次 snapshot 有效；站点经验不得固化这些短期 ref。

Hartevo 应独立实现 `SemanticSnapshot`：

- 合并 Accessibility Tree、必要 DOM 属性、可操作性、URL 和 iframe 边界。
- 明确 `snapshot_id`、tab、frame、文档版本、viewport、生成时间和脱敏策略。
- 临时 `element_ref` 只能在同一 snapshot/generation 内使用。
- 可复用定位器必须通过唯一性、可见性和稳定性校验，并记录 fallback 次序。
- 页面变化后先重新观察；不能因为旧 ref 仍能解析就认为目标业务对象未改变。

Snapshot 是执行上下文，不是业务证据本身。发布、发送、保存或购买仍需要 Receipt、readback、截图或 Provider 查询等独立 Verification。

### 3.4 语义、视觉和协议三级降级

Ego Lite 区分三种页面工作流：普通 DOM 优先语义定位；Canvas、富编辑器和高度虚拟化界面使用截图与真实键鼠；必要时才进入直接 DOM/CDP。

Hartevo 采用相同的路由原则：

1. `Semantic`：首选，可审计，Token 成本低。
2. `Visual`：用于 Canvas、地图、表格和富编辑器；先小范围探针，再截图/readback 验证。
3. `Protocol`：只开放经过白名单的 CDP 能力；任意脚本执行不是默认路径。

三级降级必须进入 Trace，说明为何从语义路径降级、执行了什么探针以及如何验证，避免 Agent 在页面结构异常时盲点或盲写。

### 3.5 批量 Browser Plan

Ego Lite 让模型在一次 Node heredoc 中组合多步 helper，减少“调用两个工具—读取输出—再调用两个工具”的往返。Hartevo 吸收其低往返思想，但不执行模型生成的任意 Node.js。

Runtime 生成受限、可验证的 `BrowserActionBatch`：

```text
observe → resolve → act → wait → verify → emit typed result
```

Batch 只能引用注册动作、参数 schema、当前 Workspace 和租约；遇到页面变更、登录、CAPTCHA、账号不符、审批点、Prompt Injection 或不确定写入立即终止。跨观察边界的动作必须重新规划，不能把整个复杂 Mission 打包成不可中断脚本。

### 3.6 站点经验包

Ego Lite 将站点知识组织为 domain manifest、说明、Node tools 和 browser tools，并验证路径、参数/返回类型、域名和临时 ref。这个思路适合 Hartevo 的渠道、社媒、CRM 与达人平台。

Hartevo 对应对象为 `BrowserRecipePackage`：

- 固定来源、版本、适用域名、账号类型和 UI 版本范围。
- 声明只读/写入能力、Effect class、所需 Scope、审批和成本边界。
- 定位器、提取 schema、等待条件、验证方法和失效信号分开保存。
- 代码、WASM 或协议动作均需要签名、静态审查、权限清单和沙箱。
- 成功 Trace 只能生成 `CandidateRecipe`，不能自动晋升生产 Recipe。

### 3.7 可观察的生命周期

Task Space 的 create/reuse/handoff/takeover/complete/keep/close 对桌面产品很重要。Hartevo 应把 Browser Workspace 状态投影到原 Mission Live Work：用户能看到 Hartevo 正在哪个账号、哪个页面、以什么权限操作，以及当前由谁控制；不需要进入新的“浏览器模块”或新会话。

## 4. Rust 能力引入矩阵

| Ego Lite 机制 | Hartevo Rust 归属 | 决策 | 阶段 |
| --- | --- | --- | --- |
| Task Space | `browser-adapter/workspace` | 重构为 Project/Profile/Mission-bound BrowserWorkspace | B0 |
| Agent/User ownership | `browser-adapter/control-lease` | 使用 lease generation、CAS 和显式继续确认 | B0 |
| Stable error codes / hard stop | `protocol/browser-event` | 建立 typed stop reason，控制权错误禁止重试 | B0 |
| Browser helper surface | `browser-adapter/action-schema` | 只暴露最小、类型化动作，不暴露任意 Node runtime | B0 |
| Snapshot + refs | `browser-adapter/semantic-snapshot` | Rust 实现 AX/DOM snapshot、短期 ref 与 locator 候选 | B1 |
| Multi-step heredoc | `browser-adapter/action-batch` | 改为可中断、带租约与策略检查的 typed batch | B1 |
| Playwright-style locator ergonomics | `browser-adapter/locator` | 吸收语义，不复制 TypeScript facade | B1 |
| Semantic / Visual / CDP fallback | `application/browser-router` | 记录降级理由、探针与 Verification | B1 |
| Site learnings | `browser-adapter/recipe-registry` | 版本化、签名、权限化 Recipe 与候选晋升 | B2 |
| Screenshot/screencast | `browser-adapter/observer` | 本地生成、敏感区域脱敏、按 Project retention 保存 | B2 |
| Downloads/uploads | `browser-adapter/file-broker` | 文件隔离、类型/大小/路径检查、恶意内容扫描 | B2 |
| Parallel spaces | `application/browser-scheduler` | 跨 Profile 有界并行；同 Profile 写操作串行 | B2 |
| Visible handoff | `ui/live-work` + `ui/workpad` | 在原 Mission 显示控制权、账号、标签和继续动作 | B2 |

## 5. 必须修正后再吸收的部分

### 5.1 不默认继承用户的整套个人浏览器身份

Ego Lite 把迁移 Chrome 数据和复用登录作为低摩擦卖点。Hartevo 面向多个品牌、市场、客户和团队，不能默认复制个人 Chrome Profile，更不能让不同项目共享 Cookie。

Hartevo 默认创建 **Project-bound managed profile**。若用户选择导入或附加现有 Profile，必须：

- 明确展示来源、目标 Project、将复制的数据类型和撤销方式。
- 不读取或迁移浏览历史、密码、扩展和书签，除非用户逐类选择且确有必要。
- 复制到受管理 Profile，而不是自动控制用户正在使用的主 Profile。
- 将 Cookie encryption key 保存在 OS keyring，禁止进入 Prompt、日志、项目文件或同步包。
- 切换 Project、账号或租户时重新验证 Profile identity，不复用旧 lease。

### 5.2 不执行模型生成的任意 Node.js

公开 helper 通过 `AsyncFunction` 执行 stdin JavaScript，并允许 Node 侧和页面侧脚本。这种通用性适合开发者工具，不适合默认持有社媒、邮箱、CRM、广告和联盟登录态的业务 OS。

Hartevo 默认只运行 typed Rust action。低层 CDP、页面 JavaScript、浏览器上下文 fetch 和文件系统访问必须分别授权、沙箱化并记录；生产 Recipe 不得通过动态 import 获取未声明权限。

### 5.3 Page-authenticated fetch 不能绕过 Effect Broker

浏览器上下文 `fetch` 会自动携带站点身份，可能直接产生发布、关注、邀请、购买、CRM 更新或其他副作用。Hartevo 按 HTTP method、目标域名、请求语义和账号身份分类；任何潜在写入必须先建立 Pending Effect，并走 Approval、Idempotency、Receipt 与 Verification。

### 5.4 控制权交接不能只靠 Prompt 约束

Ego Lite 文档明确指出 `takeOverTaskSpace` 没有 ownership check，要求 Agent 只在用户确认后调用。Hartevo 不接受仅靠 Skill 文案保护控制权：Browser Host 必须验证用户确认事件、lease generation 和当前 owner，旧调用即使排队中也要失效。

### 5.5 站点经验不能自动成为可信能力

站点 CSS selector、DOM 结构和 UI 文案会变化，也可能被网页 Prompt Injection 污染。Candidate Recipe 必须经过静态 validator、离线 fixture、真实低风险 canary、账号/域名边界测试和签名晋升；失败时回退到语义观察或人工，不允许无限重试。

### 5.6 产品宣称不能替代 Hartevo Eval

增强 snapshot 深层 iframe 能力、2.5× 速度和 5× 经验复用等主张依赖闭源浏览器或尚未完整公开的 benchmark。Hartevo 只在自己的 Browser/GT workload 上比较成功率、动作数、Token、时间、人工接管率、误写率和验证完整度。

## 6. Browser Workspace 核心合同

建议首版类型至少包含：

```text
BrowserProfile
BrowserIdentity
BrowserWorkspace
BrowserControlLease
BrowserTab
SemanticSnapshot
ElementRef
StableLocatorCandidate
BrowserActionBatch
BrowserActionResult
BrowserRecipePackage
BrowserReceipt
BrowserVerification
```

关键绑定：

```text
browser_profile_id
  → tenant_id + project_id + account_identity + credential_ref

browser_workspace_id
  → project_id + mission_id + browser_profile_id + lease_generation

browser_action_batch_id
  → workspace_id + task_id + effect_id? + snapshot_id + policy_digest
```

`BrowserWorkspace` 不直接保存明文 Cookie；`SemanticSnapshot` 不保存敏感输入值；`BrowserActionResult` 不能直接把 Provider Success 投影为业务完成。

## 7. UI 与总调度关系

Browser Workspace 不新增一级导航，也不产生割裂对话：

- 总调度和单 Mission 的 Live Work 显示“正在操作的账号 / 页面 / 控制方 / 最近验证”。
- Agent 开始浏览器任务时自动创建或恢复匹配的 Workspace；用户无需学习 Task Space 概念。
- 需要登录、MFA、CAPTCHA 或人工判断时，原 Mission 中出现单一接管卡片；点击后用户获得控制，Composer 与所有工作面立即同步暂停状态。
- 用户点击“交还 Hartevo 继续”后签发新 lease，Agent 从原 Mission、原 Workspace 和明确 tab 恢复，不创建新会话。
- 用户主动打开 Agent 页面时，产品先说明是查看还是接管；仅查看不得隐式改变 owner。
- 完成时默认关闭临时 Workspace；只有用户需要继续使用页面或人工完成剩余步骤时才保留，并清理无关标签。

该能力进入产品原型前，必须在同一个变更中更新交互规格与原型，不能只在代码里增加隐藏控制状态。

## 8. 安全与质量 Gate

进入受控 Pilot 前至少验证：

1. 用户接管提交后，旧 lease 的下一条点击、键盘、fetch 和上传全部被拒绝。
2. 同一 Mission 恢复原 Workspace；不同 Project 不复用 Profile、Cookie、snapshot、下载目录或 Recipe private state。
3. 登录、MFA 和 CAPTCHA 从不被绕过；人工输入的密码、验证码和敏感字段不进入模型上下文。
4. Snapshot ref 过期、DOM 重绘、tab 切换、iframe 导航和账号切换均触发重新观察。
5. 任意潜在外部写入不能由 raw CDP、页面 JS、browser fetch 或站点 Recipe 绕过 Effect Broker。
6. 下载进入 Project 隔离区并扫描；上传只能访问当前 Mission 明确授权的文件。
7. Browser Host、Desktop 或 Runtime 崩溃后恢复 owner、lease、tab 和 uncertain Effect，不盲目重放。
8. Candidate Recipe 无法读取 Secret、私有 Rubric、其他 Project 或未声明域名。
9. Semantic、Visual 和 Protocol 三条路径均有成功、失败、降级和 Verification Trace。
10. Windows、macOS 与 Linux 分别通过 Browser contract test；不把 macOS-only 上游行为视为跨平台完成。

## 9. 实施顺序

### B0：合同与模拟器

- 定义 Workspace、Profile、Lease、Action、Snapshot、Recipe 和 typed error schema。
- 建立 Fake Browser Host，覆盖接管、过期 ref、账号不符、Prompt Injection 和崩溃恢复。
- 将 Browser Effect 与现有 Effect Broker、Receipt 和 Verification 对齐。

### B1：Rust Browser Host

- 通过 Rust CDP client 驱动受管理 Chromium/兼容浏览器；具体 crate 另行 ADR 固定。
- 实现 managed profile、tab/workspace、语义 snapshot、locator、键鼠和截图。
- 首版不开放未认证 remote-debugging port；本地通道必须绑定 child/process identity。

### B2：增长平台闭环

- 为一个真实低风险社媒/渠道流程实现首个签名 Recipe。
- 完成人工登录、接管、交还、草稿、审批、唯一执行、Receipt 和在线验证。
- 把 Workspace 状态投影回总调度和单 Mission Live Work。

### B3：经验候选与规模化

- 将成功 Trace 转为 Candidate Recipe，接入 Penguin-inspired Harness Candidate Lab。
- 建立多站点 UI 版本、回归 fixture、canary、失效检测和回滚。
- 只有在 Browser/GT Gate 达标后才扩大到邮件、CRM、达人和联盟后台。

## 10. 许可证与来源

公开 `citrolabs/ego-lite` 仓库采用 MIT License。Hartevo 默认进行行为级独立 Rust 实现。若选择性移植公开 helper 中的具体算法，必须固定来源 commit 与文件路径，在 `THIRD_PARTY_NOTICES` 保留 MIT 版权和许可，并记录 Rust 落地与测试。

禁止：

- 把下载版 Ego Lite Browser 当作 MIT 源码或 Hartevo 可再分发组件。
- 反编译、提取或复刻闭源 `globalThis.ego` runtime 与品牌资产。
- 机械翻译整个 TypeScript helper，或把 Node runtime 打包进 Hartevo。
- 使用 Ego Lite 名称、Logo、安装包或产品比较文案作为 Hartevo 资产。

## 11. 主要依据

- [Ego Lite repository](https://github.com/citrolabs/ego-lite)
- [代码审查 commit](https://github.com/citrolabs/ego-lite/tree/c46a439e7fbad90ad33dbea6c6af329b6009809f)
- [README 与产品边界](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/README.md)
- [Repository architecture](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/AGENTS.md)
- [Agent Skill 与 Task Space 交接合同](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/skills/ego-browser/SKILL.md)
- [Node helper runtime](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/package/ego-browser/README.md)
- [Browser runtime bridge](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/package/ego-browser/src/browser-runtime.ts)
- [Semantic snapshot helper](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/package/ego-browser/src/driver/observe.ts)
- [Site learning validator](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/package/ego-browser/src/learning/validate-learning-format.ts)
- [CI workflow](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/.github/workflows/ci.yml)
- [MIT License](https://github.com/citrolabs/ego-lite/blob/c46a439e7fbad90ad33dbea6c6af329b6009809f/LICENSE)
