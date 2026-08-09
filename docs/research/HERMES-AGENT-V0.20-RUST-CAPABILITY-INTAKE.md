# Hermes Agent v0.20 → Hartevo Rust 能力引入清单

状态：**Accepted**
版本：1.0
日期：2026-08-09
发布审查基线：`NousResearch/hermes-agent@v2026.8.3`（Hermes Agent v0.20.0，commit `3c27eb6234bf91b8ceee9e9071591b31e9b148cb`）

## 1. 决策纠正

Hermes 曾在清理旧候选架构时从 Hartevo Desktop 当前文档中完全消失。这一处理避免了 Hermes 与 OpenInterpreter 同时被误读为技术基座，但也错误地丢失了 Hermes 对长期 Agent、桌面交互、上下文治理、多 Agent 协作和工具可靠性的参考价值。

现正式采用以下分层：

- **主代码与运行时基座：** Rust OpenInterpreter App Server。
- **产品与能力参考源：** Hermes Agent v0.20 及后续经过单独审查的版本。
- **Hartevo 领域事实源：** Hartevo Domain Kernel。
- **最终实现：** Hartevo-owned Rust + Dioxus；不把 Hermes Python Core、Electron Desktop 或 Node runtime 带入出货产品。

Hermes 不是第二个基座，不作为 Hartevo 的常驻 sidecar，也不整体 fork 到本仓库。我们吸收的是经过验证的能力机制，并根据增长经营领域重新建模。

## 2. 为什么 v0.20 值得重新引入

Hermes Agent v0.20.0 的重点已经超出普通 Chat/TUI：

- 流式语音、barge-in、本地唤醒词与跨平台语音路由。
- 可验证引用、原文匹配与 fact-checking。
- Artifacts、沙箱预览、桌面插件 SDK、浮动工作面、多窗口和全局 Quick Entry。
- A2A v1.0 双向互操作与签名 Push notification。
- 签名 outbound webhooks，把 Session、Turn 与 Tool lifecycle 主动推给外部系统。
- 运行中 redirect，保留已完成工作并对当前方向纠偏。
- 工具错误自诊断、自恢复和文件写入后验证。
- 渐进式工具结果裁剪、按 Turn 微压缩、最近用户消息保留和 ghost-skill 防护。
- 从审批历史生成 allowlist 建议、连续拒绝熔断与更完整的审批面。
- 更持久的 Kanban Dispatcher：原子认领、heartbeat、崩溃回收、失败自动阻塞和可恢复任务。
- 按需 Skills、跨会话 Memory、Cron、Heartbeat、Plugins、MCP 和多平台 Gateway。

这些机制与 Hartevo 的“持续总调度、少让用户操作、长任务可恢复、跨渠道执行且可验证”高度一致。

## 3. Rust 能力引入矩阵

优先级含义：`R0` 为首个垂直切片必须验证；`R1` 为 Pilot 前；`R2` 为后续平台化。

| Hermes 机制 | Hartevo Rust 归属 | 引入方式 | 优先级 | Hartevo 特有约束 |
| --- | --- | --- | --- | --- |
| Mid-turn redirect | `runtime-adapter` + `application` | 将纠偏作为 Mission command，关联当前 Run 并保留已完成 item | R0 | 不创建割裂会话；总调度、工作面与 Composer 同时看到新方向 |
| Durable Goal / Kanban Dispatcher | `domain` + `application` + `storage` | 重构为 Mission/Task lease、heartbeat、reclaim、block、resume 状态机 | R0 | Task Board 只是 Mission 投影，不能成为第二事实源 |
| Tool self-recovery | `capability-gateway` | 为截断、空结果、重复写入、路径错误和可恢复失败返回 typed recovery hint | R0 | 自动恢复不得扩大 Scope，也不得重试不确定外部 Effect |
| Context micro-compaction | `runtime-adapter` + `application/context` | Rust Context Assembler：工具结果裁剪、最近用户消息尾部保证、可检索归档 | R0 | Project/Mission Goal、Constraint、Approval 和未完成 Effect 永不被摘要覆盖 |
| Grounded citations / fact-checking | `domain/evidence` + `capability-gateway` | 原文匹配、Claim–Evidence ledger、时效、来源与 verified/unverified 状态 | R0 | 引用必须进入 Truth/Evidence，而不是只渲染 Markdown 链接 |
| Artifacts + live preview | `domain/work-product` + `ui` | 版本化 Work Product、来源 lineage、沙箱预览、Diff、采用与发布状态 | R0 | 产物不是 Session 附件；必须可审计、可回退并与 Outcome 相连 |
| Smart approval suggestions | `effect-broker` | 从历史生成规则建议，由用户显式采纳；连续拒绝触发 circuit breaker | R0 | 历史不能自动放宽外部动作权限；预算、发布、触达和付款仍逐层治理 |
| Quick Entry | `desktop` + `ui/command-composer` | 系统全局快捷键唤起轻量 Composer，自动解析当前 User/Project/Mission | R0 | 不默认发送；必须显示将写入哪个项目，并允许切换或暂存 Inbox |
| Signed outbound webhooks | `application/events` + `connector-sdk` | HMAC 签名、事件筛选、幂等 ID、重放防护和投递回执 | R1 | 只发布允许外部观察的领域事件；不得泄漏 Prompt、Secret 或 PII |
| Cron + session heartbeat | `application/automation` | 区分 durable Schedule 与轻量 Mission heartbeat，支持暂停、补偿和 missed-tick coalescing | R1 | 自动任务仍受 Project、预算、Consent 和 Effect Policy 上限约束 |
| Desktop plugin SDK | `ui-extension-sdk` + `capability-registry` | 设计 Rust/WASM 或受限进程扩展协议；注册 Pane、Command、Renderer 和 Capability | R1 | 插件必须签名、声明权限、项目 Scope 和网络/Secret 使用；不运行任意 ESM |
| Memory + learned Skills | `domain/memory` + `capability-registry` | User、Organization、Project、Mission 分层记忆；经验先形成候选 Lesson/Skill 再晋升 | R1 | Agent 不得直接改写 Truth、Consent 或组织策略；纠错与来源必须保留 |
| A2A v1.0 | `agent-federation-adapter` | Rust A2A client/server、Agent Card、身份、rate limit、audit 和 anti-loop | R1 | 外部 Agent 只能作为 Capability Provider，不能成为 Project/Mission 事实源 |
| Multi-window / floating panes | `desktop` + `ui` | Work Product、Approval、Live Work 可拆窗；状态仍来自同一 Application Store | R1 | 不复制会话状态，不让多个窗口形成多个总调度 |
| Streaming voice + barge-in + wake word | `voice-adapter` + `ui/command-composer` | 本地唤醒、流式 STT/TTS、语音纠偏与明确录音状态 | R2 | 唤醒监听尽量本地；外发音频前展示 Provider 与隐私边界 |
| Multi-platform Gateway | `connector-sdk` + `channel-adapters` | 将 Email、Slack、Teams、Feishu 等作为 Hartevo Inbox/Effect adapters | R2 | 消息平台不是业务真相；联系人、Consent、触达频率仍由 CRM/Effect Broker 管理 |

## 4. 不照搬的部分

以下能力即使在 Hermes 中成熟，也不能原样成为 Hartevo 结构：

1. **Chat-first 信息架构。** Hartevo 以 User → Project → Mission → Effect/Outcome 为核心，持续总调度不是一组独立聊天。
2. **Profile/Board 等同于 Project。** Hermes Profile、Kanban Board 和 Tenant 的隔离思路可参考，但 Hartevo Project 有 Truth、CRM、Consent、连接、预算与成果等更强领域边界。
3. **Python Agent Core 与 Electron Desktop。** 不进入 Hartevo 出货栈；对应能力必须落到 Rust crate 和 Dioxus 组件。
4. **ESM Desktop Plugin。** Hartevo 不加载拥有主进程能力的任意 JavaScript；扩展必须有 capability manifest 和进程/沙箱边界。
5. **YOLO 或单层本地审批。** 文件/命令授权永远不能批准邮件、社媒发布、广告花费、CRM 写入、联盟付款或达人触达。
6. **Agent 自主改写 Memory/Skill 即视为事实。** 学到的内容先是 Candidate Lesson，经过来源、范围和冲突检查后才能晋升。
7. **无限延长自治循环。** 更高迭代上限不是完成保证；Hartevo 依靠 Mission budget、progress signal、stall detection 和 failure policy 控制。
8. **Gateway 直接持有全部业务凭据。** 外部写入凭据由 Effect Broker 和 OS keyring 管理，Runtime 只得到最小能力句柄。
9. **Nous Portal 产品绑定。** Provider 与 Tool Gateway 可作为可选适配，不进入 Hartevo 核心对象和默认商业依赖。

## 5. Rust 重构与许可证边界

Hermes Agent 使用 MIT License，因此允许商业使用、修改和移植，但需要保留相应版权与许可证通知。

Hartevo 采用两种可审计路径：

- **行为级独立实现（默认）：** 根据公开文档、发布说明和 Hartevo 场景重新设计 Rust 类型、状态机、协议与 UI；在设计记录中注明启发来源，不复制 Python/TypeScript 实现。
- **源码级选择性移植（例外）：** 只有当具体算法具有显著价值且独立重写无意义时才允许。必须记录 Hermes 文件路径、固定 commit、移植范围，在 `THIRD_PARTY_NOTICES` 保留 MIT 通知，并通过单独代码审查。

禁止整体导入 Hermes 仓库、同时维护 Python Runtime，或逐文件机械翻译后声称为 Hartevo 原创。品牌资产、界面文案和 Hermes 专有产品结构不作为移植对象。

## 6. 与 OpenInterpreter 的关系

每个候选能力先做三步判断：

1. OpenInterpreter 是否已经提供等价协议或运行时机制。
2. 若已提供，优先在 `runtime-adapter` 上包装，不复制 Hermes 实现。
3. 若未提供且属于 Hartevo 领域能力，在 Hartevo-owned crate 中实现；只有通用 Agent Runtime 能力才考虑向 OpenInterpreter 上游贡献。

因此不会出现两个 Agent Loop、两个 Thread Store、两个 Tool Registry 或两个桌面状态源。Hermes 是经过版本固定的能力研究对象，不是运行依赖。

## 7. 实施顺序

### R0：先进入首个垂直切片

1. Mid-turn redirect 与共享 Mission State。
2. Mission lease/heartbeat/reclaim/block/resume。
3. Context Assembler 与安全压缩。
4. Capability Recovery Contract。
5. Claim–Evidence ledger 与 grounded verification。
6. Work Product lineage 与沙箱预览。
7. Approval suggestion + denial circuit breaker。
8. 全局 Quick Entry。

### R1：Pilot 前的平台能力

1. Signed outbound webhook。
2. Schedule / heartbeat automation。
3. 受限扩展 SDK。
4. Candidate Memory / Learned Skill 晋升流程。
5. A2A federation。
6. 多窗口共享状态。

### R2：规模化入口

1. 语音、barge-in 与本地 wake word。
2. 多消息平台的 Inbox 与 Effect adapter。

## 8. 验收原则

每项 Hermes-inspired 能力进入实现前都必须有 Hartevo 场景和失败测试：

- 能明确减少用户导航、重复解释、等待或人工恢复。
- 不创建第二领域事实源或第二总调度。
- 中断、重启、离线和模型切换后可恢复。
- 不越过 Project Scope、Consent、Approval 和 Effect Policy。
- 用户看到的是业务状态，不是 Hermes/OpenInterpreter 内部术语。
- 有固定来源版本、许可证判断、Rust owner、Eval 场景和落地阶段。

## 9. 主要依据

- [Hermes Agent v0.20.0 release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.3)
- [Hermes Agent repository](https://github.com/NousResearch/hermes-agent)
- [Hermes Desktop](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/desktop.md)
- [Interrupt and redirect](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/cli.md#redirecting-the-agent-mid-turn)
- [Kanban collaboration](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/kanban.md)
- [Context compression and caching](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/developer-guide/context-compression-and-caching.md)
- [Persistent memory](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/memory.md)
- [Skills](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/skills.md)
- [Hooks and outbound webhooks](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/hooks.md#outbound-webhooks)
- [A2A](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/messaging/a2a.md)
- [Voice mode](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/voice-mode.md)
- [Desktop plugin SDK](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/developer-guide/desktop-plugin-sdk.md)
- [MIT License](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/LICENSE)
