# Hartevo Desktop 视觉回归与剩余差异账本

状态：细颗粒交互基线 checkpoint。此账本证明本切片的真实 Dioxus 渲染、原型覆盖、原生交互与确定性测试；不提升 Mission E0～E5，也不证明 Provider、Receipt、Verification、付款或外部 Effect 成功。`design-qa.md` 继续保持 `result: blocked`。

## 冻结来源与优先级

1. 最高优先级：`/Users/yann/geo-desktop/prototype/README.md`、`index.html`、内嵌 CSS/JavaScript 和 `hartevo-logo-mark.png`。
2. 用户提供的五张 ChatGPT/Codex Desktop 截图只补充原型未定义的流式正文、内联活动、Stop、附件、多栏和 Inspector 交互，不覆盖 Hartevo 的导航、Token、品牌或业务语义。
3. 正式构建只读取 Application/Domain projection；显式 `visual-fixtures` feature 才能加载 `prototype-baseline-v1`，每页持续显示 `VISUAL_FIXTURE`。
4. fixture 中的外部动作、连接、结果、收入和付款均转写为 `未执行`、`未验证`、`未测量`、`BLOCKED_ENV` 或 `NOT_IMPLEMENTED`；没有 fixture 会创建 `ApprovalGrant`、`EffectIntent`、`ProviderReceipt` 或 `OutcomeEvent`。

## 比较与交互方法

1. 从冻结原型逐状态捕获 1366×840 内容视口；原生 macOS 31px 标题栏不进入 joined comparison。
2. 构建真实 Dioxus Desktop bundle，分别启动 17 个 surface；本轮 17/17 捕获成功、0 blocked。
3. 对 13 个有源状态的 surface 生成 source/implementation joined comparison；`mission-inspector`、Current、Missions、State Coverage 没有伪造源图，作为 supplementary evidence 单独呈现。
4. 对 joined image 逐项检查栅格、字体、间距、hairline、圆角、Workpad tab、Composer、审批、结果和运营表；本轮由比较发现并修复 Workpad tab 被基础 button width 挤压、Settings rail/panel/group 偏离源值两处真实缺陷，再重新捕获。
5. 使用原生 macOS AX/Computer Use 操作真实窗口验证焦点、菜单、抽屉、Composer、Workpad splitter、审批修改和流式 Stop；截图本身不作为交互通过依据。

## Surface 对照结果

| Surface | 实现证据 | 当前结论 | 仍未关闭的差异 |
|---|---|---|---|
| Orchestrator | `comparisons/orchestrator-side-by-side.png` | hero、四格摘要、优先/等待队列、调度 narrative、quick-entry 与源层级对齐 | Dispatcher 内联过滤和真实 summary projection 未持久化 |
| Mission Conversation | `comparisons/mission-conversation-side-by-side.png` | bubble、assistant byline、Mission Contract、活动流、能力组、连接建议、WorkProduct、结论和建议条已还原 | 正式 Runtime 仍没有 token delta；真实 correlated activity ledger 不完整 |
| Mission Streaming | `comparisons/mission-streaming-side-by-side.png` | running 时发送动作替换为单一 square Stop；content-free Runtime phase strip 与事件序列可见 | fixture replay 不是 Runtime 证据；pause/resume、reconnect cursor 与 token stream 未实现 |
| Mission Workpad | `comparisons/mission-workpad-side-by-side.png` | 四 tab、工具簇、报告、四阶段 strip、真实源 SVG、候选与 provenance 已还原 | comment/export、adoption command 与通用 PDF/image viewer 未接线 |
| Mission Inspector | `surfaces/mission-inspector-macos-content.png` | Checkpoint、WorkProduct、Effect、Worker、Browser、Sources 分区与折叠语义完成 | live Worker/Browser/Effect/Revision projections 未完成；没有伪造 active worker |
| Mission Approval | `comparisons/mission-approval-side-by-side.png` | 四 effect 结构、facts、minor-unit 修改、新 SAMPLE revision、延期与结果预览完成 | 真实逐 Effect Approval Service/Adapter 未接线；fixture 始终 0 Effect |
| Mission Outcome | `comparisons/mission-outcome-side-by-side.png` | 结果 metrics、Receipt/readback/Attribution 行与 Next Loop 同构呈现 | 全部保持未执行/未验证/未测量；真实 OutcomeEvent/reconcile 未接线 |
| Channels | `comparisons/channels-side-by-side.png` | shared topbar、hero、tabs、readiness、ranked rows、right rail 与源密度接近 | scheduler、publishing、inbox、outcome 真实 projection 未接线 |
| Relationships / CRM | `comparisons/relationships-side-by-side.png` | Pipeline、Consent table 和 CRM IA 已恢复 | Person/Company/Conversation/Handoff 真实 projection 未接线 |
| Partners / Creator Work | `comparisons/partners-side-by-side.png` | 六 tab 与供给表恢复；任务悬赏→申请/邀请→交付→review→权利→付款边界已落成 | Contract、File Broker、Review CAS、Stripe Connect payout 均未接线 |
| Connections | `comparisons/connections-side-by-side.png` | need-next、统计、right rail、四步 wizard 与 policy 子视图完成 | 无实时 Probe 时保持 0 Connected/`BLOCKED_ENV`；OAuth/callback/revoke 未接线 |
| Outcomes | `comparisons/outcomes-side-by-side.png` | Ledger/Attribution/Next decision 页面结构完成且保留 0 Revenue | event ingest、FX/refund/commission/attribution reconcile 未接线 |
| Capability Evidence | `comparisons/capability-evidence-side-by-side.png` | E0～E5 ledger 和 `release_passed=false` 清晰可见 | 原型采用对话/Workpad；独立页是产品 IA 投影，不声明像素同构 |
| Settings | `comparisons/settings-side-by-side.png` | 52px topbar、242px rail、900px panel、58px outlined groups 与源值恢复 | 10 分区中只有部分为专有控件；Settings persistence 未接线 |
| Current / Missions / State Coverage | `surface-contact-sheet.png` | 共享同一 Domain 投影和 Token；10/10 状态、德日长文本有回归载体 | 原型没有独立像素状态；i18n catalog 与真实部分状态 gateway 未完成 |

## 原生交互证据

- Search：点击后焦点落到 `global-search-input`；Esc 关闭并回到搜索 trigger。
- Notifications：打开后焦点落到关闭按钮；Esc 回到 notification trigger。
- Current object menu：Esc 关闭 native menu 并回到同一 ellipsis trigger；未接线命令保持禁用。
- Composer：focus 展开；Esc 真正 blur 到 Dioxus document；Enter/Shift+Enter/IME composing 由 pure contract test 覆盖。
- Workpad：键盘 ArrowRight 将 splitter 从 500px 调为 524px；AX `Value` 和 `Details` 同步更新。
- Approval：修改 budget minor units 后生成 `SAMPLE r2`，不创建 ApprovalGrant/EffectIntent；预览后仍显示 0 Receipt/Verification/OutcomeEvent。
- Streaming Stop：最终页面只有一个主 Stop；点击后出现 `VISUAL_FIXTURE · Stop 控件状态已触发` 和 `#5`，按钮禁用，并明确未发送真实 interrupt。真实协调器路径由 version-fenced integration test 单独证明。

## 响应式与缩放

| Case | 请求 | 实际内容 | 结论 |
|---|---:|---:|---|
| compact | 1024×768 | 1024×769 | PASS；无水平溢出，Composer 主动作可达 |
| baseline | 1366×900 | 1366×842 | `BLOCKED_ENV_SCREEN_BOUNDS`；本机可见工作区限制高度 |
| wide | 1600×1000 | 1512×842 | `BLOCKED_ENV_SCREEN_BOUNDS`；不把较小截图冒充目标视口 |
| zoom-200 | 1024×768 @200% | 1024×769 @200% | PASS；标题、统计、Composer 和主动作仍可达 |

精确窗口记录见 `artifacts/visual/prototype-baseline/responsive/capture-results.tsv`。

## 无障碍与测试

- 17 个原生 surface AX snapshot 全部通过：窗口可识别、交互控件无空 accessible name、十种状态码 10/10 可见。
- Search/Notifications/menu/Composer/splitter 的焦点与键盘行为使用真实原生窗口验证。
- CSS gate 覆盖 `:focus-visible`、`prefers-reduced-motion` 与 `overflow-wrap:anywhere`。
- `cargo test -p hartevo-desktop --features visual-fixtures`：35/35；默认 feature：34/34。
- Clippy：`--all-targets --features visual-fixtures -- -D warnings` 通过。
- VoiceOver、Windows Narrator、Windows native window 与 1600×1000 真实物理视口仍为 `BLOCKED_ENV`；AX 通过不等于 AT 实机完成。

## 仍阻断 Design QA 的高杠杆差异

1. `P0`：真实 token delta/稳定段落持久化、pause/resume、reconnect cursor/replay 尚未实现。
2. `P0`：File Broker/附件扫描、语音、live Worker/Browser handoff/Inspector 尚未接线。
3. `P0`：CRM、Creator contract/deliverable/review/payout、Provider/OAuth/Probe、Outcome 等真实 Application/Provider 闭环未完成。
4. `P0`：默认未接线路径仍有部分 compact `state-canvas`；完整中英 UI locale catalog 尚未实现。
5. `P1/BLOCKED_ENV`：VoiceOver/Narrator、Windows、1600×1000、真实 configured Runtime 长任务 native canary 缺证。
6. 真实 Provider、E3/E4/E5、420 Mission cases、180 cross-cutting cases 和长周期 cohort 均不属于本视觉 checkpoint 的完成证据。

## 冻结摘要哈希

| 冻结对象 | SHA-256 |
|---|---|
| prototype `README.md` | `59025493c5fb92090ec6f7d4876b19a20710a8e249a5ec5f13bf932808badd38` |
| prototype `index.html` | `7d00e33e195164f492143841b75cadf3d7995c4efb16fc65c57ef05da3fba17d` |
| prototype brand mark | `71c905b1e8150fe1976b306af119997ba46f0456fca966ae7f5c89dc5aef9b9c` |
| visual fixture | `2e427b0549e39f3d511a4d5a41fb7778b11040618b9d779f6b91633dad1f1249` |
| joined comparison contact sheet | `df52c0db032b64d9e1feda69c3af729464776feafaed3691b3b494e8709b24e6` |
| native surface contact sheet | `954e027c9346847801030521afc8bf3dc5870ed0a48e98f95084f77313151bd4` |
| responsive capture report | `42876761d9a619124bd4a558866e5aeb1d51dfd35c7072d77cf03f23f754f364` |
| accessibility audit | `c39cd20ea56505813908b425fbc9c003e2d93af98c5ef84c4cf944e871aaea00` |

这些哈希只冻结本 checkpoint 的视觉输入/输出，不改变上面的完成边界。
