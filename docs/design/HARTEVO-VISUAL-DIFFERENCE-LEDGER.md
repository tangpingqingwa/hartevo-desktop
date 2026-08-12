# Hartevo Desktop 视觉回归与剩余差异账本

状态：高保真交互基线 checkpoint。此账本只证明本切片的原型覆盖、原生渲染与静态/交互测试，不提升 Mission 的 E0～E5，也不证明任何 Provider、Receipt、Verification 或外部 Effect 成功。

## 冻结来源

- 产品与视觉 Source of Truth：`/Users/yann/geo-desktop/prototype/README.md`、`/Users/yann/geo-desktop/prototype/index.html`、`/Users/yann/geo-desktop/prototype/hartevo-logo-mark.png`。
- `prototype/` 中没有独立 CSS、JavaScript、字体或图标文件：页面 CSS 与 JavaScript 内嵌在 `index.html`，唯一图片资产是品牌 PNG；字体栈由内嵌 CSS 声明，未附带字体二进制。
- 产品状态和 Application/Domain 边界补充合同：`docs/product/HARTEVO-DESKTOP-INTERACTION-SPEC.md`。
- 实现不是 iframe、截图背景或第二套 demo store。页面读取 `DesktopUiModel` 的 Application projections；只有 `visual-fixtures` feature 可加载显式、带 `VISUAL_FIXTURE` 标记的视觉场景。

## 比较方法

1. 完整读取冻结原型后抽取 Token、Typography、布局、层级、状态和键盘合同。
2. 构建真实 Dioxus Desktop 二进制，用同一显式 fixture 逐 surface 启动原生窗口。
3. 原型与实现都裁到 `1205×741` 内容视口；原生 macOS 标题栏不进入像素比较。
4. 将原型和实现并排合成；对布局、间距、字体、颜色、状态、空态和交互逐项检查。
5. 修正 Settings 覆盖层、Esc 返回来源页面、⌘/Ctrl+P 搜索、⌘/Ctrl+K 总调度、原生标题栏裁切、窄屏和 200% zoom 后重新捕获。

原生截图来自实际编译的 Dioxus 二进制。为规避本机 LaunchServices 中旧 bundle ID 冲突，验证时把同一二进制复制进一次性、唯一 bundle ID 的临时 ad-hoc 签名 wrapper，再按 PID/AX 定位窗口；该 wrapper 不进入产品源码或发布产物。直接 `screencapture` 当前仍受本机 Screen Recording 环境阻塞，脚本会诚实记录 `BLOCKED_ENV_SCREEN_CAPTURE` 并保留最后一次成功基线，而不会覆盖为黑图。

## Surface 对照结果

| Surface | 原型依据 | 实现证据 | 当前结论 | 剩余差异 |
|---|---|---|---|---|
| Project Dispatcher / Orchestrator | `orchestrator` + project home | `orchestrator-macos-content.png` | 布局网格、侧栏、标题、统计、队列、Composer 和品牌语言已对齐 | 原型相对时间被 revision/cycle 取代；原生 WebKit 与原型截图的文字抗锯齿略有不同 |
| Channels | prototype Channels page | `channels-macos-content.png` | 顶栏、tab、统计带、内容区和空态结构已对齐 | 原型演示发布数据未复制；Application 未投影的 Provider 状态显示 `NOT_IMPLEMENTED` |
| CRM / Relationships | prototype Relationships page | `relationships-macos-content.png` | 双栏关系视图、标题、统计和 Pipeline 布局已对齐 | 演示联系人和 Consent 不复制；真实 Relationship projection 未接线时保持明确空态 |
| Partners / 达人任务 | prototype Partners page + 用户补充的 VM-06 Creator Work 合同 | `partners-macos-content.png` | 页面骨架与交互 tab 已实现；达人任务 12 阶段在“任务与交付”tab 可见 | Contract、Deliverable、Review、Settlement 写入仍为 `NOT_IMPLEMENTED`；不会伪造付款 |
| Connections | prototype Connections page | `connections-macos-content.png` | 连接卡、账号边界、Probe/授权说明和空态结构已对齐 | 没有实时 Probe 时只显示 `BLOCKED_ENV`/`NOT_IMPLEMENTED`，因此密度低于原型演示数据 |
| Outcomes | prototype `outcome` conversation/workpad state | `outcomes-macos-content.png` | 保留同一层级、密度和视觉语言，并落成独立 Outcome projection 页面 | 原型没有独立 Outcomes 业务页；这是用户要求 IA 的投影适配，不声称逐像素同构 |
| Capability Evidence | prototype `capabilities` conversation/workpad state | `capability-evidence-macos-content.png` | 证据表、E0～E5 状态和诚实标签已实现 | 原型以对话/Workpad 展示；实现按当前产品架构使用独立证据表 |
| Settings | prototype full-screen settings shell | `settings-macos-content.png` | 全屏覆盖、分区侧栏、返回、搜索、行控件、开关和层级已对齐 | 未接 Settings Application Service 的控件禁用并标 `NOT_IMPLEMENTED`；不复制原型假路径和假账户数据 |
| Current | prototype project home 与 Current 导航意图 | `current-macos-content.png` | 采用相同 Token 和 project readiness 语言 | 原型没有独立 Current 页面像素目标；按真实 Project projection 实现 |
| Missions | prototype mission rail 与会话状态 | `missions-macos-content.png` | Mission 列表、状态点、打开同一会话已实现 | 原型没有独立 Missions 页面像素目标；演示任务不进入正式 store |
| State Coverage | 产品状态合同 | `state-coverage-macos-content.png` | 10/10 状态、德语/日语和超长文本回归载体完成 | 仅 `visual-fixtures` 可进入；它不是产品业务状态来源 |

完整并排总览见 `artifacts/visual/prototype-baseline/comparison-contact-sheet.png`；真实页面总览见 `surface-contact-sheet.png`。

## 响应式与缩放

| Case | 请求内容视口 | 实际验证 | 结论 |
|---|---:|---:|---|
| compact | 1024×768 | 1024×768 | PASS；无水平溢出，侧栏降为图标密度，Composer 可操作 |
| baseline | 1366×900 | 1366×839 | `BLOCKED_ENV_SCREEN_BOUNDS`；本机可见工作区限制高度，实际尺寸下布局通过 |
| wide | 1600×1000 | 1512×839 | `BLOCKED_ENV_SCREEN_BOUNDS`；当前物理屏幕宽高不足，不把较小截图冒充 1600×1000 |
| zoom-200 | 1024×768 @ 200% | 1024×768 @ 200% | PASS；关键标题、统计、队列与 Composer 保持可访问 |

真实窗口证据和精确 bounds 位于 `artifacts/visual/prototype-baseline/responsive/`。1600×1000 必须在对应 runner/显示器上复跑后才能关闭差异。

## 无障碍与键盘

- 11 个原生 surface AX 树均识别到 `Hartevo Desktop` 窗口，交互控件无空 accessible name。
- 十种状态码在原生 AX 树中 10/10 可见。
- CSS gate 覆盖 `:focus-visible`、`prefers-reduced-motion` 和 `overflow-wrap: anywhere`。
- 快捷键合同：⌘/Ctrl+P 全局搜索、⌘/Ctrl+K 项目总调度、⌘/Ctrl+N 新任务、⌘/Ctrl+, 设置、Esc 关闭/返回。
- VoiceOver 和 Windows Narrator 的脚本化端到端旅程仍为 `BLOCKED_ENV`；AX 树通过不等于辅助技术实机完成。

## 不在本 checkpoint 中冒充完成的事项

- 真实 Provider 授权、Probe、回调、Receipt、Verification、付款、外部发布和 E4 Canary。
- Settings、CRM、Partner contract/deliverable/settlement 等尚未接线的 Application handlers。
- Windows 原生窗口、Narrator、1600×1000 物理视口与发行签名安装验证。
- 全产品 420 个 Mission Cases、180 个横切 Cases、E3/E4/E5 和 90 天 cohort。

## 冻结摘要哈希

| Artifact | SHA-256 |
|---|---|
| `prototype/README.md` | `59025493c5fb92090ec6f7d4876b19a20710a8e249a5ec5f13bf932808badd38` |
| `prototype/index.html` | `7d00e33e195164f492143841b75cadf3d7995c4efb16fc65c57ef05da3fba17d` |
| `prototype/hartevo-logo-mark.png` | `71c905b1e8150fe1976b306af119997ba46f0456fca966ae7f5c89dc5aef9b9c` |
| `assets/prototype.css` | `5b6f0a9e39931cf62388dc0c68d0045d03a6b35b64087cce006b83d6f110f77a` |
| `fixtures/prototype-baseline.v1.json` | `ccc21017c61ed13269ad37084705e57ed5370ba9153f332bbd614c33dcffb4d0` |
| `comparison-contact-sheet.png` | `f63810b28964ca25c9081eca0de8d9310cc9523e0ec5f3c6f4b759aa1502731a` |
| `surface-contact-sheet.png` | `5c9b5b9e6a9d682072163d4551878f852ffb62f24cee62ea74dcaf208574ae75` |
| `responsive-contact-sheet.png` | `879d4beee187db9b248ae4b70cc7fce6f6225b55e51f19427f9308c313cb7689` |
