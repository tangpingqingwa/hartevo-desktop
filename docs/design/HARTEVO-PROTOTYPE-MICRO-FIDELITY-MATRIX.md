# Hartevo Desktop 原型微颗粒还原矩阵

状态：实施后验证账本（2026-08-12）。本文件保留逐项验收粒度，并以真实 Dioxus 代码、同视口 joined comparison、原生 AX/键盘操作和确定性测试更新“当前差异”。视觉与交互 Source of Truth 为 `/Users/yann/geo-desktop/prototype/README.md`、`index.html`、内嵌 CSS/JavaScript 以及 `hartevo-logo-mark.png`；ChatGPT.app 只补充原型未定义的流式交互语法，不覆盖 Hartevo 信息架构和视觉 Token。

状态：`CLOSED_BASELINE` 表示本切片已有实现和对应验证；`PARTIAL(Pn)` 表示结构已存在但真实投影、持久化或边缘行为仍缺；`NOT_IMPLEMENTED(Pn)` 与 `BLOCKED_ENV(Pn)` 保持诚实未完成。严重度：`P0` 表示结构、核心旅程或诚实边界缺失；`P1` 表示主要交互或真实数据闭环缺失；`P2` 表示像素、动效、辅助状态或边缘视口差异。`CLOSED_BASELINE` 不提升任何 Mission 的 E0～E5。

## 冻结 Design Tokens

| Token 族 | 原型值 | 实现要求 |
|---|---|---|
| 字体 | `Geist, SF Pro Text, Segoe UI, PingFang SC, Microsoft YaHei, sans-serif` | 保留中英文混排栈、`font-synthesis:none`、抗锯齿与紧凑字阶；不得改成通用 Dashboard 大字号 |
| 主文字 | `#202124` / `#38393d` | 标题、正文、强信息分别使用，不得全页同一灰度 |
| 次文字 | `#65666b` / `#85868b` | 元数据、时间、说明与不可用状态分层 |
| 表面与侧栏 | `#ffffff` / `#f6f6f7` / topbar `#fafafb` | 保留近白层级，不以大面积灰卡替代 |
| 线条 | `#e6e6e8` / `#d7d8dc` | 表格、section、浮层和输入边界使用 1px hairline |
| 品牌金 | `#c8932f` / `#986b1d` / `#faf5e9` | focus、当前运行、审批边界和克制强调 |
| 成功绿 | `#237a50` / `#edf7f1` | 仅用于真实状态投影；视觉 fixture 必须带样例披露 |
| 错误红 | `#b5403a` | 撤销、授权失效、危险动作与零容忍失败 |
| 交互面 | hover `#eeeeef` / selected `#e9e9eb` | hover、pressed、active 必须可区分 |
| 栅格 | topbar `52px`；sidebar `260px`，≤1390 时 `238px`；task chat `550px`，≤1390 时 `500px` | Dispatcher 为 sidebar + flexible；Workpad 打开后为 sidebar + chat + document |
| 圆角 | nav `7px`、button `7–8px`、panel `9–12px`、popover `11px`、composer `12px` | 不得把所有内容统一成 16–24px 大圆角卡片 |
| 阴影 | composer `0 2px 6px rgba(29,29,31,.07)`；popover `0 6px 8px rgba(28,29,33,.10–.12)` | 只用于浮层与可输入容器，不给每个 section 加阴影 |
| 动效 | `cubic-bezier(.16,1,.3,1)`；120/150/180/220/300ms | content-in、popover、drawer、composer expansion、active press；reduced motion 关闭 |
| 层级 | sticky 20 / switcher 30 / drawer 50 / modal 70 / toast 80 | 浮层不得互相穿透；Esc 只关闭最上层 |

## A. 应用壳层、导航与全局浮层

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| A01 | 52px 全局 chrome | `App` 根栅格、`.prototype-app` | 固定顶部、内容独立滚动 | 52px、`#fafafb`、hairline | UI shell + 当前 Application projection | `CLOSED_BASELINE`；17 个 surface 共用稳定栅格，原生标题栏单独裁切 | 1366×900 bounding-box 差 ≤2px；滚动时 chrome 不动 |
| A02 | 左上品牌区 | logo、品牌名、搜索与通知 icon | hover/active/focus、通知 badge | 238px、28px logo、30px icon button | 原始 PNG + UI overlay state | `CLOSED_BASELINE`；使用原始品牌 PNG 与 Lucide，badge/hover/focus 已回归 | source/implementation 1:1 裁片 diff |
| A03 | Mission 顶栏 | `.app-mission-bar` | 标题省略、状态圆点、置顶、更多菜单 | 10px gap、18px side padding | 当前 project/mission projection | `PARTIAL(P2)`；布局和动作簇对齐，1600×1000 物理视口仍受 runner 限制 | 1024/1366/1600 长标题截图 + AX name |
| A04 | Workpad 顶栏 | document bar / tab strip | tab 选择、关闭、折叠、导出、评论 | 34px tab、7px radius | WorkProduct projection；fixture 只供视觉回归 | `PARTIAL(P1)`；多 tab、Inspector、评论/导出/收起结构完成，评论与导出服务保持 `NOT_IMPLEMENTED` | research state 打开后与源同视口并排 |
| A05 | 侧栏新任务 | `new-task` | 点击、Ctrl/⌘+N、focus、press | 42px、8px radius | selected project + Application command | `CLOSED_BASELINE`；点击与快捷键回到同一 Dispatcher 并展开 Composer | 点击与快捷键都进入同一 expanded composer 状态 |
| A06 | 侧栏分组标题 | 工作/任务/自动任务/成果/运营/系统 | 滚动与 sticky project footer | 10.5px/9.5px | Application projections + explicit fixture labels | `CLOSED_BASELINE`；分组、计数、滚动和 footer 节奏已按同视口修正 | sidebar 专项 238×848 diff |
| A07 | 侧栏导航行 | `NavButton` variants | hover、active、count、status dot、ellipsis | 32–42px、7px radius | Project/Mission projections | `CLOSED_BASELINE`；图标、二级说明、计数、状态点和 hover/active 已统一 | hover/focus/active 三态截图 |
| A08 | 任务行更多菜单 | mission object menu | hover 后显现、rename/archive/delete、Esc | 28px icon、menu elevation | Mission identity + UI-only menu state | `PARTIAL(P1)`；菜单、禁用原因、Esc 与焦点回还已实机通过，rename/archive Application command 尚未接线 | 键盘打开菜单；删除只到确认，不实际删 fixture |
| A09 | 项目 footer | workspace button | 展开、旋转 chevron、project truth meta | 28px logo、8px padding | current project projection | `CLOSED_BASELINE`；项目身份、E2EE 状态和路径隐私提示已还原 | source/implementation footer 1:1 diff |
| A10 | 项目切换器 | `ProjectSwitcherOverlay` | 选择、hover 操作、设置、新建项目、额度、退出 | 342px、11px、6×8px shadow | inventory projections；visual fixture 仅用于多项目样例 | `PARTIAL(P1)`；多项目、账户头、设置/证据入口、焦点陷阱与外部点击完成；额度/退出等真实命令未接线 | 1366 screenshot + project selection interaction test |
| A11 | 全局搜索 | `GlobalSearchOverlay` | Ctrl/⌘+P、实时过滤、上下键、Enter、Esc | centered panel、分组行、footer hints | project/mission/work-product projections | `CLOSED_BASELINE`；原生实测打开即聚焦输入，Esc 精确回到搜索触发器 | 键盘全流程 + query/no-results screenshots |
| A12 | 通知中心 | `NotificationsPanel` | 全部/需要你/运行动态、已读、打开对象、设置 | left 10/top 46/390px/11px | Notification projection 缺失；fixture 为明确样例 | `PARTIAL(P1)`；完整抽屉、三 tab、已读与焦点协议已还原；默认产品仍诚实显示 Notification Projection 未接入 | fixture disclosure + 3 tab + unread transition tests |
| A13 | 顶部更多菜单 | current project actions | 打开 project settings/rename/archive | 32px icon、7px menu row | selected project + Application commands | `PARTIAL(P1)`；菜单和焦点回还实机通过，rename/archive 保持禁用并显示 `NOT_IMPLEMENTED` | menu AX role、Esc、outside click、focus return |
| A14 | 浮层关闭协议 | overlay dispatcher | Esc 关闭顶层、外部点击、触发点恢复 focus | z-index 30/50/70/80 | UI-only state | `CLOSED_BASELINE`；搜索、通知、对象菜单、项目切换器和 Composer 的 Esc/焦点回还均有原生证据 | 单测 + 原生键盘旅程 |
| A15 | toast | product toast | success/warning/error、自消失、不会遮 Composer | bottom context-aware、elevation | Application result only；fixture 显式样例 | `PARTIAL(P1)`；上下文建议条与 Workpad 操作反馈完成，统一 timer/queue toast service 尚未接线 | state injection fixture + timer/reduced-motion test |
| A16 | resize handle | task conversation divider | drag、keyboard resize、reset | gold 1px hover indicator | UI preference state | `PARTIAL(P1)`；拖动、Arrow/Home、440–650 fence 和 AX value 同步完成；跨重启偏好未持久化 | drag 500→620px；min/max fence；reload preference |

## B. Project Dispatcher 与任务调度

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| B01 | Dispatcher hero | `ProjectDispatcherSurface` header | 新建任务、项目标题/说明 | 46px mark、25px h1、25px bottom padding | DesktopProjectProjection | `CLOSED_BASELINE`；品牌 mark、标题、说明、动作与投影标签已同视口校正 | 1366 hero crop diff |
| B02 | 4 格任务摘要 | queue summary strip | 进入对应筛选 | border-only、74px、1.4fr+3fr | mission counts + truth projection | `CLOSED_BASELINE`；四格数字可由 fixture Mission 重算，层级和边线已对齐 | 数字可重算 + cell bounds diff |
| B03 | 优先任务列表 | priority rows | 打开同一 Mission Conversation | 61px row、8px state dot | Mission projections | `CLOSED_BASELINE`；状态、Checkpoint/cycle、进度与打开动作已恢复紧凑行 | 同一数据逐列比对 |
| B04 | 等待你 | attention list | 处理 pending approval/user decision | compact row + gold action | mission checkpoint/pending approval | `CLOSED_BASELINE`；waiting_user 与 waiting_approval 分开，原因与处理动作可见 | waiting_user/waiting_approval 两 fixture |
| B05 | 调度更新 | assistant summary card | 列表展开、项目级状态回写 | hairline card、logo byline | dispatcher projection；fixture narrative disclosed | `PARTIAL(P1)`；跨任务 narrative 和 bullet 密度已实现 fixture，真实 Dispatcher summary projection 尚未持久化 | text wrap at 1024/1366 + fixture marker |
| B06 | 总调度 Composer | project composer | suggestion dismiss/restore、expanded input、runtime selector | 760px/12px/gold focus | Application command | `CLOSED_BASELINE`；轻入口、建议条、展开合同、运行边界与收起状态均已还原 | collapsed/expanded/suggestion states diff |
| B07 | “全部任务/待确认”投影 | nav filter + central dispatcher | active filter 改变 central rows，不只改导航高亮 | selected `#e9e9eb` | Mission projections | `PARTIAL(P1)`；导航进入对应真实 surface，但 Dispatcher 内联过滤与 URL/state persistence 尚未完成 | filter counts/rows deterministic test |
| B08 | Project home | `Current`/project home projection | 查看成果、项目设置、描述新任务 | 1120 max、1.25fr/.75fr | Project/Truth/Connection projections | `PARTIAL(P1)`；Current 已改为紧凑投影页并共享同一 Domain，原型没有独立像素状态可逐页同构 | same project data, no second store |

## C. Mission Conversation、审批与恢复

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| C01 | Conversation header | `OrchestratorSurface` header | Workpad toggle、复制 deep link | 48px、20px side padding | Mission projection | `CLOSED_BASELINE`；状态 hint、fixture disclosure、Workpad 和对象操作簇已对齐 | source crop + copy feedback |
| C02 | 用户消息 | message bubble | selectable text、timestamp | max-width、11–12px text | persisted MissionConversation | `CLOSED_BASELINE`；紧凑 bubble、时间和长文本换行已落地 | long Chinese/German/Japanese wrap |
| C03 | assistant byline | logo/name/time | narrative entry animation | small logo + 10px meta | persisted conversation or disclosed fixture | `CLOSED_BASELINE`；原始 mark、名称、时间、正文 rhythm 与流式 caret 已校正 | source/implementation 1:1 crop |
| C04 | Mission Contract 卡 | mission-contract | natural-language edit entry | 3-column boundary grid、gold-soft | OperatingContract projection | `CLOSED_BASELINE`；“已编译为 Mission”三列边界卡和自然语言修改入口已还原 | compiled-contract fixture + edit flow |
| C05 | 过程行 | progress-row | 展开证据、跳到 trace | 46px、18/1fr/auto grid | Checkpoint/runtime events | `PARTIAL(P1)`；fixture 的 done/live/blocked 叙事流和真实 Runtime phase strip均存在，完整持久 event ledger 投影未完成 | 3-state journey: done/live/blocked |
| C06 | capability tag | progress inline tags | 展开能力边界 | 8–9px capsule | Capability/Provider projections | `CLOSED_BASELINE`；Skill/Plugin/MCP/Connector 样式和诚实边界已还原 | MCP/Skill/Connector 3 variants |
| C07 | capability stack | `<details>` equivalent | expand/collapse、chevron | hairline top/bottom | Capability graph projection | `PARTIAL(P1)`；details 交互与键盘语义完成，展开状态未跨重启持久化 | keyboard Space/Enter + persistence |
| C08 | connection suggestion | inline suggestion row | 跳 Connections，保留 mission context | neutral surface + compact CTA | missing capability projections | `PARTIAL(P1)`；内联建议和 Connections 导航完成，返回同一滚动锚点尚未持久化 | deep link and return bridge test |
| C09 | WorkProduct attachment | attachment row | 打开 Workpad、active highlight | file icon、11px title、9px meta | WorkProductManifest projection | `CLOSED_BASELINE`；附件式 WorkProduct 行、meta 和 Workpad 打开已还原 | multiple products + long title |
| C10 | decision summary | conclusion block | cite evidence、局部修订 | h3 + body, no card excess | WorkProduct/Decision projection | `PARTIAL(P1)`；结论与来源叙事已完成 fixture，真实局部 revision command 尚未接线 | text + evidence relation test |
| C11 | 审批 intro | assistant copy before approval | natural-language modify | paragraph rhythm | pending EffectIntent projection | `CLOSED_BASELINE`；等待审批的 assistant intro 与修改提示已按原型落地 | waiting_approval fixture + no effect execution |
| C12 | approval panel header | exact approval digest summary | expand digest | 48px, gold border/soft bg | EffectIntent + policy version | `PARTIAL(P1)`；Effect Broker 视觉合同和完整 digest 展开完成，真实 EffectIntent projection 尚未接线 | digest equality test + source crop |
| C13 | effect list | 4 independent effect rows | select/modify/defer individually | numbered rows, danger/write badges | EffectIntent[] | `PARTIAL(P1)`；四条独立行与修改/延期结构完成，fixture 明确不创建 EffectIntent/Grant | payload/account/audience change invalidates grant |
| C14 | approval facts | budget/account/schedule/market | exact diff and reapproval | 2-column 40px facts | EffectIntent digest | `PARTIAL(P1)`；facts 展开、minor units 修改和 SAMPLE revision 失效语义完成，真实 digest command 未接线 | value mutation test |
| C15 | approval actions | approve/modify/defer/scope | keyboard/focus | compact primary/secondary/link | Application approval service | `PARTIAL(P1)`；预览/修改/稍后/完整 digest 可交互，真实 Approval Service 未接线且绝不外发 | no external adapter in fixture; status stays sample |
| C16 | result/receipt narrative | result rows | receipt/reconcile/readback details | green only for verified | ProviderReceipt + Verification | `CLOSED_BASELINE`；同构诚实结果样例以 `未执行/未验证/未测量` 呈现，0 Receipt/Verification/OutcomeEvent | fixture labels `样例/未执行`; default no row |
| C17 | outcome next-loop | continue/stop/scale/test | compile next contract | compact decision actions | OutcomeReview projection | `PARTIAL(P1)`；结果结构与返回审批/下一步入口在同一 Mission，真实 Next Contract command 未接线 | route back to same Mission |
| C18 | composer collapsed | mission intent input | focus expansion、suggestion | 52px/760px/12px | Application continuation | `CLOSED_BASELINE`；52px 快速入口、建议、附件/Runtime/发送动作和 focus expansion 已实机验证 | focus/click/typing screenshots |
| C19 | composer expanded | context header + tools | attach/file/voice/runtime/send | 72–160px textarea | Application continuation + file broker boundary | `PARTIAL(P1)`；多行自增长、IME-safe Enter、附件托盘结构、Runtime 菜单和 Stop 完成；File Broker/语音仍 `NOT_IMPLEMENTED/BLOCKED_ENV` | no fake upload; blocked state rendered |
| C20 | blocked/recovery rows | inline recovery contract | retry/reconcile, no auto replay | semantic gold/red, same thread flow | RuntimeRecovery projection | `PARTIAL(P1)`；真实 retry/Stop/uncertain 文案与状态机测试完成，完整 reconnect banner/cursor replay 尚未完成 | crash/recovery fixture + state machine assertions |

## D. Workpad / Work Product 文档面

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| D01 | Workpad tab strip | `Workpad` header | active tab、close tab、collapse all | 34px tabs、3px gap | WorkProduct projections | `CLOSED_BASELINE`；三 WorkProduct tab + 运行检查器、active/overflow/收起完成，最终同视口修复了 tab 挤压 | 3 products fixture + keyboard tabs |
| D02 | 文档工具 | comments/export/collapse/close | tooltip、disabled reason | 30–32px icon button | WorkProduct capabilities | `PARTIAL(P1)`；评论/导出/收起工具簇与可访问名完成，服务未接时以状态提示拒绝 | hover/focus tooltip snapshots |
| D03 | 文档 meta | title/version/source/evidence chips | inspect manifest | 9–11px, hairline | WorkProductManifest | `CLOSED_BASELINE`；标题、revision、来源、0 Receipt/0 Verification chips 已呈现 | digest/evidence counts deterministic |
| D04 | Loop diagram | Measure/Fix/Distribute/Verify | select phase | compact four-stage strip | mission checkpoint DAG | `PARTIAL(P1)`；四阶段语义 strip 与 Lucide/文本完成，真实 DAG phase selection 未接线 | no CSS/ASCII art; use real icon library + labels |
| D05 | 结论区 | decision callout | adopt/edit/reject | subtle surface, left rail | WorkProduct adoption status | `PARTIAL(P1)`；结论/证据 line 视觉完成，真实 adopt/edit/reject command 未接线 | adoption state test |
| D06 | 趋势图 | source chart slot | hover values、source link | measured chart slot | Dataset/WorkProduct asset | `CLOSED_BASELINE`；使用从冻结原型抽取的真实 SVG 资产和可访问描述，不使用 div/CSS 假图 | same slot size + accessible description |
| D07 | 候选方向 rows | ranked evidence rows | open evidence | compact table | WorkProduct preview model | `CLOSED_BASELINE`；三候选紧凑排序、展开验证假设与 Mission 定位反馈完成 | 3 candidate fixture |
| D08 | source list | provenance rows | copy/open, offline state | 9px meta | Truth/Evidence projections | `PARTIAL(P1)`；三条 provenance 行与 Inspector Sources 完成，真实 revoked/offline/open command 未接线 | source count/digest tests |

## E. Growth Operations 页面

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| E01 | Growth shared topbar | shared `GrowthShell` | Connections/Channels/Relationships/Partners 跳转 | 47px、24px padding | selected project | `CLOSED_BASELINE`；四页复用同一 geometry、导航和共享状态提示 | four pages identical geometry |
| E02 | page hero/actions/tabs | shared `GrowthPageHeader` | tabs、primary/secondary action | 22–25px h1, compact CTA | Application projections | `CLOSED_BASELINE`；hero、tab 与双动作从大卡恢复为原型紧凑层级 | per-page source crop |
| E03 | readiness strip | shared `ReadinessStrip` | click metric/filter | border-only cells | deterministic page projection | `CLOSED_BASELINE`；border-only intro/stat cells 和可重算 fixture 数字已恢复 | counts and bounds diff |
| E04 | Channels overview | ranked channel rows + right rail | connect/open plan | dense list | ChannelCapability projection; fixture disclosed | `PARTIAL(P1)`；四行/右 rail/状态动作完成，真实 ChannelCapability projection 未接线 | 4-row fixture + default honest empty |
| E05 | Channels calendar | channel×week grid | previous/next, select item | fine grid, subtle event blocks | Schedule projection | `PARTIAL(P1)`；calendar tab/网格结构 fixture 完成，真实 scheduler、timezone/DST command 未接线 | timezone/DST fixture + keyboard grid |
| E06 | Publishing queue | dense table | filter/status/open digest | compact rows | EffectIntent/Attempt projections | `PARTIAL(P1)`；队列表结构和 `样例·未执行` 边界完成，真实 EffectIntent/Attempt 未接线 | no fake publish; fixture marks `样例·未执行` |
| E07 | Channels outcome | metric strip + table | sort/open attribution | number hierarchy | Outcome projections | `PARTIAL(P1)`；结构与 0 Revenue 边界完成，真实 Channel Outcome projection 未接线 | no Revenue from stage/provider response |
| E08 | CRM pipeline | stage strip + dense table | filter/sort/open person | six-stage strip | Person/Company/Opportunity projections | `PARTIAL(P1)`；Pipeline/table/Consent 样例完成，默认构建不复制 fixture 联系人 | explicit fixture disclosure; default honest empty |
| E09 | CRM Inbox | list/detail split | select, draft, handoff | two-pane minmax grid | Conversation/Handoff projections | `PARTIAL(P1)`；split view 与 handoff 状态结构完成，真实 CAS handoff command 未接线 | human lock prevents outgoing action |
| E10 | Email sequences | stats + table | pause/resume/open | compact status rows | Campaign/Consent projections | `PARTIAL(P1)`；Sequence tab/统计/行结构完成，真实 suppression/callback 仍未接线 | suppression/consent assertions |
| E11 | Contacts | dense identity table | search/filter/open | 42–48px rows | Person/IdentityLink projections | `PARTIAL(P1)`；Identity table fixture 完成，真实 Person/IdentityLink projection 未接线 | cross-tenant fixture prohibited |
| E12 | Partners overview | supply stats/table/right cautions | inspect class and permission | 4-cell strip | Partner/SupplyClass projections | `CLOSED_BASELINE`；四格供给统计、推荐表与公开候选警示已取代粗 12-stage 首页 | official/opt-in/private/public distinct |
| E13 | Creator discovery | dense candidate table | sort/filter/open | compact table | Partner projections; public research-only | `PARTIAL(P1)`；发现表与 Supply Class/Contact Permission 边界完成，真实匹配 projection 未接线 | public candidate cannot generate EffectIntent |
| E14 | Outreach pipeline | five-column kanban | open/move only through Application transition | compact columns/cards | Partner relationship state | `PARTIAL(P1)`；五列 pipeline 结构完成，真实状态迁移 command 未接线 | invalid transition rejected |
| E15 | Program | terms strip + contract table | create/revise/approve exact terms | border-only data table | Program/Agreement projections | `PARTIAL(P1)`；Program/terms/agreement 表结构完成，真实 revision/digest service 未接线 | revision invalidates old approval |
| E16 | Attribution & commission | stat strip + order/refund table | reconcile/open payout | money minor units | Order/Refund/Commission/Payout | `PARTIAL(P1)`；金额/退款/佣金/结算结构完成且不声称付款，真实 ledger 未接线 | currency/refund deterministic oracle |
| E17 | Creator task listing | new `任务与交付` tab | create brief/reward/deadline | same partner page language | CreatorTask projection | `PARTIAL(P1)`；已落成独立任务/悬赏/期限/申请状态列表，不再是粗文字阶段条；真实 CreatorTask command 未接线 | full state path fixture, no payout claim |
| E18 | Apply/invite/award | candidate/task match panel | invite/apply/review/award | compact list + approval | CreatorApplication/Invitation/Award | `PARTIAL(P1)`；申请/邀请/授予与 Contact Permission 样例可见，真实 exact award digest 未接线 | Contact Permission + exact award digest |
| E19 | Milestone & upload | delivery workspace | progress/update/file upload | file broker rows | Milestone/Deliverable projections | `PARTIAL(P1)`；Milestone/交付上传/扫描状态结构完成，File Broker 与恶意文件扫描未接线 | scan/size/type/injection failure states |
| E20 | User review/revision | review split pane | accept/request revision/comments | dense review panel | Review projection | `PARTIAL(P1)`；交付 review、接受/返修/评论结构完成，真实 Review CAS 未接线 | stale generation cannot overwrite review |
| E21 | rights & payout | settlement summary | rights acceptance + exact payout approval | money rows + warning boundary | RightsGrant/Payout projections | `PARTIAL(P1)`；权利/付款顺序与 `未支付/待验证` 边界完成，Stripe Connect/真实 payout 未接线 | Provider accepted ≠ paid; verify/reconcile only |
| E22 | Connections overview | need-next rows + verified/problem rows + right rail | connect/re-auth/detail/revoke | 3/4 stats, compact rows | metadata-only Connection projections | `PARTIAL(P1)`；真实 rows、status、probe evidence summary、revoke coordinator 已接线；无实时 Probe 时始终 0 Connected/`BLOCKED_ENV` | only live Probe may say Connected |
| E23 | Add connection modal | four-step wizard | purpose→account→auth→probe | 620px modal, stepper | Application authorization session | `PARTIAL(P1)`；provider-neutral callback/state/nonce/account/project reducer、restart/revoke/error states 与四步边界完成；Connector SDK、OS deep-link registration、真实 OAuth/account/probe 未接线 | cancel/expired/wrong-account/revoke/error states |
| E24 | Connections subviews | all/policy/activity | filter/open details/revoke | compact table/list | Connection/Policy/Audit projections | `PARTIAL(P1)`；all/policy/activity、metadata rows、revoke/error boundary 完成；真实 Provider audit 与 secret projection 未接线 | secrets absent from DOM/AX/log |
| E25 | Outcomes page | ledger/attribution/decision | mission filter, refund reconcile | dense ledger | Outcome projections | `PARTIAL(P1)`；Ledger/Attribution/Next decision 结构完成且保留 0 Revenue/Unattributed，真实事件摄取与 reconcile 未接线 | totals recompute, Unattributed retained |

## F. Settings、状态覆盖与平台适配

| # | 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|---|
| F01 | Full-screen Settings shell | `SettingsSurface` overlay | Ctrl/⌘+, Esc, return focus | 52px topbar, 242px rail | settings projections | `CLOSED_BASELINE`；最终按源恢复 242px rail、900px panel、58px outline groups 与 52px topbar | 1366 source/implementation diff |
| F02 | Settings search | filter nav + highlight setting | keyboard result open | 34px search | UI filter state | `PARTIAL(P1)`；搜索可过滤 10 分区，no-result 提示与结果直接定位细项尚未完成 | query/no-result/clear tests |
| F03 | 10 settings panels | Common/appearance/model/storage/privacy/notification/connections/account/billing/shortcuts | panel navigation、controls、disabled reason | 900px max, 58px row | Application settings service；未接线明确 NOT_IMPLEMENTED | `PARTIAL(P1)`；10 分区路由完成，General/Appearance/Models/Shortcuts 为专有行，其余未接线分区仍使用诚实边界行 | per-panel distinct rows + honesty labels |
| F04 | Switch/select/text controls | shared setting control variants | toggle/select/browse | 31px inputs、7px radius | settings commands | `PARTIAL(P1)`；原型控件样式与 disabled/read-only 语义完成，Settings persistence 未接线 | keyboard + focus + persistence/no-op tests |
| F05 | Loading/empty/offline/error | inline state variants | retry/return boundary | same page density, no giant blank canvas | real Application state | `PARTIAL(P0)`；fixture 运营页已用 inline rows/banner 替代大画布，但若干默认未接线分支仍保留 compact `state-canvas` | state must preserve surrounding IA |
| F06 | Blocked/waiting states | inline banners/panels | resolve/review | gold semantic | domain status | `CLOSED_BASELINE`；blocked/waiting_user/waiting_approval 在上下文内呈现并有精确动作边界 | 4 state screenshots |
| F07 | Handoff/success/recovery | inline conversation/business page variants | lock/resume/inspect | info/green/gold | real projection only | `PARTIAL(P1)`；10 状态 fixture 与 false-complete/uncertain 测试完成，真实 Handoff gateway/恢复旅程仍未全接线 | false-complete test; visual fixture disclosure |
| F08 | 1024×768 | compact responsive shell | sidebar compact, Workpad collapse | breakpoint contracts | same component tree | `CLOSED_BASELINE`；1024×768 原生 capture PASS、无水平溢出、Composer 主动作可达 | native screenshot + no horizontal overflow |
| F09 | 1366×900 | baseline viewport | all core journeys | exact source dimensions | same data state | `CLOSED_BASELINE`；13 个可比 surface 均生成同状态、同内容视口 joined comparison | source+implementation joined comparison per state |
| F10 | 1600×1000 | wide viewport | max widths/extra document space | intrinsic max constraints | same component tree | `BLOCKED_ENV(P2)`；本机实际 1512×842，报告未冒充 1600×1000 | browser/native capable runner capture |
| F11 | 200% zoom | accessibility zoom | no clipped primary action | minmax/overflow-wrap | same component tree | `CLOSED_BASELINE`；1024×768 @200% 原生 capture PASS，Composer、标题与主动作仍可达 | 1024×768 @200%, keyboard journey |
| F12 | reduced motion | media query | all movement removed, state change preserved | motion token | OS preference | `PARTIAL(P2)`；全局和 fixture CSS gate 已验证，真实 OS reduced-motion 切换截图尚未留证 | computed styles + screenshot |
| F13 | 中/英 UI、德/日内容 | typography/overflow | locale switch, long content | font stack/line-height | i18n catalog + fixture | `PARTIAL(P0)`；德/日/超长内容和中英文混排 fixture 完成，真实 UI locale catalog/切换仍未实现 | Chinese/English UI; German/Japanese payload fixtures |
| F14 | VoiceOver/Narrator | semantic roles and live regions | full keyboard/AT journey | visible focus 3px gold | component semantics | `BLOCKED_ENV(P1)`；17 个原生 AX surface 与关键焦点旅程通过，但 VoiceOver/Narrator 实机端到端不能由 AX 树推断 | macOS/Windows scripted/manual evidence |
| F15 | Visual regression assets | `artifacts/visual/prototype-baseline/` | state-by-state source/actual/joined | exact viewport/state | frozen source + native binary | `CLOSED_BASELINE`；17 个真实 surface、13 组 joined comparisons、响应式、AX 与差异 ledger 已刷新 | every P0/P1 row linked to screenshot or test |

## G. ChatGPT.app 对标的流式 Mission 体验

参考来源：用户于 2026-08-12 提供的五张 ChatGPT/Codex Desktop 截图。这里只吸收成熟交互模式，并翻译为 Hartevo 的 Mission / Checkpoint / Worker / Browser / Effect / Verification 语义；不复制其品牌、导航命名或开发工具专属业务模型。

| # | 参考交互 | Hartevo 实际组件 | 交互与状态合同 | 数据来源 | 当前差异 | 验收方法 |
|---:|---|---|---|---|---|---|
| G01 | 流式正文 | `StreamingAssistantTurn` | token delta 合并、段落稳定、完成后冻结 revision；刷新不重复正文 | persisted Runtime private deltas + Conversation | `PARTIAL(P0)`；pinned Runtime adapter、Domain/Application/SQLCipher 已持久化 exact `item/agentMessage/delta`，绑定 Turn/item/stream/evidence sequence、累计字节和 chain digest，并校验完成正文精确重组；c71061e 的 Dioxus 尚未读取该私有流，fixture 字符回放仍不能冒充真实 Runtime UI | durable reconnect/replay test + virtual clock delta test + 30fps visual capture |
| G02 | 内联运行事件 | `MissionActivityStream` | 读取、工具、浏览器、Worker、验证等事件按时间排序；状态图标与文案独立 | Runtime/Checkpoint/Browser event ledger | `PARTIAL(P1)`；真实 coordinator 输出 content-free Preparing/Dispatched/Turn/Item/Stop/terminal phases，完整持久化 Browser/Worker/Verification event projection 未完成 | duplicate/out-of-order/reconnect replay test |
| G03 | 可折叠工具组 | `ActivityGroup` | 摘要行展开子步骤；已完成自动折叠，失败/等待保持展开 | correlated event group | `PARTIAL(P1)`；fixture activity group 的摘要/展开/折叠完成，真实 correlated event group 未持久投影 | mouse + keyboard expand/collapse + retained state |
| G04 | 事件持续时间 | `ActivityDuration` | 运行中单调计时，结束后冻结；虚拟时钟可复现 | start/end timestamps | `PARTIAL(P1)`；fixture 有冻结时间点，真实 monotonic elapsed/虚拟时钟 UI 未实现 | virtual clock boundary/DST test |
| G05 | 上下文压缩提示 | `CompactionEventRow` | 明确显示压缩发生、保留哪些 Pending Effect/Truth correction；可打开 Compaction Record | Context Fabric compaction ledger | `PARTIAL(P1)`；压缩提示结构和保留边界文案完成，真实 Compaction Record/打开详情未接线 | CTX case: pending approval/correction survives compaction |
| G06 | 步骤进度胶囊 | `MissionProgressPill` | `第 n / m 步`、变更/证据/成本增量；展开到 Checkpoint DAG | Mission/Checkpoint projection | `PARTIAL(P1)`；Checkpoint pill/popover 结构完成，成本/证据 delta 与真实 DAG projection 尚不完整 | revision-correct counts + sticky placement screenshots |
| G07 | 生成中 Stop | `RunControlButton` | running 时为 Stop；点击立即登记 content-free stop request，协调器再提交 version-fenced interrupt；不能假停 | Runtime control Application Service | `PARTIAL(P1)`；单一 square Stop、exact version-fenced interrupt、确定性集成测试和原生状态转换均通过；但 UI request 在 interrupt command 被 Application ledger 接收前仍是进程内信号，尚缺 crash-window 持久化与 cancel p95 | cancel p95 + crash-before-command + restart recovery test |
| G08 | 暂停/恢复 | `PauseResumeControl` | pause 保留 cursor、lease 与 draft；resume 只恢复当前 generation | Worker/Runtime lease | `NOT_IMPLEMENTED(P0)`；现有 retry/resume 是终态恢复，不冒充 pause/reattach | old generation cannot resume/write |
| G09 | 滚动跟随 | `FollowLatestController` | 用户在底部时跟随 delta；手动上滚立即停止；显示“回到最新” | local view state | `PARTIAL(P1)`；fixture 的 near-bottom follow、手动停止和“回到最新”完成，真实持久 stream/reconnect scroll intent 未完成 | deterministic scroll position E2E |
| G10 | 流式不抖动 | message layout containment | 已渲染段落不因新 token/工具卡插入产生大幅跳动；图片先保留槽位 | renderer + asset metadata | `PARTIAL(P1)`；正文/活动/附件使用稳定槽位和 bounded composer，尚无自动 CLS 阈值测试 | screenshot sequence + layout-shift threshold |
| G11 | 附件缩略图 | `ComposerAttachmentTray` | 图片/文件缩略图、名称、大小、扫描状态、移除、失败重试 | File Broker draft projection | `PARTIAL(P1)`；缩略图、名称、样例扫描边界与移除完成；真实 File Broker、扫描、失败重试未接线 | type/size/malware/prompt-injection cases |
| G12 | Composer 多行扩展 | `MissionComposer` | 内容增长到上限后内部滚动；附件、语音、模型/运行设置和发送/Stop 始终可达 | Application draft state | `CLOSED_BASELINE`；52px collapsed→160px auto-grow、Shift+Enter、IME-safe Enter、Esc blur、200% zoom 与 Stop 可达均验证 | collapsed/expanded/attachments/200% zoom screenshots |
| G13 | 运行配置菜单 | `RuntimeProfileMenu` | 模型、推理强度、速度、预算显示当前有效值；Capability 不随菜单扩大 | HarnessProfile + budget projection | `PARTIAL(P1)`；菜单展示真实 Runtime/Provider/Tokenizer 与权限边界，选择和偏好持久化未实现 | policy-denied option and selection persistence |
| G14 | 语音输入 | `PushToTalkControl` | recording/transcribing/error/cancel；barge-in；wake word 默认关闭 | local audio broker | `BLOCKED_ENV(P0)`；控件以禁用状态明确麦克风/本地转写未接线，没有假录音 | permission denied/offline/cancel/long dictation |
| G15 | 右侧运行检查器 | `MissionInspector` | Truth revisions、Work Products、Effects、Worker graph、Browser workspace、成本与来源分区折叠 | same Application projections | `PARTIAL(P1)`；Workpad Inspector tab、Checkpoint/WorkProduct/Effect/Worker/Browser/Sources 分区和 AX 完成；真实 live projections 仅部分可用 | open/close/resize/persist + no second store |
| G16 | Inspector 变更摘要 | `RevisionSummary` | 当前 Mission revision 的 additions/removals、事实/产物/Effect 分开，不用代码行数冒充业务结果 | projection diff | `PARTIAL(P1)`；fixture 按业务对象显示 revision summary，真实 deterministic projection diff 未接线 | revision diff deterministic test |
| G17 | 后台进程/Worker | `WorkerInspector` | running/idle/blocked、lease、generation、heartbeat、stop；正文/secret 不进入面板 | Worker lease projection | `NOT_IMPLEMENTED(P0)`；Inspector 诚实显示 0 active/`BLOCKED_ENV`，未用动画冒充 Worker | lease transfer/crash/reattach cases |
| G18 | Browser/Computer handoff | `BrowserInspector` | BrowserWorkspace、人工接管锁、resume 条件；接管后 agent input 硬停 | Browser/Application projection | `NOT_IMPLEMENTED(P0)`；Inspector 有未创建/接管边界结构，真实 BrowserWorkspace 与 CAS handoff 未接线 | handoff violation zero-tolerance test |
| G19 | Sources 区 | `SourceInspector` | 附件、Provider 文档、Replay、用户提供链接分组；每项 provenance 与读取状态可见 | Evidence/Attachment projections | `PARTIAL(P1)`；Workpad 与 Inspector 均有 provenance 行，真实 open/copy/offline/revoked 状态未接线 | open/copy/offline/revoked source tests |
| G20 | 图片/产物查看器 | `ArtifactViewer` | 新 tab/side pane、zoom、评论、关闭、返回原位置；不使用截图背景冒充产品 | WorkProduct asset | `PARTIAL(P1)`；Workpad tab/side pane 和真实原型 SVG 资产完成，通用 image/PDF zoom/comment viewer 未实现 | image/pdf/text fixture + keyboard test |
| G21 | 多栏可折叠 | shell pane controller | sidebar、conversation、Workpad/Inspector 独立收起与恢复，窄窗一次只保留主任务面 | local UI preference | `PARTIAL(P1)`；Workpad/Inspector 打开收起、拖动/键盘 resize、1024 collapse 完成；sidebar 与偏好跨重启未统一持久化 | 1024/1366/1600 + focus retention |
| G22 | 状态轻量化 | inline event/badge/banner variants | 正常过程用轻行；只有需决策/阻塞/危险才升级为卡片或弹层 | semantic state | `PARTIAL(P0)`；核心 fixture 页面已改为轻行/banner，若干默认未接线路径仍有 compact `state-canvas` | density comparison + hierarchy audit |
| G23 | 长任务持续反馈 | heartbeat + staged summaries | 60 秒内持续可见具体变化；无 delta 时显示正在等待的外部条件和可取消入口 | worker/runtime heartbeat | `PARTIAL(P1)`；真实 Runtime phase feed 每 60ms 轮询并最多显示 32 事件，尚无 >10 分钟/无静默间隙 SLA 证据 | virtual clock 10-minute run, no silent gap >60s |
| G24 | 重连/恢复 | `ReconnectBanner` + replay | 重连后从 event cursor 补齐，不重复消息/工具/Effect；保持用户滚动意图 | durable cursor/ledger | `PARTIAL(P0)`；Runtime/Conversation durable ledger 与 cursor test 已存在，用户可见 reconnect banner、scroll intent 与完整 delta replay 未完成 | network drop/restart/duplicate delta E2E |

## 数据诚实边界

- 默认产品构建只读取 Application Service / Domain projection；不得为视觉密度重新引入 demo store。
- `visual-fixtures` 是显式、编译期隔离的视觉回归场景。每个 fixture 页面必须持续显示 `VISUAL_FIXTURE · 不构成 Probe / Receipt / Verification / E3`。
- 原型里的 Connected、Provider 成功、Receipt、成交、归因和付款文本只能转写为“结构样例 / 未执行 / 未验证”；默认构建没有真实投影时显示紧凑、上下文内的 `NOT_IMPLEMENTED` 或 `BLOCKED_ENV`，不能使用占满页面的大空卡。
- 金额使用 minor units + ISO currency；Creator reward、commission、refund、payout 均不得使用 `f64` 或仅显示字符串后宣称业务状态。
- 本矩阵的任何一项只有在同状态、同视口的原型与真实 Dioxus 截图并排审查，并且关联交互/无障碍/诚实边界测试通过后，才能从差异列表移除。
