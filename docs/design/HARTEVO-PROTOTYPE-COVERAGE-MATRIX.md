# Hartevo Desktop 原型还原与覆盖矩阵

状态：首轮高保真基线。设计 Source of Truth 是 `prototype/README.md`、`prototype/index.html` 与 `prototype/hartevo-logo-mark.png`；交互和状态补充合同是 `docs/product/HARTEVO-DESKTOP-INTERACTION-SPEC.md`。视觉夹具只在 `visual-fixtures` feature 下编译，始终显示 `VISUAL_FIXTURE`，不计作 Receipt、Verification、Provider 成功或 E3 证据。

| 原型区域 | 实际页面/组件 | 交互 | Design Token | 数据来源 | 当前差异 | 验收方法 |
|---|---|---|---|---|---|---|
| 全局 52px 顶栏 | `app-chrome`、`brand-bar`、`mission-bar`、`document-bar` | 搜索、通知、刷新、Workpad 开关 | `--side-w`、`--chat-w`、`--line`、52px row | Application projection + UI-only overlay state | macOS 原生标题栏额外占 31px；不改变内容网格 | 1366×869 同视口并排截图；AX 名称检查 |
| 品牌标识 | `BRAND_MARK_DATA_URL`、`UiIcon` | 品牌图只读；Lucide 图标继承按钮语义 | 29/42px、`--ink`、`--gold` | 原始 PNG 由 `include_bytes!` 编译；`dioxus-icons` Lucide | 无手绘 SVG、Emoji 或文本符号替代 | 源文件 SHA；像素截图；构建资产清单 |
| 左侧栏 | `sidebar`、`NavButton`、`project-rail`、`mission-rail` | 页面切换、项目/任务选择、滚动 | `--sidebar`、32px item、7px radius、`--selected` | `DesktopInventoryProjection` | 原型中“待确认/自动任务”是派生分组；正式投影未提供时不伪造 | 键盘 Tab/Enter；长列表滚动；1024/1366/1600 截图 |
| 新任务入口 | `new-task` | 点击或 ⌘/Ctrl+N 返回 Project Dispatcher 并展开合同托盘 | 42px、8px radius、hairline border | 当前 Project selection | 无项目时禁用，避免创建游离 Mission | 快捷键单测；无项目/有项目交互测试 |
| 项目切换器 | `workspace-switcher`、`project-switcher` | 打开、选择项目、Esc/外部点击关闭、进入设置/证据 | popover elevation、7/10px radius | `DesktopInventoryProjection` | 原型演示菜单项被真实 Inventory 替代 | AX dialog/tree；项目选择状态测试 |
| 项目总调度 | `ProjectDispatcherSurface` | 按 Mission 状态聚合、打开同一 Mission Conversation | 1040px max、4-column stats、64px rows | `DesktopProjectProjection`；视觉回归使用显式 fixture | “同步于几分钟前”等相对时间未投影，改为 revision/cycle | 原型/实现 1205×741 内容视口并排；数字可由 fixture 重算 |
| Mission Conversation | `OrchestratorSurface`、`MissionStateCard` | 继续、纠正、Human Checkpoint 确认、Application handler | 760px content、9px panels、dense 8–12px type | `MissionProjection`、`MissionRuntimeProjection` | 只有持久消息才显示；视觉 fixture 不制造聊天正文 | 同一 Mission 选择/返回；重启恢复测试；无 false-complete 断言 |
| 底部 Composer | `composer-zone`、`catalog-contract-fields` | 文本输入、折叠/展开 Operating Contract、提交、Runtime 安全重试 | 12px radius、gold focus ring、sticky bottom | Application command input；Catalog route projection | 原型是轻量输入；完整合同放入可折叠托盘以保留全部安全字段 | 默认/展开截图；键盘 focus；字段校验与 minor-unit 测试 |
| 精确审批 | `human-checkpoint-confirmation`、WorkProduct 选择 | 绑定 Mission/Checkpoint/conversation revision 与选定产物 | `--gold-soft`、warning border | Application human checkpoint route | 不存在真实 pending approval 时不显示演示审批 | digest/revision 单测；空 WorkProduct 拒绝；键盘复选 |
| Workpad | `Workpad` | Mission 选中时打开/收起，展示持久 WorkProduct Preview | `--chat-w`、42px header、40px document padding | 解锁后的 `WorkProductProjection` | Project Dispatcher 默认不占用 Workpad；与原型总调度一致 | Mission 选中截图；锁定/无产物/有产物三状态 |
| Current | `CurrentSurface` | 查看项目边界、Mission/产物/审批计数 | readiness strip、surface section variants | `DesktopProjectProjection`、`ProjectContextAccessProjection` | Provider health 保持 `NOT_IMPLEMENTED` | 数字重算测试；空项目、锁定、可用截图 |
| Missions | `MissionsSurface` | Mission 列表、打开同一会话 | table rows、stage dots、selected row | Project scoped `MissionProjection[]` | 原型未接入的筛选按钮保持 disabled | 列表选择测试；EXPECTED_REFUSAL/失败标签测试 |
| Channels | `ChannelSurface` | Overview/Content/Calendar/Publishing/Inbox tabs 骨架 | tabs、pipeline strip、compact empty | 当前 Project/Mission projection | Provider/Outcome 未接线处显示 `NOT_IMPLEMENTED` | Tab 键盘流；空/blocked/error 状态截图 |
| CRM / Relationships | `RelationshipsSurface` | Inbox/Contacts/Companies/Opportunities/Campaigns 视图 | relationship split layout、badges | Project/Mission projection；Relationship projection 待接线 | 明确 `NOT_IMPLEMENTED`，不复制演示联系人/Consent | 隐私文本断言；空/未接入视觉回归 |
| Partners / 达人任务 | `PartnersSurface`、`creator-work-flow` | 12 阶段建联、悬赏、交付、review、接受/返修、付款状态展示 | 3/4-column stage flow、state badges | Project/Mission projection；Creator/Settlement projection 待接线 | 完整状态机已可见；真实 contract/deliverable/payout 写入仍 `NOT_IMPLEMENTED` | 12 阶段覆盖断言；公开候选不可触达安全测试 |
| Connections | `ConnectionsSurface` | Overview/Catalog/Accounts/Activity；4 步授权说明 | readiness cards、connection modal language | Project context + Provider capability boundary | 未接线 Probe 一律 `BLOCKED_ENV`/`NOT_IMPLEMENTED`，不显示 Connected | 无假 Connected 静态检查；空/错误/撤销文案检查 |
| Outcomes | `OutcomesSurface` | Mission KPI/Attribution/Cost/Next loop 入口 | outcome layout、ledger rows | Mission outcome projection | 无 OutcomeEvent 时保持 EMPTY；不把 Stage 当 Revenue | 金额/币种/退款/Unattributed 文案与领域测试 |
| Settings | `SettingsSurface`、`SettingsPanel`、`SettingsRow` | 左侧分区、关闭、⌘/Ctrl+, | settings rail、row variants | Runtime projection；Settings Application Service 待接线 | 未持久化控件保持禁用/`NOT_IMPLEMENTED` | 快捷键单测；键盘导航；运行态截图 |
| 全局搜索 | `GlobalSearchOverlay` | ⌘/Ctrl+P、过滤 Project/Mission、Esc 关闭；⌘/Ctrl+K 返回总调度 | modal elevation、search rows | 当前 `DesktopUiModel` 的 Application projections | 不搜索未投影的联系人/产物正文 | 快捷键单测；查询/空结果/打开结果交互 |
| 通知中心 | `NotificationsPanel` | 打开、tab 结构、关闭、进入设置 | drawer elevation、notification tabs | Notification projection 待接线 | 明确 `NOT_IMPLEMENTED`，不复制原型演示通知 | AX dialog；Esc/外部点击；空状态截图 |
| 状态语言 | `IntegrityBanner`、`EmptyState`、honesty chips | loading/empty/offline/error/blocked/waiting_user/waiting_approval/handoff/success/recovery | semantic green/gold/red + neutral boundary | Application/Domain status；缺失状态不推导 | success 只允许由业务 Oracle/Projection 驱动；部分 Gateway 状态尚无投影 | 状态合同测试；false complete/uncertain 不重放断言 |
| 状态视觉合同 | `StateCoverageSurface`、`StateContractCard` | 十种状态与德/日/超长文本压力样例；仅 visual fixture 可直达 | state tone、hairline、semantic left rail | 显式 `VISUAL_FIXTURE`；实际产品仍由 Application/Domain 投影驱动 | 这是回归载体，不是第二套业务 store，也不提升证据等级 | 原生截图、ARIA role/label、1024 与 200% zoom 回归 |
| 响应式 | CSS media contracts | 1024/1366/1600、窄窗、长列表 | 1390/1120/900/680 breakpoints | 同一组件树 | 1024 下 Workpad 收起；900 下图标栏 | 同视口截图矩阵；无水平溢出检查 |
| 200% zoom / 长文本 / 多语言 | intrinsic grid、ellipsis、overflow-wrap、bounded trays | 浏览/输入/弹层不丢操作 | minmax(0,1fr)、thin scrollbars | 中文 UI；fixture/scenario 提供德/日/长文本 | 完整产品 i18n catalog 尚未接线，当前仍以中文 UI 为基线 | 200% zoom；德/日内容；超长项目名/路径截图 |
| 键盘 / 无障碍 / 动效 | root shortcut dispatcher、ARIA labels、`:focus-visible`、reduced-motion | Tab/Shift+Tab、Enter/Space、Esc、⌘/Ctrl+P/K/N/, | 3px gold focus ring；120/180ms motion | 组件语义 + pure shortcut mapping | VoiceOver/Narrator 全量实机回归仍需平台 runner | shortcut unit tests；AX tree；reduced-motion CSS gate |
| 原生窗口 | `main.rs` Desktop `WindowBuilder` | 默认 1366×900、最小 1024×768 | native frame + product grid | Dioxus Desktop | macOS 可见工作区会把内容高度约束到 869px | 原生窗口 bounds；安装包 smoke；同内容视口比较 |

## 视觉 fixture 边界

- Feature：`visual-fixtures`，默认产品构建不包含 fixture loader。
- Scenario：`hartevo-rs/desktop/fixtures/prototype-baseline.v1.json`。
- 启用变量：`HARTEVO_DESKTOP_UI_SCENARIO=prototype-baseline-v1`。
- 每个可见 Work Product 都标识为视觉夹具；`verified_effect_count=0`，Runtime 为 `NOT_CONFIGURED`，Release 为 `false`。
- fixture 只用于同视口视觉、键盘和交互回归，不提升 E0～E5。
