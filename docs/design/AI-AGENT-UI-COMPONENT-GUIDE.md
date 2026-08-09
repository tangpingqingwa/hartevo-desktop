# Hartevo Agent UI 组件采用规范

状态：**Accepted**
版本：1.0
日期：2026-08-09

本文规定怎样在 Rust/Dioxus Hartevo Desktop 中参考 AI CSS，而不引入第二套前端运行时、错误授权或通用 Chat UI 语义。

## 1. 基本策略

- UI 组件以 Rust + Dioxus RSX 实现。
- 样式使用 Hartevo-owned plain CSS 和 design tokens。
- 不把 React、Vue 或 Svelte 源码作为运行依赖。
- AI CSS 提供交互、状态、动效和样式参考，不提供 Hartevo 的业务信息架构。
- 组件只渲染 Rust application state，不自行模拟 Agent 状态。

## 2. 授权边界

AI CSS 当前列出 14 个组件，其中 9 个免费，其他组件需要付费授权。免费组件可用于个人和商业项目；付费授权禁止把组件原样作为竞品组件库再分发。

### 可先采用的免费组件

- AI Agent Input
- Thinking State
- Thinking + Reasoning
- Orbs
- Text Response
- Streaming Text
- Code Block
- To-do List
- Data Table

### 取得授权后才能复制源码的组件

- Web Search
- File Diff
- Image Generation
- Inline Citations
- Comparison Table

团队开发前建议购买适用的 Enterprise license。授权前，锁定组件只允许做视觉和交互研究，不得把其源码、CSS、SVG 或派生复制品提交到 Git。

每次引入组件都更新 `ui-component-license-manifest`：来源 URL、tier、取得日期、授权主体、改写文件和原始版本 digest。

## 3. Hartevo 组件层级

### 3.1 System primitives

- Button、IconButton、Menu、Popover、Tooltip。
- Input、Textarea、Select、Switch、Slider。
- Dialog、Drawer、Sheet、Toast。
- Tabs、Tree、VirtualList、ResizablePane。
- Badge、StatusDot、Progress、Skeleton。

### 3.2 Agent primitives

- `CommandComposer`
- `ModelRuntimePicker`
- `ReasoningSummary`
- `LiveActivity`
- `ToolActivity`
- `TaskProgress`
- `EvidenceCitation`
- `WorkProductCard`
- `ApprovalCard`
- `EffectReceipt`
- `VerificationState`
- `StructuredResultTable`

### 3.3 Growth domain components

- `MissionHeader`
- `ProjectSwitcher`
- `TaskRail`
- `TruthGraphStatus`
- `ConnectionScope`
- `ChannelOperation`
- `CrmTimeline`
- `CreatorCandidate`
- `OutreachSequence`
- `CampaignBudget`
- `OutcomeReview`

AI CSS 只能影响 Agent primitives，不能把 Growth domain 降级为通用对话卡片。

## 4. 组件采用矩阵

| AI CSS 参考 | Hartevo 组件 | 必须改变的语义 |
| --- | --- | --- |
| AI Agent Input | `CommandComposer` | 增加 Project/Mission context、模型、推理强度、速度、权限、附件和推荐下一步 |
| Thinking State | `LiveActivity` | 显示业务阶段，如“核对市场证据”，不显示内部工具名 |
| Thinking + Reasoning | `ReasoningSummary` | 只展示可公开摘要和依据，不暴露 chain-of-thought |
| Orbs | `AmbientActivity` | 仅用于非阻塞背景活动，不替代明确进度 |
| Streaming Text | `StreamingNarrative` | 支持暂停、redirect、引用和结构化 item 插入 |
| To-do List | `TaskProgress` | Task 来自 Mission State，不由组件本地定时器模拟 |
| Data Table | `StructuredResultTable` | 支持来源、时效、筛选、导出和证据状态 |
| Web Search | `EvidenceSearch` | 显示来源覆盖、时效、去重、可信度和引用绑定 |
| File Diff | `WorkProductDiff` | 不限于代码；支持文案、预算、受众和序列变更 |
| Inline Citations | `EvidenceCitation` | 绑定 Evidence ID、抓取时间、原始来源和事实状态 |

## 5. Command Composer

Composer 是系统级常驻入口，但同一时间只有一个主实例。模块中不复制完整输入框。

必须包含：

- 多行自然语言输入。
- 文件、图片、文件夹和对象引用。
- 当前 Project 与 Mission context 状态。
- Provider / Model / Harness 的用户友好选择。
- 推理强度与速度/成本 preset。
- 当前权限模式和外部动作边界。
- Voice 和发送/停止动作。
- 结合当前页面、连接和阻塞状态生成的建议命令。

折叠状态只保留一条紧凑 command bar；展开后保持用户草稿、附件、模型配置和上下文。切换工作面不创建新会话。

## 6. Agent 状态语言

界面展示用户能理解的业务状态：

```text
正在核对 Amazon 与 Google Trends 的需求差异
正在整理 16 条可追溯证据
等待你确认预算上限
Meta 发布已提交，正在验证页面可见性
```

禁止直接展示：

```text
mcp__provider__call
tool_result success
thread 01...
harness kimi-code
provider returned 200
```

底层详情可进入开发者诊断视图，但不进入默认业务工作流。

## 7. Motion

- 动效表达状态变化，不做装饰性 AI 光效。
- Processing 使用低频、低对比 shimmer 或 orb；持续任务必须同时有文字状态。
- 状态完成后动画停止，不永久占用注意力。
- 遵守 `prefers-reduced-motion`；关键状态不依赖运动才能理解。
- Streaming 不采用强制逐字打字机效果阻碍快速阅读；以 chunk 更新和稳定布局为主。
- 列表、表格和长任务使用虚拟化，避免动画造成滚动跳动。

## 8. Design tokens

组件只能使用语义 token：

```css
--color-bg-canvas
--color-bg-surface
--color-bg-subtle
--color-text-primary
--color-text-secondary
--color-border-default
--color-brand-forest
--color-brand-gold
--color-state-success
--color-state-warning
--color-state-danger
--color-focus-ring
--radius-sm
--radius-md
--shadow-popover
--motion-fast
--motion-normal
```

不得把 AI CSS 的视觉 token 直接当成 Hartevo 品牌 token。迁移时先映射状态与层级，再调整颜色、字重、密度和圆角。

## 9. Accessibility

- WCAG 2.2 AA。
- 所有菜单、Composer、Task 和 Approval 可纯键盘操作。
- Focus 可见且不被浮层遮挡。
- Streaming、Task 和 Effect 状态使用适当 live region，避免逐 token 朗读。
- 图标按钮有可读 label；颜色不是唯一状态信号。
- 中文、英文、长模型名、长路径和 200% 缩放不截断关键操作。
- Reasoning、Task 和工具活动默认可折叠，但摘要始终可读。

## 10. 组件验收

每个 Agent component 必须有：

1. Rust state model。
2. Dioxus component test。
3. idle、loading、streaming、success、error、blocked、cancelled snapshot。
4. Keyboard 与 screen reader 检查。
5. reduced-motion snapshot。
6. 中文、英文和长文本 fixture。
7. License manifest entry。
8. 与 Mission / Task / Effect 状态的契约测试。

## 11. 依据

- [AI CSS component index](https://www.aicss.dev/llms.txt)
- [AI CSS pricing and usage terms](https://www.aicss.dev/pricing)
- [AI Agent Input](https://www.aicss.dev/components/ai-agent-input)
- [Thinking + Reasoning](https://www.aicss.dev/components/thinking-reasoning)
- [Task List](https://www.aicss.dev/components/task-list)
- [Dioxus](https://github.com/DioxusLabs/dioxus)
