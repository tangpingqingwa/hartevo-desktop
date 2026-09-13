# Agent 执行反馈与动效

本次把任务准备、执行、回复、等待确认与结束统一到 Rust 状态组件。它展示当前项目和任务的观测结果，不启动执行、不按定时器推进业务状态，也不把传输追平当作任务完成。

## 交互

| 场景 | 呈现 |
| --- | --- |
| 准备执行 | 连接形态 Orb 与两行准备说明 |
| 执行中、等待正文 | 低频点阵 Orb 与可停止的文字说明 |
| 正文增量到达 | 丝带形态 Orb；立即显示已收到的正文，不人工逐字重放 |
| 等待决定、停止请求 | 静态语义图标；会话与输入区同步停止持续动效 |
| 完成、失败、中断、结果待核实 | 静态状态与下一步说明；不依据历史活动状态继续旋转 |
| 成果出现 | 短距离淡入；文字成果按内容自然展开 |
| 工作台收放 | 240 ms 过渡；关闭立即 inert，离场后释放内容；快速重开取消过期移除 |
| 关闭工作台 | Escape 或关闭按钮收起，焦点回入口，可用空格重新打开 |

入口确认、流式正文、素材加载、成果卡与工作面切换使用同一组时长和缓动。默认流程只显示业务文字，处理和回复的技术记录折叠显示。未发送草稿不由动效层保存、清空或切换。

## 性能与可访问性

- Rust 决定状态，Canvas 只负责绘制。单个 requestAnimationFrame 调度器最多绘制 30 fps，32 px 画布的像素倍率最多为 2。
- 不可见 Orb、后台窗口、减少动态效果模式停止持续绘制；节点卸载后解除观察并释放调度。
- 原生后台 WebKit 的动画时钟可能暂停在起始帧。后台 CSS 直接使用最终布局，不让工作台宽度或文字透明度卡在起点。前台恢复后才启用进入过渡。
- 系统减少动态效果切换实时生效，文字和静态图标保留。动画不承担唯一的状态表达。
- 状态行只在阶段改变时更新，避免对每个正文增量重复播报状态；正文仍由现有会话阅读与跟随逻辑管理。
- 关闭中的工作台不接受键盘或辅助技术访问，期间仍使用当前权限校验后的 children，不缓存上一任务的内容。

## 来源与构建

[Transitions thinking states](https://transitions.dev/detail.html?t=thinking-states) 用于参考状态切换的节奏，没有复制其源码。点阵几何使用 [Libraries.dev Thinking Orbs](https://libraries.dev/orbs) 的公开 MIT 源码，固定 Git 修订 `422180dd7a5ac646c85deedc65500c4a74339127`，保留原始文件与许可证。

没有引入 React 运行时。预览图标取自产品已有的 dioxus-icons / Lucide（ISC），来源、版本和每个文件的 SHA-256 记录于 `ui-component-license-manifest.json`。

```sh
# Node 24：校验上游文件摘要并生成纯展示脚本
node scripts/build-agent-motion.mjs
node scripts/build-agent-motion.mjs --check
node scripts/test-agent-motion.mjs

cargo test --locked -p hartevo-desktop --lib agent_motion --all-features
cargo clippy --locked -p hartevo-desktop --all-targets --all-features -- -D warnings
dx build --desktop -p hartevo-desktop --locked
```

`prototype/agent-motion.html` 使用生产样式和相同画布渲染，提供完整阶段、播放、停止、草稿保留与工作台收放的交互预览，明确标为模拟数据，不调用模型。

原生交互样例使用现有 `visual-fixtures` 构建、`prototype-baseline-v1` 场景及 `mission-persisted-stream` / `first-append`。窄窗口可使用 `HARTEVO_DESKTOP_UI_VIEWPORT=1024x768`。样例用于布局、键盘与状态呈现验收；不能替代真实模型运行、私有上下文恢复或外部业务效果的验证。
