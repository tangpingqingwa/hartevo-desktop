# Hartevo Desktop

Hartevo Desktop 是面向增长负责人、品牌经营者和代理团队的 Agent-native Growth AI OS 工作入口。用户用自然语言表达业务目标，Hartevo 在同一项目总调度中持续协调研究、证据、创作、渠道、CRM、达人与联盟、审批、外部动作和结果验证。

当前仓库状态：**产品与交互基线已冻结，工程尚未开始。**
当前交互版本：**Desktop v12**
技术基座：**Rust + OpenInterpreter App Server + Dioxus Desktop + Hartevo Domain Kernel**

## 开始阅读

只需要按下面顺序阅读，不需要查找其他 Hartevo 历史文档：

1. [PRODUCT.md](./PRODUCT.md)：产品用户、目的、边界、品牌和设计原则。
2. [Rust 与 OpenInterpreter 基座 RFC](./docs/product/HARTEVO-DESKTOP-RUST-OPENINTERPRETER-RFC.md)：对上游的技术审查、采用边界、Rust 栈、仓库策略和实施路线。
3. [Hermes v0.20 Rust 能力引入清单](./docs/research/HERMES-AGENT-V0.20-RUST-CAPABILITY-INTAKE.md)：哪些 Hermes 前沿机制应由 Hartevo 用 Rust 重构，哪些不能照搬。
4. [PenguinHarness Rust Harness Lab 引入清单](./docs/research/PENGUIN-HARNESS-RUST-CAPABILITY-INTAKE.md)：怎样吸收其极简工具面、Trace、Benchmark 与自我改进闭环，并修正不适合业务 Agent 的部分。
5. [Ego Lite Rust Browser Workspace 引入清单](./docs/research/EGO-LITE-RUST-BROWSER-WORKSPACE-INTAKE.md)：怎样吸收 Agent 专属浏览空间、登录复用、语义快照和人机接管，并修正闭源内核、任意脚本与 Profile 越界风险。
6. [Prime Agent Rust Context Fabric 引入清单](./docs/research/PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md)：怎样吸收其外置上下文、持久工作集、Context Branch、Worker Graph 与 Continual Harness，并修正任意 Python 执行和无边界自改写风险。
7. [Desktop 交互规格](./docs/product/HARTEVO-DESKTOP-INTERACTION-SPEC.md)：当前冻结的产品层级、信息架构和完整交互。
8. [Desktop 当前架构](./docs/architecture/HARTEVO-DESKTOP-ARCHITECTURE.md)：组件所有权、数据流、本地与云边界、安全不变量。
9. [Agent UI 组件采用规范](./docs/design/AI-AGENT-UI-COMPONENT-GUIDE.md)：如何在 Dioxus 中参考 AI CSS，并处理授权、状态语义和可访问性。
10. [质量与 Eval 入口](./docs/quality/README.md)：怎样证明 Mission 真正完成，而不只是界面或工具存在。
11. [可交互原型](./prototype/index.html)：当前产品行为的最终视觉和交互参考。

## 当前冻结的产品决策

- 产品层级是：用户 / 组织 → 宣发项目 → Mission → Effect、Receipt、Verification 与 Outcome。
- 每个项目只有一个持续存在的总调度关系；业务工作面共享 Mission State，不产生割裂会话。
- 任务与 Mission 是主要工作对象，模块只是结构化工作面。
- 自然语言入口常驻；模型、推理强度和速度从同一入口配置。
- 切换项目后默认进入该项目总调度，并同步切换任务、事实、连接、审批与长期记忆。
- Desktop 本地优先；项目可以位于已有文件夹、新建本地文件夹、本地加密同步或云工作区。
- 连接成功不等于允许执行；外部动作仍受 Scope、Consent、Approval 与 Effect Policy 控制。
- Provider 返回成功不等于业务成功；必须保留 Receipt、Verification 和 Outcome。
- 长上下文不是无限 Prompt；Context Fabric 用持久工作集、Continuation Ledger、Context Capsule 和可恢复 Worker Graph 保持 Mission 连续。

## 仓库结构

```text
hartevo-desktop/
  README.md
  PRODUCT.md
  docs/
    SOURCE-OF-TRUTH.md
    product/
      HARTEVO-DESKTOP-RUST-OPENINTERPRETER-RFC.md
      HARTEVO-DESKTOP-INTERACTION-SPEC.md
    architecture/
      HARTEVO-DESKTOP-ARCHITECTURE.md
    design/
      AI-AGENT-UI-COMPONENT-GUIDE.md
    research/
      EGO-LITE-RUST-BROWSER-WORKSPACE-INTAKE.md
      HERMES-AGENT-V0.20-RUST-CAPABILITY-INTAKE.md
      PENGUIN-HARNESS-RUST-CAPABILITY-INTAKE.md
      PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md
    quality/
      README.md
      HARTEVO-HARNESS-ENGINEERING-ROADMAP.md
      HARTEVO-EVAL-SCENARIO-CATALOG.md
      HARTEVO-COMPLETION-METRICS-SCORECARD.md
      PRODUCT-SLO-AND-EVAL-GATES.md
  prototype/
    README.md
    index.html
    hartevo-logo-mark.png
```

## 未收录的材料

本仓库只收录当前产品、交互、架构和质量合同。历史部署快照、会话交接、过期架构、早期原型、过程截图和生产账号资料均留在原项目，不进入本仓库，也不构成 Hartevo Desktop 的事实源。

## 下一阶段

下一步应在本仓库补齐四个实现合同，然后开始首个垂直切片：

1. OpenInterpreter bootstrap、完整来源历史与 App Server schema pin。
2. `hartevo-rs` Workspace、Domain Contract 与 Runtime Adapter 协议。
3. Generic Benchmark Registry、Terminal-Bench/SWE-bench adapter、垂直开发集、私有 Holdout 与 Fresh Shadow 的隔离存储和 Runner。
4. 将 Hermes v0.20 R0、PenguinHarness Candidate Lab、Ego Lite-inspired Browser Workspace 和 Prime Agent-inspired Context Fabric 合同写入 MVP Implementation Backlog、Dioxus Shell 与首批 Mission Harness。

首个可运行切片应完成：自然语言目标 → Mission 编译 → 研究与 Work Product → 外部动作审批 → Receipt / Verification → Outcome，而不是先完成大量空模块。
