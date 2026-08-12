# Hartevo Desktop 质量与 Eval 文档

四份核心质量合同定义“产品完成”的含义；Validation Ladder 与 Dataset Registry 合同定义执行顺序和样本隔离。它们都是目标/运行合同，不是当前完成声明。

## 阅读顺序

1. [Completion Metrics Scorecard](./HARTEVO-COMPLETION-METRICS-SCORECARD.md)：先理解怎样计分，以及什么证据才算成熟。
2. [Eval Scenario Catalog](./HARTEVO-EVAL-SCENARIO-CATALOG.md)：再确定需要覆盖哪些用户 Mission、故障、长任务和并发场景。
3. [Harness Engineering Roadmap](./HARTEVO-HARNESS-ENGINEERING-ROADMAP.md)：然后建设 World、Journey、Trace、Oracle、Replay 和差异报告。
4. [Product SLO and Eval Gates](./PRODUCT-SLO-AND-EVAL-GATES.md)：最后用数值门槛决定 Release Candidate 能否发布。
5. [Development Validation Ladder](./DEVELOPMENT-VALIDATION-LADDER.md)：按 L0～L4、V1/V2、E4、GA、E5 的顺序取证。
6. [Dataset Registry and Isolation](./DATASET-REGISTRY-AND-ISOLATION.md)：固定 420+180 样本结构及私有内容边界。
7. [Current Worktree Evidence](./CURRENT-WORKTREE-EVIDENCE.md)：记录当前 checkpoint 内容真正执行过的本地证据与环境阻塞；它不是 Release Evidence。

## 四者关系

```text
Completion Metrics
  定义“什么叫完成”
        ↓
Eval Scenario Catalog
  定义“在哪些业务世界里证明”
        ↓
Harness Engineering Roadmap
  定义“用什么工程系统运行和取证”
        ↓
Product SLO and Eval Gates
  定义“达到什么门槛才允许发布”
        ↓
Development Validation Ladder
  定义“在哪个环境按什么顺序运行”
```

## 使用规则

- 不把工具调用成功、页面存在或 Schema 存在计为 Mission 完成。
- 每次结果必须绑定完整 Commit SHA、场景版本、World Fixture、模型与 Provider 配置。
- 历史 Hartevo 得分不能继承给 Desktop。
- 环境缺失报告 `BLOCKED_ENV`，能力不存在报告 `NOT_IMPLEMENTED`，不能用 `SKIP` 隐藏。
- Application route 只有同时出现在 Mission Catalog、Application Handler Registry 与当前二进制时才算可执行；当前机器覆盖必须由 Catalog Snapshot 与 Release Evidence 输出，不能从页面按钮推断。
- 外部动作场景必须检查 Scope、Consent、Approval、Idempotency、Receipt 与 Verification。
- 长任务场景必须检查 Context Capsule 隔离、压缩不变量、Worker authority、分支回流、Runtime-independent resume 和成本归因。
- 公开通用 Benchmark 只证明基础竞争力；Harness 晋升必须同时通过 Hartevo 垂直开发集、私有 Holdout 和 Candidate 冻结后的 Fresh Shadow。
- 失败必须生成可重放的最小 Replay Pack，进入下一次回归。
