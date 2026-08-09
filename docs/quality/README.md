# Hartevo Desktop 质量与 Eval 文档

这四份文件共同定义“产品完成”的含义。它们是目标合同，不是当前完成声明。

## 阅读顺序

1. [Completion Metrics Scorecard](./HARTEVO-COMPLETION-METRICS-SCORECARD.md)：先理解怎样计分，以及什么证据才算成熟。
2. [Eval Scenario Catalog](./HARTEVO-EVAL-SCENARIO-CATALOG.md)：再确定需要覆盖哪些用户 Mission、故障、长任务和并发场景。
3. [Harness Engineering Roadmap](./HARTEVO-HARNESS-ENGINEERING-ROADMAP.md)：然后建设 World、Journey、Trace、Oracle、Replay 和差异报告。
4. [Product SLO and Eval Gates](./PRODUCT-SLO-AND-EVAL-GATES.md)：最后用数值门槛决定 Release Candidate 能否发布。

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
```

## 使用规则

- 不把工具调用成功、页面存在或 Schema 存在计为 Mission 完成。
- 每次结果必须绑定完整 Commit SHA、场景版本、World Fixture、模型与 Provider 配置。
- 历史 Hartevo 得分不能继承给 Desktop。
- 环境缺失报告 `BLOCKED_ENV`，能力不存在报告 `NOT_IMPLEMENTED`，不能用 `SKIP` 隐藏。
- 外部动作场景必须检查 Scope、Consent、Approval、Idempotency、Receipt 与 Verification。
- 失败必须生成可重放的最小 Replay Pack，进入下一次回归。
