# Hartevo Dataset Registry 与隔离合同

状态：**Current + Target Contract**
机器事实源：`/contracts/datasets/registry.v1.json` 与 `hartevo-catalog`
合同版本：`desktop-2026-08-11-v4`

## 1. 目的

Dataset Registry 证明 Hartevo 在不同业务主体、市场、项目成熟度、表达和故障组合下能完成整条 Mission。单个 Prompt、Demo、Fixture 或 Provider happy path 不能作为数据集。

## 2. 固定规模

每条 VM-00～VM-11 至少具有：

- V0：20 个仓库可见开发 Case；
- V1：10 个隔离私有 Holdout Case；
- V2：5 个 Candidate 冻结后 Fresh Shadow Case；
- 15 个独立横切 Case。

总计为 420 个 Mission Case + 180 个横切 Case。Provider Contract Test、Judge Calibration、真实 Canary 和生产 Replay 另计。

## 3. V0 构成

前 12 个 Case 固定覆盖：

```text
DTC Brand | Marketplace Seller | B2B SaaS | Local Service
                         ×
                     US | DE | JP
```

每条 Mission 内，`blank/partial/mature/conflicted` 和 `solo_owner/operator/sales_partner_manager/team_with_approver` 各出现三次。其余八个 Case 为两个 Truth conflict、两个 Auth/Consent、两个 Provider/Recovery 和两个 Steering/Mode。

VM-08 在不适用的 B2B SaaS/Local Service 世界中应给出可解释的 `EXPECTED_REFUSAL`，不能强造 Marketplace 执行。

VM-06 的 V0 Journey 必须同时覆盖：

- 官方网络、Hartevo Opt-in、租户私域和公开候选四类供给；
- 公开候选保持 research-only，及联系许可在邀请审批后撤回时 Provider 调用数为 0；
- 用户冻结 Hiring Offer，通过已验证定向 Invitation 或已验证公开 Task/Bounty Listing 接收 Application；
- 用户显式选择 Application 并生成不可伪造 Award；未选中、撤回、Offer 变化和无已验证来源的申请均有确定性终态；
- 正式 Task 重新验证持久化 Award，达人接受后上传真实 Deliverable；
- 一次性 `campaign` 与长期 `continuous_relationship` 两种合法 Operating Mode；
- 资金准备/预留的 exact Provider evidence，以及“不是法定 escrow”的诚实标签；
- 文件扫描、素材来源和使用权声明；
- 用户接受、请求修改、拒绝/争议；
- 接受前禁止付款，接受后精确审批和 Stripe Connect Receipt；
- Review 期仅评估访问、接受后等待付款、独立验证付款后合同使用权生效三种可判定状态；
- Deliverable digest 变更、重复付款、KYC/资金不足和 chargeback。

## 4. V1/V2 隔离

产品仓库只保存 V1/V2 的 Case ID、Mission、Family、Fixture/Simulator metadata、private locator 和冻结要求。以下内容只存在于隔离 Evaluator：

- Prompt 和用户事件原文；
- World delta 和私有 Provider 返回；
- Checkpoint/Oracle/Rubric；
- gold artifact、expected state 和 failure trace；
- contamination canary 的具体内容。

Target、Optimizer、产品 Runtime 和普通 CI 无权读取。Evaluator 只返回受限结果、统计和已清洗 Trace link。任何读取都会使整个 Dataset revision 作废。

## 5. Case 计数规则

一个 Case 只有同时具有以下内容才计数：

1. 唯一 ID、版本、partition 和 deterministic seed；
2. 完整 Mission Checkpoint Journey；
3. 确定性初始世界、至少一个状态变化和可判定终态；
4. 允许与禁止的 Effect；
5. 适用的 Business Oracle；
6. provenance、license、冻结时间和污染标记；
7. 连续型 Mission 至少两个周期或一次时间线事件。

仅修改 Prompt 措辞、模型温度或 Case 名称不能生成新样本。

## 6. 生产 Replay

- 生产 Trace 先去标识、删除正文/Secret/直接 PII，再由权限隔离的人员转成 Fixture。
- Replay 保留业务状态和故障机制，不保留真实客户身份。
- 每个已关闭事故必须绑定 Replay Case、修复 Commit 和回归结果。
- Fresh Shadow 在 Candidate 冻结后生成；同一 Candidate 看到结果后不得修改并再次声称样本外通过。

## 7. Judge Dataset

200 个双人专家样本的构成为 144 Mission、24 跨市场/语言、16 Truth 对抗、16 Work Product 采用。金额、状态、权限、Consent、Effect、URL、Receipt 和 Attribution 永远由确定性 Oracle 处理。

## 8. 当前诚实状态

Wave 0 已能物化并验证 240 个完整 V0 metadata/content contract、120 V1 metadata、60 V2 metadata 和 180 横切 metadata。它们证明 E1 数据合同存在，不证明 Target 已运行或通过。实际执行计数保持 0，Release Baseline 必须失败关闭。
