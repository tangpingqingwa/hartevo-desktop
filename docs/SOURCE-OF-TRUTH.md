# Hartevo Desktop 事实源规则

本文定义本仓库内部的文档权威关系，防止后续再次出现多个版本互相冲突。

## 1. 当前事实源

| 问题 | 权威文件 |
| --- | --- |
| 产品为谁服务、解决什么问题 | `/PRODUCT.md` |
| 新 Mac 怎样准备环境、克隆仓库和完成首个 Bootstrap PR | `/DEVELOPMENT.md` |
| 下一轮 bounded merge-train 与 Cordis/Rust 插件宿主合同 | `/docs/BUILD.md`（Target Contract，不是实现证明） |
| 为什么采用 Rust/OpenInterpreter、产品线怎样启动 | `/docs/product/HARTEVO-DESKTOP-RUST-OPENINTERPRETER-RFC.md` |
| Hermes 的哪些能力需要用 Rust 重构、哪些不能照搬 | `/docs/research/HERMES-AGENT-V0.20-RUST-CAPABILITY-INTAKE.md` |
| PenguinHarness 的哪些 Harness/Eval 机制需要重构 | `/docs/research/PENGUIN-HARNESS-RUST-CAPABILITY-INTAKE.md` 与 `/docs/quality/HARTEVO-HARNESS-ENGINEERING-ROADMAP.md` |
| Ego Lite 的哪些 Browser Workspace、人机接管与语义自动化机制需要重构 | `/docs/research/EGO-LITE-RUST-BROWSER-WORKSPACE-INTAKE.md` 与 `/docs/architecture/HARTEVO-DESKTOP-ARCHITECTURE.md` |
| Prime Agent 的哪些长上下文、持久工作集与 Worker Graph 机制需要重构 | `/docs/research/PRIME-AGENT-RUST-CONTEXT-FABRIC-INTAKE.md` 与 `/docs/architecture/HARTEVO-DESKTOP-ARCHITECTURE.md` |
| 用户怎样操作、界面怎样响应 | `/docs/product/HARTEVO-DESKTOP-INTERACTION-SPEC.md` 与 `/prototype/index.html` |
| 组件怎样协作、谁拥有事实和权限 | `/docs/architecture/HARTEVO-DESKTOP-ARCHITECTURE.md` |
| Agent UI 组件怎样实现与授权 | `/docs/design/AI-AGENT-UI-COMPONENT-GUIDE.md` |
| 怎样判定完成与允许发布 | `/docs/quality/` 下的四份质量合同 |
| 十二条 Mission 的机器合同 | `/contracts/missions/catalog.v1.json`，由 `hartevo-catalog` 校验 |
| Application route 是否真正有生产 handler | `/contracts/application-handlers/catalog.v1.json`；缺席即 `NOT_IMPLEMENTED`，注册项必须同时存在于当前二进制 |
| Capability 与 Provider 当前状态 | `/contracts/capabilities/catalog.v1.json`、`/contracts/providers/catalog.v1.json` |
| 420+180 数据集结构与私有隔离 | `/contracts/datasets/registry.v1.json` 与 `/docs/quality/DATASET-REGISTRY-AND-ISOLATION.md` |
| 从本地到 E5 的验证顺序 | `/docs/quality/DEVELOPMENT-VALIDATION-LADDER.md` |
| 当前 checkpoint 内容实际运行过什么、哪些环境被阻塞 | `/docs/quality/CURRENT-WORKTREE-EVIDENCE.md`；它不能把 Release baseline 改为通过 |
| 安全、隐私和 Creator 交付/付款威胁 | `/docs/security/HARTEVO-THREAT-MODEL.md` |
| 部署、DR、观测和签名更新 | `/docs/operations/DEPLOYMENT-DR-AND-UPDATES.md` |
| Release schema、通过标志与 Application 覆盖 | `/contracts/missions/stage-application-route-scope.v1.json#/releaseEvidenceSchemaVersion`、`/contracts/release-evidence/schema.v2.3.json#/properties/schemaVersion/const` 与 `hartevo-catalog::ReleaseEvidence::wave_zero_baseline` 的机器事实；当前 `passed` 必须由证据派生并保持 `false` |

## 2. 冲突处理

1. 实际代码和可重放测试证据优先于完成声明。
2. 原型负责视觉与交互细节，交互规格负责行为语义；两者不一致时必须在同一个变更中修正，不能长期并存。
3. 架构文档负责组件所有权与安全边界，RFC 负责重大决策及其理由；实现不得静默改变两者。
4. Quality 文档定义目标和 Gate，不证明某个版本已经通过。通过结果必须绑定 Commit、环境、场景版本和证据位置。
5. 本仓库之外的旧文档只能作为来源或历史证据，不能直接覆盖本仓库当前事实。
6. 机器 Catalog 负责 ID、映射、数量和版本；产品文档负责语义。两者不一致时 CI 必须失败，不能选择对实现更有利的一份。

## 3. 文档状态

本仓库只使用三种状态：

- **Current**：当前实现与产品决策必须遵守。
- **Accepted**：已经决策，等待或正在实现。
- **Target Contract**：目标与验收合同，不代表已经实现。

历史文档不进入主分支。需要保留时放入独立 Archive Release，不与 Current 文档混排。

## 4. 更新要求

- 产品层级、默认导航、自然语言入口、外部动作边界或数据所有权变化，必须同时更新交互规格、架构和相应 Eval。
- 上游 OpenInterpreter 基线变化，必须更新 RFC，记录 release、commit、license、App Server schema digest、Harness 行为和迁移影响。
- Cordis 插件宿主、typed event dispatch、loader overlay 或 bounded merge-train 合同变化，必须更新 [`BUILD.md`](./BUILD.md)；该文件是 Target Contract，不得把其中的 `### PR N:` 标题写成已经落地的实现。
- 引入新的 Hermes-inspired 能力时，必须先更新 Hermes 能力引入清单，记录固定版本、Rust owner、与 OpenInterpreter 的重叠、许可证路径和 Hartevo Eval 场景。
- 引入新的 PenguinHarness-inspired 机制时，必须固定来源版本，并证明它没有创建第二 Agent Loop、第二 wire protocol、模型自评分或可改写 Gate 的自我优化通道。
- 引入新的 Ego Lite-inspired 机制时，必须固定公开代码 commit，区分 MIT helper 与闭源浏览器边界，并证明 Profile、Cookie、Browser Workspace、控制租约和外部 Effect 不会跨 Project 或绕过审批。
- 引入新的 Prime Agent-inspired 机制时，必须固定稳定 Release 与代码审查 commit，并证明它没有创建第二 Agent Runtime、执行模型生成的任意 Python、把 Session/Kernel 当成 Mission 事实源、让 child 扩大权限，或让 Continual Harness 绕过 Candidate Eval 与签名晋升。

- Generic Benchmark Registry、垂直 Dataset partition、私有 Holdout 或 Fresh Shadow 合同变化，必须同步升级四份 Quality 文档版本；公开榜单成绩不能覆盖垂直 Mission 失败，开发集提升不能表述为样本外泛化。
- 每个 Release Candidate 必须生成独立的 Eval 结果，不修改质量合同来适配失败实现。
- 文档中的“已完成”“已连接”“已验证”必须链接到对应的代码或测试证据。
- Creator Hiring/Listing/Application/Award、Task/Bounty、Funding Reservation、Deliverable、Review、Entitlement、Dispute 或 Payout 合同变化必须同时更新 VM-06 Manifest、交互规格、Threat Model、Provider Matrix、Dataset Case 和 Effect/Settlement Oracle。

## 5. 可执行 Docs↔Machine Truth 门禁

当前文档 projection 由 [`contracts/docs-machine-truth/claims.v1.json`](../contracts/docs-machine-truth/claims.v1.json) 定义，并由 `bash scripts/check-docs-machine-truth.sh verify` 读取 JSON pointer、精确 Rust symbol/file authority 与本节的结构化 projection；`bash scripts/check-docs-machine-truth.sh self-test` 会故意验证 stale、missing、duplicate、contradictory claim。该门禁不扫描松散 prose，也不从源码推断测试计数或 E-level；历史证据仍按原文和原 commit 保留。

<!-- docs-machine-truth:begin -->
```json
{
  "manifest": "contracts/docs-machine-truth/claims.v1.json",
  "claims": [
    {"claimId": "DMT-REL-SCHEMA-01", "value": "2.3.0"},
    {"claimId": "DMT-REL-SCHEMA-STAGE-01", "value": "2.3.0"},
    {"claimId": "DMT-APP-REGISTRY-VERSION-01", "value": "desktop-2026-09-05-v22"},
    {"claimId": "DMT-APP-REGISTRY-COUNT-01", "value": 22},
    {"claimId": "DMT-APP-ROUTE-COUNT-01", "value": 52},
    {"claimId": "DMT-APP-NOT-IMPLEMENTED-COUNT-01", "value": 30},
    {"claimId": "DMT-REL-PASSED-01", "value": false},
    {
      "claimId": "DMT-GM01-ISSUES-01",
      "value": [
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/30",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/36",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/37",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/38",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/39",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/40",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/41",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/42",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/43",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/44",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/47",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/48",
        "https://github.com/tangpingqingwa/hartevo-desktop/issues/49"
      ]
    },
    {"claimId": "DMT-DESKTOP-EXECUTION-HANDLE-01", "value": true},
    {"claimId": "DMT-DESKTOP-SUBSCRIPTION-SCOPE-01", "value": true},
    {"claimId": "DMT-DESKTOP-EXECUTION-PAINT-01", "value": true},
    {"claimId": "DMT-DESKTOP-SUBSCRIPTION-API-01", "value": true},
    {"claimId": "DMT-DESKTOP-SUBSCRIPTION-CALLER-01", "value": true},
    {"claimId": "DMT-DESKTOP-VM11-EIGHTH-CALLER-01", "value": true}
  ]
}
```
<!-- docs-machine-truth:end -->
