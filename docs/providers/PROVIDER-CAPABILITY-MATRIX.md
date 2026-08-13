# Hartevo Provider Capability Matrix

状态：**Target Contract**
机器事实源：`/contracts/providers/catalog.v1.json`

## 1. 状态语义

- `target_contract`：在完整产品范围内，当前仍须按 Capability 达到 E4 才可显示可用。
- `authorization_required`：合同已定义，但依赖商业授权或特定账号。
- `experimental`：只在 Feature Flag 和测试租户中使用，不成为 GA 硬依赖。
- `contract_only`：只验证替代接口，不宣称 live support。
- `evidenceLevel` 是当前证据，不是路线图目标；未完成真实 Probe 的 Provider 一律不能显示 Connected。

## 2. 冻结矩阵

| 能力组 | Provider | 主要 Mission | 默认边界 |
| --- | --- | --- | --- |
| Identity/Billing | Keycloak、Google OIDC、Stripe | VM-00 | OIDC state/nonce、账号确认、Webhook 幂等 |
| Search/Analytics | GSC、GA4、Google Ads、DataForSEO、Google Trends（授权后） | VM-01、02、07 | 第一方与估算分离、账号/属性/市场/语言/时间口径；Google Ads 只读 GAQL |
| Models/GT | OpenAI、DeepSeek、OpenAI-compatible local | VM-02、07 | BYOK/Credits、固定 Harness Profile |
| Marketplace | Amazon SP-API、Sorftime | VM-07、08 | Seller/市场身份、估算标签、Listing readback |
| Site/Domain | GitHub、WordPress、Shopify、IndexNow、GoDaddy、Cloudflare Registrar（实验） | VM-01、03 | 购买/发布独立审批、在线 Verification |
| Social | Meta、TikTok、X、LinkedIn、Reddit、YouTube | VM-02、04、10、11 | 逐账号 Scope、逐内容审批、平台政策 |
| CRM/Email | HubSpot、Twenty、Chatwoot、Gmail、Outlook、Resend | VM-05、09、10 | Identity、Consent、Suppression、Webhook |
| Partner | Awin、impact.com、CJ、Hartevo Opt-in | VM-06 | Supply Class、动态 Contact Permission、可验证邀请、网络自身结算边界 |
| Creator Hiring & Work | Hartevo Opt-in + Stripe Connect | VM-06 | `campaign`/`continuous_relationship`、可验证 Listing/Invitation、Application、用户 Award、Task/Bounty、真实 Deliverable、评估访问→Review→已验证付款→合同使用权；Funding Reservation 不冒充法定 Escrow |
| Messaging | Slack、Teams、飞书 | VM-10 | 验签、Tenant route、Handoff、最小回复权限 |
| Settlement | Stripe Billing/Connect | VM-00、06、11 | minor units、KYC、接受前禁付、Receipt/reconcile |
| Alternate Settlement | Adyen | 无 live Mission 声明 | `contract_only` |
| Browser | Managed BrowserWorkspace | VM-02、04、06、07 | 用户 Profile、CAS lease、人工接管硬停止 |

## 3. 统一 Adapter

每个 Adapter 按适用范围实现：

```text
probe
begin_auth
refresh
read
prepare_effect
execute
reconcile
verify
handle_webhook
revoke
```

Provider 返回只形成候选事实或 Receipt；它不能直接写 Mission 业务状态。所有 Domain 变化经过 Application Service，所有外部写入经过 Effect Broker。

SIGNAL-01 的 E1 注册表仅绑定四个只读增长信号 Provider 的 `probe`/`read` 元数据：Google Ads 的 OAuth + developer-token 账号探测和只读 GAQL、GSC 的 site/property 查询、GA4 的 property `runReport`、以及 DataForSEO v3 的 Basic-auth live/standard SERP task。DataForSEO 估算、live 结果和 first-party 账号/属性事实必须使用不同的证据分类；标准 task 的 task ID/callback/poll、速率头、费用、freshness 和 durable replay digest 只能形成可审计引用，不能把估算升级为第一方事实。

当前 registry 不授予 `Connected`、Provider receipt、业务验证或 E4 authority；没有真实凭据时，生产 probe 属于 `BLOCKED_ENV`，fixture/component-harness worlds 也不会伪造 live 成功。campaign、budget、conversion upload 等外部写入不在本 Slice 内。

## 4. 标准合同测试

完整 read/write/webhook Adapter 至少运行 37 个场景：Auth 7、Read 7、Write 10、Webhook 7、Data/Security 6。不适用场景要写明原因，不能 `skip`。

E4 再对每个变更的 Provider-Capability 运行五个真实受控场景：成功、最小权限拒绝、撤销/重授权、写入+readback（读能力改为分页/空结果）、`uncertain` reconciliation。

## 5. Creator Work Provider 规则

- Awin/impact/CJ 的既有联盟关系和结算由其网络事实决定，不伪装成 Hartevo 雇佣市场。
- Hartevo Opt-in 承载 Creator Identity、Hiring Offer、Listing/Invitation、Application、用户 Award、Task、Acceptance、Deliverable 和 Review；Stripe Connect 只负责适用的条件付款和 Payout。
- 定向 Invitation 每次执行前重读当前 Contact Permission；审批之后撤回许可必须在网络调用前失败关闭。公开候选没有 Permission 时只能研究。
- Application 必须引用独立验证的 Invitation 或 Listing。用户 Award 绑定唯一申请、Offer digest 和选择证据；Provider 回调、Agent 输出或前端 payload 不能直接制造已雇佣状态。
- “悬赏”是版本化金额合同；若平台没有相应牌照或 Provider 合同，不使用法律意义上的“托管”表述。
- 用户接受的对象是固定 Deliverable digest、里程碑、使用权和验收条款；任何变更使付款审批失效。
- Dispute、chargeback、退款和税务状态保留独立事件，不改写原交付或原付款。

## 6. Browser Fallback

仅在 Provider 条款允许且官方 API 无法完成已授权目标时启用。Browser fallback 必须：

- 使用 project/profile/mission-scoped BrowserWorkspace；
- 通过 Effect Broker；
- CAPTCHA/MFA 时转人工；
- 人工接管后旧 lease 全部失效；
- 保存 semantic snapshot、locator、Receipt 和独立 readback；
- 不开放公网 CDP/debug port。
