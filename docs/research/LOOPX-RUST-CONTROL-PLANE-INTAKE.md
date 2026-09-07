# LoopX 长期任务控制面：Rust 接入

- 状态：**Current（Rust 控制内核、SQLCipher、Application 与 Cordis 接入）；完整领域能力覆盖仍属 Target Contract**。
- 审查日期：2026-09-07。
- 上游：[huangruiteng/loopx](https://github.com/huangruiteng/loopx)，`pyproject.toml` 版本 `1.0.0`，固定提交 [`c19f82f7e1372364b389c09799b1653f087ba4a3`](https://github.com/huangruiteng/loopx/tree/c19f82f7e1372364b389c09799b1653f087ba4a3)。Hartevo 基线为 Integration `bee1821926cae8bcacfeb16120f74ba0191a84da`。
- 来源许可证：该提交的 [`LICENSE`](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/LICENSE) 为 Apache-2.0；[`NOTICE`](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/NOTICE) 保留 v0.4.7 及以前的 MIT 历史。本次按公开行为合同重新实现 Rust，没有复制或运行上游 Python/TypeScript，也没有安装 LoopX 服务。

## 1. 引入依据

LoopX 最有价值的部分是持久控制面：跨轮次保存目标、工作边界、认领、人工决策、证据、配额与交接。`should-run` 是决策编译器，不能简化成“还有余额且还有待办”。已审查的主要依据：

- [架构](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/docs/architecture.md)：Agent → Capability → Provider，Kernel 接受经过验证的 transition；Kanban 是投影。
- [Quota](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/control_plane/quota/should_run.py)：身份、目标边界、人工决策、能力、工作区、frontier、interaction contract 和调度提示。
- [认领](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/control_plane/coordination/todo_claim.ts)与[租约](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/control_plane/work_items/task_lease_acquire.ts)：注册 peer、actor/owner 一致、写范围冲突、generation fencing。
- [结算](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/control_plane/turn_driver/settlement.ts)：validation → durable writeback → quota spend；恢复不重复已提交阶段。
- [Todo 合同](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/docs/project-agent-todo-contract.md)和[完成语义](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/control_plane/todos/completion_state.ts)：人工决策必须具体且有范围；关闭待办不等于完成目标。

Hartevo 已有 Mission/Operating Contract、Checkpoint DAG、Context Workspace/Worker、Effect Broker、SQLCipher、Scheduler 和 Cordis。本次复用这些所有者，没有建立独立 `.loopx/` 事实源、第二套业务 Goal 或第二个模型运行时。

## 2. 已实现的 Rust 映射

| LoopX 考虑的事情 | Rust 接入 |
| --- | --- |
| 长期目标、权限与验收 | 复用 Mission/OperatingContract；MissionLoop 绑定 Tenant/Project/Mission，只有原 Mission 终态才能返回 Terminal。 |
| 每轮决策 | `MissionLoop::should_run` 返回 `LoopDecision`：模式、候选、用户通知、`LoopWake`；只读，无模型调用。 |
| 有限工作、依赖、优先级 | `LoopTodoSpec` 为现有 Task 内的切片；普通推进和监控必须绑定真实 Task/Capability。Repair/Replan 可以是本地控制工作。依赖只能引用已有工作。 |
| peer 身份与能力 | `LoopPeer` 注册 + 每轮 `LoopHost` 声明 + Mission 合同同时满足；注册不授予 Effect 权限。 |
| 认领、租约、写冲突 | SQLCipher `BEGIN IMMEDIATE` 内重新决策和 CAS；actor 必须匹配 owner，租约上限 15 分钟，相对写路径按路径段检查重叠。 |
| 软建议与硬限制 | `decision_for_todo` 可选择优先建议之外的合法 Todo；建议顺序不成为权限。 |
| 人工协作 | `LoopUserGate` 必须有具体 question，范围为 Mission、Agent、Todo 或层级 Decision；局部 gate 不阻塞独立切片。通知发给同一 Mission operator，按当前问题集合摘要去重：相同集合共享确认，不同集合互不覆盖，解决或重新打开问题只影响相关通知。配置的 operator 才能关闭 gate、调配 quota、暂停和批准恢复。 |
| 暂停、改向 | Pause、降低配额、Steer 撤销当前代际；未确定结果保留为 Uncertain。持久用户 Conversation 摘要与 Operating Contract 共同形成 claim authority fence。 |
| 配额与防空转 | 认领预留 slot，验证写回后消费。NoProgress 不扣配额，连续无进展触发 Repair；每个 Repair/Replan 切片自身也有持久无进展次数上限，耗尽后等待新修复计划或状态变化。 |
| 监控 | 无写范围的 Monitor 保留 target digest、due/cadence/expiry 与上次摘要；合并错过的 tick；首次基线和未变化时静默，变化才通知，监控不消费推进 slot。 |
| 证据与交接 | Progress 必须引用当前 Mission 内 Confirmed、claim 开始后观察到、未被其他结算接受的 Evidence。`MissionLoopHandoff` 从数据库重建目标、non-goals、下一步、gate、最近 32 条摘要与 claim。 |
| 原子结算 | 同事务提交切片状态、accepted evidence、quota、摘要、operation receipt 和 Event/Outbox。原证据由既有 Application 命令持久化，不把模型回复或 Provider Receipt 直接当证据。 |
| 去重与恢复 | operation id 绑定完整请求摘要；同请求回放只读，换内容复用 id 被拒绝。Claim 与 BeginExecution 分开持久化，重复 dispatch 被抑制。 |
| 写回后崩溃 | `ReconcileSettlement` 在 operator 独立 readback 后用原 claim/证据补结算，不再次调用 host；来源或 steering 改变则拒绝。`ReconcileRetry` 另需证明可安全重试。 |
| 运行时 | `run_mission_loop_slice` 只调用一个既有 runner，dispatch 提交后再次用同一次最新 snapshot 检查 Task 可执行性，关闭的 Task 不进入 callback；`bind_cordis_mission_loop_guard` 接入真实 `agent/pre-step`，每步重读 SQLCipher，读失败、锁占用、暂停、过期、改向均拒绝下一模型步骤。 |
| 桌面与隐私 | `MissionProjection.loop_accounting` 和既有 Agent Operations 配额区展示真实消费、预留、待办、gate、已持久标记 Uncertain 的计数；自然过期和 authority 变化是否需要核对，以当前 `LoopDecision.reconciliation_required` 为准，账本计数不代表执行许可。目标、问题、工作区、工作标题不进入 Event/Outbox 或 handoff Debug。 |

代码入口：

- [Domain 类型](../../hartevo-rs/domain-kernel/src/mission_loop/mod.rs)、[决策](../../hartevo-rs/domain-kernel/src/mission_loop/decision.rs)、[转换](../../hartevo-rs/domain-kernel/src/mission_loop/transition.rs)。
- [SQLCipher v52](../../hartevo-rs/storage/src/mission_loop_store.rs)：`mission_loops`、`mission_loop_operations`，带 FK、唯一键、大小约束、摘要核对和 schema 验证；既有 v51 先做加密备份再事务迁移。
- [Application](../../hartevo-rs/application/src/mission_loop.rs)、[Cordis guard](../../hartevo-rs/application/src/mission_loop_cordis.rs)、[Desktop](../../hartevo-rs/desktop/src/agent_operations.rs)。

## 3. 调用顺序

1. 对**已有 Mission** 调用 `configure_mission_loop`，显式给出 operator、推进额度、并发、lease 和无进展上限；重复配置不能重置账本。
2. 经 `apply_mission_loop_command` 注册 peer、登记真实 Task 切片与具体 gate。调用方身份由可信 Application/host adapter 提供，不能把模型传入的 `Operator` 字段当作用户认证。
3. 调用 `mission_loop_decision`。`LoopWake::Now` 进入候选，`At` 指示下次观察时间，`OnStateChange` 不应轮询模型，`Stop` 停止自动安排。提示不是租约，执行前必须重新认领。
4. `run_mission_loop_slice` 接收可替换 runner。runner 使用已有 Cordis/Capability/Application 写入证据；monitor runner 只读。超过单次 lease 的手动执行应 Heartbeat，并使用返回的新 claim。
5. Cordis runner 在对应 Agent lifecycle 安装 `bind_cordis_mission_loop_guard`，reader 使用同一加密数据库的专用连接；guard 跟随同一执行代际的持久续租，拒绝替换 claim，Task 关闭后拒绝继续模型步骤。执行返回 typed `LoopTurnResult`，Application 用最新续租 proof 结算。
6. 重启先读 snapshot/decision。Uncertain/过期 claim 先独立 readback，再选择 `ReconcileSettlement` 或 `ReconcileRetry`；“进程没了”不代表没有执行过。

这是显式配置的 Application 接入。现有普通 Mission 的启动行为保留；没有给已有 Mission 默认开启无限自动运行，没有自动配置定时器或外部账号。Cordis guard 是可安装入口，尚未安装它的历史宿主路径不能宣称已经受此 gate 控制。

## 4. 上游 20 个内置领域能力

固定提交的 [Capability catalog](https://github.com/huangruiteng/loopx/blob/c19f82f7e1372364b389c09799b1653f087ba4a3/loopx/capabilities/catalog.py) 包含以下 20 项。表内是 Rust 归属和后续适配判断，**不是 20 个生产 handler 已完成**；实际可运行状态仍以 Hartevo Catalog 和二进制注册为准。

| 上游能力 | Hartevo 归属与后续边界 |
| --- | --- |
| `issue-fix` | Github work connector、WorkProduct、Evidence、Review；补 issue→patch→check 的领域协议。 |
| `change-quality-qualification` | Eval/质量门禁绑定最终源码版本；不能用模型评分决定发布。 |
| `integration-branch-reconcile` | 现有仓库治理/merge train；不变成通用 Kernel 的 merge 权限。 |
| `repository-change-window` | Context Workspace + claim/write scopes；已有范围冲突保护，完整 Git 适配待实现。 |
| `pull-request-review` | Github review connector、evidence/gates；审批和合并保留现有治理。 |
| `benchmark-toolkit` | Eval/Dataset registry；保持 dev/held-out 与样本外边界。 |
| `decision-context` | Domain Evidence/Truth + Context Fabric，按来源版本重建上下文。 |
| `project-skill-delivery` | Catalog/plugin lifecycle，保留安装、版本、scope 与签名边界。 |
| `material-lifecycle` | 加密 Context CAS、WorkProduct、deletion propagation，不另建明文材料库。 |
| `agent-turn-recall` | 持久 Cordis Session、Runtime evidence、Context continuation；transcript 不等于事实。 |
| `semantic-preference` | Context Fabric 显式偏好，不能扩大 Operating Contract。 |
| `reward-memory` | Candidate learning + Eval + 签名晋升；本次未接 Reward Memory provider。 |
| `periodic-report` | Scheduler + monitor/changed notification + receipt；渠道投递仍需 provider 适配。 |
| `content-ops` | 现有内容/渠道/WorkProduct 流程；发布经过 Effect Broker。 |
| `value-connectors` | Capability Gateway、readiness、Outcome；可连接不代表价值已验证。 |
| `explore` | 研究切片、证据、依赖、Replan；假设和实验谱系仍需领域模型。 |
| `deep-research` | 研究 Capability、来源 Evidence、报告 WorkProduct；补引用和来源完整性验证。 |
| `public-safe-outbound` | 现有隐私边界和 Effect Broker，通知不能泄露私有正文、路径、密钥。 |
| `connector-registry` | 复用 Capability/Provider Catalog 和 plugin runtime。 |
| `reliability-diagnostics` | Runtime Recovery、durable history、health；诊断不等于修复证据。 |

上游 Codex/Claude/OpenCode/Pi/DSH facade、Python CLI、Node Effect core、Web Dashboard、Lark Kanban 不直接移植。Hartevo 使用 Rust Application、Cordis、Dioxus 和 provider 层，按 outcome 验收，不按 CLI 数量宣称同等覆盖。

## 5. 验证和限制

```sh
cd hartevo-rs
cargo test -p hartevo-domain-kernel -p hartevo-storage -p hartevo-application --lib --locked
cargo clippy -p hartevo-domain-kernel -p hartevo-storage -p hartevo-application -p hartevo-desktop --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

测试依据：[Domain 行为矩阵](../../hartevo-rs/domain-kernel/src/mission_loop/tests.rs)、[Storage 并发/重开/故障注入/迁移](../../hartevo-rs/storage/src/mission_loop_store_tests.rs)、[Application 与真实 Cordis pre-step](../../hartevo-rs/application/src/mission_loop_tests.rs)。

2026-09-07 本机验证记录（macOS，Rust 1.95.0；完整回归后，审查修复按影响范围复测）：

| 检查 | 结果 |
| --- | --- |
| Domain Kernel 完整 lib 回归 | 163 passed，0 failed。 |
| Storage 完整 lib 回归 | 214 passed，0 failed；包含旧版本迁移与并发属性测试。 |
| Application 完整 lib 回归 | 152 passed，0 failed，2 个既有实机测试 ignored。 |
| 审查修复后的最终专项回归 | 30 passed：Domain 16、Storage 7、Application/Cordis 7，包含跨连接 Task 关闭后的 callback 抑制与 Repair/Replan 无进展上限。 |
| 四个受影响 crate 的 all-targets Clippy | `-D warnings` 通过，包含 Desktop 类型检查。 |
| 格式与文档机器事实 | `cargo fmt --all -- --check` 与 `check-docs-machine-truth.sh verify` 通过。 |

两个忽略的既有 Application 测试分别要求固定 OpenInterpreter 包/隔离运行目录，以及可启动的 Chrome；没有将它们计作通过。文档门禁保持 `releasePassed=false`，本次没有提升生产发布或 Mission E3 状态。

本地验证证明控制面行为，不代表真实付费模型、生产 provider、多设备同步、无人值守长时间运行或 E3/E4 已证明。operation 回执永久保留；热历史保留 32 条，Todo/gate frontier 上限 512，peer 上限 64。历史 frontier 归档、跨 Cell lease、默认 OS 唤醒、配置/决策编辑 UI、通用 `.loopx` 导入、上游完整领域协议仍未实现。后续扩展必须保持 Mission/Truth/Effect 所有权和来源/证据边界。
