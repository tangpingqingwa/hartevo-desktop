# DeepSeek Harness 0.1.3 → Rust 核心更新

状态：**Current**。本文件记录已采用的行为与保留的边界，不声明整个上游功能或文件格式兼容。

## 固定来源

- 审查日期：2026-09-07。
- 上游：[deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)，MIT。
- 原参考版本：`0.1.2-alpha.1`，`cd5ef8148158c3a752a658978873241fdf8e2bbc`（2026-08-27）。
- 本轮参考版本：[`0.1.3-alpha.1`](https://github.com/deepseek-ai/deepseek-harness/blob/d347e703908d0406b7a7ef80e3a0e594d86b2215/apps/cli/package.json)，`d347e703908d0406b7a7ef80e3a0e594d86b2215`（2026-09-04）。
- [版本比较](https://github.com/deepseek-ai/deepseek-harness/compare/cd5ef8148158c3a752a658978873241fdf8e2bbc...d347e703908d0406b7a7ef80e3a0e594d86b2215)包含 984 次提交（包括合并提交）。这些提交不是 984 项 Hartevo 能力。
- 本轮根据公开契约独立实现 Rust；没有加入 TypeScript、Node、Python 或新的 Agent Runtime。来源许可证见[固定版本 LICENSE](https://github.com/deepseek-ai/deepseek-harness/blob/d347e703908d0406b7a7ef80e3a0e594d86b2215/LICENSE)。

## 关键变化与采用决策

| 上游变化 | Hartevo 处理 | 当前证据入口 |
| --- | --- | --- |
| 跨进程 Session 写入所有权（上游 PR #3362） | 新增每个数据库、每个 Session 的系统独占锁；从认领持续到 owning `ProjectStore` 释放，不使用到期抢占 | `storage/src/cordis_session_ownership.rs`、真实子进程崩溃测试 |
| 恢复和发布前取得写入权 | 桌面启动先认领完整恢复集合，再修复中断尾部、发布 Session；新回合在建立 Session、调用模型前认领；Runtime transcript 也走相同入口 | `ProjectStore::load_owned_session_checkpoints`、`DesktopSessionPersistence::claim_write` |
| 持久化与只读观察分离 | 只读 checkpoint 查询不取得写入锁；SQLite 事务继续保护日志前缀一致性；一个 Session 被占用不阻止另一个 Session 的写入 | storage 多连接回归 |
| 取消生成保留可见前缀 | 取消优先于下一个已就绪 chunk；终结前保存已收到的非空 text/reasoning，保留关闭块的权威内容和原始 chunk 来源；未执行的工具调用不进入模型历史 | `agent.rs`、`agent_loop.rs` 取消/恢复回归、桌面 SQLCipher 重开回归 |
| Provider 失败与用户取消区别处理 | Provider 的 error/aborted 保留诊断、usage 与原始流，不伪造成功消息；生命周期取消保留可见正文，回合仍是 Aborted | 既有 provider failure 回归与新增 cancellation 回归 |
| 格式世代拒绝与迁移不能猜测 | Storage 在解码事件、恢复或写入前拒绝不支持的版本，保留未知记录原样；不把上游 JSONL v2 当成本地格式 | `session_future_format_is_refused_before_unknown_events_or_repair` |
| 上游 v2 内嵌 assistant stream / log-only attempt（PR #3400） | 已采用本轮相关的取消结算语义；本地仍使用有类型的原始 chunk 日志、精确来源序号与 SQLCipher，不进行事件删并或序号重排 | `SESSION_FORMAT_VERSION`、`SessionSurfaceIntent`、`SessionLog::restore` |
| 子代理继承边界与自有 descriptor 分离 | 现有 Rust 子代理的继承前缀与 descriptor 追加保持分离；不改写旧 seed length 或引用 | `SessionStore`、`subagent.rs` 与既有 subagent 测试 |
| Web 上传、搜索、链接、Python SDK 与代理配置更新 | 不引入上游 Web/SDK 运行时；现有 File Broker、Provider adapter 和权限边界继续由各 Rust owner 管理 | 不是本轮新增实现或兼容性声明 |

上游写入锁的权威实现在 [`lease.ts`](https://github.com/deepseek-ai/deepseek-harness/blob/d347e703908d0406b7a7ef80e3a0e594d86b2215/packages/session/session-persistence-jsonl/src/lease.ts)；其 Session persistence seam README 仍有仅进程内所有权的旧描述，本轮依据当前实现及测试核对。取消结算参考 [`assistant-stream.ts`](https://github.com/deepseek-ai/deepseek-harness/blob/d347e703908d0406b7a7ef80e3a0e594d86b2215/packages/core/agent-loop/src/assistant-stream.ts) 和 [`assembler.ts`](https://github.com/deepseek-ai/deepseek-harness/blob/d347e703908d0406b7a7ef80e3a0e594d86b2215/packages/llm/llm/src/assembler.ts)。

## 写入所有权与恢复

SQLite 的短写事务只能阻止同时提交，不能阻止两个 Agent 在两次提交之间分别执行同一个会话。新锁将所有权延长到活跃 writer 的整个生命周期，并保持数据库的普通读取可用。

锁保存在数据库旁的 `.cordis-session-locks` 私有目录，文件名为 Session ID 的 SHA-256，文件内容为空。POSIX 目录/文件权限分别为 0700/0600，锁文件不得是符号链接。Windows 使用 Rust 标准库系统文件锁，并在持有期间禁止删除/重命名锁文件。正常释放不删除锁文件。

POSIX 每次写入前核对当前路径与已锁定 inode。路径消失或被替换会永久使该 writer 失效；恢复原路径也不能让旧内存重新获得权限。系统在进程退出或崩溃时释放锁，没有心跳文件、PID 猜测或租约过期抢占。保证针对支持系统文件锁、使用本协议的本地数据库进程；升级时需关闭仍运行旧写入实现的应用。

恢复先在短 SQLite 事务内读取一致集合、取得所有权。任一 Session 已被占用时，本次新取得的其他锁一起释放，尚不修复或发布会话。成功恢复后，这些锁随桌面持有的 `ProjectStore` 保留；当前桌面会加载全部保存的会话，因此另一个桌面进程不能同时恢复这批会话。

同一桌面刷新同一数据库时复用原持锁连接，重新校验当前 durable prefix，不争抢自身锁或提前释放所有权。生成已有合法 Finish 后若 transport 仍等待 EOF，随后取消会复用已有结束记录并保存正文，不追加第二个 Finish。

## 兼容与回退

数据库 schema 仍为 52，本地 Rust Session 格式仍为 0。没有重写已提交事件，没有丢弃原始 token 边界、时间戳、usage 或 replay metadata，没有更改 Domain/Effect 的权限与事实归属。

上游 JSONL v2 的导入/导出、压缩 stream settlement、历史世代迁移和 Web transient-frame 协议尚未实现。它们不能通过改一个版本号宣布兼容。若随后实现基数变化迁移，必须完整校验源、映射所有 provenance/compaction/seed 引用、保留源 artifact，并验证派生消息一致性；本轮拒绝未知版本，避免错误解释这些记录。

回退本轮代码前关闭所有新旧 writer。空锁文件可保留；不能通过删除活跃锁文件解除占用。不存在需要降级的 schema 或已迁移历史。

## 验证入口

- `cargo test -p hartevo-storage --locked --lib cordis_session_store`：不可变 checkpoint、版本拒绝、跨连接/跨进程竞争、崩溃释放、占用时恢复回滚、inode 替换与符号链接拒绝。带 ignore 的 child fixture 由真实崩溃测试显式启动，不是跳过崩溃验证。
- `cargo test -p hartevo-cordis --locked --test agent_loop`：取消、原始流、provider failure/retry、工具排序和回合边界。
- `cargo test -p hartevo-desktop --locked --lib cordis_host::tests`：桌面绑定、恢复、模型前认领、取消正文跨 SQLCipher 重开。
- `cargo fmt --all --check` 与相关 Rust crate 的 `cargo clippy --all-targets --locked -- -D warnings`。

上述命令是可复现验证入口；实际执行结果以本轮 PR 的当前提交和 CI 为准，不构成生产模型、Windows 实机或 Release 验收声明。
