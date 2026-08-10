# Hartevo Desktop 开发与 macOS Bootstrap

- 状态：**Current（工程交接入口）**
- 适用：从一台全新 macOS 机器接手 Hartevo Desktop，并完成首个 Bootstrap R0 PR
- 最后审查：2026-08-10

## 1. 先确认仓库所处阶段

远程仓库当前已经包含产品、交互、架构、上游能力引入和质量合同，以及可直接打开的交互原型；工程代码尚未开始。当前根目录没有 `Cargo.toml`、`rust-toolchain.toml`、`Dioxus.toml` 或可执行的 `hartevo eval`。

因此：

- 现在可以在新 Mac 上克隆仓库、阅读唯一事实源、打开原型并创建 Bootstrap 分支；
- 现在不能执行 `cargo run`、`dx serve` 或 Eval Runner；
- 下文标记为“Bootstrap R0 合并后”的命令是首个工程 PR 的验收目标，不是假定它们已经存在。

不要从旧目录、聊天附件或其他 Hartevo 仓库复制历史代码。当前远程仓库是 Desktop 产品线唯一工程起点。

## 2. 新 Mac 的最小环境

### 2.1 Apple 开发工具

安装 Command Line Tools：

```bash
xcode-select --install
xcode-select -p
git --version
clang --version
```

Dioxus Desktop 官方说明 macOS 本地开发没有额外平台依赖。首个 Shell 与本地调试只要求 Rust 工具链和正常可用的系统 WebView。进入签名、公证、安装包和自动更新阶段前，再安装完整 Xcode 并单独记录 Apple Developer 身份与发布流程；不要把个人签名凭据提交到仓库。

### 2.2 GitHub 私有仓库身份

`tangpingqingwa/hartevo-desktop` 是私有仓库。先在 GitHub CLI 或 SSH 中完成有权限账号的认证。推荐使用 GitHub CLI：

如果新 Mac 尚未安装 `gh`，按 GitHub CLI 官方安装说明安装；Homebrew 只是可选安装方式，不是 Hartevo 构建依赖。

```bash
gh auth login
gh auth status
gh repo clone tangpingqingwa/hartevo-desktop
cd hartevo-desktop
```

如果使用 SSH，可以改为：

```bash
git clone git@github.com:tangpingqingwa/hartevo-desktop.git
cd hartevo-desktop
```

### 2.3 Rust 与 Dioxus

使用 Rust 官方 `rustup`，不要使用系统包管理器维护另一套并行 Rust：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup --version
cargo --version
```

当前固定审查的 OpenInterpreter 提交使用 Rust `1.95.0`，组件为 `clippy`、`rustfmt` 和 `rust-src`。Bootstrap R0 必须在仓库根目录提交自己的 `rust-toolchain.toml`；在该文件合并前，可先安装兼容工具链用于上游验证：

```bash
rustup toolchain install 1.95.0 --component clippy --component rustfmt --component rust-src
```

当前采用 Dioxus `0.7.10`。CLI 也必须固定版本，不能静默跟随最新 alpha 或未来 minor：

```bash
cargo install dioxus-cli --version 0.7.10 --locked
dx --version
dx doctor
```

## 3. 克隆后的完整性检查

```bash
git switch main
git pull --ff-only origin main
git status --short
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

验收条件：

- `git status --short` 没有输出；
- `git rev-parse HEAD` 与 `git ls-remote` 输出的远程 `main` SHA 相同；
- `README.md`、`PRODUCT.md`、`DEVELOPMENT.md`、`docs/` 与 `prototype/` 均存在。

直接打开当前冻结原型：

```bash
open prototype/index.html
```

若浏览器限制 `file://` 且机器已经安装 Python 3，可在仓库根目录临时执行：

```bash
python3 -m http.server 8000 --directory prototype
open http://127.0.0.1:8000
```

Python 这里只是可选的静态原型预览手段，不是 Hartevo 产品运行时或出货依赖。

## 4. 开工前只读这些事实源

按 [README](./README.md) 的“开始阅读”顺序完成阅读。发生冲突时遵守 [事实源规则](./docs/SOURCE-OF-TRUTH.md)，尤其注意：

- OpenInterpreter 是 Agent Runtime 与 App Server 基座，不拥有 Hartevo 业务事实；
- Hartevo-owned 实现使用 Rust + Dioxus，不引入第二套 Electron/React/Python Agent Core；
- Mission、Task、Truth、Work Product、Effect、Receipt、Verification 和 Outcome 由 Domain Kernel 持有；
- 连接成功不等于允许发布、发送、花费或写 CRM；所有外部动作经过 Effect Broker；
- Hermes、PenguinHarness、Ego Lite 和 Prime Agent 只按各自 Intake 文档吸收机制，不复制其运行时或绕过 Hartevo 权限边界；
- AI CSS 只用于研究交互问题；不得复制付费源码、CSS、SVG 或高度近似实现。

## 5. 艰难问题与第一性原理

> 遇到艰难险阻，不要受限；从第一性原理出发，解决难关，创新架构。

这里的“不受限”是指不受既有实现、上游习惯、框架默认路径和历史偶然选择束缚。遇到关键难题时，不能只堆超时、重试、兼容分支或临时胶水，也不能因为某个开源基座没有提供能力就降低 Hartevo 的产品目标。按以下顺序处理：

1. 重新写出用户最终要达成的结果，以及不能破坏的领域、安全和权限不变量；
2. 用最小可复现 Case、Trace、性能数据或协议记录描述真实失败，不凭印象争论；
3. 区分硬约束与假设：操作系统、协议、物理资源和已验证法规是约束；上游目录、当前抽象、流行做法和“以前一直这样”只是候选方案；
4. 同时比较修复现有实现、替换抽象、拆分进程/状态所有权、重写 Rust 组件和设计新架构，而不是只优化眼前代码；
5. 在隔离分支做最小 Spike，用 Mission 完成度、安全、恢复、延迟、成本和可维护性共同评估；
6. 把结论写入 RFC/架构文档，保留被否决方案、迁移与回滚路径，并把故障固化为永久 Contract Test 或 Eval Fixture；
7. 如果证据证明当前子系统违反第一性原则或无法达到产品合同，应主动重构边界，不能因沉没成本继续堆补丁。

以下边界不可用“创新”绕过：用户 Consent 与 Approval、Effect Broker、安全与隐私、许可证和来源历史、跨项目隔离、确定性业务状态、私有 Benchmark 隔离及 Release Gate。真正的创新必须扩大产品能力，同时让权限、证据和失败恢复更加清晰。

## 6. 首个分支：Bootstrap R0

从同步后的 `main` 创建独立分支：

```bash
git switch -c bootstrap/macos-r0
```

Bootstrap R0 只负责建立可重复工程地基，不实现大量业务模块。它至少交付：

1. 根目录 `rust-toolchain.toml`、Cargo workspace、`Cargo.lock`、格式化与 lint 策略；
2. 独立的 `hartevo-rs/` workspace/zone，以及最小 `desktop`、`domain-kernel`、`runtime-adapter`、`effect-broker` crate；
3. Dioxus Desktop Shell、Hartevo 品牌 token、原型主框架和一个无网络的启动 smoke test；
4. OpenInterpreter 上游 remote、来源 manifest、Apache-2.0 `LICENSE`/`NOTICE`、固定 release/commit 和可审计历史；
5. App Server stable schema snapshot、digest、initialize/stream/interrupt/approval/resume 契约测试；实验 API 必须单独标注，不能混入稳定协议；
6. macOS CI：format、clippy、unit test、schema drift 和 Desktop smoke；
7. 本地配置示例与 Secret 规则；真实 Token、Cookie、OAuth refresh token 和签名证书不得进入 Git；
8. 更新本文件，把下节目标命令改成实际已验证命令并记录 Apple Silicon/Intel 验证状态。

### 6.1 OpenInterpreter intake 的第一步

只添加和核验上游，不在命令行临时复制源码快照：

```bash
git remote add openinterpreter-upstream https://github.com/openinterpreter/openinterpreter.git
git fetch openinterpreter-upstream --tags
git cat-file -t 984acc698cd038885ecb0b82721402b01e11a5ad
git tag -l rust-v0.0.34
```

审查基线是提交 `984acc698cd038885ecb0b82721402b01e11a5ad`，公开稳定参考是 `rust-v0.0.34`。二者不自动等价于最终 R0 pin；PR 必须先比较 App Server schema、Harness 行为、安全测试和 macOS 构建。具体采用保留完整历史的 subtree、vendor zone 或其他可审计方式，应在 Bootstrap PR 中显式说明；禁止无来源复制和 `--squash` 后丢失升级依据。

## 7. Bootstrap R0 合并后的目标命令

以下命令是首个工程 PR 必须使其成立的验收合同：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
dx doctor
dx serve --desktop
```

OpenInterpreter zone 的最小协议验证目标为：

```bash
cargo run -p codex-app-server -- --stdio
cargo run -p codex-app-server -- generate-json-schema --out <schema-dir>
```

最终路径和 workspace 参数以 Bootstrap PR 实际导入结构为准。合并前必须由 CI 和一台干净 macOS 机器复跑，不能只在开发者已有环境中成功。

## 8. 分支与提交纪律

- `main` 始终保持可克隆、文档无冲突和已声明命令可复现；
- 上游升级使用 `upstream-intake/<date>-<sha>`，不直接在 `main` 拉取；
- 功能分支以 `feature/`、`fix/`、`eval/` 或 `docs/` 开头；
- 不提交 `.env`、账号数据库、浏览器 Profile、下载文件、Eval 私有 Holdout 或生产 Replay 原文；
- 每个“完成”声明必须链接代码、测试、Commit 和可重放证据；Target Contract 本身不是完成证明。

## 9. 官方依据

- [Apple：安装 Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools)
- [GitHub CLI 安装说明](https://cli.github.com/manual/installation)
- [Rust/Cargo 官方安装说明](https://doc.rust-lang.org/stable/cargo/getting-started/installation.html)
- [Dioxus 0.7 Getting Started 与 macOS 依赖](https://dioxuslabs.com/learn/0.7/getting_started/)
- [Dioxus v0.7.10](https://github.com/DioxusLabs/dioxus/releases/tag/v0.7.10)
- [OpenInterpreter Rust v0.0.34](https://github.com/openinterpreter/openinterpreter/releases/tag/rust-v0.0.34)
- [固定 OpenInterpreter 审查提交](https://github.com/openinterpreter/openinterpreter/tree/984acc698cd038885ecb0b82721402b01e11a5ad)
