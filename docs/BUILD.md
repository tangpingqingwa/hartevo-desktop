# Hartevo Desktop build contract

Status: **Target Contract** (docs-only; this file is not implementation)

This document locks the next Integration sequence: unstick bounded repository
merge trains, then rebuild the product **powered by Cordis**, **all Rust**.
Headings of the form `### PR N: title` are the fleet parser contract. Later PRs
must implement these headings; this PR lands the contract only.

Product semantics remain [PRODUCT.md](../PRODUCT.md). Local bootstrap remains
[DEVELOPMENT.md](../DEVELOPMENT.md). Component ownership remains
[Desktop architecture](architecture/HARTEVO-DESKTOP-ARCHITECTURE.md).
Authority conflicts follow [SOURCE-OF-TRUTH.md](SOURCE-OF-TRUTH.md).
Cordis primer semantics are authoritative concepts, not TypeScript to vendor:

- [Cordis primer](https://deepseek-harness.github.io/deepseek-harness/reference/cordis-primer)
- [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (everything is a plugin; powered by Cordis)

Pinned source provenance for this target contract:

- Cordis: cordiverse/cordis@8cc9e33fab69e2d0476d126baaf2acb24e6a6ab4
  (MIT).
- DeepSeek Harness: deepseek-ai/deepseek-harness@cd5ef8148158c3a752a658978873241fdf8e2bbc
  (MIT).

Hartevo reimplements the pinned primer behavior in Rust. It does not vendor or
run the TypeScript/Node cores, and it does not add a Node/Electron/React/Python
agent core.

The bounded train fallback is [`scripts/ci-merge-train.py`](../scripts/ci-merge-train.py)
and [`.github/policies/branch-ruleset-policy.json`](../.github/policies/branch-ruleset-policy.json).

## Non-goals for this document

- Do not implement the Cordis rewrite here.
- Do not vendor DeepSeek Harness TypeScript or run Node Cordis.
- Do not add a second Electron / React / Python agent core.
- Do not expand `contracts/docs-machine-truth/claims.v1.json` for this file.
  Machine-truth remains bound to `docs/SOURCE-OF-TRUTH.md` and does not scan
  loose prose.

## Locked sequence

### PR 1: land this BUILD.md contract

Docs-only. Land this file and a one-line contract link from SOURCE-OF-TRUTH.
Do not rewrite Rust crates. Do not start PR 2 in the same change.
Do not merge this PR into `main` or by pushing `bootstrap/macos-r0`.
Root `README.md` / `DEVELOPMENT.md` remain Current; they must not be edited in
this PR because repository-root files fail-closed into the full Rust matrix.

### PR 2: Rust Cordis kernel (Context, Service, inject, reversible effect/on)

Reimplement the pinned primer plugin-host and Fiber/runtime semantics in Rust.
This heading is a target contract for later implementation; this docs-only
change does not implement PR 2, N0, or N1.

1. Plugin = a Service object or an opaque repeatable PluginFactory. inject
   declares dependencies, and activation waits until those services are ready.
   The consuming Service.apply(self, ctx) form is an explicit strict one-shot
   compatibility adapter; it cannot claim reload or update parity.
2. Context is the service container: stable ctx.<key> lookups (ctx.tools,
   ctx.llm, ctx.sessions, plus Hartevo ctx.domain, ctx.effect_broker,
   ctx.runtime, ctx.desktop). Plugins look up by key, not concrete imports.
   Provider records keep namespace/key, authorization provider_id, owning Fiber
   uid, and mutable provider generation as separate fields. Ordinary
   registration starts at generation zero; authorized in-place rebind
   increments generation exactly once.
3. The complete target Fiber/runtime has root uid 0, monotonic distinct child
   uids, and states PENDING, LOADING, ACTIVE, FAILED, UNLOADING, and terminal
   DISPOSED. It permits one current transition at a time, retains start
   errors, and prevents work or callbacks after disposal.
4. Missing inject dependencies create a pending Fiber. A repeatable opaque
   PluginFactory is retained and can be invoked once per committed load epoch;
   cloning a factory preserves its opaque identity. Provider-generation refresh
   uses the active owner Fiber uid plus provider generation, not authorization
   provider_id, as its activation fingerprint.
5. Reload/unload, update/restart, terminal child disposal, and reversible
   synchronous/asynchronous lifecycle registrations are part of the complete
   target. Effects have one Fiber teardown owner and idempotent disposal;
   asynchronous cleanup is awaited by the lifecycle transition. The N0 slice
   establishes only the provider/ownership boundary and minimal PENDING/ACTIVE
   activation; N1 owns the remaining lifecycle/effect implementation and its
   race oracles.
6. Load order is dependency-driven, not a hardcoded crate boot sequence.
   Context parent/child ownership and isolated namespaces must not leak
   Hartevo-owned services across an isolate boundary.

### PR 3: typed events with exactly one dispatch mode each

Lock five upstream core dispatch modes. Each event has exactly one mode:

| Mode | Await | Return | Contract |
| --- | --- | --- | --- |
| Emit | no | no | Synchronous observe-only listeners in registration order. |
| Parallel | yes | no | Start all matching listeners, await all, and aggregate every typed cause in registration order. |
| Serial | yes | yes | Give every listener the same original payload, await in registration order, and stop at the first BailOutcome<T>::Bail(_). Never thread a prior return as input. |
| Bail | no | yes | Synchronous first-bailed dispatch over the same original payload; never await a listener. |
| Waterfall | no | yes | Synchronous around-middleware; next delegates and omitting next intentionally short-circuits. |

Serial and Bail use an explicit BailOutcome<T> decision wrapper. The non-bailing
set is exactly Undefined, Null, and False; 0, -0, NaN, the empty string,
true, empty arrays/objects, and opaque object values bail. Do not infer this
rule from Rust bool, Option, emptiness, Default, or general truthiness. A
no-bail/no-listener result is Continue(Undefined).

The current Hartevo transform, where each listener consumes the preceding
listener's result, is not upstream Serial. Rename it to the explicit
Accumulate extension (on_accumulate/accumulate, DispatchMode::Accumulate) and
never count it as one of the five core modes.

Interception and policy use events. Capability calls use service methods.

### PR 4: loader + overlay

Config is interpolated after `inject` on the plugin context. `disabled` is
interpolated from the loader context. An environment overlay selects plugins.
Do not replace this with a hardcoded crate boot list.

### PR 5: map Hartevo surfaces onto Cordis services

Practice mapping, not a second runtime:

- tools pipeline events on `ctx.tools`
- model streams on `ctx.llm`
- live agent coordination on `ctx.agents`
- Hartevo-owned `ctx.domain`, `ctx.effect_broker`, `ctx.runtime`, `ctx.desktop`

Every registration has a disposer. OpenInterpreter remains an optional runtime
plugin behind the existing adapter. It never owns Mission, Truth, or Effect.

### PR 6: Cordis-hosted Rust agent loop; OpenInterpreter as optional plugin

Replace OpenInterpreter-as-the-loop with a Cordis-hosted Rust agent loop.
Keep the existing adapter as an optional runtime plugin. Do not let the child
process own Domain Kernel facts.

### PR 7: keep Domain Kernel invariants under the new host

Consent, approval, Receipt ≠ Verification, SQLCipher, Eval gates, and
local-first remain in force. Cordis is the plugin host, not a license to
bypass them. Architecture, RFC, quality contracts, and catalogs stay
authoritative for those invariants.

## Merge-train / branch merges

Default Integration branch is `bootstrap/macos-r0` (repository default).
`main` exists and is protected, but it is not the merge-train base.

GitHub hosted merge queue is `BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER` (personal
account cannot host `merge_queue`). Fallback is the bounded repository merge
train:

- Script: [`scripts/ci-merge-train.py`](../scripts/ci-merge-train.py)
- Max **4** independent **root** PRs
- Candidates must be Open + Ready (not draft), based on `bootstrap/macos-r0`,
  current head, required checks green (train-only governance check excluded
  by policy), not stacked
- Composite `merge-train/*` PR runs the full `ubuntu-24.04` + `macos-15`
  matrix, then a normal protected merge (merge commit; squash/rebase/auto-merge
  are disabled)
- No bypass, never direct-push `bootstrap/macos-r0`
- Historical receipts live under `.github/merge-train/manifests/`. There is
  no live `current.json`; open GitHub PRs are the only current-train pointer.
  Local `merge-train/20260816-0452` is stale (`origin` gone).

Integration Manager sequence after this docs PR:

1. Undraft and rebase eligible roots onto current `origin/bootstrap/macos-r0`.
2. `python3 scripts/ci-merge-train.py prepare` with 1–4 independent ready roots.
3. `python3 scripts/ci-merge-train.py publish` (one normal push, one non-draft
   train PR). Do not merge from the publisher.
4. Merge the composite only when the full matrix and governance checks are
   green, using the normal merge method. Do not squash.

### Live 2026-08-24 train board

| PR | State | Blocker |
| --- | --- | --- |
| [#116](https://github.com/tangpingqingwa/hartevo-desktop/pull/116) HLAB-02 | OPEN draft, BEHIND, MERGEABLE, **not** in a merge queue | Must leave draft and rebase onto current bootstrap before it can ride a train |
| [#119](https://github.com/tangpingqingwa/hartevo-desktop/pull/119) SCHED-03 runtime fence | OPEN draft, CONFLICTING, stacked on #110 SCHED-02 | Cannot enter a train until #110 is merged and this is retargeted/rebased to bootstrap with a clean tree |
| [#110](https://github.com/tangpingqingwa/hartevo-desktop/pull/110) SCHED-02 | OPEN draft, BEHIND, MERGEABLE | Land this root before retargeting #119 |
| [#118](https://github.com/tangpingqingwa/hartevo-desktop/pull/118) Shopify provenance | CLOSED, CONFLICTING | Dead; do not revive in this docs PR |
| [#224](https://github.com/tangpingqingwa/hartevo-desktop/pull/224) attribution evidence query | OPEN ready, MERGEABLE, BEHIND, required checks green | Eligible root candidate once it is current on bootstrap |
| Train 100/107/108/115 | MERGED 2026-08-17 | Local `merge-train/20260816-0452` is stale (`origin` gone) |

Next Integration Manager cuts after this docs PR: undraft+rebase #116 onto
current bootstrap; land #110 then retarget/rebase #119; do not revive #118;
when 1–4 independent ready roots exist, prepare a new `merge-train/*` PR.

## Powered by Cordis, all Rust

Cordis (`cordiverse/cordis`) is TypeScript. Hartevo must **reimplement primer
semantics in Rust**. Do not vendor DeepSeek Harness TS. Do not add
Node/Electron/React/Python agent core.

OpenInterpreter remains an optional runtime plugin behind the existing
adapter; it never owns Mission / Truth / Effect. Domain Kernel remains the
only business fact source. Effect Broker remains the only external-write
path. Receipt is not Verification.

## Authority

| Topic | Authority |
| --- | --- |
| Users, purpose, anti-references | [PRODUCT.md](../PRODUCT.md) |
| macOS bootstrap and local gates | [DEVELOPMENT.md](../DEVELOPMENT.md) |
| Component ownership and security invariants | [architecture](architecture/HARTEVO-DESKTOP-ARCHITECTURE.md) |
| Docs conflict rules | [SOURCE-OF-TRUTH.md](SOURCE-OF-TRUTH.md) |
| Bounded merge train | [`scripts/ci-merge-train.py`](../scripts/ci-merge-train.py) |
| Hosted queue blocked + train policy | [branch-ruleset-policy.json](../.github/policies/branch-ruleset-policy.json) |
| Cordis concepts | [primer](https://deepseek-harness.github.io/deepseek-harness/reference/cordis-primer) |
| Plugin-host practice | [deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) |
