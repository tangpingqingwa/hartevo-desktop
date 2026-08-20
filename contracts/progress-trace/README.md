# Durable progress trace contract

This directory is the issue #44 support-only Eval oracle for generic durable progress and terminal sequencing. It is separate from platform North Star issue #52 and must not block or upgrade that platform work.

The contract is Eval-only (`authority=eval_only_no_production_authority`) and permanently non-release-bearing (`releaseEligible=false`). It does not change Desktop, Application, Runtime, SQL, or Release baseline behavior, and it never manufactures a native receipt.

The trace must preserve one durable `scope + epoch + cursor` identity on every event. The executable sequence requires:

- durable, painted `Awaiting` before runtime `Resume`;
- first useful, mission-specific progress distinct from generic loading and heartbeat;
- `Running` and `CaughtUp` as non-terminal states, with a legal late delta;
- a terminal `Append` or `Reset` envelope followed by a final `CaughtUp` at the same cursor;
- rejection of duplicate, skipped, cross-scope, and regressed cursors, post-terminal events, and wall-clock pseudo-determinism;
- exactly three contract-position restart markers: before resume, after first useful progress, and before terminal. They explicitly do not claim that a process was killed.

Fixture, simulator, and native provenance are mutually exclusive. The checked-in example is fixture-only, has no native receipt, and therefore cannot satisfy native evidence.

Run the self-contained verifier with:

```text
cargo run -p hartevo-eval --locked -- progress-trace validate-example
cargo run -p hartevo-eval --locked -- validate-assets
```
