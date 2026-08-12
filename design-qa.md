# Design QA

result: blocked

baseline: `/Users/yann/geo-desktop/prototype/index.html` at 1366×840 content viewport
secondary interaction reference: five user-provided ChatGPT/Codex Desktop screenshots
implementation: real Dioxus Desktop with opt-in `visual-fixtures`; never iframe, screenshot background or demo store
matrix: `docs/design/HARTEVO-PROTOTYPE-MICRO-FIDELITY-MATRIX.md`
evidence: `artifacts/visual/prototype-baseline/`
runtime stream evidence: `artifacts/visual/runtime-stream-readonly/`

## Closed in this checkpoint

- The 52px shell, dense sidebar, Mission chrome, Dispatcher, Mission Conversation, Workpad, business-page shell and Settings geometry now follow the frozen prototype tokens and information hierarchy.
- Mission Conversation now includes compact user/assistant rhythm, Mission Contract, staged activity rows, capability disclosure, connection suggestion, WorkProduct attachment, decision summary and contextual composer guidance.
- Composer supports 52px quick-entry, focus expansion, textarea auto-growth, IME-safe Enter, Shift+Enter newline, Esc blur, attachment-tray structure, Runtime boundary menu and a single running-state Stop action.
- Real Runtime cancellation no longer performs a cosmetic task abort: the coordinator turns it into an exact version-fenced interrupt and records a content-free ordered progress feed. The integration test proves `StopRequested → InterruptSent → Interrupted` without replay.
- Persisted Runtime private text now crosses an exact Project/Mission and current Device Context gate into a read-only Dioxus projection. Restart or reselection replays the SQLCipher delta chain, terminal text is deduplicated against the durable `RuntimeDraft`, and follow-latest/unseen remains local UI state without expanding Runtime authority.
- Exact approval and outcome visual journeys are interactive and honest: budget mutation generates a new SAMPLE revision; preview keeps EffectIntent, ApprovalGrant, Receipt, Verification and OutcomeEvent at zero.
- Workpad has four tabs including Mission Inspector, source-derived chart asset, ranked candidates, provenance, comments/export refusal feedback, collapse and pointer/keyboard resize.
- Channels, Relationships, Partners, Connections and Outcomes restore dense prototype IA. Creator work includes task/reward, application/invite/award, milestone/delivery, user review/revision, rights and payout boundaries without claiming payment.
- Search, notifications, project/current-object menus and project switcher have layered dismissal/focus-return behavior. Native checks prove search and notification autofocus, Esc focus return, Composer blur and splitter AX value updates.
- Same-state comparisons were regenerated after visual review. A Workpad tab-collapse bug and Settings rail/panel/group geometry drift were found from the joined images, fixed, and recaptured.
- 17/17 real native Dioxus surfaces captured; 13 source/implementation joined comparisons generated; 17 AX snapshots pass the automated accessibility contract.

## Open findings

- P0 — Runtime delta ingestion/persistence and the exact Project/Mission-gated, read-only Dioxus projection are implemented. The projection reconstructs SQLCipher private deltas, replays after restart/reselection, deduplicates the terminal `RuntimeDraft`, and provides follow-latest/unseen behavior. A brand-new Catalog Mission still cannot paint its first Turn incrementally until the blocking Application call returns the exact Mission ID; the execution-time command-handle/subscription contract remains absent.
- P0 — Pause/resume with a durable subscription/cursor/lease/generation and user-visible live reconnect continuity are not implemented. Restart readback now exists, but it is polling/replay rather than a retained execution-time subscription.
- P0 — File Broker upload, malware/prompt-injection scanning, retry, and real attachment persistence are not implemented.
- P0 — Push-to-talk, local transcription, barge-in and audio permission states remain `BLOCKED_ENV`/`NOT_IMPLEMENTED`.
- P0 — Mission Inspector does not yet receive complete live Truth/Revision/Worker/Browser/Effect/Cost projections; it honestly displays zero or blocked states.
- P0 — CRM/Handoff, Creator Contract/Deliverable/Review/Payout, Provider OAuth/Probe, Publishing and Outcome ingestion still lack their production Application/Provider loops. The completed structures are fixture-backed interaction baselines, not E3.
- P0 — Several default unimplemented branches still use compact `state-canvas`; full Chinese/English UI locale switching is absent even though German/Japanese/long-content stress fixtures exist.
- P1 — Settings routing and source geometry are restored, but several of the ten panels still use generic honest boundary rows and no settings are persisted.
- P1 — Activity group, Compaction row, progress pill and Sources remain functional fixture patterns. Follow-latest/unseen is wired to the persisted Runtime projection but remains local UI state; full durable subscription/reconnect retention is not yet proved.
- P1 — Stop reaches the exact Runtime attempt through a fenced Application command, but the click-to-coordinator request is still process-local until that command is accepted; crash-window persistence and cancel p95 remain unproved.
- P1 — VoiceOver, Windows Narrator, Windows native UI, and a true 1600×1000 viewport remain `BLOCKED_ENV`. macOS AX exposure is not equivalent to assistive-technology completion.
- P2 — Native WebKit font rasterization differs subtly from the source browser capture; reduced-motion is covered by CSS gates but lacks an OS-toggle screenshot.

## Verified gates

- `cargo clippy -p hartevo-desktop --all-targets --features visual-fixtures -- -D warnings`
- `cargo test -p hartevo-desktop --locked --features visual-fixtures`: 38 passed
- `cargo test -p hartevo-desktop --locked`: 37 passed
- native capture: 17 passed, 0 blocked
- native AX audit: 17 surfaces passed; required honest states 10/10
- responsive: 1024×768 PASS; 200% zoom PASS; 1366 height and 1600×1000 recorded as `BLOCKED_ENV_SCREEN_BOUNDS`

## Exit rule

Change `result` to exactly `passed` only after every P0/P1/P2 finding above is closed with same-state joined visual evidence or deterministic interaction/accessibility evidence. Screenshots alone are insufficient, and any unavailable platform or external capability keeps the result blocked.
