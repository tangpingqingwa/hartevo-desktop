# Runtime private-text stream — atomic Design QA

## Scope and evidence contract

- **Implementation slice:** exact Project/Mission-scoped, read-only projection of persisted Runtime `item/agentMessage/delta` text into the real Dioxus Mission Conversation.
- **Source of truth:** `artifacts/visual/prototype-baseline/references/mission-streaming-prototype-1366x840.png`, traced back to `prototype/index.html` and its linked assets.
- **Implementation capture:** `iteration-2/persisted-stream-content-1366x840.png` from the native macOS Dioxus bundle, not a browser recreation.
- **Responsive captures:** `iteration-2/persisted-stream-content-1024x768.png` and `iteration-2/persisted-stream-content-1024x768-zoom200.png`.
- **Full-screen comparison:** `iteration-2/source-left-implementation-right.png`.
- **Focused comparisons:** `iteration-2/focus/source-conversation.png` ↔ `iteration-2/focus/implementation-conversation.png`, and `iteration-2/focus/source-lower-flow.png` ↔ `iteration-2/focus/implementation-lower-flow.png`.
- **Accessibility evidence:** `iteration-2/native-ax.txt`, captured from the native macOS accessibility tree.
- **Fixture honesty:** the visual state explicitly says `VISUAL_FIXTURE · 模拟 12 个正文增量；未读取 SQLCipher`. It is only a deterministic visual state. SQLCipher persistence and context isolation are proven separately by the deterministic data-plane test.

## State and viewport parity

| Dimension | Source | Implementation |
|---|---|---|
| Viewport | 1366×840 CSS px | 1366×840 content px; native outer window 1366×932 with a 31 px macOS title bar at 2× backing scale |
| Product state | VM-07 Mission running; user prompt; assistant response in progress; work/process below | Same Mission and prompt; persisted private text is active; exact runtime status and stop affordance are visible |
| Project/Mission | 美国健身器材机会研究 | 美国健身器材机会研究 |
| External-effect truth | User forbids publish/spend | No Provider receipt or business success is claimed; capability does not expand |
| Scroll position | Conversation start and current work visible | Conversation start, active text stream, collapsed durable state, and active composer visible |

## Prototype restoration matrix

| Prototype region | Dioxus component / selector | Interaction | Token or variant | Data source | Prior gap | Verification |
|---|---|---|---|---|---|---|
| User prompt bubble | `PersistedConversationMessages`, `.mission-user-message` | Persistent chronological message | surface-muted, 12 px type, compact radius | `MissionConversationMessageProjection` | Conversation body was replaced by a coarse state canvas | Native screenshot + semantic source assertion |
| Assistant identity and body | `PersistedConversationMessages`, `.mission-assistant-turn` | Append-stable body; no whole-message flicker | 760 px reading measure, 12.5 px/1.75 | persisted conversation + Runtime stream | No private Runtime text reached Dioxus | Data-plane test, UI tests, native capture |
| Live text increment | `PersistedRuntimeStreamTurn`, `.runtime-stream-copy` | 100 ms read-only polling while active; caret; reduced-motion safe | brand caret, neutral copy | existing `latest_runtime_turn_for_mission` + `runtime_turn_private_text_deltas` | Runtime event labels were shown without actual text | Deterministic two-delta reconstruction and restart replay |
| Stream truth receipt | `.runtime-stream-receipt` | Shows active cursor/delta count or persisted replay | mono metadata token | Runtime turn/delta projection | UI could imply live persistence without evidence | Exact fixture disclosure; redacted projection `Debug` tests |
| Follow-latest | `.runtime-follow-latest` | Auto-follow near bottom; unseen marker when reader scrolls away | sticky neutral action | local UI signal only | No ChatGPT-class stream-follow behavior | Source contract assertion + scroll handler |
| Durable task state | `.mission-state-details` | Native disclosure, collapsed by default | quiet divider/detail variant | Mission projection | Large state block displaced the narrative | Iteration 1→2 comparison |
| Active composer | `.mission-composer.runtime-active` | Compact active event and Stop control | compact active variant | existing Runtime UI state | Composer consumed excessive vertical space | Iteration 1→2 comparison + native screenshot |
| Error/recovery | `.runtime-stream-system.runtime-stream-error` | Query error hides private text and exposes recovery-safe status | error semantic token | `UiFailure` mapped from context/data errors | Poll failures could disappear silently | Monitor error branch + context-gate test |

## Iteration record

### Iteration 1

- **P1 — layout/density:** the durable state canvas occupied most of the reading column, pushing the conversational flow away from the prototype.
- **P1 — active composer:** the full idle composer remained expanded during Runtime activity.
- **P1 — truth wording:** a visual fixture needed to distinguish simulated deltas from SQLCipher readback.

### Iteration 2

- Collapsed exact Mission state into a native disclosure while retaining revision/checkpoint truth.
- Added the persisted user/assistant narrative, append-stable Runtime paragraphs, caret, delta receipt, follow-latest/unseen behavior, and exact terminal deduplication.
- Added a compact Runtime-active composer and explicit fixture disclosure.
- Captured the native macOS accessibility hierarchy. It contains `持久 Mission Conversation`, `正在响应`, the assistant body, `任务边界与持久状态`, `Runtime 事件流`, and `停止 Runtime 交互结构样例`.

## Remaining differences and disposition

| Priority | Difference | Disposition |
|---|---|---|
| P1 | The source continues from the assistant body into a dense, real process timeline, evidence artifact, capability row, and suggestion card. This atomic slice only has the persisted text projection plus existing Runtime event/state projections. | **Blocked outside this lease.** Must be implemented from real Checkpoint/Work Product/Capability projections; placeholder timeline content is not acceptable. |
| P1 | A brand-new Catalog Mission cannot expose its generated exact Mission ID to the Dioxus monitor until the existing blocking Application call returns. The persisted deltas appear immediately after return/restart, but the first turn is not yet painted incrementally during execution. | Requires a future Application command-handle/stream subscription contract; do not bypass Application or infer an ID in Desktop. |
| P2 | Existing global shell/sidebar proportions and some icon/line-weight details remain different from the prototype; they predate this Runtime slice. | Retain in the full prototype micro-fidelity backlog and validate under a separately leased shell slice. |
| P2 | The visual fixture uses a disclosure string and Runtime cursor metadata not present in the source screenshot. | Intentional evidence honesty; keep until a screenshot is captured from a seeded encrypted real-mode database. |
| P2 | At 200% zoom, follow-latest necessarily gives the compact composer and newest prompt most of the short 384 CSS-px vertical viewport; earlier assistant text requires scrolling. | Native 1024×768 / 200% evidence now exists. The composer was reduced to its active status, two essential runtime/provider controls, and Stop; retain a later keyboard/screen-reader usability study before declaring whole-product accessibility complete. |

## QA result

- **Read-only Runtime text projection slice:** conditionally accepted at deterministic/component/native-smoke level.
- **Full Mission streaming prototype fidelity:** **blocked**, because the P1 real process/artifact density and first-turn live subscription contract above remain unresolved.
- This checkpoint does **not** change any Mission evidence level, Provider status, Receipt/Verification claim, release gate, schema version, or migration.
