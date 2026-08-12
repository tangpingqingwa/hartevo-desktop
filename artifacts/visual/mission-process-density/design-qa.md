# Mission process density — native Design QA attempt

## Scope and evidence boundary

- **Implementation slice:** persisted Mission checkpoint counts and exact current checkpoint, current Capability / Executor / Oracle / completion policy / Application handler status, projected Work Products, and a Mission-state-derived next boundary.
- **Reference:** `artifacts/visual/prototype-baseline/references/mission-streaming-prototype-1366x840.png`, traced to `prototype/index.html` and its checked-in assets.
- **Fixture:** the isolated `prototype-baseline-v1` / `mission-persisted-stream` visual fixture. Its UI explicitly says `VISUAL_FIXTURE` and `未读取 SQLCipher`; it is not L3, E3, Provider, Receipt, Verification, or release evidence.
- **Schema / migration:** none.

## Attempt result — 2026-08-12

1. `dx build --desktop -p hartevo-desktop --features visual-fixtures --locked` passed and produced the native macOS bundle.
2. The bundle was launched with only `HARTEVO_DESKTOP_UI_SCENARIO=prototype-baseline-v1`, `HARTEVO_DESKTOP_UI_SURFACE=mission-persisted-stream`, `HARTEVO_DESKTOP_UI_VIEWPORT=1366x840`, and an isolated temporary data root.
3. Computer Use enumerated the running app as bundle id `team.hartevo.desktop`, display name `HartevoDesktop`.
4. Native state capture failed closed: Computer Use returned `Invalid app` for the display name, bundle id, and exact built app path. Per the exclusive visual-slot stop-on-first-failure rule, the process was terminated and no fallback AppleScript, `screencapture`, Chrome, Keychain, or user profile access was attempted.

## Honest disposition

- **Native screenshots:** `BLOCKED_ENV_COMPUTER_USE_APP_TARGET`.
- **Actual native bounds:** `NOT_MEASURED`.
- **1366×840 same-state side-by-side comparison:** `NOT_RUN`; a source screenshot alone is not QA.
- **1024×768 and 200% zoom:** `NOT_RUN` after the first native-control failure.
- **Keyboard, disclosure, Workpad attachment, focus return, and AX tree:** `BLOCKED_ENV_COMPUTER_USE_APP_TARGET`.
- **Previously checked-in screenshots:** preserved but not relabeled as evidence for this revision.

The deterministic Rust tests and successful bundle build prove compilation and projection contracts only. They do not substitute for the blocked native visual, interaction, or accessibility checks.

## Non-visual verification

- Default Desktop suite before the test-only split: 39 passed, 0 failed.
- `visual-fixtures` Desktop suite before the test-only split: 40 passed, 0 failed.
- Split deterministic checks: `mission_process_counts_fail_closed` and `mission_next_boundary_uses_persisted_authority` each passed independently; the final count check includes `Skipped` 9/3 → 5.
- `cargo clippy -p hartevo-desktop --all-targets --features visual-fixtures --locked -- -D warnings`: passed after the final count fix.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
