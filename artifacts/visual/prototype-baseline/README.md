# Hartevo Desktop prototype baseline artifacts

This directory contains checked-in evidence from the real Dioxus Desktop implementation, the frozen Hartevo HTML prototype, and supplementary ChatGPT.app-class streaming states requested by the user. It is a visual/interaction baseline, not Mission E3, Provider, Receipt, Verification, Outcome, payment, or release evidence.

## Primary evidence

- `comparison-contact-sheet.png`: 13 same-state, same-content-viewport prototype/implementation comparisons.
- `surface-contact-sheet.png`: 17 implemented Dioxus surfaces, including Mission conversation/streaming/workpad/inspector/approval/outcome.
- `responsive/responsive-contact-sheet.png`: 1024, physical-screen-clamped baseline/wide, and 200% zoom evidence.
- `responsive/capture-results.tsv`: requested and observed native bounds; blocked rows are intentionally retained.
- `accessibility-audit.md`: native AX snapshot and CSS-contract audit.
- `native-ax/`: 17 accessibility trees captured from the real native window.

`mission-inspector` is supplementary because the frozen prototype has no exact Inspector source state. The streaming surface uses ChatGPT.app interaction patterns only for activity grouping, follow-latest and Stop. Both remain visibly marked `VISUAL_FIXTURE`; zero active Worker/Browser/Effect and zero Receipt/Verification are intentional.

## Reproduce

From the repository root:

```sh
python3 -m pip install -r scripts/requirements-visual.txt
cargo test -p hartevo-desktop --locked --features visual-fixtures
dx build --desktop -p hartevo-desktop --features visual-fixtures --locked
./scripts/capture-desktop-visual-baseline.sh
./scripts/capture-desktop-responsive-baseline.sh
python3 ./scripts/compose-desktop-visual-baseline.py
python3 ./scripts/audit-desktop-accessibility.py
```

macOS Screen Recording and Accessibility permissions are required for direct native capture. If Screen Recording is unavailable, capture scripts emit `BLOCKED_ENV_SCREEN_CAPTURE`, keep the last successful baseline, and write an attempt report instead of silently replacing evidence.

The source reference images were captured from `/Users/yann/geo-desktop/prototype/index.html` at the same 1366×840 content viewport and state. Mission Inspector, Current, Missions and State Coverage have no independent prototype page, so they are supplementary surfaces rather than fake joined comparisons. The coverage and residual-difference rationale is recorded in `docs/design/HARTEVO-VISUAL-DIFFERENCE-LEDGER.md`; `design-qa.md` remains `result: blocked` while real token streaming, pause/reconnect, File Broker, voice, live inspectors and platform evidence remain open.
