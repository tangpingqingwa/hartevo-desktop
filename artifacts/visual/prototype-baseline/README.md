# Hartevo Desktop prototype baseline artifacts

This directory contains checked-in evidence from the real Dioxus Desktop implementation and the frozen HTML prototype. It is a visual/interaction baseline, not Mission E3, Provider, Receipt, Verification, or release evidence.

## Primary evidence

- `comparison-contact-sheet.png`: same-content-viewport prototype/implementation comparisons.
- `surface-contact-sheet.png`: the implemented Dioxus surfaces.
- `responsive/responsive-contact-sheet.png`: 1024, physical-screen-clamped baseline/wide, and 200% zoom evidence.
- `responsive/capture-results.tsv`: requested and observed native bounds; blocked rows are intentionally retained.
- `accessibility-audit.md`: native AX snapshot and CSS-contract audit.
- `native-ax/`: accessibility trees captured from the real native window.

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

The source reference images were captured from `/Users/yann/geo-desktop/prototype/index.html` at the same content viewport and state. Current/Missions have no independent prototype page; the coverage and residual-difference rationale is recorded in `docs/design/HARTEVO-VISUAL-DIFFERENCE-LEDGER.md`.
