# Hartevo Desktop accessibility audit

This report audits native macOS accessibility snapshots from the real Dioxus Desktop window. It does not claim VoiceOver or Windows Narrator completion.

| Surface | AX lines | named controls | Result |
|---|---:|---:|---|
| `orchestrator` | 101 | 35 | PASS |
| `mission-conversation` | 117 | 46 | PASS |
| `mission-streaming` | 133 | 46 | PASS |
| `mission-workpad` | 177 | 59 | PASS |
| `mission-inspector` | 162 | 56 | PASS |
| `mission-approval` | 98 | 45 | PASS |
| `mission-outcome` | 88 | 42 | PASS |
| `current` | 120 | 28 | PASS |
| `missions` | 105 | 39 | PASS |
| `channels` | 82 | 32 | PASS |
| `relationships` | 93 | 32 | PASS |
| `partners` | 85 | 33 | PASS |
| `connections` | 88 | 33 | PASS |
| `outcomes` | 93 | 28 | PASS |
| `capability-evidence` | 117 | 28 | PASS |
| `settings` | 96 | 45 | PASS |
| `state-coverage` | 132 | 38 | PASS |

Required UI state codes: 10/10 present.

CSS gates: visible focus, reduced motion, and long-text wrapping are present.

VoiceOver and Narrator scripted journeys remain `BLOCKED_ENV`; semantic AX exposure is verified here, but assistive-technology behavior is not inferred from the tree alone.

Overall: **PASS**
