#!/usr/bin/env bash
# Offline Cordis crate gate used by BUILD PR 5+. Does not claim the full
# product matrix and does not promote Release evidence.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo test -p hartevo-cordis --locked
cargo clippy -p hartevo-cordis --all-targets --locked -- -D warnings
