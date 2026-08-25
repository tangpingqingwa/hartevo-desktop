#!/usr/bin/env bash
# Offline Cordis crate gate used by BUILD PR 6. Does not claim the full
# product matrix, does not call live OpenInterpreter, and does not promote
# Release evidence.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
unset OPENINTERPRETER_HOME || true
unset OPENINTERPRETER_API_KEY || true
cargo test -p hartevo-cordis --locked
cargo clippy -p hartevo-cordis --all-targets --locked -- -D warnings
