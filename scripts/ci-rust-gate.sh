#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'usage: ci-rust-gate.sh fmt|clippy|test [--full] [--packages JSON-array]'
}

mode="${1:-}"
shift || true
full=false
packages='[]'

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --full)
      full=true
      shift
      ;;
    --packages)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      packages="$2"
      shift 2
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

case "$mode" in
  fmt)
    cargo fmt --all -- --check
    ;;
  clippy|test)
    if [[ "$full" == true ]]; then
      if [[ "$mode" == clippy ]]; then
        cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
      else
        cargo test --workspace --all-targets --all-features --locked
      fi
      exit 0
    fi

    selected=()
    while IFS= read -r selected_package; do
      selected+=("$selected_package")
    done < <(python3 - "$packages" <<'PY'
import json
import re
import sys

values = json.loads(sys.argv[1])
if not isinstance(values, list) or not values:
    raise SystemExit("scoped Rust gate requires at least one package")
for value in values:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", value):
        raise SystemExit(f"invalid Cargo package name: {value!r}")
    print(value)
PY
    )
    for package in "${selected[@]}"; do
      if [[ "$mode" == clippy ]]; then
        cargo clippy -p "$package" --all-targets --all-features --locked -- -D warnings
      else
        cargo test -p "$package" --all-targets --all-features --locked
      fi
    done
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
