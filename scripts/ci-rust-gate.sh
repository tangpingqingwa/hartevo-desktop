#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
planner="$repo_root/scripts/ci-rust-test-shards.py"

usage() {
  printf '%s\n' 'usage: ci-rust-gate.sh fmt|clippy|test [--full] [--packages JSON-array] [--plan PATH]'
}

fail() {
  printf 'ci-rust-gate: %s\n' "$1" >&2
  exit 1
}

self_test() {
  [[ "$#" -eq 0 ]] || { usage >&2; return 2; }
  local fixture_dir fake_bin cargo_log injection_marker plan_path
  fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/hartevo-ci-rust-gate.XXXXXX")"
  trap 'rm -rf -- "$fixture_dir"' RETURN
  fake_bin="$fixture_dir/bin"
  cargo_log="$fixture_dir/cargo.log"
  injection_marker="$fixture_dir/injection"
  plan_path="$fixture_dir/empty-plan.json"
  mkdir -p "$fake_bin"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "%q " "$@" >> "$FAKE_CARGO_LOG"' \
    'printf "\n" >> "$FAKE_CARGO_LOG"' \
    > "$fake_bin/cargo"
  chmod +x "$fake_bin/cargo"

  run_fake() {
    PATH="$fake_bin:$PATH" FAKE_CARGO_LOG="$cargo_log" "$script_dir/ci-rust-gate.sh" "$@"
  }

  : > "$cargo_log"
  run_fake test --packages '["hartevo-application","hartevo-browser-adapter"]'
  [[ "$(wc -l < "$cargo_log" | tr -d ' ')" == "1" ]] || fail "self-test expected one Cargo invocation"
  grep -F -- '-p hartevo-application' "$cargo_log" >/dev/null || fail "self-test lost the first package selector"
  grep -F -- '-p hartevo-browser-adapter' "$cargo_log" >/dev/null || fail "self-test lost the second package selector"
  grep -F -- '--all-targets --all-features --locked' "$cargo_log" >/dev/null || fail "self-test lost locked Cargo flags"

  local invalid_scope
  for invalid_scope in \
    'not-json' \
    '["hartevo-application","hartevo-application"]' \
    '["hartevo-not-a-package"]' \
    '["hartevo-application","$(touch '"$injection_marker"')"]'; do
    : > "$cargo_log"
    if run_fake test --packages "$invalid_scope"; then
      fail "self-test accepted invalid package scope: $invalid_scope"
    fi
    [[ ! -e "$injection_marker" ]] || fail "self-test executed an injected package token"
    [[ ! -s "$cargo_log" ]] || fail "self-test invoked Cargo for rejected package scope"
  done

  : > "$cargo_log"
  if run_fake test --packages '[]'; then
    fail "self-test accepted empty scoped execution without a marker"
  fi
  python3 "$planner" plan \
    --repo "$repo_root" \
    --shard 0 \
    --shard-count 2 \
    --full-workspace false \
    --packages '["hartevo-browser-adapter"]' \
    --output "$plan_path" >/dev/null
  run_fake test --plan "$plan_path"
  [[ ! -s "$cargo_log" ]] || fail "self-test invoked Cargo for a planned-empty shard"

  printf '%s\n' '{"schema":"hartevo-ci-rust-gate-self-test/v1","status":"PASS"}'
}

mode="${1:-}"
shift || true
if [[ "$mode" == self-test ]]; then
  self_test "$@"
  exit $?
fi

full=false
packages='[]'
plan=''

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --full)
      [[ "$full" == false ]] || { usage >&2; exit 2; }
      full=true
      shift
      ;;
    --packages)
      [[ "$#" -ge 2 && -z "$plan" ]] || { usage >&2; exit 2; }
      packages="$2"
      shift 2
      ;;
    --plan)
      [[ "$#" -ge 2 && "$full" == false && "$mode" == test && "$packages" == '[]' ]] || { usage >&2; exit 2; }
      plan="$2"
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
    [[ "$full" == false && "$plan" == "" && "$packages" == '[]' ]] || { usage >&2; exit 2; }
    cargo fmt --all -- --check
    ;;
  clippy|test)
    if [[ "$full" == true ]]; then
      [[ "$plan" == "" ]] || { usage >&2; exit 2; }
      if [[ "$packages" != '[]' ]]; then
        python3 "$planner" verify \
          --repo "$repo_root" \
          --packages "$packages" \
          --full-workspace true >/dev/null || exit $?
      fi
      if [[ "$mode" == clippy ]]; then
        cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
      else
        cargo test --workspace --all-targets --all-features --locked
      fi
      exit 0
    fi

    selected=()
    selected_output=''
    if [[ -n "$plan" ]]; then
      selected_output="$(python3 "$planner" verify --repo "$repo_root" --plan "$plan" --emit-packages)" || exit $?
    else
      selected_output="$(python3 "$planner" verify --repo "$repo_root" --packages "$packages" --emit-packages)" || exit $?
    fi
    if [[ -n "$selected_output" ]]; then
      while IFS= read -r selected_package; do
        selected+=("$selected_package")
      done <<< "$selected_output"
    fi
    [[ "${#selected[@]}" -gt 0 ]] || {
      if [[ -n "$plan" ]]; then
        printf '%s\n' 'Rust shard plan is explicitly planned-empty; Cargo is not executed.'
        exit 0
      fi
      fail "scoped Rust gate requires at least one package"
    }

    cargo_args=("$mode")
    for package in "${selected[@]}"; do
      cargo_args+=("-p" "$package")
    done
    cargo_args+=("--all-targets" "--all-features" "--locked")
    if [[ "$mode" == clippy ]]; then
      cargo_args+=("--" "-D" "warnings")
    fi
    cargo "${cargo_args[@]}"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
