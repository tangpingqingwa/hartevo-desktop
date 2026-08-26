#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_root="${HARTEVO_NATIVE_JOURNEY_OUTPUT_ROOT:-${repo_root}/target/native-journey/b2-native-01-${run_stamp}}"
receipt_path="${run_root}/receipt.json"
app_log="${run_root}/desktop.log"
mkdir -p "${run_root}"

write_blocked_env() {
  local code="$1"
  if [[ -s "${receipt_path}" ]]; then
    printf 'FAILED %s existing_receipt=%s\n' "${code}" "${receipt_path}"
    exit 1
  fi
  python3 - "${receipt_path}" "${code}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
code = sys.argv[2]
path.write_text(json.dumps({
    "schemaVersion": "b2-native-runtime-journey/v1",
    "journeyId": "B2-NATIVE-01",
    "status": "blocked_env",
    "failureCode": code,
    "boundaries": {
        "proven": [],
        "notProven": [
            "native_dioxus_window",
            "local_sqlcipher",
            "controlled_runtime_subprocess",
            "dioxus_render_commit_fence",
            "operating_system_compositor_evidence",
            "accessibility_tree_evidence",
            "mission_e3",
        ],
    },
    "assertions": {},
    "timeline": None,
}, indent=2) + "\n", encoding="utf-8")
PY
  printf 'BLOCKED_ENV %s receipt=%s\n' "${code}" "${receipt_path}"
  exit 77
}

[[ "$(uname -s)" == "Darwin" ]] || write_blocked_env "NATIVE_MACOS_REQUIRED"
command -v dx >/dev/null 2>&1 || write_blocked_env "DIOXUS_CLI_REQUIRED"
command -v python3 >/dev/null 2>&1 || write_blocked_env "PYTHON3_REQUIRED"

cd "${repo_root}"
dx build --package hartevo-desktop --features native-journey --locked

app_binary="${repo_root}/target/dx/hartevo-desktop/debug/macos/HartevoDesktop.app/Contents/MacOS/hartevo-desktop"
[[ -x "${app_binary}" ]] || write_blocked_env "NATIVE_APP_ARTIFACT_MISSING"

HARTEVO_NATIVE_RUNTIME_JOURNEY=1 \
HARTEVO_NATIVE_RUNTIME_JOURNEY_ROOT="${run_root}" \
HARTEVO_NATIVE_RUNTIME_JOURNEY_RECEIPT="${receipt_path}" \
RUST_LOG=error \
"${app_binary}" >"${app_log}" 2>&1 &
app_pid=$!

deadline=$((SECONDS + 180))
while kill -0 "${app_pid}" 2>/dev/null; do
  if (( SECONDS >= deadline )); then
    kill "${app_pid}" 2>/dev/null || true
    wait "${app_pid}" 2>/dev/null || true
    write_blocked_env "NATIVE_WINDOW_OR_JOURNEY_TIMEOUT"
  fi
  sleep 0.2
done

if ! wait "${app_pid}"; then
  [[ -f "${receipt_path}" ]] || write_blocked_env "NATIVE_APP_EXITED_WITHOUT_RECEIPT"
fi
[[ -f "${receipt_path}" ]] || write_blocked_env "NATIVE_RECEIPT_MISSING"

python3 - "${receipt_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_text(encoding="utf-8")
for forbidden in (
    "native-private",
    "native-journey-thread",
    "native-journey-turn",
    "native-journey-item",
):
    if forbidden in raw:
        raise SystemExit(f"private material leaked into receipt: {forbidden}")

receipt = json.loads(raw)
if receipt.get("schemaVersion") != "b2-native-runtime-journey/v1":
    raise SystemExit("unexpected receipt schema")
if receipt.get("status") != "passed" or receipt.get("failureCode") is not None:
    raise SystemExit(f"native journey did not pass: {receipt.get('failureCode')}")

boundaries = receipt["boundaries"]
proven = set(boundaries.get("proven", []))
not_proven = set(boundaries.get("notProven", []))
for key in (
    "native_dioxus_window",
    "local_sqlcipher",
    "controlled_runtime_subprocess",
    "dioxus_render_commit_fence",
):
    if key not in proven:
        raise SystemExit(f"missing native boundary: {key}")
for key in (
    "operating_system_compositor_evidence",
    "accessibility_tree_evidence",
    "mission_e3",
):
    if key not in not_proven or key in proven:
        raise SystemExit(f"honesty boundary was raised: {key}")

assertions = receipt["assertions"]
if not assertions or not all(value is True for value in assertions.values()):
    raise SystemExit("one or more native journey assertions failed")

timeline = receipt["timeline"]
events = timeline["events"]
sequences = [event["sequence"] for event in events]
if sequences != list(range(1, len(events) + 1)):
    raise SystemExit("timeline sequence is not contiguous")
elapsed = [event["elapsedMillis"] for event in events]
if elapsed != sorted(elapsed):
    raise SystemExit("timeline clock is not monotonic")
kinds = [event["kind"] for event in events]
required = [
    "sqlcipher_ready",
    "catalog_start_committed",
    "awaiting_render_committed",
    "post_render_acknowledged",
    "runtime_resume_dispatched",
    "first_delta_observed",
    "running_caught_up",
    "offscreen_reselect_isolated",
    "stale_epoch_rejected",
    "late_delta_observed",
    "terminal_observed",
    "final_caught_up",
    "runtime_command_released",
    "stop_mission_awaiting_rendered",
    "stop_before_resume_isolated",
]
cursor = 0
for kind in required:
    try:
        cursor = kinds.index(kind, cursor) + 1
    except ValueError as error:
        raise SystemExit(f"timeline milestone missing: {kind}") from error
if kinds.count("runtime_resume_dispatched") != 1:
    raise SystemExit("runtime resume count is not exactly one")
awaiting = next(event for event in events if event["kind"] == "awaiting_render_committed")
if awaiting.get("awaitingSnapshotHandleBound") is not True:
    raise SystemExit("Awaiting paint did not bind the durable snapshot and exact handle")
if len(timeline.get("replayDigest", "")) != 64:
    raise SystemExit("timeline replay digest is invalid")

print(f"PASS B2-NATIVE-01 receipt={path}")
PY

printf 'native_log=%s\n' "${app_log}"
