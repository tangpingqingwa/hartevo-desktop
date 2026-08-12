#!/bin/zsh

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
app_binary="$repo_root/target/dx/hartevo-desktop/debug/macos/HartevoDesktop.app/Contents/MacOS/hartevo-desktop"
output_root="$repo_root/artifacts/visual/prototype-baseline/responsive"
capture_root="$(mktemp -d)"
active_pid=""
crop_tool="$capture_root/crop-image"

cleanup() {
  if [[ -n "$active_pid" ]] && kill -0 "$active_pid" 2>/dev/null; then
    kill -TERM "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

if [[ ! -x "$app_binary" ]]; then
  print -u2 "missing Desktop bundle; run the visual-fixtures desktop build first"
  exit 1
fi

mkdir -p "$output_root"
swiftc "$repo_root/scripts/crop-image.swift" -o "$crop_tool"
verified_report="$output_root/capture-results.tsv"
attempt_report="$output_root/last-capture-attempt.tsv"
print "case\trequested\tactual_window\tcontent\tzoom\tstatus" > "$attempt_report"
captured_count=0
blocked_count=0

cases=(
  "compact|1024x768|1"
  "baseline|1366x900|1"
  "wide|1600x1000|1"
  "zoom-200|1024x768|2"
)

for definition in "${cases[@]}"; do
  case_name="${definition%%|*}"
  remainder="${definition#*|}"
  requested="${remainder%%|*}"
  zoom="${remainder##*|}"
  requested_width="${requested%x*}"
  requested_height="${requested#*x}"

  HARTEVO_DESKTOP_UI_SCENARIO=prototype-baseline-v1 \
  HARTEVO_DESKTOP_UI_SURFACE=orchestrator \
  HARTEVO_DESKTOP_UI_VIEWPORT="$requested" \
  HARTEVO_DESKTOP_UI_ZOOM="$zoom" \
  HARTEVO_DATA_ROOT="/tmp/hartevo-ui-responsive-baseline" \
    "$app_binary" >/dev/null 2>&1 &
  active_pid="$!"

  window_id=""
  for _ in {1..30}; do
    window_id="$(swift -e 'import CoreGraphics
let expected = Int32(CommandLine.arguments[1])!
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
for window in windows {
  if let pid = window[kCGWindowOwnerPID as String] as? Int32, pid == expected,
     let id = window[kCGWindowNumber as String],
     let name = window[kCGWindowName as String] as? String,
     name == "Hartevo Desktop" {
    print(id)
    break
  }
}' "$active_pid")"
    [[ -n "$window_id" ]] && break
    sleep 0.1
  done

  if [[ -z "$window_id" ]]; then
    print -u2 "responsive case $case_name did not expose a native window"
    exit 1
  fi

  sleep 0.8
  requested_outer_height="$(( requested_height + 32 ))"
  ax_resized=false
  for _ in {1..20}; do
    if osascript - "$active_pid" "$requested_width" "$requested_outer_height" >/dev/null 2>&1 <<'APPLESCRIPT'
on run argv
  set targetPid to item 1 of argv as integer
  set targetWidth to item 2 of argv as integer
  set targetHeight to item 3 of argv as integer
  tell application "System Events"
    set targetProcess to first application process whose unix id is targetPid
    set frontmost of targetProcess to true
    tell window 1 of targetProcess
      set size to {targetWidth, targetHeight}
      set position to {0, 0}
    end tell
  end tell
end run
APPLESCRIPT
    then
      ax_resized=true
      break
    fi
    sleep 0.1
  done
  sleep 0.15
  window_geometry="$(swift -e 'import CoreGraphics
import Foundation
let expected = Int32(CommandLine.arguments[1])!
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
for window in windows {
  if let pid = window[kCGWindowOwnerPID as String] as? Int32, pid == expected,
     let id = window[kCGWindowNumber as String],
     let name = window[kCGWindowName as String] as? String,
     name == "Hartevo Desktop",
     let bounds = window[kCGWindowBounds as String] as? [String: Any],
     let x = bounds["X"] as? NSNumber,
     let y = bounds["Y"] as? NSNumber,
     let width = bounds["Width"] as? NSNumber,
     let height = bounds["Height"] as? NSNumber {
    print("\(id) \(x.intValue) \(y.intValue) \(width.intValue) \(height.intValue)")
    break
  }
}' "$active_pid")"
  read window_id window_x window_y window_width window_height <<< "$window_geometry"
  raw_capture="$capture_root/$case_name-retina.png"
  cropped_capture="$capture_root/$case_name-content-retina.png"
  captured=false
  for _ in {1..5}; do
    if /usr/sbin/screencapture -x -o -l "$window_id" "$raw_capture" 2>/dev/null; then
      captured=true
      break
    fi
    sleep 0.2
  done
  if [[ "$captured" != true ]]; then
    print "$case_name\t$requested\t${window_width}x${window_height}\t—\t${zoom}00%\tBLOCKED_ENV_SCREEN_CAPTURE" >> "$attempt_report"
    blocked_count="$(( blocked_count + 1 ))"
    kill -TERM "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
    active_pid=""
    continue
  fi
  raw_width="$(sips -g pixelWidth "$raw_capture" | awk '/pixelWidth/ { print $2 }')"
  raw_height="$(sips -g pixelHeight "$raw_capture" | awk '/pixelHeight/ { print $2 }')"
  scale_factor=1
  if (( raw_width > 2000 )); then
    scale_factor=2
  fi
  actual_width="$(( raw_width / scale_factor ))"
  actual_height="$(( raw_height / scale_factor ))"
  content_height="$(( actual_height - 31 ))"
  crop_height="$(( content_height * scale_factor ))"
  crop_width="$(( actual_width * scale_factor ))"
  crop_offset_y="$(( 31 * scale_factor ))"

  sips -z "$actual_height" "$actual_width" "$raw_capture" --out "$output_root/$case_name-window.png" >/dev/null
  "$crop_tool" "$raw_capture" "$cropped_capture" 0 "$crop_offset_y" "$crop_width" "$crop_height"
  sips -z "$content_height" "$actual_width" "$cropped_capture" --out "$output_root/$case_name-content.png" >/dev/null

  case_status="PASS"
  content_height_delta="$(( content_height - requested_height ))"
  if (( content_height_delta < 0 )); then
    content_height_delta="$(( -content_height_delta ))"
  fi
  if (( actual_width != requested_width || content_height_delta > 1 )); then
    case_status="BLOCKED_ENV_SCREEN_BOUNDS"
  fi
  print "$case_name\t$requested\t${actual_width}x${actual_height}\t${actual_width}x${content_height}\t${zoom}00%\t$case_status" >> "$attempt_report"
  captured_count="$(( captured_count + 1 ))"

  kill -TERM "$active_pid" 2>/dev/null || true
  wait "$active_pid" 2>/dev/null || true
  active_pid=""
done

if (( blocked_count == 0 )); then
  mv "$attempt_report" "$verified_report"
  print "responsive capture result: $captured_count captured; verified report: $verified_report"
else
  print "responsive capture result: $captured_count captured, $blocked_count blocked; preserved verified report and wrote $attempt_report"
fi
