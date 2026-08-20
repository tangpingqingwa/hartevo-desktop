#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'usage: ci-distribution-hook.sh --artifact PATH --output PATH [--evidence PATH]'
}

artifact=""
output=""
evidence=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      artifact="$2"
      shift 2
      ;;
    --output)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      output="$2"
      shift 2
      ;;
    --evidence)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      evidence="$2"
      shift 2
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$artifact" && -n "$output" ]] || { usage >&2; exit 2; }
[[ -f "$artifact" && ! -L "$artifact" ]] || { echo "artifact is not a regular file" >&2; exit 1; }

artifact_digest="$(shasum -a 256 "$artifact" | awk '{print $1}')"
mkdir -p "$(dirname "$output")"

if [[ -z "$evidence" ]]; then
  python3 - "$output" "$artifact_digest" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "schema": "hartevo-ci-distribution-hook/v1",
    "authority": "future-82-distribution-contract",
    "status": "NOT_IMPLEMENTED",
    "release": False,
    "deployment": False,
    "artifactSha256": sys.argv[2],
    "message": "#82 distribution evidence is intentionally not consumed before its contract merges",
}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
  exit 0
fi

[[ -f "$evidence" && ! -L "$evidence" ]] || { echo "distribution evidence is not a regular file" >&2; exit 1; }
python3 - "$evidence" "$output" "$artifact_digest" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(source, dict):
    raise SystemExit("distribution evidence must be a JSON object")
if source.get("artifactSha256") != sys.argv[3]:
    raise SystemExit("distribution evidence artifact digest does not match the built artifact")
if source.get("release") is True or source.get("deployment") is True:
    raise SystemExit("future distribution evidence cannot enable release or deployment in this workflow")
wrapped = {
    "schema": "hartevo-ci-distribution-hook/v1",
    "authority": "future-82-distribution-contract",
    "status": source.get("status", "UNKNOWN"),
    "release": False,
    "deployment": False,
    "artifactSha256": sys.argv[3],
    "sourceEvidenceSha256": hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest(),
}
Path(sys.argv[2]).write_text(json.dumps(wrapped, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
