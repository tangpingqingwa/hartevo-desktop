#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  printf '%s\n' '{"schema":"hartevo-distribution-gate-verification/v1","status":"BLOCKED_ENV","code":"REPOSITORY_NOT_AVAILABLE","releaseDecision":"NOT_EVALUATED","releasePassed":false}'
  exit 2
}

command -v python3 >/dev/null 2>&1 || {
  printf '%s\n' '{"schema":"hartevo-distribution-gate-verification/v1","status":"BLOCKED_ENV","code":"PYTHON_NOT_AVAILABLE","releaseDecision":"NOT_EVALUATED","releasePassed":false}'
  exit 2
}

exec python3 "${repo_root}/scripts/check-distribution.py" "$@"
