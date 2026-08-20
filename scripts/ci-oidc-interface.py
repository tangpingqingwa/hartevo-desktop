#!/usr/bin/env python3
"""Emit the no-credential OIDC interface used by future promotion targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = {
        "schema": "hartevo-ci-oidc-interface/v1",
        "provider": "github-actions-oidc",
        "tokenRequested": False,
        "deployment": False,
        "longLivedCredentials": False,
        "status": "INTERFACE_ONLY",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
