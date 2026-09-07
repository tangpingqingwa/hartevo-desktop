#!/usr/bin/env python3
"""Prepare, launch and inspect the normal native app against opt-in real models.

Credentials enter only the child environment. No generation POST is made by
this launcher: the operator explicitly chooses Generate in the native window.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "launch", "inspect"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--app", type=Path)
    parser.add_argument("--allow-paid", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    if args.action == "prepare":
        output.mkdir(parents=True, exist_ok=False)
    elif not (output / "scope.json").is_file():
        parser.error("prepare a new private fixture first")
    child = dict(os.environ)
    child.update({"HARTEVO_LIVE_MEDIA_UI": "1", "HARTEVO_LIVE_OUTPUT": str(output),
                  "HARTEVO_DESKTOP_DATA_DIR": str(output / "desktop-data"), "RUST_LOG": "error"})
    if args.action in ("prepare", "inspect"):
        test = "live_media_prepare_desktop" if args.action == "prepare" else "live_media_inspect_desktop"
        receipt = output / ("scope.json" if args.action == "prepare" else "media-receipts.json")
        previous_receipt = receipt.stat().st_mtime_ns if receipt.exists() else None
        with (output / (args.action + ".log")).open("wb") as log:
            result = subprocess.run(["cargo", "test", "--locked", "-p", "hartevo-desktop", "--lib", test,
                                     "--", "--ignored", "--test-threads=1"], cwd=root, env=child,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise SystemExit("Native fixture operation failed; inspect its private log")
        if not receipt.is_file() or receipt.stat().st_mtime_ns == previous_receipt:
            raise SystemExit("Native fixture operation produced no fresh receipt")
        json.loads(receipt.read_text(encoding="utf-8"))
        print(f"{args.action}: {output}")
        return
    if not args.allow_paid or not args.app or not args.app.is_file():
        parser.error("launch requires --allow-paid and an existing normal --app binary")
    spec = importlib.util.spec_from_file_location("live_model_config", root / "scripts/run-live-model-journeys.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = module.read_config(args.env_file)
    child.update({"HARTEVO_MEDIA_API_BASE": config["api_base"],
                  "HARTEVO_GPT_API_KEY": config["gpt_api"], "HARTEVO_GROK_API_KEY": config["grok_api"],
                  "HARTEVO_MEDIA_GPT_KEY_ENV": "HARTEVO_GPT_API_KEY",
                  "HARTEVO_MEDIA_GROK_KEY_ENV": "HARTEVO_GROK_API_KEY"})
    app = args.app.resolve()
    with (output / "desktop.log").open("ab") as log:
        process = subprocess.Popen([str(app)], cwd=root, env=child, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
    receipt = {"pid": process.pid, "binarySha256": hashlib.sha256(app.read_bytes()).hexdigest(),
               "paidGenerationRequiresNativeButton": True}
    (output / "launch.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"Native app launched: pid={process.pid}; receipts={output}")


if __name__ == "__main__":
    main()
