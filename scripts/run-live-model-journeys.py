#!/usr/bin/env python3
"""Opt-in paid model checks. Never source .env or print credentials/raw replies.

Text runs the Rust Desktop/Cordis/SQLCipher journey. Media is explicitly a
provider capability probe, not evidence of a Desktop media-generation flow.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
from urllib import error, parse, request


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def read_config(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*", line)
        if not match:
            continue
        key, value = match.groups()
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError("Malformed quoted environment entry")
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        values[key] = value
    if not all(values.get(key) for key in ("base_url", "gpt_api", "grok_api")):
        raise ValueError("Required .env keys: base_url, gpt_api, grok_api")
    url = parse.urlsplit(values["base_url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Expected an HTTPS API base without embedded credentials")
    base = values["base_url"].rstrip("/")
    values["api_base"] = base if base.endswith("/v1") else base + "/v1"
    return values


def write_json(path, data):
    with path.open("w", encoding="utf-8") as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
        out.write("\n")


def api(config, credential, route, payload=None, timeout=180):
    headers = {"Authorization": "Bearer " + config[credential], "Accept": "application/json"}
    encoded = None
    if payload is not None:
        encoded = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    call = request.Request(config["api_base"] + route, data=encoded, headers=headers)
    with request.build_opener(NoRedirect).open(call, timeout=timeout) as response:
        raw = response.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("Response exceeds bound")
        return json.loads(raw)


def download(url, api_base, api_key=None):
    # Credentials may reach only the exact user-configured API origin. Other
    # asset hosts receive no credentials; local destinations/redirects fail.
    if url.startswith("/") and not url.startswith("//"):
        url = parse.urljoin(api_base, url)
    parsed = parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid generated asset URL")
    configured = parse.urlsplit(api_base)
    same_origin = (parsed.hostname, parsed.port or 443) == (configured.hostname, configured.port or 443)
    if not same_origin:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise ValueError("Non-public generated asset host")
    headers = {"Authorization": "Bearer " + api_key} if same_origin and api_key else {}
    with request.build_opener(NoRedirect).open(request.Request(url, headers=headers), timeout=120) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if not data or len(data) > 64 * 1024 * 1024:
        raise ValueError("Generated asset size outside bound")
    return data


def image_dimensions(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n") and data[12:16] == b"IHDR" and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 4 <= len(data):
            if data[offset] != 255:
                break
            while offset < len(data) and data[offset] == 255:
                offset += 1
            if offset + 3 > len(data):
                break
            marker = data[offset]
            offset += 1
            length = int.from_bytes(data[offset:offset + 2], "big")
            if length < 2 or offset + length > len(data):
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                if length < 7:
                    break
                height, width = struct.unpack(">HH", data[offset + 3:offset + 7])
                return width, height
            offset += length
    raise ValueError("Image dimensions unavailable")


def image_conformance(data, kind):
    width, height = image_dimensions(data)
    expected = [1024, 1024] if kind == "gpt-image" else "1:1"
    conforms = (width, height) == (1024, 1024) if kind == "gpt-image" else width == height and width > 0
    return {"actualDimensions": [width, height], "expectedDimensions": expected, "requestConforms": conforms}


def media_probe(config, output, kind, model):
    receipt = {"schemaVersion": "live-media-provider-probe/v1", "kind": kind,
               "requestedModel": model, "desktopJourney": False, "postAttempts": 1}
    started = time.monotonic()
    try:
        prompt = ("A premium studio product shot for fictional reusable-bottle brand Nordlicht: "
                  "a forest-green metal water bottle on pale stone, soft morning light, "
                  "clean background, no people, no text, no logo. Synthetic test campaign.")
        payload = {"model": model, "prompt": prompt}
        if kind == "gpt-image":
            payload.update(n=1, size="1024x1024", quality="low")
            result = api(config, "gpt_api", "/images/generations", payload)
        elif kind == "grok-image":
            payload.update(n=1, response_format="b64_json", aspect_ratio="1:1")
            result = api(config, "grok_api", "/images/generations", payload)
        else:
            payload.update(duration=3, aspect_ratio="1:1", resolution="480p")
            result = api(config, "grok_api", "/videos/generations", payload)
            job = result.get("request_id")
            if not isinstance(job, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", job):
                raise ValueError("Missing bounded video request ID")
            # Persist the issued job before polling. Never resubmit a timed-out
            # POST automatically; this private ID permits later read-only poll.
            write_json(output / "video-job.json", {"requestId": job, "model": model})
            polls = 0
            while time.monotonic() - started < 900:
                result = api(config, "grok_api", "/videos/" + job, timeout=45)
                polls += 1
                if result.get("status") == "done":
                    break
                if result.get("status") in ("failed", "expired"):
                    raise ValueError("Video job ended without an asset")
                time.sleep(10)
            else:
                raise TimeoutError("Video remains pending; do not resubmit")
            receipt["polls"] = polls
        if kind == "grok-video":
            asset = result["video"]
            if asset.get("respect_moderation") is False:
                raise ValueError("Video filtered")
            data = download(asset["url"], config["api_base"], config["grok_api"])
            if len(data) < 12 or data[4:8] != b"ftyp":
                raise ValueError("Asset is not an MP4 container")
            suffix = ".mp4"
            receipt["reportedDurationSeconds"] = asset.get("duration")
        else:
            asset = result["data"][0]
            if asset.get("respect_moderation") is False:
                raise ValueError("Image filtered")
            credential = config["gpt_api" if kind == "gpt-image" else "grok_api"]
            data = base64.b64decode(asset["b64_json"], validate=True) if asset.get("b64_json") else download(asset["url"], config["api_base"], credential)
            if data.startswith(b"\x89PNG\r\n\x1a\n"):
                suffix = ".png"
            elif data.startswith(b"\xff\xd8\xff"):
                suffix = ".jpg"
            else:
                raise ValueError("Asset is not PNG or JPEG")
        asset_path = output / (kind + suffix)
        asset_path.write_bytes(data)
        receipt.update(status="passed", file=asset_path.name, bytes=len(data),
                       sha256=hashlib.sha256(data).hexdigest())
        if kind != "grok-video":
            receipt.update(image_conformance(data, kind))
            if not receipt["requestConforms"]:
                receipt.update(status="failed", failure="IMAGE_DIMENSIONS_MISMATCH", generated=True)
    except error.HTTPError as failure:
        receipt.update(status="failed", failure="HTTP_ERROR", httpStatus=failure.code)
    except Exception as failure:
        # Exception text may contain a URL or provider body. Record type only.
        receipt.update(status="failed", failure=type(failure).__name__)
    receipt["elapsedSeconds"] = round(time.monotonic() - started, 2)
    write_json(output / (kind + ".json"), receipt)
    print(json.dumps(receipt), flush=True)
    return receipt["status"] == "passed"


def recover_video(config, output):
    """Recover an already-issued job with GETs only, preserving the first receipt."""
    receipt = {"schemaVersion": "live-media-provider-probe/v1", "kind": "grok-video",
               "desktopJourney": False, "postAttempts": 0, "recovery": True}
    started = time.monotonic()
    try:
        job = json.loads((output / "video-job.json").read_text(encoding="utf-8"))
        identifier = job["requestId"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", identifier):
            raise ValueError("Invalid stored video ID")
        receipt["requestedModel"] = job["model"]
        while time.monotonic() - started < 900:
            result = api(config, "grok_api", "/videos/" + identifier, timeout=45)
            if result.get("status") == "done":
                break
            if result.get("status") in ("failed", "expired"):
                raise ValueError("Stored video job failed")
            time.sleep(10)
        else:
            raise TimeoutError("Stored video job is still pending")
        asset = result["video"]
        if asset.get("respect_moderation") is False:
            raise ValueError("Video filtered")
        data = download(asset["url"], config["api_base"], config["grok_api"])
        if len(data) < 12 or data[4:8] != b"ftyp":
            raise ValueError("Asset is not an MP4 container")
        path = output / "grok-video.mp4"
        path.write_bytes(data)
        receipt.update(status="passed", file=path.name, bytes=len(data),
                       sha256=hashlib.sha256(data).hexdigest(),
                       reportedDurationSeconds=asset.get("duration"))
    except error.HTTPError as failure:
        receipt.update(status="failed", failure="HTTP_ERROR", httpStatus=failure.code)
    except Exception as failure:
        receipt.update(status="failed", failure=type(failure).__name__)
    receipt["elapsedSeconds"] = round(time.monotonic() - started, 2)
    write_json(output / "grok-video-recovered.json", receipt)
    print(json.dumps(receipt), flush=True)
    return receipt["status"] == "passed"


def valid_text_receipt(output, provider, model):
    try:
        receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
        required = {"catalogMission", "realProviderDraft", "sameMissionContinuation", "contextRetained",
                    "idempotentReplay", "sqlcipherReopen", "exactSessionReplay", "workProductAdoption",
                    "staleAdoptionRejected", "noPublicationEffects"}
        if (receipt.get("schemaVersion") != "desktop-live-model-journey/v1"
                or receipt.get("status") != "passed" or receipt.get("provider") != provider + "-compatible"
                or receipt.get("model") != model
                or set(receipt.get("assertions", {})) != required
                or any(value is not True for value in receipt["assertions"].values())):
            return False
        calls = receipt.get("modelCalls", [])
        if len(calls) != 2 or any(call.get("status") != "received" for call in calls):
            return False
        for filename, field in (("initial-draft.md", "initialDraftSha256"),
                                ("continued-draft.md", "continuedDraftSha256")):
            data = (output / filename).read_bytes()
            if not data or hashlib.sha256(data).hexdigest() != receipt.get(field):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def text_journey(config, output, binary, provider, model):
    env = dict(os.environ)
    env.update(HARTEVO_LIVE_MODELS="1", HARTEVO_RUNTIME_PROVIDER=provider + "-compatible",
               HARTEVO_RUNTIME_MODEL=model, HARTEVO_RUNTIME_API_BASE=config["api_base"],
               HARTEVO_RUNTIME_API_KEY_ENV="HARTEVO_LIVE_API_KEY",
               HARTEVO_RUNTIME_CONTEXT_TOKENS="32768", HARTEVO_RUNTIME_MAX_TOKENS="2048",
               HARTEVO_LIVE_API_KEY=config["gpt_api" if provider == "openai" else "grok_api"],
               HARTEVO_LIVE_OUTPUT=str(output / provider), RUST_LOG="error")
    args = [str(binary), "data_plane::tests::live_models::live_mission_continuation_adoption_and_recovery",
            "--ignored", "--exact", "--nocapture", "--test-threads=1"]
    metadata = {"testBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "provider": provider, "model": model, "startedAtUnix": time.time()}
    write_json(output / (provider + "-run.json"), metadata)
    run = subprocess.run(args, env=env, capture_output=True, timeout=1200, check=False)
    log = (run.stdout + run.stderr).decode("utf-8", errors="replace")
    for secret in (config["gpt_api"], config["grok_api"]):
        log = log.replace(secret, "[REDACTED]")
    (output / (provider + "-rust.log")).write_text(log, encoding="utf-8")
    verified = run.returncode == 0 and valid_text_receipt(output / provider, provider, model)
    print(json.dumps({"kind": "desktop-rust-journey", "provider": provider,
                      "model": model, "exitCode": run.returncode, "receiptVerified": verified}), flush=True)
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-paid", action="store_true", required=True)
    parser.add_argument("--mode", choices=("text", "media", "all", "recover-video"), default="all")
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--gpt-model", default="gpt-6")
    parser.add_argument("--grok-model", default="grok-4.6")
    args = parser.parse_args()
    if args.mode in ("text", "all") and not args.test_binary:
        parser.error("Text journeys require --test-binary from cargo test --no-run")
    os.umask(0o077)
    config = read_config(args.env_file)
    output = args.output.resolve()
    if args.mode == "recover-video":
        return 0 if recover_video(config, output) else 1
    output.mkdir(parents=True, exist_ok=False)
    outcomes = []
    if args.mode != "media":
        for provider, model in (("openai", args.gpt_model), ("grok", args.grok_model)):
            outcomes.append(text_journey(config, output, args.test_binary.resolve(), provider, model))
    if args.mode != "text":
        for kind, model in (("gpt-image", "gpt-image-2"), ("grok-image", "grok-imagine-image-2.0"),
                            ("grok-video", "grok-imagine-video-1.5")):
            outcomes.append(media_probe(config, output, kind, model))
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
