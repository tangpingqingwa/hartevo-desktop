#!/usr/bin/env python3
"""Offline regressions for paid-test evidence and credential boundaries."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("live_runner", Path(__file__).with_name("run-live-model-journeys.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class LiveRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = {"api_base": "https://configured.example/v1", "gpt_api": "synthetic-gpt", "grok_api": "synthetic-grok"}

    def receipt(self):
        for name in ("initial-draft.md", "continued-draft.md"):
            (self.root / name).write_text("NORDLICHT synthetic campaign", encoding="utf-8")
        digest = hashlib.sha256((self.root / "initial-draft.md").read_bytes()).hexdigest()
        receipt = {"schemaVersion": "desktop-live-model-journey/v1", "status": "passed",
                   "provider": "openai-compatible", "model": "synthetic-model",
                   "modelCalls": [{"status": "received"}, {"status": "received"}],
                   "initialDraftSha256": digest, "continuedDraftSha256": digest,
                   "assertions": {key: True for key in (
                       "catalogMission", "realProviderDraft", "sameMissionContinuation", "contextRetained",
                       "idempotentReplay", "sqlcipherReopen", "exactSessionReplay", "workProductAdoption",
                       "staleAdoptionRejected", "noPublicationEffects")}}
        runner.write_json(self.root / "receipt.json", receipt)
        return receipt

    def test_receipt_requires_artifacts_identity_calls_and_all_assertions(self):
        receipt = self.receipt()
        self.assertTrue(runner.valid_text_receipt(self.root, "openai", "synthetic-model"))
        for field, invalid in (("provider", "grok-compatible"), ("modelCalls", []), ("assertions", {}), ("status", "failed")):
            changed = dict(receipt, **{field: invalid})
            runner.write_json(self.root / "receipt.json", changed)
            self.assertFalse(runner.valid_text_receipt(self.root, "openai", "synthetic-model"))
        runner.write_json(self.root / "receipt.json", receipt)
        (self.root / "initial-draft.md").write_text("tampered", encoding="utf-8")
        self.assertFalse(runner.valid_text_receipt(self.root, "openai", "synthetic-model"))

    def test_successful_zero_test_binary_does_not_pass(self):
        binary = self.root / "wrong-test-binary"
        binary.write_bytes(b"not actually executed")
        completed = subprocess.CompletedProcess([], 0, b"running 0 tests\ntest result: ok. 0 passed\n", b"")
        with patch.object(runner.subprocess, "run", return_value=completed), patch("builtins.print"):
            self.assertFalse(runner.text_journey(self.config, self.root, binary, "openai", "synthetic-model"))

    def test_env_is_parsed_as_data_without_shell_expansion(self):
        path = self.root / ".env"
        path.write_text("base_url='https://configured.example/v1'\ngpt_api='$(false)'\ngrok_api=literal-key # comment\n", encoding="utf-8")
        values = runner.read_config(path)
        self.assertEqual(values["gpt_api"], "$(false)")
        self.assertEqual(values["grok_api"], "literal-key")
        self.assertEqual(values["api_base"], "https://configured.example/v1")

    def test_generated_image_is_not_a_pass_when_dimensions_are_wrong(self):
        header = b"\x89PNG\r\n\x1a\n" + (13).to_bytes(4, "big") + b"IHDR"
        actual_failed_image = header + struct.pack(">II", 1122, 1402)
        self.assertFalse(runner.image_conformance(actual_failed_image, "gpt-image")["requestConforms"])
        self.assertTrue(runner.image_conformance(header + struct.pack(">II", 1024, 1024), "gpt-image")["requestConforms"])
        with self.assertRaises(ValueError):
            runner.image_dimensions(b"not an image")

    def test_relative_same_origin_asset_gets_only_its_provider_credential(self):
        with patch.object(runner.request, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(b"media")
            self.assertEqual(runner.download("/generated/video.mp4", self.config["api_base"], "synthetic-grok"), b"media")
            call = opener.return_value.open.call_args.args[0]
            self.assertEqual(call.full_url, "https://configured.example/generated/video.mp4")
            self.assertEqual(call.get_header("Authorization"), "Bearer synthetic-grok")

    def test_cross_origin_asset_never_receives_provider_credential(self):
        address = [(2, 1, 6, "", ("1.1.1.1", 443))]
        with patch.object(runner.socket, "getaddrinfo", return_value=address), patch.object(runner.request, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(b"media")
            runner.download("https://assets.example/image.png", self.config["api_base"], "synthetic-gpt")
            self.assertIsNone(opener.return_value.open.call_args.args[0].get_header("Authorization"))

    def test_unconfigured_private_asset_host_is_rejected(self):
        address = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch.object(runner.socket, "getaddrinfo", return_value=address), patch.object(runner.request, "build_opener") as opener:
            with self.assertRaises(ValueError):
                runner.download("https://other.example/private", self.config["api_base"], "synthetic-grok")
            opener.assert_not_called()

    def test_video_recovery_gets_original_job_without_resubmitting(self):
        runner.write_json(self.root / "video-job.json", {"requestId": "existing-job", "model": "synthetic-video"})
        completed = {"status": "done", "video": {"url": "/media/video.mp4", "duration": 3, "respect_moderation": True}}
        media = b"\x00\x00\x00\x18ftypisom" + b"\x00" * 12
        with patch.object(runner, "api", return_value=completed) as api, patch.object(runner, "download", return_value=media), patch("builtins.print"):
            self.assertTrue(runner.recover_video(self.config, self.root))
            api.assert_called_once_with(self.config, "grok_api", "/videos/existing-job", timeout=45)
        receipt = json.loads((self.root / "grok-video-recovered.json").read_text())
        self.assertEqual(receipt["postAttempts"], 0)
        self.assertEqual(receipt["sha256"], hashlib.sha256(media).hexdigest())


if __name__ == "__main__":
    unittest.main()
