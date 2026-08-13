from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-plugin-truth.py"
CONFIG_PATH = ROOT / "scripts" / "plugin-truth-claims.v1.json"


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_plugin_truth", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to import checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class VerifyPluginTruthTests(unittest.TestCase):
    def test_current_bootstrap_is_verified(self) -> None:
        result = CHECKER.verify(ROOT, CONFIG_PATH)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["facts"]["capability_catalog_entries"], 48)
        self.assertEqual(result["facts"]["provider_adapter_registration_count"], 0)
        self.assertEqual(result["facts"]["provider_catalog_connected_count"], 0)
        self.assertTrue(result["facts"]["capability_adapter_symbol"])
        self.assertTrue(result["facts"]["capability_consumer_symbol"])
        self.assertFalse(result["facts"]["plugin_composition_kernel"])
        self.assertFalse(result["facts"]["plugin_reversible_lifecycle"])

    def test_positive_fixture_and_negation_scopes(self) -> None:
        config = CHECKER.validate_config(CHECKER.load_json(CONFIG_PATH))
        facts, authorities = CHECKER.evaluate_facts(ROOT, config)
        documents = CHECKER.synthetic_documents(
            "```yaml\nfixture: positive\nentryState:\n  website: connected\n```\n"
            "No real Probe means do not show Connected.\n"
            "Plugin target remains not implemented."
        )
        self.assertEqual(CHECKER.scan_documents(config, facts, authorities, documents), [])

    def test_negative_claim_taxonomy(self) -> None:
        config = CHECKER.validate_config(CHECKER.load_json(CONFIG_PATH))
        facts, authorities = CHECKER.evaluate_facts(ROOT, config)
        cases = {
            "catalog": ("The capability catalog is executable and production registered.", "CATALOG_AS_CAPABILITY"),
            "connected": ("Provider status: connected", "CONNECTED_WITH_EMPTY_REGISTRY"),
            "contradictory": ("Provider registrations: 0; status: connected.", "CONTRADICTORY_CLAIM"),
            "surface": ("A fixed dashboard is the central cockpit.", "FIXED_DASHBOARD_OR_COCKPIT"),
            "native": ("Fixture evidence passed as native production proof.", "NON_NATIVE_EVIDENCE_ESCALATED"),
            "lifecycle": ("Plugins are implemented with reversible mount/unmount lifecycle.", "PLUGIN_LIFECYCLE_UNPROVEN"),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label=label):
                drifts = CHECKER.scan_documents(config, facts, authorities, CHECKER.synthetic_documents(text))
                self.assertIn(expected, {drift["code"] for drift in drifts})

    def test_duplicate_and_missing_claims_fail_closed(self) -> None:
        config = CHECKER.validate_config(CHECKER.load_json(CONFIG_PATH))

        duplicate = copy.deepcopy(config)
        duplicate["claims"].append(copy.deepcopy(duplicate["claims"][0]))
        with self.assertRaises(CHECKER.TruthError) as duplicate_error:
            CHECKER.validate_config(duplicate)
        self.assertEqual(duplicate_error.exception.code, "DUPLICATE_CLAIM_ID")

        missing = copy.deepcopy(config)
        missing["claims"] = missing["claims"][:-1]
        with self.assertRaises(CHECKER.TruthError) as missing_error:
            CHECKER.validate_config(missing)
        self.assertEqual(missing_error.exception.code, "MISSING_CLAIM")

    def test_cli_json_and_self_test_exit_taxonomy(self) -> None:
        verify = subprocess.run(
            [sys.executable, str(SCRIPT), "verify"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(verify.returncode, 0)
        verify_json = json.loads(verify.stdout)
        self.assertEqual(verify_json["schema"], "hartevo.doc-plugin-truth-verification/v1")
        self.assertEqual(verify_json["status"], "VERIFIED")
        self.assertNotIn("content", verify_json)
        self.assertNotIn("matches", verify_json)

        self_test = subprocess.run(
            [sys.executable, str(SCRIPT), "self-test"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(self_test.returncode, 0)
        self.assertEqual(json.loads(self_test.stdout)["status"], "SELF_TEST_VERIFIED")


if __name__ == "__main__":
    unittest.main()
