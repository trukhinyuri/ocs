"""Exercise the actual independent caller and authenticated reference HTTP service."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class InteractionReferenceTests(unittest.TestCase):
    def observe(self, name):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "observation.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "assurance/interaction/probe.py",
                    "--mode",
                    "runtime",
                    "--check",
                    name,
                    "--report",
                    str(report),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=35,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            (row,) = json.loads(report.read_bytes())["checks"]
            self.assertEqual((row["id"], row["status"]), (name, "pass"))
            return row["observed"]

    def test_retired_instance(self):
        seen = self.observe("interaction.lifecycle")
        self.assertGreater(seen["replacement"]["generation"], seen["before"]["generation"])
        self.assertEqual((seen["replacement"]["streams"], seen["replacement"]["panels"]), (0, 0))
        self.assertEqual(seen["read"]["state"], "ready")

    def test_credit_and_terminal_outcome(self):
        seen = self.observe("interaction.stream")
        self.assertEqual((seen["creditPause"]["credit"], seen["creditPause"]["sent"]), (0, 1))
        self.assertEqual(seen["ordinals"], [1, 2, 3])
        self.assertEqual(seen["terminal"]["data"], {"chunks": 3})
        self.assertEqual(seen["committedOutcome"], "applied")
        self.assertEqual(seen["uncertainOutcome"], "unknown")
