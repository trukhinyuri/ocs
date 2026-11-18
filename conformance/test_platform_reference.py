"""Check the bounded reference cell, real outage and fenced recovery work."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PlatformReferenceTests(unittest.TestCase):
    def test_cell_capacity_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "observations.json"
            process = subprocess.run(
                [
                    sys.executable,
                    "assurance/platform/probe.py",
                    "--mode",
                    "runtime",
                    "--check",
                    "platform.capacity",
                    "--check",
                    "platform.partition",
                    "--report",
                    str(report),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            rows = {
                r["id"]: r["observed"]
                for r in json.loads(report.read_bytes())["checks"]
                if r["status"] == "pass"
            }
            capacity, partition = rows["platform.capacity"], rows["platform.partition"]
            self.assertEqual(len(capacity["boundLatencyNs"]), 32)
            self.assertLessEqual(capacity["stats"]["peak"], 4)
            self.assertGreaterEqual(capacity["stats"]["rejected"], 1)
            self.assertEqual(partition["reconciledOutcome"], "unknown")
            self.assertTrue(partition["sameOperationId"])
            self.assertLess(partition["restartToScopedReadNs"], 5_000_000_000)
