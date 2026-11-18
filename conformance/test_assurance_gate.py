"""A passing sibling observation cannot conceal a failed or missing published witness."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance"))
from trust import admit_reports, save


class AssuranceGateTests(unittest.TestCase):
    def test_every_required_witness_must_pass_for_its_cell(self):
        atom = "test.guarantee"
        subject = {"treeSha256": "a" * 64}
        catalog = {
            atom: {
                "rule": "test",
                "expected": "Observe both endpoints.",
                "scope": "host",
                "profile": "core",
                "scenarios": ["fixture"],
                "levels": ["reference"],
            }
        }
        required = {f"suite/{name}@runtime-observation": [atom] for name in ("first", "second")}
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "suite.json"

            def verdict(status):
                rows = [
                    {
                        "id": "first",
                        "level": "runtime-observation",
                        "claims": [atom],
                        "status": "pass",
                        "observed": "response A",
                    }
                ]
                if status:
                    rows.append(
                        {
                            "id": "second",
                            "level": "runtime-observation",
                            "claims": [atom],
                            "status": status,
                            "observed": "response B",
                        }
                    )
                data = {"checks": rows, "scope": "fixture"}
                save(path, data)
                out = admit_reports(
                    catalog, {"suite": (data, path, ["fixture"])}, subject, True, required
                )
                return out["status"], out["obligations"][0]["levels"]["reference"]["status"]

            self.assertEqual(verdict("pass"), ("pass", "accepted"))
            self.assertEqual(verdict(None), ("fail", "open"))
            self.assertEqual(verdict("fail"), ("fail", "failed"))
            self.assertEqual(verdict("skipped"), ("fail", "failed"))
