"""Public entry-point regressions for provider routing and durable metering."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance/provider"))
from check import BASE, MODEL, ROUTE, Client, local_admin
from contracts import utc_at


class ProviderReferenceTests(unittest.TestCase):
    def test_requested_model_and_mode(self):
        with tempfile.TemporaryDirectory() as folder, Client(Path(folder) / "db") as client:
            account = client.connect()["account"]["accountId"]
            for tier in ("standard", "fast"):
                options = {"reasoning": "off", "tier": tier}
                request = client.request(account, "Name the colour of a fern.", parameters=options)
                response = client.call("model.generate", request, key=tier)
                self.assertEqual(
                    (response["accountId"], response["route"], response["model"]),
                    (account, ROUTE, MODEL),
                )
                self.assertEqual(response["sent"], options)
                self.assertEqual(response["confirmed"], options)
                self.assertEqual(response["parts"], [{"type": "text", "text": "green"}])
            invalid = client.request(
                account, "fern", parameters={"reasoning": "off", "tier": "ultrafast"}
            )
            client.call("model.generate", invalid, expect="incompatible", key="unmapped")
            client.call(
                "model.generate",
                client.request(account, "fern", route="another"),
                expect="denied",
                key="foreign",
            )

    def test_meter_terms_and_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "primary"
            restored = Path(folder) / "backup"
            with Client(db) as client:
                account = client.connect()["account"]["accountId"]
                terms = client.call("example.product.terms", {"accountId": account})
                self.assertEqual(
                    (terms["owner"], terms["basis"], terms["currency"]),
                    ("alpha", "organization", "USD"),
                )
                event = (account, "example.units", "settled-once", "sample-day", 2, 15, BASE - 60)
                self.assertTrue(local_admin(db, "alpha", "meter", *event)["added"])
                query = {
                    "scope": {"kind": "account", "id": account},
                    "from": utc_at(BASE - 120),
                    "to": utc_at(BASE + 1),
                }
                self.assertEqual(
                    client.call("usage.read", query)["spend"], {"amount": "0.3", "currency": "USD"}
                )
                backup = local_admin(db, "alpha", "backup", restored)
                self.assertGreaterEqual(
                    backup["availableBytesBeforeBackup"], backup["requiredBytes"]
                )
            with Client(restored) as client:
                self.assertFalse(local_admin(restored, "alpha", "meter", *event)["added"])
                self.assertEqual(
                    client.call("usage.read", query)["spend"], {"amount": "0.3", "currency": "USD"}
                )
            with Client(restored, principal="another") as outsider:
                outsider.call("usage.read", query, expect="denied")
