"""Public entry-point regressions for provider routing and durable metering."""

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance/provider"))
from check import BASE, MODEL, PRODUCT_ARGS, ROUTE, Client, local_admin
from contracts import utc_at


class ProviderReferenceTests(unittest.TestCase):
    def test_expired_pages_release_storage_and_live_pages_survive_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "provider.sqlite"
            restored = Path(directory) / "restored.sqlite"
            first_tokens = {}
            for owner in ("alpha", "beta"):
                with Client(store, principal=owner, clock=BASE) as client:
                    for number in range(3):
                        client.connect(f"Account {number}")
                    first_page = client.call("account.list", PRODUCT_ARGS)
                    first_tokens[owner] = first_page["nextPageToken"]
            with Client(store, clock=BASE + 89) as client:
                live_token = client.call("account.list", PRODUCT_ARGS)["nextPageToken"]
                last_page = client.call(
                    "account.list", {**PRODUCT_ARGS, "pageToken": first_tokens["alpha"]}
                )
                self.assertTrue(last_page["complete"])
            with Client(store, clock=BASE + 90) as client:
                client.call("account.list", PRODUCT_ARGS)
                client.call(
                    "account.list", {**PRODUCT_ARGS, "pageToken": first_tokens["alpha"]}, "conflict"
                )
                live_page = {**PRODUCT_ARGS, "pageToken": live_token}
                still_live = client.call("account.list", live_page)
            with closing(sqlite3.connect(store)) as db:
                remaining = {row[0] for row in db.execute("SELECT id FROM cursors")}
            self.assertNotIn(first_tokens["alpha"], remaining)
            self.assertIn(first_tokens["beta"], remaining)
            self.assertIn(live_token, remaining)
            local_admin(store, "alpha", "backup", restored, clock=BASE + 90)
            with Client(restored, clock=BASE + 90) as client:
                recovered = client.call("account.list", live_page)
                self.assertEqual(recovered, still_live)
            with Client(restored, principal="beta", clock=BASE + 89) as client:
                other_page = client.call(
                    "account.list", {**PRODUCT_ARGS, "pageToken": first_tokens["beta"]}
                )
                self.assertTrue(other_page["complete"])

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
