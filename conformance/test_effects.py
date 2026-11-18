"""Read the real fixture balances across lost replies and conflicting commits."""

import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/reset"))
sys.path.insert(0, str(ROOT / "reference"))
from contracts import validate
from ledger import Ledger, Refused

PIN = "a" * 64
T = 1_893_456_000


class EffectTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "state.db"
        self.store = Ledger(self.file)
        self.store.add_fixture_account("owner", "trial")
        self.proposal = self.prepare()
        self.operation = self.proposal["operationId"]
        self.digest = self.proposal["intentDigest"]

    def prepare(self, key="reset-a", pin=PIN, revision=1):
        return self.store.prepare("owner", "trial", key, pin, revision, T)

    def approve(self):
        self.store.record_approval("owner", self.operation, self.digest, T + 1)

    def commit(self, owner="owner", digest=None, pin=PIN, when=T + 2):
        return self.store.commit(owner, self.operation, digest or self.digest, pin, when)

    def test_prepare_is_inert_stable_and_scoped(self):
        validate("profile-wire", self.proposal, "proposal")
        self.assertEqual(self.prepare(), self.proposal)
        self.assertEqual(self.store.balance("owner", "trial"), (1, 0, 1))
        with self.assertRaisesRegex(Refused, "conflict"):
            self.prepare(pin="b" * 64)
        with self.assertRaisesRegex(Refused, "denied"):
            self.commit()
        self.assertEqual(
            self.store.readback("owner", self.operation, T + 3)["state"], "not-applied"
        )

    def test_changed_scope_grant_pin_and_expiry_are_denied(self):
        self.approve()
        for kw, kind in [
            ({"owner": "visitor"}, "denied"),
            ({"digest": "c" * 64}, "conflict"),
            ({"pin": "b" * 64}, "pin"),
            ({"when": T + 60}, "deadline"),
        ]:
            with self.assertRaisesRegex(Refused, kind):
                self.commit(**kw)
        with self.assertRaisesRegex(Refused, "denied"):
            self.store.readback("visitor", self.operation, T + 2)
        self.store.set_write_grant("owner", "trial", False)
        with self.assertRaisesRegex(Refused, "denied"):
            self.commit()
        self.assertEqual(self.store.balance("owner", "trial"), (1, 0, 1))

    def test_disconnect_then_reopen_and_replay(self):
        self.approve()
        self.commit()  # Caller loses the reply.
        self.store = Ledger(self.file)
        receipt = self.store.readback("owner", self.operation, T + 300)
        validate("profile-data", receipt, "effectReceipt")
        self.assertEqual(receipt["state"], "applied")
        self.assertEqual(self.commit(when=T + 600), receipt)
        self.assertEqual(self.store.balance("owner", "trial"), (0, 100, 2))

    def test_concurrent_duplicate_and_competing_proposal(self):
        other = self.prepare(key="competing")
        self.store.record_approval("owner", other["operationId"], other["intentDigest"], T + 1)
        self.approve()
        barrier = threading.Barrier(2, timeout=5)

        def attempt():
            barrier.wait()
            return self.commit()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = [pool.submit(attempt) for _ in range(2)]
            self.assertEqual(first.result(), second.result())
        with self.assertRaisesRegex(Refused, "conflict"):
            self.store.commit("owner", other["operationId"], other["intentDigest"], PIN, T + 3)
        self.assertEqual(self.store.balance("owner", "trial"), (0, 100, 2))
