"""Controls for one exact, independently attributed adverse check on a hosted commit."""

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from authority import Decision, framed
from forge import CHECK
from forge_delivery import deliver, sole_main

CANDIDATE = "c" * 40
TRUST = {"candidate": CANDIDATE, "repositoryId": 17}
BODY = {
    "name": CHECK,
    "head_sha": CANDIDATE,
    "status": "completed",
    "conclusion": "failure",
    "external_id": "refused:" + "a" * 64,
    "output": {
        "title": "Recorded adverse measurements",
        "summary": "One of two comparable measured cells worsened.",
    },
}


class Presenter:
    def __init__(self, body=BODY):
        self.body = body
        self.observed = False
        self.posts = 0
        self.ref = None

    def live(self, readback):
        if self.observed:
            return {
                "result": "verified-failure-readback"
                if readback
                else "already-reported",
                "checkRunId": 71,
            }
        if readback:
            raise Decision("refusal.check", "missing")
        return {
            "result": "proposal",
            "appId": 37,
            "body": dict(self.body),
            "validBefore": 150,
        }

    def post(self, body):
        self.posts += 1
        self.observed = True
        return {"id": 71, "head_sha": body["head_sha"], "app": {"id": 37}}

    def execute(self, d, approval=None, post=None):
        return deliver(
            d,
            TRUST,
            approval or framed(self.body),
            self.live,
            post or self.post,
            lambda: self.ref,
            clock=lambda: 145,
        )


class DeliveryTests(unittest.TestCase):
    def test_once_idempotent_and_owned_readback(self):
        op = Presenter()
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            first = op.execute(d)
            after = op.execute(d)
            self.assertEqual(first["checkRunId"], after["checkRunId"])
            self.assertEqual(op.posts, 1)
            self.assertIsNone(first["refBefore"])
            self.assertIsNone(first["refAfter"])
            self.assertEqual(len(list((d / "hosted-refusals").glob("*.json"))), 2)

    def test_wrong_approval_success_or_other_candidate_never_posts(self):
        for body, approval in (
            (BODY, "b" * 64),
            ({**BODY, "conclusion": "success"}, None),
            ({**BODY, "head_sha": "d" * 40}, None),
            ({**BODY, "external_id": "admitted:1"}, None),
        ):
            with (
                self.subTest(body=body, approval=approval),
                tempfile.TemporaryDirectory() as t,
            ):
                op = Presenter(body)
                with self.assertRaisesRegex(Decision, "delivery.approval"):
                    op.execute(Path(t), approval)
                self.assertEqual(op.posts, 0)
        with tempfile.TemporaryDirectory() as t:
            op = Presenter()
            with self.assertRaisesRegex(Decision, "delivery.expiry"):
                deliver(
                    Path(t),
                    TRUST,
                    framed(BODY),
                    op.live,
                    op.post,
                    lambda: None,
                    clock=lambda: 151,
                )
            self.assertEqual(op.posts, 0)

    def test_uncertain_delivery_never_retries_post(self):
        op = Presenter()
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t)

            def interrupted(_):
                op.posts += 1
                raise OSError("response was lost")

            with self.assertRaises(OSError):
                op.execute(directory, post=interrupted)
            with self.assertRaisesRegex(Decision, "delivery.uncertain"):
                op.execute(directory)
            self.assertEqual(op.posts, 1)
            op.observed = True
            self.assertEqual(
                op.execute(directory)["submission"], "previous exact result confirmed"
            )
            self.assertEqual(op.posts, 1)

    def test_foreign_responder_and_concurrent_ref_do_not_confirm(self):
        op = Presenter()
        with (
            tempfile.TemporaryDirectory() as t,
            self.assertRaisesRegex(Decision, "delivery.response"),
        ):
            op.execute(Path(t), post=lambda body: {**op.post(body), "app": {"id": 88}})
        op = Presenter()

        def moved(body):
            response = op.post(body)
            op.ref = "a" * 40
            return response

        with (
            tempfile.TemporaryDirectory() as t,
            self.assertRaisesRegex(Decision, "delivery.confirm"),
        ):
            op.execute(Path(t), post=moved)

    def test_ref_prefix_is_not_the_canonical_ref(self):
        class API:
            def __init__(self, rows):
                self.rows = rows

            def get(self, path):
                assert path == "/repos/fixture/project/git/matching-refs/heads/main"
                return self.rows

        self.assertIsNone(
            sole_main(API([{"ref": "refs/heads/main-extra"}]), "fixture/project")
        )
        self.assertEqual(
            sole_main(
                API(
                    [
                        {
                            "ref": "refs/heads/main",
                            "object": {"type": "commit", "sha": CANDIDATE},
                        }
                    ]
                ),
                "fixture/project",
            ),
            CANDIDATE,
        )
