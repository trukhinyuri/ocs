"""Participant A drives participant B only through the native OCS wire."""

import hashlib
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from contracts import utc_at, validate
from host import Channel, Failure


class DialogueTests(unittest.TestCase):
    def setUp(self):
        folder = ROOT / "examples/dialog"
        self.pin = hashlib.sha256((folder / "ocs.json").read_bytes()).hexdigest()
        self.peer = Channel(folder / "executor.py", budget=5)
        self.addCleanup(self.peer.close)
        self.deadline = utc_at(time.time() + 5)
        desc = self.peer.request(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.agents/0.1"],
                "meta": {"deadline": self.deadline},
            },
        )
        validate("wire", desc, "describeResult")
        self.assertEqual(desc["manifestDigest"], self.pin)
        self.assertEqual(desc["features"], ["ocs.agents/0.1"])

    def send(self, message):
        validate("profile-data", message, "message")
        result = self.peer.request(
            "tool.call",
            {
                "operation": "agent.exchange",
                "version": "1.0.0",
                "input": message,
                "meta": {"protocol": "0.1", "manifestDigest": self.pin, "deadline": self.deadline},
            },
        )
        validate("profile-wire", result["data"], "agentReply")
        answer = result["data"]["message"]
        self.assertEqual(answer["replyTo"], message["messageId"])
        return answer

    @staticmethod
    def message(mid, prompt, **options):
        return {
            "messageId": mid,
            "contextId": "conversation-a",
            "parts": [{"type": "text", "text": prompt}],
            "accept": ["text/plain"],
            **options,
        }

    def test_clarify_answer_and_return_fact(self):
        q = self.message("q1", "Read", budget={"remainingTurns": 3, "remainingBytes": 160})
        first = self.send(q)
        self.assertEqual(first["kind"], "clarification")
        self.assertEqual(first["budget"]["remainingTurns"], 2)
        q2 = self.message("q2", "Read demo", replyTo=first["messageId"], budget=first["budget"])
        fact = self.send(q2)
        self.assertEqual(fact["contextId"], q["contextId"])
        self.assertRegex(fact["parts"][0]["text"], r"^[0-9a-f]{16}$")
        self.assertEqual(self.send(q2), fact)
        final = self.send(
            self.message(
                "q3",
                "Confirm " + fact["parts"][0]["text"],
                replyTo=fact["messageId"],
                budget=fact["budget"],
            )
        )
        self.assertEqual(final["parts"][0]["text"], "confirmed")
        self.assertEqual(final["budget"]["remainingTurns"], 0)
        self.assertLess(final["budget"]["remainingBytes"], fact["budget"]["remainingBytes"])
        with self.assertRaises(Failure) as exp:
            self.send(self.message("q4", "Read demo", budget=final["budget"]))
        self.assertEqual(exp.exception.error["data"]["kind"], "busy")

    def test_conflicting_message_denial_and_required_modality(self):
        self.send(self.message("q", "Read demo"))
        probes = [
            (self.message("q", "Read"), "conflict"),
            (self.message("private", "Read other", senderLabel="administrator"), "denied"),
            (self.message("oversize", "Read demo", budget={"remainingBytes": 1}), "busy"),
            (self.message("image", "Read demo", accept=["image/png"]), "incompatible"),
        ]
        for message, expected in probes:
            with self.subTest(message=message["messageId"]), self.assertRaises(Failure) as error:
                self.send(message)
            self.assertEqual(error.exception.error["data"]["kind"], expected)
        self.assertEqual(self.send(self.message("final", "Read demo"))["kind"], "answer")
