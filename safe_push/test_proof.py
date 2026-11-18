"""Public admission contract, including concrete negative kernel proofs and a data binding fault."""

import base64
import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from safe_push import proof
from safe_push.proof import REQUIRED_FACTS, AdmissionError, certify, replay_certificate


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


def metric(direction, value, scope="32 reads at four clients"):
    return {"direction": direction, "condition": digest(scope), "value": value}


def example(width=40):
    shared = {
        "availability": digest("works on the admitted input domain"),
        'decode/λ"\\\n': digest("opaque UTF-8 identifiers retain leading zero bytes"),
    }
    return {
        "previous_claims": shared.copy(),
        "current_claims": shared.copy(),
        "previous_metrics": {
            "latency": metric("min", "9.10000000000000000000001"),
            "capacity": metric("max", "1.25"),
        },
        "current_metrics": {
            "latency": metric("min", "9.10000000000000000000000"),
            "capacity": metric("max", "1.250001"),
        },
        "parent": "0" + "1" * (width - 1),
        "actual_parent": "0" + "1" * (width - 1),
        "candidate": "2" * width,
        "tree": "3" * width,
        "facts": {name: True for name in REQUIRED_FACTS},
    }


class AdmissionProofTests(unittest.TestCase):
    def expect_refusal(self, args, criterion, status, proved=True):
        with self.assertRaises(AdmissionError) as refused:
            certify(**args)
        observed = refused.exception
        self.assertEqual((criterion, status), (observed.criterion, observed.outcome))
        if proved:
            self.assertEqual(criterion, observed.certificate["criterion"])
            self.assertIn(
                "SafePushCandidate.consequence",
                observed.certificate["kernel"]["theorems"],
            )
        else:
            self.assertIsNone(observed.certificate)

    def test_real_accepted_additions_and_exact_domains(self):
        args = example(64)
        args["current_claims"]["free extension"] = digest("new meaning")
        args["current_metrics"]["signed score"] = metric("max", "-1.00e-9")
        result = certify(**args)
        self.assertEqual(
            ("accepted", "pass", args["tree"]),
            (result["verdict"], result["status"], result["tree"]),
        )
        self.assertEqual(64, len(result["inputSha256"]))
        raw = zlib.decompress(base64.b64decode(result["witness"]["data"]))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result["inputSha256"])
        self.assertEqual(json.loads(raw)["previousClaims"], args["previous_claims"])
        kernel = result["kernel"]
        for name in (
            "SafePushCandidate.checked",
            "SafePush.exact_commit",
            "SafePush.history_journal",
            "SafePush.stale_competing_parent",
            "SafePush.arbitrary_history",
            "SafePush.revoke_blocks",
        ):
            self.assertIn(name, kernel["theorems"])
        self.assertGreater(kernel["checkedDeclarations"], len(kernel["theorems"]))

    def test_changed_semantics_and_removed_claim_have_concrete_refusals(self):
        for replacement in (None, digest("only a smaller population works")):
            args = example()
            if replacement is None:
                del args["current_claims"]["availability"]
            else:
                args["current_claims"]["availability"] = replacement
            with self.subTest(replacement=replacement):
                self.expect_refusal(args, "claim:availability", "rejected")

    def test_each_metric_uses_its_exact_value_direction_and_condition(self):
        args = example()
        old = args["previous_metrics"]["latency"]
        cases = (
            metric("min", "9.10000000000000000000002"),
            metric("max", old["value"]),
            metric("min", "1", "only one read"),
            None,
        )
        for replacement in cases:
            args = example()
            if replacement:
                args["current_metrics"]["latency"] = replacement
            else:
                del args["current_metrics"]["latency"]
            with self.subTest(replacement=replacement):
                self.expect_refusal(args, "metric:latency", "rejected")
        args = example()
        args["current_metrics"]["capacity"] = metric("max", "1.249999999999999999999")
        self.expect_refusal(args, "metric:capacity", "rejected")

    def test_each_required_fact_and_actual_parent(self):
        args = example()
        args["facts"]["fresh"] = False
        self.expect_refusal(args, "fact:fresh", "undetermined")
        args = example()
        args["facts"]["noCounterexample"] = False
        self.expect_refusal(args, "fact:noCounterexample", "rejected")
        for name in REQUIRED_FACTS:
            args = example()
            del args["facts"][name]
            with self.subTest(name=name):
                self.expect_refusal(args, "fact:" + name, "undetermined", proved=False)
        args = example()
        args["facts"]["skip"] = True
        self.expect_refusal(args, "evidence.facts", "undetermined", proved=False)
        args = example()
        args["actual_parent"] = "4" * 40
        self.expect_refusal(args, "reference.update", "rejected")

    def test_invalid_oid_and_unordered_numeric_inputs_hold(self):
        for field, oid in (
            ("tree", "3" * 64),
            ("actual_parent", "0" * 40),
            ("candidate", "HEAD"),
        ):
            args = example()
            args[field] = oid
            self.expect_refusal(args, "reference.update", "undetermined", proved=False)
        for value in ("NaN", "Infinity", False, 1.25, "0x55"):
            args = example()
            args["current_metrics"]["latency"]["value"] = value
            self.expect_refusal(
                args, "performance.encoding", "undetermined", proved=False
            )
        args = example()
        args["current_metrics"]["latency"]["value"] = "1e100000000000"
        self.expect_refusal(args, "verification.cost", "undetermined", proved=False)

    def test_lean_received_all_rows_even_if_translator_drops_a_passing_row(self):
        args = example()
        original = proof._tree

        def missing(old, new, literal):
            if "availability" in old:
                old = {k: v for k, v in old.items() if k != "availability"}
                new = {k: v for k, v in new.items() if k != "availability"}
            return original(old, new, literal)

        with patch.object(proof, "_tree", side_effect=missing):
            self.expect_refusal(args, "proof.encoding", "undetermined", proved=False)

    def test_substituted_prover_manifest_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text('{"axioms":["invented"]}')
            with patch.dict("os.environ", {"SAFE_PUSH_TOOLCHAIN_MANIFEST": str(path)}):
                self.expect_refusal(
                    example(), "proof.toolchain", "undetermined", proved=False
                )

    def test_exact_certificate_changes_when_only_the_git_tree_changes(self):
        args = example()
        first = certify(**args)
        args["tree"] = "4" * 40
        second = certify(**args)
        self.assertNotEqual(first["inputSha256"], second["inputSha256"])
        self.assertNotEqual(
            first["kernel"]["instanceSha256"], second["kernel"]["instanceSha256"]
        )
        self.assertNotEqual(
            first["kernel"]["proofSha256"], second["kernel"]["proofSha256"]
        )

    def test_portable_witness_replays_against_independently_supplied_inputs(self):
        args = example()
        issued = certify(**args)
        self.assertEqual(issued, replay_certificate(issued, **args))
        changed = {**issued, "witness": {**issued["witness"], "data": "forged"}}
        with self.assertRaisesRegex(AdmissionError, "proof.receipt"):
            replay_certificate(changed, **args)


if __name__ == "__main__":
    unittest.main()
