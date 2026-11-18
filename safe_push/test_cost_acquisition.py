"""Independent one-shot baseline acquisition using a real protected prepare on a disposable reference target."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cost_acquisition as acquisition
from admission import state
from authority import ROLES, Decision, canonical, framed, immutable, load, signature
from cost import platform_conditions
from evolution import evolution_scope, evolution_signature_payload
from operator_cli import install, rotate
from test_receiver import BASE, Experiment, append_note, git


class CostAcquisitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srcdir = tempfile.TemporaryDirectory()
        cls.src = Path(cls.srcdir.name)
        git(cls.src, "init", "-b", "main")
        for path in acquisition.SOURCE_PATHS:
            dest = cls.src / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE.parent / path, dest)
        git(cls.src, "add", ".")
        git(cls.src, "commit", "-m", "Intentional isolated incumbent source fixture")
        cls.rev = git(cls.src, "rev-parse", "HEAD")
        cls.identity = acquisition.source_identity(cls.src, cls.rev)

    @classmethod
    def tearDownClass(cls):
        cls.srcdir.cleanup()

    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix="ocs-cost-enrollment-")
        self.addCleanup(t.cleanup)
        self.w = Path(t.name)
        exp = Experiment(self.w, HERE.parent)
        self.exp = exp
        old = copy.deepcopy(exp.policy)
        old["receiverCost"] = None
        sha = acquisition.sha((HERE / "cost_acquisition.py").read_bytes())
        old["predicateCheckers"]["first-cost"] = {
            "sha256": sha,
            "requirements": ["evolution/receiver-cost"],
            "pathPrefixes": ["policy/receiverCost"],
        }
        policy = self.w / "p0.json"
        immutable(policy, canonical(old))
        methods = list((exp.a / "methods").glob("*.py")) + [
            HERE / "cost_acquisition.py"
        ]
        cfg = install(
            self.w / "phased",
            HERE.parent,
            policy,
            self.w / "bootstrap",
            [],
            methods,
            exp.keydir / "publisher.key",
            None,
        )
        exp.config = cfg
        exp.cfg, exp.a, exp.j, exp.bare, exp.policy = state(cfg)
        self.old = old
        self.proto = {
            "format": "ocs.safe-push.cost-protocol/1",
            "incumbentRevision": self.rev,
            "incumbentSourceSha256": framed(self.identity),
            "platformSha256": framed(platform_conditions()),
            "conditions": {
                "target": "isolated fixture-only stdio target",
                "workload": "same genuine four-frame public status",
                "cache": "fresh verifier process",
                "concurrency": "one receive lock",
                "observer": "disposable protected publisher",
                "uncertainty": "raw frozen measurements only",
                "exclusions": "none",
            },
            "ceilings": "first-eligible-observation",
        }

    def eligible(self, title, review):
        e = self.exp
        c = e.candidate(BASE, title, append_note(title))
        e.stage(c)
        if review:
            e.reviews(BASE, c)
        ctx, _, _ = acquisition.plan_for(
            e.cfg, e.a, e.j, e.bare, self.old, c, self.proto, self.src
        )
        now = datetime.now(UTC)
        body = {
            **ctx,
            "issuedAt": (now - timedelta(seconds=1)).isoformat(),
            "expiresAt": (now + timedelta(minutes=10)).isoformat(),
        }
        return c, {
            "payload": body,
            "signatures": {
                r: signature({**body, "role": r}, e.keydir / (r + ".key"))
                for r in ROLES
            },
        }

    def objects(self, home):
        def obj(x):
            raw = canonical(x)
            k = acquisition.sha(raw)
            immutable(home / k, raw)
            return k

        return obj

    def evolve(self, reported):
        e = self.exp
        old = self.old
        new = copy.deepcopy(old)
        new["epoch"] = 1
        new["receiverCost"] = reported["registration"]
        store = e.a / "evolution/objects"
        obj = self.objects(store)
        home = e.j / "cost-acquisitions" / e.cfg["genesisDigest"]
        for sha in reported["artifacts"].values():
            immutable(store / sha, (home / "objects" / sha).read_bytes())
        scope = framed(evolution_scope(old, new))
        subjects = {}
        for side, policy in (("old", old), ("new", new)):
            subjects[side] = obj(
                {
                    "format": "ocs.safe-push.policy-subject/1",
                    "policySha256": framed(policy),
                    "assuranceRevision": policy["assurancePin"],
                    "epoch": policy["epoch"],
                    "data": {"workload": "registered finite fixture"},
                    "artifacts": reported["artifacts"] if side == "new" else {},
                }
            )
        purpose = "evolution/receiver-cost"
        proof = {
            "format": "ocs.safe-push.evolution-proof/1",
            "purpose": purpose,
            "scopeSha256": scope,
            "subjects": subjects,
        }
        good = obj({**proof, "body": reported["proofBody"]})
        adverse = copy.deepcopy(reported["proofBody"])
        adverse["observed"]["inputBlocks"] += 1
        bad = obj({**proof, "body": adverse})
        packet = {
            "format": "ocs.safe-push.policy-control/1",
            "scopeSha256": scope,
            "parent": BASE,
            "actualParent": BASE,
            "candidate": "f" * 40,
            "ageSeconds": 5,
            "serviceSeconds": 3,
            "targetConditions": {k: v["conditions"] for k, v in new["targets"].items()},
            "costs": reported["registration"]["ceilings"],
            "criterion": None,
            "refutations": {},
        }
        ev = {
            "format": "ocs.safe-push.evolution/1",
            "scopeSha256": scope,
            "subjects": subjects,
            "controls": {
                "positive": obj(packet),
                "refusal": obj(
                    {
                        **packet,
                        "actualParent": "a" * 40,
                        "criterion": "reference.parent",
                        "refutations": {purpose: bad},
                    }
                ),
            },
            "proofs": {purpose: {"method": "first-cost", "artifact": good}},
        }
        payload = evolution_signature_payload(old, new, ev)
        record = {"policy": new, "evolution": ev}
        for side in ("old", "new"):
            record[side] = {
                r: signature(
                    {**payload, "role": r, "side": side}, e.keydir / (r + ".key")
                )
                for r in ROLES
            }
        path = self.w / "elected.json"
        immutable(path, canonical(record))
        rotate(e.config, path)
        return new, home, record

    def test_first_eligible_prepare_owns_the_initial_reference_without_resetting_genesis(
        self,
    ):
        e = self.exp
        c, auth = self.eligible("qualified-sample", True)
        prefs = e.a / "genesis.json"
        original = prefs.read_bytes()
        proto_path = self.w / "protocol.json"
        auth_path = self.w / "approval.json"
        immutable(proto_path, canonical(self.proto))
        immutable(auth_path, canonical(auth))
        cmd = [
            sys.executable,
            "-I",
            "-B",
            str(HERE / "operator_cli.py"),
            "cost-acquire",
            str(e.config),
            c,
            str(proto_path),
            str(auth_path),
            "--incumbent-repo",
            str(self.src),
        ]
        p = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(p.returncode, 0, p.stderr.decode()[-900:])
        result = json.loads(p.stdout)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(set(result["artifacts"]), acquisition.LABELS)
        new, home, transition = self.evolve(result)
        baseline = acquisition.reference(e.cfg, e.a, e.j, new, load(prefs))
        self.assertEqual(
            framed(baseline), new["receiverCost"]["baselineEvidenceSha256"]
        )
        self.assertEqual(set(baseline["observed"]), acquisition.UNITS.keys())
        receipt = load(home / "objects" / result["artifacts"]["costReceipt"])
        self.assertEqual(receipt["candidate"], c)
        self.assertEqual(
            framed(receipt), baseline["acquisition"]["verifiedReceiptSha256"]
        )
        self.assertEqual(prefs.read_bytes(), original)
        self.assertEqual(git(e.bare, "rev-parse", "refs/heads/main"), BASE)
        follow = {
            "format": "ocs.safe-push.prepared/1",
            "candidate": "c" * 40,
            "receiverCost": {"status": "accepted", "observed": {"wallNs": 1}},
        }
        self.assertIs(
            acquisition.reference(e.cfg, e.a, e.j, new, follow), follow["receiverCost"]
        )
        # Strengthen the recorded success by one unit without changing its original samples.
        blobs = {k: load(home / "objects" / v) for k, v in result["artifacts"].items()}
        altered = copy.deepcopy(blobs)
        altered["costObservation"]["observed"]["wallNs"] -= 1
        with self.assertRaisesRegex(ValueError, "acquisition"):
            acquisition.verify_packet(self.old, new, altered)
        incorrect = copy.deepcopy(altered["costOutcome"]["payload"])
        incorrect["observationSha256"] = framed(altered["costObservation"])
        altered["costOutcome"] = signature(incorrect, e.keydir / "publisher.key")
        resigned = {
            **new,
            "receiverCost": acquisition.registration(
                self.old, self.proto, altered["costObservation"]
            ),
        }
        with self.assertRaisesRegex(ValueError, "raw samples"):
            acquisition.verify_packet(self.old, resigned, altered)
        wrong = copy.deepcopy(blobs)
        wrong["costReceipt"]["sourceSha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "acquisition"):
            acquisition.verify_packet(self.old, new, wrong)
        election = copy.deepcopy(transition)
        election["evolution"]["subjects"]["new"] = "0" * 64
        with self.assertRaises((ValueError, OSError)):
            acquisition.elected_material(e.cfg, e.a, e.j, self.old, new, election)

    def test_real_unreviewed_workload_stays_undetermined_and_same_tree_cannot_be_resampled(
        self,
    ):
        e = self.exp
        c, auth = self.eligible("missing-real-review", False)
        with self.assertRaises((ValueError, OSError)):
            acquisition.acquire(e.config, c, self.proto, auth, self.src)
        home = e.j / "cost-acquisitions" / e.cfg["genesisDigest"]
        slot = next((home / "attempts").iterdir())
        record = load(slot / "outcome.json")
        self.assertEqual(
            acquisition.auth(record, self.old["keys"]["publisher"])["status"],
            "undetermined",
        )
        self.assertIn("incompleteObservationSha256", record["payload"])
        self.assertFalse((home / "first-positive.json").exists())
        with self.assertRaisesRegex(Decision, "verification.cost.spent"):
            acquisition.acquire(e.config, c, self.proto, auth, self.src)
        self.assertEqual(git(e.bare, "rev-parse", "refs/heads/main"), BASE)

    def test_eligible_prepare_exceeding_a_preregistered_zero_wall_budget_is_a_retained_refusal(
        self,
    ):
        e = self.exp
        self.proto["ceilings"] = {k: 0 for k in acquisition.UNITS}
        candidate, auth = self.eligible("measured-ceiling-refusal", True)
        with self.assertRaisesRegex(Decision, "verification.cost.regression"):
            acquisition.acquire(e.config, candidate, self.proto, auth, self.src)
        home = e.j / "cost-acquisitions" / e.cfg["genesisDigest"]
        result = acquisition.auth(
            load(next((home / "attempts").glob("*/outcome.json"))),
            self.old["keys"]["publisher"],
        )
        self.assertEqual(result["status"], "rejected")
        measured = load(home / "objects" / result["objects"]["costObservation"])
        self.assertGreater(measured["observed"]["wallNs"], 0)
        self.assertTrue(any((e.j / "adverse" / auth["payload"]["tree"]).glob("*.json")))
        self.assertFalse((home / "first-positive.json").exists())

    def test_forged_election_or_different_incumbent_cannot_consume_a_sample(self):
        e = self.exp
        c, authorization = self.eligible("wrong-approval", False)
        mask = copy.deepcopy(authorization)
        mask["signatures"]["independent"] = mask["signatures"]["domain"]
        with self.assertRaisesRegex(ValueError, "acquisition"):
            acquisition.acquire(e.config, c, self.proto, mask, self.src)
        with self.assertRaisesRegex(ValueError, "incumbent source"):
            acquisition.acquire(
                e.config,
                c,
                {**self.proto, "incumbentSourceSha256": "b" * 64},
                authorization,
                self.src,
            )
        home = e.j / "cost-acquisitions" / e.cfg["genesisDigest"]
        self.assertFalse(home.exists())

    def test_interruption_preserves_a_spent_trial_after_restart(self):
        e = self.exp
        c, approval = self.eligible("interrupted-once", False)
        with (
            patch.object(acquisition, "_measured", side_effect=SystemExit(87)),
            self.assertRaises(SystemExit),
        ):
            acquisition.acquire(e.config, c, self.proto, approval, self.src)
        with self.assertRaisesRegex(Decision, "verification.cost.spent"):
            acquisition.acquire(e.config, c, self.proto, approval, self.src)
        home = e.j / "cost-acquisitions" / e.cfg["genesisDigest"]
        final = next((home / "attempts").glob("*/outcome.json"))
        self.assertEqual(
            acquisition.auth(load(final), self.old["keys"]["publisher"])["criterion"],
            "verification.cost.interrupted",
        )
        self.assertFalse((home / "first-positive.json").exists())


if __name__ == "__main__":
    unittest.main()
