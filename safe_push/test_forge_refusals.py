"""Verify bound adverse evidence and the failure-only hosted proposal."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forge_refusals as refusals
from authority import Decision, canonical, digest, framed
from forge import CHECK
from forge_apps import PERMISSIONS
from scope import change_requirements, inventory, subject

BASE = "3facf571910e0799539a77a1a5112e6609a9a5ca"
CANDIDATE = "2f722bc4337860f24e7a081ad9ee785f7c4291ad"
VERIFIER = "e09a5d7d0ae15d35910e72243c4a466974f09401"
GIT = HERE.parent


def sha(value):
    return digest(value.encode())


def metric(value, direction="min", condition=None):
    return {
        "direction": direction,
        "condition": condition or sha("fixed condition"),
        "value": str(value),
    }


def enrollment():
    return {
        "format": refusals.TRUST,
        "project": "ocs-fixture",
        "measurementProject": "measured-fixture",
        "repository": "fixture-owner/fixture-ocs",
        "repositoryId": 12,
        "ownerId": 18,
        "ownerType": "user",
        "expectedVisibility": "public",
        "target": "test-target",
        "stagingRef": "refs/heads/review/safe-push",
        "parent": BASE,
        "candidate": CANDIDATE,
        **{k: sha(k) for k in refusals.PIN_FIELDS},
    }


def reporter(t):
    return {
        "format": "ocs.safe-push.app-installation/1",
        "role": "reporter",
        "custodianUid": 801,
        **{k: t[k] for k in ("repository", "repositoryId", "ownerId", "ownerType")},
        "appId": 821,
        "installationId": 871,
        "clientId": "app-fixture",
        "slug": "fixture-checks",
        "permissions": PERMISSIONS["reporter"],
        "publicKeySha256": sha("public"),
        "repositoryVisibility": "public",
    }


class FakeReads:
    def __init__(self, t, who):
        self.repo = {
            "id": t["repositoryId"],
            "full_name": t["repository"],
            "owner": {
                "login": t["repository"].split("/")[0],
                "id": t["ownerId"],
                "type": "User",
            },
            "visibility": "public",
            "private": False,
            "default_branch": "review/safe-push",
            "archived": False,
            "disabled": False,
        }
        self.branch = {
            "object": {"type": "commit", "sha": CANDIDATE},
            "ref": t["stagingRef"],
        }
        self.branches = {self.branch["ref"]: self.branch}
        self.commit = {
            "sha": CANDIDATE,
            "tree": {"sha": "9" * 40},
            "parents": [{"sha": BASE}],
        }
        self.installation = {
            "id": who["installationId"],
            "app_id": who["appId"],
            "app_slug": who["slug"],
            "client_id": who["clientId"],
            "events": [],
            "account": self.repo["owner"].copy(),
            "target_id": t["ownerId"],
            "target_type": "User",
            "suspended_at": None,
            "repository_selection": "selected",
            "permissions": dict(PERMISSIONS["reporter"]),
        }
        self.runs = []
        self.statuses = []
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path.endswith("/installation"):
            return self.installation
        if "/git/ref/" in path:
            return self.branches.get("refs/" + path.split("/git/ref/", 1)[1], {})
        if "/git/commits/" in path:
            return self.commit
        if "/statuses?" in path:
            return self.statuses
        if "/check-runs?" in path:
            assert "filter=all" in path
            return {"total_count": len(self.runs), "check_runs": self.runs}
        assert path == "/repos/" + self.repo["full_name"]
        return self.repo


class HistoricalRefusalTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("OCS_HOSTED_REFUSAL_HISTORY"),
        "operator's two independently enrolled signed dossiers required",
    )
    def test_actual_filed_refusal_and_original_enrollment(self):
        from qualification import QualificationError

        root = Path(os.environ["OCS_HOSTED_REFUSAL_HISTORY"]).resolve()
        base = root / "out/acceptance/3facf571"
        release = root / "out/safe-push/2f722bc4"
        trust = {
            "format": refusals.TRUST,
            "project": "ocs",
            "measurementProject": "ocs-live-receiver-check",
            "repository": "trukhinyuri/ocs",
            "repositoryId": 1463085350,
            "ownerId": 1245379,
            "ownerType": "user",
            "expectedVisibility": "public",
            "target": "kubernetes",
            "stagingRef": "refs/heads/review/safe-push",
            "parent": BASE,
            "candidate": CANDIDATE,
            "releasePolicySha256": "950967dc641cbba8fc5c7178f5979e258e63ee83653f55af29478eb0654e72c5",
            "previousReceiptSha256": "c20332a9e5f88931182adf74fadf2fe1ef438dc67ef6688e43c2999c85ade2ee",
            "metricProfileSha256": "72f3f7545125079b9230e6410b882f1da39203553f99d72fa254b518c02a5858",
            "baseEnrollmentSha256": "f6cc2e2f4bd87016c1e89712b60b0d2f55348144b9691376d0ab960538a63495",
            "candidateEnrollmentSha256": "05b0cce83f25265c6f72dbf34532e62f6c90f383990496474960966d5ba961dc",
        }
        basis = release / "release-receipts"

        def verify():
            return refusals.adjudicate(
                trust,
                "238f5efcd1b37af7940b201f4a28dcf4b04de5678e9926b52a27b0433e6ec9cb",
                GIT,
                basis / "root.json",
                basis / "genesis.json",
                root / "out/qualification/full/runs/cc89ab8424f345e3af67f7e7179650af",
                base / "independent-enrollment.json",
                release / "qualification/full",
                release / "final-enrollment.json",
                base / "observer.pub",
            )

        if time.time() >= 1795106238.63914:
            with self.assertRaises((QualificationError, Decision)):
                verify()
        else:
            result = verify()
            self.assertEqual(
                (
                    result["requiredClaimLevels"],
                    result["compared"],
                    result["worse"],
                    result["equal"],
                    result["improved"],
                ),
                (394, 364, 210, 82, 72),
            )
            self.assertEqual(
                framed(result),
                "f497d4df65cc470e3e2518a796b146364a350918a7b31e204322d22f75e91fa8",
            )


class RefusalTests(unittest.TestCase):
    def test_comparable_strict_adverse_required_for_every_original_cell(self):
        old = {"a": metric(1), "b": metric(2, "max"), "c": metric(3)}
        got = refusals.compare(
            old,
            {
                "a": metric("1.0000000000000000001"),
                "b": metric(1, "max"),
                "c": metric(3),
            },
        )
        self.assertEqual((got["worse"], got["equal"], got["compared"]), (2, 1, 3))
        for candidate in (
            {"a": metric(2), "b": metric(1, "max")},
            {**old, "a": metric(2), "c": metric(2, "max")},
            {**old, "a": metric(2), "c": metric("NaN")},
            {**old, "a": metric(2), "c": metric(1, condition=sha("different"))},
        ):
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(Decision) as error,
            ):
                refusals.compare(old, candidate)
            self.assertIn(
                error.exception.criterion,
                ("refusal.incomplete", "refusal.incomparable"),
            )
        for candidate in (
            old,
            {"a": metric("0.9"), "b": metric(3, "max"), "c": metric(3)},
        ):
            with self.assertRaises(Decision) as error:
                refusals.compare(old, candidate)
            self.assertEqual(error.exception.criterion, "refusal.unproved")

    def test_offline_proposal_live_readback_and_idempotent_existing_failure(self):
        t = enrollment()
        who = reporter(t)
        api = FakeReads(t, who)
        raw = {
            **t,
            "format": refusals.RECEIPT,
            "verdict": "measured-regression",
            "enrollmentSha256": framed(t),
            "tree": "9" * 40,
            "worse": 3,
            "compared": 17,
            "requiredClaimLevels": 394,
            "validBefore": time.time() + 300,
        }

        def observed():
            return dict(raw)

        dry = refusals.draft(t, framed(t), who, framed(who), observed)
        self.assertEqual(api.calls, [])
        proposed = refusals.propose(api, api, t, framed(t), who, framed(who), observed)
        self.assertEqual(dry["body"], proposed["body"])
        self.assertEqual(
            (
                proposed["method"],
                proposed["body"]["name"],
                proposed["body"]["conclusion"],
            ),
            ("POST", CHECK, "failure"),
        )
        self.assertTrue(proposed["externalId"].startswith("refused:"))

        def not_yet():
            return refusals.propose(
                api, api, t, framed(t), who, framed(who), observed, readback=True
            )

        with self.assertRaises(Decision):
            not_yet()
        api.runs = [{**proposed["body"], "id": 71, "app": {"id": who["appId"]}}]
        self.assertEqual(
            refusals.propose(api, api, t, framed(t), who, framed(who), observed)[
                "result"
            ],
            "already-reported",
        )
        self.assertEqual(not_yet()["result"], "verified-failure-readback")
        for field, value in (
            ("external_id", "other evidence"),
            ("conclusion", "success"),
            ("app", {"id": 982}),
            ("output", {"title": "different", "summary": ""}),
            ("output", {**proposed["body"]["output"], "text": "unverified extra text"}),
            ("output", {**proposed["body"]["output"], "annotations_count": 1}),
        ):
            backup = api.runs[0]
            api.runs = [{**backup, field: value}]
            with self.subTest(field=field), self.assertRaises(Decision):
                not_yet()
            api.runs = [backup]
        api.runs *= 2
        with self.assertRaises(Decision):
            not_yet()
        api.runs = []
        api.statuses = [{"context": CHECK}]
        with self.assertRaises(Decision):
            not_yet()
        api.statuses = []
        api.installation["suspended_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            not_yet()
        api.installation["suspended_at"] = None
        api.branch["object"]["sha"] = BASE
        with self.assertRaises(Decision):
            not_yet()

    def test_measured_child_on_separate_review_branch_checks_both_refs(self):
        trust = {
            **enrollment(),
            "format": "ocs.safe-push.hosted-refusal-enrollment/2",
            "bootstrapRef": "refs/heads/review/safe-push",
            "bootstrapCommit": "8" * 40,
            "stagingRef": "refs/heads/review/corrected",
        }
        who = reporter(trust)
        api = FakeReads(trust, who)
        bootstrap = {
            "ref": trust["bootstrapRef"],
            "object": {"type": "commit", "sha": trust["bootstrapCommit"]},
        }
        api.branches[bootstrap["ref"]] = bootstrap
        receipt = {
            **trust,
            "format": refusals.RECEIPT,
            "verdict": "measured-regression",
            "enrollmentSha256": framed(trust),
            "tree": api.commit["tree"]["sha"],
            "worse": 1,
            "compared": 364,
            "requiredClaimLevels": 394,
            "validBefore": time.time() + 300,
        }

        def preview():
            return refusals.propose(
                api, api, trust, framed(trust), who, framed(who), lambda: receipt
            )

        for default in ("review/safe-push", "main"):
            with self.subTest(default=default):
                api.repo["default_branch"] = default
                body = preview()["body"]
                self.assertEqual(
                    (body["head_sha"], body["conclusion"]), (CANDIDATE, "failure")
                )
        api.repo["default_branch"] = "review/corrected"
        with self.assertRaisesRegex(Decision, "forge.repository"):
            preview()
        api.repo["default_branch"] = "review/safe-push"
        bootstrap["object"]["sha"] = BASE
        with self.assertRaisesRegex(Decision, "refusal.bootstrap"):
            preview()
        bootstrap["object"]["sha"] = trust["bootstrapCommit"]
        api.branch["object"]["sha"] = BASE
        with self.assertRaisesRegex(Decision, "refusal.staging"):
            preview()
        for key in ("bootstrapRef", "bootstrapCommit"):
            partial = dict(trust)
            del partial[key]
            with self.subTest(missing=key), self.assertRaises(Decision):
                refusals.registration(partial, framed(partial))
        old = {
            k: v
            for k, v in trust.items()
            if k not in ("bootstrapRef", "bootstrapCommit")
        }
        old["format"] = refusals.TRUST
        with self.assertRaisesRegex(Decision, "forge.repository"):
            refusals.host_state(api, api, old, who, receipt, "refused:fixture", {})

    def test_registered_owner_role_visibility_and_digest(self):
        t = enrollment()
        who = reporter(t)
        for k, v in (
            ("ownerId", 150),
            ("repositoryVisibility", "private"),
            ("role", "publisher"),
            ("permissions", PERMISSIONS["publisher"]),
            ("publicKeySha256", "unknown"),
            ("unregisteredIssuerField", "unexpected"),
        ):
            wrong = {**who, k: v}
            with self.subTest(k=k), self.assertRaises(ValueError):
                refusals.reporter_pin(t, wrong, framed(wrong))
        with self.assertRaises(Decision):
            refusals.registration(t, sha("wrong enrollment"))
        with self.assertRaises(Decision):
            refusals.reporter_pin(t, who, sha("different App"))

    def test_replayed_legacy_cells_are_bound_to_the_exact_git_and_registered_basis(
        self,
    ):
        # Only the signed-dossier backend is substituted in this control. Exercise real Git
        # objects, all published atomic IDs and the actual scope and public-key decoder.
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            t = enrollment()
            keys = {}
            for role in ("domain", "independent", "publisher", "guardian"):
                private = work / (role + ".key")
                subprocess.run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "ED25519",
                        "-out",
                        str(private),
                    ],
                    check=True,
                    capture_output=True,
                )
                keys[role] = subprocess.check_output(
                    ["openssl", "pkey", "-in", str(private), "-pubout"], text=True
                )
            observer = work / "observer.pub"
            observer.write_text(keys["guardian"])
            name = t["target"]
            condition = sha("externally selected target")
            key_hash = digest(observer.read_bytes())
            p = {
                "format": "ocs.safe-push.policy/1",
                "profile": "ocs-release/1",
                "project": t["measurementProject"],
                "epoch": 0,
                "genesis": BASE,
                "assurancePin": VERIFIER,
                "targets": {
                    name: {
                        "adapter": "ocs-dossier/1",
                        "conditions": condition,
                        "observerSha256": key_hash,
                    }
                },
                "keys": keys,
                "lifetimeSeconds": 86400,
                "receiveTimeoutSeconds": 60,
                "receiverCost": None,
                "requiredOpen": ["demo receives no positive publication"],
                "predicateCheckers": {},
                "adapters": {},
            }
            policy_path = work / "root.json"
            policy_path.write_bytes(canonical(p))
            inventories = [inventory(GIT, x) for x in (BASE, CANDIDATE)]
            ids = [
                subject(GIT, x, s)
                for x, s in zip((BASE, CANDIDATE), inventories, strict=True)
            ]
            levels = change_requirements(
                GIT, BASE, BASE, inventories[0], inventories[0]
            )["requirements"]["qualification.full"]["levels"]
            claims = {
                atom + "@" + lvl: sha(atom + "@" + lvl)
                for atom, ll in levels.items()
                for lvl in ll
            }
            old = {"claim": metric(1)}
            new = {"claim": metric(2)}
            seed = {
                "format": "ocs.safe-push.genesis/1",
                "candidate": BASE,
                "profile": p["profile"],
                "project": p["project"],
                "policy": framed(p),
                "tree": refusals.git(GIT, "rev-parse", BASE + "^{tree}"),
                "subject": ids[0],
                "wholeTreeSha256": framed(inventories[0]),
                "claims": {name + "/" + k: v for k, v in claims.items()},
                "metrics": {name + "/" + k: v for k, v in old.items()},
                "targetReports": {name: sha("base report")},
                "coverageLimits": {name: {}},
                "expiresEpoch": time.time() + 120,
            }
            seed_path = work / "genesis.json"
            seed_path.write_bytes(canonical(seed))
            dossiers = [work / "base-dossier", work / "candidate-dossier"]
            enrollments = [work / "base.json", work / "candidate.json"]
            for d, e in zip(dossiers, enrollments, strict=True):
                d.mkdir()
                e.write_bytes(canonical({"side": e.stem}))
            t.update(
                releasePolicySha256=framed(p),
                previousReceiptSha256=framed(seed),
                metricProfileSha256=digest((HERE / "metrics.json").read_bytes()),
                baseEnrollmentSha256=digest(enrollments[0].read_bytes()),
                candidateEnrollmentSha256=digest(enrollments[1].read_bytes()),
            )
            from datetime import UTC, datetime

            future = datetime.fromtimestamp(time.time() + 1000, UTC).isoformat()
            rows = [
                {
                    "subject": identity,
                    "scope": "fixture scoped original",
                    "claims": dict(claims),
                    "acceptedVerifier": VERIFIER,
                    "metricProfileSha256": t["metricProfileSha256"],
                    "targetConditionSha256": condition,
                    "metricGaps": [],
                    "controls": 3,
                    "witnesses": 5,
                    "reportSha256": sha(side + " report"),
                    "standReceiptSha256": sha(side + " stand"),
                    "coverageLimits": {},
                    "metrics": m,
                    "expiresAt": future,
                }
                for side, identity, m in zip(
                    ("base", "candidate"), ids, (old, new), strict=True
                )
            ]

            def check():
                with patch.object(refusals, "inspect_dossier", side_effect=rows):
                    return refusals.adjudicate(
                        t,
                        framed(t),
                        GIT,
                        policy_path,
                        seed_path,
                        dossiers[0],
                        enrollments[0],
                        dossiers[1],
                        enrollments[1],
                        observer,
                    )

            good = check()
            self.assertEqual(
                (good["verdict"], good["requiredClaimLevels"], good["worse"]),
                ("measured-regression", 394, 1),
            )
            for field, replacement in [
                ("metricGaps", ["required acquisition"]),
                ("targetConditionSha256", sha("another platform")),
                (
                    "claims",
                    {k: v for k, v in claims.items() if k != "W-06.recovery@reference"},
                ),
                ("scope", "another subject"),
                ("subject", ids[0]),
            ]:
                existing = rows[1][field]
                rows[1][field] = replacement
                with self.subTest(field=field), self.assertRaises(Decision):
                    check()
                rows[1][field] = existing
            substitute = {**seed, "metrics": {name + "/claim": metric("0.99")}}
            seed_path.write_bytes(canonical(substitute))
            t["previousReceiptSha256"] = framed(substitute)
            with self.assertRaisesRegex(Decision, "original observations"):
                check()


if __name__ == "__main__":
    unittest.main()
