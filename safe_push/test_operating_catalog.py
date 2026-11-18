"""Controls for public-role possession, carried obligations, adverse retention and offline replay."""

import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from safe_push import operating_catalog as op


class OperatingCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "archive"
        (self.archive / "custody").mkdir(parents=True)

    def role_fixture(self, duplicate=False):
        place = self.archive / "custody"
        roles = {}
        for i, name in enumerate(op.ROLES_ALL):
            key = self.root / (name + ".key")
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                capture_output=True,
                check=True,
            )
            public = subprocess.check_output(["openssl", "pkey", "-in", key, "-pubout"])
            (place / (name + ".pub")).write_bytes(public)
            roles[name] = {
                "uid": 7310 + i,
                "unixRole": "fixture-" + name,
                "purpose": "technical fixture custody only",
                "privateKeyMode": "0600",
                "privateStateMode": "0700",
                "publicKeyPemSha256": op.digest(public),
            }
        if duplicate:
            roles["guardian"]["uid"] = roles["publisher"]["uid"]
        registry = {
            "format": "ocs.operating-custody/1",
            "project": "ocs",
            "humanOwner": {"humanOwnerCount": 1, "login": "fixture", "id": 71},
            "nativeRoles": roles,
            "hostedApps": {
                "reporter": {"custodianUid": 7001},
                "publisher": {"custodianUid": 7002},
            },
        }
        sha = op.framed(registry)
        for f in ("custody.json", "custody-proposal.json"):
            (place / f).write_bytes(op.canonical(registry))
        chosen = {
            "format": "ocs.operating-custody-selection/1",
            "githubOwnerId": 71,
            "humanOwner": "fixture",
            "publicKeysSha256": sha,
            "selectedAt": "2026-11-18T12:00:00Z",
            "effect": "initial registration of public keys only",
            "canonicalPublicationAuthorized": False,
        }
        (place / "owner-selection.json").write_bytes(op.canonical(chosen))
        challenge = {
            "format": "ocs.key-possession-test/1",
            "project": "ocs",
            "proposal": sha,
            "purpose": "assert possession only",
            "nonce": "a" * 64,
        }
        (place / "possession-challenge.json").write_bytes(op.canonical(challenge))
        for n in op.ROLES_ALL:
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    self.root / (n + ".key"),
                    "-in",
                    place / "possession-challenge.json",
                    "-out",
                    place / (n + "-possession.sig"),
                ],
                capture_output=True,
                check=True,
            )
        return registry, sha

    def test_four_possession_records_have_only_the_selected_scope(self):
        registry, sha = self.role_fixture()
        checked, keys = op.custody(self.archive, sha)
        self.assertEqual(checked, registry)
        self.assertEqual(set(keys), set(op.ROLES_ALL))
        place = self.archive / "custody"
        original = (place / "domain-possession.sig").read_bytes()
        (place / "domain-possession.sig").write_bytes(
            (place / "guardian-possession.sig").read_bytes()
        )
        with self.assertRaises(ValueError):
            op.custody(self.archive, sha)
        (place / "domain-possession.sig").write_bytes(original)
        approval = op.load(place / "owner-selection.json")
        approval["canonicalPublicationAuthorized"] = True
        (place / "owner-selection.json").write_bytes(op.canonical(approval))
        with self.assertRaisesRegex(ValueError, "different scope"):
            op.custody(self.archive, sha)

    def test_same_uid_and_changed_independent_selection_hold(self):
        _, sha = self.role_fixture(duplicate=True)
        with self.assertRaisesRegex(ValueError, "share"):
            op.custody(self.archive, sha)
        with self.assertRaisesRegex(ValueError, "sole owner"):
            op.custody(self.archive, "0" * 64)

    def test_catalogue_context_cannot_drop_a_prior_tree_or_hold(self):
        tree = {"tree": "1" * 40, "report": "d" * 64, "input": "c" * 64, "worse": 165}
        old = {
            "format": op.CATALOG,
            "project": "ocs",
            "custody": {"registrySha256": "b" * 64},
            "basis": {"comparatorsSha256": "c" * 64},
            "requiredOpen": ["permanent election", "critical applications"],
            "coverageLimits": {"kubernetes": ["unobserved"]},
            "prerequisites": {"cost": "still pending"},
            "hosting": {"hold": 71},
            "hostedAdverse": {"checkRunId": 47},
            "adverse": [tree],
            "firstCostMethod": {"candidate": None},
        }
        op.compatible(old, copy.deepcopy(old))
        for name, change in (
            ("adverse", []),
            ("requiredOpen", ["permanent election"]),
            ("coverageLimits", {}),
            ("prerequisites", {"cost": "claimed without evidence"}),
            ("hosting", {"hold": 2}),
        ):
            bad = {**old, name: change}
            with self.subTest(name=name), self.assertRaises(ValueError):
                op.compatible(old, bad)

    def test_future_checker_is_data_and_needs_real_controls(self):
        repo = self.root / "objects.git"
        subprocess.run(
            [
                "git",
                "init",
                "--bare",
                "--quiet",
                "--initial-branch=unpublished",
                "--template=",
                repo,
            ],
            check=True,
        )
        method = b'raise RuntimeError("must never execute during preparation")\n'
        tests = b"# independently reviewed fixture controls\n"

        def object_id(argv, raw):
            return (
                subprocess.check_output(
                    ["git", "--no-replace-objects", "--git-dir", repo, *argv],
                    input=raw,
                    env=op.clean_env(self.root),
                )
                .strip()
                .decode()
            )

        files = {
            n: object_id(["hash-object", "-w", "--stdin"], v)
            for n, v in (
                ("cost_acquisition.py", method),
                ("test_cost_acquisition.py", tests),
            )
        }
        pkg = object_id(
            ["mktree"],
            "".join(
                f"100644 blob {v}\t{k}\n" for k, v in sorted(files.items())
            ).encode(),
        )
        tree = object_id(["mktree"], f"040000 tree {pkg}\tsafe_push\n".encode())
        oid = object_id(
            ["hash-object", "-t", "commit", "-w", "--stdin"],
            f"tree {tree}\nauthor Fixture <fixture@example.invalid> 10 +0000\ncommitter Fixture <fixture@example.invalid> 10 +0000\n\ninert local data\n".encode(),
        )
        request = {
            "firstCostCandidate": {
                "revision": oid,
                "methodSha256": op.digest(method),
                "testSha256": op.digest(tests),
            }
        }
        proposal = op.checker_plan(request, repo)
        self.assertEqual(proposal["requirements"], ["evolution/receiver-cost"])
        self.assertEqual(proposal["pathPrefixes"], ["policy/receiverCost"])
        self.assertEqual(proposal["status"], "awaiting-independent-enrollment")
        self.assertIsNone(proposal["permanentSuccessfulCostObservation"])
        self.assertIsNone(op.checker_plan({}, repo)["candidate"])
        request["firstCostCandidate"]["methodSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "changed"):
            op.checker_plan(request, repo)

    def test_existing_destination_is_never_replaced(self):
        first = self.root / "first"
        first.mkdir()
        second = self.root / "second"
        second.mkdir()
        self.assertFalse(op.install_directory_once(first, second))
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())
        third = self.root / "third"
        self.assertTrue(op.install_directory_once(first, third))
        self.assertTrue(third.is_dir())


class HistoricalOperatingCatalogTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("OCS_OPERATING_CATALOG_INPUTS"),
        "an independently selected real administrative public-input descriptor is required",
    )
    def test_original_owner_basis_and_resealed_counterexample_removal(self):
        inputs = Path(os.environ["OCS_OPERATING_CATALOG_INPUTS"])
        cfg = op.load(inputs)
        expected = op.framed(cfg)
        with tempfile.TemporaryDirectory(
            prefix="ocs-catalog-acceptance-", dir="/var/tmp"
        ) as td:
            out = Path(td) / "bundle"
            actual = op.prepare(inputs, expected, out, admin=os.geteuid() == 0)
            self.assertFalse(actual["canonicalAuthorization"])
            self.assertEqual(
                (
                    actual["claimLevels"],
                    actual["comparisonCells"],
                    actual["retainedAdverseTrees"],
                ),
                (394, 364, 2),
            )
            catalog = op.load(out / "catalog.json")
            proposal = op.load(out / "operating-policy-inputs.json")
            self.assertEqual(sorted(v["worse"] for v in catalog["adverse"]), [165, 210])
            self.assertEqual(len(catalog["requiredOpen"]), 2)
            self.assertIsNone(proposal["selectedFields"]["receiverCost"])
            self.assertIsNone(proposal["authorization"])
            self.assertEqual(len(catalog["custody"]["humanOwners"]), 1)
            with self.assertRaises(ValueError):
                op.validate_policy(proposal)
            op.verify(out, expected, previous=catalog)
            # A dishonest packager can rewrite its local inventory. The selection independent
            # of this packager still retains both earlier adverse receipts.
            veto = next((out / "archive/history/adverse").glob("*/*.json"))
            veto.parent.chmod(0o755)
            veto.unlink()
            manifest = op.bundle_inventory(out)
            manifest.pop("inventory.json")
            (out / "inventory.json").chmod(0o644)
            (out / "inventory.json").write_bytes(op.canonical(manifest))
            with self.assertRaisesRegex(ValueError, "historical inventory"):
                op.verify(out, expected)


if __name__ == "__main__":
    unittest.main()
