"""Exercise scope through committed Git objects on the published public corpus."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scope import (
    GUARDIAN,
    ScopeError,
    change_requirements,
    fingerprint,
    inventory,
    subject,
)

EDITION = "df209a3d0b486e6fd771a67a65f137447785a352"
HISTORICAL = "6f6e22842347806f2963ef1984d9ea592fdddaf0"
CORPUS = "conformance/cases/core.json"
LEDGER = "conformance/scenarios.json"
CASES = "recover-after-input-error"


def json_bytes(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()


def git(repo, *args, data=None, env=None):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Scope test",
            "GIT_AUTHOR_EMAIL": "scope@example.test",
            "GIT_COMMITTER_NAME": "Scope test",
            "GIT_COMMITTER_EMAIL": "scope@example.test",
            **(env or {}),
        },
        input=data,
        stderr=subprocess.PIPE,
        timeout=20,
    )


class TreeFixture:
    def __init__(self, directory):
        self.repo = directory / "objects"
        # Local shared clone. All authored controls are unreachable objects in this disposable store.
        git(
            directory,
            "clone",
            "--shared",
            "--no-checkout",
            "--quiet",
            str(GUARDIAN),
            str(self.repo),
        )
        self.generation = 0

    def data(self, name, parent=EDITION):
        return git(self.repo, "show", parent + ":" + name)

    def json(self, name, parent=EDITION):
        return json.loads(self.data(name, parent))

    def commit(self, edits, parent=EDITION, extra_env=None):
        self.generation += 1
        env = {
            "GIT_INDEX_FILE": str(
                self.repo / ".git" / f"fixture-index-{self.generation}"
            ),
            **(extra_env or {}),
        }
        git(self.repo, "read-tree", parent, env=env)
        for path, value in edits.items():
            if value is None:
                git(self.repo, "update-index", "--force-remove", "--", path, env=env)
                continue
            mode, body = value if isinstance(value, tuple) else ("100644", value)
            oid = (
                body
                if mode == "160000"
                else git(self.repo, "hash-object", "-w", "--stdin", data=body, env=env)
                .decode()
                .strip()
            )
            git(
                self.repo,
                "update-index",
                "--add",
                "--cacheinfo",
                mode,
                oid,
                path,
                env=env,
            )
        tree = git(self.repo, "write-tree", env=env).decode().strip()
        return (
            git(
                self.repo,
                "commit-tree",
                tree,
                "-p",
                parent,
                data=f"local control {self.generation}\n".encode(),
                env=env,
            )
            .decode()
            .strip()
        )


class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ocs-safe-push-scope-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.fixture = TreeFixture(cls.work)
        cls.repo = cls.fixture.repo
        cls.original = inventory(cls.repo, EDITION)

    def plan(self, edits, parent=EDITION):
        candidate = self.fixture.commit(edits, parent=parent)
        before = self.original if parent == EDITION else inventory(self.repo, parent)
        return change_requirements(
            self.repo, parent, candidate, before, inventory(self.repo, candidate)
        )

    def refusal(self, outcome, expression, callback):
        with self.assertRaisesRegex(ScopeError, expression) as caught:
            callback()
        self.assertEqual(caught.exception.outcome, outcome)

    def test_full_git_inventory_matches_pristine_qualification_subject(self):
        checkout = self.work / "published-checkout"
        git(self.repo, "worktree", "add", "--quiet", "--detach", str(checkout), EDITION)
        trusted_program = (
            "import json,sys; from pathlib import Path; "
            "sys.path.insert(0,str(Path(sys.argv[1])/'assurance')); from trust import subject_identity; "
            "print(json.dumps(subject_identity(Path(sys.argv[1]))))"
        )
        published = json.loads(
            subprocess.check_output(
                [sys.executable, "-I", "-B", "-c", trusted_program, str(checkout)],
                timeout=12,
            )
        )
        self.assertEqual(subject(self.repo, EDITION, self.original), published)
        self.assertEqual(sum(r["type"] == "blob" for r in self.original.values()), 214)
        self.assertEqual(sum(r["type"] == "tree" for r in self.original.values()), 32)
        plan = change_requirements(
            self.repo, EDITION, EDITION, self.original, self.original
        )
        self.assertEqual(plan["changes"], [])
        self.assertFalse(plan["policyChange"])
        self.assertEqual(len(plan["requirements"]["qualification.full"]["claims"]), 245)
        self.assertEqual(plan["wholeTreeSha256"], plan["priorTreeSha256"])

    def test_historical_deleted_public_case_and_ledger_rewrite_are_rejected(self):
        cases = self.fixture.json(CORPUS)
        historic = self.fixture.json(CORPUS, HISTORICAL)
        self.assertTrue(any(c["id"] == CASES and c["rule"] == "W-06" for c in historic))
        index = self.fixture.json(LEDGER)
        for scenario in index["scenarios"].values():
            scenario["checks"] = [c for c in scenario["checks"] if c != CASES]
        self.refusal(
            "rejected",
            CASES,
            lambda: self.plan(
                {
                    CORPUS: json_bytes([c for c in cases if c["id"] != CASES]),
                    LEDGER: json_bytes(index),
                }
            ),
        )
        self.refusal(
            "rejected",
            CASES,
            lambda: self.plan(
                {CORPUS: json_bytes([c for c in historic if c["id"] != CASES])},
                parent=HISTORICAL,
            ),
        )

    def test_weakened_public_error_and_response_do_not_satisfy_published_case(self):
        cases = self.fixture.json(CORPUS)
        original = next(c for c in cases if c["id"] == CASES)
        del original["steps"][1]["expect"]["error"]["data"]["kind"]
        self.refusal("rejected", CASES, lambda: self.plan({CORPUS: json_bytes(cases)}))
        cases = self.fixture.json(CORPUS)
        original = next(c for c in cases if c["id"] == CASES)
        original["steps"][2]["params"]["input"]["resourceId"] = "other"
        self.refusal("rejected", CASES, lambda: self.plan({CORPUS: json_bytes(cases)}))

    def test_additive_case_preserves_prior_trace_and_requires_real_oracle(self):
        cases = self.fixture.json(CORPUS)
        case = next(c for c in cases if c["id"] == CASES)
        case["steps"].append(case["steps"][-1].copy())
        plan = self.plan({CORPUS: json_bytes(cases)})
        self.assertFalse(plan["policyChange"])
        self.assertEqual(plan["requirements"]["test.oracle"]["kind"], "qualification")
        self.assertEqual(plan["requirements"]["test.independent"]["paths"], [CORPUS])
        self.assertIn(
            "W-06.recovery", plan["requirements"]["qualification.full"]["claims"]
        )

    def test_edited_validator_and_executable_tester_require_incumbent_proof(self):
        for path in [
            "conformance/test_contracts.py",
            "conformance/compatibility.py",
            "assurance/trust.py",
        ]:
            with self.subTest(path=path):
                plan = self.plan({path: b"def main():\n    return True\n"})
                self.assertTrue(plan["policyChange"])
                self.assertEqual(
                    plan["requirements"]["policy.transition"]["kind"], "portable-proof"
                )
                self.assertEqual(
                    plan["requirements"]["policy.independent"]["ownerRole"],
                    "independent",
                )

    def test_lost_controls_claims_evidence_levels_and_scenario_links_are_rejected(self):
        roster = "assurance/evidence-index.json"
        data = self.fixture.json(roster)
        data["controlIds"]["local"].remove("WR-07.python-lost-scenario")
        self.refusal(
            "rejected",
            "WR-07.python-lost-scenario",
            lambda: self.plan({roster: json_bytes(data)}),
        )
        ledger = self.fixture.json(LEDGER)
        ledger["requirements"]["spec/core.md"]["C-02"].remove("scoped-binding")
        self.refusal(
            "rejected", "C-02", lambda: self.plan({LEDGER: json_bytes(ledger)})
        )
        path = "assurance/obligations.json"
        cat = self.fixture.json(path)
        cat["groups"]["C-01"]["claims"].pop(0)
        self.refusal(
            "rejected", "C-01.inspect", lambda: self.plan({path: json_bytes(cat)})
        )
        cat = self.fixture.json(path)
        claim = next(c for c in cat["groups"]["C-01"]["claims"] if c["id"] == "admit")
        claim["levels"].remove("model")
        self.refusal(
            "rejected", "C-01.admit", lambda: self.plan({path: json_bytes(cat)})
        )

    def test_candidate_classification_and_unchanged_unknown_objects_cannot_self_enroll(
        self,
    ):
        extension = "out/ignored.asset"
        policy = json.loads((GUARDIAN / "safe_push/coverage.json").read_bytes())
        policy["classes"].insert(
            0,
            {
                "id": "self-approved",
                "pattern": ".*",
                "policy": False,
                "requirements": [],
            },
        )
        self.refusal(
            "undetermined",
            "unclassified",
            lambda: self.plan(
                {
                    extension: b"tracked bytes",
                    "safe_push/coverage.json": json_bytes(policy),
                }
            ),
        )
        unsupported = self.fixture.commit({extension: b"tracked bytes"})
        objects = inventory(self.repo, unsupported)
        self.assertEqual(
            objects[extension]["sha256"], hashlib.sha256(b"tracked bytes").hexdigest()
        )
        self.refusal(
            "undetermined",
            "unclassified",
            lambda: change_requirements(
                self.repo, unsupported, unsupported, objects, objects
            ),
        )
        self.refusal(
            "undetermined",
            "unclassified",
            lambda: self.plan({"reference/extension.unknown": b"new format"}),
        )
        self.refusal(
            "undetermined",
            "edition interpretation",
            lambda: self.plan({"spec/profiles/new.md": b"# Optional capability\n"}),
        )
        self.refusal(
            "undetermined",
            "unclassified",
            lambda: self.plan(
                {"spec/profiles/new.json": b'{"unregisteredLanguage": 1}'}
            ),
        )

    def test_metadata_link_and_external_objects_have_distinct_obligations(self):
        path = "reference/interaction/kernel.py"
        candidate = self.fixture.commit({path: ("100755", self.fixture.data(path))})
        new = inventory(self.repo, candidate)
        self.assertEqual(
            subject(self.repo, EDITION, self.original)["treeSha256"],
            subject(self.repo, candidate, new)["treeSha256"],
        )
        plan = change_requirements(self.repo, EDITION, candidate, self.original, new)
        self.assertNotEqual(plan["wholeTreeSha256"], plan["priorTreeSha256"])
        self.assertIn("tree.object", plan["requirements"])
        internal = self.fixture.commit({"docs/copy.md": ("120000", b"../README.md")})
        objects = inventory(self.repo, internal)
        self.assertEqual(objects["docs/copy.md"]["type"], "link")
        self.assertEqual(subject(self.repo, internal, objects)["fileCount"], 215)
        self.assertIn(
            "artifact.provenance",
            change_requirements(self.repo, EDITION, internal, self.original, objects)[
                "requirements"
            ],
        )
        for mode, path, body, message in [
            ("120000", "docs/missing.md", b"missing.md", "cycle"),
            ("120000", "docs/elsewhere.md", b"../../outside", "escapes"),
            ("160000", "reference/module", EDITION, "external"),
            (
                "100644",
                "docs/large.md",
                b"version https://git-lfs.github.com/spec/v1\nsize 12\n",
                "external",
            ),
        ]:
            with self.subTest(path=path):
                bad = self.fixture.commit({path: (mode, body)})
                selected = inventory(self.repo, bad)
                self.refusal(
                    "undetermined",
                    message,
                    lambda bad=bad, selected=selected: subject(
                        self.repo, bad, selected
                    ),
                )

    def test_same_content_unsigned_inventory_substitution_is_detected(self):
        changed = self.fixture.commit({"README.md": b"Reviewed documentation.\n"})
        objects = dict(inventory(self.repo, changed))
        forged = {**objects, "README.md": dict(self.original["README.md"])}
        self.refusal(
            "rejected",
            "another committed tree",
            lambda: change_requirements(
                self.repo, EDITION, changed, self.original, forged
            ),
        )
        first = change_requirements(self.repo, EDITION, changed, self.original, objects)
        second = self.plan({"README.md": b"Reviewed documentation.\n"})
        self.assertNotEqual(
            first["requirements"]["docs.meaning"]["digest"],
            second["requirements"]["docs.meaning"]["digest"],
        )
        self.assertEqual(first["requirements"]["docs.meaning"]["kind"], "domain-review")
        self.assertFalse(
            any(v["kind"] == "portable-proof" for v in first["requirements"].values())
        )

    def test_proof_only_addition_and_changed_proposition_get_distinct_scope(self):
        path = "assurance/interaction/Source.lean"
        original = self.fixture.data(path)
        end = b"end Interaction"
        addition = b"theorem newCorollary (n : Nat) : n = n := by\n  rfl\n\n"
        candidate = self.plan({path: original.replace(end, addition + end)})
        self.assertFalse(candidate["policyChange"])
        self.assertEqual(
            candidate["requirements"]["proof.replay"]["kind"], "qualification"
        )
        changed = self.plan(
            {
                path: original.replace(
                    b"budget share = reserve budget share", b"budget share = 0"
                )
            }
        )
        self.assertTrue(changed["policyChange"])

    def test_qualified_equivalence_new_portable_binary_and_scientific_critical_use(
        self,
    ):
        kernel = "reference/interaction/kernel.py"
        equivalent = self.plan(
            {kernel: self.fixture.data(kernel) + b"\n# Same executable decisions.\n"}
        )
        self.assertFalse(equivalent["policyChange"])
        self.assertEqual(
            equivalent["requirements"]["source.refinement"]["kind"], "portable-proof"
        )
        combined = self.plan(
            {
                "research/trial.md": b"Prospective latency hypothesis.",
                "safety/intended-use.md": b"Declared timing safety case.",
                "assurance/external/example/optional.wasm": b"\0asm\x01\0\0\0",
            }
        )
        for name, kind in [
            ("science.protocol", "domain-review"),
            ("science.reproduction", "independent-review"),
            ("safety.hazards", "domain-review"),
            ("safety.independent", "independent-review"),
            ("binary.refinement", "portable-proof"),
            ("source.refinement", "portable-proof"),
            ("platform.portability", "independent-review"),
        ]:
            self.assertEqual(combined["requirements"][name]["kind"], kind)
        self.refusal(
            "undetermined",
            "binary does not match",
            lambda: self.plan(
                {
                    "assurance/external/example/optional.wasm": b"text in place of required format"
                }
            ),
        )

    def test_editorial_normative_reformat_and_additive_obligation(self):
        path = "schemas/manifest.schema.json"
        raw = self.fixture.json(path)
        reformatted = self.plan(
            {path: json.dumps(raw, ensure_ascii=True, separators=(",", ":")).encode()}
        )
        self.assertNotIn("contract.relation", reformatted["requirements"])
        self.assertIn("docs.meaning", reformatted["requirements"])
        path = "assurance/obligations.json"
        catalog = self.fixture.json(path)
        catalog["groups"]["C-01"]["claims"].append(
            {
                "id": "new-positive",
                "expected": "Read optional new metadata.",
                "levels": ["reference"],
            }
        )
        plan = self.plan({path: json_bytes(catalog)})
        qualified = plan["requirements"]["qualification.full"]
        self.assertEqual(len(qualified["claims"]), 246)
        self.assertEqual(qualified["levels"]["C-01.new-positive"], ["reference"])
        self.assertTrue(plan["policyChange"])

    def test_receive_pack_quarantine_is_part_of_object_visibility(self):
        quarantine = self.work / "incoming-fixture"
        quarantine.mkdir()
        prior_objects = self.repo / ".git" / "objects"
        env = {
            "GIT_OBJECT_DIRECTORY": str(quarantine),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(prior_objects),
            "GIT_QUARANTINE_PATH": str(quarantine),
        }
        candidate = self.fixture.commit(
            {"docs/quarantine.md": b"Quarantined bytes.\n"}, extra_env=env
        )
        with patch.dict(os.environ, env):
            objects = inventory(self.repo, candidate)
            self.assertEqual(
                objects["docs/quarantine.md"]["sha256"],
                hashlib.sha256(b"Quarantined bytes.\n").hexdigest(),
            )
            plan = change_requirements(
                self.repo, EDITION, candidate, self.original, objects
            )
            self.assertEqual(plan["wholeTreeSha256"], fingerprint(objects))
        self.refusal(
            "undetermined", "unavailable", lambda: inventory(self.repo, candidate)
        )


if __name__ == "__main__":
    unittest.main()
