"""The admitted example is an exact four-input data-defined predicate, under an older checker."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from authority import (
    ROLES,
    Decision,
    authentic,
    canonical,
    digest,
    framed,
    immutable,
    policy_history,
    signature,
)
from cost import EXPERIMENT, UNITS
from evolution import evolution_scope, evolution_signature_payload, verify_evolution

# This real, bounded reference target adapter includes the advertised target name in its behavior.
TRANSPORT = b"""import json,sys,hashlib
q=json.load(sys.stdin)
tables={'original':[True,False,True,False],'backup':[True,False,True,False]}
outcomes=tables[q['target']]
claims={str(i):hashlib.sha256(str(x).encode()).hexdigest() for i,x in enumerate(outcomes)}
result={'reportSha256':hashlib.sha256(json.dumps(outcomes).encode()).hexdigest(),'claims':claims,
        'metrics':{'finite-domain':{'value':str(len(outcomes)),'direction':'max','condition':q['conditions']}},
        'expiresAt':'2099-01-01T00:00:00Z'}
print(json.dumps(result))
"""

# The enrolled predecessor fixes this complete domain and both outcomes. It enumerates each
# element of BOTH independently bound subject tables and the submitted witness, inside bwrap.
FINITE_CHECKER = b"""import hashlib,json,sys
from pathlib import Path
def enc(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
q=json.load(sys.stdin);c=q['context'];s=json.loads((Path(q['evidence'])/'subjects.json').read_bytes())
a=Path(q['artifact']).read_bytes(); proof=json.loads(a)
policies=json.loads((Path(q['evidence'])/'policies.json').read_bytes())
expected=[True,False,True,False]
def exact_table(v):
 return type(v) is list and len(v)==4 and all(type(y) is bool and y==x for x,y in zip(expected,v))
ok=all(exact_table(s[side]['data'].get('outcomes')) for side in ('old','new'))
ok=ok and exact_table(proof['body'].get('outcomes'))
if c['purpose']=='evolution/target/backup':
 target=policies['new']['targets']['backup']
 old=policies['old']['targets']['original']
 sha=policies['old']['adapters'][old['adapter']]
 source=(Path(q['evidence'])/(sha+'.data')).read_bytes()
 ok=ok and target==old and sha=='TRANSPORT_DIGEST' and hashlib.sha256(source).hexdigest()==sha
elif c['purpose']=='evolution/receiveTimeoutSeconds':
 ok=ok and min(policies['old']['receiveTimeoutSeconds'],policies['new']['receiveTimeoutSeconds'])>=max([1,2,3,8])
else:
 ok=ok and c['purpose']=='evolution/close/finite-domain'
print(json.dumps({'status':'accepted' if ok else 'refused','contextSha256':hashlib.sha256(enc(c)).hexdigest(),
                  'artifactSha256':hashlib.sha256(a).hexdigest()}))
""".replace(b"TRANSPORT_DIGEST", digest(TRANSPORT).encode("ascii"))


class Fixture:
    def __init__(
        self,
        work,
        keys,
        scope=(
            "evolution/close/finite-domain",
            "evolution/add-target",
            "evolution/receiveTimeoutSeconds",
        ),
    ):
        self.a = work / "authority"
        self.keys = keys
        adapter = TRANSPORT
        method_sha = digest(FINITE_CHECKER)
        adapter_sha = digest(adapter)
        immutable(self.a / "methods" / (method_sha + ".py"), FINITE_CHECKER)
        immutable(self.a / "methods" / (adapter_sha + ".py"), adapter)
        self.old = {
            "format": "ocs.safe-push.policy/1",
            "project": "proof-fixture",
            "profile": "receiver-experiment/1",
            "epoch": 0,
            "genesis": "1" * 40,
            "assurancePin": "2" * 40,
            "keys": keys["public"],
            "lifetimeSeconds": 600,
            "receiveTimeoutSeconds": 300,
            "receiverCost": EXPERIMENT,
            "adapters": {"sealed-reader": adapter_sha},
            "targets": {
                "original": {
                    "adapter": "sealed-reader",
                    "conditions": "a" * 64,
                    "observerSha256": None,
                }
            },
            "requiredOpen": [],
            "predicateCheckers": {
                "finite": {
                    "sha256": method_sha,
                    "requirements": list(scope),
                    "pathPrefixes": [
                        "policy/requiredOpen",
                        "policy/targets",
                        "policy/receiveTimeoutSeconds",
                    ],
                }
            },
        }
        self.new = copy.deepcopy(self.old)
        self.new["epoch"] = 1
        self.tables = {
            "old": [True, False, True, False],
            "new": [True, False, True, False],
        }

    def obj(self, value):
        data = canonical(value)
        key = digest(data)
        immutable(self.a / "evolution/objects" / key, data)
        return key

    def formation(
        self,
        method="finite",
        invalid_witness=None,
        negative_criterion="reference.parent",
        artifacts=None,
    ):
        scope = evolution_scope(self.old, self.new)
        scope_sha = framed(scope)
        subjects = {
            n: self.obj(
                {
                    "format": "ocs.safe-push.policy-subject/1",
                    "epoch": p["epoch"],
                    "policySha256": framed(p),
                    "assuranceRevision": p["assurancePin"],
                    "data": {"outcomes": self.tables[n]},
                    "artifacts": (artifacts or {}).get(n, {}),
                }
            )
            for n, p in (("old", self.old), ("new", self.new))
        }
        proofs = {}
        rejects = {}
        for purpose in scope["purposes"]:
            base = {
                "format": "ocs.safe-push.evolution-proof/1",
                "purpose": purpose,
                "scopeSha256": scope_sha,
                "subjects": subjects,
            }
            proofs[purpose] = {
                "method": method,
                "artifact": self.obj(
                    {**base, "body": {"outcomes": [True, False, True, False]}}
                ),
            }
            rejects[purpose] = self.obj(
                {
                    **base,
                    "body": {
                        "outcomes": invalid_witness
                        if invalid_witness is not None
                        else [True, True, True, False]
                    },
                }
            )
        pos = {
            "format": "ocs.safe-push.policy-control/1",
            "scopeSha256": scope_sha,
            "parent": "1" * 40,
            "actualParent": "1" * 40,
            "candidate": "3" * 40,
            "ageSeconds": 8,
            "serviceSeconds": 3,
            "targetConditions": {
                k: v["conditions"] for k, v in self.new["targets"].items()
            },
            "costs": {},
            "criterion": None,
            "refutations": {},
        }
        neg = {
            **pos,
            "criterion": negative_criterion,
            "actualParent": "4" * 40,
            "refutations": rejects,
        }
        if negative_criterion.startswith("qualification.target/"):
            removed = negative_criterion.split("/", 1)[1]
            neg = {
                **pos,
                "criterion": negative_criterion,
                "targetConditions": {
                    k: v for k, v in pos["targetConditions"].items() if k != removed
                },
                "refutations": rejects,
            }
        ev = {
            "format": "ocs.safe-push.evolution/1",
            "scopeSha256": scope_sha,
            "subjects": subjects,
            "controls": {"positive": self.obj(pos), "refusal": self.obj(neg)},
            "proofs": proofs,
        }
        binding = evolution_signature_payload(self.old, self.new, ev)
        record = {"policy": self.new, "evolution": ev}
        for side in ("old", "new"):
            record[side] = {
                r: signature({**binding, "role": r, "side": side}, self.keys[r])
                for r in ROLES
            }
        return record


class EvolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_dir = tempfile.TemporaryDirectory()
        keydir = Path(cls.keys_dir.name)
        cls.keys = {"public": {}}
        for name in (*ROLES, "publisher"):
            key = keydir / name
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                check=True,
                capture_output=True,
            )
            cls.keys["public"][name] = subprocess.check_output(
                ["openssl", "pkey", "-in", str(key), "-pubout"], text=True
            )
            cls.keys[name] = key

    @classmethod
    def tearDownClass(cls):
        cls.keys_dir.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.f = Fixture(Path(self.workspace.name), self.keys)
        self.addCleanup(self.workspace.cleanup)

    def test_monotone_added_target_and_equivalent_predicate_alias(self):
        f = self.f
        f.new["targets"]["backup"] = copy.deepcopy(f.old["targets"]["original"])
        f.new["predicateCheckers"]["second-reader"] = copy.deepcopy(
            f.old["predicateCheckers"]["finite"]
        )
        rec = f.formation(negative_criterion="qualification.target/backup")
        result = verify_evolution(f.a, f.old, f.new, rec)
        self.assertEqual({"evolution/target/backup"}, set(rec["evolution"]["proofs"]))
        # Actual target route of the already-enrolled adapter consumes the proposed target name.
        from admission import run_adapter

        observed = run_adapter(
            f.a,
            f.old["adapters"],
            "sealed-reader",
            {"target": "backup", "conditions": "a" * 64},
        )
        self.assertEqual("4", observed["metrics"]["finite-domain"]["value"])
        self.assertEqual({"0", "1", "2", "3"}, set(observed["claims"]))
        self.assertEqual(
            (0, 1, framed(rec["evolution"])),
            (result["fromEpoch"], result["epoch"], result["evolutionSha256"]),
        )
        for side in ("old", "new"):
            for role in ROLES:
                self.assertEqual(
                    {**result, "role": role, "side": side},
                    authentic(
                        rec[side][role], self.keys["public"][role], "test.signature"
                    ),
                )

    def test_closed_mandatory_claim_executes_only_the_prior_complete_finite_checker(
        self,
    ):
        f = self.f
        f.old["requiredOpen"] = ["finite-domain"]
        rec = f.formation()
        result = verify_evolution(f.a, f.old, f.new, rec)
        self.assertEqual(result["subjects"], rec["evolution"]["subjects"])
        self.assertEqual(result["proofsSha256"], framed(rec["evolution"]["proofs"]))
        # A candidate changed one previously refused input to successful, with the same shape.
        f.tables["new"][1] = True
        bad = f.formation()
        with self.assertRaisesRegex(Decision, "evolution.refinement"):
            verify_evolution(f.a, f.old, f.new, bad)

    def test_predecessor_proves_stronger_timeout_for_its_complete_finite_workload(self):
        f = self.f
        f.new["receiveTimeoutSeconds"] = 10
        verify_evolution(f.a, f.old, f.new, f.formation())
        # The positive sample lasts only three seconds. One admissible old operation needs eight.
        f.new["receiveTimeoutSeconds"] = 5
        with self.assertRaisesRegex(Decision, "evolution.refinement"):
            verify_evolution(f.a, f.old, f.new, f.formation())

    def test_absent_older_purpose_and_candidate_installed_self_authorization_fail(self):
        f = self.f
        f.old["requiredOpen"] = ["finite-domain"]
        f.new["predicateCheckers"]["future"] = copy.deepcopy(
            f.old["predicateCheckers"]["finite"]
        )
        rec = f.formation(method="future")
        with self.assertRaisesRegex(Decision, "evolution.authority"):
            verify_evolution(f.a, f.old, f.new, rec)
        rec["evolution"]["proofs"] = {}
        with self.assertRaisesRegex(Decision, "evolution.proofs"):
            verify_evolution(f.a, f.old, f.new, rec)

    def test_unbound_subject_substitution(self):
        f = self.f
        f.old["requiredOpen"] = ["finite-domain"]
        rec = f.formation()
        ev = rec["evolution"]
        ev["subjects"]["new"] = f.obj(
            {
                "format": "ocs.safe-push.policy-subject/1",
                "epoch": 99,
                "policySha256": framed(f.new),
                "assuranceRevision": f.new["assurancePin"],
                "data": {},
            }
        )
        with self.assertRaisesRegex(Decision, "evolution.subject"):
            verify_evolution(f.a, f.old, f.new, rec)

    def test_exact_source_subject_and_no_self_certified_replacement(self):
        f = self.f
        f.new["targets"]["backup"] = copy.deepcopy(f.old["targets"]["original"])
        original = b"independently selected opaque reference subject\0"
        mark = digest(original)
        raw = f.a / "evolution/objects" / mark
        immutable(raw, original)
        rec = f.formation(artifacts={"old": {"exact-reference.bin": mark}})
        verify_evolution(f.a, f.old, f.new, rec)
        raw.write_bytes(b"an unrelated reference")
        with self.assertRaisesRegex(Decision, "evolution.object"):
            verify_evolution(f.a, f.old, f.new, rec)
        replacement = b"print('unqualified future checker')\n"
        new_sha = digest(replacement)
        immutable(f.a / "methods" / (new_sha + ".py"), replacement)
        f.new["predicateCheckers"]["finite"]["sha256"] = new_sha
        # Its own future grant cannot authorize replacement of the already admitted verifier.
        f.new["predicateCheckers"]["finite"]["requirements"].append(
            "evolution/predicate/finite"
        )
        rec = f.formation()
        with self.assertRaisesRegex(Decision, "evolution.authority"):
            verify_evolution(f.a, f.old, f.new, rec)

    def test_false_refusal_control(self):
        f = self.f
        f.old["requiredOpen"] = ["finite-domain"]
        # Give the checker two syntactically different, semantically valid finite witnesses;
        # the required independent refusal must fail even if both thresholds signed it.
        rec = f.formation()
        key = "evolution/close/finite-domain"
        ev = rec["evolution"]
        path = f.a / "evolution/objects"
        cb = json.loads((path / ev["controls"]["refusal"]).read_bytes())
        good = json.loads((path / ev["proofs"][key]["artifact"]).read_bytes())
        cb["refutations"][key] = f.obj(
            {**good, "body": {**good["body"], "note": "same valid witness"}}
        )
        ev["controls"]["refusal"] = f.obj(cb)
        with self.assertRaisesRegex(Decision, "evolution.refinement"):
            verify_evolution(f.a, f.old, f.new, rec)

    def test_looser_bound_removal_scope_and_workload_identity_are_refused(self):
        for change, code in (
            (lambda p: p.update(lifetimeSeconds=601), "bound"),
            (lambda p: p.update(receiveTimeoutSeconds=301), "bound"),
            (lambda p: p["targets"].pop("original"), "retention"),
            (
                lambda p: p["targets"]["original"].update(conditions="f" * 64),
                "conditions",
            ),
            (
                lambda p: p["predicateCheckers"]["finite"].update(
                    pathPrefixes=["different"]
                ),
                "domain",
            ),
        ):
            f = self.f
            new = copy.deepcopy(f.new)
            change(new)
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(Decision, "evolution." + code),
            ):
                evolution_scope(f.old, new)
        f = self.f
        registered = {
            "format": "ocs.safe-push.verifier-cost-policy/1",
            "profile": "receiver-experiment/1",
            "workloadSha256": "a" * 64,
            "platformSha256": "b" * 64,
            "baselineEvidenceSha256": "c" * 64,
            "ceilings": {k: 10 for k in UNITS},
        }
        f.old["receiverCost"] = registered
        for change in (
            lambda p: p["ceilings"].update({next(iter(UNITS)): 11}),
            lambda p: p.update(workloadSha256="d" * 64),
        ):
            new = copy.deepcopy(f.new)
            new["receiverCost"] = copy.deepcopy(registered)
            change(new["receiverCost"])
            with self.assertRaisesRegex(Decision, "evolution.cost"):
                evolution_scope(f.old, new)

    def test_incomplete_installed_bytes_and_permitted_example_are_held(self):
        f = self.f
        f.new["targets"]["backup"] = copy.deepcopy(f.old["targets"]["original"])
        rec = f.formation()
        ev = rec["evolution"]
        path = f.a / "evolution/objects"
        case = json.loads((path / ev["controls"]["positive"]).read_bytes())
        case["ageSeconds"] = f.new["lifetimeSeconds"]
        ev["controls"]["positive"] = f.obj(case)
        with self.assertRaisesRegex(Decision, "evolution.realizability"):
            verify_evolution(f.a, f.old, f.new, rec)
        rec = f.formation()
        (f.a / "methods" / (f.old["adapters"]["sealed-reader"] + ".py")).unlink()
        with self.assertRaisesRegex(Decision, "evolution.installation"):
            verify_evolution(f.a, f.old, f.new, rec)

    def test_previous_and_proposed_quorums_bind_the_entire_record_in_policy_history(
        self,
    ):
        f = self.f
        f.new["targets"]["backup"] = copy.deepcopy(f.old["targets"]["original"])
        rec = f.formation()
        immutable(f.a / "root.json", canonical(f.old))
        file = f.a / "rotations" / "000000000001.json"
        immutable(file, canonical(rec))
        self.assertEqual([f.old, f.new], policy_history(f.a, framed(f.old)))
        rec["new"]["domain"] = rec["old"]["domain"]
        file.write_bytes(canonical(rec))
        with self.assertRaisesRegex(Decision, "trust.rotation"):
            policy_history(f.a, framed(f.old))

    def test_operator_entrypoint_advances_real_isolated_epoch_and_witness(self):
        from admission import state
        from authority import load
        from test_receiver import Experiment

        work = Path(self.workspace.name) / "live-operator"
        work.mkdir()
        exp = Experiment(work, HERE.parent)
        f = self.f
        f.old = exp.policy
        f.new = copy.deepcopy(f.old)
        f.new["epoch"] = 1
        prior = next(iter(f.old["predicateCheckers"].values()))
        f.new["predicateCheckers"]["equivalent-alias"] = copy.deepcopy(prior)
        f.keys = {r: exp.keydir / (r + ".key") for r in ROLES}
        record = f.formation()
        self.assertFalse(record["evolution"]["proofs"])
        cli = [sys.executable, "-I", str(HERE / "operator_cli.py")]
        for obj in (f.a / "evolution/objects").iterdir():
            subprocess.run(
                [
                    *cli,
                    "evolution-input",
                    str(exp.config),
                    "subject-or-proof",
                    obj.name,
                    str(obj),
                ],
                check=True,
                capture_output=True,
            )
        packet = work / "approved-evolution.json"
        immutable(packet, canonical(record))
        subprocess.run(
            [*cli, "rotate", str(exp.config), str(packet)],
            check=True,
            capture_output=True,
        )
        cfg, _, _, _, actual = state(exp.config)
        self.assertEqual(actual, f.new)
        self.assertEqual(load(Path(cfg["witness"]))["policy"], framed(f.new))


if __name__ == "__main__":
    unittest.main()
