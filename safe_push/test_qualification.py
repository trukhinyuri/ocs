"""Offline acceptance and falsification tests for the sealed OCS adapter."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "safe_push"))
import qualification as q

OLD_CHECKER = "e09a5d7d0ae15d35910e72243c4a466974f09401"
OLD_SUBJECT = "3facf571910e0799539a77a1a5112e6609a9a5ca"


def run(*command, data=None):
    return subprocess.run(
        command, check=True, input=data, capture_output=True, timeout=25
    ).stdout


def key_pair(tmp):
    secret, public = tmp / "fixture.key", tmp / "fixture.pub"
    run("openssl", "genpkey", "-algorithm", "ED25519", "-out", secret)
    run("openssl", "pkey", "-in", secret, "-pubout", "-out", public)
    return secret, public


def sign(secret, doc):
    signature = doc.with_suffix(".sig")
    temp = doc.with_suffix(".tmp")
    run(
        "openssl",
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        secret,
        "-in",
        doc,
        "-out",
        temp,
    )
    temp.replace(signature)


def replace(path, raw):
    new = path.with_name(path.name + ".tmp")
    new.write_bytes(raw)
    new.replace(path)


class IndependentFixtureTests(unittest.TestCase):
    def test_signed_file_independent_key_and_artifact_bytes(self):
        # The only external dependencies in this test are the pinned Git object and local OpenSSL.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            folder = tmp / "dossier"
            folder.mkdir()
            secret, public = key_pair(tmp)
            artifact = folder / "evidence" / "example"
            artifact.parent.mkdir()
            artifact.write_bytes(b"hermetic observation\n")
            table = {
                "evidence/example": {
                    "sha256": q.sha(artifact.read_bytes()),
                    "bytes": artifact.stat().st_size,
                }
            }
            report = folder / "report.json"
            report.write_bytes(q.canonical({"artifactInventory": table}))
            sign(secret, report)
            dossier_copy = tmp / "checked"
            names = q.snapshot_dossier(folder, dossier_copy)
            q.artifact_inventory(dossier_copy, names, table)
            oracle = tmp / "pinned"
            q.export_commit(REPO, OLD_CHECKER, oracle, checker=True)
            worker = """
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]); sys.path.insert(0,sys.argv[2])
import qualification as q, trust, verify_receipt
q.authenticate_aggregate(Path(sys.argv[3]), {'operatorKey':sys.argv[4]}, Path(sys.argv[5]),verify_receipt,trust)
"""
            cmd = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                worker,
                str(q.HERE),
                str(oracle / "assurance"),
                str(dossier_copy),
                q.sha(public.read_bytes()),
                str(public),
            ]
            run(*cmd)
            (dossier_copy / "report.json").write_bytes(
                q.canonical({"artifactInventory": {}})
            )
            with self.assertRaises(subprocess.CalledProcessError):
                run(*cmd)
            (dossier_copy / "report.json").write_bytes(report.read_bytes())
            with self.assertRaises(subprocess.CalledProcessError):
                run(*[*cmd[:-2], "0" * 64, cmd[-1]])
            (dossier_copy / "evidence/example").write_bytes(b"hermetic replacement\n")
            with self.assertRaisesRegex(q.QualificationError, "detached bytes"):
                q.artifact_inventory(dossier_copy, names, table)

    def test_link_pipe_and_extra_file_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = tmp / "in"
            src.mkdir()
            (tmp / "outside").write_bytes(b"outside")
            (src / "x").symlink_to(tmp / "outside")
            with self.assertRaises(OSError):
                q.snapshot_dossier(src, tmp / "link-output")
            (src / "x").unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(src / "fifo")
                with self.assertRaisesRegex(q.QualificationError, "invalid file"):
                    q.snapshot_dossier(src, tmp / "fifo-output")
                (src / "fifo").unlink()
            (src / "linked-directory").symlink_to(tmp, target_is_directory=True)
            with self.assertRaisesRegex(q.QualificationError, "linked"):
                q.snapshot_dossier(src, tmp / "dir-output")
            for name in ("../asset", "/asset", "a/../asset", "a//asset"):
                with self.assertRaises(q.QualificationError):
                    q.check_name(name)
            with self.assertRaisesRegex(q.QualificationError, "inventory"):
                q.artifact_inventory(
                    src, {"evidence/legit", "evidence/extra"}, {"evidence/legit": {}}
                )

    def test_raw_population_per_direction_and_condition(self):
        spec = {
            "id": "speed",
            "source": "f/test@measurement",
            "conditions": ["clients"],
            "fields": [{"unit": "tasks", "max": ["correct"]}],
            "arrays": [
                {
                    "field": "ms",
                    "unit": "ms",
                    "direction": "min",
                    "size": 3,
                    "order": "rank",
                }
            ],
        }
        row = {
            "observed": {
                "clients": 3,
                "correct": 8,
                "ms": [Decimal("1.1"), Decimal("2.2"), Decimal("1.2")],
            }
        }
        orig = q.group_metrics(spec, row, {"cpu": "class-1"})
        self.assertEqual(orig["speed/ms/rank-03"]["value"], "2.2")
        self.assertEqual(orig["speed/correct"]["direction"], "max")
        row["observed"]["ms"].reverse()
        self.assertEqual(orig, q.group_metrics(spec, row, {"cpu": "class-1"}))
        row["observed"]["ms"][1] = Decimal(
            "2.20000000000000000000000000000000000000000000004"
        )
        exact = q.group_metrics(spec, row, {"cpu": "class-1"})
        self.assertEqual(
            exact["speed/ms/rank-03"]["value"],
            "2.20000000000000000000000000000000000000000000004",
        )
        self.assertEqual(
            orig["speed/ms/rank-03"]["condition"],
            exact["speed/ms/rank-03"]["condition"],
        )
        row["observed"]["clients"] = 1
        self.assertNotEqual(
            orig["speed/ms/rank-03"]["condition"],
            q.group_metrics(spec, row, {"cpu": "class-1"})["speed/ms/rank-03"][
                "condition"
            ],
        )
        row["observed"]["ms"].pop()
        with self.assertRaisesRegex(q.QualificationError, "population"):
            q.group_metrics(spec, row, {})

    def test_missing_cost_cannot_be_zero_and_exact_difference(self):
        group = {
            "id": "billing",
            "source": "r/spend@measurement",
            "conditions": [],
            "fields": [],
            "differences": [
                {
                    "id": "charge",
                    "field": "after",
                    "prior": "before",
                    "kind": "decimal-text",
                    "unit": "USD",
                    "direction": "min",
                }
            ],
        }
        v = "123456789012345678901234567890.1234567890123456789012"
        delta = q.group_metrics(
            group, {"observed": {"before": v + "0", "after": v + "9"}}, {}
        )
        self.assertEqual(delta["billing/charge"]["value"], "0.00000000000000000000009")
        for bad in (None, False, "unknown", "Infinity", "-0.05"):
            with self.subTest(bad=bad), self.assertRaises(q.QualificationError):
                q.group_metrics(group, {"observed": {"before": "0", "after": bad}}, {})

    def test_unknown_numeric_observation_requires_prior_enrollment(self):
        row = {
            "checks": [
                {"id": "probe", "level": "measurement", "observed": {"latencyMs": 3}}
            ]
        }
        before = q.numeric_observation_shape(row)
        row["checks"][0]["observed"]["peakRssBytes"] = 450
        self.assertNotEqual(before, q.numeric_observation_shape(row))
        row["checks"][0]["observed"]["latencyMs"] = 4
        self.assertEqual(len(q.numeric_observation_shape(row)), 2)


class SealedEditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(
            os.fsdecode(
                run(
                    "git",
                    "-C",
                    REPO,
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                )
            ).strip()
        ).parent
        root = Path(os.environ.get("OCS_SAFE_PUSH_HISTORY", str(root))).resolve()
        cls.original = root / "out/qualification/full/latest"
        cls.assets = root / "out/acceptance/3facf571"
        if not (cls.assets / "independent-enrollment.json").is_file():
            raise RuntimeError(
                "An independently enrolled historical dossier is required. Set OCS_SAFE_PUSH_HISTORY to its custodian directory."
            )
        cls.enrollment = cls.assets / "independent-enrollment.json"
        cls.public = cls.assets / "observer.pub"
        if (
            not (cls.original / "report.json").is_file()
            or q.decode((cls.original / "report.json").read_bytes())["subject"][
                "revision"
            ]
            != OLD_SUBJECT
        ):
            runs = (root / "out/qualification/full/runs").glob("*/report.json")
            match = next(
                (
                    p
                    for p in runs
                    if q.decode(p.read_bytes())["subject"]["revision"] == OLD_SUBJECT
                    and p.with_suffix(".sig").is_file()
                ),
                None,
            )
            if match is None:
                raise unittest.SkipTest(
                    "the independently enrolled historical dossier is unavailable"
                )
            cls.original = match.parent
        cls.report = q.decode((cls.original / "report.json").read_bytes())
        cls.at = q.stamp(cls.report["finishedAt"]).timestamp() + 1

    def inspect(
        self,
        dossier=None,
        enrollment=None,
        public=None,
        at=None,
        repo=None,
        subject=None,
    ):
        return q._inspect(
            dossier or self.original,
            enrollment or self.enrollment,
            public or self.public,
            repo or REPO,
            OLD_CHECKER,
            subject or self.report["subject"],
            at or self.at,
        )

    def temporary(self, tmp):
        directory = tmp / "dossier"
        shutil.copytree(self.original, directory, copy_function=shutil.copyfile)
        return directory

    def rekey(self, tmp, directory):
        secret, public = key_pair(tmp)
        enrollment = tmp / "owner-enrollment.json"
        ed = q.decode(self.enrollment.read_bytes())
        ed["operatorKey"] = q.sha(public.read_bytes())
        enrollment.write_bytes(q.canonical(ed))
        attestation = directory / "attestation.json"
        info = q.decode(attestation.read_bytes())
        info["operatorKey"] = ed["operatorKey"]
        replace(attestation, q.canonical(info))
        sign(secret, attestation)
        sign(secret, directory / "report.json")
        return secret, public, enrollment

    def test_real_full_edition_and_external_stand(self):
        result = self.inspect()
        self.assertEqual(
            (len(result["claims"]), result["controls"], result["witnesses"]),
            (394, 66, 326),
        )
        self.assertEqual(len(result["metrics"]), 364)
        self.assertEqual(result["metricGaps"], [])
        self.assertEqual(
            result["reportSha256"],
            "9b48d20fa66c191837d364ddaca13d861372df764f86b028150b4624094bb232",
        )
        self.assertEqual(
            result["targetConditionSha256"],
            "fc50d1ab853e2a582d0e65d26de95450422be55c79a60caf554154c6dcd58e83",
        )
        self.assertEqual(
            result["metrics"]["stand.inference/direct/correct"]["value"], "8"
        )
        self.assertEqual(
            result["metrics"]["stand.inference/direct/endToEndMs.p95"]["value"],
            "14.607",
        )
        self.assertEqual(
            result["metrics"]["qualification/full-wall-seconds"]["value"], "218.041273"
        )
        self.assertIn("runtime.repeatability", result["coverageLimits"])

    def test_filesystem_cannot_replace_checker_in_bare_authority(self):
        with tempfile.TemporaryDirectory() as d:
            bare = Path(d) / "objects.git"
            run("git", "clone", "--bare", "--shared", REPO, bare)
            decoy = bare / "assurance"
            decoy.mkdir()
            (decoy / "trust.py").write_text(
                "raise RuntimeError('worktree code was imported')"
            )
            self.assertEqual(len(self.inspect(repo=bare)["claims"]), 394)

    def test_public_dossier_with_separately_owned_bare_repository(self):
        if os.geteuid() == 0 or not shutil.which("sudo") or not shutil.which("setfacl"):
            self.skipTest(
                "requires a separate Linux test UID and disposable filesystem ACLs"
            )
        if subprocess.run(
            ["sudo", "-n", "-u", "nobody", "true"], check=False, capture_output=True
        ).returncode:
            self.skipTest("separate test UID unavailable")
        with tempfile.TemporaryDirectory() as d:
            temp = Path(d)
            bare = temp / "objects.git"
            runtime = temp / "adapter"
            runtime.mkdir()
            for name in ("qualification.py", "metrics.json"):
                shutil.copyfile(q.HERE / name, runtime / name)
            run("git", "init", "--bare", "--template=", bare)
            with tempfile.TemporaryFile() as pack:
                subprocess.run(
                    [
                        "git",
                        "--no-replace-objects",
                        "-C",
                        REPO,
                        "pack-objects",
                        "--revs",
                        "--stdout",
                        "--quiet",
                    ],
                    input=(OLD_CHECKER + "\n" + OLD_SUBJECT + "\n").encode(),
                    stdout=pack,
                    check=True,
                )
                pack.seek(0)
                subprocess.run(
                    ["git", "-C", bare, "index-pack", "--strict", "--stdin"],
                    stdin=pack,
                    stdout=subprocess.PIPE,
                    check=True,
                )
            shutil.copytree(
                self.original, temp / "dossier", copy_function=shutil.copyfile
            )
            shutil.copyfile(self.public, temp / "observer.pub")
            shutil.copyfile(self.enrollment, temp / "enrollment.json")
            run("setfacl", "-R", "-m", "u:nobody:rX", temp)
            plain = subprocess.run(
                [
                    "sudo",
                    "-n",
                    "-u",
                    "nobody",
                    "env",
                    "GIT_CONFIG_GLOBAL=/dev/null",
                    "GIT_CONFIG_NOSYSTEM=1",
                    "git",
                    "-C",
                    bare,
                    "rev-parse",
                    "--git-dir",
                ],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(plain.returncode, 0)
            worker = """
import sys
from pathlib import Path
t=Path(sys.argv[1]);sys.path.insert(0,str(t/"adapter"));import qualification as q
r=q.decode((t/"dossier/report.json").read_bytes())
x=q._inspect(t/"dossier",t/"enrollment.json",t/"observer.pub",t/"objects.git",r["acceptedVerifier"],
             r["subject"],q.stamp(r["finishedAt"]).timestamp()+1)
print(len(x["claims"]),len(x["metrics"]))
"""
            self.assertEqual(
                run(
                    "sudo",
                    "-n",
                    "-u",
                    "nobody",
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    worker,
                    temp,
                ).strip(),
                b"394 364",
            )

    def test_subject_enrollment_freshness_and_witness_location(self):
        with self.assertRaisesRegex(q.QualificationError, "identity"):
            self.inspect(subject={**self.report["subject"], "treeSha256": "0" * 64})
        with self.assertRaisesRegex(q.QualificationError, "stale"):
            self.inspect(at=self.at + 86402)
        with self.assertRaisesRegex(q.QualificationError, "outside"):
            self.inspect(enrollment=self.original / "report.json")
        with tempfile.TemporaryDirectory() as d:
            enrollment = Path(d) / "fixture-enrollment.json"
            data = q.decode(self.enrollment.read_bytes())
            data["target"]["clusterUID"] = "different-cluster"
            enrollment.write_bytes(q.canonical(data))
            with self.assertRaisesRegex(q.QualificationError, "target"):
                self.inspect(enrollment=enrollment)

    def test_authenticated_aggregate_cannot_conceal_dropped_level_or_control(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            folder = self.temporary(tmp)
            secret, pub, enrollment = self.rekey(tmp, folder)
            self.assertEqual(len(self.inspect(folder, enrollment, pub)["claims"]), 394)
            report_path = folder / "report.json"
            for mutation, reason in (
                ("level", "protected replay"),
                ("control", "control roster"),
            ):
                r = q.decode((self.original / "report.json").read_bytes())
                if mutation == "level":
                    r["obligations"][0]["levels"].pop("reference")
                else:
                    r["independentControls"].pop()
                    replace(
                        folder / "controls.json", q.canonical(r["independentControls"])
                    )
                replace(report_path, q.canonical(r))
                sign(secret, report_path)
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaisesRegex(q.QualificationError, reason),
                ):
                    self.inspect(folder, enrollment, pub)

    def test_detached_artifact_and_unsigned_diagnostic_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            folder = self.temporary(tmp)
            asset = folder / "evidence/wire-evidence/Extracted.lean"
            replace(asset, b"unrelated artifact\n")
            with self.assertRaisesRegex(q.QualificationError, "detached bytes"):
                self.inspect(dossier=folder)
            replace(asset, (self.original / asset.relative_to(folder)).read_bytes())
            reference = folder / "reference/conformance.json"
            diag = q.decode(reference.read_bytes())
            diag["checks"][0]["status"] = "fail"
            replace(reference, q.canonical(diag))
            with self.assertRaisesRegex(q.QualificationError, "reference case"):
                self.inspect(dossier=folder)

    def test_resealed_asset_cannot_impersonate_formal_proof(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            folder = self.temporary(tmp)
            secret, pub, enrollment = self.rekey(tmp, folder)
            artifact_name = "evidence/core.ndjson"
            wrong = b"wrong certificate entirely\n"
            replace(folder / artifact_name, wrong)
            report = q.decode((folder / "report.json").read_bytes())
            report["artifactInventory"][artifact_name] = {
                "sha256": q.sha(wrong),
                "bytes": len(wrong),
            }
            replace(folder / "report.json", q.canonical(report))
            sign(secret, folder / "report.json")
            with self.assertRaisesRegex(q.QualificationError, "core certificate"):
                self.inspect(folder, enrollment, pub)


if __name__ == "__main__":
    unittest.main()
