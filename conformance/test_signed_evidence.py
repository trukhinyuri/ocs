"""Portable real-signature controls using a synthetic stand and a frozen Git test edition."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance"))
from trust import observer_keys, save, sha, sign
from verify_receipt import verify_dossier

T0 = 1_893_456_000


def stamp(seconds):
    return (
        datetime.fromtimestamp(seconds, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


BINDINGS = {
    "stand.tls": ["W-08.tls"],
    "stand.resource": ["L-01.policy"],
    "stand.load": ["B-07.domain", "L-04.tail"],
    "P-03.basis": ["P-03.basis"],
    "L-06.terms": ["L-06.terms"],
    "Q-02.read-only": ["Q-02.read-only"],
    "Q-01.reobserve": ["Q-01.reobserve"],
    "M-01.axes": ["M-01.axes"],
    "M-02.response": ["M-02.response"],
    "A-02.probe": ["A-02.probe"],
    "G-04.comparison": ["G-04.comparison"],
    "stand.accessibility": ["U-03.accessibility"],
    "stand.text-and-keyboard": ["U-03.accessibility"],
    "L-06.recovery": ["L-06.recovery"],
}


def example(policy, revision, public):
    w = policy["workload"]
    cur = w["currency"]
    model = w["model"]
    route = w["route"]
    namespace = w["namespace"]
    src = "f" * 40
    image = "example.invalid/stand@sha256:" + "c" * 64
    target = {
        "apiVersion": "v1.37.2",
        "clusterUID": "unit-cluster",
        "serviceUID": "unit-service",
        "namespace": namespace,
        "image": image,
        "imageID": image,
        "sourceRevision": src,
        "inputSha256": "b" * 64,
        "pvcUID": "unit-pvc",
        "goExecutableSha256": "a" * 64,
        "actualOCIIdentities": {"provider": image, "interaction": image},
        "relayPodUID": "relay-one",
        "relayServiceUID": "relay-service",
        "standCaSha256": "6" * 64,
        "serverCertificateSha256": "7" * 64,
        "relayCertificateSha256": "8" * 64,
    }
    subject = {"revision": src, "treeSha256": "d" * 64, "fileCount": 19, "dirty": False}
    enrollment = {
        "format": "ocs.stand-enrollment/1",
        "acceptedVerifier": revision,
        "operatorKey": sha(public),
        "subject": {k: subject[k] for k in ("revision", "treeSha256", "fileCount")},
        "target": copy.deepcopy(target),
        "providerManifestSha256": "9" * 64,
        "serverCertificateDerSha256": "a" * 64,
        "readyPods": {"provider": "pod-after", "relay": "relay-one"},
    }
    account = "scoped-account"
    scope = {"kind": "account", "id": account}
    params = {"reasoning": "off", "tier": "standard"}
    qn = w["qualitySamples"]

    def money(amount):
        return {"amount": str(amount), "currency": cur}

    usage = {
        "scope": scope,
        "workRequests": 2,
        "fallbackUses": 0,
        "spend": money(0),
        "probeRequests": 3 * qn + 1,
    }
    modes = {}
    for idx, kind in enumerate(("direct", "full-admissible-history", "minimum-facts")):
        forwarded = 40 if idx else 0
        size = 120 if idx == 1 else 64
        quantile = {"p50": 1.0, "p95": 2.0, "p99": 2.5, "max": 3.0, "n": qn}
        modes[kind] = {
            "tasks": qn,
            "correct": qn,
            "endToEndMs": quantile,
            "synchronousFirstUsefulMs": quantile,
            "requestJsonBytes": size,
            "responseJsonBytes": 30,
            "upstreamRequestJsonBytes": forwarded,
            "upstreamResponseJsonBytes": forwarded,
            "inputTokens": 8 if idx == 1 else 2,
            "outputTokens": 1,
            "allHopJsonBytes": size + 30 + 2 * forwarded,
            "relayPodUID": "relay-one" if idx else None,
        }
    probe = {
        "route": route,
        "model": model,
        "accountId": account,
        "mode": params,
        "usage": usage,
        "priorUsage": {**usage, "probeRequests": 0},
    }

    def plan(a):
        return {"price": money(a), "basis": "organization", "period": "P30D"}

    win = {"windowId": "burst", "scope": scope, "evidence": {"observedAt": stamp(T0)}}
    views = [
        {
            "requestedCssWidth": n,
            "observedCssWidth": n - 15,
            "scrollWidth": n - 15,
            "rootFontPx": f,
            "focusVisibleAfterClose": True,
            "accountRowsChecked": 1,
            "keyboard": ["Refresh", "Open", "Close"],
        }
        for n, f in [(960, 16), (320, 32)]
    ]
    resources = {"limits": {"cpu": "1", "memory": "256Mi"}, "requests": {"cpu": "50m"}}
    witness = {
        "stand.tls": {
            "identity": {
                "pod": "pod-before",
                "namespace": namespace,
                "role": "probe",
                "sourceRevision": src,
                "manifestDigest": enrollment["providerManifestSha256"],
            },
            "wrongCredentialStatus": 401,
            "serviceJob": {
                "pin": enrollment["providerManifestSha256"],
                "caSha256": target["standCaSha256"],
                "dns": f"https://ocs-provider.{namespace}.svc/ocs",
                "jobUID": "job-observed",
                "routes": [route],
            },
        },
        "stand.resource": {
            "placement": namespace,
            "availableReplicas": 1,
            "otherPrincipal": "denied",
            "storageClass": "local",
            "volume": "disk",
            "accessModes": ["ReadWriteOnce"],
            "provisionedCapacity": {"storage": "1Gi"},
            "node": "unit",
            "resourceLimits": resources,
        },
        "stand.load": {
            "samplesMs": [1.5] * w["replicates"],
            "p95Ms": 1.5,
            "concurrency": w["concurrency"],
            "node": "unit",
            "resourceLimits": resources,
            "cancellation": {"accepted": 204, "terminalCode": -33004, "elapsedMs": 4.0},
        },
        "P-03.basis": {
            "published": plan(w["publishedListPrice"]),
            "observedAccountPrice": plan(w["accountPrice"]),
        },
        "L-06.terms": {
            "owner": w["account"],
            "scope": scope,
            "retentionSeconds": 86400,
            "currency": cur,
            "basis": "organization",
            "period": "P30D",
            "continuity": "restore verified data",
            "support": "stand owner",
        },
        "Q-02.read-only": {
            "beforeCount": 1,
            "afterCount": 1,
            "account": account,
            "operations": ["limits.read"],
            "grant": {"count": 1, "charge": money(w["resetCharge"])},
        },
        "Q-01.reobserve": {
            "before": {**win, "resetAt": stamp(T0 + 1)},
            "after": {**win, "resetAt": stamp(T0 + 3), "evidence": {"observedAt": stamp(T0 + 1)}},
        },
        "M-01.axes": {
            "scope": scope,
            "revision": "cat-1",
            "current": {
                "id": model,
                "officiallyListed": True,
                "entitled": True,
                "adapterSupported": True,
                "verifiedAt": stamp(T0 + 1),
                "verifiedOptions": [params],
            },
            "unmapped": {"id": "unmapped", "entitled": None, "adapterSupported": False},
        },
        "M-02.response": {
            "accountId": account,
            "route": route,
            "model": model,
            "requested": params,
            "sent": params,
            "confirmed": params,
            "verifiedCombinations": 3 * qn,
            "unsupportedTier": "incompatible",
        },
        "A-02.probe": probe,
        "G-04.comparison": {**probe, "results": modes, "relay": {"podUID": "relay-one"}},
        "stand.accessibility": {
            "views": views,
            "scriptCanReadCredential": False,
            "namespace": namespace,
            "sourceRevision": src,
            "pod": "pod-before",
            "certificateSha256": enrollment["serverCertificateDerSha256"],
        },
        "stand.text-and-keyboard": {
            "cssWidths": [v["observedCssWidth"] for v in views],
            "fontPixels": [16, 32],
            "horizontalOverflowPixels": [0, 0],
            "checkedKeyboardOperations": 6,
        },
        "L-06.recovery": {
            "accountId": account,
            "grants": 1,
            "controller": {
                "oldPodUID": "pod-before",
                "newPodUID": "pod-after",
                "pvcUID": "unit-pvc",
                "elapsedMs": 100.0,
                "backupSha256": "c" * 64,
                "verifiedRestoredTenantIsolation": True,
            },
        },
    }
    rows = [
        {
            "id": key,
            "level": "measurement" if key == "stand.text-and-keyboard" else "deployment",
            "status": "pass",
            "claims": claims,
            "observedAt": stamp(T0 + 2),
            "observed": witness[key],
        }
        for key, claims in BINDINGS.items()
    ]
    stand = {
        "scope": "synthetic signed verifier test only",
        "status": "pass",
        "observedAt": stamp(T0),
        "finishedAt": stamp(T0 + 4),
        "target": copy.deepcopy(target),
        "checks": rows,
    }
    return enrollment, {
        "acceptedVerifier": revision,
        "operatorKey": sha(public),
        "subject": subject,
        "target": target,
        "stand": stand,
    }


class SignedEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.tmp = Path(temp.name)
        self.private, self.public = observer_keys(self.tmp / "observer")
        self.foreign, self.other_public = observer_keys(self.tmp / "other-observer")
        self.repo = self.tmp / "approved-git"
        self.repo.mkdir()

        def git(*args, data=None):
            return (
                subprocess.run(
                    ["git", "-C", str(self.repo), *args],
                    input=data,
                    capture_output=True,
                    check=True,
                )
                .stdout.decode()
                .strip()
            )

        git("init", "--quiet")
        policy = json.loads((ROOT / "stand/kubernetes/policy.json").read_bytes())
        save(self.repo / "stand/kubernetes/policy.json", policy)
        fixed = {
            f"stand/{key}@"
            + ("measurement" if key == "stand.text-and-keyboard" else "deployment"): v
            for key, v in BINDINGS.items()
        }
        save(self.repo / "assurance/evidence-index.json", {"checks": fixed})
        for file in ("trust.py", "structure.py"):
            shutil.copyfile(ROOT / "assurance" / file, self.repo / "assurance" / file)
        git("add", "--", ".")
        oid = git(
            "-c",
            "user.name=OCS test fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit-tree",
            git("write-tree"),
            data=b"Independent synthetic checker input\n",
        )
        self.dossier = self.tmp / "dossier"
        (self.dossier / "evidence").mkdir(parents=True)
        self.enrollment, self.baseline = example(policy, oid, self.public)

    def emit(self, envelope, private=None):
        stand = self.dossier / "evidence/stand.json"
        save(stand, envelope["stand"])
        save(self.dossier / "attestation.json", {**envelope, "standSha256": sha(stand)})
        sign(
            self.dossier / "attestation.json",
            private or self.private,
            self.dossier / "attestation.sig",
        )

    def verify(self, enrollment=None, key=None, now=T0 + 5):
        return verify_dossier(
            self.dossier, enrollment or self.enrollment, key or self.public, self.repo, now=now
        )

    def test_valid_receipt_is_offline_and_edition_pinned(self):
        self.emit(self.baseline)
        # Editing the working policy or its bindings cannot control a protected verdict.
        save(self.repo / "stand/kubernetes/policy.json", {"workload": {"minimumCorrect": 99}})
        save(self.repo / "assurance/evidence-index.json", {"checks": {}})
        accepted = self.verify()
        self.assertEqual(accepted["status"], "pass")
        self.assertEqual(accepted["acceptedCheckCount"], len(BINDINGS))

    def test_independently_resigned_target_subject_checker_and_key_are_rejected(self):
        for field, value in [
            ("clusterUID", "other-cluster"),
            ("serviceUID", "another-service"),
            ("namespace", "another-namespace"),
            ("image", "example.invalid/stand@sha256:" + "0" * 64),
            ("sourceRevision", "2" * 40),
            ("standCaSha256", "1" * 64),
            ("serverCertificateSha256", "2" * 64),
            ("relayCertificateSha256", "3" * 64),
            ("goExecutableSha256", "0" * 64),
            ("inputSha256", "0" * 64),
            ("pvcUID", "replacement"),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.baseline)
                changed["target"][field] = value
                changed["stand"]["target"][field] = value
                self.emit(changed)
                with self.assertRaisesRegex(ValueError, "target"):
                    self.verify()
        for field, adjust, message in [
            ("build", lambda e: e["subject"].update(treeSha256="7" * 64), "subject"),
            ("dirty", lambda e: e["subject"].update(dirty=True), "subject"),
            ("checker", lambda e: e.update(acceptedVerifier="1" * 40), "checker"),
            ("key", lambda e: e.update(operatorKey=sha(self.other_public)), "observer"),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.baseline)
                adjust(changed)
                self.emit(changed)
                with self.assertRaisesRegex(ValueError, message):
                    self.verify()
        changed = copy.deepcopy(self.baseline)
        changed["operatorKey"] = sha(self.other_public)
        self.emit(changed, self.foreign)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "public key"):
            self.verify(key=self.other_public)

    def test_signed_stale_missing_substituted_or_unmeasured_rows_fail(self):
        def row(e, key):
            return next(r for r in e["stand"]["checks"] if r["id"] == key)

        cases = [
            ("old row", lambda e: row(e, "stand.load").update(observedAt=stamp(T0 - 90000))),
            ("future", lambda e: e["stand"].update(finishedAt=stamp(T0 + 90000))),
            ("missing", lambda e: e["stand"]["checks"].pop()),
            ("foreign claim", lambda e: row(e, "stand.tls").update(claims=["U-03.accessibility"])),
            ("skipped", lambda e: row(e, "stand.accessibility").update(status="skipped")),
            (
                "unknown row",
                lambda e: e["stand"]["checks"].append({**row(e, "stand.tls"), "id": "unapproved"}),
            ),
            ("workload", lambda e: row(e, "stand.load")["observed"]["samplesMs"].pop()),
            ("quantile", lambda e: row(e, "stand.load")["observed"].update(p95Ms=0)),
            (
                "model",
                lambda e: row(e, "G-04.comparison")["observed"]["results"]["direct"].update(
                    correct=0
                ),
            ),
            (
                "negative latency",
                lambda e: row(e, "G-04.comparison")["observed"]["results"]["minimum-facts"][
                    "endToEndMs"
                ].update(p95=-1),
            ),
            (
                "wrong window",
                lambda e: row(e, "Q-01.reobserve")["observed"]["after"].update(resetAt=stamp(T0)),
            ),
            (
                "catalog",
                lambda e: row(e, "M-01.axes")["observed"]["unmapped"].update(adapterSupported=True),
            ),
            (
                "different runtime",
                lambda e: row(e, "stand.tls")["observed"]["serviceJob"].update(pin="0" * 64),
            ),
            (
                "keyboard",
                lambda e: row(e, "stand.text-and-keyboard")["observed"].update(
                    checkedKeyboardOperations=0
                ),
            ),
            (
                "recovery",
                lambda e: row(e, "L-06.recovery")["observed"]["controller"].update(
                    newPodUID="pod-before"
                ),
            ),
        ]
        for name, adjust in cases:
            with self.subTest(name=name):
                e = copy.deepcopy(self.baseline)
                adjust(e)
                self.emit(e)
                with self.assertRaises((ValueError, KeyError)):
                    self.verify()
        self.emit(self.baseline)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.verify(now=T0 + 86406)

    def test_detached_report_and_signature_bind_exact_bytes(self):
        self.emit(self.baseline)
        path = self.dossier / "evidence/stand.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.verify()
        self.emit(self.baseline)
        path = self.dossier / "attestation.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify()
