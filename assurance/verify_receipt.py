#!/usr/bin/env python3
"""Verify a stand dossier offline against an independently established enrollment."""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from structure import fingerprint
from trust import save, unique

MAX_EVIDENCE = 32 * 1024 * 1024
HEX256 = re.compile(r"[0-9a-f]{64}")
GIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
TARGET_DIGESTS = (
    "inputSha256",
    "goExecutableSha256",
    "standCaSha256",
    "serverCertificateSha256",
    "relayCertificateSha256",
)
TARGET_IDS = (
    "apiVersion",
    "clusterUID",
    "serviceUID",
    "pvcUID",
    "relayPodUID",
    "relayServiceUID",
    "namespace",
)


def require(condition, error):
    if not condition:
        raise ValueError(error)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, limit=MAX_EVIDENCE):
    # O_NONBLOCK keeps a submitted pipe/device from stalling the verifier.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(
            stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "receipt input must be a regular file"
        )
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "empty or oversized receipt input")
    return raw


def decoded(raw):
    def bad_number(_):
        raise ValueError("nonfinite number in receipt")

    def finite_number(value):
        n = float(value)
        require(math.isfinite(n), "nonfinite number in receipt")
        return n

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_constant=bad_number,
        parse_float=finite_number,
    )


def public_pem(path):
    key = read_file(path, 32 * 1024)
    require(
        re.fullmatch(
            rb"\s*-----BEGIN PUBLIC KEY-----\s+[A-Za-z0-9+/=\r\n]+\s*-----END PUBLIC KEY-----\s*",
            key,
        ),
        "expected a standalone observer public PEM",
    )
    encoded = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=key, capture_output=True, timeout=10
    )
    # RFC 8410 SubjectPublicKeyInfo for Ed25519 with absent parameters and a 32-byte key.
    prefix = bytes.fromhex("302a300506032b6570032100")
    require(
        encoded.returncode == 0
        and len(encoded.stdout) == len(prefix) + 32
        and encoded.stdout.startswith(prefix),
        "expected an enrolled Ed25519 observer public key",
    )
    return key


def full_revision(value):
    require(isinstance(value, str) and GIT_ID.fullmatch(value), "expected a full Git commit ID")
    return value


def committed_bytes(root, rev, path):
    git = ["git", "--no-replace-objects", "-C", str(root)]
    typ = subprocess.run(
        [*git, "cat-file", "-t", full_revision(rev)], capture_output=True, timeout=10
    )
    require(
        typ.returncode == 0 and typ.stdout.strip() == b"commit",
        "approved verifier commit is unavailable locally",
    )
    obj = subprocess.run([*git, "show", rev + ":" + path], capture_output=True, timeout=20)
    require(obj.returncode == 0, "approved verifier edition lacks " + path)
    return obj.stdout


def approved_rules(root, revision):
    policy = decoded(committed_bytes(root, revision, "stand/kubernetes/policy.json"))
    accepted = decoded(committed_bytes(root, revision, "assurance/evidence-index.json"))["checks"]
    rows = {
        k.removeprefix("stand/"): sorted(v) for k, v in accepted.items() if k.startswith("stand/")
    }
    require(
        rows
        and all(
            v and len(v) == len(set(v)) and all(isinstance(c, str) for c in v)
            for v in rows.values()
        ),
        "approved checker has no usable stand evidence inventory",
    )
    return policy, rows


def protected_call(checker_repo, revision, operation, arguments):
    """Replay the actual accepted observer's adjudicator using a clean import path."""
    worker = """import json, sys
sys.path.insert(0, sys.argv[1])
from trust import verify_signature, verify_stand
try:
    args=json.load(sys.stdin)
    if sys.argv[2]=="signature":
        verify_signature(*args)
    elif sys.argv[2]=="stand":
        if verify_stand(*args) is not True: raise ValueError("no accepted stand verdict")
    else:
        raise ValueError("unsupported verification stage")
except (ValueError, TypeError, KeyError, IndexError, OverflowError, AttributeError) as exc:
    print(str(exc)[:200],file=sys.stderr)
    raise SystemExit(1)
"""
    with tempfile.TemporaryDirectory(prefix="ocs-approved-observer-") as folder:
        for name in ("trust.py", "structure.py"):
            (Path(folder) / name).write_bytes(
                committed_bytes(checker_repo, revision, "assurance/" + name)
            )
        result = subprocess.run(
            [sys.executable, "-I", "-c", worker, folder, operation],
            input=json.dumps(arguments, allow_nan=False),
            text=True,
            capture_output=True,
            timeout=30,
        )
        require(
            result.returncode == 0,
            "protected stand adjudicator refused: " + result.stderr.strip()[:220],
        )


def checked_time(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(stamp.tzinfo is not None, "timestamp lacks its clock offset")
    return stamp.timestamp()


def crosscheck_witnesses(stand, policy, enrollment):
    """Reconcile the independent identities and advertised observations across rows."""
    byid = {row["id"]: row["observed"] for row in stand["checks"]}
    target = enrollment["target"]
    criteria = policy["workload"]
    tls = byid["stand.tls"]
    identity = tls["identity"]
    job = tls["serviceJob"]
    restored = byid["L-06.recovery"]
    recovery = restored["controller"]
    require(
        enrollment["readyPods"]["provider"] in (recovery["oldPodUID"], recovery["newPodUID"]),
        "recovery did not observe the independently enrolled provider pod",
    )
    require(
        identity["pod"] == recovery["oldPodUID"]
        and identity["namespace"] == target["namespace"]
        and identity["sourceRevision"] == enrollment["subject"]["revision"]
        and identity["role"] == "probe"
        and tls["wrongCredentialStatus"] == 401,
        "TLS observation refers to a different workload or authority",
    )
    require(
        job["pin"] == identity["manifestDigest"] == enrollment["providerManifestSha256"]
        and job["caSha256"] == target["standCaSha256"]
        and job["dns"] == f"https://ocs-provider.{target['namespace']}.svc/ocs"
        and job["jobUID"]
        and criteria["route"] in job["routes"],
        "in-cluster DNS, manifest or CA witness differs",
    )
    q = byid["A-02.probe"]
    cmp = byid["G-04.comparison"]
    mode = byid["M-02.response"]
    account = q["accountId"]
    require(
        bool(account)
        and all(
            v["accountId"] == account
            and v["route"] == criteria["route"]
            and v["model"] == criteria["model"]
            for v in (q, cmp, mode)
        ),
        "model observation changed account, route or model",
    )
    require(
        mode["requested"] == mode["sent"] == mode["confirmed"] == q["mode"]
        and mode["unsupportedTier"] == "incompatible"
        and mode["verifiedCombinations"] == 3 * criteria["qualitySamples"],
        "requested, sent and confirmed inference evidence diverges",
    )
    before = q["priorUsage"]
    after = q["usage"]
    require(
        after["scope"] == before["scope"] == {"kind": "account", "id": account}
        and after["probeRequests"] - before["probeRequests"] == 3 * criteria["qualitySamples"] + 1
        and after["workRequests"] == before["workRequests"]
        and after["fallbackUses"] == before["fallbackUses"]
        and after["spend"] == before["spend"] == {"amount": "0", "currency": criteria["currency"]},
        "probe attribution or actual spend diverges",
    )
    require(
        q["usage"] == cmp["usage"] and q["priorUsage"] == cmp["priorUsage"],
        "comparison and probe use different evidence",
    )
    short = cmp["results"]["minimum-facts"]
    full = cmp["results"]["full-admissible-history"]
    require(
        short["inputTokens"] < full["inputTokens"]
        and short["requestJsonBytes"] < full["requestJsonBytes"],
        "comparison failed to witness reduced context and request size",
    )
    for stats in cmp["results"].values():
        require(
            type(stats["correct"]) is int and type(stats["tasks"]) is int,
            "ambiguous quality counters",
        )
    axes = byid["M-01.axes"]
    model = axes["current"]
    unmapped = axes["unmapped"]
    require(
        axes["scope"] == after["scope"]
        and axes["revision"]
        and model["id"] == criteria["model"]
        and model["officiallyListed"] is True
        and model["entitled"] is True
        and model["adapterSupported"] is True
        and model["verifiedAt"]
        and model["verifiedOptions"]
        and unmapped["entitled"] is None
        and unmapped["adapterSupported"] is False,
        "catalog, entitlement or verified-option axes collapsed",
    )
    quota = byid["Q-01.reobserve"]
    old = quota["before"]
    new = quota["after"]
    grant = byid["Q-02.read-only"]
    started, finished = checked_time(stand["observedAt"]), checked_time(stand["finishedAt"])
    for value in (
        model["verifiedAt"],
        old["evidence"]["observedAt"],
        new["evidence"]["observedAt"],
    ):
        require(
            started - 1 <= checked_time(value) <= finished + 1,
            "live account observation falls outside the signed qualification interval",
        )
    require(
        old["windowId"] == new["windowId"]
        and old["scope"] == new["scope"] == after["scope"]
        and checked_time(old["resetAt"]) < checked_time(new["resetAt"])
        and checked_time(new["evidence"]["observedAt"]) >= checked_time(old["resetAt"]),
        "quota refresh did not cross the actual reset boundary",
    )
    require(
        grant["account"] == account
        and grant["operations"] == ["limits.read"]
        and grant["grant"]["count"] == grant["afterCount"]
        and grant["grant"]["charge"]
        == {"amount": criteria["resetCharge"], "currency": criteria["currency"]},
        "read-only reset grant lacks scoped authoritative values",
    )
    terms = byid["L-06.terms"]
    resource = byid["stand.resource"]
    loadrow = byid["stand.load"]
    require(
        terms["owner"] == criteria["account"]
        and terms["scope"] == after["scope"]
        and terms["retentionSeconds"] > 0
        and terms["currency"] == criteria["currency"]
        and terms["basis"] == "organization"
        and terms["period"] == "P30D"
        and bool(terms["continuity"])
        and bool(terms["support"]),
        "scoped service terms are insufficient",
    )
    require(
        resource["placement"] == target["namespace"]
        and resource["availableReplicas"] >= 1
        and resource["otherPrincipal"] == "denied"
        and resource["storageClass"]
        and resource["volume"]
        and "ReadWriteOnce" in resource["accessModes"]
        and resource["provisionedCapacity"].get("storage")
        and resource["node"] == loadrow["node"]
        and resource["resourceLimits"] == loadrow["resourceLimits"],
        "placement, tenant denial or native resource evidence differs",
    )
    ui = byid["stand.accessibility"]
    measured = byid["stand.text-and-keyboard"]
    views = ui["views"]
    require(
        ui["pod"] == recovery["oldPodUID"]
        and ui["certificateSha256"] == enrollment["serverCertificateDerSha256"],
        "browser observed another pod or leaf",
    )
    require(
        measured["cssWidths"] == [v["observedCssWidth"] for v in views]
        and measured["fontPixels"] == [v["rootFontPx"] for v in views]
        and measured["horizontalOverflowPixels"] == [0 for _ in views]
        and measured["checkedKeyboardOperations"] == sum(len(v["keyboard"]) for v in views)
        and max(measured["fontPixels"]) >= 2 * min(measured["fontPixels"]),
        "keyboard or enlarged-width measurements disagree",
    )
    require(
        restored["accountId"] == account
        and restored["grants"] == grant["afterCount"]
        and recovery["verifiedRestoredTenantIsolation"] is True
        and HEX256.fullmatch(recovery["backupSha256"]),
        "restored state lacks scoped grant, backup or isolation evidence",
    )


def enrolled(enrollment):
    require(
        isinstance(enrollment, dict) and enrollment.get("format") == "ocs.stand-enrollment/1",
        "expected an independent stand enrollment",
    )
    rev = full_revision(enrollment["acceptedVerifier"])
    subject = enrollment["subject"]
    full_revision(subject["revision"])
    for value in (
        subject["treeSha256"],
        enrollment["operatorKey"],
        enrollment["providerManifestSha256"],
        enrollment["serverCertificateDerSha256"],
    ):
        require(
            isinstance(value, str) and HEX256.fullmatch(value),
            "invalid enrolled subject or observer fingerprint",
        )
    target = enrollment["target"]
    require(
        target["sourceRevision"] == subject["revision"],
        "enrolled target has a different subject revision",
    )
    require(
        all(
            isinstance(target.get(k), str) and target[k] and not target[k].isspace()
            for k in TARGET_IDS
        ),
        "incomplete independently bound cluster, resource or ready relay identity",
    )
    require(
        all(isinstance(target.get(k), str) and HEX256.fullmatch(target[k]) for k in TARGET_DIGESTS),
        "incomplete independently bound executable, source inventory or TLS identity",
    )
    require(
        isinstance(target.get("image"), str)
        and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", target["image"]),
        "enrollment requires an immutable named OCI image",
    )
    image_ids = target["actualOCIIdentities"]
    require(
        isinstance(image_ids, dict)
        and "provider" in image_ids
        and "interaction" in image_ids
        and all(
            isinstance(v, str) and re.search(r"sha256:[0-9a-f]{64}$", v) for v in image_ids.values()
        )
        and target["imageID"] in image_ids.values(),
        "invalid enrolled runtime image identity",
    )
    ready = enrollment["readyPods"]
    require(
        isinstance(ready.get("provider"), str)
        and ready["provider"]
        and ready.get("relay") == target["relayPodUID"],
        "missing independently observed ready pods",
    )
    return rev, subject, target


def verified_rows(stand, approved):
    actual = {}
    for row in stand["checks"]:
        key = row["id"] + "@" + row["level"]
        require(key not in actual, "duplicate signed check " + key)
        claims = row.get("claims", row.get("obligations"))
        if "claims" in row and "obligations" in row:
            require(row["claims"] == row["obligations"], "ambiguous signed claim binding")
        require(
            isinstance(claims, list)
            and claims
            and all(isinstance(x, str) and x for x in claims)
            and len(claims) == len(set(claims)),
            "invalid signed claims for " + key,
        )
        actual[key] = sorted(claims)
    require(
        actual == approved,
        "signed check inventory or atomic claim binding differs from the protected edition",
    )
    return actual


def verify_dossier(directory, enrollment, public_file, checker_repo, *, now=None):
    directory = Path(directory)
    revision, expected_subject, expected_target = enrolled(enrollment)
    at = time.time() if now is None else now
    # Hash and verify the same immutable byte snapshots. A detached stand file
    # is bound both by the signature's digest and by its decoded contents.
    key = public_pem(public_file)
    require(
        digest(key) == enrollment["operatorKey"],
        "observer public key does not match independent enrollment",
    )
    attested = read_file(directory / "attestation.json")
    signature = read_file(directory / "attestation.sig", 1024)
    require(len(signature) == 64, "expected an Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="ocs-receipt-") as state:
        tmp = Path(state)
        for name, raw in (("record", attested), ("signature", signature), ("public.pem", key)):
            (tmp / name).write_bytes(raw)
        protected_call(
            checker_repo,
            revision,
            "signature",
            [str(tmp / name) for name in ("record", "public.pem", "signature")],
        )
    attestation = decoded(attested)
    require(
        attestation["acceptedVerifier"] == revision,
        "signed evidence names another checker revision",
    )
    require(
        attestation["operatorKey"] == enrollment["operatorKey"],
        "signed evidence names another observer",
    )
    subject = attestation["subject"]
    require(
        subject["revision"] == expected_subject["revision"]
        and subject["treeSha256"] == expected_subject["treeSha256"]
        and subject["dirty"] is False
        and type(subject["fileCount"]) is int
        and subject["fileCount"] > 0,
        "signed evidence names another subject or a dirty build",
    )
    if "fileCount" in expected_subject:
        require(
            subject["fileCount"] == expected_subject["fileCount"], "subject inventory count changed"
        )
    require(
        fingerprint(attestation["target"]) == fingerprint(expected_target),
        "signed target differs from independent enrollment",
    )
    raw_stand = read_file(directory / "evidence/stand.json")
    require(
        attestation["standSha256"] == digest(raw_stand),
        "stand report bytes do not match the signed digest",
    )
    stand = decoded(raw_stand)
    require(
        fingerprint(stand) == fingerprint(attestation["stand"]),
        "signed and detached stand observations disagree",
    )
    require(
        fingerprint(stand["target"]) == fingerprint(expected_target),
        "stand payload has another target",
    )
    policy, expected_rows = approved_rules(checker_repo, revision)
    rows = verified_rows(stand, expected_rows)
    protected_call(
        checker_repo, revision, "stand", [stand, policy, expected_subject, expected_target, at]
    )
    crosscheck_witnesses(stand, policy, enrollment)
    return {
        "format": "ocs.stand-verification/1",
        "status": "pass",
        "acceptedVerifier": revision,
        "subjectRevision": expected_subject["revision"],
        "subjectTreeSha256": expected_subject["treeSha256"],
        "clusterUID": expected_target["clusterUID"],
        "namespace": expected_target["namespace"],
        "operatorKey": enrollment["operatorKey"],
        "verifiedAt": datetime.fromtimestamp(at, timezone.utc).isoformat(timespec="seconds"),
        "target": expected_target,
        "readyPods": enrollment["readyPods"],
        "receiptSha256": digest(attested),
        "standSha256": digest(raw_stand),
        "acceptedCheckCount": len(rows),
        "acceptedRows": sorted(rows),
        "acceptedDeploymentClaims": sorted(policy["deploymentClaims"]),
        "observationInterval": [stand["observedAt"], stand["finishedAt"]],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dossier",
        type=Path,
        required=True,
        help="directory with attestation.json, attestation.sig and evidence/stand.json",
    )
    p.add_argument(
        "--enrollment",
        type=Path,
        required=True,
        help="operator-owned independent origin and subject pins",
    )
    p.add_argument(
        "--public-key",
        type=Path,
        required=True,
        help="independently provisioned Ed25519 public PEM",
    )
    p.add_argument(
        "--checker-repo",
        type=Path,
        default=HERE.parent,
        help="local Git database containing the protected edition",
    )
    p.add_argument("--report", type=Path, help="save a machine-readable offline verdict")
    args = p.parse_args()
    if args.report and (
        args.report.resolve().is_relative_to(args.dossier.resolve())
        or args.report.resolve() in {args.public_key.resolve(), args.enrollment.resolve()}
    ):
        p.error("choose a verdict output outside the input dossier, enrollment and public key")
    try:
        require(
            not args.enrollment.resolve().is_relative_to(args.dossier.resolve())
            and not args.public_key.resolve().is_relative_to(args.dossier.resolve()),
            "enrollment and public key must be provisioned outside the submitted dossier",
        )
        outcome = verify_dossier(
            args.dossier, decoded(read_file(args.enrollment)), args.public_key, args.checker_repo
        )
        print("Accepted signed remote stand observation:", outcome["acceptedCheckCount"], "checks.")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as e:
        print("FAIL signed stand observation:", e, file=sys.stderr)
        outcome = {"format": "ocs.stand-verification/1", "status": "fail", "reason": str(e)}
    if args.report:
        save(args.report, outcome)
    return int(outcome["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
