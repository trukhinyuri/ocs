"""Evidence identity and acceptance rules used by the protected release observer."""

import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from structure import fingerprint


def unique(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate evidence field " + key)
        data[key] = value
    return data


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, mode="w", encoding="utf-8", delete=False
    ) as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
        tmp = Path(f.name)
    try:
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def subject_identity(root):
    names = (
        subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
        )
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    files = {name: sha(root / name) for name in sorted(set(names)) if (root / name).is_file()}
    return {
        "revision": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip(),
        "dirty": bool(
            subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"]).strip()
        ),
        "treeSha256": fingerprint(files),
        "fileCount": len(files),
    }


def obligations(catalog, scenario_index):
    scenario_links = {
        rule: set(names)
        for file in scenario_index["requirements"].values()
        for rule, names in file.items()
    }
    expected = set(scenario_links) | set(catalog["extraLocators"])
    if set(catalog["groups"]) != expected:
        raise ValueError(
            "normative rules lacking atomic criteria or unknown groups: "
            + ", ".join(sorted(expected ^ set(catalog["groups"])))
        )
    scenario_links.update(
        {
            "core.schema-resources": {"schema-boundary", "package-inspection"},
            "core.package-distribution": {"distribution"},
            "core.interpretation": {"package-inspection", "approved-effect"},
            "composition.deployment": {"scoped-binding", "native-binding"},
            "composition.outbound": {"peer-authority"},
            "wire.error-table": {"wire-errors"},
            "interface.registry": {"negotiated-session", "extension-evolution"},
            "interface.intent": {"approved-effect"},
            "interface.http-stream": {"stream-delivery"},
            "interface.pages": {"catalog-change", "account-inventory"},
        }
    )
    results = {}
    for rule, group in catalog["groups"].items():
        if rule not in scenario_links:
            raise ValueError("no scenario for rule " + rule)
        for row in group["claims"]:
            key = rule + "." + row["id"]
            if key in results or len(row["levels"]) != len(set(row["levels"])) or not row["levels"]:
                raise ValueError("invalid atomic obligation " + key)
            results[key] = {
                "rule": rule,
                "scope": group["role"],
                "profile": group["profile"],
                "scenarios": sorted(scenario_links[rule]),
                **row,
            }
    represented = {s for row in results.values() for s in row["scenarios"]}
    if represented != set(scenario_index["scenarios"]):
        raise ValueError(
            "unaccounted or unknown reference scenario: "
            + ", ".join(sorted(represented ^ set(scenario_index["scenarios"])))
        )
    return results


def compare_policy(old, new, old_scope, new_scope):
    errors = []
    if old_scope != new_scope:
        errors.append("scope/assumptions changed relative to accepted contour")
    for key, item in old.items():
        n = new.get(key)
        if n is None:
            errors.append("removed atomic obligation " + key)
            continue
        if any(item[field] != n[field] for field in ("scope", "expected", "profile")):
            errors.append("changed predicate, scope or premises: " + key)
        if set(item["levels"]) - set(n["levels"]):
            errors.append("weakened required evidence level: " + key)
        if set(item["scenarios"]) - set(n["scenarios"]):
            errors.append("lost required scenario linkage: " + key)
    return errors


def validate_time(value, now, lifetime):
    if not isinstance(value, str):
        raise ValueError("missing observation time")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("observation time has no offset")
    age = now - stamp.timestamp()
    if age < -5 or age > lifetime:
        raise ValueError(f"stale or future observation ({age:.1f}s)")


def verify_stand(stand, policy, subject, target, now):
    if stand.get("status") != "pass":
        raise ValueError("live stand qualification incomplete")
    if stand.get("target") != target or target["sourceRevision"] != subject["revision"]:
        raise ValueError("wrong target or source revision in deployment receipt")
    validate_time(stand["observedAt"], now, policy["workload"]["maximumReceiptAgeSeconds"])
    validate_time(stand["finishedAt"], now, policy["workload"]["maximumReceiptAgeSeconds"])
    if datetime.fromisoformat(stand["finishedAt"].replace("Z", "+00:00")) < datetime.fromisoformat(
        stand["observedAt"].replace("Z", "+00:00")
    ):
        raise ValueError("stand observation interval reversed")
    seen = set()
    byid = {}
    for row in stand.get("checks", []):
        key = row["id"], row["level"]
        if key in seen or row["status"] != "pass" or not row["observed"]:
            raise ValueError("invalid deployment observation " + key[0])
        seen.add(key)
        byid[row["id"]] = row
        validate_time(row["observedAt"], now, policy["workload"]["maximumReceiptAgeSeconds"])

        def epoch(stamp):
            return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()

        if (
            not epoch(stand["observedAt"]) - 1
            <= epoch(row["observedAt"])
            <= epoch(stand["finishedAt"]) + 1
        ):
            raise ValueError("observation outside the witnessed qualification interval")
        if row["level"] not in ("deployment", "measurement"):
            raise ValueError("wrong method for a stand observation")
    missing = set(policy["deploymentClaims"]) - {
        a
        for row in stand["checks"]
        if row["level"] == "deployment"
        for a in row.get("claims", row.get("obligations", []))
    }
    if missing:
        raise ValueError("missing live observations: " + ", ".join(sorted(missing)))
    for claim, check_id in (
        ("W-08.tls", "stand.tls"),
        ("B-07.domain", "stand.load"),
        ("L-01.policy", "stand.resource"),
        ("L-04.tail", "stand.load"),
        ("U-03.accessibility", "stand.accessibility"),
        ("L-06.recovery", "L-06.recovery"),
    ):
        row = byid.get(check_id, {})
        if row.get("level") != "deployment" or claim not in row.get(
            "claims", row.get("obligations", [])
        ):
            raise ValueError("wrong deployment check or level: " + claim)
    for field in (
        "standCaSha256",
        "serverCertificateSha256",
        "relayCertificateSha256",
        "goExecutableSha256",
    ):
        if (
            not isinstance(target.get(field), str)
            or len(target[field]) != 64
            or any(ch not in "0123456789abcdef" for ch in target[field])
        ):
            raise ValueError("missing or invalid target artifact: " + field)
    limits = policy["workload"]
    quality = byid["G-04.comparison"]["observed"]
    routes = quality["results"]
    if set(routes) != {"direct", "full-admissible-history", "minimum-facts"}:
        raise ValueError("missing comparative inference route")
    if (
        quality["route"] != limits["route"]
        or quality["model"] != limits["model"]
        or quality["relay"]["podUID"] != target["relayPodUID"]
    ):
        raise ValueError("comparison used an unbound model or relay")
    for name, route in routes.items():
        if (
            route["tasks"] != limits["qualitySamples"]
            or not limits["minimumCorrect"] <= route["correct"] <= route["tasks"]
            or route["endToEndMs"]["p95"] > limits["p95LimitMs"]
        ):
            raise ValueError("failed live model quality or time bound: " + name)
        if any(
            type(route[k]) is not int or route[k] < 0
            for k in (
                "requestJsonBytes",
                "responseJsonBytes",
                "upstreamRequestJsonBytes",
                "upstreamResponseJsonBytes",
                "inputTokens",
                "outputTokens",
            )
        ):
            raise ValueError("unsupported or negative traffic accounting")
        if route["allHopJsonBytes"] != sum(
            route[k]
            for k in (
                "requestJsonBytes",
                "responseJsonBytes",
                "upstreamRequestJsonBytes",
                "upstreamResponseJsonBytes",
            )
        ):
            raise ValueError("hop traffic does not reconcile")
        if name == "direct":
            if route["relayPodUID"] is not None or route["upstreamRequestJsonBytes"] != 0:
                raise ValueError("unexpected direct inference hop")
        elif (
            route["relayPodUID"] != target["relayPodUID"]
            or not min(route["upstreamRequestJsonBytes"], route["upstreamResponseJsonBytes"]) > 0
        ):
            raise ValueError("unobserved relay inference")
    prices = byid["P-03.basis"]["observed"]
    for key, amount in (
        ("published", limits["publishedListPrice"]),
        ("observedAccountPrice", limits["accountPrice"]),
    ):
        plan = prices[key]
        if (
            plan["price"] != {"amount": amount, "currency": limits["currency"]}
            or plan["basis"] != "organization"
            or plan["period"] != "P30D"
        ):
            raise ValueError("wrong live price or accounting basis: " + key)
    reset = byid["Q-02.read-only"]["observed"]
    if reset["beforeCount"] != reset["afterCount"] or reset["beforeCount"] <= 0:
        raise ValueError("discovery consumed or failed to witness a reset grant")
    ui = byid["stand.accessibility"]["observed"]
    if (
        not {v["requestedCssWidth"] for v in ui["views"]} >= {320, 960}
        or any(
            v["scrollWidth"] > v["observedCssWidth"]
            or not v["focusVisibleAfterClose"]
            or v["accountRowsChecked"] < 1
            for v in ui["views"]
        )
        or ui["scriptCanReadCredential"]
        or ui["namespace"] != target["namespace"]
        or ui["sourceRevision"] != target["sourceRevision"]
    ):
        raise ValueError("browser observation failed the qualified task")
    data = byid["stand.load"]["observed"]
    samples = data["samplesMs"]
    limits = policy["workload"]
    if (
        len(samples) != limits["replicates"]
        or data["concurrency"] != limits["concurrency"]
        or not all(
            type(v) in (float, int) and 0 <= v <= limits["requestDeadlineMs"] for v in samples
        )
    ):
        raise ValueError("changed workload size, domain or individual latency threshold")
    import math

    p95 = sorted(samples)[math.ceil(0.95 * len(samples)) - 1]
    if p95 != data["p95Ms"] or p95 > limits["p95LimitMs"]:
        raise ValueError("invalid latency percentile")
    cancel = data["cancellation"]
    if (
        cancel["accepted"] != 204
        or cancel["terminalCode"] != -33004
        or not 0 <= cancel["elapsedMs"] <= limits["requestDeadlineMs"]
    ):
        raise ValueError("missing acknowledged, bounded stream cancellation")
    recovery = byid["L-06.recovery"]["observed"]["controller"]
    if (
        not 0 <= recovery["elapsedMs"] <= limits["recoveryLimitSeconds"] * 1000
        or recovery["oldPodUID"] == recovery["newPodUID"]
        or recovery["pvcUID"] != target["pvcUID"]
    ):
        raise ValueError("unqualified restoration or mismatched tenant state")
    return True


def sign(path, private, signature):
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private),
            "-in",
            str(path),
            "-out",
            str(signature),
        ],
        check=True,
        timeout=10,
        stdout=subprocess.DEVNULL,
    )


def verify_signature(path, public, signature):
    p = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public),
            "-in",
            str(path),
            "-sigfile",
            str(signature),
        ],
        capture_output=True,
        timeout=10,
    )
    if p.returncode:
        raise ValueError("deployment receipt signature mismatch")


def observer_keys(directory):
    """Private operator state outside the candidate checkout or deployed image."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.stat().st_mode & 0o077:
        raise ValueError("observer state must be private")
    private = directory / "observer.key"
    public = directory / "observer.pub"
    # Exclusive creation prevents two independent initializations from disagreeing.
    import fcntl

    with (directory / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not private.is_file():
            if public.exists():
                raise ValueError("approved observer public key has no matching local signer")
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
                tmp = Path(f.name)
            try:
                subprocess.run(
                    ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(tmp)],
                    capture_output=True,
                    check=True,
                )
                tmp.chmod(0o600)
                tmp.replace(private)
            finally:
                tmp.unlink(missing_ok=True)
        if private.is_symlink() or private.stat().st_mode & 0o077:
            raise ValueError("observer key permissions")
        raw = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout"])
        if public.exists() and (public.is_symlink() or public.read_bytes() != raw):
            raise ValueError("observer enrollment key changed")
        if not public.exists():
            public.write_bytes(raw)
    return private, public


def admit_reports(catalog, reports, subject, require_stand, required_checks=None):
    """Close each scoped cell only with evidence from a freshly executed approved suite."""
    cells = defaultdict(list)
    unexpected = []
    keys = set()
    rows = []
    for family, (report, path, command) in reports.items():
        origin = sha(path)
        for row in report["checks"]:
            key = family + "/" + row["id"] + "@" + row["level"]
            if key in keys:
                unexpected.append("duplicate evidence ID: " + key)
                continue
            keys.add(key)
            claims = sorted(set(row.get("claims", row.get("obligations", []))))
            if not claims:
                unexpected.append("unattributed evidence: " + key)
            for atom in claims:
                if atom not in catalog:
                    unexpected.append("unknown obligation: " + atom)
            if required_checks is not None and (
                key not in required_checks or set(required_checks[key]) != set(claims)
            ):
                unexpected.append("changed or unapproved evidence binding: " + key)
            if row.get("status") != "pass" or row.get("observed") is None:
                unexpected.append("failed or missing result: " + key)
                continue
            # Signed deployment results originate only from the stand verifier.
            if row["level"] == "deployment" and family != "stand":
                unexpected.append("untrusted deployment origin: " + key)
                continue
            normalized = {
                "runtime-observation": "reference",
                "artifact-observation": "reference",
            }.get(row["level"], row["level"])
            for atom in claims:
                cells[(atom, normalized)].append(key)
                if row["level"] == "artifact-observation":
                    cells[(atom, "artifact-observation")].append(key)
            rows.append(
                {
                    "id": key,
                    "claims": claims,
                    "level": row["level"],
                    "scope": report.get("scope", family),
                    "assumptions": row.get("assumptions", report.get("assumptions", [])),
                    "subject": subject["treeSha256"],
                    "report": "evidence/" + path.name,
                    "reportSha256": origin,
                    "replay": command,
                    "theorem": row.get("theorem"),
                    "result": "pass",
                }
            )
    if required_checks:
        unexpected += [
            "missing accepted evidence: " + k
            for k in sorted(set(required_checks) - keys)
            if require_stand or not k.startswith("stand/")
        ]
    totals = defaultdict(Counter)
    profile = defaultdict(Counter)
    scenarios = defaultdict(Counter)
    result = []
    for key, c in catalog.items():
        levels = {}
        for level in c["levels"]:
            ids = cells.get((key, level), [])
            status = "accepted" if ids else "open"
            levels[level] = {"status": status, "evidence": ids}
            totals[level][status] += 1
            profile[c["profile"]][status] += 1
            for scenario in c["scenarios"]:
                scenarios[scenario][status] += 1
        result.append(
            {
                "id": key,
                "source": c["rule"],
                "property": c["expected"],
                "subjectRole": c["scope"],
                "profile": c["profile"],
                "scenarios": c["scenarios"],
                "levels": levels,
            }
        )
    missing = [
        r["id"] + "@" + level
        for r in result
        for level, e in r["levels"].items()
        if e["status"] != "accepted" and (level != "deployment" or require_stand)
    ]
    return {
        "obligations": result,
        "evidence": rows,
        "byLevel": {k: {**v, "applicable": sum(v.values())} for k, v in totals.items()},
        "byProfile": {k: {**v, "applicable": sum(v.values())} for k, v in profile.items()},
        "byScenario": {k: {**v, "applicable": sum(v.values())} for k, v in scenarios.items()},
        "scenarioCounting": "Overlapping evidence slots in linked normative rules. Individual property receipts identify their precise subjects.",
        "openRequired": missing,
        "failures": unexpected,
        "status": "pass" if not missing and not unexpected else "fail",
    }
