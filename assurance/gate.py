#!/usr/bin/env python3
"""Trusted edition checker. The launcher materializes this file from an explicit Git commit."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

HOME_TREE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME_TREE / "assurance"))
from controls import checks as policy_controls
from controls import stand_controls
from structure import compare as structural_changes
from structure import fingerprint, inventory
from trust import (
    admit_reports,
    compare_policy,
    load,
    obligations,
    observer_keys,
    save,
    sha,
    sign,
    subject_identity,
    verify_signature,
    verify_stand,
)


def rel(path, root):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def historical_agent(root, archive, output):
    """Use the current real caller and validator against the original executor."""
    folder = output / "historical-agent"
    folder.mkdir()
    for name in ("ocs.json", "executor.py"):
        (folder / name).write_bytes(archive.read("examples/dialog/" + name))
    sys.path.insert(0, str(root / "reference"))
    from contracts import utc_at, validate
    from host import Channel, Failure

    pin = sha(folder / "ocs.json")
    caller = Channel(folder / "executor.py", budget=5)
    try:
        deadline = utc_at(time.time() + 5)
        desc = caller.request(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.agents/0.1"],
                "meta": {"deadline": deadline},
            },
        )
        validate("wire", desc, "describeResult")
        if desc["manifestDigest"] != pin:
            raise ValueError("old agent descriptor changed")

        def invoke(mid, text):
            response = caller.request(
                "tool.call",
                {
                    "operation": "agent.exchange",
                    "version": "1.0.0",
                    "input": {
                        "messageId": mid,
                        "contextId": "mixed-versions",
                        "parts": [{"type": "text", "text": text}],
                        "accept": ["text/plain"],
                    },
                    "meta": {"protocol": "0.1", "manifestDigest": pin, "deadline": deadline},
                },
            )
            validate("profile-wire", response["data"], "agentReply")
            message = response["data"]["message"]
            if message["replyTo"] != mid:
                raise ValueError("historical reply attribution changed")
            return message["parts"][0]["text"]

        value = invoke("read", "Read demo")
        if (
            not re.fullmatch("[0-9a-f]{16}", value)
            or invoke("confirm", "Confirm " + value) != "confirmed"
        ):
            raise ValueError("candidate caller failed old actor roundtrip")
        try:
            invoke("denied", "Read private")
        except Failure as exc:
            if exc.error["data"]["kind"] != "denied":
                raise ValueError("old executor rejected with wrong classification")
        else:
            raise ValueError("ungranted old actor read succeeded")
        return {
            "archivedPin": pin,
            "archivedExecutorSha256": sha(folder / "executor.py"),
            "currentCallerSha256": sha(root / "reference/host.py"),
            "successfulExchanges": 2,
            "refusals": 1,
            "scope": "dedicated local process channel",
        }
    finally:
        caller.close()


def feature_matrix(registry, reports, root):
    rows = {}

    def observe(method, item, source):
        if method not in registry:
            raise ValueError("unpublished registered operation " + method)
        old = registry[method]
        if (item["inputSchema"], item["outputSchema"], item["channel"]) != (
            old["input"],
            old["output"],
            old["channel"],
        ):
            raise ValueError("old/new shape or channel mismatch " + method)
        if item.get("publishedMethodSha256", fingerprint(old)) != fingerprint(old):
            raise ValueError("changed published operation meaning " + method)
        counts = item.get("counts", {})
        admitted = item.get("accepted", counts.get("result", 0) + counts.get("notification", 0))
        if not isinstance(admitted, int) or admitted < 1:
            return
        rows.setdefault(method, []).append(
            {"observedBy": source, "accepted": admitted, "transcript": item}
        )

    for domain, (data, path, _) in reports.items():
        for method, item in data.get("featureMatrix", {}).items():
            observe(method, item, domain)
        for check in data["checks"]:
            detail = check.get("observed", {})
            if isinstance(detail, dict):
                for method, item in detail.get("registeredExchanges", {}).items():
                    observe(method, item, domain + "/" + check["id"])
    unknown = sorted(set(registry) - set(rows))
    if unknown:
        raise ValueError("missing actual published-operation witnesses: " + ", ".join(unknown))
    # The previous working draft ships a genuine peer and agent but no executable
    # for most optional profiles. The historical data schemas are still replayable.
    from zipfile import ZipFile

    with tempfile.TemporaryDirectory() as tmp:
        baseline = "6f6e22842347806f2963ef1984d9ea592fdddaf0"
        zipfile = Path(tmp) / "packages.zip"
        subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                str(root),
                "archive",
                "--format=zip",
                "-o",
                str(zipfile),
                baseline,
                "examples",
                "reference/go",
                "spec/profiles",
            ],
            check=True,
            capture_output=True,
        )
        with ZipFile(zipfile) as z:
            published = json.loads(z.read("spec/profiles/operations.json"))["operations"]
            if any(registry.get(row["method"]) != row for row in published):
                raise ValueError("registry differs from named historical contract")
            reverse_agent = historical_agent(root, z, Path(tmp))
            old_exec = {}
            for name in z.namelist():
                if name.endswith("/ocs.json"):
                    pkg = json.loads(z.read(name))
                    if pkg["runtime"]["binding"] != "data":
                        for op in pkg["exports"]:
                            old_exec.setdefault(op["id"], []).append(pkg["id"])
    all_profiles = {p["id"] for p in load(root / "spec/profiles/index.json")["profiles"]}
    consumers = defaultdict(set)
    for name, witnesses in rows.items():
        consumers[registry[name]["profile"]].update(
            w["observedBy"].split("/")[0] for w in witnesses
        )
    if not reports["platform"][0]["checks"] or not reports["wire"][0]["checks"]:
        raise ValueError("missing peer or platform consumer")
    consumers["ocs.platform/0.1"].add("platform")
    consumers["ocs.peers/0.1"].add("wire")
    if set(consumers) != all_profiles:
        raise ValueError(
            "unqualified normative profile consumer: "
            + ", ".join(sorted(all_profiles ^ set(consumers)))
        )
    boundaries = {
        "stream": "I-02.credit",
        "events": "I-03.dedup",
        "artifacts": "I-04.scope",
        "effects": "E-03.preconditions",
        "jobs": "J-01.continue",
        "providers": "M-02.invocation",
        "agents": "G-02.trust",
        "presentation": "U-03.surface-event",
        "cloud": "L-01.resource",
        "platform": "L-03.confinement",
        "peers": "B-03.delegate",
    }
    qualified_consumers = {}
    for feature in all_profiles:
        suffix = feature.split("/")[0].removeprefix("ocs.")
        failure = boundaries.get(suffix)
        checks = [
            family + "/" + r["id"]
            for family, (rep, _, _) in reports.items()
            for r in rep["checks"]
            if r["status"] == "pass"
            and r["level"] in ("reference", "runtime-observation")
            and failure in r.get("claims", r.get("obligations", []))
        ]
        if not checks:
            raise ValueError("no witnessed failure boundary for claimed feature " + feature)
        qualified_consumers[feature] = {
            "consumers": sorted(consumers[feature]),
            "failureBoundary": failure,
            "witnesses": checks,
        }
    data = {
        n: {
            "profile": registry[n]["profile"],
            "publishedCallerCurrentTarget": entries,
            "historicalExecutors": old_exec.get(n, []),
            "reverseScope": "historical executable is available"
            if n in old_exec
            else "previous edition published the interface only",
        }
        for n, entries in rows.items()
    }
    data["agent.exchange"]["currentCallerPublishedTarget"] = reverse_agent
    if any(n in old_exec and n != "agent.exchange" for n in data):
        raise ValueError("missing reverse executable witness for an archived profile")
    return data, qualified_consumers


def collect(oracle, subject, kind, accepted, destination, stand, bootstrap=False):
    started = datetime.now(timezone.utc).isoformat()
    if not (oracle / "assurance/evidence-index.json").is_file() and not bootstrap:
        raise ValueError(
            "unsealed evidence roster; only an explicit pre-enrollment run is available"
        )
    if (
        bootstrap
        and subprocess.check_output(
            ["git", "-C", str(oracle), "rev-parse", "HEAD"], text=True
        ).strip()
        != accepted
    ):
        raise ValueError("bootstrap requires the exact committed checker checkout")

    previous_catalog = load(oracle / "assurance/obligations.json")
    current_catalog = load(subject / "assurance/obligations.json")
    previous_scope = load(oracle / "assurance/scope.json")
    current_scope = load(subject / "assurance/scope.json")
    old = obligations(previous_catalog, load(oracle / "conformance/scenarios.json"))
    current = obligations(current_catalog, load(subject / "conformance/scenarios.json"))
    errors = compare_policy(old, current, previous_scope, current_scope)
    if load(oracle / "stand/kubernetes/policy.json") != load(
        subject / "stand/kubernetes/policy.json"
    ):
        errors.append("changed stand threshold, target or freshness assumption")
    structural = inventory(oracle, previous_catalog)
    working = inventory(subject, current_catalog)
    errors.extend(structural_changes(structural, working))
    ident = subject_identity(subject)
    env = {**os.environ, "OCS_SUBJECT_ROOT": str(subject), "PYTHONDONTWRITEBYTECODE": "1"}
    report_dir = destination / "evidence"
    report_dir.mkdir(parents=True, exist_ok=True)
    save(
        destination / "declarations.json",
        {
            "accepted": accepted,
            "evidenceLevel": "source declaration identity",
            "items": working,
            "source": ident,
        },
    )
    reports = {}

    def run(family, script, *args):
        path = report_dir / (family + ".json")
        if path.exists():
            raise ValueError("qualification requires a fresh run directory: " + str(path))
        command = [
            sys.executable,
            "-E",
            "-s",
            str(oracle / script),
            *map(str, args),
            "--report",
            str(path),
        ]
        print("Checking", family, flush=True)
        result = subprocess.run(command, cwd=subject, env=env, timeout=480)
        if not path.is_file():
            errors.append(f"{family} produced no result (exit {result.returncode})")
            return {}
        data = load(path)
        if result.returncode:
            errors.append(f"{family} failed (exit {result.returncode})")
        if "checks" in data:
            reports[family] = (
                data,
                path,
                [
                    "python",
                    script,
                    *[rel(Path(str(a)), subject) for a in args],
                    "--report",
                    path.name,
                ],
            )
        return data

    run("provider", "assurance/provider/check.py")
    run("interaction", "assurance/interaction/probe.py")
    run("platform", "assurance/platform/probe.py")
    run("external", "assurance/external/check.py")
    if "platform" in reports and "interaction" in reports:
        run(
            "profile-artifacts",
            "assurance/interaction/verify_artifacts.py",
            "--subject-root",
            subject,
            "--interaction-report",
            reports["interaction"][1],
            "--platform-report",
            reports["platform"][1],
        )
    run("wire", "assurance/wire/check.py", "--subject-root", subject)
    run("core", "assurance/core/check.py")
    run("admission", "assurance/admission/check.py")
    if "wire" in reports and reports["wire"][0].get("formal"):
        path = reports["wire"][1]
        replay = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                str(oracle / "assurance/wire/check.py"),
                "--subject-root",
                str(subject),
                "--report",
                str(path),
                "--verify-artifacts",
            ],
            cwd=subject,
            env=env,
            timeout=240,
        )
        if replay.returncode:
            errors.append("wire independent artifact replay failed")
        run(
            "wire-controls",
            "assurance/wire/controls.py",
            "--wire-report",
            path,
            "--subject-root",
            subject,
        )
    negative_provider = run("provider-controls", "assurance/provider/controls.py")
    negative_interaction = run("interaction-controls", "assurance/interaction/controls.py")
    # These control files are observations about the verifier, not replacement
    # evidence for the subject's implementation.
    reports.pop("interaction-controls", None)
    with tempfile.TemporaryDirectory(prefix="assurance-controls-") as scratch:
        controls = policy_controls(current, current_scope, Path(scratch))
    errors.extend(
        "failed qualification control " + c["id"] for c in controls if c["result"] != "pass"
    )
    for item in negative_provider.get("controls", []):
        if item["result"] != "pass" or item["expectedVerification"] != item["actuallyVerified"]:
            errors.append("failed falsification " + item["case"])
        controls.append(
            {"id": item["case"], "result": item["result"], "claims": [item["obligation"]]}
        )
    for item in negative_interaction.get("checks", []):
        if item["status"] != "pass":
            errors.append("failed falsification " + item["id"])
        controls.append({"id": item["id"], "result": item["status"]})
    registry = {
        o["method"]: o for o in load(subject / "spec/profiles/operations.json")["operations"]
    }
    accepted_registry = {
        o["method"]: o for o in load(oracle / "spec/profiles/operations.json")["operations"]
    }
    for name, contract in accepted_registry.items():
        if registry.get(name) != contract:
            errors.append("removed or changed supported public operation: " + name)
    try:
        matrix, consumers = feature_matrix(registry, reports, subject)
        save(destination / "operations.json", matrix)
        feature_report = {
            "scope": "published registry shapes and actual public consumers",
            "checks": [
                {
                    "id": "published-operation-matrix",
                    "level": "reference",
                    "claims": ["T-03.feature-matrix", "L-05.profile-consumer"],
                    "status": "pass",
                    "observed": {
                        "methodCount": len(matrix),
                        "consumers": consumers,
                        "matrixDigest": sha(destination / "operations.json"),
                    },
                }
            ],
        }
        path = report_dir / "interfaces.json"
        save(path, feature_report)
        reports["interfaces"] = (
            feature_report,
            path,
            ["qualification", "replay", "public operations"],
        )
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    if kind == "full":
        if ident["dirty"]:
            errors.append("full release qualification requires an identified clean checkout")
        policy = load(oracle / "stand/kubernetes/policy.json")
        real = report_dir / "stand.json"
        try:
            state = Path(
                os.environ.get("OCS_OBSERVER_STATE", Path.home() / ".local/state/ocs/qualification")
            )
            private, public = observer_keys(state)
            deployment = subject / "out/kubernetes/deployment.json"
            local = not any((stand["context"], stand["kubeconfig"], stand["image"]))
            common = ["--namespace", stand["namespace"] or policy["workload"]["namespace"]]
            if not local:
                if not all((stand["context"], stand["kubeconfig"], stand["image"])):
                    raise ValueError(
                        "remote mode needs explicit kubeconfig, context and OCI digest"
                    )
                common += ["--kubeconfig", stand["kubeconfig"], "--context", stand["context"]]
            args = (
                common
                + (["--local"] if local else ["--image", stand["image"]])
                + ["--report", str(deployment)]
            )
            if stand.get("oci_proof"):
                args += ["--oci-proof", stand["oci_proof"]]
            if stand["storage"]:
                args += ["--storage-class", stand["storage"]]
            subprocess.run(
                [sys.executable, "-I", str(oracle / "stand/kubernetes/deploy.py"), *args],
                cwd=subject,
                env=env,
                check=True,
                timeout=1050,
            )
            # Invoke the immutable observer directly. Mark deployment evidence
            # accepted only after its signature, exact target and TTL are checked.
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(oracle / "stand/kubernetes/observe.py"),
                    *common,
                    "--deployment",
                    str(deployment),
                    "--report",
                    str(real),
                ],
                cwd=subject,
                env=env,
                check=True,
                timeout=450,
            )
            data = load(real)
            bound = load(deployment)
            target = data["target"]
            for field in (
                "clusterUID",
                "serviceUID",
                "namespace",
                "image",
                "sourceRevision",
                "standCaSha256",
                "serverCertificateSha256",
                "relayCertificateSha256",
            ):
                if bound[field] != target[field]:
                    raise ValueError("deployment identity mismatch: " + field)
            live = {
                "stand": data,
                "acceptedVerifier": accepted,
                "subject": ident,
                "target": target,
                "operatorKey": sha(public),
                "standSha256": sha(real),
            }
            attestation = destination / "attestation.json"
            signature = destination / "attestation.sig"
            save(attestation, live)
            sign(attestation, private, signature)
            verify_signature(attestation, public, signature)
            verified = load(attestation)
            if (
                verified["acceptedVerifier"] != accepted
                or verified["subject"] != ident
                or verified["standSha256"] != sha(real)
            ):
                raise ValueError("signed evidence belongs to a different subject")
            verify_stand(verified["stand"], policy, ident, target, time.time())
            extra = stand_controls(verified["stand"], policy, ident)
            controls.extend(extra)
            errors.extend(
                "stand falsification passed incorrectly: " + c["id"]
                for c in extra
                if c["result"] != "pass"
            )
            reports["stand"] = (data, real, ["python", "stand/kubernetes/observe.py", *common])
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            errors.append("stand: " + str(exc)[:500])
    for row in reports.get("wire-controls", ({"checks": []}, None, None))[0]["checks"]:
        controls.append(
            {
                "id": row["id"],
                "result": row["status"],
                "claims": row.get("claims", row.get("obligations", [])),
            }
        )
    save(destination / "controls.json", controls)
    required_file = oracle / "assurance/evidence-index.json"
    required = load(required_file)["checks"] if required_file.is_file() else None
    admitted = admit_reports(current, reports, ident, kind == "full", required)
    admitted["failures"].extend(errors)
    if errors:
        admitted["status"] = "fail"
    if subject_identity(subject) != ident:
        admitted["failures"].append("subject changed during qualification")
        admitted["status"] = "fail"
    required_local = (
        sum(len(s) for s in (r["levels"] for r in admitted["obligations"]))
        - admitted["byLevel"].get("deployment", {}).get("accepted", 0)
        - admitted["byLevel"].get("deployment", {}).get("open", 0)
    )
    applicable = sum(len(a["levels"]) for a in current.values())
    satisfied = sum(
        v["status"] == "accepted" for row in admitted["obligations"] for v in row["levels"].values()
    )
    accounting = {
        "numberedRules": sum(
            len(r) for r in load(subject / "conformance/scenarios.json")["requirements"].values()
        ),
        "scenarios": len(load(subject / "conformance/scenarios.json")["scenarios"]),
        "profiles": len(load(subject / "spec/profiles/index.json")["profiles"]),
        "additionalProseGroups": len(current_catalog["extraLocators"]),
        "atomicPromises": len(current),
        "declarations": dict(Counter(x["kind"] for x in working.values())),
        "declarationCount": len(working),
    }
    result = {
        "format": "ocs.qualification/1",
        "kind": kind,
        "eligibility": "initial collection for review"
        if bootstrap
        else "independent pinned edition replay",
        "acceptedVerifier": accepted,
        "startedAt": started,
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "subject": ident,
        "accounting": accounting,
        "applicableEvidenceSlots": applicable,
        "requiredLocalSlots": required_local,
        "acceptedEvidenceSlots": satisfied,
        "independentControls": controls,
        "scope": previous_scope,
        **admitted,
    }
    Draft202012Validator(
        load(oracle / "assurance/result.schema.json"), format_checker=FormatChecker()
    ).validate(result)
    save(destination / "report.json", result)
    print(
        f"{kind}: {satisfied}/{applicable} evidence obligations; local denominator {required_local}; {len(working)} normative declaration locations.",
        flush=True,
    )
    for msg in (result["failures"] + result["openRequired"])[:30]:
        print("UNRESOLVED", msg, file=sys.stderr)
    return int(result["status"] != "pass")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("kind", choices=("local", "full"))
    p.add_argument("--subject", type=Path, required=True)
    p.add_argument("--accepted", required=True)
    p.add_argument(
        "--bootstrap",
        action="store_true",
        help="collect witnesses in the exact checker checkout before independent enrollment",
    )
    p.add_argument("--output", type=Path, required=True)
    for name in ("context", "kubeconfig", "image", "namespace", "storage", "oci_proof"):
        p.add_argument("--" + name)
    o = p.parse_args()
    try:
        raise SystemExit(
            collect(
                HOME_TREE,
                o.subject.resolve(),
                o.kind,
                o.accepted,
                o.output.resolve(),
                {
                    n: getattr(o, n)
                    for n in ("context", "kubeconfig", "image", "namespace", "storage", "oci_proof")
                },
                o.bootstrap,
            )
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        p.exit(1, f"qualification failed: {exc}\n")
