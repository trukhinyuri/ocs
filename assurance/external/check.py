#!/usr/bin/env python3
"""Import an offline external claim using a separately enrolled verifier."""

import argparse
import base64
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ORACLE = Path(__file__).resolve().parent
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE.parents[1])).resolve()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(data):
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def decode(raw):
    def unique(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise ValueError("duplicate evidence member")
        return obj

    def nonfinite(_):
        raise ValueError("nonfinite evidence value")

    return json.loads(
        raw.decode("utf-8", errors="strict"), object_pairs_hook=unique, parse_constant=nonfinite
    )


def fields(obj, names):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise ValueError("unexpected or missing fields in evidence contract")


def regular(path, limit):
    p = Path(path)
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        m = os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_size > limit:
            raise ValueError("inadmissible or oversized evidence file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("evidence exceeded the operator's byte limit")
    return data


def protected_file(directory, descriptor, limit):
    fields(descriptor, "path sha256")
    path = directory / descriptor["path"]
    raw = regular(path, limit)
    if sha(raw) != descriptor["sha256"]:
        raise ValueError("operator-enrolled file integrity mismatch")
    return raw


def evaluate(policy_path, policy_digest, bundle_path, source_path, artifact_path):
    policy_source = regular(policy_path, 256 * 1024)
    if sha(policy_source) != policy_digest:
        raise ValueError("unapproved policy digest")
    p = decode(policy_source)
    fields(p, "format scope statement subjectSha256 artifactSha256 checker bounds")
    if p["format"] != "ocs.external-enrollment/1":
        raise ValueError("unsupported operator enrollment")
    scope = p["scope"]
    fields(
        scope,
        "edition property packageId packageVersion operation contractVersion role binding features platform level assumptions suite",
    )
    for name in (
        "edition",
        "property",
        "packageId",
        "packageVersion",
        "operation",
        "contractVersion",
        "role",
        "binding",
        "platform",
        "level",
        "suite",
    ):
        if not isinstance(scope[name], str) or not scope[name].strip():
            raise ValueError("invalid enrolled scope: " + name)
    for name in ("features", "assumptions"):
        seq = scope[name]
        if (
            not isinstance(seq, list)
            or not all(isinstance(s, str) and s.strip() for s in seq)
            or len(seq) != len(set(seq))
        ):
            raise ValueError("invalid enrolled scope list: " + name)
    owner = policy_path.parent
    maximum = p["bounds"]
    fields(maximum, "source artifact bundle verifier resource seconds")
    if any(type(n) is not int or n <= 0 for n in maximum.values()):
        raise ValueError("invalid enrollment limits")
    statement = protected_file(owner, p["statement"], maximum["source"])
    subject = regular(source_path, maximum["source"])
    artifact = regular(artifact_path, maximum["artifact"])
    if sha(subject) != p["subjectSha256"]:
        raise ValueError("unadmitted source artifact")
    if sha(artifact) != p["artifactSha256"]:
        raise ValueError("unadmitted execution artifact")
    b = decode(regular(bundle_path, maximum["bundle"]))
    fields(b, "format scope statementSha256 subjectSha256 artifactSha256 certificate")
    if b["format"] != "ocs.external-evidence/1":
        raise ValueError("unsupported evidence format")
    binding = {
        "scope": p["scope"],
        "statementSha256": sha(statement),
        "subjectSha256": sha(subject),
        "artifactSha256": sha(artifact),
    }
    claimed = {k: b[k] for k in binding}
    if canonical(claimed) != canonical(binding):
        raise ValueError("property, scope, assumptions or target differ from enrollment")
    binding_sha = sha(canonical(binding))
    proof = b["certificate"]
    if not isinstance(proof, dict) or proof.get("bindingSha256") != binding_sha:
        raise ValueError("foreign certificate binding")
    checker = p["checker"]
    fields(checker, "program engine arguments resources")
    program = protected_file(owner, checker["program"], maximum["verifier"])
    if (
        checker["engine"] not in ("native", "python-stdlib")
        or not isinstance(checker["arguments"], list)
        or not all(isinstance(v, str) for v in checker["arguments"])
    ):
        raise ValueError("unsupported enrolled checker command")
    resources = {
        name: decode(protected_file(owner, descriptor, maximum["resource"]))
        for name, descriptor in checker["resources"].items()
    }
    packet = {
        "format": "ocs.external-check-input/1",
        "nonce": secrets.token_hex(16),
        "binding": binding,
        "bindingSha256": binding_sha,
        "certificate": proof,
        "certificateSha256": sha(canonical(proof)),
        "checkerResources": resources,
        "artifact": base64.b64encode(artifact).decode(),
        "subject": base64.b64encode(subject).decode(),
        "statement": base64.b64encode(statement).decode(),
    }
    # No supplied command, path, import, URL or status can select a verifier.
    # Execute the exact verified program bytes in an isolated temporary directory.
    with tempfile.TemporaryDirectory(prefix="ocs-external-") as temp:
        exe = Path(temp) / "checker"
        exe.write_bytes(program)
        exe.chmod(0o700)
        args = (
            [sys.executable, "-I", "-S", str(exe)]
            if checker["engine"] == "python-stdlib"
            else [str(exe)]
        ) + checker["arguments"]
        env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "LC_ALL": "C"}
        if "ELAN_HOME" in os.environ:
            env["ELAN_HOME"] = os.environ["ELAN_HOME"]
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=diagnostic,
                cwd=temp,
                env=env,
                start_new_session=True,
            )
            try:
                proc.communicate(canonical(packet), timeout=maximum["seconds"])
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise ValueError("enrolled checker deadline")
            output.seek(0)
            diagnostic.seek(0)
            if proc.returncode:
                message = diagnostic.read(500).decode(errors="replace").strip()
                raise ValueError("enrolled checker refused: " + message)
            result = output.read(65537)
            if len(result) > 65536:
                raise ValueError("checker output limit")
    validation = decode(result)
    fields(validation, "format nonce bindingSha256 certificateSha256 accepted witness")
    if (
        validation["format"] != "ocs.external-check-result/1"
        or validation["accepted"] is not True
        or validation["nonce"] != packet["nonce"]
        or validation["bindingSha256"] != binding_sha
        or validation["certificateSha256"] != packet["certificateSha256"]
        or not isinstance(validation["witness"], dict)
        or not validation["witness"]
    ):
        raise ValueError("unexpected or stale checker response")
    return {
        "format": "ocs.external-receipt/1",
        **binding,
        "bindingSha256": binding_sha,
        "property": p["scope"]["property"],
        "policySha256": policy_digest,
        "checkerProgramSha256": sha(program),
        "certificateSha256": packet["certificateSha256"],
        "witness": validation["witness"],
        "result": "accepted",
        "observedAt": datetime.now(timezone.utc).isoformat(),
    }


def cli_import(policy, pin, bundle, source, artifact, destination, eligible):
    args = [
        sys.executable,
        "-I",
        str(ORACLE / "check.py"),
        "--policy",
        str(policy),
        "--policy-sha256",
        pin,
        "--bundle",
        str(bundle),
        "--subject",
        str(source),
        "--artifact",
        str(artifact),
        "--report",
        str(destination),
    ]
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    receipt = decode(regular(destination, 65536))
    if (
        result.returncode != (0 if eligible else 1)
        or receipt["format"] != "ocs.external-receipt/1"
        or receipt["result"] != ("accepted" if eligible else "refused")
    ):
        raise ValueError("external import CLI did not produce the corresponding receipt")
    return receipt


def fixture_controls(policy_path, policy_sha, bundle, source, artifact):
    data = decode(regular(bundle, 65536))
    outcomes = {}
    with tempfile.TemporaryDirectory(prefix="ocs-external-controls-") as tmp:
        tmp = Path(tmp)
        expected = cli_import(
            policy_path, policy_sha, bundle, source, artifact, tmp / "accepted.json", True
        )

        def altered(label, change, binary=artifact, src=source, passed_policy=policy_sha):
            changed = decode(canonical(data))
            change(changed)
            f = tmp / "bundle.json"
            f.write_bytes(canonical(changed))
            try:
                evaluate(policy_path, passed_policy, f, src, binary)
            except (OSError, ValueError, KeyError, TypeError) as err:
                outcomes[label] = str(err)
                return
            raise ValueError("unaccepted external evidence passed: " + label)

        altered("changed-property", lambda b: b.update(statementSha256="0" * 64))
        altered("foreign-certificate", lambda b: b["certificate"].update(bindingSha256="0" * 64))
        altered("weakened-scope", lambda b: b["scope"].update(binding="sample-only"))
        altered(
            "added-assumption",
            lambda b: b["scope"]["assumptions"].append("All grants are already valid."),
        )
        altered("spoof-result", lambda b: b.update(accepted=True))
        altered("choose-own-checker", lambda b: b.update(checkerCommand=["unused"]))
        altered(
            "invalid-stack-certificate",
            lambda b: b["certificate"]["frames"].__setitem__(1, ["offered"]),
        )
        altered("different-policy", lambda _: None, passed_policy="1" * 64)
        other = tmp / "other.wasm"
        other.write_bytes(regular(artifact, 65536)[:-1] + bytes([0]))
        altered("different-artifact", lambda _: None, binary=other)
        source2 = tmp / "other.c"
        source2.write_bytes(regular(source, 65536) + b"\n")
        altered("different-source", lambda _: None, src=source2)

        # The foreign proof is independently valid for an equivalent body whose
        # local loads occur in the opposite order. Rebinding its label cannot
        # make that trace an execution of the original bytes.
        alternate = tmp / "alternate.wasm"
        original = regular(artifact, 65536)
        suffix = bytes([32, 1, 32, 0, 113, 11])
        if not original.endswith(suffix):
            raise ValueError("alternate witness needs the enrolled fixture")
        alternate.write_bytes(original[: -len(suffix)] + bytes([32, 0, 32, 1, 113, 11]))
        policy = decode(regular(policy_path, 256 * 1024))
        policy["artifactSha256"] = sha(alternate.read_bytes())
        for ref in (
            policy["statement"],
            policy["checker"]["program"],
            *policy["checker"]["resources"].values(),
        ):
            ref["path"] = str((policy_path.parent / ref["path"]).resolve())
        other_policy = tmp / "alternate-policy.json"
        other_policy.write_bytes(canonical(policy))
        alternate_data = decode(canonical(data))
        alternate_data["artifactSha256"] = policy["artifactSha256"]
        foreign = alternate_data["certificate"]
        foreign["bindingSha256"] = sha(
            canonical(
                {
                    k: alternate_data[k]
                    for k in ("scope", "statementSha256", "subjectSha256", "artifactSha256")
                }
            )
        )
        foreign["instructions"] = ["imported", "offered", "band"]
        final = [["and", "imported", "offered"]]
        foreign["frames"] = [["imported"], ["offered", "imported"], final]
        foreign["final"] = final
        alternate_bundle = tmp / "alternate.json"
        alternate_bundle.write_bytes(canonical(alternate_data))
        alternate_receipt = cli_import(
            other_policy,
            sha(other_policy.read_bytes()),
            alternate_bundle,
            source,
            alternate,
            tmp / "new.json",
            True,
        )
        copied = decode(canonical(data))
        copied["certificate"] = dict(foreign, bindingSha256=data["certificate"]["bindingSha256"])
        copied_bundle = tmp / "copied.json"
        copied_bundle.write_bytes(canonical(copied))
        refused = cli_import(
            policy_path, policy_sha, copied_bundle, source, artifact, tmp / "refusal.json", False
        )
        outcomes["foreign-valid-proof-with-rebound-label"] = refused["reason"]
    return expected, outcomes, alternate_receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path, required=True)
    for k in ("policy", "bundle", "subject", "artifact"):
        p.add_argument("--" + k, type=Path)
    p.add_argument(
        "--policy-sha256", help="operator-selected enrollment digest for explicit import"
    )
    o = p.parse_args()
    supplied = (o.policy, o.bundle, o.subject, o.artifact, o.policy_sha256)
    if any(supplied) and not all(supplied):
        p.error(
            "explicit import requires policy, independent policy SHA, bundle, subject and artifact"
        )
    receipt = None
    try:
        if o.policy:
            receipt = evaluate(o.policy, o.policy_sha256, o.bundle, o.subject, o.artifact)
            report = receipt
        else:
            examples = SUBJECT / "assurance/external/example"
            pol = ORACLE / "enrollment.json"
            receipt, refusals, equivalent = fixture_controls(
                pol,
                sha(regular(pol, 256 * 1024)),
                examples / "evidence.json",
                examples / "grant.c",
                examples / "grant.wasm",
            )
            report = {
                "format": "ocs.external-qualification/1",
                "scope": "Offline import of the enrolled C/Wasm component into the published operator verifier",
                "checks": [
                    {
                        "id": "external.import",
                        "claims": ["C-09.scope", "T-01.receipt", "T-02.oracle"],
                        "level": "runtime-observation",
                        "status": "pass",
                        "observed": {
                            "receipt": receipt,
                            "rejected": refusals,
                            "separatelyEnrolledEquivalentArtifact": equivalent,
                        },
                    }
                ],
                "observedAt": receipt["observedAt"],
            }
        code = 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
        subprocess.SubprocessError,
    ) as err:
        report = {
            "format": "ocs.external-qualification/1",
            "scope": "offline operator-enrolled external proof",
            "checks": [
                {
                    "id": "external.import",
                    "claims": ["C-09.scope", "T-01.receipt", "T-02.oracle"],
                    "level": "runtime-observation",
                    "status": "fail",
                    "observed": str(err),
                }
            ],
            "observedAt": datetime.now(timezone.utc).isoformat(),
        }
        if o.policy:
            report = {
                "format": "ocs.external-receipt/1",
                "result": "refused",
                "reason": str(err),
                "observedAt": datetime.now(timezone.utc).isoformat(),
            }
        print(str(err), file=sys.stderr)
        code = 1
    o.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=o.report.parent, delete=False) as out:
        out.write(
            json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n"
        )
        tmp = Path(out.name)
    os.replace(tmp, o.report)
    print("External import", "accepted" if not code else "failed", o.report)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
