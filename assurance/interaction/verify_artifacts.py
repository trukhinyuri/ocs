#!/usr/bin/env python3
"""Rebuild the required statements independently and verify the submitted term bundles."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from certificate import pinned_kernels, verify_export

ROOT = Path(__file__).resolve().parents[2]
RELEASE = "leanprover/lean4:v4.36.0-rc2"
COMMIT = "b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a"
LEVELS = {"model", "source-refinement"}


def distinct(items):
    obj = {}
    for k, v in items:
        if k in obj:
            raise ValueError("duplicate JSON member in evidence")
        obj[k] = v
    return obj


def finite_constant(value):
    raise ValueError("nonfinite numeric metadata in proof report: " + value)


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=distinct, parse_constant=finite_constant)


def hashed(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def formal_rows(report):
    out = {}
    for r in report["checks"]:
        if r["level"] not in LEVELS:
            continue
        if r["id"] in out:
            raise ValueError("duplicate formal evidence ID: " + r["id"])
        out[r["id"]] = r
    return out


def rebuild(domain, subject, folder):
    source = ROOT / "assurance" / domain
    fresh = folder / "fresh.json"
    env = {**os.environ, "OCS_SUBJECT_ROOT": str(subject)}
    result = subprocess.run(
        [
            sys.executable,
            "-E",
            "-s",
            str(source / "probe.py"),
            "--mode",
            "formal",
            "--report",
            str(fresh),
        ],
        cwd=subject,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode or not fresh.is_file():
        raise ValueError(
            "protected rebuild of " + domain + " failed: " + (result.stderr or result.stdout)[-700:]
        )
    fresh_report = load(fresh)
    expected = formal_rows(fresh_report)
    declarations = {}
    for name, entry in load(source / "bindings.json")["checks"].items():
        if entry["level"] in LEVELS:
            namespace, symbol = entry["theorem"].split(".")
            declarations[name] = namespace + ".Accepted_" + symbol
    if set(expected) != set(declarations) or any(r["status"] != "pass" for r in expected.values()):
        raise ValueError("trusted rebuild omitted an obligation or returned a failure")
    expected_cert = fresh.with_suffix(".ndjson")
    return {
        "fresh": expected,
        "scope": fresh_report["scope"],
        "assumptions": fresh_report["assumptions"],
        "sha": hashed(expected_cert),
        "bytes": expected_cert.stat().st_size,
        "statements": declarations,
    }


def replay(domain, submitted, rebuilt, tools, folder):
    if submitted.is_symlink() or not submitted.is_file():
        raise ValueError("a regular, selected report file is required")
    fd = os.open(submitted, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as report_file:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise ValueError("submitted report exceeds its ingestion bound")
        raw = report_file.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("submitted report grew outside its ingestion bound")
    data = json.loads(raw, object_pairs_hook=distinct, parse_constant=finite_constant)
    if data.get("scope") != rebuilt["scope"] or data.get("assumptions") != rebuilt["assumptions"]:
        raise ValueError("changed evidence scope or assumptions")
    rows = formal_rows(data)
    if set(rows) != set(rebuilt["statements"]):
        raise ValueError("submitted report has missing or foreign formal obligations")
    terms = submitted.with_suffix(".ndjson")
    if terms.is_symlink() or not terms.is_file():
        raise ValueError("detached proof terms are absent or redirected")
    for key, decl in rebuilt["statements"].items():
        live, pinned = rows[key], rebuilt["fresh"][key]
        for field in ("theorem", "level", "claims", "criterion", "targets", "status"):
            if live[field] != pinned[field]:
                raise ValueError(key + ": changed subject, formula, scope or result field " + field)
        for boundary in ("scope", "assumptions"):
            if live.get(boundary, rebuilt[boundary]) != pinned.get(boundary, rebuilt[boundary]):
                raise ValueError(key + ": changed per-claim " + boundary)
        f = live["observed"]
        trusted = pinned["observed"]
        for field, value in trusted.items():
            if field != "certificate" and f.get(field) != value:
                raise ValueError(key + ": changed checked theorem evidence " + field)
        cert = f["certificate"]
        if (
            f["acceptedDeclaration"] != decl
            or cert.get("file") != terms.name
            or cert.get("sha256") != rebuilt["sha"]
            or cert.get("checker") != trusted["certificate"]["checker"]
            or cert.get("declarations") != trusted["certificate"]["declarations"]
        ):
            raise ValueError(
                key + ": foreign or substituted detached certificate for the selected subject"
            )
    if terms.stat().st_size != rebuilt["bytes"]:
        raise ValueError("detached proof artifact length differs from the protected rebuild")
    # Check an immutable local copy. The independent checker consumes exactly the bytes hashed here.
    snapshot = folder / "submitted.ndjson"
    term_fd = os.open(terms, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(term_fd, "rb") as src, snapshot.open("wb") as dst:
        info = os.fstat(term_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != rebuilt["bytes"]:
            raise ValueError("proof term is not the expected regular artifact")
        for block in iter(lambda: src.read(262144), b""):
            if dst.tell() + len(block) > rebuilt["bytes"]:
                raise ValueError("proof bundle grew during replay")
            dst.write(block)
    actual = hashed(snapshot)
    if actual != rebuilt["sha"]:
        raise ValueError("detached certificate bytes differ from the protected rebuild")
    binaries, env, approved = tools
    count = verify_export(binaries, env, folder, list(rebuilt["statements"].values()), snapshot)
    if count != next(iter(rebuilt["fresh"].values()))["observed"]["certificate"]["declarations"]:
        raise ValueError("independent checker qualified a different declaration set")
    return {
        "domain": domain,
        "reportSha256": hashlib.sha256(raw).hexdigest(),
        "submittedCertificateSha256": actual,
        "independentRebuildSha256": rebuilt["sha"],
        "certificateBytes": rebuilt["bytes"],
        "acceptedDeclarations": sorted(rebuilt["statements"].values()),
        "kernelDeclarations": count,
        "checkerSha256": approved["bin/nanoda_bin"],
    }


def result(domain, status, observed, control=False):
    return {
        "id": "profiles.detached." + ("foreign-control." + domain if control else domain),
        "level": "artifact-observation",
        "claims": ["T-04.proof-baseline"],
        "status": status,
        "observed": observed,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interaction-report", type=Path, required=True)
    parser.add_argument("--platform-report", type=Path, required=True)
    parser.add_argument(
        "--subject-root", type=Path, default=Path(os.environ.get("OCS_SUBJECT_ROOT", ROOT))
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    subject = args.subject_root.resolve()
    inputs = {
        "interaction": args.interaction_report.absolute(),
        "platform": args.platform_report.absolute(),
    }
    rows = []
    with tempfile.TemporaryDirectory(prefix="ocs-detached-replay-") as tmp:
        base = Path(tmp)
        for domain, source in inputs.items():
            folder = base / domain
            folder.mkdir()
            try:
                expected = rebuild(domain, subject, folder)
                tools = pinned_kernels(ROOT, folder, RELEASE, COMMIT)
                verified = replay(domain, source, expected, tools, folder)
                rows.append(result(domain, "pass", verified))
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                rows.append(result(domain, "fail", {"reason": str(exc)}))
                continue
            other = inputs["platform" if domain == "interaction" else "interaction"].with_suffix(
                ".ndjson"
            )
            forged = folder / "swapped.json"
            swapped = forged.with_suffix(".ndjson")
            try:
                shutil.copyfile(other, swapped)
                foreign = hashed(swapped)
                if foreign == expected["sha"]:
                    raise ValueError("negative control needs a distinct genuine proof")
                foreign_report = load(
                    inputs["platform" if domain == "interaction" else "interaction"]
                )
                foreign_meta = next(iter(formal_rows(foreign_report).values()))["observed"][
                    "certificate"
                ]
                rehashed = load(source)
                for entry in formal_rows(rehashed).values():
                    entry["observed"]["certificate"].update(
                        file=swapped.name, sha256=foreign, declarations=foreign_meta["declarations"]
                    )
                forged.write_text(json.dumps(rehashed))
                try:
                    replay(domain, forged, expected, tools, folder)
                except ValueError as exc:
                    if "foreign or substituted detached certificate" not in str(exc):
                        raise
                    rows.append(
                        result(
                            domain,
                            "pass",
                            {
                                "control": "real foreign term bundle with rewritten metadata hashes",
                                "foreignSha256": foreign,
                                "expectedSha256": expected["sha"],
                                "diagnostic": str(exc),
                            },
                            True,
                        )
                    )
                else:
                    raise ValueError(
                        "accepted a valid but foreign certificate for the selected subject"
                    )
            except (OSError, ValueError, KeyError, TypeError) as exc:
                rows.append(result(domain, "fail", {"reason": str(exc)}, True))
    out = {
        "scope": "Selected working Python interaction and platform source compiled against distinct accepted model/theorem challenges",
        "observedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "checks": rows,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=args.report.parent, delete=False) as f:
        json.dump(out, f, indent=2)
        f.write("\n")
        file = Path(f.name)
    file.replace(args.report)
    failed = [r for r in rows if r["status"] != "pass"]
    for r in failed:
        print("FAIL", r["id"], r["observed"]["reason"], file=sys.stderr)
    print(f"{len(rows) - len(failed)}/{len(rows)} detached profile replays/controls passed")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
