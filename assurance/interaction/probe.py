#!/usr/bin/env python3
"""Replay published model statements, Python source decisions and interaction observations."""

import argparse
import hashlib
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORACLE = HERE.parents[1]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
import observe
from certificate import external_certificate, pinned_kernels
from lean_tools import checked_run, declarations, definitions, verify_consumption
from lift import translate

TOOLCHAIN = "leanprover/lean4:v4.36.0-rc2"
COMMIT = "b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a"
PACKAGE = "reference/interaction"
FILES = (
    "privacy.py",
    "kernel.py",
    "service.py",
    "state.py",
    "server.py",
    "client.py",
    "terminal.py",
    "ocs.json",
)
CONFIG = json.loads((HERE / "bindings.json").read_bytes())
SAFE_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(key, status, observed, targets=None):
    entry = CONFIG["checks"][key]
    item = {
        "id": key,
        "level": entry["level"],
        "claims": entry["claims"],
        "status": status,
        "criterion": entry["criterion"],
        "observed": observed,
        "targets": targets or [],
    }
    if "theorem" in entry:
        item["theorem"] = entry["theorem"]
    return item


def check_sites():
    # Formula coverage is confined to these actual consumed decision call sites.
    required = {
        "service.py": {
            "Host.__init__": {"admit"},
            "Host.session": set(),
            "Host.lifecycle": set(),
            "Host.open_stream": set(),
            "Host.control": set(),
            "Transfer.control": set(),
            "Transfer.frames": set(),
            "allow": {"admit"},
            "step": {"stream_step"},
            "artifact": {"page_size"},
            "delegate": {"grant", "reserve"},
            "surface": {"admit", "grant"},
            "eligible": {"surface_eligible"},
            "rpc": {"callback_safe"},
            "agent": {"reserve"},
        },
        "state.py": {
            "Store.tx": set(),
            "Store._job": set(),
            "event_position": {"ack_position"},
            "job": {"can_continue"},
        },
    }
    for file, funcs in required.items():
        verify_consumption(ORACLE / PACKAGE / file, SUBJECT / PACKAGE / file, funcs, "kernel")


def formal(mode, targets, certificate_path):
    needed = {
        k: v for k, v in CONFIG["checks"].items() if v["level"] in ("model", "source-refinement")
    }
    rows = []
    with tempfile.TemporaryDirectory(prefix="ocs-interaction-lean-") as tmp:
        d = Path(tmp)
        env = {**os.environ, "LEAN_PATH": str(d)}
        try:
            binaries, env, approved = pinned_kernels(ORACLE, d, TOOLCHAIN, COMMIT)
            version = COMMIT
            check_sites()
            archived = (HERE / "Interaction.lean").read_text()
            actual = (SUBJECT / "assurance/interaction/Interaction.lean").read_text()
            base_defs, live_defs = definitions(archived), definitions(actual)
            for name, text in base_defs.items():
                if live_defs.get(name) != text:
                    raise ValueError("changed frozen semantics: " + name)
            for key, text in (
                ("Interaction", actual),
                ("Source", (SUBJECT / "assurance/interaction/Source.lean").read_text()),
            ):
                if re.search(
                    r"(?m)^\s*(axiom|unsafe|#eval|run_cmd)\b|\bsorry\b|\bnative_decide\b|skipKernelTC|trustCompiler",
                    text,
                ):
                    raise ValueError("untrusted proof declaration in " + key)
                (d / (key + ".lean")).write_text(text)
            concrete = translate(SUBJECT / PACKAGE / "kernel.py")
            (d / "Concrete.lean").write_text(concrete)
            for module in ("Interaction", "Concrete", "Source"):
                checked_run(
                    [str(binaries / "lean"), "-o", module + ".olean", module + ".lean"], d, env
                )
            required = declarations(archived)
            required.update(declarations((HERE / "Source.lean").read_text()))
            challenge = ["import Source", "set_option autoImplicit false", "namespace Interaction"]
            for key, entry in needed.items():
                n = entry["theorem"].removeprefix("Interaction.")
                challenge.extend(
                    (
                        "-- obligation " + key,
                        required[n].replace("example ", "theorem Accepted_" + n + " ", 1),
                        "#print axioms Interaction." + n,
                    )
                )
            challenge.append("end Interaction")
            (d / "Challenge.lean").write_text("\n".join(challenge) + "\n")
            diagnostics = checked_run(
                [str(binaries / "lean"), "-o", "Challenge.olean", "Challenge.lean"], d, env
            )
            # Each independent process replays one module and its declared imports.
            for module in ("Interaction", "Concrete", "Source", "Challenge"):
                checked_run([str(binaries / "leanchecker"), "--silent", module], d, env)
            names = [
                "Interaction.Accepted_" + entry["theorem"].split(".")[-1]
                for entry in needed.values()
            ]
            certificate = external_certificate(binaries, env, d, names, certificate_path)
            for key, entry in needed.items():
                theorem = entry["theorem"]
                m = re.search(
                    r"'"
                    + re.escape(theorem)
                    + r"' (?:does not depend on any axioms|depends on axioms: \[(.*?)\])",
                    diagnostics,
                    re.DOTALL,
                )
                if not m:
                    raise ValueError("missing axiom audit: " + theorem)
                axioms = set(x.strip() for x in (m.group(1) or "").split(",") if x.strip())
                if not axioms <= SAFE_AXIOMS:
                    raise ValueError("unapproved axiom for " + theorem)
                rows.append(
                    record(
                        key,
                        "pass",
                        {
                            "checker": version,
                            "kernelReplay": "separate leanchecker and nanoda_bin",
                            "certificate": certificate,
                            "acceptedDeclaration": "Interaction.Accepted_" + theorem.split(".")[-1],
                            "checkerSha256": approved["bin/nanoda_bin"],
                            "axioms": sorted(axioms),
                            "statementSha256": hashlib.sha256(
                                required[theorem.split(".")[-1]].encode()
                            ).hexdigest(),
                            "concreteSha256": digest(d / "Concrete.lean"),
                        },
                        targets,
                    )
                )
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            return [record(k, "fail", {"reason": str(exc)}, targets) for k in needed]
    return rows


def runtime(endpoint, mode, targets, selected):
    chosen = (
        {"keyboard", "comparison"}
        if mode == "stand"
        else {
            "life",
            "streams",
            "events",
            "jobs",
            "artifact",
            "delegation",
            "ui",
            "keyboard",
            "agent",
            "comparison",
            "updated_policy",
            "data_policy",
            "callback",
            "late_job",
            "historical_dialog",
            "review_intent",
            "transport_bounds",
        }
    )
    rows = []
    for test in sorted(chosen):
        entries = [k for k, v in CONFIG["checks"].items() if v.get("probe") == test]
        if mode == "stand":
            entries = [k for k in entries if CONFIG["checks"][k]["level"] == "measurement"]
        if selected:
            entries = [k for k in entries if k in selected]
            if not entries:
                continue
        with tempfile.TemporaryDirectory(prefix="ocs-observation-") as temp:
            deployment = None
            try:
                deployment = observe.Deployment(Path(temp), endpoint)
                observed = getattr(observe, test)(deployment)
                observed = {
                    **observed,
                    "placement": "named external endpoint" if endpoint else "fresh local process",
                    "admittedManifestDigest": observed.get("manifestDigest", deployment.a.pin),
                    "registeredExchanges": deployment.journal.snapshot(),
                }
                rows.extend(record(k, "pass", observed, targets) for k in entries)
            except Exception as exc:
                rows.extend(
                    record(k, "fail", {"reason": str(exc)[:1400]}, targets) for k in entries
                )
            finally:
                if deployment:
                    deployment.stop()
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--mode", choices=("all", "formal", "runtime", "stand"), default="all")
    p.add_argument("--endpoint")
    p.add_argument(
        "--check",
        action="append",
        choices=[k for k, v in CONFIG["checks"].items() if "probe" in v],
        help="select a named runtime observation",
    )
    opt = p.parse_args()
    if opt.check and opt.mode != "runtime":
        p.error("select individual runtime observations using --mode runtime")
    if opt.mode == "stand" and not opt.endpoint:
        opt.endpoint = os.environ.get("OCS_INTERACTION_ENDPOINT")
    if bool(opt.endpoint) != (opt.mode == "stand"):
        p.error("stand mode requires an explicitly selected loopback endpoint")
    targets = [{"path": PACKAGE + "/" + f, "sha256": digest(SUBJECT / PACKAGE / f)} for f in FILES]
    rows = []
    if opt.mode in ("all", "formal"):
        rows.extend(formal(opt.mode, targets, opt.report.with_suffix(".ndjson")))
    if opt.mode in ("all", "runtime", "stand"):
        rows.extend(runtime(opt.endpoint, opt.mode, targets, opt.check))
    out = {
        "callerRuntime": {
            "python": platform.python_version(),
            "binarySha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
            "sqlite": sqlite3.sqlite_version,
            "os": sys.platform,
            "machine": platform.machine(),
            "kernel": platform.release(),
            "abi": sys.implementation.cache_tag,
        },
        "scope": CONFIG["subject"],
        "mode": opt.mode,
        "observedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "assumptions": CONFIG["assumptions"],
        "checks": rows,
    }
    opt.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=opt.report.parent, delete=False) as stream:
        json.dump(out, stream, indent=2)
        stream.write("\n")
        staged = Path(stream.name)
    staged.replace(opt.report)
    failed = [r for r in rows if r["status"] != "pass"]
    for row in failed:
        print("FAIL", row["id"], row["observed"].get("reason"), file=sys.stderr)
    print(f"{len(rows) - len(failed)}/{len(rows)} interaction checks passed")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
