#!/usr/bin/env python3
"""Replay the accepted cell/ABI properties on the selected local subject."""

import argparse
import hashlib
import json
import os
import platform
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORACLE = HERE.parents[1]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
import observe

sys.path.insert(0, str(ORACLE / "assurance/interaction"))
from certificate import external_certificate, pinned_kernels
from lean_tools import checked_run, declarations, definitions, verify_consumption
from lift import translate

CONFIG = json.loads((HERE / "bindings.json").read_bytes())
TOOLCHAIN = "leanprover/lean4:v4.36.0-rc2"
COMMIT = "b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a"
SIG = {
    "admit_native": (("Bool",) * 5, "Bool"),
    "may_write": (("Bool", "Bool", "Nat", "Nat"), "Bool"),
    "enter_cell": (("Nat",) * 4, "Bool"),
}
TRUST = {"propext", "Classical.choice", "Quot.sound"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def item(key, ok, observed, targets):
    info = CONFIG["checks"][key]
    result = {
        "id": key,
        "level": info["level"],
        "claims": info["claims"],
        "criterion": info["criterion"],
        "observed": observed,
        "targets": targets,
        "status": "pass" if ok else "fail",
    }
    if "theorem" in info:
        result["theorem"] = info["theorem"]
    return result


def formal(targets, certificate_path):
    rows = {k: v for k, v in CONFIG["checks"].items() if "theorem" in v}
    with tempfile.TemporaryDirectory(prefix="ocs-platform-lean-") as temp:
        directory = Path(temp)
        env = {**os.environ, "LEAN_PATH": str(directory)}
        try:
            binaries, env, approved = pinned_kernels(ORACLE, directory, TOOLCHAIN, COMMIT)
            version = COMMIT
            original = (HERE / "Platform.lean").read_text()
            live = (SUBJECT / "assurance/platform/Platform.lean").read_text()
            old = definitions(original)
            new = definitions(live)
            for name, value in old.items():
                if new.get(name) != value:
                    raise ValueError("changed frozen semantics: " + name)
            bridge = (SUBJECT / "assurance/platform/Source.lean").read_text()
            if re.search(
                r"(?m)^\s*(axiom|unsafe|#eval|run_cmd)\b|\bsorry\b|\bnative_decide\b|skipKernelTC|trustCompiler",
                live + bridge,
            ):
                raise ValueError("untrusted proof declaration")
            sites = {
                "Cell.admit": {"enter_cell"},
                "Cell.fence": {"may_write"},
                "Cell.lease": {"admit_native"},
                "Cell.mutate": set(),
                "Cell.restore": set(),
                "Cell.dispatch": set(),
                "Cell.tx": set(),
                "Cell.release": set(),
            }
            verify_consumption(
                ORACLE / "reference/platform/cell.py",
                SUBJECT / "reference/platform/cell.py",
                sites,
                "native_decisions",
            )
            concrete = translate(SUBJECT / "reference/platform/native_decisions.py", SIG)
            files = {"Platform": live, "Concrete": concrete, "Source": bridge}
            expected = declarations(original, "Platform")
            expected.update(declarations((HERE / "Source.lean").read_text(), "Platform"))
            body = ["import Source", "set_option autoImplicit false", "namespace Platform"]
            for k, v in rows.items():
                n = v["theorem"].split(".")[-1]
                body.extend(
                    (
                        "-- obligation " + k,
                        expected[n].replace("example ", "theorem Accepted_" + n + " ", 1),
                        "#print axioms " + v["theorem"],
                    )
                )
            body.append("end Platform")
            files["Challenge"] = "\n".join(body) + "\n"
            for module, code in files.items():
                (directory / (module + ".lean")).write_text(code)
                output = checked_run(
                    [str(binaries / "lean"), "-o", module + ".olean", module + ".lean"],
                    directory,
                    env,
                )
            for module in files:
                checked_run([str(binaries / "leanchecker"), "--silent", module], directory, env)
            names = ["Platform.Accepted_" + v["theorem"].split(".")[-1] for v in rows.values()]
            certificate = external_certificate(binaries, env, directory, names, certificate_path)
            result = []
            for k, v in rows.items():
                name = v["theorem"]
                m = re.search(
                    "'"
                    + re.escape(name)
                    + r"' (?:does not depend on any axioms|depends on axioms: \[(.*?)\])",
                    output,
                    re.DOTALL,
                )
                if not m:
                    raise ValueError("missing axiom audit: " + name)
                axioms = set(q.strip() for q in (m.group(1) or "").split(",") if q.strip())
                if not axioms <= TRUST:
                    raise ValueError("foreign axiom on " + name)
                result.append(
                    item(
                        k,
                        True,
                        {
                            "compiler": version,
                            "axioms": sorted(axioms),
                            "kernelReplay": "separate leanchecker and nanoda_bin",
                            "certificate": certificate,
                            "acceptedDeclaration": "Platform.Accepted_" + name.split(".")[-1],
                            "checkerSha256": approved["bin/nanoda_bin"],
                            "sourceTermSha256": sha(concrete.encode()),
                            "statementSha256": sha(expected[name.split(".")[-1]].encode()),
                        },
                        targets,
                    )
                )
            return result
        except Exception as exc:
            return [item(k, False, {"reason": str(exc)[:1400]}, targets) for k in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--mode", choices=("formal", "runtime", "all"), default="all")
    parser.add_argument(
        "--check",
        action="append",
        choices=[k for k, v in CONFIG["checks"].items() if "probe" in v],
        help="select a named runtime observation",
    )
    args = parser.parse_args()
    if args.check and args.mode != "runtime":
        parser.error("select individual observations using --mode runtime")
    names = [
        "reference/platform/" + n
        for n in ("cell.py", "server.py", "native_decisions.py", "ocs.json")
    ]
    names += [
        "reference/interaction/client.py",
        "reference/interaction/state.py",
        "reference/contracts.py",
    ]
    targets = [{"path": n, "sha256": sha((SUBJECT / n).read_bytes())} for n in names]
    rows = [] if args.mode == "runtime" else formal(targets, args.report.with_suffix(".ndjson"))
    if args.mode != "formal":
        for test in ("lifecycle", "native", "federation", "capacity"):
            keys = [k for k, v in CONFIG["checks"].items() if v.get("probe") == test]
            if args.check:
                keys = [k for k in keys if k in args.check]
                if not keys:
                    continue
            try:
                observed = observe.run_sample(getattr(observe, test))
                ok = True
            except Exception as exc:
                ok = False
                observed = {"reason": str(exc)}
            rows.extend(item(k, ok, observed, targets) for k in keys)
    report = {
        "callerRuntime": {
            "python": platform.python_version(),
            "binarySha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
            "sqlite": sqlite3.sqlite_version,
            "os": sys.platform,
            "machine": platform.machine(),
            "kernel": platform.release(),
            "abi": sys.implementation.cache_tag,
        },
        "scope": CONFIG["scope"],
        "mode": args.mode,
        "observedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "assumptions": CONFIG["assumptions"],
        "checks": rows,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=args.report.parent, delete=False) as f:
        json.dump(report, f, indent=2)
        f.write("\n")
        path = Path(f.name)
    path.replace(args.report)
    failed = [x for x in rows if x["status"] != "pass"]
    for x in failed:
        print("FAIL", x["id"], x["observed"].get("reason"), file=sys.stderr)
    print(f"{len(rows) - len(failed)}/{len(rows)} local platform checks passed")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
