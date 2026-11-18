#!/usr/bin/env python3
"""Replay the sealed wire model and source theorems and observe real public processes."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from extract import extract
from observe import check_hosts, child_deadlines, run_executor

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parents[1]
PIN = "6f6e22842347806f2963ef1984d9ea592fdddaf0"
MODEL_ASSUMPTIONS = [
    "Finite decoded JSON with no duplicate keys and one sequential admitted session per channel.",
    "The declared validator observations have their reviewed meaning; a future clock observation is taken before dispatch.",
    "An authorized local caller supplies one fixed resource grant and one admitted descriptor.",
]
SOURCE_ASSUMPTIONS = [
    *MODEL_ASSUMPTIONS,
    "The audited finite syntax translator preserves Python and Go control flow over its declared predicates.",
    "The standard JSON, regular expression, datetime, file, scheduling and syscall semantics are trusted.",
    "The runtime and ordinary compiler preserve the admitted source semantics. Binary functional correctness is outside this proof.",
]
THEOREMS = [
    "bootstrapAcceptance",
    "readAcceptance",
    "ordinaryPreserves",
    "witnesses",
    "firstMutuallySupported",
    "boundedFrame",
    "correlation",
    "replyIds",
    "frameBoundary",
    "nestedBounds",
    "pathBudget",
    "replyOrderIndependent",
    "otherRequestRetained",
    "metadataCannotGrant",
    "pythonReadRefines",
    "goReadRefines",
    "pythonDescribeRefines",
    "goDescribeRefines",
    "pythonRecovers",
    "goRecovers",
    "pythonUnknown",
    "goUnknown",
    "pythonStdio",
    "goStdio",
    "pythonHostBinding",
    "goHostBinding",
    "reachableHostGate",
]
WIRE = {
    "WR-01": ["W-05.bootstrap"],
    "WR-02": ["C-03.negotiate", "C-06.required", "W-05.selection"],
    "WR-03": ["W-06.recovery"],
    "WR-04": ["C-05.input", "C-07.scope", "W-05.pin", "W-06.public-call", "W-06.metadata"],
    "WR-05": ["W-04.syntax"],
    "WR-06": [
        "W-01.encoding",
        "W-01.precision",
        "W-01.request-id",
        "W-02.envelope",
        "W-02.correlation",
        "W-02.malformed-id",
        "W-02.notification",
        "W-03.min-bound",
        "W-03.framing",
        "W-08.stdio",
    ],
    "WR-07": ["T-02.oracle", "T-03.directions"],
}
MODEL_WITNESSES = {
    "WR-01": ["bootstrapAcceptance", "readAcceptance", "witnesses"],
    "WR-02": ["bootstrapAcceptance", "firstMutuallySupported", "witnesses"],
    "WR-03": ["ordinaryPreserves", "witnesses"],
    "WR-04": ["readAcceptance", "metadataCannotGrant", "witnesses", "reachableHostGate"],
    "WR-05": ["readAcceptance", "witnesses", "nestedBounds", "pathBudget"],
    "WR-06": [
        "boundedFrame",
        "replyIds",
        "correlation",
        "replyOrderIndependent",
        "otherRequestRetained",
        "frameBoundary",
    ],
}
SOURCE_WITNESSES = {
    "WR-01": ["DescribeRefines", "ReadRefines"],
    "WR-02": ["DescribeRefines"],
    "WR-03": ["Recovers", "ReadRefines"],
    "WR-04": ["ReadRefines", "HostBinding"],
    "WR-05": ["ReadRefines", "DescribeRefines"],
    "WR-06": ["Stdio"],
}
MODEL_ATOMS = {
    **{name: WIRE[name] for name in ("WR-01", "WR-02", "WR-03", "WR-04")},
    "WR-05": ["W-04.propagate"],
    "WR-06": ["W-02.correlation", "W-02.notification", "W-03.min-bound"],
}
SOURCE_ATOMS = {
    **WIRE,
    "WR-04": ["C-05.input", "C-07.scope", "W-05.pin", "W-06.public-call"],
    "WR-06": ["W-08.stdio"],
}
OBSERVATIONS = {
    "admitted-read": (
        "WR-01",
        [
            "C-03.versions",
            "C-03.negotiate",
            "C-09.scope",
            "W-05.bootstrap",
            "W-05.selection",
            "W-05.pin",
            "W-05.frame-bound",
            "W-06.public-call",
            "W-06.output",
            "W-08.stdio",
        ],
    ),
    "recovered-calls": (
        "WR-03",
        [
            "C-05.input",
            "C-05.pointer",
            "C-07.scope",
            "W-01.request-id",
            "W-02.envelope",
            "W-02.correlation",
            "W-02.notification",
            "W-04.syntax",
            "W-06.recovery",
            "W-06.metadata",
            "W-07.classification",
        ],
    ),
    "renegotiate": ("WR-02", ["C-06.required", "W-05.selection", "W-05.bootstrap"]),
    "framing": (
        "WR-06",
        [
            "W-01.encoding",
            "W-01.precision",
            "W-02.malformed-id",
            "W-03.min-bound",
            "W-03.framing",
            "W-08.stdio",
        ],
    ),
}
TARGET_FILES = [
    "examples/status/executor.py",
    "examples/status/ocs.json",
    "reference/go/executor.go",
    "reference/go/main.go",
    "reference/go/ocs.json",
    "reference/host.py",
    "reference/peer.py",
    "reference/bounded_http.py",
    "reference/contracts.py",
    "reference/admission.py",
    "go.mod",
    "uv.lock",
]


def load(file):
    return json.loads(file.read_bytes())


def sha(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execute(args, cwd, env=None, timeout=120):
    proc = subprocess.run(
        [str(v) for v in args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode:
        diagnostic = (proc.stdout + proc.stderr).strip()
        location = re.search(r"(?m)^(Replay|Host|Contract)\.lean:(\d+):\d+: error", diagnostic)
        if location:
            failed_module = Path(cwd) / (location[1] + ".lean")
            prefix = "\n".join(failed_module.read_text().splitlines()[: int(location[2])])
            names = re.findall(r"(?m)^theorem (\w+)", prefix)
            if names:
                diagnostic = names[-1] + ": " + diagnostic
        raise ValueError(
            f"{Path(str(args[0])).name} returned {proc.returncode}: {diagnostic[:1800]}"
        )
    return proc.stdout


def proof_tools():
    release = load(HERE / "toolchain.json")
    name = platform.system() + "/" + platform.machine()
    if name not in release["builds"]:
        raise ValueError("no approved proof toolchain build for this checker platform")
    release = {**release, **release["builds"][name], "checkedOn": name}
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("LEAN_PATH", "LEAN_SRC_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH")
    }
    env["ELAN_TOOLCHAIN"] = release["release"]
    installed = execute(["elan", "toolchain", "list"], HERE, env)
    if release["release"] not in installed.splitlines() and not any(
        line.split()[:1] == [release["release"]] for line in installed.splitlines()
    ):
        raise ValueError("install the pinned Lean release before offline qualification")
    prefix = Path(execute(["lean", "--print-prefix"], HERE, env).strip())
    for path, expected in release["files"].items():
        if sha(prefix / path) != expected:
            raise ValueError(
                "T-04.proof-baseline: substituted proof checker or shared library " + path
            )
    if execute([prefix / "bin/lean", "--githash"], HERE, env).strip() != release["commit"]:
        raise ValueError("T-04.proof-baseline: wrong Lean revision")
    return release, prefix, env


def build_go(root, work, name, args):
    env = {
        **os.environ,
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOWORK": "off",
        "GOFLAGS": "",
        "GOTOOLCHAIN": "local",
        "CGO_ENABLED": "0",
    }
    binary = work / name
    execute(
        ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", binary, *args],
        root,
        env,
    )
    return binary


def theorem_replay(subject, work):
    release, prefix, env = proof_tools()
    source_files = sorted((subject / "reference/go").glob("*.go"))
    source_files = [p for p in source_files if not p.name.endswith("_test.go")]
    if {p.name for p in source_files} != {"executor.go", "main.go"}:
        raise ValueError("unreviewed Go reference package source graph")
    reader = build_go(HERE, work, "go-ast-reader", [str(HERE / "goast/main.go")])
    functions = json.loads(execute([reader, *source_files], work))
    (work / "Extracted.lean").write_text(extract(subject, functions))
    env = {**env, "LEAN_PATH": str(work)}
    auditor_output = []
    for name in ("Contract", "Extracted", "Replay", "Host"):
        if name != "Extracted":
            shutil.copy2(HERE / (name + ".lean"), work / (name + ".lean"))
        auditor_output.append(
            execute(
                [
                    prefix / "bin/lean",
                    "-DwarningAsError=true",
                    "-o",
                    name + ".olean",
                    name + ".lean",
                ],
                work,
                env,
            )
        )
    all_output = "\n".join(auditor_output)
    audits = {}
    for name in THEOREMS:
        match = re.search(
            r"'OCSWire\."
            + name
            + r"' (?:does not depend on any axioms|depends on axioms: \[([^\]]*)\])",
            all_output,
        )
        if not match:
            raise ValueError("missing theorem axiom audit for " + name)
        audits[name] = sorted(x.strip() for x in (match.group(1) or "").split(",") if x.strip())
        if set(audits[name]) - set(release["axioms"]):
            raise ValueError("unaccepted transitive axiom for " + name)
    execute(
        [prefix / "bin/leanchecker", "--silent", "Contract", "Extracted", "Replay", "Host"],
        work,
        env,
    )
    names = ["OCSWire." + n for n in THEOREMS]
    proof = work / "wire.ndjson"
    with proof.open("wb") as stream:
        proc = subprocess.run(
            [str(prefix / "bin/leanexport"), "Replay", "Host", "--", *names],
            cwd=work,
            env=env,
            stdout=stream,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    if proc.returncode or not proof.stat().st_size:
        raise ValueError("Lean did not export a complete stand-alone proof")
    config = {
        "export_file_path": str(proof),
        "permitted_axioms": release["axioms"],
        "unpermitted_axiom_hard_error": True,
        "nat_extension": True,
        "string_extension": True,
        "pp_to_stdout": True,
        "pp_declars": names,
        "pp_options": {"proofs": False},
        "print_success_message": True,
    }
    (work / "kernel.json").write_text(json.dumps(config))
    kernel = execute([prefix / "bin/nanoda_bin", work / "kernel.json"], work, env)
    if not all(re.search(r"(?m)^theorem " + re.escape(name) + r"\b", kernel) for name in names):
        raise ValueError("independent checker did not export every expected theorem")
    match = re.search(r"Checked (\d+) declarations with no errors", kernel)
    if not match:
        raise ValueError("independent kernel did not accept the exported declarations")
    (work / "kernel.txt").write_text(kernel)
    return {
        "theorems": audits,
        "independentKernel": "nanoda 0.4.17",
        "checkedDeclarations": int(match.group(1)),
        "certificateSha256": sha(proof),
        "extractedSourceSha256": sha(work / "Extracted.lean"),
        "checkerFiles": release["files"],
        "toolchainArchiveSha256": release["assetSha256"],
        "toolchainArchive": release["asset"],
        "replayedOn": release["checkedOn"],
        "leanRevision": release["commit"],
    }


def source_digests(subject):
    rels = [
        *TARGET_FILES,
        *(str(p.relative_to(subject)) for p in sorted((subject / "schemas").glob("*.json"))),
    ]
    return {name: sha(subject / name) for name in rels}


def oracle_digests():
    files = [
        f
        for f in HERE.rglob("*")
        if f.is_file()
        and "__pycache__" not in f.parts
        and f.suffix in {".go", ".py", ".json", ".lean"}
    ]
    return {str(p.relative_to(HERE)): sha(p) for p in sorted(files)}


def interface(path):
    """Catalogue the declarations used by this accepted, deliberately small Lean source form.

    Definitions must retain their body, theorem names must retain their type.
    Proofs may change and extra declarations may be added. The independent
    kernel subsequently checks the accepted statements against the extracted subject.
    """
    raw = re.sub(r"/-.*?-/", "", path.read_text(), flags=re.DOTALL)
    lines = [
        line
        for line in raw.splitlines()
        if not line.startswith(("#print", "end ", "namespace ", "import "))
    ]
    source = "\n".join(lines)
    matches = list(re.finditer(r"(?m)^(theorem|def|abbrev|structure|inductive)\s+(\w+)\b", source))
    declarations = {}
    for index, match in enumerate(matches):
        segment = source[
            match.start() : matches[index + 1].start() if index + 1 < len(matches) else len(source)
        ]
        if match[1] == "theorem":
            depth = 0
            quoted = False
            for position, character in enumerate(segment):
                if character == '"' and (position == 0 or segment[position - 1] != "\\"):
                    quoted = not quoted
                elif not quoted and character in "([{":
                    depth += 1
                elif not quoted and character in ")]}":
                    depth -= 1
                elif not quoted and depth == 0 and segment.startswith(":=", position):
                    segment = segment[:position]
                    break
            else:
                raise ValueError("missing wire theorem body delimiter for " + match[2])
        if match[2] in declarations:
            raise ValueError("duplicate wire policy symbol " + match[2])
        declarations[match[2]] = " ".join(segment.split())
    return declarations


def check_public_interface(subject):
    for file in ("Contract.lean", "Replay.lean", "Host.lean"):
        expected = interface(HERE / file)
        actual = interface(subject / "assurance/wire" / file)
        for name, criterion in expected.items():
            if actual.get(name) != criterion:
                raise ValueError(
                    f"T-04.proof-baseline: removed or changed wire definition/statement {name}"
                )


def old_suite(subject, work, commands):
    git = ["git", "--no-replace-objects", "-C", str(subject)]
    old = work / "published"
    old.mkdir()
    raw = subprocess.run(
        [*git, "archive", "--format=zip", PIN, "conformance", "reference/contracts.py", "schemas"],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    from io import BytesIO
    from zipfile import ZipFile

    with ZipFile(BytesIO(raw)) as archive:
        archive.extractall(old)
    corpus = load(old / "conformance/cases/core.json")
    expected = {row["id"] for row in corpus}
    results = {}
    for language, (command, manifest) in commands.items():
        output = work / ("published-" + language + ".json")
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                str(old / "conformance/run.py"),
                "--manifest",
                str(manifest),
                "--report",
                str(output),
                "--target",
                *map(str, command),
            ],
            cwd=old,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if not output.is_file():
            raise ValueError(
                "fixed runner produced no " + language + " report: " + process.stderr[:200]
            )
        report = load(output)
        rows = report["checks"]
        failed = [row["id"] for row in rows if row["status"] != "pass"]
        if (
            failed
            or {row["id"] for row in rows} != expected
            or len(rows) != len(expected)
            or process.returncode
        ):
            raise ValueError(
                "published "
                + language
                + " case failure: "
                + ", ".join(failed or ["wrong case inventory"])
            )
        results[language] = {
            "caseIds": sorted(expected),
            "corpusSha256": sha(old / "conformance/cases/core.json"),
            "reportSha256": sha(output),
            "baseline": PIN,
        }
    return results


def row(label, level, atoms, status, observed, **extra):
    return {
        "id": label,
        "level": level,
        "obligations": atoms,
        "status": status,
        "observed": observed,
        **extra,
    }


def publish(file, target):
    part = target.with_name(target.name + f".{os.getpid()}.tmp")
    try:
        shutil.copy2(file, part)
        os.replace(part, target)
    finally:
        part.unlink(missing_ok=True)


def collect(subject, work, dest, formal_only=False):
    out = {
        "scope": "Sealed stdio status operation org.example.status and org.example.status-go, exact Linux host build.",
        "observedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": [],
        "sources": source_digests(subject),
        "oracle": oracle_digests(),
        "artifacts": {},
    }
    reports = out["checks"]
    try:
        check_public_interface(subject)
        metadata = theorem_replay(subject, work)
        out["formal"] = metadata
        for key, names in MODEL_WITNESSES.items():
            reports.append(
                row(
                    key + ".model",
                    "model",
                    MODEL_ATOMS[key],
                    "pass",
                    "Model theorem checked, including a permitted and a forbidden witness.",
                    theorem=names,
                    assumptions=MODEL_ASSUMPTIONS,
                )
            )
        for lang in ("python", "go"):
            for key, names in SOURCE_WITNESSES.items():
                reports.append(
                    row(
                        key + "." + lang + "-source",
                        "source-refinement",
                        SOURCE_ATOMS[key],
                        "pass",
                        "Concrete dispatch or stdio control projection checked against the independently defined contract.",
                        theorem=[lang + n for n in names],
                        assumptions=SOURCE_ASSUMPTIONS,
                        targets=out["sources"],
                    )
                )
    except (ValueError, KeyError, OSError, SyntaxError, subprocess.SubprocessError) as e:
        message = str(e)
        for key in MODEL_WITNESSES:
            reports.append(
                row(
                    key + ".model",
                    "model",
                    MODEL_ATOMS[key],
                    "open",
                    "A complete independently replayed certificate was not produced.",
                )
            )
        for lang in ("python", "go"):
            for key in SOURCE_WITNESSES:
                reports.append(
                    row(
                        key + "." + lang + "-source",
                        "source-refinement",
                        SOURCE_ATOMS[key],
                        "fail",
                        message,
                    )
                )
    if formal_only:
        out["partial"] = True
    else:
        native = build_go(subject, work, "status-go", ["./reference/go"])
        python_file = subject / "examples/status/executor.py"
        commands = {
            "python": ([sys.executable, "-I", str(python_file)], python_file.with_name("ocs.json")),
            "go": (
                [str(native), "--serve", "--manifest", str(subject / "reference/go/ocs.json")],
                subject / "reference/go/ocs.json",
            ),
        }
        targets = {
            "goBinarySha256": sha(native),
            "pythonScriptSha256": sha(python_file),
            "pythonInterpreterSha256": sha(Path(sys.executable)),
            "pythonVersion": platform.python_version(),
            "goVersion": execute(["go", "version"], subject).strip(),
            "platform": platform.system() + "/" + platform.machine(),
            "goBuild": "go build -trimpath -buildvcs=false -ldflags=-buildid= ./reference/go (CGO_ENABLED=0)",
        }
        out["build"] = targets
        for lang, (cmd, manifest) in commands.items():
            try:

                def observe(name, details):
                    label, atoms = OBSERVATIONS[name]
                    reports.append(
                        row(
                            label + "." + lang + "-" + name,
                            "runtime-observation",
                            atoms,
                            "pass",
                            "Observed sealed stdio exchange.",
                            details=details,
                            targets=targets,
                        )
                    )

                run_executor(cmd, manifest, observe)
                reports.append(
                    row(
                        "WR-06." + lang + "-artifact",
                        "artifact-observation",
                        ["W-08.stdio"],
                        "pass",
                        "Identified and ran this artifact through stdio. Its runtime/compiler semantical correctness is trusted.",
                        targets=targets,
                    )
                )
            except (ValueError, AssertionError, OSError, subprocess.SubprocessError) as e:
                reports.append(
                    row(
                        "WR-06." + lang + "-reference",
                        "runtime-observation",
                        WIRE["WR-06"],
                        "fail",
                        str(e),
                    )
                )
        try:
            hosts = check_hosts(subject, native, work)
            for lang, observations in hosts.items():
                reports.append(
                    row(
                        "WR-05." + lang + "-host",
                        "runtime-observation",
                        [
                            "W-04.late-read",
                            "W-05.pin",
                            "W-05.frame-bound",
                            "W-03.min-bound",
                            "C-05.output",
                            "W-02.correlation",
                            "W-06.output",
                        ],
                        "pass",
                        "The normal host returned refusal on each planted fault; recorded whether the executor received a call.",
                        details=observations,
                        targets=targets,
                    )
                )
        except (ValueError, AssertionError, OSError, subprocess.SubprocessError) as e:
            reports.append(
                row(
                    "WR-05.host",
                    "runtime-observation",
                    ["W-04.late-read", "W-05.pin"],
                    "fail",
                    str(e),
                )
            )
        try:
            observed = child_deadlines(subject, work)
            reports.append(
                row(
                    "WR-05.delegated-time",
                    "runtime-observation",
                    ["W-04.propagate", "W-04.late-read"],
                    "pass",
                    "Observed actual child budgets and refused a timely result whose teardown exceeded the parent deadline.",
                    details=observed,
                )
            )
        except (ValueError, AssertionError, OSError, subprocess.SubprocessError) as e:
            reports.append(
                row(
                    "WR-05.delegated-time",
                    "runtime-observation",
                    ["W-04.propagate", "W-04.late-read"],
                    "fail",
                    str(e),
                )
            )
        try:
            old = old_suite(subject, work, commands)
            for lang, data in old.items():
                reports.append(
                    row(
                        "WR-07." + lang + "-baseline",
                        "runtime-observation",
                        ["T-02.oracle"],
                        "pass",
                        "Unedited accepted caller replayed all its cases against the current executor, including recover-after-input-error.",
                        details=data,
                    )
                )
        except (ValueError, AssertionError, OSError, subprocess.SubprocessError) as e:
            reports.append(
                row("WR-07.baseline", "runtime-observation", ["T-02.oracle"], "fail", str(e))
            )
    dest.mkdir(parents=True, exist_ok=True)
    for name in (
        "wire.ndjson",
        "Extracted.lean",
        "kernel.txt",
        "status-go",
        "published-python.json",
        "published-go.json",
    ):
        file = work / name
        if file.is_file():
            publish(file, dest / name)
            out["artifacts"][name] = sha(file)
    return out


def verify_existing(report, subject, artifacts, work):
    check_public_interface(subject)
    saved = load(report)
    if (
        saved.get("partial")
        or not saved.get("checks")
        or any(r["status"] != "pass" for r in saved["checks"])
    ):
        raise ValueError("WR-07: receipt is incomplete or contains an unverified result")
    if source_digests(subject) != saved["sources"] or oracle_digests() != saved["oracle"]:
        raise ValueError("WR-03: recorded target or verifier revision changed")
    for key in (
        "wire.ndjson",
        "Extracted.lean",
        "kernel.txt",
        "status-go",
        "published-python.json",
        "published-go.json",
    ):
        if sha(artifacts / key) != saved["artifacts"].get(key):
            raise ValueError(
                ("WR-06" if key == "status-go" else "WR-03") + ": substituted artifact " + key
            )
    fresh = theorem_replay(subject, work)
    if fresh != saved["formal"] or sha(work / "wire.ndjson") != saved["artifacts"]["wire.ndjson"]:
        raise ValueError(
            "WR-03: supplied certificate does not match the independently rederived program and proof"
        )
    native = build_go(subject, work, "status-go", ["./reference/go"])
    if (
        sha(native) != saved["artifacts"]["status-go"]
        or sha(native) != saved["build"]["goBinarySha256"]
    ):
        raise ValueError("WR-06: supplied binary does not match the independently reproduced build")


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--report", type=Path, required=True)
    args.add_argument(
        "--subject-root", type=Path, default=Path(os.environ.get("OCS_SUBJECT_ROOT", DEFAULT_ROOT))
    )
    args.add_argument(
        "--formal-only",
        action="store_true",
        help="partial diagnostic scope, qualification requires the full run",
    )
    args.add_argument(
        "--verify-artifacts",
        action="store_true",
        help="rederive the certificate and binary for a previously full receipt",
    )
    opt = args.parse_args()
    report = opt.report.resolve()
    subject = opt.subject_root.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    dest = report.parent / (report.stem + "-evidence")
    try:
        with tempfile.TemporaryDirectory(prefix=".wire-", dir=report.parent) as tmp:
            work = Path(tmp)
            if opt.verify_artifacts:
                verify_existing(report, subject, dest, work)
                print("Wire source certificate and executed artifact identities reproduced.")
                return 0
            result = collect(subject, work, dest, opt.formal_only)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, AssertionError) as e:
        if opt.verify_artifacts:
            print("FAIL", str(e), file=sys.stderr)
            return 1
        result = {
            "scope": "Sealed stdio source and runtime qualification",
            "checks": [row("WR-07.runner", "runtime-observation", ["T-02.oracle"], "fail", str(e))],
        }
    name = report.with_name(report.name + f".{os.getpid()}.tmp")
    name.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.replace(name, report)
    failures = [r for r in result["checks"] if r["status"] != "pass"]
    if failures:
        for cause in dict.fromkeys(r["observed"] for r in failures):
            print("FAIL wire qualification", cause, file=sys.stderr)
    else:
        print(f"Wire qualification: {len(result['checks'])} passing evidence rows ({report})")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
