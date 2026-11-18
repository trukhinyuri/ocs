#!/usr/bin/env python3
"""Discriminating fault controls for the sealed wire qualification."""

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from check import (
    DEFAULT_ROOT,
    PIN,
    build_go,
    check_public_interface,
    execute,
    load,
    sha,
    theorem_replay,
    verify_existing,
)


def expect_failure(action, fragment):
    try:
        action()
    except (ValueError, KeyError, AssertionError) as exc:
        message = str(exc)
        if fragment not in message:
            raise ValueError(f"wrong refusal, expected {fragment!r}: {message[:320]}") from exc
        return message.splitlines()[0][:240]
    raise ValueError("the planted fault passed: " + fragment)


def mutate(file, old, new):
    original = file.read_text()
    if original.count(old) != 1:
        raise ValueError(f"cannot reproduce the published control in {file.name}")
    file.write_text(original.replace(old, new))
    return original


def run_corpus(runner, corpus, manifest, cmd, report):
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            str(runner),
            "--cases",
            str(corpus),
            "--manifest",
            str(manifest),
            "--report",
            str(report),
            "--target",
            *map(str, cmd),
        ],
        capture_output=True,
        text=True,
        timeout=160,
    )
    if not report.is_file():
        raise ValueError("fixture runner produced no evidence: " + proc.stderr[:240])
    outcomes = load(report)["checks"]
    return proc.returncode, [o["id"] for o in outcomes if o["status"] != "pass"], len(outcomes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--wire-report", type=Path, required=True)
    parser.add_argument(
        "--subject-root", type=Path, default=Path(os.environ.get("OCS_SUBJECT_ROOT", DEFAULT_ROOT))
    )
    args = parser.parse_args()
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    root = args.subject_root.resolve()
    results = []

    def record(name, detail):
        results.append(
            {
                "id": "WR-07." + name,
                "level": "runtime-observation",
                "status": "pass",
                "obligations": ["T-02.oracle", "T-04.proof-baseline"],
                "observed": detail,
            }
        )

    try:
        with tempfile.TemporaryDirectory(dir=report.parent, prefix=".wire-control-") as temp:
            work = Path(temp)
            subject, old = work / "candidate", work / "published"
            execute(["git", "clone", "--quiet", "--no-hardlinks", str(root), str(subject)], work)
            execute(["git", "clone", "--quiet", "--no-hardlinks", str(root), str(old)], work)
            execute(["git", "checkout", "--detach", "--quiet", PIN], old)
            for path in ("assurance/wire", "examples/status", "reference/go"):
                dest = subject / path
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(root / path, dest, ignore=shutil.ignore_patterns("__pycache__"))
            for path in ("reference/host.py", "go.mod"):
                shutil.copy2(root / path, subject / path)
            corpus = subject / "conformance/cases/core.json"
            missing = "recover-after-input-error"
            cases = [row for row in load(corpus) if row["id"] != missing]
            corpus.write_text(json.dumps(cases))
            idx = subject / "conformance/scenarios.json"
            index = load(idx)
            index["scenarios"]["status-call"]["checks"].remove(missing)
            idx.write_text(json.dumps(index))
            for lang in ("python", "go"):
                stage = work / lang
                stage.mkdir()
                if lang == "python":
                    src = subject / "examples/status/executor.py"
                    old_text = '            raise Fault(-33009, "input", "Expected a resource identifier.", "/resourceId")'
                    saved = mutate(src, old_text, "            self.ready = False\n" + old_text)
                    cmd = [sys.executable, "-I", src]
                    manifest = src.with_name("ocs.json")
                else:
                    src = subject / "reference/go/executor.go"
                    lines = src.read_text().splitlines()
                    match = [
                        line
                        for line in lines
                        if "Invalid resource identifier." in line and "return object" in line
                    ]
                    if len(match) != 1:
                        raise ValueError("cannot plant Go input failure")
                    saved = mutate(src, match[0], "\t\t\ts.ready = false\n" + match[0])
                    cmd = [
                        build_go(subject, stage, "control-go", ["./reference/go"]),
                        "--serve",
                        "--manifest",
                        subject / "reference/go/ocs.json",
                    ]
                    manifest = subject / "reference/go/ocs.json"
                try:
                    working = run_corpus(
                        subject / "conformance/run.py",
                        corpus,
                        manifest,
                        cmd,
                        stage / "working.json",
                    )
                    fixed = run_corpus(
                        old / "conformance/run.py",
                        old / "conformance/cases/core.json",
                        manifest,
                        cmd,
                        stage / "frozen.json",
                    )
                    if (
                        working[:2] != (0, [])
                        or fixed[0] == 0
                        or fixed[1] != [missing]
                        or working[2] != fixed[2] - 1
                    ):
                        raise ValueError(f"wire case control failed for {lang}: {working}; {fixed}")
                    failure = expect_failure(
                        lambda: theorem_replay(subject, stage), lang + "ReadRefines"
                    )
                    record(
                        lang + "-lost-scenario",
                        f"Edited corpus {working[2]}/{working[2]}, accepted corpus {fixed[2] - 1}/{fixed[2]}; {missing}; {failure}",
                    )
                finally:
                    src.write_text(saved)

            contract = subject / "assurance/wire/Contract.lean"
            saved = mutate(contract, "(invoke s f).1 = s ∧", "True ∧")
            record(
                "weakened-formula",
                expect_failure(lambda: check_public_interface(subject), "readAcceptance"),
            )
            contract.write_text(saved)
            saved = mutate(
                contract,
                "(s : Bool) (fs : List Facts) :",
                "(s : Bool) (fs : List Facts) (impossible : False) :",
            )
            record(
                "vacuous-premise",
                expect_failure(lambda: check_public_interface(subject), "ordinaryPreserves"),
            )
            contract.write_text(saved)
            py = subject / "examples/status/executor.py"
            grant = '        if value["resourceId"] != "demo":\n            raise Fault(-33001, "denied", "The resource is outside the fixture scope.")\n'
            saved = mutate(py, grant, "")
            stage = work / "no-refusal"
            stage.mkdir()
            record(
                "removed-refusal",
                expect_failure(lambda: theorem_replay(subject, stage), "pythonReadRefines"),
            )
            py.write_text(saved)
            # A compatible independent order of pure checks still satisfies the same universal property.
            syntax = re.search(
                r'        if not isinstance\(meta\["manifestDigest"\].*?(?=        if not self.ready)',
                saved,
                re.S,
            )
            if not syntax:
                raise ValueError("cannot plant compatible rearrangement")
            segment = syntax.group()
            version = segment.index('        if (\n            not isinstance(params["version"]')
            py.write_text(saved.replace(segment, segment[version:] + segment[:version]))
            stage = work / "compatible"
            stage.mkdir()
            theorem_replay(subject, stage)
            record(
                "equivalent-implementation",
                "Reordered version and pin-syntax refusal checks in the actual executor; kernel accepted both universal source theorems.",
            )
            py.write_text(saved)

            # A genuinely stronger conjunction reuses the accepted theorem and independently replays.
            strengthened = stage / "Stronger.lean"
            strengthened.write_text(
                "import Replay\nnamespace OCSWire\n"
                "theorem stronger (s : Bool) (f : Facts) : Extracted.pythonRead s f = invoke s f ∧ (invoke s f).1 = s := "
                "⟨pythonReadRefines s f, (readAcceptance s f).1⟩\nend OCSWire\n"
            )
            from check import proof_tools

            _, prefix, env = proof_tools()
            env["LEAN_PATH"] = str(stage)
            execute([prefix / "bin/lean", "-o", "Stronger.olean", "Stronger.lean"], stage, env)
            execute([prefix / "bin/leanchecker", "--silent", "Stronger"], stage, env)
            record(
                "stronger-proof",
                "Both the original theorem and an added conjunction were independently kernel-accepted.",
            )

            # Substitute the receipt hash too; a self-consistent forged receipt still has to match derivation.
            source_report = args.wire_report.resolve()
            receipt = work / "archived.json"
            original = load(source_report)
            receipt.write_text(json.dumps(original))
            artifacts = work / "archived-evidence"
            shutil.copytree(source_report.parent / (source_report.stem + "-evidence"), artifacts)
            for kind, file, marker in [
                ("foreign-certificate", "wire.ndjson", "WR-03"),
                ("substituted-binary", "status-go", "WR-06"),
            ]:
                path = artifacts / file
                original_file = path.read_bytes()
                path.write_bytes(original_file + b"\n")
                receipt_data = copy.deepcopy(original)
                receipt_data["artifacts"][file] = sha(path)
                # The build and certificate statement of identity are forged consistently as well.
                if kind == "substituted-binary":
                    receipt_data["build"]["goBinarySha256"] = sha(path)
                else:
                    receipt_data["formal"]["certificateSha256"] = sha(path)
                receipt.write_text(json.dumps(receipt_data))
                stage = work / kind
                stage.mkdir()
                record(
                    kind,
                    expect_failure(
                        lambda: verify_existing(receipt, root, artifacts, stage), marker
                    ),
                )
                path.write_bytes(original_file)
                receipt.write_text(json.dumps(original))
    except (AssertionError, ValueError, OSError, KeyError, subprocess.SubprocessError) as e:
        results.append(
            {
                "id": "WR-07.controls",
                "level": "runtime-observation",
                "status": "fail",
                "obligations": ["T-04.proof-baseline"],
                "observed": str(e)[:900],
            }
        )
    report.write_text(
        json.dumps(
            {
                "scope": "Isolated copies of both working executors and published proof artifacts.",
                "checks": results,
            },
            indent=2,
        )
        + "\n"
    )
    failed = [r for r in results if r["status"] != "pass"]
    for r in failed:
        print("FAIL", r["observed"], file=sys.stderr)
    if not failed:
        print(f"Wire fault controls passed ({len(results)}).")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
