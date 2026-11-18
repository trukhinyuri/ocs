#!/usr/bin/env python3
"""Check the interaction and native assurance oracles against deliberate candidate changes."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ORACLE = Path(__file__).resolve().parents[2]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()


def replacement(source, old, new):
    if source.count(old) != 1:
        raise ValueError("The named control site needs review: " + old[:80])
    return source.replace(old, new)


def controls(report):
    rows = []
    with tempfile.TemporaryDirectory(prefix="ocs-profile-controls-") as tmp:
        base = Path(tmp)
        candidate = base / "candidate"
        for name in ("interaction", "platform"):
            for kind in ("reference", "assurance"):
                dest = candidate / kind / name
                shutil.copytree(
                    SUBJECT / kind / name, dest, ignore=shutil.ignore_patterns("__pycache__")
                )
        (candidate / "reference/contracts.py").write_bytes(
            (SUBJECT / "reference/contracts.py").read_bytes()
        )
        for folder in ("schemas", "spec/profiles", "examples/records"):
            shutil.copytree(SUBJECT / folder, candidate / folder)
        files = {
            "i-kernel": candidate / "reference/interaction/kernel.py",
            "i-runtime": candidate / "reference/interaction/service.py",
            "i-outcome": candidate / "reference/interaction/state.py",
            "i-model": candidate / "assurance/interaction/Interaction.lean",
            "i-bridge": candidate / "assurance/interaction/Source.lean",
            "p-kernel": candidate / "reference/platform/native_decisions.py",
            "p-cell": candidate / "reference/platform/cell.py",
        }
        saved = {name: path.read_text() for name, path in files.items()}
        changes = [
            (
                "disabled-source-refusal",
                "interaction",
                "i-kernel",
                " and active and owner_ok",
                " and owner_ok",
                False,
                "admitSource",
            ),
            (
                "weakened-theorem",
                "interaction",
                "i-model",
                "admit i a b false o current seen = false := by simp [admit]",
                "True := by trivial",
                False,
                "revokedNoDispatch",
            ),
            (
                "narrowed-semantics",
                "interaction",
                "i-model",
                "if owned && (s.finals == 0) then",
                "if (s.credit < 7) && owned && (s.finals == 0) then",
                False,
                "changed frozen semantics: tick",
            ),
            (
                "equivalent-grant-implementation",
                "interaction",
                "i-kernel",
                "return parent and exported and imported and scoped",
                "return parent and imported and exported and scoped",
                True,
                "",
            ),
            (
                "additional-corollary",
                "interaction",
                "i-model",
                "end Interaction",
                "theorem strengthened (s : Stream) (t : List Command) (h : s.credit+s.sent=s.granted) : (runStream s t).credit+(runStream s t).sent=(runStream s t).granted ∧ (runStream s t).sent≤(runStream s t).granted := by have eqn := streamConserved s t h; exact ⟨eqn,by omega⟩\nend Interaction",
                True,
                "",
            ),
            (
                "hard-timing-refusal",
                "platform",
                "p-kernel",
                "and not hard",
                "and True",
                False,
                "nativeSource",
            ),
            (
                "stale-write-authority",
                "platform",
                "p-kernel",
                "and current_epoch == admitted_epoch",
                "and True",
                False,
                "writerSource",
            ),
            (
                "bypassed-occupancy-guard",
                "platform",
                "p-cell",
                "if not native_decisions.enter_cell(",
                "if False and not native_decisions.enter_cell(",
                False,
                "changed decision consumption",
            ),
        ]
        changes.extend(
            [
                (
                    "foreign-artifact-purpose",
                    "interaction",
                    "i-runtime",
                    "if principal.purpose != purpose:",
                    "if False and principal.purpose != purpose:",
                    False,
                    "Expected a refusal",
                ),
                (
                    "lost-post-commit-handle",
                    "interaction",
                    "i-outcome",
                    "self.operation_id = operation_id",
                    "self.operation_id = None",
                    False,
                    "late committed result lost",
                ),
            ]
        )
        changes.extend(
            [
                (
                    "early-return-before-stream-send",
                    "interaction",
                    "i-runtime",
                    "        self.state = kernel.stream_step(action, owned, *self.state, amount, CREDIT)",
                    "        if action == 1:\n            return\n        self.state = kernel.stream_step(action, owned, *self.state, amount, CREDIT)",
                    False,
                    "changed decision consumption",
                ),
                (
                    "overwrite-computed-credit",
                    "interaction",
                    "i-runtime",
                    "        self.state = kernel.stream_step(action, owned, *self.state, amount, CREDIT)",
                    "        self.state = kernel.stream_step(action, owned, *self.state, amount, CREDIT)\n        self.state = (9,0,9,1,0)",
                    False,
                    "changed decision consumption",
                ),
                (
                    "bypass-fenced-write-before-check",
                    "platform",
                    "p-cell",
                    "        if not row or (",
                    "        if require and actor.writer == 'replacement':\n            return row\n        if not row or (",
                    False,
                    "changed decision consumption",
                ),
            ]
        )
        changes.extend(
            [
                (
                    "changed-refinement-projection",
                    "interaction",
                    "i-bridge",
                    "def packed (s : Stream) := (s.credit, s.sent, s.granted, s.remaining, s.finals)",
                    "def packed (s : Stream) := (s.credit, s.sent, s.granted, s.remaining, 0)",
                    False,
                    "changed frozen semantics: packed",
                ),
                (
                    "added-elaboration-notation",
                    "interaction",
                    "i-model",
                    "namespace Interaction",
                    'namespace Interaction\nlocal notation "hiddenPredicate" => True',
                    False,
                    "unreviewed string or syntax quotation",
                ),
                (
                    "shadowed-semantic-domain",
                    "interaction",
                    "i-model",
                    "namespace Interaction",
                    "namespace Interaction\nabbrev AdditionalDomain := Unit",
                    False,
                    "changed frozen semantics: AdditionalDomain",
                ),
            ]
        )
        runtime_cases = {
            "foreign-artifact-purpose": "interaction.artifact",
            "lost-post-commit-handle": "interaction.lateOutcome",
        }
        for label, domain, target, old, new, success, reason in changes:
            path = files[target]
            path.write_text(replacement(saved[target], old, new))
            out = base / (label + ".json")
            p = subprocess.run(
                [
                    sys.executable,
                    str(ORACLE / f"assurance/{domain}/probe.py"),
                    "--mode",
                    "runtime" if label in runtime_cases else "formal",
                    *(["--check", runtime_cases[label]] if label in runtime_cases else []),
                    "--report",
                    str(out),
                ],
                env={**os.environ, "OCS_SUBJECT_ROOT": str(candidate)},
                capture_output=True,
                text=True,
                timeout=160,
            )
            path.write_text(saved[target])
            if not out.is_file():
                raise RuntimeError("Missing oracle report: " + label)
            checks = json.loads(out.read_bytes())["checks"]
            failures = [c for c in checks if c["status"] != "pass"]
            detail = failures[0]["observed"]["reason"] if failures else ""
            ok = (
                (p.returncode == 0 and not failures)
                if success
                else (p.returncode != 0 and failures and reason in detail)
            )
            rows.append(
                {
                    "id": "control.interaction-platform." + label,
                    "level": "runtime-observation",
                    "status": "pass" if ok else "fail",
                    "expectedAcceptance": success,
                    "observed": {
                        "exit": p.returncode,
                        "firstDiagnostic": detail[:700],
                        "qualified": len(checks) - len(failures),
                        "offered": len(checks),
                    },
                }
            )
            print(label, rows[-1]["status"], flush=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {"scope": "Independent fixture/model challenge controls", "checks": rows}, indent=2
        )
        + "\n"
    )
    return int(any(c["status"] != "pass" for c in rows))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path, required=True)
    raise SystemExit(controls(p.parse_args().report))
