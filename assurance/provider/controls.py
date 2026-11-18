#!/usr/bin/env python3
"""Mutation controls for the independent provider oracle. Uses disposable candidate trees."""

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from refinement import verify

ROOT = Path(__file__).resolve().parents[2]
SUBJECTS = (
    "examples/reset/ledger.py",
    "examples/reset/decision.py",
    "reference/provider/policy.py",
    "reference/provider/service.py",
    "assurance/provider/Provider.lean",
    "assurance/provider/Contract.lean",
)


def candidate(folder):
    for relative in SUBJECTS:
        src = ROOT / relative
        dest = folder / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def substitute(folder, name, old, new):
    path = folder / name
    s = path.read_text()
    if s.count(old) != 1:
        raise ValueError("mutation requires one unique source location: " + name)
    path.write_text(s.replace(old, new))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    controls = [
        (
            "E-03.serialize",
            "weaken-public-contract-definition",
            "assurance/provider/Contract.lean",
            "def Once := ∀ events : List Event, (trace fresh events).dispatches ≤ 1",
            "def Once := ∀ events : List Event, (trace fresh events).dispatches ≤ 2",
            False,
        ),
        (
            "M-02.invocation",
            "drop-subject-authorization",
            "reference/provider/policy.py",
            "return active and authenticated and entitled and supported and same_route and options_supported",
            "return active and entitled and supported and same_route and options_supported",
            False,
        ),
        (
            "E-03.serialize",
            "excess-durable-debit",
            "examples/reset/ledger.py",
            "credits=credits-1, remaining=100",
            "credits=credits-2, remaining=100",
            False,
        ),
        (
            "E-04.unknown",
            "reopen-unknown-dispatch",
            "examples/reset/decision.py",
            'if remote_reserved:\n        return "reserved"',
            'if remote_reserved:\n        return "apply"',
            False,
        ),
        (
            "M-01.complete",
            "discard-old-page-on-gap",
            "reference/provider/service.py",
            "if not pages:\n        return previous",
            "if not pages:\n        return None",
            False,
        ),
        (
            "E-03.serialize",
            "weaken-exported-theorem",
            "assurance/provider/Provider.lean",
            "theorem once_over_trace : Once := by\n  intro ops\n  exact (invariant_trace fresh (by simp [fresh, invariant]) ops).1",
            "theorem once_over_trace : True := by trivial",
            False,
        ),
        (
            "L-06.meter",
            "unaccounted-early-return",
            "reference/provider/service.py",
            '        if action == "conflict":',
            '        if action == "append":\n            return False, None\n        if action == "conflict":',
            False,
        ),
        (
            "E-02.inert",
            "grant-lookup-mutates-balance",
            "reference/provider/service.py",
            '        r = self.connection(db, state["owner"], state["account"])',
            '        db.execute("UPDATE accounts SET revision=revision+1 WHERE account=?", (state["account"],))\n        r = self.connection(db, state["owner"], state["account"])',
            False,
        ),
        (
            "M-02.invocation",
            "equivalent-boolean-program",
            "reference/provider/policy.py",
            "return active and authenticated and entitled and supported and same_route and options_supported",
            "return options_supported and same_route and supported and entitled and authenticated and active",
            True,
        ),
    ]
    cases = []
    with tempfile.TemporaryDirectory(prefix="ocs-provider-mutations-") as tmp:
        for claim, name, src, old, new, expected in controls:
            folder = Path(tmp) / name
            candidate(folder)
            substitute(folder, src, old, new)
            err = None
            try:
                verify(folder)
            except Exception as exc:
                err = str(exc)
            cases.append(
                {
                    "obligation": claim,
                    "case": name,
                    "expectedVerification": expected,
                    "actuallyVerified": err is None,
                    "result": "pass" if (err is None) == expected else "fail",
                    "diagnostic": err,
                }
            )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"controls": cases}, indent=2) + "\n")
    print("Provider mutation controls", sum(c["result"] == "pass" for c in cases), "/", len(cases))
    return int(any(c["result"] != "pass" for c in cases))


if __name__ == "__main__":
    raise SystemExit(main())
