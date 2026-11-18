#!/usr/bin/env python3
"""Replay typed core obligations and observe actual public host and package boundaries."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORACLE = HERE.parents[1]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
sys.path.insert(0, str(HERE))
from runtime import observe

MAPPING = {
    "admission_exact": ["C-01.admit", "C-07.effect"],
    "missing_authority_refuses": ["C-07.request", "C-07.effect"],
    "all_required": ["C-04.required"],
    "optional_independent": [],
    "display_independent": ["C-02.object-id"],
    "identity_disjoint": [],
    "preserve_on_failure": ["core.package-distribution.atomic-install"],
    "install_valid": ["C-01.admit"],
    "arbitrary_failed_updates": ["core.package-distribution.atomic-install"],
    "deadlines_decrease": ["W-04.propagate", "B-05.budgets"],
    "step_conserves": ["W-03.queues"],
    "capacity_invariant": ["W-03.queues", "B-07.limits"],
    "busy_bound": ["B-07.limits"],
    "zero_capacity_denies": ["W-03.queues"],
    "capacity_progress": ["B-07.limits"],
    "hard_requires_bound": ["L-03.timing", "L-03.confinement"],
    "native_soft_witness": ["L-03.timing"],
    "native_hard_refusal": ["L-03.timing"],
    "unknown_on_lost_evidence": [],
    "transitive_refinement": [],
    "status_realizable": ["W-06.public-call"],
    "valid_status_witness": ["W-06.public-call"],
    "wrong_status_forbidden": ["W-06.public-call"],
    "rank_decreases_on_path": ["C-04.cycles"],
    "rank_excludes_cycle": ["C-04.cycles"],
    "forward_preserves_optional": [],
    "no_evidence_no_action": ["P-02.absence"],
    "public_record_noninterference": ["C-10.redaction"],
    "reverse_is_unbound": ["B-01.direction"],
    "bound_route_exists": ["B-01.direction"],
    "no_grant_from_request": ["C-07.request"],
    "elapsed_does_not_rollback": [],
    "fresh_grant_required": ["B-02.fresh-authority"],
    "extension_preserves_status": [],
    "extended_status_realizable": [],
    "successful_grant": ["C-01.admit"],
    "denied_grant": ["C-07.effect"],
    "authenticated_subject_exact": ["C-02.issuer"],
    "scoped_identifiers_disjoint": ["C-02.object-id"],
    "timeout_keeps_scoped_intent": ["W-04.write-timeout"],
    "timeout_empty_keeps_record": ["W-04.write-timeout"],
    "foreign_receipt_inert": ["W-04.write-timeout"],
    "owner_receipt_establishes_outcome": ["W-04.write-timeout"],
    "old_traces_complete": ["C-09.refinement"],
    "silence_is_incompatible": ["C-09.refinement"],
    "mixed_generation_contract": ["C-09.refinement", "T-03.directions"],
    "per_export_imports_exact": ["C-04.optional"],
    "isolated_optional_failure": ["C-04.optional"],
    "lossless_forward_exact": ["C-06.opaque"],
    "refuses_essential_loss": ["C-06.opaque"],
}
TOOLCHAIN = "leanprover/lean4:v4.36.0-rc2"
COMMIT = "b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(argv, cwd, env=None, timeout=90):
    p = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if p.returncode:
        raise ValueError(f"{Path(str(argv[0])).name} failed: {p.stdout[-900:]}")
    return p.stdout


def proofs(directory):
    prefix = Path(
        execute(
            ["elan", "which", "lean"], directory, {**os.environ, "ELAN_TOOLCHAIN": TOOLCHAIN}
        ).strip()
    ).parent
    version = execute([prefix / "lean", "--version"], directory)
    if COMMIT not in version:
        raise ValueError("Lean kernel revision mismatch")
    # The statements and semantic definitions come from the protected oracle.
    # The witness bodies come from the submitted subject tree.
    if (SUBJECT / "assurance/core/Contract.lean").read_bytes() != (
        HERE / "Contract.lean"
    ).read_bytes():
        raise ValueError(
            "core semantic definitions changed; review a separately versioned refinement"
        )
    proof_source = SUBJECT / "assurance/core/Proofs.lean"
    source = proof_source.read_text()
    if any(
        line.startswith("import ") and line.strip() != "import Contract"
        for line in source.splitlines()
    ):
        raise ValueError("unreviewed core proof import")
    if re.search(
        r"(?<!\.)\b(sorry|admit|axiom|native_decide|unsafe|run_tac|elab|macro|extern|implemented_by)\b|#eval|#run|\bset_option\b",
        source,
    ):
        raise ValueError("unreviewed core proof dependency")
    for name, origin in (("Contract", HERE), ("Proofs", proof_source.parent), ("Expected", HERE)):
        shutil.copyfile(origin / (name + ".lean"), directory / (name + ".lean"))
    env = {**os.environ, "LEAN_PATH": str(directory)}
    output = ""
    for name in ("Contract", "Proofs", "Expected"):
        output += execute(
            [prefix / "lean", "-DwarningAsError=true", "-o", name + ".olean", name + ".lean"],
            directory,
            env,
        )
    execute([prefix / "leanchecker", "--silent", "Contract", "Proofs", "Expected"], directory, env)
    certificate = directory / "core.ndjson"
    names = ["OCS.Core." + name for name in MAPPING]
    with certificate.open("wb") as f:
        subprocess.run(
            [prefix / "leanexport", "Expected", "--", *names],
            cwd=directory,
            env=env,
            stdout=f,
            stderr=subprocess.PIPE,
            check=True,
            timeout=90,
        )
    cfg = {
        "export_file_path": str(certificate),
        "pp_to_stdout": True,
        "pp_declars": names,
        "pp_options": {"proofs": False},
        "permitted_axioms": ["propext", "Classical.choice", "Quot.sound"],
        "unpermitted_axiom_hard_error": True,
        "nat_extension": True,
        "string_extension": True,
        "print_success_message": True,
    }
    (directory / "kernel.json").write_text(json.dumps(cfg))
    kernel = execute([prefix / "nanoda_bin", directory / "kernel.json"], directory, env)
    if not re.search(r"Checked [0-9]+ declarations with no errors", kernel) or not all(
        re.search(r"(?m)^theorem " + re.escape(name) + r"\b", kernel) for name in names
    ):
        raise ValueError("independent kernel did not confirm every expected theorem")
    rows = []
    auxiliary = {}
    for name, atoms in MAPPING.items():
        m = re.search(
            r"'OCS\.Core\."
            + name
            + r"' (?:does not depend on any axioms|depends on axioms: \[([^\]]*)\])",
            output,
        )
        if not m:
            raise ValueError("missing axiom audit " + name)
        axioms = [a.strip() for a in (m[1] or "").split(",") if a.strip()]
        if set(axioms) - set(cfg["permitted_axioms"]):
            raise ValueError("untrusted axiom in " + name)
        if not atoms:
            auxiliary["OCS.Core." + name] = axioms
            continue
        rows.append(
            {
                "id": "core." + name,
                "level": "model",
                "claims": atoms,
                "status": "pass",
                "theorem": "OCS.Core." + name,
                "assumptions": [
                    "Finite individual messages and trace prefixes; typed owner state, reviewed grant dimensions and declared clocks."
                ],
                "observed": {
                    "statementFile": sha(HERE / "Expected.lean"),
                    "model": sha(HERE / "Contract.lean"),
                    "proof": sha(proof_source),
                    "axioms": axioms,
                    "certificate": sha(certificate),
                },
            }
        )
    return rows, {
        "lean": version.strip(),
        "leanSha256": sha(prefix / "lean"),
        "independentKernel": re.search(
            r"Checked [0-9]+ declarations with no errors", kernel
        ).group(),
        "independentKernelSha256": sha(prefix / "nanoda_bin"),
        "auxiliaryTheorems": auxiliary,
        "certificateSha256": sha(certificate),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"scope": "Core formal contract and local public entry points", "checks": []}
    with tempfile.TemporaryDirectory(prefix="ocs-core-proof-") as tmp:
        try:
            rows, formal = proofs(Path(tmp))
            report["checks"].extend(rows)
            report["formal"] = formal
            shutil.copyfile(Path(tmp) / "core.ndjson", args.report.parent / "core.ndjson")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report["checks"].append(
                {
                    "id": "core.proof-replay",
                    "level": "model",
                    "status": "fail",
                    "observed": str(exc),
                }
            )
        observe(SUBJECT, ORACLE, Path(tmp), report["checks"])
    report["observedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    failed = [r for r in report["checks"] if r["status"] != "pass"]
    for row in failed:
        print("FAIL", row["id"], row["observed"], file=sys.stderr)
    print(
        f"{len(report['checks']) - len(failed)}/{len(report['checks'])} core evidence items passed"
    )
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
