"""Run Safe Push's independent controls and read the actual Git ref in a fresh receiver."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    history = p.add_mutually_exclusive_group()
    history.add_argument("--history-only", action="store_true")
    history.add_argument("--hosted-refusal-only", action="store_true")
    history.add_argument("--operating-catalog-only", action="store_true")
    p.add_argument("--report", type=Path, default=Path("out/safe-push/check.json"))
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    suites = (
        "test_authority",
        "test_scope",
        "test_proof",
        "test_qualification.IndependentFixtureTests",
        "test_forge",
        "test_forge_apps",
        "test_forge_stage.ReviewStageTests",
        "test_forge_delivery",
        "test_forge_refusals.RefusalTests",
        "test_cost",
        "test_cost_acquisition",
        "test_operating_catalog.OperatingCatalogTests",
        "test_local_install",
        "test_evolution",
        "test_method_worker",
        "test_object_view",
    )
    sys.path.insert(0, str(root))
    chosen = suites
    historical_scope = None
    if a.history_only:
        chosen = (
            "test_qualification.SealedEditionTests",
            "test_forge_stage.HistoricalStageTests",
        )
        historical_scope = "independently enrolled original full OCS dossier"
    if a.hosted_refusal_only:
        chosen = ("test_forge_refusals.HistoricalRefusalTests",)
        historical_scope = (
            "independently signed and comparable hosted refusal measurements"
        )
    if a.operating_catalog_only:
        chosen = ("test_operating_catalog.HistoricalOperatingCatalogTests",)
        historical_scope = "separately provided operating custody and retained measured counterexamples"
    names = [f"safe_push.{m}" for m in chosen]
    if historical_scope is None:
        names.append("conformance.test_platform_reference.PlatformReferenceTests")
    checks = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=1).run(checks)
    if not result.wasSuccessful() or result.skipped or result.testsRun == 0:
        raise SystemExit(
            "required Safe Push checks failed, were skipped or were unavailable"
        )
    a.report.parent.mkdir(parents=True, exist_ok=True)
    if historical_scope is not None:
        a.report.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "scope": historical_scope,
                    "tests": result.testsRun,
                    "skipped": 0,
                },
                indent=2,
            )
            + "\n"
        )
        return
    with tempfile.TemporaryDirectory(prefix="receiver-controls-") as tmp:
        work = Path(tmp) / "case"
        subprocess.run(
            [
                sys.executable,
                str(root / "safe_push/test_receiver.py"),
                "--source",
                str(root),
                "--work",
                str(work),
            ],
            cwd=root,
            check=True,
        )
        experiments = json.loads((work / "experiments.json").read_bytes())
        result = {
            "format": "ocs.safe-push.check/1",
            "profile": "receiver-experiment/1",
            "observedAt": datetime.now(UTC).isoformat(),
            "suites": names,
            "tests": result.testsRun,
            "skipped": len(result.skipped),
            "experiments": experiments,
            "receiver": "native git receive-pack",
            "status": "pass",
        }
        with tempfile.NamedTemporaryFile(dir=a.report.parent, delete=False) as f:
            f.write(json.dumps(result, indent=2).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(f.name, a.report)
    print(
        "Safe Push checked and read back",
        len(experiments),
        "real Git experiments.",
        a.report,
    )


if __name__ == "__main__":
    main()
