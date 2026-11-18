"""Exercise the published OCS qualification adapter on two independently enrolled, real dossiers."""

import argparse
import json
import shutil
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from authority import ROLES, canonical, digest, immutable
from operator_cli import import_object, install, stage_files
from qualification import inspect_dossier
from test_receiver import client_command, ensure_key


def trial(dossier, enrollment, destination):
    destination.mkdir(parents=True)
    shutil.copytree(dossier.resolve(), destination / "dossier")
    shutil.copy2(enrollment, destination / "enrollment.json")


def rowset(base, candidate):
    worse, incomparable, improved, equal = [], [], [], []
    for key, x in base.items():
        y = candidate.get(key)
        if (
            not y
            or x["condition"] != y["condition"]
            or x["direction"] != y["direction"]
        ):
            incomparable.append(key)
            continue
        a, b = Decimal(x["value"]), Decimal(y["value"])
        if a == b:
            equal.append(key)
        elif b > a if x["direction"] == "min" else b < a:
            worse.append({"cell": key, "baseline": x["value"], "candidate": y["value"]})
        else:
            improved.append(key)
    return {
        "worse": worse,
        "incomparable": incomparable,
        "improved": improved,
        "equal": equal,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in (
        "repo",
        "base-dossier",
        "candidate-dossier",
        "base-enrollment",
        "candidate-enrollment",
        "observer",
        "work",
    ):
        p.add_argument("--" + n, type=Path, required=True)
    p.add_argument("--initialize", action="store_true")
    p.add_argument("--config", type=Path)
    p.add_argument("--url")
    args = p.parse_args()
    w = args.work.resolve()
    w.mkdir(parents=True, exist_ok=True)
    inputs = []
    for f, e in (
        (args.base_dossier, args.base_enrollment),
        (args.candidate_dossier, args.candidate_enrollment),
    ):
        report = json.loads((f / "report.json").read_bytes())
        facts = inspect_dossier(
            f.resolve(),
            e.resolve(),
            args.observer.resolve(),
            args.repo.resolve(),
            report["acceptedVerifier"],
            report["subject"],
        )
        inputs.append((report, facts))
    (old, oldfacts), (new, newfacts) = inputs
    workbase = old["subject"]["revision"]
    candidate = new["subject"]["revision"]
    comparison = rowset(oldfacts["metrics"], newfacts["metrics"])
    assert comparison["worse"] or comparison["incomparable"], (
        "these measured dossiers do not supply the requested adverse control"
    )
    if args.config is None:
        secrets = w / "technical-test-identities"
        secrets.mkdir(mode=0o700)
        keys = {k: ensure_key(secrets, k) for k in (*ROLES, "publisher")}
        name = "kubernetes"
        policy = {
            "format": "ocs.safe-push.policy/1",
            "profile": "ocs-release/1",
            "project": "ocs-live-receiver-check",
            "epoch": 0,
            "genesis": workbase,
            "assurancePin": old["acceptedVerifier"],
            "keys": keys,
            "adapters": {},
            "predicateCheckers": {},
            "targets": {
                name: {
                    "adapter": "ocs-dossier/1",
                    "conditions": oldfacts["targetConditionSha256"],
                    "observerSha256": digest(args.observer.read_bytes()),
                }
            },
            "lifetimeSeconds": 86400,
            "receiveTimeoutSeconds": 180,
            "receiverCost": None,
            "requiredOpen": [
                "independently enrolled operating authority for the permanent project",
                "critical-use and universal claims require additional evidence as described in the proposal",
            ],
        }
        immutable(w / "policy.json", canonical(policy))
        trial(args.base_dossier, args.base_enrollment, w / "bootstrap" / name)
        config = install(
            w / "receiver",
            args.repo,
            w / "policy.json",
            w / "bootstrap",
            [args.observer],
            [],
            secrets / "publisher.key",
            None,
        )
    else:
        config = args.config.resolve()
    if args.initialize:
        print(config)
        return
    site = w / "next-trial"
    trial(args.candidate_dossier, args.candidate_enrollment, site)
    import_object(config, args.repo, candidate)
    stage_files(config, "evidence", candidate, site, "kubernetes")
    url = (
        args.url or f"ext::{sys.executable} -I {HERE / 'receiver.py'} serve {config} %S"
    )

    def run(*cmd):
        return subprocess.run(
            client_command(
                args.repo.resolve(), ("-c", "protocol.ext.allow=always", *cmd)
            ),
            check=False,
            capture_output=True,
            text=True,
        )

    before = run("ls-remote", url, "refs/heads/main")
    before.check_returncode()
    push = run("push", url, candidate + ":refs/heads/main")
    after = run("ls-remote", url, "refs/heads/main")
    after.check_returncode()
    assert (
        push.returncode
        and before.stdout == after.stdout
        and before.stdout.split()[0] == workbase
    ), (push, before, after)
    assert "metrics." in push.stderr, push.stderr
    outcome = {
        "profile": "ocs-release/1",
        "custody": "isolated acceptance identities",
        "parent": workbase,
        "candidate": candidate,
        "acceptedOldSuite": [
            old["acceptedEvidenceSlots"],
            new["acceptedEvidenceSlots"],
        ],
        "qualifiedCells": len(oldfacts["metrics"]),
        "comparison": comparison,
        "gitExit": push.returncode,
        "refBefore": before.stdout.split()[0],
        "refAfter": after.stdout.split()[0],
        "diagnostic": push.stderr[:1800],
        "targetCondition": oldfacts["targetConditionSha256"],
        "historicalScopeLimits": oldfacts["coverageLimits"],
    }
    immutable(w / "live-verdict.json", canonical(outcome))
    print(
        "Real OCS receiver rejected",
        len(comparison["worse"]),
        "worse protected observations. main",
        workbase,
    )


if __name__ == "__main__":
    main()
