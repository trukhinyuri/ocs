"""Evaluate a candidate using only previously installed code and custody-owned evidence."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from authority import (
    NAME,
    OBJECT,
    ROLES,
    SHA256,
    Decision,
    authentic,
    canonical,
    digest,
    framed,
    fresh,
    immutable,
    instant,
    load,
    policy_history,
    read,
    require,
    stamp,
)
from scope import change_requirements, inventory, subject


def git(repo, *args):
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    # Only the receive-pack hook has a trusted temporary object directory.
    if os.environ.get("OCS_SAFE_RECEIVER"):
        for name in (
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_QUARANTINE_PATH",
        ):
            if name in os.environ:
                env[name] = os.environ[name]
    return (
        subprocess.check_output(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "safe.directory=" + str(Path(repo).resolve()),
                "-C",
                str(repo),
                *args,
            ],
            env=env,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        .decode()
        .strip()
    )


def readref(repo):
    return git(repo, "rev-parse", "--verify", "refs/heads/main")


def commit_binding(repo, parent, candidate):
    require(
        OBJECT.fullmatch(parent)
        and OBJECT.fullmatch(candidate)
        and len(parent) == len(candidate),
        "reference.identity",
        "invalid full object ID",
    )
    require(
        git(repo, "cat-file", "-t", candidate) == "commit",
        "reference.type",
        "expected commit",
        "rejected",
    )
    parents = git(repo, "show", "-s", "--format=%P", candidate).split()
    require(
        parents == [parent],
        "reference.parent",
        "requires one exact direct child of main",
        "rejected",
    )
    tree = git(repo, "rev-parse", candidate + "^{tree}")
    return {"parent": parent, "candidate": candidate, "tree": tree}


def state(config, pending_checkpoint=None):
    cfg = load(config)
    require(
        load(Path(config).parent / "sealed.json").get("configuration") == framed(cfg),
        "trust.installation",
        "receiver installation is incomplete or changed",
    )
    a, j, repo = (Path(cfg[k]).resolve() for k in ("authority", "journal", "repo"))
    epochs = policy_history(a, cfg["rootDigest"])
    policy = epochs[-1]
    floor = load(Path(cfg["witness"]))
    require(
        floor["epoch"] == policy["epoch"]
        and floor["policy"] == framed(policy)
        and floor["project"] == policy["project"],
        "trust.rollback",
        "epoch differs from the independent checkpoint",
    )
    tip = readref(repo)
    base = git(repo, "merge-base", floor["branchFloor"], tip)
    require(
        base == floor["branchFloor"],
        "trust.rollback",
        "published ref is behind the independent checkpoint",
    )
    if floor["branchFloor"] != policy["genesis"]:
        proof = load(j / "committed" / (floor["branchFloor"] + ".json"))
        require(
            framed(proof) == floor["receiptDigest"],
            "trust.rollback",
            "pinned external receipt differs",
        )
    else:
        require(
            floor["receiptDigest"] == cfg["genesisDigest"],
            "trust.rollback",
            "genesis witness disagrees",
        )
    for file in sorted((a / "checkpoints").glob("*.json")):
        approvals = load(file)
        record = approvals["guardian"]["payload"]
        epoch = record["epoch"]
        require(
            type(epoch) is int and 0 <= epoch < len(epochs),
            "trust.checkpoint",
            "invalid checkpoint epoch",
        )
        previous = epochs[epoch]
        statement = {k: v for k, v in record.items() if k != "role"}
        require(
            file.stem == framed(statement)
            and statement["project"] == cfg["project"]
            and statement["policy"] == framed(previous),
            "trust.checkpoint",
            "changed checkpoint",
        )
        for role in ("guardian", "independent"):
            require(
                authentic(approvals[role], previous["keys"][role], "trust.checkpoint")
                == {**statement, "role": role},
                "trust.checkpoint",
                "checkpoint not jointly authenticated",
            )
        if (
            pending_checkpoint is not None
            and approvals == pending_checkpoint
            and statement["priorFloor"] == floor["branchFloor"]
        ):
            continue
        require(
            git(repo, "merge-base", statement["tip"], floor["branchFloor"])
            == statement["tip"],
            "trust.rollback",
            "external witness precedes a retained authenticated branch checkpoint",
        )
    require(
        cfg["genesis"] == policy["genesis"],
        "trust.genesis",
        "receiver and policy disagree",
    )
    return cfg, a, j, repo, policy


def get_parent(cfg, authority, journal, parent):
    genesis = load(authority / "genesis.json")
    require(
        framed(genesis) == cfg["genesisDigest"]
        and genesis["candidate"] == cfg["genesis"],
        "trust.genesis",
        "enrollment differs from external anchor",
        "rejected",
    )
    if parent == cfg["genesis"]:
        return genesis
    epochs = policy_history(authority, cfg["rootDigest"])
    repo = Path(cfg["repo"])
    tip, expected, nearest = parent, None, None
    while tip != cfg["genesis"]:
        envelope = load(journal / "signatures" / (tip + ".json"))
        epoch = envelope["payload"]["epoch"]
        require(
            type(epoch) is int and 0 <= epoch < len(epochs),
            "audit.epoch",
            "unknown parent epoch",
        )
        root = epochs[epoch]
        receipt = authentic(envelope, root["keys"]["publisher"], "audit.parent")
        require(
            receipt == load(journal / "committed" / (tip + ".json"))
            and receipt["candidate"] == tip
            and receipt["project"] == cfg["project"]
            and receipt["profile"] == root["profile"]
            and receipt["policy"] == framed(root)
            and receipt["verifiedProof"]["verdict"] == "accepted"
            and commit_binding(repo, receipt["parent"], tip)["tree"] == receipt["tree"]
            and (expected is None or expected == framed(receipt)),
            "audit.parent",
            "parent state differs from its authenticated Git/evidence history",
            "rejected",
        )
        if nearest is None:
            nearest = receipt
        tip, expected = receipt["parent"], receipt["previousReceipt"]
    require(
        expected == framed(genesis),
        "audit.parent",
        "unanchored parent receipt",
        "rejected",
    )
    return nearest


def run_adapter(authority, methods, name, args, timeout=90):
    require(name in methods, "evidence.method", "no enrolled method for " + str(name))
    registered = methods[name]
    sha = registered["sha256"] if isinstance(registered, dict) else registered
    if (authority / "broker.json").is_file():
        from method_worker import remote_method

        return remote_method(authority, name, sha, args, timeout)
    require(
        not os.environ.get("OCS_NATIVE_METHODS_REQUIRED"),
        "isolation.unavailable",
        "separately administered native evaluator is not enrolled",
    )
    data = read(authority / "methods" / (sha + ".py"), 4 * 1024 * 1024)
    require(
        digest(data) == sha,
        "evidence.method",
        "independently installed method changed",
        "rejected",
    )
    return execute_method(data, name, args, timeout)


def execute_method(data, name, args, timeout=90):
    """Run bytes already matched to a protected method or to the fixed self-test."""
    with tempfile.TemporaryDirectory(prefix="ocs-checker-") as td:
        script = Path(td) / "method.py"
        script.write_bytes(data)
        require(
            sys.platform == "linux" and shutil.which("bwrap", path=os.defpath),
            "isolation.unavailable",
            "no enrolled isolated method runtime on this platform",
        )
        command = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/bin",
            "/bin",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/inputs",
            "--ro-bind",
            str(script),
            "/method.py",
        ]
        operands = dict(args)
        for field in ("repo", "evidence", "artifact", "counterexample"):
            if field in args:
                destination = "/inputs/" + field
                command += ["--ro-bind", str(Path(args[field]).resolve()), destination]
                operands[field] = destination
        quarantine = []
        if (
            "repo" in args
            and os.environ.get("OCS_SAFE_RECEIVER")
            and os.environ.get("GIT_QUARANTINE_PATH")
        ):
            objects = Path(args["repo"]).resolve() / "objects"
            incoming = Path(os.environ["GIT_QUARANTINE_PATH"]).resolve()
            require(
                incoming.parent == objects and incoming.is_dir(),
                "evidence.quarantine",
                "unknown temporary object store",
            )
            quarantine = [
                "--setenv",
                "GIT_OBJECT_DIRECTORY",
                "/inputs/repo/objects/" + incoming.name,
                "--setenv",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "/inputs/repo/objects",
            ]
        command += [
            "--chdir",
            "/tmp",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "LC_ALL",
            "C",
            *quarantine,
            "/usr/bin/python3",
            "-I",
            "/method.py",
        ]

        def limit_worker():
            import resource

            resource.setrlimit(
                resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024)
            )
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))

        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.run(
                command,
                check=False,
                input=canonical(operands),
                stdout=out,
                stderr=err,
                timeout=timeout,
                preexec_fn=limit_worker,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
            out.seek(0)
            output = out.read(16 * 1024 * 1024 + 1)
    require(
        proc.returncode == 0,
        "evidence.method",
        "independent method did not produce a verified result: " + name,
    )
    require(len(output) <= 16 * 1024 * 1024, "evidence.method", "oversized output")
    from authority import pairs

    result = json.loads(output, object_pairs_hook=pairs)
    if isinstance(result, dict) and result.get("verdict") == "refuted":
        candidate = args.get("subject", {}).get("revision") or args.get(
            "context", {}
        ).get("candidate")
        require(
            result.get("candidate") == candidate
            and SHA256.fullmatch(result.get("evidenceSha256", ""))
            and NAME.fullmatch(result.get("criterion", "")),
            "evidence.method",
            "invalid machine refutation",
        )
        raise Decision(
            "evidence.method/" + result["criterion"],
            "enrolled "
            + name
            + " observed a counterexample, evidence "
            + result["evidenceSha256"],
            "rejected",
        )
    return result


def observe(authority, repo, policy, name, folder, ident):
    target = policy["targets"][name]
    if target["adapter"] == "ocs-dossier/1":
        from qualification import inspect_dossier

        public = authority / "observers" / (target["observerSha256"] + ".pem")
        require(
            digest(read(public)) == target["observerSha256"],
            "evidence.observer",
            "observer public key differs from enrollment",
            "rejected",
        )
        evidence = inspect_dossier(
            folder / "dossier",
            folder / "enrollment.json",
            public,
            repo,
            policy["assurancePin"],
            ident,
        )
        require(
            evidence.get("targetConditionSha256") == target["conditions"],
            "qualification.conditions",
            "signed experiment differs from the pre-enrolled target and workload",
        )
    else:
        evidence = run_adapter(
            authority,
            policy["adapters"],
            target["adapter"],
            {
                "repo": str(repo),
                "subject": ident,
                "target": name,
                "conditions": target["conditions"],
                "evidence": str(folder),
            },
        )
    require(
        isinstance(evidence, dict)
        and SHA256.fullmatch(evidence["reportSha256"])
        and isinstance(evidence["claims"], dict)
        and evidence["claims"]
        and isinstance(evidence["metrics"], dict)
        and evidence["metrics"],
        "qualification.full",
        "empty or malformed subject evidence",
    )
    require(
        instant(evidence["expiresAt"]) > time.time(),
        "qualification.current",
        "expired target",
    )
    return evidence


def compare_cells(old, new):
    from decimal import Decimal, InvalidOperation

    pending, adverse = [], []
    for key, before in old.items():
        if key not in new:
            pending.append(
                Decision("metrics.missing/" + key, "registered cell unavailable")
            )
            continue
        after = new[key]
        if (
            before["direction"] not in ("min", "max")
            or before["direction"] != after["direction"]
            or before["condition"] != after["condition"]
        ):
            pending.append(
                Decision(
                    "metrics.condition/" + key, "incomparable direction or experiment"
                )
            )
            continue
        try:
            x, y = Decimal(before["value"]), Decimal(after["value"])
        except (TypeError, InvalidOperation):
            pending.append(Decision("metrics.number/" + key, "invalid measurement"))
            continue
        if not (x.is_finite() and y.is_finite()):
            pending.append(Decision("metrics.number/" + key, "nonfinite measurement"))
            continue
        worse = y > x if before["direction"] == "min" else y < x
        if worse:
            adverse.append(
                {
                    "id": key,
                    "old": str(x),
                    "new": str(y),
                    "direction": before["direction"],
                    "condition": before["condition"],
                }
            )
    if adverse:
        disproved = adverse[0]
        err = Decision(
            "metrics.regression/" + disproved["id"],
            disproved["new"] + " is worse than " + disproved["old"],
            "rejected",
        )
        err.cells = adverse
        raise err
    if pending:
        raise pending[0]


def bundle_inventory(directory):
    entries = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "evidence.object", "unsealed linked evidence")
        if path.is_file():
            entries[path.relative_to(directory).as_posix()] = digest(
                read(path, 64 * 1024 * 1024)
            )
    return entries


def target_attempts(
    authority, journal, repo, policy, target, ident, tree, previous, single=None
):
    folder = authority / "evidence" / ident["revision"] / target
    entries = (
        [single]
        if single is not None
        else sorted(folder.iterdir())
        if folder.is_dir()
        else []
    )
    require(
        entries,
        "qualification.missing/" + target,
        "no registered evidence for exact commit",
    )
    best, claims, reports, gaps, expiry = {}, None, [], set(), None
    prior = {
        k.removeprefix(target + "/"): v
        for k, v in previous["metrics"].items()
        if k.startswith(target + "/")
    }
    issues, live = [], 0
    for entry in entries:
        require(
            entry.is_dir() and not entry.is_symlink() and NAME.fullmatch(entry.name),
            "evidence.registry",
            "unrecognized trial entry",
        )
        try:
            archive = (
                authority
                / "acquisitions"
                / ident["revision"]
                / target
                / (entry.name + ".json")
            )
            stored = load(archive) if single is None and archive.is_file() else {}
            result = stored.get("verified")
            historical = (
                result is not None
                and instant(result["expiresAt"]) <= time.time()
                and stored.get("policy") == framed(policy)
                and stored.get("input") == entry.name
            )
            if historical:
                require(
                    framed(bundle_inventory(entry)) == entry.name,
                    "evidence.history",
                    "previously authenticated observation bytes changed",
                    "rejected",
                )
            else:
                result = observe(authority, repo, policy, target, entry, ident)
                live += 1
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ) as exc:
            issues.append(exc)
            continue
        seq = result["reportSha256"]
        metrics = result["metrics"]
        try:
            compare_cells(prior, metrics)
        except Decision as exc:
            if exc.outcome == "rejected" and exc.criterion.startswith(
                "metrics.regression/"
            ):
                veto = {
                    "project": policy["project"],
                    "target": target,
                    "condition": policy["targets"][target]["conditions"],
                    "tree": tree,
                    "report": seq,
                    "criterion": exc.criterion,
                    "reason": str(exc),
                    "cells": exc.cells,
                }
                immutable(
                    journal / "adverse" / tree / (framed(veto) + ".json"),
                    canonical(veto),
                )
            issues.append(exc)
            continue
        checks = result["claims"]
        require(
            claims is None or claims == checks,
            "qualification.trials",
            "inconsistent obligation sets",
        )
        claims = checks
        require(
            not best or set(best) == set(metrics),
            "metrics.trials",
            "trial contains a different population",
        )
        for key, value in metrics.items():
            if key in best:
                incumbent = best[key]
                require(
                    incumbent["direction"] == value["direction"]
                    and incumbent["condition"] == value["condition"],
                    "metrics.condition/" + key,
                    "registered trials have inconsistent conditions",
                )
                from decimal import Decimal

                x, y = Decimal(incumbent["value"]), Decimal(value["value"])
                if x <= y if value["direction"] == "min" else x >= y:
                    continue
            best[key] = value
        gaps.update(result.get("metricGaps", []))
        reports.append(seq)
        bound = instant(result["expiresAt"])
        if not historical:
            expiry = bound if expiry is None else min(bound, expiry)
    if issues:
        raise next(
            (e for e in issues if getattr(e, "outcome", None) == "rejected"), issues[0]
        )
    require(
        live > 0, "qualification.current/" + target, "no fresh verified observation"
    )
    return claims, best, sorted(reports), sorted(gaps), expiry


def evaluate_targets(cfg, authority, journal, repo, policy, ident, tree, previous):
    for root in (authority, journal):
        veto_dir = root / "adverse" / tree
        for path in sorted(veto_dir.glob("*.json")):
            veto = load(path)
            raise Decision(
                "metrics.prior-regression",
                "retained unfavorable trial: " + veto["reason"],
                "rejected",
            )
    qualified, cells, reports, gaps, expiry = {}, {}, {}, [], []
    for target in sorted(policy["targets"]):
        claims, metrics, src, missing, until = target_attempts(
            authority, journal, repo, policy, target, ident, tree, previous
        )
        for key, value in claims.items():
            qualified[target + "/" + key] = value
        for key, value in metrics.items():
            cells[target + "/" + key] = value
        reports[target] = src
        gaps.extend(target + "/" + item for item in missing)
        expiry.append(until)
    require(
        not gaps,
        "metrics.unmeasured",
        "missing or incomparable required cells: " + ", ".join(gaps[:12]),
    )
    return qualified, cells, reports, min(expiry)


def review_context(policy, binding, ident, plan, reports):
    return {
        "project": policy["project"],
        "profile": policy["profile"],
        "epoch": policy["epoch"],
        "policy": framed(policy),
        **binding,
        "sourceSha256": ident["treeSha256"],
        "changeSha256": framed(plan),
        "targetReports": reports,
    }


def valid_findings(authority, folder, policy, role, context, plan, now):
    criterion = "review." + role
    signed = authentic(load(folder / (role + ".json")), policy["keys"][role], criterion)
    require(
        set(signed)
        in (
            {"format", "role", "context", "issuedAt", "expiresAt", "findings"},
            {
                "format",
                "role",
                "context",
                "issuedAt",
                "expiresAt",
                "findings",
                "supersedes",
            },
        )
        and signed["format"] == "ocs.safe-push.review/1"
        and signed["role"] == role
        and signed["context"] == context,
        criterion,
        "review is for a different transition",
        "rejected",
    )
    fresh(signed["issuedAt"], signed["expiresAt"], now, policy["lifetimeSeconds"])
    needs = {k: v for k, v in plan["requirements"].items() if v["ownerRole"] == role}
    require(
        set(signed["findings"]) == set(needs),
        criterion,
        "missing or extraneous disposition",
    )
    for key, need in needs.items():
        sha = signed["findings"][key]
        require(
            isinstance(sha, str) and SHA256.fullmatch(sha),
            criterion,
            "invalid artifact digest",
        )
        raw = read(folder / "findings" / (sha + ".json"))
        require(digest(raw) == sha, criterion, "review material changed", "rejected")
        detail = load(folder / "findings" / (sha + ".json"))
        require(
            detail.get("requirement") == need["digest"]
            and detail.get("candidate") == context["candidate"]
            and detail.get("conclusion") == "satisfied"
            and detail.get("unresolved") == []
            and isinstance(detail.get("counterevidence"), list)
            and all(
                isinstance(detail.get(k), str) and detail[k].strip()
                for k in ("method", "domain", "falsifier")
            )
            and all(
                isinstance(detail.get(k), list)
                and detail[k]
                and all(isinstance(v, str) and v.strip() for v in detail[k])
                for k in ("sources", "observations")
            ),
            criterion + "/" + key,
            "claim-specific evidence or outstanding findings",
        )
        facets = detail.get("facets")
        require(
            isinstance(facets, dict) and set(facets) == set(need["evidence"]),
            criterion + "/" + key,
            "missing required evidence facets",
        )
        registered = {s for hashes in context["targetReports"].values() for s in hashes}
        for label, sha in facets.items():
            require(
                isinstance(sha, str) and SHA256.fullmatch(sha),
                criterion,
                "invalid evidence reference",
            )
            file = folder / "materials" / (sha + ".json")
            require(
                digest(read(file)) == sha,
                criterion,
                "review source differs from its digest",
                "rejected",
            )
            evidence = load(file)
            require(
                evidence.get("facet") == label
                and evidence.get("criterion") == need["digest"]
                and evidence.get("paths") == need["paths"]
                and evidence.get("claims") == need["claims"]
                and isinstance(evidence.get("finding"), str)
                and evidence["finding"].strip()
                and isinstance(evidence.get("sources"), list)
                and evidence["sources"],
                criterion + "/" + label,
                "evidence does not cover the enrolled question, objects and claims",
            )
            for source in evidence["sources"]:
                require(
                    isinstance(source, str) and SHA256.fullmatch(source),
                    criterion,
                    "invalid research source binding",
                )
                if source not in registered and source != context["sourceSha256"]:
                    require(
                        digest(read(folder / "materials" / source)) == source,
                        criterion,
                        "missing primary evidence",
                    )
    return signed


def proof_material(authority, folder, repo, policy, context, plan):
    requested = {
        k: v for k, v in plan["requirements"].items() if v["kind"] == "portable-proof"
    }
    require(
        not requested or (folder / "proofs.json").is_file(),
        "proof.missing",
        "missing incumbent replay for " + ", ".join(sorted(requested)),
    )
    material = load(folder / "proofs.json") if requested else {}
    require(
        set(material) == set(requested),
        "proof.missing",
        "missing an independently checked refinement",
    )
    for key, criterion in requested.items():
        advice = material[key]
        require(
            set(advice) == {"method", "artifact"}
            and isinstance(advice["artifact"], str)
            and SHA256.fullmatch(advice["artifact"]),
            "proof.binding",
            "invalid proof request",
        )
        sha = advice["artifact"]
        method = policy["predicateCheckers"].get(advice["method"])
        require(
            isinstance(method, dict)
            and key in method["requirements"]
            and all(
                any(
                    p == prefix or p.startswith(prefix.rstrip("/") + "/")
                    for prefix in method["pathPrefixes"]
                )
                for p in criterion.get("paths", [])
            ),
            "proof.purpose/" + key,
            "replay method is not enrolled for this obligation and subject",
        )
        artifact = folder / "proofs" / sha
        require(
            digest(read(artifact)) == sha,
            "proof.binding",
            "proof artifact changed",
            "rejected",
        )
        arguments = {
            "repo": str(repo),
            "context": context,
            "criterion": criterion,
            "artifact": str(artifact),
        }
        if "counterexampleSha256" in criterion:
            arguments["counterexample"] = str(
                authority / "counterexamples" / criterion["counterexampleSha256"]
            )
        result = run_adapter(
            authority, policy["predicateCheckers"], advice["method"], arguments
        )
        require(
            result
            == {
                "status": "accepted",
                "criterion": criterion["digest"],
                "context": framed(context),
                "artifact": sha,
            },
            "proof.refinement/" + key,
            "old checker did not verify the exact claim",
        )
    return material


def active_holds(authority, cfg, repo, binding, resolved):
    holds = {}
    directory = authority / "alerts"
    if not directory.exists():
        return holds
    epochs = policy_history(authority, cfg["rootDigest"])
    ancestors = set(git(repo, "rev-list", binding["parent"]).splitlines())
    trees = set(git(repo, "log", "--format=%T", binding["parent"]).splitlines())
    for path in sorted(directory.glob("*.json")):
        envelope = load(path)
        epoch = envelope["payload"]["epoch"]
        require(
            type(epoch) is int and 0 <= epoch < len(epochs),
            "counterexample.custody",
            "unknown epoch",
        )
        msg = authentic(
            envelope, epochs[epoch]["keys"]["guardian"], "counterexample.custody"
        )
        require(
            msg.get("format") == "ocs.safe-push.counterexample/1"
            and msg.get("project") == cfg["project"]
            and msg.get("id") == path.stem
            and SHA256.fullmatch(msg["evidence"])
            and digest(read(authority / "counterexamples" / msg["evidence"]))
            == msg["evidence"],
            "counterexample.binding",
            "unbound report",
        )
        if (
            msg.get("scope")
            in {"all", binding["candidate"], binding["tree"]} | ancestors | trees
        ) and resolved.get(path.stem) != framed(envelope):
            holds[path.stem] = framed(envelope)
    return holds


def resolve_holds(folder, policy, holds, context, proof_rows):
    if not holds:
        return
    resolutions = load(folder / "resolutions.json")
    require(
        set(resolutions) == set(holds),
        "counterexample.open",
        "open confirmed counterexamples",
    )
    for key, resolution in resolutions.items():
        data = {
            "format": "ocs.safe-push.remediation/1",
            "context": context,
            "id": key,
            "alert": holds[key],
            "regressionEvidence": resolution["regressionEvidence"],
            "replay": resolution["replay"],
        }
        require(
            isinstance(data["regressionEvidence"], str)
            and SHA256.fullmatch(data["regressionEvidence"])
            and digest(
                read(folder / "findings" / (data["regressionEvidence"] + ".json"))
            )
            == data["regressionEvidence"]
            and data["replay"] == "remediation/" + key
            and data["replay"] in proof_rows,
            "counterexample.open",
            "repair lacks independent replay",
        )
        for role in ROLES:
            require(
                authentic(
                    resolution[role], policy["keys"][role], "counterexample." + role
                )
                == {**data, "role": role},
                "counterexample.open",
                "remediation is not jointly approved",
            )


def prepare(config, parent, candidate, want_context=False, *, published=None):
    cfg, authority, journal, repo, policy = state(config)
    actual = readref(repo)
    if published is None:
        require(
            actual == parent, "reference.parent", "canonical parent moved", "rejected"
        )
    else:
        require(
            actual == candidate
            and published["candidate"] == candidate
            and published["parent"] == parent,
            "audit.binding",
            "readback is for another committed transition",
        )
        origin = policy_history(authority, cfg["rootDigest"])[published["epoch"]]
        semantics = lambda p: {k: v for k, v in p.items() if k not in ("epoch", "keys")}
        require(
            origin["epoch"] == policy["epoch"]
            or semantics(origin) == semantics(policy),
            "audit.policy",
            "the previously qualified release needs a new adjudication under evolved semantics",
        )
        policy = origin
    binding = commit_binding(repo, parent, candidate)
    previous = get_parent(cfg, authority, journal, parent)
    old = inventory(repo, parent)
    new = inventory(repo, candidate)
    ident = subject(repo, candidate, new)
    plan = change_requirements(repo, parent, candidate, old, new)
    veto = authority / "review-adverse" / binding["tree"]
    require(
        not veto.is_dir() or not any(veto.iterdir()),
        "review.counterexample",
        "confirmed or unresolved contrary finding on identical source bytes",
        "rejected",
    )
    resolved = previous.get("resolvedCounterexamples", {})
    holds = active_holds(authority, cfg, repo, binding, resolved)
    for key, claim in holds.items():
        alert = load(authority / "alerts" / (key + ".json"))["payload"]
        criterion = {
            "kind": "portable-proof",
            "id": "remediation/" + key,
            "ownerRole": "verifier",
            "criterion": "Reproduce the original counterexample and establish recovery under the previous scope.",
            "alert": claim,
            "parent": parent,
            "candidate": candidate,
            "counterexampleSha256": alert["evidence"],
            "paths": sorted(
                row["path"]
                for row in plan["changes"]
                if row["before"] is None
                or row["after"] is None
                or row["before"]["type"] != "tree"
                or row["after"]["type"] != "tree"
            ),
        }
        plan["requirements"][criterion["id"]] = {
            **criterion,
            "digest": framed(criterion),
        }
    if want_context == "scope":
        return {"subject": ident, "change": plan, "binding": binding}
    claims, metrics, reports, until = evaluate_targets(
        cfg, authority, journal, repo, policy, ident, binding["tree"], previous
    )
    if policy["profile"] == "ocs-release/1":
        full = plan["requirements"]["qualification.full"]
        expected = {
            key + "@" + level
            for key, levels in full["levels"].items()
            for level in levels
        }
        for target in (
            k for k, v in policy["targets"].items() if v["adapter"] == "ocs-dossier/1"
        ):
            require(
                all(target + "/" + key in claims for key in expected),
                "qualification.full",
                "a required OCS claim-level witness is missing",
            )
    context = review_context(policy, binding, ident, plan, reports)
    if want_context:
        return {
            "context": context,
            "requirements": plan["requirements"],
            "policyChange": plan["policyChange"],
        }
    require(
        not policy["requiredOpen"],
        "scope.open",
        "unresolved mandatory claims: " + ", ".join(policy["requiredOpen"]),
    )
    reviews_home = authority / "reviews" / candidate
    selection = (
        load(reviews_home / "current.json")
        if published is None
        else {"bundle": published["evidenceManifest"]["reviewBundle"]}
    )
    require(
        isinstance(selection.get("bundle"), str)
        and SHA256.fullmatch(selection["bundle"]),
        "review.selection",
        "unrecognized review bundle",
    )
    folder = reviews_home / "runs" / selection["bundle"]
    review_files = bundle_inventory(folder)
    require(
        framed(review_files) == selection["bundle"],
        "review.selection",
        "review materials changed",
        "rejected",
    )
    now = time.time()
    reviews = {
        role: valid_findings(authority, folder, policy, role, context, plan, now)
        for role in ("domain", "independent")
    }
    material = proof_material(authority, folder, repo, policy, context, plan)
    if plan["policyChange"]:
        approval = authentic(
            load(folder / "guardian.json"),
            policy["keys"]["guardian"],
            "policy.transition",
        )
        require(
            approval
            == {
                "format": "ocs.safe-push.guardian/1",
                "context": context,
                "proofs": framed(material),
            }
            and material,
            "policy.transition",
            "protection change lacks proof under the incumbent policy",
        )
    resolve_holds(folder, policy, holds, context, material)
    from proof import certify

    facts = {
        "singleParent": True,
        "inventory": True,
        "qualification": True,
        "domainReview": True,
        "independentReview": True,
        "fresh": True,
        "noCounterexample": True,
        "policyContinuity": True,
        "priorEvidence": True,
    }
    packet = {
        "previous_claims": previous["claims"],
        "current_claims": claims,
        "previous_metrics": previous["metrics"],
        "current_metrics": metrics,
        "parent": parent,
        "actual_parent": parent if published else actual,
        "candidate": candidate,
        "tree": binding["tree"],
        "facts": facts,
    }
    if published is None:
        cert = certify(**packet)
    else:
        from proof import replay_certificate

        cert = replay_certificate(published["verifiedProof"], **packet)
    require(
        isinstance(cert, dict)
        and cert.get("verdict") == "accepted"
        and cert.get("status") == "pass",
        "proof.receiver",
        "missing accepted concrete decision certificate",
    )
    valid_until = min(
        until, *(instant(review["expiresAt"]) for review in reviews.values())
    )
    require(
        time.time() < valid_until,
        "evidence.freshness",
        "evidence expired during replay",
    )
    return {
        "format": "ocs.safe-push.prepared/1",
        **context,
        "previousReceipt": framed(previous),
        "claims": claims,
        "metrics": metrics,
        "verifiedProof": cert,
        "reviews": {k: framed(v) for k, v in reviews.items()},
        "evidenceManifest": {
            "reviewBundle": selection["bundle"],
            "portableReplays": material,
            "guardian": review_files.get("guardian.json"),
            "remediations": review_files.get("resolutions.json"),
        },
        "resolvedCounterexamples": {**resolved, **holds},
        "expiresEpoch": valid_until,
        "preparedAt": stamp(),
    }
