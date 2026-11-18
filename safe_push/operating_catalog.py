#!/usr/bin/env python3
"""Build and replay an offline preparation catalogue for the permanent OCS owner."""

import argparse
import base64
import ctypes
import errno
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import bundle_inventory, compare_cells
from authority import (
    ROLES,
    Decision,
    authentic,
    canonical,
    digest,
    framed,
    fsync_dir,
    load,
    public_der,
    read,
    require,
    validate_policy,
)
from evolution import evolution_scope
from forge import _rule_detail, bootstrap_rules, enrollment, hold_rule, oid
from forge_apps import admin_parent, assemble, epoch, positive, read_pins
from forge_refusals import compare as compare_observations
from forge_stage import clean_env, clean_object_view, git_value
from local_install import copy_regular
from qualification import _inspect as inspect_historical
from scope import inventory, subject

HASH = re.compile(r"[a-f0-9]{64}")
ROLES_ALL = (*ROLES, "publisher")
INPUT = "ocs.operating-catalog-inputs/1"
CATALOG = "ocs.operating-preparation/1"
PUBLIC_CUSTODY = (
    "custody.json",
    "custody-proposal.json",
    "owner-selection.json",
    "possession-challenge.json",
    *(r + ".pub" for r in ROLES_ALL),
    *(r + "-possession.sig" for r in ROLES_ALL),
)
HOST_FILES = (
    "hold-response.json",
    "integrity-live.json",
    "writer-live.json",
    "bootstrap-overlap.json",
    "repository.json",
    "reported-measured-failure.json",
    "genuine-failure-preview.json",
)
HISTORY_TABLES = ("adverse", "acquisitions", "refusals", "readbacks")
PATHS = (
    "custody",
    "appPins",
    "forgePolicy",
    "hostedObservations",
    "releaseReceipts",
    "evidenceAuthority",
    "gitObjects",
)


def checked(ok, reason):
    require(ok, "operating.catalog", reason, "rejected")


def nonempty_dir(path):
    checked(
        path.is_dir() and not path.is_symlink(),
        "missing or linked public input directory",
    )
    return path


def files_digest(directory):
    return framed(bundle_inventory(nonempty_dir(directory)))


def public_assets(paths):
    c = paths["custody"]
    host = paths["hostedObservations"]
    r = paths["releaseReceipts"]
    return {
        **{"custody/" + n: c / n for n in PUBLIC_CUSTODY},
        **{"host/" + n: host / n for n in HOST_FILES},
        "host/app-pins.json": paths["appPins"],
        "host/forge-policy.json": paths["forgePolicy"],
        "history/root.json": r / "root.json",
        "history/genesis.json": r / "genesis.json",
    }


def table_sources(paths):
    a, r = paths["evidenceAuthority"], paths["releaseReceipts"]
    return {
        "adverse": a / "adverse",
        "acquisitions": a / "acquisitions",
        "refusals": r / "refusals",
        "readbacks": r / "readbacks",
    }


def selection(paths, custody_sha):
    checked(
        set(paths) == set(PATHS) and HASH.fullmatch(custody_sha),
        "select all public sources and the independently accepted custody digest",
    )
    assets = {k: digest(read(f)) for k, f in public_assets(paths).items()}
    original = load(paths["custody"] / "custody.json")
    checked(
        framed(original) == custody_sha and original.get("project") == "ocs",
        "wrong independent project or custody selection",
    )
    tables = {k: files_digest(d) for k, d in table_sources(paths).items()}
    return {
        "format": INPUT,
        "project": "ocs",
        "custodySha256": custody_sha,
        "paths": {k: str(v.resolve()) for k, v in paths.items()},
        "publicAssetSha256": assets,
        "historicalTableSha256": tables,
    }


def checked_selection(cfg):
    checked(
        isinstance(cfg, dict)
        and set(cfg) - {"firstCostCandidate"}
        == {
            "format",
            "project",
            "custodySha256",
            "paths",
            "publicAssetSha256",
            "historicalTableSha256",
        }
        and cfg["format"] == INPUT
        and cfg["project"] == "ocs"
        and set(cfg["paths"]) == set(PATHS)
        and all(
            isinstance(v, str) and Path(v).is_absolute() for v in cfg["paths"].values()
        )
        and set(cfg["historicalTableSha256"]) == set(HISTORY_TABLES)
        and all(
            isinstance(v, str) and HASH.fullmatch(v)
            for v in (
                cfg["custodySha256"],
                *cfg["publicAssetSha256"].values(),
                *cfg["historicalTableSha256"].values(),
            )
        ),
        "invalid prior public input enrollment",
    )
    if "firstCostCandidate" in cfg:
        v = cfg["firstCostCandidate"]
        checked(
            isinstance(v, dict)
            and set(v) == {"revision", "methodSha256", "testSha256"}
            and oid(v["revision"])
            and all(
                isinstance(v[k], str) and HASH.fullmatch(v[k])
                for k in ("methodSha256", "testSha256")
            ),
            "an optional checker selection needs its immutable code and control identities",
        )
    paths = {k: Path(v) for k, v in cfg["paths"].items()}
    checked(
        set(cfg["publicAssetSha256"]) == set(public_assets(paths)),
        "missing public input family",
    )
    return paths


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def custody(archive, expected, *, check_local_uids=False):
    location = archive / "custody"
    authority = load(location / "custody.json")
    sel = load(location / "owner-selection.json")
    challenge = load(location / "possession-challenge.json")
    checked(
        authority == load(location / "custody-proposal.json")
        and framed(authority) == expected
        and authority["format"] == "ocs.operating-custody/1"
        and authority["project"] == "ocs"
        and type(authority["humanOwner"]["humanOwnerCount"]) is int
        and authority["humanOwner"]["humanOwnerCount"] == 1
        and positive(authority["humanOwner"]["id"])
        and sel["format"] == "ocs.operating-custody-selection/1"
        and sel["publicKeysSha256"] == expected
        and sel["humanOwner"] == authority["humanOwner"]["login"]
        and sel["githubOwnerId"] == authority["humanOwner"]["id"]
        and sel["effect"] == "initial registration of public keys only"
        and sel["canonicalPublicationAuthorized"] is False
        and epoch(sel["selectedAt"]) > 0,
        "sole owner selected a different set or authorized a different scope",
    )
    checked(
        set(challenge) == {"format", "project", "proposal", "nonce", "purpose"}
        and challenge["format"] == "ocs.key-possession-test/1"
        and challenge["project"] == "ocs"
        and challenge["proposal"] == expected
        and HASH.fullmatch(challenge["nonce"])
        and challenge["purpose"] == "assert possession only",
        "foreign or widened possession statement",
    )
    roles = authority["nativeRoles"]
    checked(set(roles) == set(ROLES_ALL), "missing operating role")
    keys = {}
    for role in ROLES_ALL:
        decl = roles[role]
        raw = read(location / (role + ".pub"), 4096)
        pem = raw.decode("ascii")
        checked(
            decl["publicKeyPemSha256"] == digest(raw)
            and positive(decl["uid"])
            and decl["privateStateMode"] == "0700"
            and decl["privateKeyMode"] == "0600"
            and decl["purpose"].strip(),
            "unverified or unconfined operating role " + role,
        )
        if check_local_uids:
            checked(
                pwd.getpwnam(decl["unixRole"]).pw_uid == decl["uid"],
                "local authority account differs from selected UID",
            )
        signature = read(location / (role + "-possession.sig"), 1024)
        checked(
            authentic(
                {
                    "payload": challenge,
                    "signature": base64.b64encode(signature).decode(),
                },
                pem,
                "operating.possession",
            )
            == challenge,
            "incorrect role proof",
        )
        keys[role] = pem
    identities = [r["uid"] for r in roles.values()] + [
        r["custodianUid"] for r in authority["hostedApps"].values()
    ]
    checked(
        len(set(identities)) == len(identities) == 6
        and len({public_der(p) for p in keys.values()}) == 4,
        "distinct technical roles share a credential or operating UID",
    )
    return authority, keys


def hosted(archive, authority):
    place = archive / "host"
    pins = load(place / "app-pins.json")
    p = enrollment(load(place / "forge-policy.json"))
    roles = pins["roles"]
    target = authority["referenceBasis"]
    human = authority["humanOwner"]
    checked(
        assemble(roles["reporter"], roles["publisher"], pins["project"]) == pins
        and pins["project"] == p["project"] == "ocs"
        and pins["ownerId"] == human["id"] == p["ownerId"]
        and pins["repository"] == authority["repository"] == p["repository"]
        and pins["repository"].split("/")[0].casefold() == human["login"].casefold()
        and pins["repositoryId"] == authority["repositoryId"] == p["repositoryId"]
        and p["format"] == "ocs.safe-push.forge/2"
        and p["expectedVisibility"] == pins["repositoryVisibility"] == "public"
        and p["mode"] == "mirror"
        and isinstance(p["bootstrap"], dict),
        "hosted scope or public App enrollment differs",
    )
    for name, actual in roles.items():
        recorded = authority["hostedApps"][name]
        checked(
            {
                k: actual[k]
                for k in (
                    "appId",
                    "installationId",
                    "custodianUid",
                    "publicKeySha256",
                    "permissions",
                )
            }
            == recorded,
            "App installation or custody changed for " + name,
        )
    b = p["bootstrap"]
    one, two = bootstrap_rules(p)
    checked(
        b["genesis"] == target["genesis"]
        and p["checkAppId"] == roles["reporter"]["appId"]
        and p["checkInstallationId"] == roles["reporter"]["installationId"]
        and p["publisherAppId"] == roles["publisher"]["appId"]
        and b["publisherInstallationId"] == roles["publisher"]["installationId"],
        "incorrect ruleset actors or historical seed",
    )
    for path, scope, id_key in (
        ("hold-response.json", hold_rule(), "holdRulesetId"),
        ("integrity-live.json", one, "integrityRulesetId"),
        ("writer-live.json", two, "writerRulesetId"),
    ):
        _rule_detail(load(place / path), scope, b[id_key], p)
    overlap = load(place / "bootstrap-overlap.json")
    repo = load(place / "repository.json")
    checked(
        overlap["repositoryId"] == repo["id"] == p["repositoryId"]
        and repo["ownerId"] == p["ownerId"]
        and repo["full_name"] == p["repository"]
        and repo["default_branch"]
        == overlap["defaultBranch"]
        == b["stagingRef"].removeprefix("refs/heads/")
        and overlap["visibility"] == repo["visibility"] == "public"
        and not repo["private"]
        and all(
            overlap[k] == b[k]
            for k in (
                "stagingRef",
                "stagingCommit",
                "genesis",
                "holdRulesetId",
                "integrityRulesetId",
                "writerRulesetId",
            )
        )
        and overlap["holdDisabledAt"] is None
        and overlap["closureRulesetId"] is None
        and positive(overlap["holdVersion"])
        and len(overlap["guardVersions"]) == 2
        and all(positive(x) for x in overlap["guardVersions"]),
        "observed hosted guard versions, owner or target differ",
    )
    return {
        "status": "historical-active-overlap",
        "repositoryId": p["repositoryId"],
        "repository": p["repository"],
        "observedDefault": overlap["defaultBranch"],
        "stagingRef": b["stagingRef"],
        "stagingCommit": b["stagingCommit"],
        "hold": b["holdRulesetId"],
        "integrity": b["integrityRulesetId"],
        "writer": b["writerRulesetId"],
        "holdVersion": overlap["holdVersion"],
        "permanentVersions": overlap["guardVersions"],
        "issuerPinsSha256": framed(pins),
        "forgePolicySha256": framed(p),
        "canonicalAuthority": "separate future readback required",
    }


def collect_evidence(paths, selection_data, archive):
    old = load(paths["releaseReceipts"] / "root.json")
    seed = load(paths["releaseReceipts"] / "genesis.json")
    validate_policy(old)
    checked(
        load(paths["evidenceAuthority"] / "root.json") == old
        and load(paths["evidenceAuthority"] / "genesis.json") == seed,
        "receiver and operator copies of historical policy or seed disagree",
    )
    for name, path in public_assets(paths).items():
        raw = read(path)
        checked(
            digest(raw) == selection_data["publicAssetSha256"][name],
            "changed selected public record " + name,
        )
        put(archive / name, raw)
    for name, source in table_sources(paths).items():
        copy_regular(source, archive / "history" / name)
        checked(
            files_digest(archive / "history" / name)
            == selection_data["historicalTableSha256"][name],
            "a previously enrolled " + name + " record disappeared or changed",
        )
    prior = paths["evidenceAuthority"]
    for kind in ("bootstrap", "evidence"):
        copy_regular(prior / kind, archive / kind)
    for target in old["targets"].values():
        key = target["observerSha256"]
        checked(
            isinstance(key, str) and HASH.fullmatch(key),
            "historical target lacks a sealed observer",
        )
        if not (archive / "observers" / (key + ".pem")).exists():
            raw = read(prior / "observers" / (key + ".pem"), 32768)
            checked(digest(raw) == key, "wrong registered public observer")
            put(archive / "observers" / (key + ".pem"), raw)
    revisions = sorted(
        {
            old["genesis"],
            old["assurancePin"],
            *(f.name for f in (archive / "evidence").iterdir()),
            *(
                [selection_data["firstCostCandidate"]["revision"]]
                if selection_data.get("firstCostCandidate")
                else []
            ),
        }
    )
    checked(all(oid(r) for r in revisions), "unknown Git history member")
    objects = paths["gitObjects"].resolve(strict=True)
    checked(
        objects.name == "objects"
        and not any(
            (objects / "info" / n).exists() for n in ("alternates", "http-alternates")
        ),
        "select a self-contained Git object database independently of candidates",
    )
    kind = "sha1" if len(old["genesis"]) == 40 else "sha256"
    with (
        clean_object_view(objects, kind) as repo,
        (archive / "source.pack").open("xb") as out,
    ):
        subprocess.run(
            [
                "/usr/bin/git",
                "--no-replace-objects",
                "--git-dir",
                repo,
                "pack-objects",
                "--revs",
                "--stdout",
                "--no-reuse-delta",
                "--no-reuse-object",
                "--threads=1",
                "--compression=6",
                "--quiet",
            ],
            input=("\n".join(revisions) + "\n").encode("ascii"),
            stdout=out,
            stderr=subprocess.PIPE,
            env=clean_env(repo.parent),
            check=True,
            timeout=120,
        )
    return kind


def historic(repo, old, target, root, observer, revision):
    dossier = root / "dossier"
    report = load(dossier / "report.json")
    inv = inventory(repo, revision)
    ident = subject(repo, revision, inv)
    checked(
        ident == report["subject"]
        and old["targets"][target]["adapter"] == "ocs-dossier/1",
        "historical target subject differs",
    )
    # A retained negative result remains relevant after deployment freshness expires.
    # Revalidate its original signed interval, without converting it to present availability.
    result = inspect_historical(
        dossier,
        root / "enrollment.json",
        observer,
        repo,
        old["assurancePin"],
        ident,
        epoch(report["finishedAt"]) + 1,
    )
    checked(
        result["acceptedVerifier"] == old["assurancePin"]
        and not result["metricGaps"]
        and result["targetConditionSha256"] == old["targets"][target]["conditions"],
        "historical observation lacks original comparison conditions",
    )
    return inv, result


def historical_results(archive, repo, authority):
    h = archive / "history"
    old = load(h / "root.json")
    seed = load(h / "genesis.json")
    basis = authority["referenceBasis"]
    validate_policy(old)
    checked(
        old["profile"] == seed["profile"] == "ocs-release/1"
        and seed["project"] == old["project"]
        and seed["format"] == "ocs.safe-push.genesis/1"
        and seed["policy"] == framed(old)
        and framed(seed) == basis["genesisReceiptSha256"]
        and seed["candidate"] == old["genesis"] == basis["genesis"]
        and seed["targetReports"] == basis["originalQualification"]
        and set(seed["targetReports"]) == set(old["targets"]),
        "historical released seed is different from the sole owner's source enrollment",
    )
    previous = {}
    claims = {}
    metrics = {}
    limits = {}
    for target, t in old["targets"].items():
        key = t["observerSha256"]
        observer = archive / "observers" / (key + ".pem")
        checked(digest(read(observer, 32768)) == key, "substituted public observer")
        inv, base = historic(
            repo, old, target, archive / "bootstrap" / target, observer, old["genesis"]
        )
        checked(
            base["reportSha256"] == seed["targetReports"][target]
            and seed["subject"] == base["subject"]
            and seed["tree"] == git_value(repo, "rev-parse", old["genesis"] + "^{tree}")
            and seed["wholeTreeSha256"] == framed(inv),
            "old public report or source object differs",
        )
        previous[target] = base
        claims.update({target + "/" + k: v for k, v in base["claims"].items()})
        metrics.update({target + "/" + k: v for k, v in base["metrics"].items()})
        limits[target] = base["coverageLimits"]
    checked(
        claims == seed["claims"]
        and metrics == seed["metrics"]
        and limits == seed["coverageLimits"]
        and len(claims) == basis["claimLevels"]
        and len(claims) >= 394
        and len(metrics) == basis["comparisonCells"]
        and len(metrics) >= 364,
        "original meaning, metric direction/value/condition, coverage limits or denominator changed",
    )
    adverse = {}
    for f in sorted((h / "adverse").glob("*/*.json")):
        row = load(f)
        tree = f.parent.name
        checked(
            oid(tree)
            and row["tree"] == tree
            and f.stem == framed(row)
            and row["project"] == old["project"]
            and row["target"] in previous
            and row["condition"] == old["targets"][row["target"]]["conditions"],
            "invalid retained prior adverse evidence",
        )
        address = (tree, row["target"], row["report"])
        checked(address not in adverse, "ambiguous old adverse receipt")
        adverse[address] = (f, row)
    trial_items = {}
    compared = {}
    for f in sorted((h / "acquisitions").glob("*/*/*.json")):
        row = load(f)
        candidate = f.parent.parent.name
        target = f.parent.name
        actual = archive / "evidence" / candidate / target / f.stem
        checked(
            oid(candidate)
            and target in previous
            and f.stem == framed(bundle_inventory(actual)) == row["input"]
            and row["target"] == target
            and row["candidate"] == candidate
            and row["parent"] == old["genesis"]
            and row["policy"] == framed(old)
            and row["outcome"] == "rejected",
            "lost or unbound acquisition; extend this profile before classifying another kind of trial",
        )
        checked(
            git_value(repo, "show", "-s", "--format=%P", candidate) == old["genesis"]
            and git_value(repo, "rev-parse", candidate + "^{tree}") == row["tree"],
            "adverse commit, tree or parent differs",
        )
        _, observed = historic(
            repo,
            old,
            target,
            actual,
            archive / "observers" / (old["targets"][target]["observerSha256"] + ".pem"),
            candidate,
        )
        base = previous[target]
        checked(
            all(observed["claims"].get(k) == v for k, v in base["claims"].items())
            and observed["metricProfileSha256"] == base["metricProfileSha256"],
            "old qualification meaning or metric profile changed",
        )
        address = (row["tree"], target, observed["reportSha256"])
        checked(
            address in adverse and address not in compared,
            "missing independently retained tree veto",
        )
        veto_path, veto = adverse[address]
        try:
            original_order = {
                k.removeprefix(target + "/"): v
                for k, v in seed["metrics"].items()
                if k.startswith(target + "/")
            }
            compare_cells(original_order, observed["metrics"])
        except Decision as e:
            checked(
                e.outcome == "rejected"
                and e.criterion == veto["criterion"]
                and canonical(sorted(e.cells, key=lambda x: x["id"]))
                == canonical(sorted(veto["cells"], key=lambda x: x["id"])),
                "changed retained counterexample, measurement or condition",
            )
        else:
            raise ValueError(
                "previous adverse trial was silently reclassified as passing"
            )
        counts = compare_observations(base["metrics"], observed["metrics"])
        compared[address] = {
            "candidate": candidate,
            "tree": row["tree"],
            "target": target,
            "input": f.stem,
            "report": observed["reportSha256"],
            "vetoFile": veto_path.relative_to(archive).as_posix(),
            "inheritance": "content tree",
            "claimLevels": len(base["claims"]),
            **counts,
        }
        trial_items[(candidate, target, f.stem)] = compared[address]
    offered = {
        (rev.name, t.name, i.name)
        for rev in (archive / "evidence").iterdir()
        for t in rev.iterdir()
        for i in t.iterdir()
    }
    checked(
        offered == set(trial_items) and set(adverse) == set(compared) and compared,
        "old contrary inventory is incomplete",
    )
    earlier = sorted((h / "refusals").glob("*.json"))
    outs = sorted((h / "readbacks").glob("*.json"))
    checked(
        [p.name for p in earlier] == [p.name for p in outs],
        "missing paired actual ref readback",
    )
    rejected = set()
    for f in earlier:
        record = load(f)
        readback = load(h / "readbacks" / f.name)
        update = record["updates"].strip().split()
        checked(
            len(update) == 3
            and update[0] == old["genesis"]
            and update[2] == "refs/heads/main"
            and record["criterion"] == "metrics.prior-regression"
            and record["outcome"] == "rejected"
            and readback["before"] == readback["after"] == old["genesis"]
            and any(v["candidate"] == update[1] for v in compared.values()),
            "recorded rejected candidate or unchanged canonical readback differs",
        )
        rejected.add(update[1])
    checked(
        rejected == {v["candidate"] for v in compared.values()},
        "a collected adverse attempt lost its on-ref refusal",
    )
    checked(
        set(bundle_inventory(h / "adverse"))
        == {p.relative_to(h / "adverse").as_posix() for p, _ in adverse.values()}
        and len(bundle_inventory(h / "acquisitions")) == len(trial_items)
        and len(bundle_inventory(h / "refusals")) == len(earlier)
        and len(bundle_inventory(h / "readbacks")) == len(outs),
        "unexpected unclassified retained evidence",
    )
    return (
        old,
        seed,
        sorted(compared.values(), key=lambda a: (a["tree"], a["target"], a["input"])),
    )


def compare_history(archive):
    failure = load(archive / "host/reported-measured-failure.json")
    selected = load(archive / "host/app-pins.json")
    return failure, selected["roles"]["reporter"]


def checker_plan(request, repo):
    chosen = request.get("firstCostCandidate")
    pin = None
    if chosen:
        checked(
            set(chosen) == {"revision", "methodSha256", "testSha256"}
            and oid(chosen["revision"])
            and HASH.fullmatch(chosen["methodSha256"])
            and HASH.fullmatch(chosen["testSha256"]),
            "invalid first-cost candidate selection",
        )
        for path, k in (
            ("safe_push/cost_acquisition.py", "methodSha256"),
            ("safe_push/test_cost_acquisition.py", "testSha256"),
        ):
            raw = subprocess.check_output(
                [
                    "/usr/bin/git",
                    "--no-replace-objects",
                    "--git-dir",
                    repo,
                    "cat-file",
                    "blob",
                    chosen["revision"] + ":" + path,
                ],
                env=clean_env(repo.parent),
                stderr=subprocess.PIPE,
                timeout=30,
            )
            checked(
                digest(raw) == chosen[k],
                "first-cost method or original falsification tests changed",
            )
        pin = chosen
    return {
        "status": "awaiting-independent-enrollment",
        "name": "first-cost",
        "candidate": pin,
        "requirements": ["evolution/receiver-cost"],
        "pathPrefixes": ["policy/receiverCost"],
        "beforeFreezing": [
            "Select the exact method digest and incumbent source inventory independently of the candidate.",
            "Replay a real positive on the declared disposable contour and the changed-counter, foreign receipt, platform and candidate refusals. Retain inputs, outputs and checker identities.",
            "Have the selected authority approve this narrow method in the initial permanent root before using it to introduce a cost baseline.",
        ],
        "operatingCostContext": "independently observed executionContextSha256 in the actual dedicated native publisher. Verify publisher UID, no-new-privileges, empty effective/bounding capabilities and private loopback-only network as well as the separate platformSha256.",
        "permanentSuccessfulCostObservation": None,
    }


def formulate(archive, request, repo, *, local_uids=False):
    gov, keys = custody(archive, request["custodySha256"], check_local_uids=local_uids)
    hosting = hosted(archive, gov)
    old, seed, vetoes = historical_results(archive, repo, gov)
    failure, reporter = compare_history(archive)
    known = {row["candidate"]: row for row in vetoes}
    checked(
        failure.get("result") == "verified-failure-readback"
        and failure.get("candidate") in known
        and failure["tree"] == known[failure["candidate"]]["tree"]
        and positive(failure["checkRunId"])
        and failure["appId"] == reporter["appId"]
        and failure["installationId"] == reporter["installationId"]
        and failure["repositoryId"] == gov["repositoryId"]
        and failure["ownerId"] == gov["humanOwner"]["id"]
        and failure["project"] == "ocs"
        and failure["measurementProject"] == old["project"]
        and failure["parent"] == old["genesis"]
        and failure["refBefore"] == failure["refAfter"]
        and failure["reporterPinSha256"] == framed(reporter)
        and failure["externalId"]
        == "refused:"
        + framed({"evidence": failure["evidenceSha256"], "reporter": framed(reporter)})
        and HASH.fullmatch(failure["evidenceSha256"]),
        "reported contrary observation is foreign or missing",
    )
    preview = load(archive / "host/genuine-failure-preview.json")
    body = preview["body"]
    measurement = known[failure["candidate"]]
    checked(
        all(
            preview[k] == failure[k]
            for k in (
                "evidenceSha256",
                "externalId",
                "project",
                "measurementProject",
                "repositoryId",
                "ownerId",
                "appId",
                "installationId",
                "reporterPinSha256",
                "candidate",
                "parent",
                "tree",
                "validBefore",
            )
        )
        and framed(body) == preview["bodySha256"]
        and body["conclusion"] == "failure"
        and body["status"] == "completed"
        and body["external_id"] == failure["externalId"]
        and body["head_sha"] == failure["candidate"]
        and body["output"]["summary"].startswith(
            f"{measurement['worse']} of {measurement['compared']} comparable measurements worsened "
        ),
        "retained hosted failure preview is inconsistent with independently measured cells",
    )
    fields = {
        k: v for k, v in old.items() if k not in ("format", "epoch", "project", "keys")
    }
    # An initial root for a different project needs a separate owner election. Retain
    # each predecessor hold while that election, purpose grants and scoped reviews are outstanding.
    fields.update(project="ocs", keys=keys)
    prospective = {**fields, "format": old["format"], "epoch": 0}
    validate_policy(prospective)
    pending_closures = {}
    for hold in fields["requiredOpen"]:
        # Query the deployed evolution calculus about a hypothetical removal. The draft
        # itself keeps the exact old string; this computation cannot advance an epoch.
        change = {
            **prospective,
            "epoch": 1,
            "requiredOpen": [r for r in fields["requiredOpen"] if r != hold],
        }
        pending_closures[hold] = {
            "status": "retained-open",
            "priorPurposes": evolution_scope(prospective, change)["purposes"],
            "closureEvidence": None,
            "approval": None,
        }

    tested = checker_plan(request, repo)
    proposal = {
        "format": "ocs.operating-policy-inputs/1",
        "status": "preparation-only",
        "selectedFields": fields,
        "pendingPurposeGrant": tested,
        "prospectiveOpenDispositions": pending_closures,
        "oldProject": old["project"],
        "priorPolicySha256": framed(old),
        "retainedAdverseRegistry": "archive/history/adverse",
        "authorization": None,
    }
    catalog = {
        "format": CATALOG,
        "project": "ocs",
        "effect": "local preparation and offline verification only",
        "custody": {
            "status": "selected-and-possession-verified",
            "scope": "public key custody only",
            "registrySha256": request["custodySha256"],
            "humanOwners": [gov["humanOwner"]],
            "technicalRoles": gov["nativeRoles"],
            "hostedAppRoles": gov["hostedApps"],
            "commonAdministration": "One human owner. Machine replay has no authority to supply missing human judgment.",
        },
        "hosting": hosting,
        "basis": {
            "measurementProject": old["project"],
            "priorPolicySha256": framed(old),
            "seedSha256": framed(seed),
            "parent": old["genesis"],
            "tree": seed["tree"],
            "subject": seed["subject"],
            "wholeTreeSha256": seed["wholeTreeSha256"],
            "fullTargetReports": seed["targetReports"],
            "claimLevels": len(seed["claims"]),
            "claimMeaningsSha256": framed(seed["claims"]),
            "comparisonCells": len(seed["metrics"]),
            "comparatorsSha256": framed(seed["metrics"]),
            "exactRows": "archive/history/genesis.json",
            "targets": old["targets"],
            "coverageLimits": seed["coverageLimits"],
            "historicalFreshnessEndsAt": seed["expiresEpoch"],
        },
        "adverse": vetoes,
        "hostedAdverse": {
            "checkRunId": failure["checkRunId"],
            "candidate": failure["candidate"],
            "tree": failure["tree"],
            "receiptSha256": framed(failure),
            "reportedBy": failure["appId"],
        },
        "requiredOpen": list(old["requiredOpen"]),
        "coverageLimits": seed["coverageLimits"],
        "prerequisites": {
            "ownerKeySelection": "verified for four technical UIDs and one owner only",
            "permanentRootElection": "open: explicit approval of final scope, original meanings, all retained vetoes, method bytes and purpose grants",
            "operatingAuthorityClosure": "open: install/read back the separately approved root and restricted receiver; preserve original requiredOpen until its exact authorized disposition",
            "costEvolution": "open: enroll original purpose checker and its falsification controls before the irreversible initial policy",
            "otherOpenDispositions": "open: a future change needs its own pre-enrolled narrow purpose and genuine independent proof; absent proof preserves the original hold",
            "firstSuccessfulCost": "open: acquire the actually permitted full pre-CAS operation with its old decisions, measured counters, platform and both authenticated election quorums",
            "humanReview": "open per candidate: sole owner decisions and independently checkable technical evidence have distinct meanings; no independent human attestation inferred",
            "globalCriticalUse": "open as originally recorded; application-specific hazard, empirical, portability and universal claims retain their original limits",
            "candidateAcceptance": "open: current full evidence, nonregression, costs, actual reviews and release receiver replay",
        },
        "firstCostMethod": tested,
        "publishedCanonicalRef": None,
        "authorization": None,
    }
    return {"catalog.json": catalog, "operating-policy-inputs.json": proposal}


def compatible(previous, current):
    checked(
        previous.get("format") == current["format"] == CATALOG
        and previous["project"] == current["project"]
        and previous["custody"]["registrySha256"]
        == current["custody"]["registrySha256"]
        and previous["basis"] == current["basis"]
        and set(previous["requiredOpen"]) <= set(current["requiredOpen"])
        and previous["coverageLimits"] == current["coverageLimits"]
        and all(
            current["prerequisites"].get(k) == v
            for k, v in previous["prerequisites"].items()
        )
        and previous["hosting"] == current["hosting"]
        and previous["hostedAdverse"] == current["hostedAdverse"],
        "previous owner, baseline, open obligations or contrary receipt were lost",
    )
    prior = {(r["tree"], r["report"], r["input"]): r for r in previous["adverse"]}
    now = {(r["tree"], r["report"], r["input"]): r for r in current["adverse"]}
    checked(
        all(now.get(k) == v for k, v in prior.items()),
        "previous adverse tree, condition or counterexample changed",
    )
    if previous["firstCostMethod"]["candidate"]:
        checked(
            previous["firstCostMethod"] == current["firstCostMethod"],
            "previous pinned candidate checker disappeared",
        )


def open_history(archive, request, *, local_uids=False):
    checked(
        {p.name for p in archive.iterdir()}
        == {
            "history",
            "host",
            "custody",
            "bootstrap",
            "evidence",
            "observers",
            "source.pack",
        },
        "unknown or missing archive member",
    )
    for directory in ("host", "custody"):
        approved = {
            k.partition("/")[2]
            for k in request["publicAssetSha256"]
            if k.startswith(directory + "/")
        }
        checked(
            set(bundle_inventory(archive / directory)) == approved,
            "unknown or missing registered custody/host observation",
        )
    checked(
        {p.name for p in (archive / "history").iterdir()}
        == {"root.json", "genesis.json", *HISTORY_TABLES},
        "unknown historical receipt family",
    )
    for name, sha in request["publicAssetSha256"].items():
        checked(
            digest(read(archive / name)) == sha,
            "public input differed from its original pin: " + name,
        )
    for name, sha in request["historicalTableSha256"].items():
        checked(
            files_digest(archive / "history" / name) == sha,
            "retained historical inventory changed: " + name,
        )
    policy = load(archive / "history/root.json")
    kind = "sha1" if len(policy["genesis"]) == 40 else "sha256"
    with tempfile.TemporaryDirectory(prefix="ocs-public-catalog-replay-") as d:
        repo = Path(d) / "objects.git"
        env = clean_env(d)
        subprocess.run(
            [
                "/usr/bin/git",
                "init",
                "--quiet",
                "--template=",
                "--bare",
                "--initial-branch=unpublished",
                "--object-format=" + kind,
                repo,
            ],
            env=env,
            check=True,
            timeout=15,
        )
        with (archive / "source.pack").open("rb") as pack:
            subprocess.run(
                [
                    "/usr/bin/git",
                    "--git-dir",
                    repo,
                    "index-pack",
                    "--strict",
                    "--stdin",
                ],
                stdin=pack,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
                check=True,
                timeout=120,
            )
        checked(
            not git_value(repo, "for-each-ref", "--format=%(refname)"),
            "offline verification cannot publish a ref",
        )
        exact = {
            policy["genesis"],
            policy["assurancePin"],
            *(p.name for p in (archive / "evidence").iterdir()),
        }
        if request.get("firstCostCandidate"):
            exact.add(request["firstCostCandidate"]["revision"])
        checked(all(oid(v) for v in exact), "bad source anchor")
        closure = set(
            git_value(
                repo, "rev-list", "--objects", "--no-object-names", *sorted(exact)
            ).splitlines()
        )
        all_objects = set(
            git_value(
                repo, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"
            ).splitlines()
        )
        checked(
            closure == all_objects,
            "Git archive contains unknown objects outside the selected closures",
        )
        checked(
            {p.name for p in (archive / "bootstrap").iterdir()}
            == set(policy["targets"])
            and {p.name for p in (archive / "observers").iterdir()}
            == {v["observerSha256"] + ".pem" for v in policy["targets"].values()},
            "unexpected bootstrap or observer",
        )
        for trial in (
            *sorted((archive / "bootstrap").iterdir()),
            *sorted((archive / "evidence").glob("*/*/*")),
        ):
            checked(
                {p.name for p in trial.iterdir()} == {"dossier", "enrollment.json"},
                "unregistered attachment alongside signed qualification",
            )
        return formulate(archive, request, repo, local_uids=local_uids)


def verify(bundle, expected, *, previous=None):
    nonempty_dir(bundle)
    checked(
        {p.name for p in bundle.iterdir()}
        == {
            "archive",
            "selection.json",
            "inventory.json",
            "catalog.json",
            "operating-policy-inputs.json",
        },
        "unclassified preparation output",
    )
    proof = load(bundle / "selection.json")
    checked(framed(proof) == expected, "wrong independent public-input selection")
    checked_selection(proof)
    manifest = load(bundle / "inventory.json")
    seen = bundle_inventory(bundle)
    seen.pop("inventory.json")
    checked(manifest == seen, "preparation archive lost, changed or added a member")
    answers = open_history(bundle / "archive", proof)
    for name, value in answers.items():
        checked(
            canonical(load(bundle / name)) == canonical(value),
            "derived preparation no longer follows its evidence: " + name,
        )
    if previous is not None:
        compatible(previous, answers["catalog.json"])
    return {
        "format": CATALOG,
        "status": "verified-preparation-only",
        "selectionSha256": expected,
        "catalogSha256": framed(answers["catalog.json"]),
        "inventorySha256": framed(manifest),
        "claimLevels": answers["catalog.json"]["basis"]["claimLevels"],
        "comparisonCells": answers["catalog.json"]["basis"]["comparisonCells"],
        "retainedAdverseTrees": len(
            {r["tree"] for r in answers["catalog.json"]["adverse"]}
        ),
        "requiredOpen": answers["catalog.json"]["requiredOpen"],
        "canonicalAuthorization": False,
    }


def install_directory_once(source, destination):
    # renameat2 preserves an existing directory even if it is empty, including a competing publisher.
    libc = ctypes.CDLL(None, use_errno=True)
    procedure = libc.renameat2
    procedure.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    procedure.restype = ctypes.c_int
    if procedure(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            return False
        raise OSError(code, os.strerror(code))
    return True


def prepare(inputs, expected, out, *, previous=None, admin=True):
    request = read_pins(inputs.absolute()) if admin else load(inputs)
    checked(
        framed(request) == expected,
        "selected input descriptor differs from operator digest",
    )
    paths = checked_selection(request)
    out = out.absolute()
    if admin:
        checked(os.geteuid() == 0, "custodian prepares the sealed local archive")
        admin_parent(out.parent)
        # The published custody, App pins and forge policy are separately administered.
        admin_parent(paths["custody"])
        for name in PUBLIC_CUSTODY:
            facts = (paths["custody"] / name).lstat()
            checked(
                stat.S_ISREG(facts.st_mode)
                and facts.st_uid == 0
                and facts.st_nlink == 1
                and not facts.st_mode & 0o022,
                "public owner-selection or key-possession proof lacks administrative custody",
            )
        read_pins(paths["custody"] / "custody.json")
        read_pins(paths["appPins"])
        read_pins(paths["forgePolicy"])
    checked(
        not any(out.is_relative_to(v.resolve()) for v in paths.values()),
        "choose a separate permanent archive location",
    )
    if out.exists() or out.is_symlink():
        return verify(out, expected, previous=previous)
    with tempfile.TemporaryDirectory(
        prefix=".operating-prepare-", dir=out.parent
    ) as temp:
        stage = Path(temp) / "bundle"
        stage.mkdir()
        put(stage / "selection.json", canonical(request))
        collect_evidence(paths, request, stage / "archive")
        answers = open_history(stage / "archive", request, local_uids=admin)
        if previous is not None:
            compatible(previous, answers["catalog.json"])
        for name, value in answers.items():
            put(stage / name, canonical(value))
        put(stage / "inventory.json", canonical(bundle_inventory(stage)))
        result = verify(stage, expected, previous=previous)
        for f in (stage, *stage.rglob("*")):
            if f.is_dir():
                fsync_dir(f)
                f.chmod(0o555)
            else:
                f.chmod(0o444)
        # Parent is an independently administered directory. Preserve an earlier concurrent publication.
        if not install_directory_once(stage, out):
            return verify(out, expected, previous=previous)
        fsync_dir(out.parent)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    cmd = p.add_subparsers(dest="operation", required=True)
    s = cmd.add_parser("select")
    for k in PATHS:
        flag = re.sub(r"([A-Z])", lambda a: "-" + a[1].lower(), k)
        s.add_argument("--" + flag, dest=k, type=Path, required=True)
    s.add_argument("--custody-sha256", required=True)
    s.add_argument("--first-cost-revision")
    s.add_argument("--first-cost-sha256")
    s.add_argument("--first-cost-tests-sha256")
    for op in ("prepare", "verify"):
        c = cmd.add_parser(op)
        if op == "prepare":
            c.add_argument("--inputs", type=Path, required=True)
            c.add_argument("--output", type=Path, required=True)
        else:
            c.add_argument("--bundle", type=Path, required=True)
        c.add_argument("--inputs-sha256", required=True)
        c.add_argument("--previous-bundle", type=Path)
        c.add_argument("--previous-inputs-sha256")
    args = p.parse_args()
    if args.operation == "select":
        r = selection({k: getattr(args, k) for k in PATHS}, args.custody_sha256)
        supplied = (
            args.first_cost_revision,
            args.first_cost_sha256,
            args.first_cost_tests_sha256,
        )
        if any(supplied):
            checked(
                all(supplied)
                and oid(supplied[0])
                and all(HASH.fullmatch(v) for v in supplied[1:]),
                "select an immutable commit with both checker and control-source digests",
            )
            r["firstCostCandidate"] = {
                "revision": supplied[0],
                "methodSha256": supplied[1],
                "testSha256": supplied[2],
            }
        result = r
    else:
        previous = None
        if args.previous_bundle or args.previous_inputs_sha256:
            checked(
                args.previous_bundle and args.previous_inputs_sha256,
                "select both previous complete catalogue and its independent digest",
            )
            verify(args.previous_bundle, args.previous_inputs_sha256)
            previous = load(args.previous_bundle / "catalog.json")
        if args.operation == "prepare":
            result = prepare(
                args.inputs, args.inputs_sha256, args.output, previous=previous
            )
        else:
            result = verify(args.bundle, args.inputs_sha256, previous=previous)
    if args.operation == "select":
        sys.stdout.buffer.write(canonical(result))
    else:
        print(canonical(result).decode())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
        reason = (
            str(e)
            if isinstance(e, ValueError)
            else "public enrolment, independent source or archived evidence unavailable"
        )
        print(
            json.dumps(
                {"status": "pending/preparation-unverified", "reason": reason[:480]}
            ),
            file=sys.stderr,
        )
        sys.exit(1)
