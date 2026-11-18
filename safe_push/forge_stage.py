#!/usr/bin/env python3
"""Propose, create once, and read back an explicitly selected noncanonical OCS review branch."""

import argparse
import contextlib
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import commit_binding
from authority import canonical, framed, require
from forge import (
    REPOSITORY,
    GhReadAPI,
    ReadAPI,
    _main_or_absent,
    _repository,
    _rule_detail,
    _rules,
    bootstrap_rules,
    enrollment,
    hold_rule,
    oid,
    pages,
    ref_sha,
)
from forge_apps import (
    APIClient,
    admin_parent,
    assemble,
    epoch,
    installation_session,
    read_pins,
    role_lock,
    role_receipt,
    save_private,
    secret_file,
    sha,
    stamp,
)
from qualification import _inspect as inspect_archived_execution
from scope import inventory, subject

REVIEW = re.compile(r"refs/heads/review/[a-z][a-z0-9-]{0,62}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
GUARD_TTL = 600
PARENT = "ocs.safe-push.historical-review-parent/1"
GUARD = "ocs.safe-push.review-guard-observation/1"
ACTION = "ocs.safe-push.review-transfer/1"


def selected(policy, ref):
    p = enrollment(policy)
    b = p.get("bootstrap")
    require(
        p["format"] == "ocs.safe-push.forge/2"
        and p["mode"] == "mirror"
        and p["expectedVisibility"] == "public"
        and isinstance(b, dict),
        "review.scope",
        "select an independently enrolled public guarded mirror",
    )
    require(
        isinstance(ref, str) and REVIEW.fullmatch(ref) and ref != b["stagingRef"],
        "review.destination",
        "use one separate refs/heads/review/<lower-case-slug> branch",
        "rejected",
    )
    return p


def protected_object_path(path):
    facts = path.lstat()
    require(
        facts.st_uid == 0
        and not facts.st_mode & 0o022
        and (stat.S_ISDIR(facts.st_mode) or stat.S_ISREG(facts.st_mode)),
        "review.source",
        "object source must be administrator-owned regular files and read-only to the publisher",
    )


def checked_source(source):
    source = source.absolute()
    admin_parent(source)
    require(
        ":" not in str(source) and not any(ord(c) < 32 for c in str(source)),
        "review.source",
        "invalid alternate object directory name",
    )

    def scan_error(error):
        raise error

    for folder, dirs, files in os.walk(source, followlinks=False, onerror=scan_error):
        for name in [*dirs, *files]:
            protected_object_path(Path(folder) / name)
    objects = source / "objects"
    require(
        objects.is_dir()
        and (source / "HEAD").is_file()
        and (source / "config").is_file()
        and not any(
            (objects / "info" / x).exists() for x in ("alternates", "http-alternates")
        )
        and not any((objects / "pack").glob("*.promisor")),
        "review.source",
        "require a self-contained complete administrative bare snapshot",
    )
    env = clean_env("/nonexistent")

    def setting(key):
        run = subprocess.run(
            [
                "/usr/bin/git",
                "config",
                "--no-includes",
                "--file",
                source / "config",
                "--get",
                key,
            ],
            capture_output=True,
            check=False,
            timeout=10,
            env=env,
        )
        require(
            run.returncode in (0, 1),
            "review.source",
            "cannot read administrative object format",
        )
        return run.stdout.strip().decode("ascii")

    require(
        setting("core.bare") == "true",
        "review.source",
        "source must be a bare repository",
    )
    kind = setting("extensions.objectformat") or "sha1"
    require(
        kind in ("sha1", "sha256"), "review.source", "unsupported source object format"
    )
    return objects, kind


def clean_env(home):
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_ALLOW_PROTOCOL": "https",
    }


@contextlib.contextmanager
def clean_object_view(objects, kind):
    """Never load candidate config, remotes, refs, aliases, hooks or credential helpers."""
    with tempfile.TemporaryDirectory(prefix="ocs-review-transfer-") as name:
        home = Path(name)
        repo = home / "view.git"
        subprocess.run(
            [
                "/usr/bin/git",
                "init",
                "--quiet",
                "--template=",
                "--bare",
                "--initial-branch=review-view",
                "--object-format=" + kind,
                repo,
            ],
            env=clean_env(home),
            capture_output=True,
            timeout=15,
            check=True,
        )
        (repo / "objects/info/alternates").write_text(
            str(objects) + "\n", encoding="utf-8"
        )
        yield repo


def parent_proof(
    repo, parent, verifier, dossier, independent, key, expected_report, key_hash
):
    require(
        oid(parent)
        and oid(verifier)
        and HEX.fullmatch(expected_report)
        and HEX.fullmatch(key_hash),
        "review.baseline",
        "select complete independently known source, checker, signed report and observer identities",
    )
    report = (dossier / "report.json").read_bytes()
    observer_bytes = key.read_bytes()
    require(
        sha(report) == expected_report and sha(observer_bytes) == key_hash,
        "review.baseline",
        "baseline report or observer key differs from its original enrollment",
    )
    r = json.loads(report)
    require(
        r["subject"]["revision"] == parent and r["acceptedVerifier"] == verifier,
        "review.baseline",
        "foreign historical subject",
    )
    before = inventory(repo, parent)
    ident = subject(repo, parent, before)
    require(ident == r["subject"], "review.baseline", "subject Git bytes differ")
    # This claim concerns the old witnessed observation. Present deployment availability
    # and permission to advance canonical main have separate gates.
    with tempfile.TemporaryDirectory(prefix="ocs-review-observer-") as work:
        pinned_key = Path(work) / "observer.pub"
        pinned_key.write_bytes(observer_bytes)
        attested = inspect_archived_execution(
            dossier,
            independent,
            pinned_key,
            repo,
            verifier,
            ident,
            epoch(r["finishedAt"]) + 1,
        )
    require(
        attested["reportSha256"] == expected_report
        and len(attested["claims"]) >= 394
        and not attested["metricGaps"],
        "review.baseline",
        "missing original signed full assurance scope",
    )
    return {
        "format": PARENT,
        "scope": "previously witnessed full assurance baseline for review transport",
        "parent": parent,
        "tree": git_value(repo, "rev-parse", parent + "^{tree}"),
        "subject": ident,
        "wholeTreeSha256": framed(before),
        "reportSha256": expected_report,
        "observerSha256": key_hash,
        "standReceiptSha256": attested["standReceiptSha256"],
        "verifier": verifier,
        "observedThrough": r["finishedAt"],
        "claimLevels": len(attested["claims"]),
        "metricCount": len(attested["metrics"]),
        "claimMeaningsSha256": framed(attested["claims"]),
        "metricProfileSha256": attested["metricProfileSha256"],
    }


def git_value(repo, *args):
    return (
        subprocess.check_output(
            ["/usr/bin/git", "--no-replace-objects", "--git-dir", str(repo), *args],
            env=clean_env(repo.parent),
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        .decode()
        .strip()
    )


def binding(repo, p, qualified, parent, candidate):
    b = p["bootstrap"]
    require(
        oid(parent)
        and oid(candidate)
        and parent != candidate
        and parent == b["genesis"]
        and qualified["format"] == PARENT
        and qualified["parent"] == parent
        and type(qualified["claimLevels"]) is int
        and qualified["claimLevels"] >= 394
        and all(
            isinstance(qualified[k], str) and HEX.fullmatch(qualified[k])
            for k in (
                "reportSha256",
                "observerSha256",
                "standReceiptSha256",
                "wholeTreeSha256",
            )
        ),
        "review.parent",
        "exact independently enrolled historical parent is required",
    )
    old = inventory(repo, parent)
    require(
        subject(repo, parent, old) == qualified["subject"]
        and framed(old) == qualified["wholeTreeSha256"]
        and git_value(repo, "rev-parse", parent + "^{tree}") == qualified["tree"],
        "review.parent",
        "local parent differs from the archived qualification",
    )
    ref = commit_binding(repo, parent, candidate)
    actual = inventory(repo, candidate)
    ident = subject(repo, candidate, actual)
    return {
        **ref,
        "sourceSha256": ident["treeSha256"],
        "wholeTreeSha256": framed(actual),
        "fileCount": ident["fileCount"],
        "parentTree": qualified["tree"],
        "parentReportSha256": qualified["reportSha256"],
        "parentProofSha256": framed(qualified),
    }


def rules_for(p):
    b = p["bootstrap"]
    one, two = bootstrap_rules(p)
    return {
        b["holdRulesetId"]: hold_rule(),
        b["integrityRulesetId"]: one,
        b["writerRulesetId"]: two,
    }


def observe_guards(api, p, *, admin):
    b = p["bootstrap"]
    spec = rules_for(p)
    staged = b["stagingRef"].removeprefix("refs/heads/")
    root, default = _repository(api, p, {staged, "main"})
    require(
        ref_sha(api, root, b["stagingRef"]) == b["stagingCommit"],
        "review.staging",
        "immutable staging branch changed",
    )
    groups = {i: [] for i in spec}
    for rule in pages(api, root + "/rules/branches/main"):
        rid = rule.get("ruleset_id")
        require(
            rid in groups
            and rule.get("ruleset_source_type") == "Repository"
            and rule.get("ruleset_source") == p["repository"],
            "review.guards",
            "unexpected effective canonical rule",
        )
        groups[rid].append(rule)
    effective = {}
    for rid, expected in spec.items():
        have = api.get(f"{root}/rulesets/{rid}?includes_parents=true")
        require(
            have.get("id") == rid
            and have.get("source") == p["repository"]
            and have.get("source_type") == "Repository"
            and all(
                have.get(k) == expected[k]
                for k in ("name", "target", "enforcement", "conditions")
            )
            and _rules(have.get("rules"))
            == _rules(expected["rules"])
            == _rules(groups[rid]),
            "review.guards",
            "enrolled active literal-main rules or effective rule bindings changed",
        )
        if admin or "bypass_actors" in have:
            _rule_detail(have, expected, rid, p)
        # Without administrative bypass visibility the App corroborates only the displayed
        # rule bodies. The separately authenticated, recent owner observation covers bypass.
        effective[str(rid)] = sha(_rules(groups[rid]))
    return {
        "repository": p["repository"],
        "repositoryId": p["repositoryId"],
        "ownerId": p["ownerId"],
        "visibility": "public",
        "defaultRef": "refs/heads/" + default,
        "stagingRef": b["stagingRef"],
        "stagingCommit": b["stagingCommit"],
        "main": _main_or_absent(api, root),
        "expectedRulesSha256": framed({str(k): v for k, v in spec.items()}),
        "effectiveRules": effective,
    }


def guard_record(api, p, ref, ttl=GUARD_TTL):
    selected(p, ref)
    require(
        type(ttl) is int and 30 <= ttl <= 900,
        "review.guard-window",
        "independently bound guard lifetime",
    )
    now = time.time()
    result = observe_guards(api, p, admin=True)
    require(
        result == observe_guards(api, p, admin=True) and time.time() < now + ttl,
        "review.guards",
        "administrative observations disagree",
    )
    return {
        "format": GUARD,
        "scope": "administrator readback of literal canonical guards",
        "policySha256": framed(p),
        "reviewRef": ref,
        "facts": result,
        "observedAt": stamp(now),
        "validBefore": stamp(now + ttl),
    }


def check_guard(record, p, ref, now):
    observed, until = epoch(record["observedAt"]), epoch(record["validBefore"])
    require(
        record.get("format") == GUARD
        and record.get("policySha256") == framed(p)
        and record.get("reviewRef") == ref
        and observed <= now + 5
        and now < until
        and 0 < until - observed <= 900,
        "review.guards",
        "independent administrative readback is missing, expired or foreign",
    )
    return record["facts"]


def review_oid(api, root, ref):
    require(REVIEW.fullmatch(ref), "review.destination", "invalid noncanonical ref")
    rows = api.get(root + "/git/matching-refs/" + ref.removeprefix("refs/"))
    require(
        isinstance(rows, list) and len(rows) < 4096,
        "review.ref",
        "incomplete hosted reference inventory",
    )
    found = {}
    for row in rows:
        name = row.get("ref")
        obj = row.get("object", {})
        require(
            isinstance(name, str)
            and name.startswith(ref)
            and name not in found
            and obj.get("type") == "commit"
            and oid(obj.get("sha")),
            "review.ref",
            "ambiguous or invalid hosted reference",
        )
        found[name] = obj["sha"]
    return found.get(ref)


def verify_remote_commit(api, p, local):
    root = "/repos/" + p["repository"]
    child = api.get(root + "/git/commits/" + local["candidate"])
    parent = api.get(root + "/git/commits/" + local["parent"])
    require(
        child.get("sha") == local["candidate"]
        and child.get("tree", {}).get("sha") == local["tree"]
        and [x.get("sha") for x in child.get("parents", [])] == [local["parent"]]
        and parent.get("sha") == local["parent"]
        and parent.get("tree", {}).get("sha") == local["parentTree"],
        "review.readback",
        "hosted source, tree or single parent differs from the selected object",
    )


def preflight(api, p, ref, guard, local, pins, now):
    contacts = selected(p, ref)
    roles = pins["roles"]
    who = roles["publisher"]
    require(
        assemble(roles["reporter"], who, pins["project"]) == pins
        and all(
            contacts[k] == pins[k]
            for k in ("repository", "repositoryId", "ownerId", "project")
        )
        and pins["repositoryVisibility"] == "public"
        and p["checkAppId"] == roles["reporter"]["appId"]
        and p["checkInstallationId"] == roles["reporter"]["installationId"]
        and p["publisherAppId"] == who["appId"]
        and p["bootstrap"]["publisherInstallationId"] == who["installationId"],
        "review.issuer",
        "public project or genuine publisher installation differs from the independent roots",
    )
    admin = check_guard(guard, p, ref, now)
    host = observe_guards(api, p, admin=False)
    require(
        host == admin
        and ref not in (host["defaultRef"], host["stagingRef"], "refs/heads/main"),
        "review.guards",
        "public publisher readback differs from the independent administrator",
    )
    before = review_oid(api, "/repos/" + p["repository"], ref)
    require(
        before is None or before == local["candidate"],
        "review.ref",
        "review branch already has a different object",
        "rejected",
    )
    if before:
        verify_remote_commit(api, p, local)
        root = "/repos/" + p["repository"]
        require(
            review_oid(api, root, ref) == before
            and _main_or_absent(api, root) == host["main"]
            and ref_sha(api, root, host["stagingRef"]) == host["stagingCommit"],
            "review.readback",
            "review or protected ref changed during exact Git-object verification",
        )
    check_guard(guard, p, ref, time.time())
    action = {
        "format": ACTION,
        "operation": "create-one-public-review-ref",
        "repository": p["repository"],
        "repositoryId": p["repositoryId"],
        "ownerId": p["ownerId"],
        "expectedVisibility": "public",
        "remote": "https://github.com/" + p["repository"] + ".git",
        "ref": ref,
        "expectedOld": None,
        **local,
        "mainBefore": host["main"],
        "defaultRef": host["defaultRef"],
        "enrolledStagingRef": host["stagingRef"],
        "enrolledStagingCommit": host["stagingCommit"],
        "canonicalGuardIds": {
            k: p["bootstrap"][k]
            for k in ("holdRulesetId", "integrityRulesetId", "writerRulesetId")
        },
        "publisherAppId": who["appId"],
        "publisherInstallationId": who["installationId"],
        "guardFactsSha256": framed(host),
        "policySha256": framed(p),
        "issuerPinsSha256": framed(pins),
    }
    return {
        "format": "ocs.safe-push.review-preflight/1",
        "scope": "public noncanonical review transfer",
        "result": "already-exact" if before else "proposed",
        "action": action,
        "actionSha256": framed(action),
        "guardValidBefore": guard["validBefore"],
        "canonicalAdmission": "separate",
        "main": host["main"],
    }


@contextlib.contextmanager
def memory_git_config(raw):
    fd = os.memfd_create("ocs-review-git-config", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(raw)
        os.fchmod(fd, 0o400)
        fcntl.fcntl(
            fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_SEAL,
        )
        yield fd
    finally:
        os.close(fd)


def push_once(repo, action, token):
    import base64

    require(
        isinstance(action.get("repository"), str)
        and REPOSITORY.fullmatch(action["repository"])
        and action["repository"].split("/")[1] not in (".", "..")
        and isinstance(action.get("ref"), str)
        and REVIEW.fullmatch(action["ref"])
        and action["ref"]
        not in ("refs/heads/main", action["defaultRef"], action["enrolledStagingRef"])
        and oid(action["candidate"])
        and action["expectedOld"] is None
        and action["remote"] == "https://github.com/" + action["repository"] + ".git"
        and isinstance(token, str)
        and 0 < len(token) < 4096
        and all(32 < ord(c) < 127 for c in token),
        "review.transport",
        "improper single scoped HTTPS operation",
    )
    # The curl helper reads the URL-limited header from an anonymous sealed memory
    # descriptor. No bearer or header is saved on disk, in argv or in the environment.
    header = base64.b64encode(("x-access-token:" + token).encode("ascii")).decode(
        "ascii"
    )
    config = (
        f'[http "{action["remote"]}"]\n\textraHeader = Authorization: Basic {header}\n'
    ).encode("ascii")
    with memory_git_config(config) as fd:
        directory = repo.parent
        env = clean_env(directory)
        env["GIT_CONFIG_GLOBAL"] = "/proc/self/fd/" + str(fd)
        argv = [
            "/usr/bin/git",
            "--no-replace-objects",
            "--git-dir",
            str(repo),
            "-c",
            "credential.helper=",
            "-c",
            "credential.interactive=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "push.followTags=false",
            "-c",
            "push.recurseSubmodules=no",
            "-c",
            "gc.auto=0",
            "push",
            "--porcelain",
            "--no-verify",
            "--no-follow-tags",
            "--recurse-submodules=no",
            "--force-with-lease=" + action["ref"] + ":",
            "--",
            action["remote"],
            action["candidate"] + ":" + action["ref"],
        ]
        try:
            proc = subprocess.run(
                argv,
                cwd=directory,
                env=env,
                pass_fds=(fd,),
                capture_output=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "acknowledgement-unavailable"
        if proc.returncode != 0:
            return "remote-did-not-acknowledge"
        # Porcelain reports destination scope and whether Git actually created a branch.
        statuses = [l.split(b"\t") for l in proc.stdout.splitlines() if b"\t" in l]
        if (
            len(statuses) == 1
            and len(statuses[0]) == 3
            and statuses[0][1] == (action["candidate"] + ":" + action["ref"]).encode()
        ):
            if statuses[0][0] == b"*":
                return "created"
            if statuses[0][0] == b"=":
                return "already-up-to-date"
        return "unrecognized-acknowledgement"


def dispatch(mode, custody, approved, live, writer, *, now=time.time):
    draft = live()
    if mode == "prepare":
        return draft
    action = draft["action"]
    commitment = draft["actionSha256"]
    require(
        commitment == framed(action), "review.action", "invalid exact action commitment"
    )
    if mode == "publish":
        require(
            isinstance(approved, str)
            and HEX.fullmatch(approved)
            and approved == commitment,
            "review.approval",
            "independent approval names different action bytes",
            "rejected",
        )
    else:
        require(mode == "confirm", "review.command", "unknown transfer operation")
    folder = custody / "review-transfers"
    if mode == "publish":
        folder.mkdir(mode=0o700, exist_ok=True)
    label = framed({"repositoryId": action["repositoryId"], "ref": action["ref"]})
    intent = folder / (label + ".intent.json")
    acknowledgement = folder / (label + ".ack.json")

    def current_receipt(readback, ack):
        require(
            readback["result"] == "already-exact"
            and readback["action"] == action
            and readback["actionSha256"] == commitment
            and readback["main"] == draft["main"],
            "review.confirm",
            "hosted object, canonical ref or current guard differs",
        )
        return {
            "format": "ocs.safe-push.review-readback/1",
            "scope": "authenticated noncanonical review branch only",
            "result": "verified-review-ref",
            "actionSha256": commitment,
            "ref": action["ref"],
            "observed": action["candidate"],
            "tree": action["tree"],
            "parent": action["parent"],
            "publisherAppId": action["publisherAppId"],
            "publisherInstallationId": action["publisherInstallationId"],
            "transportAcknowledgement": ack,
            "newCreationByEnrolledTransport": ack == "created",
            "mainBefore": draft["main"],
            "mainAfter": readback["main"],
            "canonicalAdmission": "separate",
            "verifiedAt": stamp(now()),
        }

    if draft["result"] == "already-exact":
        ack = "preexisting-exact/object-origin-unattributed"
        if intent.exists():
            saved = json.loads(secret_file(intent, os.geteuid()))
            require(
                saved.get("actionSha256") == commitment
                and saved.get("action") == action,
                "review.intent",
                "reserved review name belongs to a different transfer",
            )
            if acknowledgement.exists():
                previous = json.loads(secret_file(acknowledgement, os.geteuid()))
                require(
                    previous.get("actionSha256") == commitment,
                    "review.intent",
                    "unbound transport acknowledgement",
                )
                ack = previous["status"]
            else:
                ack = "submission-identity-unconfirmed"
        return current_receipt(live(), ack)
    require(mode == "publish", "review.readback", "expected review object is absent")
    require(
        not intent.exists() and not acknowledgement.exists(),
        "review.uncertain",
        "a previous attempt reserved this branch. Reconcile the actual outcome before any new authorization.",
    )
    # Waits for approval and token issuance cannot change the binding silently.
    fresh = live()
    require(
        fresh == draft and now() < epoch(fresh["guardValidBefore"]),
        "review.freshness",
        "host or object changed before the one permitted send",
    )
    save_private(
        intent,
        canonical(
            {
                "format": "ocs.safe-push.review-intent/1",
                "actionSha256": commitment,
                "action": action,
                "observedAbsent": True,
                "armedAt": stamp(now()),
            }
        ),
    )
    require(
        now() < epoch(fresh["guardValidBefore"]),
        "review.expiry",
        "guard observation expired at dispatch",
    )
    ack = writer(action)
    require(
        ack
        in (
            "created",
            "already-up-to-date",
            "remote-did-not-acknowledge",
            "acknowledgement-unavailable",
            "unrecognized-acknowledgement",
        ),
        "review.transport",
        "unknown submission outcome",
    )
    save_private(
        acknowledgement,
        canonical(
            {"actionSha256": commitment, "status": ack, "observedAt": stamp(now())}
        ),
    )
    return current_receipt(live(), ack)


def verified_transfer(args):
    # A publisher never receives the owner's administrative API credential or gh keyring.
    p = selected(read_pins(args.enrollment.absolute()), args.ref)
    pins = read_pins(args.pins.absolute())
    qualified = read_pins(args.parent_proof.absolute())
    guard_path = args.guard.absolute()
    custody = args.custody.absolute()
    require(
        os.geteuid() > 0 and pins["roles"]["publisher"]["custodianUid"] == os.geteuid(),
        "review.custody",
        "run as the enrolled publisher App custodian",
    )
    if args.mode == "publish":
        require(
            args.approved_sha256 and HEX.fullmatch(args.approved_sha256),
            "review.approval",
            "supply the approved exact action digest",
        )
    objects, kind = checked_source(args.source)
    with role_lock(custody), clean_object_view(objects, kind) as repo:
        require(
            role_receipt(custody, "publisher", os.geteuid())
            == pins["roles"]["publisher"],
            "review.custody",
            "publishing role or installation differs from independent pins",
        )
        # Refuse locally inconsistent inputs before asking the genuine App for a credential.
        binding(repo, p, qualified, args.parent, args.candidate)
        check_guard(read_pins(guard_path), p, args.ref, time.time())
        with installation_session(APIClient(), custody, "publisher", pins) as (
            token,
            until,
        ):
            host = ReadAPI(token)

            def live():
                require(
                    time.time() < epoch(until),
                    "review.issuer",
                    "selected installation credential expired",
                )
                evidence = read_pins(guard_path)
                local = binding(repo, p, qualified, args.parent, args.candidate)
                return preflight(host, p, args.ref, evidence, local, pins, time.time())

            return dispatch(
                args.mode,
                custody,
                getattr(args, "approved_sha256", None),
                live,
                lambda action: push_once(repo, action, token),
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    parent = commands.add_parser("parent-proof")
    for field in ("source", "dossier", "baseline-enrollment", "observer-key"):
        parent.add_argument("--" + field, type=Path, required=True)
    for field in ("parent", "verifier", "signed-report-sha256", "observer-sha256"):
        parent.add_argument("--" + field, required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--enrollment", type=Path, required=True)
    guard.add_argument("--ref", required=True)
    guard.add_argument("--gh-read", action="store_true", required=True)
    guard.add_argument("--gh-executable", type=Path, required=True)
    guard.add_argument("--ttl", type=int, default=GUARD_TTL)
    for phase in ("prepare", "publish", "confirm"):
        c = commands.add_parser(phase)
        for f in ("enrollment", "pins", "source", "custody", "parent-proof", "guard"):
            c.add_argument("--" + f, type=Path, required=True)
        for f in ("ref", "parent", "candidate"):
            c.add_argument("--" + f, required=True)
        if phase == "publish":
            c.add_argument("--approved-sha256", required=True)
    args = parser.parse_args()
    if args.mode == "parent-proof":
        objects, kind = checked_source(args.source)
        with clean_object_view(objects, kind) as repo:
            output = parent_proof(
                repo,
                args.parent,
                args.verifier,
                args.dossier,
                args.baseline_enrollment,
                args.observer_key,
                args.signed_report_sha256,
                args.observer_sha256,
            )
    elif args.mode == "guard":
        p = selected(read_pins(args.enrollment.absolute()), args.ref)
        output = guard_record(
            GhReadAPI(p["repository"], args.gh_executable), p, args.ref, args.ttl
        )
    else:
        output = verified_transfer(args)
    print(canonical(output).decode())


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        # A subprocess error may serialize its input command. Emit only bounded admission diagnostics.
        diagnostic = (
            str(error)
            if isinstance(error, ValueError)
            else "independent source, credential or hosted readback unavailable"
        )
        print(
            json.dumps(
                {
                    "scope": "noncanonical review transfer",
                    "status": "pending",
                    "reason": diagnostic[:480],
                }
            ),
            file=sys.stderr,
        )
        sys.exit(1)
