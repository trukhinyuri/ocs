#!/usr/bin/env python3
"""Read hosted enforcement and produce an exact unsigned proposal. Network methods are GET only."""

import argparse
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import commit_binding, readref, state
from authority import Decision, canonical, framed, load, pairs, read, require
from receiver import chain_status, selected_receipt

CHECK = "OCS Safe Push"
REF = "refs/heads/main"
API = "https://api.github.com"
PROFILE = "ocs-release/1"
OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}/[A-Za-z0-9_.-]{1,100}\Z")


def positive(value):
    return type(value) is int and value > 0


def oid(value):
    return type(value) is str and OBJECT.fullmatch(value) and int(value, 16) != 0


def enrollment(p):
    fields = {
        "format",
        "repository",
        "repositoryId",
        "ownerId",
        "project",
        "mode",
        "checkAppId",
        "checkInstallationId",
        "publisherAppId",
        "mergeQueue",
    }
    require(
        type(p) is dict
        and set(p) == fields
        and p["format"] == "ocs.safe-push.forge/1"
        and type(p["repository"]) is str
        and REPOSITORY.fullmatch(p["repository"])
        and p["repository"].split("/")[1] not in (".", "..")
        and type(p["project"]) is str
        and p["project"]
        and all(
            positive(p[k])
            for k in ("repositoryId", "ownerId", "checkAppId", "checkInstallationId")
        )
        and p["mode"] in ("pull-request", "mirror")
        and type(p["mergeQueue"]) is bool,
        "forge.enrollment",
        "invalid independently enrolled repository or identity",
    )
    if p["mode"] == "mirror":
        require(
            positive(p["publisherAppId"])
            and p["publisherAppId"] != p["checkAppId"]
            and not p["mergeQueue"],
            "forge.enrollment",
            "mirror requires separate reporter and sole publisher Apps",
        )
    else:
        require(
            p["publisherAppId"] is None,
            "forge.enrollment",
            "unexpected publisher bypass",
        )
    return p


def rulesets(policy):
    p = enrollment(policy)
    base = {
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [REF], "exclude": []}},
    }
    rules = [
        {"type": t}
        for t in ("creation", "deletion", "non_fast_forward", "required_linear_history")
    ]
    rules.append(
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": CHECK, "integration_id": p["checkAppId"]}
                ],
            },
        }
    )
    if p["mode"] == "pull-request":
        rules.append(
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["squash"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 2,
                    "required_review_thread_resolution": True,
                },
            }
        )
        if p["mergeQueue"]:
            rules.append(
                {
                    "type": "merge_queue",
                    "parameters": {
                        "check_response_timeout_minutes": 60,
                        "grouping_strategy": "ALLGREEN",
                        "max_entries_to_build": 1,
                        "max_entries_to_merge": 1,
                        "merge_method": "SQUASH",
                        "min_entries_to_merge": 1,
                        "min_entries_to_merge_wait_minutes": 5,
                    },
                }
            )
    result = [
        {**base, "name": "OCS admission integrity", "bypass_actors": [], "rules": rules}
    ]
    if p["mode"] == "mirror":
        result.append(
            {
                **base,
                "name": "OCS exclusive mirror writer",
                "bypass_actors": [
                    {
                        "actor_type": "Integration",
                        "actor_id": p["publisherAppId"],
                        "bypass_mode": "always",
                    }
                ],
                "rules": [
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": False},
                    }
                ],
            }
        )
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Decision(
            "forge.origin",
            "API redirect requires an independently re-enrolled destination",
        )


class ReadAPI:
    def __init__(self, token):
        require(
            type(token) is str
            and 0 < len(token) < 4096
            and all(32 < ord(c) < 127 for c in token),
            "forge.credentials",
            "missing enrolled read credential",
        )
        self.token = token
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def get(self, path):
        require(
            path.startswith("/repos/")
            and not path.startswith("//")
            and ".." not in path.split("?")[0].split("/"),
            "forge.origin",
            "unexpected API resource",
        )
        request = urllib.request.Request(
            API + path,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Authorization": "Bearer " + self.token,
                "User-Agent": "OCS-Safe-Push-Readback",
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and path.endswith("/branches/main/protection"):
                body = error.read(4096)
                try:
                    if json.loads(body).get("message") == "Branch not protected":
                        return None
                except (ValueError, AttributeError):
                    pass
            raise Decision(
                "forge.readback",
                f"GET returned HTTP {error.code} for {path.split('?')[0]}",
            ) from error
        except (OSError, urllib.error.URLError) as error:
            raise Decision(
                "forge.readback", "authenticated readback unavailable"
            ) from error
        require(len(raw) <= 4 * 1024 * 1024, "forge.readback", "oversized API result")
        return json.loads(raw, object_pairs_hook=pairs)


def pages(api, path):
    rows = []
    for page in range(1, 21):
        part = api.get(
            path + ("&" if "?" in path else "?") + f"per_page=100&page={page}"
        )
        require(
            type(part) is list and len(part) <= 100,
            "forge.readback",
            "invalid rule page",
        )
        rows.extend(part)
        if len(part) != 100:
            return rows
    raise Decision("forge.readback", "incomplete rule pagination")


def _rules(data):
    require(type(data) is list, "forge.rules", "invalid active rule list")
    result = {}
    for row in data:
        name = row.get("type")
        require(
            type(name) is str
            and name not in result
            and type(row.get("parameters", {})) is dict,
            "forge.rules",
            "duplicated or malformed rule",
        )
        params = dict(row.get("parameters", {}))
        if name == "required_status_checks":
            params.setdefault("do_not_enforce_on_create", False)
        if name == "pull_request":
            # API representations can include explicit values of these optional defaults.
            for field, default in (
                ("required_reviewers", []),
                ("require_extra_approval_for_unattributed_changes", False),
                ("dismissal_restriction", {"enabled": False, "allowed_actors": []}),
            ):
                if params.get(field) == default:
                    params.pop(field, None)
        result[name] = params
    return canonical(result)


def ref_sha(api, root, ref):
    require(ref.startswith("refs/heads/"), "forge.ref", "expected a branch ref")
    name = urllib.parse.quote(ref.removeprefix("refs/"), safe="/")
    row = api.get(root + "/git/ref/" + name)
    require(
        row.get("ref") == ref
        and row.get("object", {}).get("type") == "commit"
        and oid(row["object"].get("sha")),
        "forge.ref",
        "branch does not identify a commit",
    )
    return row["object"]["sha"]


def audit(api, enrollment_data):
    p = enrollment(enrollment_data)
    root = "/repos/" + p["repository"]
    repo = api.get(root)
    require(
        repo.get("id") == p["repositoryId"]
        and repo.get("owner", {}).get("id") == p["ownerId"]
        and repo.get("full_name") == p["repository"]
        and repo.get("private") is True
        and repo.get("visibility") == "private"
        and repo.get("default_branch") == "main"
        and repo.get("archived") is False
        and repo.get("disabled") is False,
        "forge.repository",
        "private repository identity, visibility or default branch changed",
    )
    expected = {t["name"]: t for t in rulesets(p)}
    all_sets = pages(api, root + "/rulesets?includes_parents=true")
    identified = {}
    for row in all_sets:
        name = row.get("name")
        require(
            not (
                row.get("enforcement") == "active"
                and row.get("target") in ("push", "repository")
            ),
            "forge.rules",
            "unreviewed repository-wide or push ruleset",
        )
        if name in expected:
            require(
                row.get("enforcement") == "active"
                and row.get("source_type") == "Repository"
                and row.get("source") == p["repository"]
                and positive(row.get("id"))
                and row["id"] not in identified
                and name not in identified.values(),
                "forge.rules",
                "expected a uniquely identified, active repository protection",
            )
            identified[row["id"]] = name
    require(
        set(identified.values()) == set(expected),
        "forge.rules",
        "required active ruleset is missing",
    )
    effective = pages(api, root + "/rules/branches/main")
    by_id = {rid: [] for rid in identified}
    for rule in effective:
        rid = rule.get("ruleset_id")
        require(
            positive(rid)
            and rid in identified
            and rule.get("ruleset_source_type") == "Repository"
            and rule.get("ruleset_source") == p["repository"],
            "forge.rules",
            "unreviewed effective rule, including an inherited ruleset",
        )
        by_id[rid].append(rule)
    for rid, name in identified.items():
        desired = expected[name]
        active = api.get(f"{root}/rulesets/{rid}?includes_parents=true")
        require(
            active.get("id") == rid
            and active.get("name") == name
            and active.get("source_type") == "Repository"
            and active.get("source") == p["repository"]
            and active.get("target") == "branch"
            and active.get("enforcement") == "active"
            and active.get("conditions") == desired["conditions"],
            "forge.rules",
            "effective ruleset differs from its enrolled branch binding",
        )
        require(
            "bypass_actors" in active
            and canonical(active["bypass_actors"])
            == canonical(desired["bypass_actors"]),
            "forge.bypass",
            "bypass actors are hidden or differ from the enrolled policy",
        )
        require(
            _rules(active.get("rules"))
            == _rules(desired["rules"])
            == _rules(by_id[rid]),
            "forge.rules",
            "effective branch constraints or expected App source differ from enrollment",
        )
    require(
        api.get(root + "/branches/main/protection") is None,
        "forge.rules",
        "additional classic branch protection requires independent enrollment",
    )
    return {
        "repositoryId": p["repositoryId"],
        "repository": p["repository"],
        "mode": p["mode"],
        "tip": ref_sha(api, root, REF),
        "ruleIds": sorted(identified),
        "policySha256": framed(p),
    }


def verified_event(raw, signature, secret):
    require(
        type(raw) is bytes
        and len(raw) <= 2 * 1024 * 1024
        and type(secret) is bytes
        and 16 <= len(secret) <= 4096
        and type(signature) is str
        and re.fullmatch(r"sha256=[0-9a-f]{64}", signature),
        "forge.event",
        "missing authentic event",
    )
    want = "sha256=" + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    require(
        hmac.compare_digest(signature, want),
        "forge.event",
        "invalid webhook HMAC",
        "rejected",
    )
    return json.loads(raw, object_pairs_hook=pairs)


def bind_event(api, p, kind, ev, target):
    root = "/repos/" + p["repository"]
    require(
        ev.get("repository", {}).get("id") == p["repositoryId"]
        and ev["repository"].get("full_name") == p["repository"]
        and ev.get("installation", {}).get("id") == p["checkInstallationId"],
        "forge.event",
        "event belongs to a different repository or App installation",
    )
    old, candidate = target["parent"], target["candidate"]
    if kind == "pull_request":
        pr = ev.get("pull_request", {})
        number = ev.get("number")
        require(
            positive(number)
            and pr.get("number") == number
            and ev.get("action")
            in ("opened", "synchronize", "reopened", "ready_for_review"),
            "forge.event",
            "not an active PR event",
        )
        live = api.get(root + f"/pulls/{number}")
        for row in (pr, live):
            require(
                row.get("number") == number
                and row.get("state") == "open"
                and row.get("draft") is False
                and row.get("base", {}).get("repo", {}).get("id") == p["repositoryId"]
                and row["base"].get("ref") == "main"
                and row["base"].get("sha") == old
                and row.get("merge_commit_sha") == candidate
                and oid(row.get("head", {}).get("sha"))
                and positive(row["head"].get("repo", {}).get("id")),
                "forge.final-object",
                "PR's observed integration object or base differs from the receipt",
            )
        require(
            (pr["head"]["sha"], pr["head"]["repo"]["id"])
            == (live["head"]["sha"], live["head"]["repo"]["id"]),
            "forge.event",
            "delivered PR head is stale",
        )
        return {
            "event": kind,
            "number": number,
            "head": live["head"]["sha"],
            "object": candidate,
        }
    require(
        kind == "merge_group"
        and ev.get("action") == "checks_requested"
        and p["mergeQueue"],
        "forge.event",
        "expected an enrolled merge-group checks request",
    )
    group = ev.get("merge_group", {})
    ref = group.get("head_ref")
    require(
        type(ref) is str
        and re.fullmatch(
            r"refs/heads/gh-readonly-queue/main/[A-Za-z0-9._/-]{1,240}", ref
        )
        and not any(segment in (".", "..", "") for segment in ref.split("/"))
        and ".." not in ref
        and group.get("base_ref") == REF
        and group.get("base_sha") == old
        and group.get("head_sha") == candidate
        and ref_sha(api, root, ref) == candidate,
        "forge.final-object",
        "merge queue head, base or current queued ref differs from the receipt",
    )
    return {"event": kind, "headRef": ref, "object": candidate}


def accepted_local(config, project):
    cfg, authority, journal, repo, _ = state(config)
    current = chain_status(config, require_current=True)
    candidate = current["tip"]
    require(
        current.get("status") == "verified"
        and current.get("profile") == PROFILE
        and current.get("project") == project
        and current.get("certifiedTransitions", 0) > 0
        and candidate == readref(repo),
        "forge.receipt",
        "current release-profile consumer did not verify the tip",
    )
    envelope = load(journal / "signatures" / (candidate + ".json"))
    receipt = selected_receipt(authority, cfg, envelope)
    binding = commit_binding(repo, receipt["parent"], candidate)
    require(
        receipt == load(journal / "committed" / (candidate + ".json"))
        and receipt.get("profile") == PROFILE
        and receipt.get("project") == project
        and all(receipt.get(k) == v for k, v in binding.items()),
        "forge.receipt",
        "authenticated exact local release receipt is missing",
    )
    proof = receipt.get("verifiedProof", {})
    require(
        proof.get("verdict") == "accepted"
        and proof.get("status") == "pass"
        and all(proof.get(k) == v for k, v in binding.items())
        and proof.get("actualParent") == binding["parent"]
        and time.time() < receipt["expiresEpoch"],
        "forge.receipt",
        "current accepted proof is missing",
    )
    return {
        **binding,
        "receiptSha256": framed(envelope),
        "expiresEpoch": receipt["expiresEpoch"],
        "project": project,
        "profile": PROFILE,
        "localRepository": str(repo),
    }


def checks(api, root, candidate, p, receipt_sha):
    legacy = pages(api, root + f"/commits/{candidate}/statuses")
    require(
        all(
            type(row) is dict
            and type(row.get("context")) is str
            and row["context"] != CHECK
            for row in legacy
        ),
        "forge.check",
        "ambiguous required context also recorded as a commit status",
    )
    query = urllib.parse.urlencode(
        {"check_name": CHECK, "filter": "latest", "per_page": 100}
    )
    page = api.get(f"{root}/commits/{candidate}/check-runs?{query}")
    rows = page.get("check_runs")
    require(
        type(rows) is list and len(rows) == page.get("total_count") and len(rows) <= 1,
        "forge.check",
        "ambiguous, incomplete or colliding check result",
    )
    if not rows:
        return None
    run = rows[0]
    require(
        run.get("name") == CHECK
        and run.get("app", {}).get("id") == p["checkAppId"]
        and run.get("head_sha") == candidate
        and positive(run.get("id"))
        and run.get("external_id") == receipt_sha,
        "forge.check",
        "result came from a different App or evidence",
    )
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "forge.check",
        "only a completed success binds the receipt, including when the host accepts neutral or skipped",
    )
    return run["id"]


def propose(
    api, p, local, action, kind=None, raw=None, signature=None, webhook_key=None
):
    """local() must re-adjudicate the independently enrolled consumer at each call."""
    require(
        action in ("check-run", "mirror", "confirm"),
        "forge.action",
        "unrecognized proposal",
    )
    constraints = audit(api, p)
    target = local()
    candidate, parent, tree = target["candidate"], target["parent"], target["tree"]
    require(
        target.get("project") == p["project"]
        and target.get("profile") == PROFILE
        and all(oid(oid_) for oid_ in (parent, candidate, tree))
        and len({len(x) for x in (parent, candidate, tree)}) == 1,
        "forge.receipt",
        "current release binding is incomplete",
    )
    require(
        constraints["tip"] == (candidate if action == "confirm" else parent),
        "forge.parent",
        "hosted canonical ref differs from the expected exact object",
        "rejected",
    )
    root = "/repos/" + p["repository"]
    obj = api.get(root + "/git/commits/" + candidate)
    require(
        obj.get("sha") == candidate
        and obj.get("tree", {}).get("sha") == tree
        and [v.get("sha") for v in obj.get("parents", [])] == [parent],
        "forge.final-object",
        "hosted candidate differs from the signed single-parent object and tree",
    )
    bound_event = None
    if p["mode"] == "pull-request" and action != "confirm":
        require(
            action == "check-run",
            "forge.event",
            "authenticated integration event required",
        )
        event = verified_event(raw, signature, webhook_key)
        bound_event = bind_event(api, p, kind, event, target)
    elif any(v is not None for v in (raw, signature, webhook_key, kind)):
        raise Decision(
            "forge.event", "unexpected event for this enrolled publication route"
        )
    check_id = checks(api, root, candidate, p, target["receiptSha256"])
    # Both independent authorities can move while checks are being read. The sole publisher
    # must repeat this preflight immediately before its action, then verify the remote read-back.
    require(
        local() == target
        and time.time() < target["expiresEpoch"]
        and audit(api, p) == constraints,
        "forge.freshness",
        "repository, rules, receipt or revocation changed",
    )
    if bound_event and bind_event(api, p, kind, event, target) != bound_event:
        raise Decision("forge.event", "integration event moved during preflight")
    require(
        checks(api, root, candidate, p, target["receiptSha256"]) == check_id,
        "forge.check",
        "the expected App result changed during preflight",
    )
    require(
        time.time() < target["expiresEpoch"],
        "forge.freshness",
        "receipt expired during final readback",
    )
    common = {
        "repositoryId": p["repositoryId"],
        "ref": REF,
        "parent": parent,
        "candidate": candidate,
        "tree": tree,
        "receiptSha256": target["receiptSha256"],
        "validBefore": target["expiresEpoch"],
        "rules": constraints["ruleIds"],
        "policySha256": constraints["policySha256"],
    }
    if action == "confirm":
        require(
            check_id is not None, "forge.check", "exact completed App check is absent"
        )
        return {**common, "result": "verified-readback", "checkRunId": check_id}
    if action == "mirror":
        require(
            p["mode"] == "mirror" and check_id is not None,
            "forge.mirror",
            "sole publisher and the exact completed independent App check are required",
        )
        remote = "https://github.com/" + p["repository"] + ".git"
        return {
            **common,
            "result": "proposal",
            "action": "mirror",
            "publisherAppId": p["publisherAppId"],
            "checkRunId": check_id,
            "argv": [
                "git",
                "-C",
                target["localRepository"],
                "push",
                "--force-with-lease=" + REF + ":" + parent,
                "--",
                remote,
                candidate + ":" + REF,
            ],
        }
    if check_id is not None:
        return {**common, "result": "already-reported", "checkRunId": check_id}
    body = {
        "name": CHECK,
        "head_sha": candidate,
        "status": "completed",
        "conclusion": "success",
        "external_id": target["receiptSha256"],
        "output": {
            "title": "OCS admission verified",
            "summary": "Verified exact release receipt "
            + target["receiptSha256"]
            + " from parent "
            + parent
            + ".",
        },
    }
    return {
        **common,
        "result": "proposal",
        "action": "check-run",
        "appId": p["checkAppId"],
        "installationId": p["checkInstallationId"],
        "event": bound_event,
        "method": "POST",
        "path": root + "/check-runs",
        "body": body,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("rules", "audit", "check-run", "mirror", "confirm")
    )
    parser.add_argument("--enrollment", required=True, type=Path)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--receiver", type=Path)
    parser.add_argument("--event", choices=("pull_request", "merge_group"))
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--signature-file", type=Path)
    parser.add_argument("--webhook-secret", type=Path)
    args = parser.parse_args()
    try:
        policy = enrollment(load(args.enrollment))
        if args.action == "rules":
            result = rulesets(policy)
        else:
            require(
                args.token_file is not None,
                "forge.credentials",
                "supply the enrolled read credential",
            )
            api = ReadAPI(read(args.token_file, 4096).decode("ascii").strip())
            if args.action == "audit":
                result = audit(api, policy)
            else:
                require(
                    args.receiver is not None,
                    "forge.receipt",
                    "supply the independent receiver configuration",
                )
                event_args = {}
                if (
                    args.event
                    or args.payload
                    or args.signature_file
                    or args.webhook_secret
                ):
                    require(
                        all(
                            (
                                args.event,
                                args.payload,
                                args.signature_file,
                                args.webhook_secret,
                            )
                        ),
                        "forge.event",
                        "supply event, exact bytes, signature and independent webhook key",
                    )
                    event_args = {
                        "kind": args.event,
                        "raw": read(args.payload, 2 * 1024 * 1024),
                        "signature": read(args.signature_file, 96)
                        .decode("ascii")
                        .strip(),
                        "webhook_key": read(args.webhook_secret, 4096),
                    }
                result = propose(
                    api,
                    policy,
                    lambda: accepted_local(args.receiver, policy["project"]),
                    args.action,
                    **event_args,
                )
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError, IndexError) as error:
        print(
            json.dumps(
                {
                    "outcome": getattr(error, "outcome", "undetermined"),
                    "criterion": getattr(error, "criterion", "forge.readback"),
                    "message": str(error)[:350],
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
