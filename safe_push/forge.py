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
from admission import commit_binding, get_parent, git, observe, readref, state
from authority import (
    ROLES,
    Decision,
    authentic,
    canonical,
    framed,
    fresh,
    instant,
    load,
    pairs,
    policy_history,
    public_der,
    read,
    require,
)
from receiver import chain_status, selected_receipt

CHECK = "OCS Safe Push"
REF = "refs/heads/main"
API = "https://api.github.com"
PROFILE = "ocs-release/1"
OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}/[A-Za-z0-9_.-]{1,100}\Z")
HOLD = "OCS main enrollment hold"
INTEGRITY = "OCS admission integrity"
WRITER = "OCS exclusive mirror writer"
CLOSED = "OCS canonical creation closed"


def positive(value):
    return type(value) is int and value > 0


def oid(value):
    return type(value) is str and OBJECT.fullmatch(value) and int(value, 16) != 0


def _staging(ref):
    return (
        type(ref) is str
        and ref != REF
        and re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,180}", ref)
        and ".." not in ref
        and not any(
            not p or p.startswith(".") or p.endswith((".lock", "."))
            for p in ref.removeprefix("refs/heads/").split("/")
        )
    )


def _identity(p):
    return (
        type(p.get("repository")) is str
        and REPOSITORY.fullmatch(p["repository"])
        and p["repository"].split("/")[1] not in (".", "..")
        and positive(p.get("repositoryId"))
        and positive(p.get("ownerId"))
        and p.get("expectedVisibility") in ("private", "public")
    )


def hold_enrollment(p):
    expected = {
        "format",
        "repository",
        "repositoryId",
        "ownerId",
        "expectedVisibility",
        "stagingRef",
        "stagingCommit",
        "holdRulesetId",
    }
    require(
        type(p) is dict
        and set(p) == expected
        and p["format"] == "ocs.safe-push.forge-hold/1"
        and _identity(p)
        and _staging(p["stagingRef"])
        and oid(p["stagingCommit"])
        and positive(p["holdRulesetId"]),
        "forge.enrollment",
        "invalid repository, staging branch or hold registration",
    )
    return p


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
        and (
            (set(p) == fields and p.get("format") == "ocs.safe-push.forge/1")
            or (
                set(p) == fields | {"expectedVisibility", "bootstrap"}
                and p.get("format") == "ocs.safe-push.forge/2"
                and _identity(p)
            )
        )
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
    b = p.get("bootstrap")
    if b is not None:
        require(
            p["mode"] == "mirror"
            and type(b) is dict
            and set(b)
            == {
                "stagingRef",
                "stagingCommit",
                "genesis",
                "holdRulesetId",
                "integrityRulesetId",
                "writerRulesetId",
                "publisherInstallationId",
            }
            and _staging(b["stagingRef"])
            and oid(b["stagingCommit"])
            and oid(b["genesis"])
            and b["stagingCommit"] != b["genesis"]
            and len(b["stagingCommit"]) == len(b["genesis"])
            and all(
                positive(b[k])
                for k in ("holdRulesetId", "integrityRulesetId", "writerRulesetId")
            )
            and positive(b["publisherInstallationId"])
            and b["publisherInstallationId"] != p["checkInstallationId"]
            and len({b["holdRulesetId"], b["integrityRulesetId"], b["writerRulesetId"]})
            == 3,
            "forge.enrollment",
            "invalid genesis, staging branch or separately operated bootstrap rules",
        )
    return p


def _repository(api, p, default_branches):
    root = "/repos/" + p["repository"]
    repo = api.get(root)
    visibility = p.get("expectedVisibility", "private")
    require(
        positive(repo.get("id"))
        and repo["id"] == p["repositoryId"]
        and positive(repo.get("owner", {}).get("id"))
        and repo["owner"]["id"] == p["ownerId"]
        and repo.get("full_name") == p["repository"]
        and repo.get("visibility") == visibility
        and repo.get("private") is (visibility == "private")
        and repo.get("default_branch") in default_branches
        and repo.get("archived") is False
        and repo.get("disabled") is False,
        "forge.repository",
        "repository identity, explicit visibility or expected default branch changed",
    )
    return root, repo["default_branch"]


def hold_rule():
    return {
        "name": HOLD,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": [REF], "exclude": []}},
        "rules": [
            {"type": n} for n in ("creation", "update", "deletion", "non_fast_forward")
        ],
    }


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
    if p.get("bootstrap") is not None:
        result[0]["rules"] = [r for r in result[0]["rules"] if r["type"] != "creation"]
        result[1]["rules"].append({"type": "creation"})
        result.append(
            {
                **base,
                "name": CLOSED,
                "bypass_actors": [],
                "rules": [{"type": "creation"}],
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
            try:
                if error.code == 404 and path.endswith("/branches/main/protection"):
                    body = error.read(4096)
                    try:
                        if json.loads(body).get("message") == "Branch not protected":
                            return None
                    except (ValueError, AttributeError):
                        pass
            finally:
                error.close()
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


def _gh_exchange(command):
    """Use only the selected gh keyring identity. Bound its status headers, body and duration."""
    import os
    import selectors
    import subprocess

    budget = 4 * 1024 * 1024 + 65536
    env = {
        "PATH": os.defpath,
        "HOME": str(Path.home()),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
        "LC_ALL": "C",
    }
    # Preserve the account's keyring session and explicitly configured local gh profile.
    for key in (
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "GNOME_KEYRING_CONTROL",
        "XDG_CONFIG_HOME",
        "GH_CONFIG_DIR",
    ):
        if key in os.environ:
            env[key] = os.environ[key]
    end = time.monotonic() + 25
    raw = bytearray()
    try:
        with subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=Path.home(),
            env=env,
        ) as child:
            try:
                with selectors.DefaultSelector() as watch:
                    watch.register(child.stdout, selectors.EVENT_READ)
                    while True:
                        left = end - time.monotonic()
                        require(
                            left > 0 and watch.select(left),
                            "forge.readback",
                            "gh API read deadline exceeded",
                        )
                        chunk = os.read(
                            child.stdout.fileno(), min(65536, budget - len(raw) + 1)
                        )
                        if not chunk:
                            break
                        raw.extend(chunk)
                        require(
                            len(raw) <= budget,
                            "forge.readback",
                            "oversized gh API response",
                        )
                status = child.wait(timeout=max(0, end - time.monotonic()))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Decision(
            "forge.readback", "selected gh keyring or bounded API read unavailable"
        ) from error
    return status, bytes(raw)


def _gh_binary(configured):
    import os
    import shutil
    import stat

    path = configured if configured is not None else shutil.which("gh", path=os.defpath)
    require(
        path is not None,
        "forge.credentials",
        "installed gh CLI unavailable; select its independently installed absolute path",
    )
    path = Path(path)
    require(
        path.is_absolute() and ".." not in path.parts,
        "forge.credentials",
        "select an absolute installed gh executable",
    )
    try:
        resolved = path.resolve(strict=True)
        file_stat = resolved.stat()
        require(
            resolved.name == "gh"
            and stat.S_ISREG(file_stat.st_mode)
            and os.access(resolved, os.X_OK)
            and file_stat.st_uid in (0, os.getuid())
            and not file_stat.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID),
            "forge.credentials",
            "selected gh must be a trusted-owner executable without shared write access",
        )
        for directory in set(path.parents) | set(resolved.parents):
            info = directory.stat()
            trusted_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            require(
                not (directory / ".git").exists()
                and not (
                    (directory / "HEAD").is_file() and (directory / "objects").is_dir()
                )
                and info.st_uid in (0, os.getuid())
                and (not info.st_mode & 0o022 or trusted_sticky),
                "forge.credentials",
                "gh executable path must be outside repository-controlled or shared-writable code",
            )
    except OSError as error:
        raise Decision(
            "forge.credentials", "selected gh executable is absent or inaccessible"
        ) from error
    return str(resolved)


class GhReadAPI:
    """Restricted admin GET using the enrolled github.com account selected in the local gh keyring."""

    def __init__(self, repository, executable=None):
        require(
            type(repository) is str
            and REPOSITORY.fullmatch(repository)
            and repository.split("/")[1] not in (".", ".."),
            "forge.origin",
            "invalid pinned GitHub repository",
        )
        self.root = "/repos/" + repository
        self.binary = _gh_binary(executable)

    def request(self, method, path):
        require(
            method == "GET",
            "forge.origin",
            "the selected gh keyring route accepts GET only",
        )
        require(
            type(path) is str
            and 0 < len(path) <= 4096
            and all(32 < ord(c) < 127 for c in path)
            and not set(path).intersection("{}\\#"),
            "forge.origin",
            "unsafe gh API path",
        )
        parsed = urllib.parse.urlsplit(path)
        require(
            not parsed.scheme
            and not parsed.netloc
            and not parsed.fragment
            and (parsed.path == self.root or parsed.path.startswith(self.root + "/"))
            and "%" not in parsed.path
            and not any(x in (".", "..", "") for x in parsed.path.split("/")[1:]),
            "forge.origin",
            "GET resource lies outside the enrolled repository",
        )
        endpoint = parsed.path.removeprefix(self.root)
        commit = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
        resources = (
            r"",
            r"/rulesets(?:/[1-9][0-9]*(?:/history(?:/[1-9][0-9]*)?)?)?",
            r"/rules/branches/main",
            r"/branches/main/protection",
            r"/git/matching-refs/heads/main",
            r"/git/ref/heads/[a-zA-Z0-9._/-]+",
            r"/git/commits/" + commit,
            r"/pulls/[1-9][0-9]*",
            r"/commits/" + commit + r"/(?:statuses|check-runs)",
            r"/check-runs/[1-9][0-9]*",
        )
        query = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
        params = dict(query)
        enrolled_check_runs = (
            re.fullmatch(r"/commits/" + commit + r"/check-runs", endpoint) is not None
            and params.get("check_name") == CHECK
            and set(params) <= {"check_name", "filter", "per_page", "page"}
        )
        require(
            any(re.fullmatch(pattern, endpoint) for pattern in resources)
            and len(query) == len(params)
            and all(
                (k == "includes_parents" and v == "true")
                or (k == "per_page" and v == "100")
                or (k == "page" and v.isascii() and v.isdigit() and 1 <= int(v) <= 20)
                or (k == "check_name" and v == CHECK)
                or (
                    k == "filter"
                    and (v == "latest" or (v == "all" and enrolled_check_runs))
                )
                for k, v in query
            ),
            "forge.origin",
            "resource or query is outside the enrolled readback interface",
        )
        command = [
            self.binary,
            "api",
            "--hostname",
            "github.com",
            "--method",
            "GET",
            "--include",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            "--",
            path,
        ]
        exitcode, raw = _gh_exchange(command)
        separator = re.search(rb"\r?\n\r?\n", raw)
        require(
            separator is not None and separator.start() <= 65536,
            "forge.readback",
            "gh returned no bounded HTTP status",
        )
        status = re.fullmatch(
            rb"HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([0-9]{3})(?: [^\r\n]*)?",
            raw[: separator.start()].splitlines()[0],
        )
        require(status is not None, "forge.readback", "unrecognized gh HTTP status")
        code = int(status[1])
        body = raw[separator.end() :]
        require(len(body) <= 4 * 1024 * 1024, "forge.readback", "oversized gh API body")
        if code == 404 and parsed.path == self.root + "/branches/main/protection":
            try:
                if json.loads(body).get("message") == "Branch not protected":
                    return None
            except (ValueError, AttributeError):
                pass
        require(
            exitcode == 0 and code == 200,
            "forge.readback",
            f"GET returned HTTP {code} for {parsed.path}",
        )
        try:
            return json.loads(body, object_pairs_hook=pairs)
        except (ValueError, UnicodeError) as error:
            raise Decision("forge.readback", "gh returned invalid API JSON") from error

    def get(self, path):
        return self.request("GET", path)


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
        if name == "update":
            # The REST rule permits omitting parameters. GitHub omits the object in
            # readbacks of an explicitly false upstream fetch-and-merge exception.
            if "parameters" in row:
                require(
                    set(params) == {"update_allows_fetch_and_merge"}
                    and params["update_allows_fetch_and_merge"] is False,
                    "forge.rules",
                    "update rule has an enabled or malformed exception",
                )
            params = {"update_allows_fetch_and_merge": False}
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


def _main_or_absent(api, root):
    # A successful prefix-list call distinguishes a missing exact ref from denied contents access.
    rows = api.get(root + "/git/matching-refs/heads/main")
    require(
        type(rows) is list and len(rows) <= 4096,
        "forge.ref",
        "incomplete matching reference readback",
    )
    seen = {}
    for row in rows:
        name = row.get("ref")
        require(
            type(name) is str
            and name.startswith(REF)
            and name not in seen
            and row.get("object", {}).get("type") == "commit"
            and oid(row["object"].get("sha")),
            "forge.ref",
            "ambiguous matching reference",
        )
        seen[name] = row["object"]["sha"]
    return seen.get(REF)


def _rule_detail(actual, desired, rid, p):
    require(
        actual.get("id") == rid
        and actual.get("name") == desired["name"]
        and actual.get("source_type") == "Repository"
        and actual.get("source") == p["repository"]
        and actual.get("target") == "branch"
        and actual.get("enforcement") == desired["enforcement"]
        and actual.get("conditions") == desired["conditions"],
        "forge.rules",
        "incorrect enrolled ruleset binding",
    )
    require(
        "bypass_actors" in actual
        and canonical(actual["bypass_actors"]) == canonical(desired["bypass_actors"]),
        "forge.bypass",
        "hidden or unexpected bypass actors",
    )
    require(
        _rules(actual.get("rules")) == _rules(desired["rules"]),
        "forge.rules",
        "rules differ from their independently enrolled constraints",
    )


def audit_hold(api, enrollment_data):
    p = hold_enrollment(enrollment_data)
    root, default = _repository(api, p, {p["stagingRef"].removeprefix("refs/heads/")})
    rid = p["holdRulesetId"]
    require(
        ref_sha(api, root, p["stagingRef"]) == p["stagingCommit"]
        and _main_or_absent(api, root) is None,
        "forge.hold",
        "staging ref moved or the canonical ref already exists",
    )
    desired = hold_rule()
    active = api.get(f"{root}/rulesets/{rid}?includes_parents=true")
    _rule_detail(active, desired, rid, p)
    relevant = [
        v
        for v in pages(api, root + "/rules/branches/main")
        if v.get("ruleset_id") == rid
    ]
    require(
        all(
            v.get("ruleset_source_type") == "Repository"
            and v.get("ruleset_source") == p["repository"]
            for v in relevant
        )
        and _rules(relevant) == _rules(desired["rules"]),
        "forge.hold",
        "the enrolled no-bypass hold does not actually govern main",
    )
    require(
        _main_or_absent(api, root) is None
        and ref_sha(api, root, p["stagingRef"]) == p["stagingCommit"],
        "forge.hold",
        "ref changed during frozen-state readback",
    )
    root, _ = _repository(api, p, {default})
    _rule_detail(
        api.get(f"{root}/rulesets/{rid}?includes_parents=true"), desired, rid, p
    )
    confirm = [
        v
        for v in pages(api, root + "/rules/branches/main")
        if v.get("ruleset_id") == rid
    ]
    require(
        all(
            v.get("ruleset_source_type") == "Repository"
            and v.get("ruleset_source") == p["repository"]
            for v in confirm
        )
        and _rules(confirm) == _rules(relevant),
        "forge.hold",
        "effective enrollment hold changed during readback",
    )
    return {
        "result": "frozen-no-main",
        "repositoryId": p["repositoryId"],
        "ownerId": p["ownerId"],
        "visibility": p["expectedVisibility"],
        "defaultBranch": default,
        "stagingRef": p["stagingRef"],
        "stagingCommit": p["stagingCommit"],
        "ref": REF,
        "tip": None,
        "holdRulesetId": rid,
        "enrollmentSha256": framed(p),
    }


def audit(api, enrollment_data):
    p = enrollment(enrollment_data)
    root, _ = _repository(api, p, {"main"})
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
        if p.get("bootstrap") is not None and name in (INTEGRITY, WRITER):
            field = "integrityRulesetId" if name == INTEGRITY else "writerRulesetId"
            require(
                rid == p["bootstrap"][field],
                "forge.rules",
                "protected permanent guard identity changed",
            )
        active = api.get(f"{root}/rulesets/{rid}?includes_parents=true")
        _rule_detail(active, desired, rid, p)
        require(
            _rules(desired["rules"]) == _rules(by_id[rid]),
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


def bootstrap_rules(p):
    p = enrollment(p)
    require(
        p["format"] == "ocs.safe-push.forge/2" and p["mode"] == "mirror",
        "forge.bootstrap",
        "initial creation requires a separately enrolled v2 sole publisher",
    )
    rules = rulesets(p)
    if p["bootstrap"] is None:
        rules[0]["rules"] = [r for r in rules[0]["rules"] if r["type"] != "creation"]
        rules[1]["rules"].append({"type": "creation"})
    return rules[:2]


def bootstrap_rule_plan(p):
    """Return enrollment/overlap/final bodies before the server assigns real rule IDs."""
    guards = bootstrap_rules(p)
    closure = {
        **guards[0],
        "name": CLOSED,
        "rules": [{"type": "creation"}],
        "bypass_actors": [],
    }
    return {"hold": hold_rule(), "permanent": guards, "closure": closure}


def _versions(api, root, rid, templates, p):
    history = pages(api, f"{root}/rulesets/{rid}/history")
    require(
        len(history) == len(templates),
        "forge.continuity",
        "ruleset history contains an unchecked transition",
    )
    history.sort(key=lambda x: instant(x["updated_at"]))
    versions = []
    for item, desired in zip(history, templates):
        number = item.get("version_id")
        require(
            positive(number) and all(v["id"] != number for v in versions),
            "forge.continuity",
            "missing or repeated ruleset version",
        )
        version = api.get(f"{root}/rulesets/{rid}/history/{number}")
        require(
            version.get("version_id") == number
            and version.get("updated_at") == item.get("updated_at")
            and isinstance(version.get("state"), dict),
            "forge.continuity",
            "unbound ruleset history state",
        )
        _rule_detail(version["state"], desired, rid, p)
        versions.append({"id": number, "at": instant(item["updated_at"])})
    return versions


def bootstrap_state(api, p, phase):
    p = enrollment(p)
    b = p.get("bootstrap")
    require(
        b is not None and phase in ("overlap", "eligible", "published"),
        "forge.bootstrap",
        "registered mirror bootstrap scope required",
    )
    staged = b["stagingRef"].removeprefix("refs/heads/")
    root, default = _repository(
        api, p, {staged, "main"} if phase == "published" else {staged}
    )
    require(
        ref_sha(api, root, b["stagingRef"]) == b["stagingCommit"]
        and _main_or_absent(api, root)
        == (b["genesis"] if phase == "published" else None),
        "forge.bootstrap-ref",
        "staging ref or canonical creation precondition changed",
    )
    active_hold = hold_rule()
    hold_expected = (
        active_hold
        if phase == "overlap"
        else {**active_hold, "enforcement": "disabled"}
    )
    desired = {b["holdRulesetId"]: hold_expected}
    for fld, spec in zip(("integrityRulesetId", "writerRulesetId"), bootstrap_rules(p)):
        desired[b[fld]] = spec
    sets = pages(api, root + "/rulesets?includes_parents=true")
    matched = {}
    closure = None
    expected_names = {v["name"] for v in desired.values()}
    for s in sets:
        require(
            not (
                s.get("target") in ("push", "repository")
                and s.get("enforcement") == "active"
            ),
            "forge.rules",
            "unreviewed enforcing repository-wide rule",
        )
        if s.get("name") in expected_names:
            rid = s.get("id")
            require(
                rid in desired
                and rid not in matched
                and s["name"] == desired[rid]["name"]
                and s.get("source_type") == "Repository"
                and s.get("source") == p["repository"]
                and s.get("enforcement") == desired[rid]["enforcement"],
                "forge.rules",
                "bootstrap ruleset or hold identity changed",
            )
            matched[rid] = s
        elif s.get("name") == CLOSED and s.get("enforcement") == "active":
            require(
                phase == "published"
                and closure is None
                and positive(s.get("id"))
                and s.get("source_type") == "Repository"
                and s.get("source") == p["repository"],
                "forge.bootstrap",
                "normal zero-bypass creation closure is already active",
            )
            closure = s["id"]
    require(
        set(matched) == set(desired),
        "forge.rules",
        "missing enrolled hold or permanent bootstrap guard",
    )
    if closure is not None:
        desired[closure] = rulesets(p)[2]
    effective = pages(api, root + "/rules/branches/main")
    applied = {rid: [] for rid, d in desired.items() if d["enforcement"] == "active"}
    for rule in effective:
        rid = rule.get("ruleset_id")
        require(
            rid in applied
            and rule.get("ruleset_source_type") == "Repository"
            and rule.get("ruleset_source") == p["repository"],
            "forge.rules",
            "unexpected effective branch constraint",
        )
        applied[rid].append(rule)
    for rid, d in desired.items():
        actual = api.get(f"{root}/rulesets/{rid}?includes_parents=true")
        _rule_detail(actual, d, rid, p)
        if d["enforcement"] == "active":
            require(
                _rules(applied[rid]) == _rules(d["rules"]),
                "forge.rules",
                "future main is missing an independently required effective rule",
            )
    versions = _versions(
        api,
        root,
        b["holdRulesetId"],
        [active_hold] if phase == "overlap" else [active_hold, hold_expected],
        p,
    )
    guards = [
        _versions(api, root, b[f], [desired[b[f]]], p)[0]
        for f in ("integrityRulesetId", "writerRulesetId")
    ]
    overlap = max(versions[0]["at"], *(v["at"] for v in guards))
    # Later rule versions, identifier reuse, hidden history and ambiguous simultaneous events all hold creation.
    if phase != "overlap":
        require(
            overlap < versions[1]["at"],
            "forge.continuity",
            "both permanent protections must predate the handoff from the original frozen hold",
        )
    if phase == "published":
        require(
            api.get(root + "/branches/main/protection") is None,
            "forge.rules",
            "unreviewed classic protection on the newly created branch",
        )
    return {
        "repositoryId": p["repositoryId"],
        "visibility": p["expectedVisibility"],
        "defaultBranch": default,
        "stagingRef": b["stagingRef"],
        "stagingCommit": b["stagingCommit"],
        "genesis": b["genesis"],
        "holdRulesetId": b["holdRulesetId"],
        "integrityRulesetId": b["integrityRulesetId"],
        "writerRulesetId": b["writerRulesetId"],
        "guardActiveSince": overlap,
        "holdVersion": versions[0]["id"],
        "guardVersions": [v["id"] for v in guards],
        "holdDisabledAt": None if phase == "overlap" else versions[1]["at"],
        "closureRulesetId": closure,
    }


def qualified_genesis(config, p):
    """Re-adjudicate the original current seed from its independent receiving installation."""
    from cost import sufficient, valid_reference, validate_profile
    from cost_acquisition import reference
    from scope import change_requirements, inventory, subject

    cfg, authority, journal, repo, policy = state(config)
    b = p["bootstrap"]
    current = chain_status(config, require_current=True)
    genesis = b["genesis"]
    require(
        policy["profile"] == PROFILE
        and not policy["requiredOpen"]
        and current.get("status") == "verified"
        and current.get("profile") == PROFILE
        and current.get("project") == p["project"] == cfg["project"]
        and current.get("certifiedTransitions") == 0
        and current.get("tip")
        == current.get("genesis")
        == cfg["genesis"]
        == policy["genesis"]
        == genesis
        == readref(repo),
        "forge.genesis",
        "current independently enrolled release genesis required",
    )
    seed = get_parent(cfg, authority, journal, genesis)
    root_policy = policy_history(authority, cfg["rootDigest"])[0]
    require(
        seed.get("format") == "ocs.safe-push.genesis/1"
        and seed.get("profile") == PROFILE
        and seed.get("project") == p["project"]
        and seed.get("candidate") == genesis
        and framed(seed) == cfg["genesisDigest"]
        and root_policy.get("profile") == PROFILE
        and root_policy.get("genesis") == genesis
        and seed.get("policy") == framed(root_policy) == cfg["rootDigest"],
        "forge.genesis",
        "genesis receipt does not match the current authority's independently enrolled root",
    )
    inv = inventory(repo, genesis)
    ident = subject(repo, genesis, inv)
    plan = change_requirements(repo, genesis, genesis, inv, inv)
    tree = git(repo, "rev-parse", genesis + "^{tree}")
    require(
        seed["subject"] == ident
        and seed["tree"] == tree
        and seed["wholeTreeSha256"] == plan["wholeTreeSha256"],
        "forge.genesis",
        "local Git object and complete source inventory disagree",
    )
    registration = policy["receiverCost"]
    validate_profile(registration)
    baseline = reference(cfg, authority, journal, policy, seed)
    require(
        isinstance(registration, dict)
        and registration.get("profile") == PROFILE
        and isinstance(baseline, dict)
        and baseline.get("status") == "baseline-observation"
        and framed(baseline) == registration.get("baselineEvidenceSha256")
        and all(
            baseline.get(k) == registration.get(k)
            for k in ("workloadSha256", "platformSha256")
        )
        and valid_reference(baseline, baseline, framed(registration)),
        "forge.cost",
        "complete enrolled verifier cost baseline required",
    )
    sufficient(baseline)
    require(
        all(baseline["observed"][k] <= v for k, v in registration["ceilings"].items()),
        "forge.cost",
        "registered verifier cost already exceeds a protected ceiling",
    )
    claims, metrics, reports, limits, bounds = {}, {}, {}, {}, []
    full = plan["requirements"]["qualification.full"]["levels"]
    require(
        isinstance(full, dict)
        and full
        and all(isinstance(levels, list) and levels for levels in full.values())
        and any(t["adapter"] == "ocs-dossier/1" for t in policy["targets"].values()),
        "forge.genesis",
        "actual prescribed full OCS assurance execution is missing",
    )
    for name, desc in policy["targets"].items():
        row = observe(
            authority, repo, policy, name, authority / "bootstrap" / name, ident
        )
        require(
            not row.get("metricGaps")
            and (
                desc["adapter"] != "ocs-dossier/1"
                or all(
                    atom + "@" + level in row["claims"]
                    for atom, levels in full.items()
                    for level in levels
                )
            ),
            "forge.genesis",
            "incomplete target, measurements or original evidence levels",
        )
        claims.update({name + "/" + k: v for k, v in row["claims"].items()})
        metrics.update({name + "/" + k: v for k, v in row["metrics"].items()})
        reports[name] = row["reportSha256"]
        limits[name] = row.get("coverageLimits", [])
        bounds.append(instant(row["expiresAt"]))
    require(
        seed["claims"] == claims
        and seed["metrics"] == metrics
        and seed["targetReports"] == reports
        and seed["coverageLimits"] == limits
        and time.time() < min(seed["expiresEpoch"], *bounds),
        "forge.genesis",
        "fresh rebuilt target observations differ from the independently enrolled genesis",
    )
    return {
        "project": p["project"],
        "profile": PROFILE,
        "genesis": genesis,
        "tree": tree,
        "parents": git(repo, "show", "-s", "--format=%P", genesis).split(),
        "sourceSha256": ident["treeSha256"],
        "genesisReceiptSha256": framed(seed),
        "genesisRootSha256": framed(root_policy),
        "policySha256": framed(policy),
        "epoch": policy["epoch"],
        "keys": policy["keys"],
        "lifetimeSeconds": policy["lifetimeSeconds"],
        "expiresEpoch": min(seed["expiresEpoch"], *bounds),
        "localRepository": str(repo),
    }


def _bootstrap_context(p, target):
    b = p["bootstrap"]
    require(
        target.get("genesis") == b["genesis"]
        and target.get("project") == p["project"]
        and target.get("profile") == PROFILE
        and oid(target.get("tree"))
        and target["tree"]
        and all(oid(v) for v in target.get("parents", []))
        and all(
            re.fullmatch(r"[a-f0-9]{64}", target.get(k, ""))
            for k in (
                "sourceSha256",
                "policySha256",
                "genesisReceiptSha256",
                "genesisRootSha256",
            )
        ),
        "forge.genesis",
        "independent genesis scope is missing",
    )
    return {
        "format": "ocs.safe-push.hosted-genesis/1",
        "enrollmentSha256": framed(p),
        "project": p["project"],
        "profile": PROFILE,
        "repository": p["repository"],
        "repositoryId": p["repositoryId"],
        "ownerId": p["ownerId"],
        "visibility": p["expectedVisibility"],
        "ref": REF,
        "expectedRef": "absent",
        "genesis": target["genesis"],
        "tree": target["tree"],
        "parents": target["parents"],
        "sourceSha256": target["sourceSha256"],
        "genesisReceiptSha256": target["genesisReceiptSha256"],
        "genesisRootSha256": target["genesisRootSha256"],
        "policySha256": target["policySha256"],
        "epoch": target["epoch"],
        "stagingRef": b["stagingRef"],
        "stagingCommit": b["stagingCommit"],
        "holdRulesetId": b["holdRulesetId"],
        "integrityRulesetId": b["integrityRulesetId"],
        "writerRulesetId": b["writerRulesetId"],
        "checkAppId": p["checkAppId"],
        "checkInstallationId": p["checkInstallationId"],
        "publisherAppId": p["publisherAppId"],
        "publisherInstallationId": b["publisherInstallationId"],
    }


def bootstrap_apps(p, reporters):
    from forge_apps import PERMISSIONS, permission_map

    require(
        isinstance(reporters, dict) and set(reporters) == {"check", "publisher"},
        "forge.installation",
        "two independent App installation readbacks required",
    )
    result = {}
    for role, app, installation, permission in (
        ("check", p["checkAppId"], p["checkInstallationId"], "checks"),
        (
            "publisher",
            p["publisherAppId"],
            p["bootstrap"]["publisherInstallationId"],
            "contents",
        ),
    ):
        row = reporters[role].get("/repos/" + p["repository"] + "/installation")
        require(
            positive(row.get("id"))
            and row["id"] == installation
            and positive(row.get("app_id"))
            and row["app_id"] == app
            and row.get("account", {}).get("id") == p["ownerId"]
            and str(row["account"].get("login", "")).casefold()
            == p["repository"].split("/")[0].casefold()
            and row.get("target_id") == p["ownerId"]
            and row.get("repository_selection") == "selected"
            and "suspended_at" in row
            and row["suspended_at"] is None
            and permission_map(row.get("permissions", {}))
            == PERMISSIONS["reporter" if role == "check" else role],
            "forge.installation",
            "App role, installation, owner, suspension or permissions differ from enrollment",
        )
        result[role] = {
            "app": app,
            "installation": installation,
            "permission": permission,
        }
    return result


def _quorum(envelope, context, target):
    require(
        isinstance(envelope, dict)
        and set(envelope) == {"payload", "signatures"}
        and isinstance(envelope["payload"], dict),
        "forge.custody",
        "independent release authorization is missing",
    )
    payload = envelope["payload"]
    require(
        set(payload) == set(context) | {"issuedAt", "expiresAt"}
        and {k: payload[k] for k in context} == context,
        "forge.custody",
        "signed scope differs from the bound genesis or hosted rules",
    )
    fresh(
        payload["issuedAt"],
        payload["expiresAt"],
        time.time(),
        target["lifetimeSeconds"],
    )
    require(
        instant(payload["expiresAt"]) <= target["expiresEpoch"],
        "forge.custody",
        "authorization outlives qualification",
    )
    require(
        set(envelope["signatures"]) == {*ROLES, "publisher"}
        and set(target["keys"]) == {*ROLES, "publisher"}
        and len({public_der(pem) for pem in target["keys"].values()}) == 4,
        "forge.custody",
        "exact domain, independent, guardian and publisher quorum required",
    )
    for role in (*ROLES, "publisher"):
        require(
            authentic(
                envelope["signatures"][role], target["keys"][role], "forge.custody"
            )
            == {**payload, "role": role},
            "forge.custody",
            "misbound authorization role",
        )
    return instant(payload["expiresAt"])


def bootstrap_propose(
    api, p, local, action, authorization=None, handoff=None, app_views=None
):
    require(
        action
        in (
            "bootstrap-context",
            "bootstrap-check",
            "bootstrap-handoff",
            "bootstrap-create",
            "bootstrap-confirm",
        ),
        "forge.action",
        "unexpected initial enrollment action",
    )
    phase = (
        "eligible"
        if action == "bootstrap-create"
        else "published"
        if action == "bootstrap-confirm"
        else "overlap"
    )
    situation = bootstrap_state(api, p, phase)
    installations = bootstrap_apps(p, app_views)
    target = local()
    context = _bootstrap_context(p, target)
    root = "/repos/" + p["repository"]
    genesis = context["genesis"]
    obj = api.get(root + "/git/commits/" + genesis)
    require(
        obj.get("sha") == genesis
        and obj.get("tree", {}).get("sha") == context["tree"]
        and [row.get("sha") for row in obj.get("parents", [])] == context["parents"],
        "forge.genesis",
        "hosted object is not the independently enrolled Git genesis",
    )
    if action == "bootstrap-context":
        require(
            local() == target
            and bootstrap_state(api, p, phase) == situation
            and bootstrap_apps(p, app_views) == installations
            and time.time() < target["expiresEpoch"],
            "forge.freshness",
            "overlap or genesis validity changed",
        )
        return {
            "result": "unsigned-genesis-scope",
            "context": context,
            "expiresNoLaterThan": target["expiresEpoch"],
        }
    expiry = _quorum(authorization, context, target)
    seal = framed(authorization)
    check = checks(api, root, genesis, p, seal)
    if action == "bootstrap-check" and check is None:
        result = {
            "result": "proposal",
            "action": "bootstrap-check",
            "method": "POST",
            "path": root + "/check-runs",
            "appId": p["checkAppId"],
            "installationId": p["checkInstallationId"],
            "body": {
                "name": CHECK,
                "head_sha": genesis,
                "status": "completed",
                "conclusion": "success",
                "external_id": seal,
                "output": {
                    "title": "OCS release genesis verified",
                    "summary": "Qualified initial Git object "
                    + genesis
                    + " under release authorization "
                    + seal
                    + ".",
                },
            },
        }
    else:
        require(
            check is not None,
            "forge.check",
            "exact completed independent App check for signed genesis is absent",
        )
        actual = api.get(f"{root}/check-runs/{check}")
        require(
            actual.get("id") == check
            and actual.get("app", {}).get("id") == p["checkAppId"]
            and actual.get("name") == CHECK
            and actual.get("head_sha") == genesis
            and actual.get("external_id") == seal
            and actual.get("status") == "completed"
            and actual.get("conclusion") == "success"
            and instant(authorization["payload"]["issuedAt"])
            <= instant(actual.get("completed_at"))
            <= time.time(),
            "forge.check",
            "authoritative App check readback or its completion time is incompatible",
        )
        charge = {
            "format": "ocs.safe-push.hosted-handoff/1",
            "contextSha256": framed(context),
            "authorizationSha256": seal,
            "repositoryId": p["repositoryId"],
            "ref": REF,
            "genesis": genesis,
            "checkRunId": check,
            "holdRulesetId": situation["holdRulesetId"],
            "holdVersion": situation["holdVersion"],
            "integrityRulesetId": situation["integrityRulesetId"],
            "writerRulesetId": situation["writerRulesetId"],
            "guardVersions": situation["guardVersions"],
            "observedMain": "absent",
            "checkCompletedAt": actual["completed_at"],
        }
        if action == "bootstrap-check":
            result = {
                "result": "already-reported",
                "checkRunId": check,
                "genesis": genesis,
            }
        elif action == "bootstrap-handoff":
            result = {
                "result": "unsigned-handoff-scope",
                "context": charge,
                "expiresNoLaterThan": expiry,
            }
        else:
            expiry = min(expiry, _quorum(handoff, charge, target))
            observed = instant(handoff["payload"]["issuedAt"])
            require(
                situation["guardActiveSince"] <= observed < situation["holdDisabledAt"]
                and instant(actual["completed_at"]) <= observed,
                "forge.continuity",
                "no independently authenticated pre-release overlap with a completed genesis check",
            )
            common = {
                "genesis": genesis,
                "tree": context["tree"],
                "ref": REF,
                "repositoryId": p["repositoryId"],
                "checkRunId": check,
                "authorizationSha256": seal,
                "handoffSha256": framed(handoff),
                "validBefore": expiry,
            }
            if action == "bootstrap-confirm":
                result = {
                    **common,
                    "result": "verified-genesis-readback",
                    "defaultBranch": situation["defaultBranch"],
                    "normalClosureVerified": situation["closureRulesetId"] is not None,
                }
            else:
                remote = "https://github.com/" + p["repository"] + ".git"
                result = {
                    **common,
                    "result": "proposal",
                    "action": "bootstrap-create",
                    "publisherAppId": p["publisherAppId"],
                    "expectedRef": "absent",
                    "argv": [
                        "git",
                        "-C",
                        target["localRepository"],
                        "push",
                        "--force-with-lease=" + REF + ":",
                        "--",
                        remote,
                        genesis + ":" + REF,
                    ],
                }
    require(
        local() == target
        and bootstrap_state(api, p, phase) == situation
        and bootstrap_apps(p, app_views) == installations
        and checks(api, root, genesis, p, seal) == check
        and time.time() < expiry,
        "forge.freshness",
        "rules, App check, custody, live evidence or ref changed",
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "rules",
            "audit",
            "audit-hold",
            "check-run",
            "mirror",
            "confirm",
            "bootstrap-rules",
            "bootstrap-context",
            "bootstrap-check",
            "bootstrap-handoff",
            "bootstrap-create",
            "bootstrap-confirm",
        ),
    )
    parser.add_argument("--enrollment", required=True, type=Path)
    admin_read = parser.add_mutually_exclusive_group()
    admin_read.add_argument("--token-file", type=Path)
    admin_read.add_argument(
        "--gh-read",
        action="store_true",
        help="use the currently selected github.com account from the local gh keyring for repository GETs",
    )
    parser.add_argument("--receiver", type=Path)
    parser.add_argument(
        "--gh-executable",
        type=Path,
        help="explicit absolute path to the independently installed gh CLI for --gh-read",
    )
    parser.add_argument("--event", choices=("pull_request", "merge_group"))
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--signature-file", type=Path)
    parser.add_argument("--webhook-secret", type=Path)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--handoff", type=Path)
    parser.add_argument("--check-app-jwt", type=Path)
    parser.add_argument("--publisher-app-jwt", type=Path)
    args = parser.parse_args()
    try:
        require(
            args.gh_executable is None or args.gh_read,
            "forge.credentials",
            "--gh-executable requires --gh-read",
        )
        policy = (hold_enrollment if args.action == "audit-hold" else enrollment)(
            load(args.enrollment)
        )
        if args.action == "bootstrap-rules":
            result = bootstrap_rules(policy)
        elif args.action == "rules":
            result = rulesets(policy)
        else:
            require(
                args.token_file is not None or args.gh_read,
                "forge.credentials",
                "select --gh-read or supply the enrolled --token-file",
            )
            api = (
                GhReadAPI(policy["repository"], args.gh_executable)
                if args.gh_read
                else ReadAPI(read(args.token_file, 4096).decode("ascii").strip())
            )
            if args.action == "audit-hold":
                result = audit_hold(api, policy)
            elif args.action == "audit":
                result = audit(api, policy)
            elif args.action.startswith("bootstrap-"):
                require(
                    args.receiver is not None,
                    "forge.genesis",
                    "supply the independent release receiver",
                )
                require(
                    args.check_app_jwt is not None
                    and args.publisher_app_jwt is not None,
                    "forge.installation",
                    "supply the selected checker and publisher App JWT files for restricted installation readback",
                )
                views = {
                    "check": ReadAPI(
                        read(args.check_app_jwt, 4096).decode("ascii").strip()
                    ),
                    "publisher": ReadAPI(
                        read(args.publisher_app_jwt, 4096).decode("ascii").strip()
                    ),
                }
                result = bootstrap_propose(
                    api,
                    policy,
                    lambda: qualified_genesis(args.receiver, policy),
                    args.action,
                    load(args.authorization) if args.authorization else None,
                    load(args.handoff) if args.handoff else None,
                    views,
                )
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
