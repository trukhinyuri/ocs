#!/usr/bin/env python3
"""Enroll two owner-installed GitHub Apps and issue short-lived repository-scoped credentials."""

import argparse
import base64
import contextlib
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

WEB = "https://github.com"
API = "https://api.github.com"
VERSION = "2022-11-28"
PERMISSIONS = {
    "reporter": {"metadata": "read", "contents": "read", "checks": "write"},
    "publisher": {"metadata": "read", "contents": "write", "checks": "read"},
}
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")
CLIENT = re.compile(r"[A-Za-z0-9_.-]{2,160}")
CODE = re.compile(r"[A-Za-z0-9_-]{8,160}")
HEX = re.compile(r"[0-9a-f]{64}")
KIND = {"user": "User", "organization": "Organization"}
LIMIT = 2 * 1024 * 1024


class Pending(ValueError):
    """The selected identity and repository grant are still unestablished."""


def require(ok, message):
    if not ok:
        raise Pending(message)


def positive(n):
    return type(n) is int and n > 0


def unique(pairs):
    data = {}
    for k, v in pairs:
        require(k not in data, "ambiguous JSON response")
        data[k] = v
    return data


def decoded(raw):
    def invalid(_):
        raise ValueError("invalid numeric response")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stamp(now):
    return (
        datetime.fromtimestamp(now, UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def epoch(text):
    value = datetime.fromisoformat(text)
    require(value.tzinfo is not None, "credential timestamp lacks a timezone")
    return value.timestamp()


def target(repository, repository_id, owner_id, owner_type):
    parts = repository.split("/")
    require(
        len(parts) == 2
        and OWNER.fullmatch(parts[0])
        and REPO.fullmatch(parts[1])
        and parts[1] not in (".", "..")
        and positive(repository_id)
        and positive(owner_id)
        and owner_type in KIND,
        "select an exact owner, repository and their numeric IDs",
    )
    return {
        "repository": repository,
        "repositoryId": repository_id,
        "ownerId": owner_id,
        "ownerType": owner_type,
    }


def identity_target(record):
    return target(
        record["repository"],
        record["repositoryId"],
        record["ownerId"],
        record["ownerType"],
    )


def permission_map(obj):
    require(
        type(obj) is dict
        and all(
            type(k) is str and v in ("none", "read", "write", "admin")
            for k, v in obj.items()
        ),
        "unrecognized permission response",
    )
    require(
        obj.get("metadata", "read") == "read",
        "invalid mandatory repository metadata permission",
    )
    # GitHub grants Metadata read access to every repository installation.
    return {"metadata": "read", **{k: v for k, v in obj.items() if v != "none"}}


def owner_ok(obj, t):
    return (
        isinstance(obj, dict)
        and obj.get("id") == t["ownerId"]
        and isinstance(obj.get("login"), str)
        and obj["login"].casefold() == t["repository"].split("/")[0].casefold()
        and obj.get("type") == KIND[t["ownerType"]]
    )


def repo_ok(row, t):
    return (
        isinstance(row, dict)
        and row.get("id") == t["repositoryId"]
        and isinstance(row.get("full_name"), str)
        and row["full_name"].casefold() == t["repository"].casefold()
        and owner_ok(row.get("owner"), t)
    )


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class APIClient:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), RejectRedirect()
        )

    def call(self, method, path, auth=None, body=None, *, operation):
        require(
            path.startswith("/")
            and not path.startswith("//")
            and "#" not in path
            and ".." not in path.split("?")[0].split("/"),
            "unexpected API origin",
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": VERSION,
            "User-Agent": "OCS-App-Custody",
            "Content-Type": "application/json",
        }
        if auth is not None:
            require(
                type(auth) is str
                and 0 < len(auth) <= 16384
                and all(32 < ord(c) < 127 for c in auth),
                "invalid App credential",
            )
            headers["Authorization"] = "Bearer " + auth
        req = urllib.request.Request(
            API + path,
            data=canonical(body) if body is not None else None,
            method=method,
            headers=headers,
        )
        try:
            with self.opener.open(req, timeout=20) as response:
                require(response.geturl() == API + path, "API origin changed")
                raw = response.read(LIMIT + 1)
        except urllib.error.HTTPError as e:
            raise Pending(f"{operation}: GitHub returned HTTP {e.code}") from None
        except (OSError, urllib.error.URLError):
            raise Pending(
                operation + ": authenticated GitHub readback unavailable"
            ) from None
        require(len(raw) <= LIMIT, "oversized GitHub response")
        try:
            return decoded(raw) if raw else {}
        except (ValueError, UnicodeError):
            raise Pending(operation + ": invalid GitHub response") from None


def private_dir(path, *, uid):
    path = Path(path).absolute()
    require(
        path.resolve(strict=True) == path and path.is_dir(),
        "choose a private regular custody directory",
    )
    facts = path.stat()
    require(
        facts.st_uid == uid and stat.S_IMODE(facts.st_mode) == 0o700,
        "custody needs its selected UID and mode 0700",
    )
    # A sibling principal with write access to a nonsticky ancestor could replace the entire custody.
    for parent in path.parents:
        s = parent.stat()
        require(
            s.st_uid in (0, uid)
            and (not s.st_mode & 0o022 or s.st_uid == 0 and s.st_mode & stat.S_ISVTX),
            "custody ancestor is writable by a different principal",
        )
    return path


def secret_file(path, uid, limit=65536):
    require(path.absolute() == path.resolve(strict=True), "linked credential path")
    with os.fdopen(
        os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb"
    ) as f:
        s = os.fstat(f.fileno())
        require(
            stat.S_ISREG(s.st_mode)
            and s.st_uid == uid
            and s.st_nlink == 1
            and stat.S_IMODE(s.st_mode) == 0o600
            and 0 < s.st_size <= limit,
            "unprotected or malformed custody file",
        )
        b = f.read(limit + 1)
        require(len(b) == s.st_size, "custody file changed during read")
        return b


def save_private(path, raw, *, replace=False):
    # An external consumer only ever sees a complete mode-0600 token or receipt.
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
            if replace:
                if path.exists() or path.is_symlink():
                    secret_file(path, os.geteuid())
                os.replace(tmp, path)
            else:
                os.link(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    sync_dir(path.parent)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_identity(custody, role, *, uid, verify_key=True):
    path = private_dir(custody, uid=uid)
    record = decoded(secret_file(path / "registration/app.json", uid))
    require(
        record["format"] == "ocs.safe-push.app-registration/1"
        and record["role"] == role
        and record["custodianUid"] == uid
        and permission_map(record["permissions"]) == PERMISSIONS[role]
        and positive(record["appId"])
        and SLUG.fullmatch(record["slug"])
        and CLIENT.fullmatch(record["clientId"])
        and HEX.fullmatch(record["publicKeySha256"])
        and identity_target(record),
        "registration belongs to another role or custodian",
    )
    if verify_key:
        pem = secret_file(path / "registration/private-key.pem", uid)
        require(
            public_fingerprint(pem) == record["publicKeySha256"],
            "App private key differs from the enrolled registration",
        )
    return record


def public_fingerprint(pem):
    require(
        len(pem) <= 32768
        and re.fullmatch(
            rb"\s*-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]+\s*-----END \1-----\s*",
            pem,
        ),
        "invalid App RSA private-key encoding",
    )
    info = subprocess.run(
        ["/usr/bin/openssl", "rsa", "-passin", "pass:", "-pubout", "-outform", "DER"],
        input=pem,
        capture_output=True,
        timeout=10,
        check=False,
    )
    require(
        info.returncode == 0 and len(info.stdout) >= 270,
        "expected a GitHub App RSA signing key",
    )
    return sha(info.stdout)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def sign_jwt(key, client_id, now):
    header = b64(canonical({"alg": "RS256", "typ": "JWT"}))
    body = b64(
        canonical({"iat": int(now) - 60, "exp": int(now) + 480, "iss": client_id})
    )
    signed = header + b"." + body
    proc = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", key],
        input=signed,
        capture_output=True,
        check=False,
        timeout=10,
    )
    require(proc.returncode == 0, "App JWT signing failed")
    return (signed + b"." + b64(proc.stdout)).decode("ascii")


def registration_record(response, role, t, uid):
    require(
        role in PERMISSIONS
        and positive(response.get("id"))
        and SLUG.fullmatch(response.get("slug", ""))
        and CLIENT.fullmatch(response.get("client_id", ""))
        and owner_ok(response.get("owner"), t)
        and permission_map(response["permissions"]) == PERMISSIONS[role]
        and response.get("events") == [],
        "registration did not establish the selected App owner and exact role permissions",
    )
    pem = response["pem"].encode("ascii")
    pub = public_fingerprint(pem)
    record = {
        "format": "ocs.safe-push.app-registration/1",
        "role": role,
        "custodianUid": uid,
        **t,
        "appId": response["id"],
        "clientId": response["client_id"],
        "slug": response["slug"],
        "permissions": PERMISSIONS[role],
        "publicKeySha256": pub,
    }
    return record, pem


def persist_registration(custody, record, pem):
    dest = custody / "registration"
    require(
        not dest.exists() and not dest.is_symlink(),
        "private registration is already enrolled",
    )
    with tempfile.TemporaryDirectory(dir=custody, prefix=".registration-") as temp:
        stage = Path(temp) / "registration"
        stage.mkdir(mode=0o700)
        save_private(stage / "app.json", canonical(record))
        save_private(stage / "private-key.pem", pem)
        os.rename(stage, dest)
        sync_dir(custody)


def app_readback(obj, ident):
    require(
        obj.get("id") == ident["appId"]
        and obj.get("slug") == ident["slug"]
        and obj.get("client_id") == ident["clientId"]
        and owner_ok(obj.get("owner"), ident)
        and permission_map(obj["permissions"]) == PERMISSIONS[ident["role"]]
        and obj.get("events") == [],
        "authenticated App or permissions differ from independent enrollment",
    )


def installation_readback(obj, ident, expected_id):
    require(
        positive(obj.get("id"))
        and (expected_id is None or obj["id"] == expected_id)
        and obj.get("app_id") == ident["appId"]
        and obj.get("app_slug") == ident["slug"]
        and obj.get("client_id", ident["clientId"]) == ident["clientId"]
        and obj.get("events") == []
        and owner_ok(obj.get("account"), ident)
        and obj.get("target_id") == ident["ownerId"]
        and obj.get("target_type") == KIND[ident["ownerType"]]
        and obj.get("repository_selection") == "selected"
        and "suspended_at" in obj
        and obj["suspended_at"] is None
        and permission_map(obj["permissions"]) == PERMISSIONS[ident["role"]],
        "installation is absent, suspended, for another owner, or exceeds the selected role/account",
    )
    return obj["id"]


def minted(api, jwt, iid, permissions, body, now):
    response = api.call(
        "POST",
        f"/app/installations/{iid}/access_tokens",
        jwt,
        body,
        operation="issue installation token",
    )
    token = response.get("token")
    require(
        isinstance(token, str)
        and 0 < len(token) <= 4096
        and all(32 < ord(c) < 127 for c in token),
        "installation token is unavailable",
    )
    try:
        require(
            permission_map(response["permissions"]) == permissions
            and now + 30 < epoch(response["expires_at"]) <= now + 3700,
            "installation token permissions or lifetime differ from requested scope",
        )
    except (KeyError, TypeError, ValueError):
        revoke(api, token)
        raise Pending("issued token had unexpected permissions or lifetime") from None
    return token, response["expires_at"]


def revoke(api, token):
    api.call(
        "DELETE",
        "/installation/token",
        token,
        operation="retire temporary discovery token",
    )


def only_repository(api, token, ident):
    view = api.call(
        "GET",
        "/installation/repositories?per_page=2",
        token,
        operation="read installation repositories",
    )
    rows = view.get("repositories")
    require(
        type(view.get("total_count")) is int
        and view["total_count"] == 1
        and isinstance(rows, list)
        and len(rows) == 1
        and repo_ok(rows[0], ident),
        "installation has a different or additional selected repository",
    )
    repo = api.call(
        "GET",
        "/repos/" + ident["repository"],
        token,
        operation="read exact repository and owner IDs",
    )
    require(
        repo_ok(repo, ident)
        and repo.get("archived") is False
        and repo.get("disabled") is False
        and repo.get("visibility") in ("public", "private")
        and repo.get("private") is (repo["visibility"] == "private"),
        "target repository is unavailable or differs from numeric enrollment",
    )

    return repo["visibility"]


def inspect_grant(api, custody, ident, expected_id, now):
    jwt = sign_jwt(custody / "registration/private-key.pem", ident["clientId"], now)
    app_readback(
        api.call("GET", "/app", jwt, operation="read authenticated App"), ident
    )
    match = api.call(
        "GET",
        "/repos/" + ident["repository"] + "/installation",
        jwt,
        operation="read repository installation",
    )
    iid = installation_readback(match, ident, expected_id)
    obj = api.call(
        "GET", f"/app/installations/{iid}", jwt, operation="read exact installation"
    )
    installation_readback(obj, ident, iid)
    # A token downscoped to this repository alone would conceal other repositories in the grant.
    permissions = {"metadata": "read"}
    discovery, _ = minted(api, jwt, iid, permissions, {"permissions": permissions}, now)
    try:
        visibility = only_repository(api, discovery, ident)
    finally:
        revoke(api, discovery)
    return jwt, iid, visibility


def bind(api, custody, role, *, expected_install=None):
    uid = os.geteuid()
    require(uid > 0, "run this command as the separate enrolled role custodian")
    ident = read_identity(custody, role, uid=uid)
    path = custody / "installation.json"
    old = None
    if path.exists() or path.is_symlink():
        old = decoded(secret_file(path, uid))
        require(
            old["appId"] == ident["appId"]
            and (expected_install is None or old["installationId"] == expected_install),
            "existing App installation pin differs",
        )
        expected_install = old["installationId"]
    _, iid, visibility = inspect_grant(
        api, custody, ident, expected_install, time.time()
    )
    receipt = {
        **ident,
        "format": "ocs.safe-push.app-installation/1",
        "installationId": iid,
        "repositoryVisibility": visibility,
    }
    if old:
        require(
            canonical(receipt) == canonical(old),
            "installation facts changed from their original pin",
        )
    else:
        save_private(path, canonical(receipt))
    return receipt


def role_receipt(custody, role, uid, *, verify_key=True):
    ident = read_identity(custody, role, uid=uid, verify_key=verify_key)
    result = decoded(secret_file(custody / "installation.json", uid))
    require(
        result
        == {
            **ident,
            "format": "ocs.safe-push.app-installation/1",
            "installationId": result.get("installationId"),
            "repositoryVisibility": result.get("repositoryVisibility"),
        }
        and result["repositoryVisibility"] in ("public", "private")
        and positive(result["installationId"]),
        "missing same-role installed grant",
    )
    return result


def assemble(reporter, publisher, project):
    require(
        isinstance(project, str)
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,96}", project),
        "invalid project",
    )
    require(
        reporter["role"] == "reporter"
        and publisher["role"] == "publisher"
        and identity_target(reporter) == identity_target(publisher)
        and reporter.get("repositoryVisibility") in ("public", "private")
        and reporter["repositoryVisibility"] == publisher.get("repositoryVisibility"),
        "two independent roles must serve the same selected repository",
    )
    for field in (
        "appId",
        "clientId",
        "installationId",
        "custodianUid",
        "publicKeySha256",
    ):
        require(
            reporter[field] != publisher[field], "reporter and publisher share " + field
        )
    require(
        all(
            positive(r["custodianUid"])
            and positive(r["installationId"])
            and positive(r["appId"])
            and permission_map(r["permissions"]) == PERMISSIONS[r["role"]]
            for r in (reporter, publisher)
        ),
        "one or both role grants lack exact independent custody",
    )
    return {
        "format": "ocs.safe-push.app-pins/1",
        "project": project,
        **identity_target(reporter),
        "repositoryVisibility": reporter["repositoryVisibility"],
        "roles": {r["role"]: r for r in (reporter, publisher)},
    }


def forge_policy(
    enrollment,
    visibility,
    phase,
    *,
    staging_ref=None,
    staging_commit=None,
    genesis=None,
    hold_id=None,
    integrity_id=None,
    writer_id=None,
    publisher_installation=None,
):
    one, two = enrollment["roles"]["reporter"], enrollment["roles"]["publisher"]
    require(
        assemble(one, two, enrollment["project"]) == enrollment,
        "inconsistent independent issuer pins",
    )
    require(
        visibility in ("public", "private")
        and visibility == enrollment["repositoryVisibility"],
        "explicit visibility differs from the two authenticated target readbacks",
    )
    ordinary = {
        "format": "ocs.safe-push.forge/2",
        "repository": enrollment["repository"],
        "repositoryId": enrollment["repositoryId"],
        "ownerId": enrollment["ownerId"],
        "project": enrollment["project"],
        "mode": "mirror",
        "checkAppId": one["appId"],
        "checkInstallationId": one["installationId"],
        "publisherAppId": two["appId"],
        "mergeQueue": False,
        "expectedVisibility": visibility,
        "bootstrap": None,
    }
    ids = (hold_id, integrity_id, writer_id)
    if phase == "initialized":
        require(
            all(
                v is None
                for v in (
                    staging_ref,
                    staging_commit,
                    genesis,
                    *ids,
                    publisher_installation,
                )
            ),
            "initialized policy received bootstrap-only arguments",
        )
        return ordinary
    require(
        phase in ("bootstrap-template", "bootstrap"),
        "choose an explicit enrollment phase",
    )
    require(
        isinstance(staging_ref, str)
        and staging_ref != "refs/heads/main"
        and re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,180}", staging_ref)
        and ".." not in staging_ref
        and all(
            v and not v.startswith(".") and not v.endswith((".lock", "."))
            for v in staging_ref.removeprefix("refs/heads/").split("/")
        ),
        "select the exact full staging branch ref",
    )
    require(
        all(
            isinstance(oid, str)
            and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", oid)
            and int(oid, 16)
            for oid in (staging_commit, genesis)
        )
        and len(staging_commit) == len(genesis)
        and staging_commit != genesis,
        "select distinct full staging and qualified genesis object IDs",
    )
    require(
        publisher_installation == two["installationId"],
        "select the independently read publisher installation ID",
    )
    bootstrap = {
        "stagingRef": staging_ref,
        "stagingCommit": staging_commit,
        "genesis": genesis,
        "holdRulesetId": hold_id,
        "integrityRulesetId": integrity_id,
        "writerRulesetId": writer_id,
        "publisherInstallationId": publisher_installation,
    }
    actual = {**ordinary, "bootstrap": bootstrap}
    if phase == "bootstrap-template":
        require(
            all(v is None for v in ids),
            "template must precede the server-assigned ruleset enrollment",
        )
        return {
            "format": "ocs.safe-push.forge-bootstrap-template/1",
            "status": "pending-ruleset-ids",
            "issuerPinsSha256": sha(canonical(enrollment)),
            "rulePlanInput": ordinary,
            "policyTemplate": actual,
            "requiredReadbacks": [
                "holdRulesetId",
                "integrityRulesetId",
                "writerRulesetId",
            ],
        }
    require(
        all(positive(v) for v in ids) and len(set(ids)) == 3,
        "independently read three distinct positive ruleset IDs",
    )
    return actual


def _authenticated_role(api, custody, role, pins):
    uid = os.geteuid()
    require(uid > 0, "run as the dedicated role owner")
    roles = pins["roles"]
    require(
        assemble(roles["reporter"], roles["publisher"], pins["project"]) == pins,
        "inconsistent independent issuer pins",
    )
    ident = role_receipt(custody, role, uid)
    require(
        ident == roles[role],
        "local authority differs from the independently enrolled App",
    )
    now = time.time()
    jwt, iid, current_visibility = inspect_grant(
        api, custody, ident, ident["installationId"], now
    )
    require(
        current_visibility == ident["repositoryVisibility"],
        "repository visibility differs from independent enrollment",
    )
    return ident, jwt, iid, now


def _selected_token(api, role, ident, jwt, iid, now):
    required = PERMISSIONS[role]
    access, until = minted(
        api,
        jwt,
        iid,
        required,
        {"repository_ids": [ident["repositoryId"]], "permissions": required},
        now,
    )
    try:
        require(
            only_repository(api, access, ident) == ident["repositoryVisibility"],
            "repository visibility changed during issuance",
        )
    except BaseException:
        revoke(api, access)
        raise
    return access, until


@contextlib.contextmanager
def installation_session(api, custody, role, pins):
    """Yield the genuine scoped installation bearer in memory, then revoke it on exit."""
    ident, jwt, iid, now = _authenticated_role(api, custody, role, pins)
    token, until = _selected_token(api, role, ident, jwt, iid, now)
    try:
        yield token, until
    finally:
        revoke(api, token)


def issue(api, custody, role, pins, *, assertion=False):
    ident, jwt, iid, now = _authenticated_role(api, custody, role, pins)
    if assertion:
        save_private(custody / "app.jwt", (jwt + "\n").encode("ascii"), replace=True)
        return {
            "role": role,
            "appId": ident["appId"],
            "installationId": iid,
            "repositoryId": ident["repositoryId"],
            "expiresAt": stamp(int(now) + 480),
            "appJwtFile": str(custody / "app.jwt"),
        }

    access, until = _selected_token(api, role, ident, jwt, iid, now)
    try:
        save_private(
            custody / "installation.token",
            (access + "\n").encode("ascii"),
            replace=True,
        )
    except BaseException:
        revoke(api, access)
        raise
    return {
        "role": role,
        "appId": ident["appId"],
        "installationId": iid,
        "repositoryId": ident["repositoryId"],
        "expiresAt": until,
        "tokenFile": str(custody / "installation.token"),
    }


def install_url(record):
    require(SLUG.fullmatch(record["slug"]), "invalid GitHub App slug")
    return WEB + "/apps/" + record["slug"] + "/installations/new"


class Registration:
    def __init__(self, role, t, name, custody, api, ttl):
        require(
            role in PERMISSIONS and 60 <= ttl <= 3600,
            "registration window must be 60–3600 seconds",
        )
        require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 -]{1,33}", name),
            "App name must use 2–34 letters, digits, spaces or hyphens",
        )
        self.role, self.t, self.name, self.custody, self.api = (
            role,
            t,
            name,
            custody,
            api,
        )
        self.entry = secrets.token_urlsafe(32)
        self.state = secrets.token_urlsafe(32)
        self.callback = secrets.token_urlsafe(24)
        self.cookie = secrets.token_urlsafe(32)
        self.until = time.monotonic() + ttl
        self.expires = stamp(time.time() + ttl)
        self.used = False
        self.record = None
        self.fail = None

    def resource(self, port):
        origin = f"http://127.0.0.1:{port}"
        callback = "/complete/" + self.callback
        manifest = {
            "name": self.name,
            "url": WEB + "/" + self.t["repository"],
            "description": "Independent OCS "
            + self.role
            + " for "
            + self.t["repository"],
            "redirect_url": origin + callback,
            "public": False,
            "request_oauth_on_install": False,
            "default_events": [],
            "default_permissions": {
                k: v for k, v in PERMISSIONS[self.role].items() if k != "metadata"
            },
        }
        owner = self.t["repository"].split("/")[0]
        start = (
            "/settings/apps/new"
            if self.t["ownerType"] == "user"
            else "/organizations/" + owner + "/settings/apps/new"
        )
        action = WEB + start + "?" + urllib.parse.urlencode({"state": self.state})
        return origin, callback, manifest, action

    def accept(self, query, cookie):
        require(
            time.monotonic() < self.until and not self.used,
            "registration challenge expired or consumed",
        )
        params = urllib.parse.parse_qs(
            query, keep_blank_values=True, strict_parsing=True, max_num_fields=4
        )
        require(
            set(params) == {"state", "code"}
            and len(params["state"]) == len(params["code"]) == 1
            and hmac.compare_digest(params["state"][0], self.state)
            and CODE.fullmatch(params["code"][0])
            and isinstance(cookie, str)
            and hmac.compare_digest(cookie, self.cookie),
            "invalid browser registration challenge",
        )
        self.used = True
        try:
            response = self.api.call(
                "POST",
                "/app-manifests/" + params["code"][0] + "/conversions",
                operation="exchange the owner-approved registration",
            )
            record, pem = registration_record(response, self.role, self.t, os.geteuid())
            persist_registration(self.custody, record, pem)
            self.record = record
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            subprocess.SubprocessError,
        ) as e:
            self.fail = "App credentials could not be enrolled; verify the owner’s registration and recover its key"
            raise Pending(self.fail) from e


def page(title, body):
    return (
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        + "<title>"
        + html.escape(title)
        + "</title><h1>"
        + html.escape(title)
        + "</h1>"
        + body
        + "</html>"
    ).encode()


class LoopbackServer(http.server.HTTPServer):
    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(6)
        return sock, addr


class Callback(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        # Callback query strings include a single-use credential.
        pass

    def reply(self, code, body, *, cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action https://github.com",
        )
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(body)

    def do_GET(self):
        flow = self.server.flow
        host = "127.0.0.1:" + str(self.server.server_port)
        origin, callback, manifest, action = flow.resource(self.server.server_port)
        try:
            require(
                self.client_address[0] == "127.0.0.1"
                and self.headers.get_all("Host") == [host],
                "loopback Host required",
            )
            require(
                len(self.path) <= 2048
                and self.path.startswith("/")
                and not self.path.startswith("//"),
                "invalid local path",
            )
            path = urllib.parse.urlsplit(self.path)
            require(
                not (path.netloc or path.fragment or path.scheme),
                "invalid local request target",
            )
            allowed = [origin, WEB] if path.path == callback else [origin]
            request_origin = self.headers.get_all("Origin") or []
            require(
                not request_origin
                or (len(request_origin) == 1 and request_origin[0] in allowed),
                "untrusted browser origin",
            )
            require(
                time.monotonic() < flow.until and not flow.used,
                "registration expired or already handled",
            )
            if path.path == "/start/" + flow.entry and not path.query:
                perms = ", ".join(
                    k + " " + v for k, v in PERMISSIONS[flow.role].items()
                )
                body = (
                    "<p>Repository "
                    + html.escape(flow.t["repository"])
                    + " (ID "
                    + str(flow.t["repositoryId"])
                    + "). This private App will request "
                    + html.escape(perms)
                    + ".</p>"
                    + '<form method="post" action="'
                    + html.escape(action, quote=True)
                    + '">'
                    + '<input type="hidden" name="manifest" value="'
                    + html.escape(json.dumps(manifest), quote=True)
                    + '">'
                    + '<button type="submit">Review registration on GitHub</button></form>'
                )
                self.reply(
                    200,
                    page("Register the OCS " + flow.role, body),
                    cookie="ocs_registration="
                    + flow.cookie
                    + "; Path="
                    + callback
                    + "; HttpOnly; SameSite=Lax",
                )
                return
            if path.path == callback:
                jar = http.cookies.SimpleCookie()
                parts = self.headers.get_all("Cookie") or []
                require(len(parts) == 1, "browser session cookie required")
                jar.load(parts[0])
                state_cookie = jar.get("ocs_registration")
                flow.accept(path.query, state_cookie.value if state_cookie else None)
                install = install_url(flow.record)
                body = (
                    "<p>Choose only <strong>"
                    + html.escape(flow.t["repository"])
                    + "</strong> on the installation page.</p>"
                    + '<p><a href="'
                    + html.escape(install, quote=True)
                    + '">Review installation on GitHub</a></p>'
                )
                self.reply(200, page("App registered", body))
                return
            self.reply(404, page("Unavailable", ""))
        except (
            ValueError,
            TypeError,
            KeyError,
            http.cookies.CookieError,
            UnicodeError,
        ):
            self.reply(
                403,
                page(
                    "Registration unavailable",
                    "Use the current approval link in its original browser.",
                ),
            )


def interact(custody, role, t, name, port, ttl):
    require(
        type(port) is int and 0 <= port <= 65535, "invalid IPv4 loopback listener port"
    )
    require(
        not (custody / "registration").exists(),
        "this role already has an enrolled App; use install-link or bind",
    )
    flow = Registration(role, t, name, custody, APIClient(), ttl)
    with LoopbackServer(("127.0.0.1", port), Callback) as server:
        server.flow = flow
        server.timeout = 1
        origin = flow.resource(server.server_port)[0]
        print(
            json.dumps(
                {
                    "status": "pending-owner-registration",
                    "role": role,
                    "repository": t["repository"],
                    "appName": name,
                    "permissions": PERMISSIONS[role],
                    "expiresAt": flow.expires,
                    "loopbackApprovalUrl": origin + "/start/" + flow.entry,
                }
            ),
            flush=True,
        )
        while time.monotonic() < flow.until and not flow.used:
            server.handle_request()
    require(
        flow.record is not None, flow.fail or "owner registration has not completed"
    )
    return {
        "status": "pending-owner-installation",
        "role": role,
        "repository": t["repository"],
        "appId": flow.record["appId"],
        "installationApprovalUrl": install_url(flow.record),
    }


@contextlib.contextmanager
def role_lock(custody):
    import fcntl

    uid = os.geteuid()
    require(uid > 0, "select an independent non-root role custodian")
    path = private_dir(custody, uid=uid)
    fd = os.open(
        path / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        s = os.fstat(fd)
        require(
            stat.S_ISREG(s.st_mode)
            and s.st_uid == uid
            and stat.S_IMODE(s.st_mode) == 0o600
            and s.st_nlink == 1,
            "unsafe role lock",
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Pending(
                "another enrollment or token operation still holds this role"
            ) from None
        yield path
    finally:
        os.close(fd)


def admin_parent(path):
    require(
        path.is_absolute() and path.is_dir() and path.resolve(strict=True) == path,
        "select a root-owned enrollment directory",
    )
    for item in (path, *path.parents):
        s = item.stat()
        require(
            s.st_uid == 0
            and (not s.st_mode & 0o022 or (s.st_mode & stat.S_ISVTX and item != path)),
            "issuer policy must be independently root-owned",
        )


def read_pins(path):
    admin_parent(path.parent)
    fact = path.lstat()
    require(
        stat.S_ISREG(fact.st_mode)
        and fact.st_uid == 0
        and not fact.st_mode & 0o022
        and fact.st_nlink == 1
        and 1 <= fact.st_size <= 65536,
        "issuer pin file is administratively unprotected",
    )
    return decoded(path.read_bytes())


def independently_observed(custody, role, uid):
    # The administrative process sees public identity receipts only. Re-authentication
    # occurs under the selected role UID using that role's private key.
    local = role_receipt(custody, role, uid, verify_key=False)
    script = Path(__file__).resolve()
    admin_parent(script.parent)
    facts = script.stat()
    require(
        facts.st_uid == 0 and not facts.st_mode & 0o022,
        "install the reviewed App custodian program under administrative ownership",
    )
    account = pwd.getpwuid(uid)
    proc = subprocess.run(
        [
            "/usr/bin/setpriv",
            "--reuid=" + str(uid),
            "--regid=" + str(account.pw_gid),
            "--clear-groups",
            "--no-new-privs",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "/usr/bin/python3",
            "-I",
            "-B",
            script,
            "bind",
            "--role",
            role,
            "--custody",
            custody.absolute(),
            "--installation-id",
            str(local["installationId"]),
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
        capture_output=True,
        timeout=180,
        check=False,
    )
    require(
        proc.returncode == 0 and len(proc.stdout) <= 65536,
        "independent authenticated installation readback is pending for " + role,
    )
    require(
        decoded(proc.stdout) == local,
        "live authenticated grant differs from its original role receipt",
    )
    return local


def enroll(directory, reporter, publisher, project):
    require(
        os.geteuid() == 0,
        "the independent issuer enrollment belongs to the administrator",
    )
    directory = directory.absolute()
    admin_parent(directory.parent)
    require(
        reporter[1] != publisher[1]
        and all(positive(uid) for _, uid in (reporter, publisher)),
        "use different non-root custodians",
    )
    credentials = [
        independently_observed(path, role, uid)
        for role, (path, uid) in (("reporter", reporter), ("publisher", publisher))
    ]
    pins = assemble(*credentials, project)
    outputs = {"app-pins.json": pins}
    if directory.exists() or directory.is_symlink():
        admin_parent(directory)
        require(
            {p.name for p in directory.iterdir()} == set(outputs),
            "use a fresh directory for immutable App issuer pins",
        )
        require(
            all(
                read_pins(directory / name) == value for name, value in outputs.items()
            ),
            "existing issuer pins differ",
        )
    else:
        with tempfile.TemporaryDirectory(
            dir=directory.parent, prefix=".ocs-enrollment-"
        ) as temp:
            prepared = Path(temp) / "enrollment"
            prepared.mkdir(mode=0o755)
            for name, record in outputs.items():
                f = prepared / name
                with f.open("xb") as out:
                    out.write(canonical(record))
                    out.flush()
                    os.fchmod(out.fileno(), 0o444)
                    os.fsync(out.fileno())
            sync_dir(prepared)
            os.rename(prepared, directory)
            sync_dir(directory.parent)
    return {
        "status": "app-identities-enrolled",
        "issuerPins": str(directory / "app-pins.json"),
        "repositoryId": pins["repositoryId"],
        "reporterAppId": credentials[0]["appId"],
        "publisherAppId": credentials[1]["appId"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmd = parser.add_subparsers(dest="action", required=True)
    for verb in ("register", "install-link", "bind", "token", "jwt", "adopt"):
        p = cmd.add_parser(verb)
        p.add_argument("--role", choices=PERMISSIONS, required=True)
        p.add_argument("--custody", type=Path, required=True)
        if verb in ("register", "adopt"):
            p.add_argument("--repository", required=True)
            p.add_argument("--repository-id", type=int, required=True)
            p.add_argument("--owner-id", type=int, required=True)
            p.add_argument("--owner-type", choices=KIND, required=True)
        if verb == "register":
            p.add_argument("--name")
            p.add_argument("--port", type=int, default=0)
            p.add_argument("--ttl", type=int, default=1800)
        if verb == "bind":
            p.add_argument("--installation-id", type=int)
        if verb in ("token", "jwt"):
            p.add_argument("--pins", type=Path, required=True)
        if verb == "adopt":
            p.add_argument("--app-id", type=int, required=True)
            p.add_argument("--client-id", required=True)
            p.add_argument("--pem-file", type=Path, required=True)
    p = cmd.add_parser("enrollment")
    for role in PERMISSIONS:
        p.add_argument("--" + role + "-custody", type=Path, required=True)
        p.add_argument("--" + role + "-uid", type=int, required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p = cmd.add_parser("policy")
    p.add_argument("--pins", type=Path, required=True)
    p.add_argument(
        "--expected-visibility", choices=("public", "private"), required=True
    )
    p.add_argument(
        "--phase",
        choices=("initialized", "bootstrap-template", "bootstrap"),
        required=True,
    )
    p.add_argument("--staging-ref")
    p.add_argument("--staging-commit")
    p.add_argument("--genesis")
    for name in (
        "hold-ruleset-id",
        "integrity-ruleset-id",
        "writer-ruleset-id",
        "publisher-installation-id",
    ):
        p.add_argument("--" + name, type=int)
    args = parser.parse_args()
    if args.action == "policy":
        result = forge_policy(
            read_pins(args.pins.absolute()),
            args.expected_visibility,
            args.phase,
            staging_ref=args.staging_ref,
            staging_commit=args.staging_commit,
            genesis=args.genesis,
            hold_id=args.hold_ruleset_id,
            integrity_id=args.integrity_ruleset_id,
            writer_id=args.writer_ruleset_id,
            publisher_installation=args.publisher_installation_id,
        )
    elif args.action == "enrollment":
        result = enroll(
            args.output_dir,
            (args.reporter_custody, args.reporter_uid),
            (args.publisher_custody, args.publisher_uid),
            args.project,
        )
    else:
        with role_lock(args.custody) as custody:
            if args.action in ("register", "adopt"):
                desired = target(
                    args.repository, args.repository_id, args.owner_id, args.owner_type
                )
            if args.action == "register":
                result = interact(
                    custody,
                    args.role,
                    desired,
                    args.name
                    or ("OCS " + args.role.title() + " " + secrets.token_hex(4)),
                    args.port,
                    args.ttl,
                )
            elif args.action == "install-link":
                record = read_identity(custody, args.role, uid=os.geteuid())
                result = {
                    "status": "pending-until-grant-readback",
                    "appId": record["appId"],
                    "installationApprovalUrl": install_url(record),
                }
            elif args.action == "bind":
                result = bind(
                    APIClient(),
                    custody,
                    args.role,
                    expected_install=args.installation_id,
                )
            elif args.action == "adopt":
                require(
                    not (custody / "registration").exists()
                    and args.pem_file.parent.resolve() == custody
                    and positive(args.app_id)
                    and CLIENT.fullmatch(args.client_id),
                    "select the original App and its protected PEM in its role directory",
                )
                pem = secret_file(args.pem_file, os.geteuid())
                jwt = sign_jwt(args.pem_file, args.client_id, time.time())
                obj = APIClient().call(
                    "GET", "/app", jwt, operation="verify owner-supplied App identity"
                )
                require(
                    obj.get("id") == args.app_id
                    and obj.get("client_id") == args.client_id,
                    "foreign App key or client",
                )
                ident, key = registration_record(
                    {**obj, "pem": pem.decode("ascii")},
                    args.role,
                    desired,
                    os.geteuid(),
                )
                persist_registration(custody, ident, key)
                result = {
                    "status": "registered-key-verified",
                    "appId": ident["appId"],
                    "installationApprovalUrl": install_url(ident),
                }
            else:
                result = issue(
                    APIClient(),
                    custody,
                    args.role,
                    read_pins(args.pins.absolute()),
                    assertion=args.action == "jwt",
                )
    print(json.dumps(result, sort_keys=True, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as e:
        # Invalid provider input can contain credential-shaped data. Emit only our own bounded diagnostics.
        reason = (
            str(e)
            if isinstance(e, Pending)
            else "required independent custody, enrollment or authenticated readback is unavailable"
        )
        print(
            json.dumps({"status": "pending/not-qualified", "reason": reason[:350]}),
            file=sys.stderr,
        )
        sys.exit(1)
