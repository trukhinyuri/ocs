"""Control the official App protocol with a loopback browser and an in-memory GitHub verifier."""

import base64
import copy
import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from safe_push import forge_apps as apps


class FixtureAPI:
    def __init__(self, tmp, role, pem, public):
        self.tmp, self.role, self.pem, self.public = tmp, role, pem, public
        self.t = apps.target("fixture/standard", 41, 7, "user")
        self.owner = {"id": 7, "login": "fixture", "type": "User"}
        self.app = {
            "id": 68 if role == "reporter" else 69,
            "slug": "fixture-" + role,
            "client_id": "Iv1." + role + "abcd",
            "owner": self.owner,
            "permissions": dict(apps.PERMISSIONS[role]),
            "events": [],
        }
        self.authenticated_client_id = self.app["client_id"]
        self.install = {
            "id": 188 if role == "reporter" else 189,
            "app_id": self.app["id"],
            "app_slug": self.app["slug"],
            "account": self.owner,
            "target_id": 7,
            "target_type": "User",
            "repository_selection": "selected",
            "permissions": dict(apps.PERMISSIONS[role]),
            "suspended_at": None,
            "events": [],
        }
        self.repo = {
            "id": 41,
            "full_name": "fixture/standard",
            "owner": self.owner,
            "visibility": "public",
            "private": False,
            "archived": False,
            "disabled": False,
        }
        self.repos = [self.repo]
        self.tokens = {}
        self.sent = []
        self.conversions = 0
        self.revoked = []
        self.posts = 0

    def verify_jwt(self, token):
        parts = token.split(".")
        assert len(parts) == 3

        def decode(p):
            return base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))

        assert json.loads(decode(parts[0])) == {"alg": "RS256", "typ": "JWT"}
        c = json.loads(decode(parts[1]))
        assert (
            c["iss"] == self.authenticated_client_id
            and c["iat"] < time.time() < c["exp"] <= time.time() + 600
        )
        sig = self.tmp / "jwt.sig"
        sig.write_bytes(decode(parts[2]))
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", self.public, "-signature", sig],
            input=(".".join(parts[:2])).encode("ascii"),
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, "App JWT was not genuinely signed by this role"

    def call(self, method, path, auth=None, body=None, *, operation):
        self.sent.append((method, path, copy.deepcopy(body)))
        if path.startswith("/app-manifests/"):
            assert method == "POST" and auth is None
            self.conversions += 1
            return {
                **copy.deepcopy(self.app),
                "pem": self.pem.decode("ascii"),
                "client_secret": "unused-client-secret",
                "webhook_secret": "unused-hook-secret",
            }
        if path == "/installation/token":
            assert method == "DELETE" and auth in self.tokens
            self.revoked.append(auth)
            del self.tokens[auth]
            return {}
        if path.startswith("/installation/repositories"):
            assert auth in self.tokens
            rows = (
                self.repos
                if self.tokens[auth] is None
                else [r for r in self.repos if r["id"] in self.tokens[auth]]
            )
            return {"total_count": len(rows), "repositories": copy.deepcopy(rows[:2])}
        if path == "/repos/fixture/standard":
            assert auth in self.tokens
            return copy.deepcopy(self.repo)
        self.verify_jwt(auth)
        if path == "/app":
            return copy.deepcopy(self.app)
        if path in (
            "/repos/fixture/standard/installation",
            "/app/installations/" + str(self.install["id"]),
        ):
            return copy.deepcopy(self.install)
        assert (
            method == "POST"
            and path == f"/app/installations/{self.install['id']}/access_tokens"
        )
        self.posts += 1
        new = "fixture-token-" + str(self.posts)
        self.tokens[new] = body.get("repository_ids")
        return {
            "permissions": body["permissions"],
            "token": new,
            "expires_at": apps.stamp(time.time() + 3600),
        }


class GitHubAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = {}
        for role in apps.PERMISSIONS:
            pem = subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                ],
                capture_output=True,
                check=True,
                timeout=20,
            ).stdout
            pub = subprocess.run(
                ["openssl", "pkey", "-pubout"],
                input=pem,
                capture_output=True,
                check=True,
                timeout=8,
            ).stdout
            cls.material[role] = (pem, pub)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.t = apps.target("fixture/standard", 41, 7, "user")
        self.fakes = {}
        self.custody = {}
        self.ident = {}
        for role, (pem, pub) in self.material.items():
            c = self.root / role
            c.mkdir(mode=0o700)
            self.custody[role] = c
            f = self.root / (role + ".pub")
            f.write_bytes(pub)
            api = FixtureAPI(self.root, role, pem, f)
            self.fakes[role] = api
            self.ident[role], _ = apps.registration_record(
                {**api.app, "pem": pem.decode()}, role, self.t, os.geteuid()
            )

    def register_private(self, role):
        apps.persist_registration(
            self.custody[role], self.ident[role], self.material[role][0]
        )

    def browser(self, flow):
        server = apps.LoopbackServer(("127.0.0.1", 0), apps.Callback)
        server.flow = flow
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        thread.start()

        def close():
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()

        self.addCleanup(close)

        def request(path, headers=None):
            client = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=4
            )
            try:
                client.request("GET", path, headers=headers or {})
                response = client.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                client.close()

        return server, request

    def test_browser_owner_form_cookie_state_origin_and_replay(self):
        api = self.fakes["reporter"]
        c = self.custody["reporter"]
        flow = apps.Registration("reporter", self.t, "Fixture Role", c, api, 300)
        server, req = self.browser(flow)
        origin, callback, manifest, action = flow.resource(server.server_port)
        self.assertTrue(
            action.startswith("https://github.com/settings/apps/new?state=")
        )
        self.assertEqual(
            manifest["default_permissions"], {"checks": "write", "contents": "read"}
        )
        self.assertFalse(manifest["public"])
        self.assertFalse(manifest["request_oauth_on_install"])
        start = "/start/" + flow.entry
        self.assertEqual(req(start, {"Host": "untrusted.example"})[0], 403)
        self.assertEqual(req(start, {"Origin": "https://untrusted.example"})[0], 403)
        status, h, content = req(start)
        self.assertEqual(status, 200)
        self.assertTrue(action.encode() in content)
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["Cache-Control"], "no-store")
        cookie = h["Set-Cookie"].split(";", 1)[0]
        self.assertFalse((c / "registration").exists())
        self.assertEqual(api.conversions, 0)
        url = callback + "?state=" + flow.state + "&code=ownerapprovedABCDEFGHIJKLMNOP"
        for path, headers in (
            (url, {}),
            (url, {"Cookie": "ocs_registration=another"}),
            (url + "&state=duplicate", {"Cookie": cookie}),
            (url, {"Cookie": cookie, "Origin": "https://other.invalid"}),
            (url.replace(flow.state, "invalidstate"), {"Cookie": cookie}),
        ):
            self.assertEqual(req(path, headers)[0], 403)
        self.assertEqual(api.conversions, 0)
        status, _, doc = req(url, {"Cookie": cookie, "Origin": "https://github.com"})
        self.assertEqual(status, 200)
        self.assertIn(apps.install_url(self.ident["reporter"]).encode(), doc)
        self.assertNotIn(b"PRIVATE KEY", doc)
        self.assertNotIn(b"unused-client-secret", doc)
        self.assertEqual(api.conversions, 1)
        self.assertEqual(req(url, {"Cookie": cookie})[0], 403)
        info = apps.read_identity(c, "reporter", uid=os.geteuid())
        self.assertEqual(info, self.ident["reporter"])
        self.assertEqual(
            (c / "registration/private-key.pem").stat().st_mode & 0o777, 0o600
        )
        self.assertNotIn("secret", json.dumps(info).lower())
        self.assertEqual(origin, "http://127.0.0.1:" + str(server.server_port))

    def test_expired_and_foreign_owner_conversion_cannot_enroll(self):
        api = self.fakes["publisher"]
        c = self.custody["publisher"]
        f = apps.Registration("publisher", self.t, "Publisher Role", c, api, 60)
        f.until = time.monotonic() - 1
        q = "state=" + f.state + "&code=temporaryABC"
        with self.assertRaises(apps.Pending):
            f.accept(q, f.cookie)
        self.assertEqual(api.conversions, 0)
        f.until = time.monotonic() + 60
        api.app["owner"] = {**api.owner, "id": 8}
        with self.assertRaises(apps.Pending):
            f.accept(q, f.cookie)
        self.assertFalse((c / "registration").exists())
        self.assertTrue(f.used)

    def test_genuine_fixture_jwt_and_repository_wide_visibility(self):
        role = "reporter"
        self.register_private(role)
        api = self.fakes[role]
        jwt, iid, visibility = apps.inspect_grant(
            api, self.custody[role], self.ident[role], 188, time.time()
        )
        self.assertEqual((iid, visibility), (188, "public"))
        api.verify_jwt(jwt)
        post = next(pkt for pkt in api.sent if pkt[0] == "POST")
        self.assertEqual(post[2], {"permissions": {"metadata": "read"}})
        self.assertEqual(len(api.revoked), 1)
        api.repos += [{**api.repo, "id": 43, "full_name": "fixture/extra"}]
        with self.assertRaisesRegex(apps.Pending, "additional"):
            apps.inspect_grant(
                api, self.custody[role], self.ident[role], 188, time.time()
            )
        self.assertEqual(len(api.revoked), 2)
        self.assertEqual(api.tokens, {})

    def test_token_is_role_signed_narrowed_and_only_written_privately(self):
        if os.geteuid() == 0:
            self.skipTest("production issuance requires a non-root role UID")
        role = "reporter"
        self.register_private(role)
        api = self.fakes[role]
        one = apps.bind(api, self.custody[role], role)
        other = {
            **self.ident["publisher"],
            "format": "ocs.safe-push.app-installation/1",
            "custodianUid": os.geteuid() + 1,
            "installationId": 189,
            "repositoryVisibility": "public",
        }
        pins = apps.assemble(one, other, "ocs")
        result = apps.issue(api, self.custody[role], role, pins)
        secret = (self.custody[role] / "installation.token").read_text().strip()
        self.assertEqual(api.tokens[secret], [41])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(
            (self.custody[role] / "installation.token").stat().st_mode & 0o777, 0o600
        )
        self.assertIn(
            (
                "POST",
                "/app/installations/188/access_tokens",
                {"repository_ids": [41], "permissions": apps.PERMISSIONS[role]},
            ),
            api.sent,
        )
        self.assertEqual(
            apps.forge_policy(pins, "public", "initialized")["publisherAppId"],
            other["appId"],
        )
        with self.assertRaises((ValueError, FileNotFoundError)):
            apps.issue(api, self.custody[role], "publisher", pins)
        self.assertEqual(apps.bind(api, self.custody[role], role), one)
        with self.assertRaisesRegex(apps.Pending, "pin"):
            apps.bind(api, self.custody[role], role, expected_install=999)

    def test_changed_role_owner_repo_suspension_selection_and_installation_hold(self):
        role = "publisher"
        self.register_private(role)
        a = self.fakes[role]
        c = self.custody[role]
        cases = (
            (
                "app",
                "permissions",
                {**apps.PERMISSIONS[role], "administration": "write"},
            ),
            ("app", "client_id", "other-client"),
            ("install", "repository_selection", "all"),
            ("install", "suspended_at", "2026-04-01T00:00:00Z"),
            ("install", "app_id", 777),
            ("install", "target_id", 800),
            ("install", "permissions", {**apps.PERMISSIONS[role], "checks": "write"}),
            ("repo", "id", 45),
            ("repo", "owner", {**a.owner, "id": 3}),
            ("repo", "archived", True),
        )
        for loc, key, val in cases:
            obj = getattr(a, loc)
            before = obj[key]
            with self.subTest(loc=loc, key=key):
                obj[key] = val
                with self.assertRaises(apps.Pending):
                    apps.inspect_grant(a, c, self.ident[role], 189, time.time())
                obj[key] = before
        self.assertFalse((c / "installation.token").exists())

    def test_independent_issuer_fields_cannot_be_collapsed(self):
        rec = {
            role: {
                **i,
                "format": "ocs.safe-push.app-installation/1",
                "installationId": 188 + index,
                "repositoryVisibility": "public",
                "custodianUid": 1010 + index,
            }
            for index, (role, i) in enumerate(self.ident.items())
        }
        one, two = rec["reporter"], rec["publisher"]
        self.assertEqual(apps.assemble(one, two, "ocs")["roles"]["reporter"], one)
        for key in (
            "custodianUid",
            "appId",
            "installationId",
            "publicKeySha256",
            "clientId",
        ):
            with self.subTest(key=key), self.assertRaisesRegex(apps.Pending, "share"):
                apps.assemble(one, {**two, key: one[key]}, "ocs")
        with self.assertRaises(apps.Pending):
            apps.assemble(one, {**two, "repositoryId": 45}, "ocs")

    def test_public_template_and_late_bound_forge2_bootstrap(self):
        from safe_push import forge

        installed = {}
        for i, (role, identity) in enumerate(self.ident.items()):
            installed[role] = {
                **identity,
                "format": "ocs.safe-push.app-installation/1",
                "installationId": 188 + i,
                "custodianUid": 1101 + i,
                "repositoryVisibility": "public",
            }
        pins = apps.assemble(installed["reporter"], installed["publisher"], "ocs")
        chosen = {
            "staging_ref": "refs/heads/review-before-main",
            "staging_commit": "1" * 40,
            "genesis": "2" * 40,
            "publisher_installation": 189,
        }
        draft = apps.forge_policy(pins, "public", "bootstrap-template", **chosen)
        self.assertEqual(draft["status"], "pending-ruleset-ids")
        self.assertEqual(
            forge.enrollment(draft["rulePlanInput"])["expectedVisibility"], "public"
        )
        self.assertIsNone(draft["policyTemplate"]["bootstrap"]["integrityRulesetId"])
        with self.assertRaises(ValueError):
            forge.enrollment(draft["policyTemplate"])
        rule_plan = forge.bootstrap_rule_plan(draft["rulePlanInput"])
        self.assertEqual(set(rule_plan), {"hold", "permanent", "closure"})
        ids = {"hold_id": 818, "integrity_id": 823, "writer_id": 829}
        current = apps.forge_policy(pins, "public", "bootstrap", **chosen, **ids)
        self.assertEqual(forge.enrollment(current), current)
        self.assertEqual(forge.rulesets(current)[:2], rule_plan["permanent"])
        self.assertEqual(current["bootstrap"]["publisherInstallationId"], 189)
        self.assertEqual(
            current["bootstrap"]["stagingRef"], "refs/heads/review-before-main"
        )
        initial_hash = apps.sha(apps.canonical(pins))
        for change in (
            {"writer_id": None},
            {"hold_id": 823},
            {"publisher_installation": 188},
            {"staging_ref": "refs/heads/main"},
            {"staging_commit": "2" * 40},
        ):
            with self.subTest(change=change), self.assertRaises(apps.Pending):
                apps.forge_policy(
                    pins, "public", "bootstrap", **(chosen | ids | change)
                )
        with self.assertRaises(apps.Pending):
            apps.forge_policy(pins, "private", "initialized")
        self.assertEqual(initial_hash, apps.sha(apps.canonical(pins)))

    def test_app_assertion_is_private_and_issued_for_the_enrolled_app(self):
        if os.geteuid() == 0:
            self.skipTest("issuance requires the selected non-root custodian")
        who = "publisher"
        self.register_private(who)
        api = self.fakes[who]
        two = apps.bind(api, self.custody[who], who)
        one = {
            **self.ident["reporter"],
            "format": "ocs.safe-push.app-installation/1",
            "custodianUid": os.geteuid() + 1,
            "installationId": 188,
            "repositoryVisibility": "public",
        }
        result = apps.issue(
            api, self.custody[who], who, apps.assemble(one, two, "ocs"), assertion=True
        )
        path = self.custody[who] / "app.jwt"
        value = path.read_text().strip()
        api.verify_jwt(value)
        self.assertEqual(result["appId"], two["appId"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(value, json.dumps(result))
        self.assertFalse((self.custody[who] / "installation.token").exists())

    def test_memory_session_revokes_success_and_exception_without_export(self):
        if os.geteuid() == 0:
            self.skipTest("requires the genuine selected non-root role UID")
        role = "reporter"
        api = self.fakes[role]
        custody = self.custody[role]
        self.register_private(role)
        one = apps.bind(api, custody, role)
        two = {
            **self.ident["publisher"],
            "format": "ocs.safe-push.app-installation/1",
            "installationId": 189,
            "custodianUid": os.geteuid() + 1,
            "repositoryVisibility": "public",
        }
        pins = apps.assemble(one, two, "ocs")
        with apps.installation_session(api, custody, role, pins) as (active, until):
            self.assertIn(active, api.tokens)
            self.assertGreater(apps.epoch(until), time.time())
        self.assertIn(active, api.revoked)
        self.assertFalse(api.tokens)
        with (
            self.assertRaisesRegex(RuntimeError, "operation refused"),
            apps.installation_session(api, custody, role, pins) as (failed, _),
        ):
            self.assertIn(failed, api.tokens)
            raise RuntimeError("operation refused")
        self.assertIn(failed, api.revoked)
        self.assertFalse(api.tokens)
        self.assertFalse((custody / "installation.token").exists())
        self.assertFalse((custody / "app.jwt").exists())

    def test_repository_token_with_changed_permissions_is_revoked(self):
        role = "publisher"
        self.register_private(role)
        api = self.fakes[role]
        jwt = apps.sign_jwt(
            self.custody[role] / "registration/private-key.pem",
            self.ident[role]["clientId"],
            time.time(),
        )
        now = time.time()
        expected = apps.PERMISSIONS[role]
        original = api.call

        def changed(method, path, auth=None, body=None, **kwargs):
            result = original(method, path, auth, body, **kwargs)
            if method == "POST":
                result["permissions"] = {**expected, "administration": "write"}
            return result

        with (
            patch.object(api, "call", side_effect=changed),
            self.assertRaisesRegex(apps.Pending, "unexpected"),
        ):
            apps.minted(
                api,
                jwt,
                189,
                expected,
                {"repository_ids": [41], "permissions": expected},
                now,
            )
        self.assertEqual(len(api.revoked), 1)
        self.assertFalse(api.tokens)
        self.assertFalse((self.custody[role] / "installation.token").exists())

    def test_public_role_receipt_can_be_compared_without_exposing_the_private_key(self):
        role = "reporter"
        self.register_private(role)
        c = self.custody[role]
        uid = os.geteuid()
        expected = {
            **self.ident[role],
            "format": "ocs.safe-push.app-installation/1",
            "installationId": 188,
            "repositoryVisibility": "public",
        }
        apps.save_private(c / "installation.json", apps.canonical(expected))
        (c / "registration/private-key.pem").unlink()
        self.assertEqual(apps.role_receipt(c, role, uid, verify_key=False), expected)
        with self.assertRaises(FileNotFoundError):
            apps.role_receipt(c, role, uid)

    def test_os_readback_and_transport_fail_closed(self):
        role = "reporter"
        self.register_private(role)
        custody = self.custody[role]
        pemfile = custody / "registration/private-key.pem"
        pemfile.chmod(0o640)
        with self.assertRaisesRegex(apps.Pending, "unprotected"):
            apps.read_identity(custody, role, uid=os.geteuid())
        pemfile.chmod(0o600)
        private = self.root / "original.key"
        pemfile.rename(private)
        pemfile.symlink_to(private)
        with self.assertRaisesRegex(apps.Pending, "linked"):
            apps.read_identity(custody, role, uid=os.geteuid())
        self.assertIsNone(
            apps.RejectRedirect().redirect_request(
                None, None, 302, "redirect", None, "https://other.invalid"
            )
        )
        api = apps.APIClient()
        with self.assertRaisesRegex(apps.Pending, "origin"):
            api.call(
                "GET",
                "//other.invalid/repositories",
                "secret",
                operation="read fixture",
            )
        with patch.object(
            api.opener, "open", side_effect=OSError("temporaryABC secret-token")
        ):
            with self.assertRaises(apps.Pending) as e:
                api.call(
                    "POST",
                    "/app-manifests/temporaryABC/conversions",
                    operation="conversion",
                )
            self.assertNotIn("temporaryABC", str(e.exception))
            self.assertNotIn("secret-token", str(e.exception))


if __name__ == "__main__":
    unittest.main()
