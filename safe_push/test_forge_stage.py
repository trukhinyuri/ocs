"""Exercise review-only transport separately from any canonical admission claim."""

import base64
import copy
import http.server
import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from safe_push import forge_apps as apps
from safe_push import forge_stage as stage

REF = "refs/heads/review/hosted-public"
STAGING = "refs/heads/review-before-main"
STAMP_OID = "3" * 40


def actor(role, uid, app_id, install_id, repo):
    return {
        "format": "ocs.safe-push.app-installation/1",
        "role": role,
        "custodianUid": uid,
        **repo,
        "appId": app_id,
        "clientId": "Iv1." + role,
        "slug": "ocs-" + role,
        "permissions": apps.PERMISSIONS[role],
        "publicKeySha256": ("c" if role == "reporter" else "d") * 64,
        "installationId": install_id,
        "repositoryVisibility": "public",
    }


class Hosted:
    def __init__(self, p, ref, *, show_bypass):
        self.p, self.ref, self.main, self.review = p, ref, None, None
        self.states = {}
        self.root = "/repos/" + p["repository"]
        self.rules = {
            i: {
                "id": i,
                "source": p["repository"],
                "source_type": "Repository",
                **copy.deepcopy(v),
            }
            for i, v in stage.rules_for(p).items()
        }
        self.expose = show_bypass
        self.read = []

    def refdata(self, name, oid):
        return {"ref": name, "object": {"sha": oid, "type": "commit"}}

    def get(self, path):
        self.read.append(path)
        p = self.p
        b = p["bootstrap"]
        key = path.split("?", 1)[0]
        if key == self.root:
            return {
                "id": p["repositoryId"],
                "full_name": p["repository"],
                "owner": {"id": p["ownerId"]},
                "visibility": "public",
                "private": False,
                "archived": False,
                "disabled": False,
                "default_branch": b["stagingRef"].removeprefix("refs/heads/"),
            }
        key = key.removeprefix(self.root)
        if key == "/git/ref/" + b["stagingRef"].removeprefix("refs/"):
            return self.refdata(b["stagingRef"], b["stagingCommit"])
        if key == "/git/matching-refs/heads/main":
            return [self.refdata("refs/heads/main", self.main)] if self.main else []
        if key == "/git/matching-refs/" + self.ref.removeprefix("refs/"):
            return [self.refdata(self.ref, self.review)] if self.review else []
        if key.startswith("/git/commits/"):
            return self.states[key.rsplit("/", 1)[1]]
        if key == "/rules/branches/main":
            return [
                {
                    "ruleset_id": i,
                    "ruleset_source": p["repository"],
                    "ruleset_source_type": "Repository",
                    **rule,
                }
                for i, body in self.rules.items()
                for rule in body["rules"]
            ]
        if key.startswith("/rulesets/"):
            out = copy.deepcopy(self.rules[int(key.rsplit("/", 1)[1])])
            if not self.expose:
                out.pop("bypass_actors")
            return out
        raise AssertionError("unexpected API read")


class ReviewStageTests(unittest.TestCase):
    def test_configuration_cannot_be_changed_after_kernel_sealing(self):
        raw = b"[credential]\nhelper =\n"
        with stage.memory_git_config(raw) as fd:
            self.assertEqual(os.pread(fd, len(raw), 0), raw)
            self.assertEqual(stage.fcntl.fcntl(fd, 1034) & 15, 15)
            with self.assertRaises(PermissionError):
                os.ftruncate(fd, 0)
        real = stage.fcntl.fcntl

        def no_positive_readback(fd, command, value=0):
            return 0 if command == 1034 else real(fd, command, value)

        with (
            patch.object(stage.fcntl, "fcntl", no_positive_readback),
            self.assertRaisesRegex(ValueError, "review.seals"),
            stage.memory_git_config(raw),
        ):
            self.fail("an unconfirmed seal was accepted")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.working = self.root / "working"
        self.remote = self.root / "remote.git"
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        self.git(
            "init", "--quiet", "--template=", "--initial-branch=main", self.working
        )
        self.git(
            "init",
            "--quiet",
            "--template=",
            "--bare",
            "--initial-branch=main",
            self.remote,
        )
        (self.working / "public.txt").write_text("qualified old tree\n")
        self.git("-C", self.working, "add", "public.txt")
        self.git("-C", self.working, "commit", "--quiet", "-m", "old")
        self.parent = self.git("-C", self.working, "rev-parse", "HEAD")
        (self.working / "public.txt").write_text("unqualified review\n")
        self.git("-C", self.working, "add", "public.txt")
        self.git("-C", self.working, "commit", "--quiet", "-m", "review")
        self.child = self.git("-C", self.working, "rev-parse", "HEAD")
        cm = stage.clean_object_view(self.working / ".git/objects", "sha1")
        self.view = cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        repo = apps.target("fixture/standard", 51, 72, "user")
        self.pins = apps.assemble(
            actor("reporter", 801, 47, 103, repo),
            actor("publisher", 802, 48, 104, repo),
            "ocs",
        )
        self.p = apps.forge_policy(
            self.pins,
            "public",
            "bootstrap",
            staging_ref=STAGING,
            staging_commit=STAMP_OID,
            genesis=self.parent,
            publisher_installation=104,
            hold_id=80,
            integrity_id=81,
            writer_id=82,
        )
        before = stage.inventory(self.view, self.parent)
        self.historical = {
            "format": stage.PARENT,
            "parent": self.parent,
            "tree": stage.git_value(self.view, "rev-parse", self.parent + "^{tree}"),
            "subject": stage.subject(self.view, self.parent, before),
            "wholeTreeSha256": stage.framed(before),
            "reportSha256": "a" * 64,
            "observerSha256": "b" * 64,
            "standReceiptSha256": "f" * 64,
            "claimLevels": 394,
        }
        self.local = stage.binding(
            self.view, self.p, self.historical, self.parent, self.child
        )
        self.admin = Hosted(self.p, REF, show_bypass=True)
        self.host = Hosted(self.p, REF, show_bypass=False)
        self.guards = stage.guard_record(self.admin, self.p, REF)
        self.custody = self.root / "publisher"
        self.custody.mkdir(mode=0o700)
        self.host.states = {
            self.child: {
                "sha": self.child,
                "tree": {"sha": self.local["tree"]},
                "parents": [{"sha": self.parent}],
            },
            self.parent: {
                "sha": self.parent,
                "tree": {"sha": self.local["parentTree"]},
            },
        }

    def git(self, *argv):
        return (
            subprocess.run(
                ["/usr/bin/git", *argv],
                env=self.env,
                capture_output=True,
                check=True,
                timeout=15,
            )
            .stdout.decode()
            .strip()
        )

    def live(self):
        return stage.preflight(
            self.host, self.p, REF, self.guards, self.local, self.pins, time.time()
        )

    def test_approval_and_all_three_active_scopes(self):
        draft = self.live()
        self.assertIsNone(draft["action"]["expectedOld"])
        self.assertEqual(draft["action"]["mainBefore"], None)
        self.assertEqual(draft["action"]["publisherAppId"], 48)
        for name in (
            "refs/heads/main",
            STAGING,
            "refs/heads/review/main/topic",
            "refs/tags/review/test",
            "refs/heads/review/.x",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                stage.selected(self.p, name)
        with self.assertRaisesRegex(ValueError, "approval"):
            stage.dispatch(
                "publish",
                self.custody,
                "0" * 64,
                self.live,
                lambda _: self.fail("write"),
            )
        self.host.rules[81]["conditions"]["ref_name"]["include"] = [REF]
        with self.assertRaisesRegex(ValueError, "guards"):
            self.live()
        self.assertFalse((self.custody / "review-transfers").exists())

    def test_public_absence_is_independent_and_main_drift_holds(self):
        self.host.main = self.parent
        with self.assertRaisesRegex(ValueError, "guards"):
            self.live()
        self.host.main = None
        self.guards["validBefore"] = apps.stamp(time.time() - 3)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.live()
        self.guards = stage.guard_record(self.admin, self.p, REF)
        self.admin.expose = False
        with self.assertRaisesRegex(ValueError, "bypass"):
            stage.guard_record(self.admin, self.p, REF)
        self.host.review = self.parent
        with self.assertRaisesRegex(ValueError, "different"):
            self.live()

    def test_unverified_parent_or_merge_cannot_stage(self):
        forged = {**self.historical, "wholeTreeSha256": "a" * 64}
        with self.assertRaisesRegex(ValueError, "parent"):
            stage.binding(self.view, self.p, forged, self.parent, self.child)
        with self.assertRaises(ValueError):
            stage.binding(self.view, self.p, self.historical, self.child, self.parent)
        if os.geteuid() != 0:
            with self.assertRaises(ValueError):
                stage.checked_source(self.remote)
        config = self.git("--git-dir", self.view, "config", "--local", "--list")
        self.assertNotIn("credential.helper", config)
        self.assertNotIn("remote.", config)

    def test_real_git_absent_lease_and_authenticated_dispatch_scope(self):
        draft = self.live()
        token = "per-role-private-fixture-credential"
        calls = []
        native = subprocess.run

        def local_remote(argv, **kw):
            self.assertEqual(argv[-2], draft["action"]["remote"])
            self.assertEqual(argv[-1], self.child + ":" + REF)
            self.assertIn("--force-with-lease=" + REF + ":", argv)
            self.assertIn("credential.helper=", argv)
            self.assertIn("http.followRedirects=false", argv)
            self.assertEqual(kw["env"]["GIT_ALLOW_PROTOCOL"], "https")
            self.assertNotIn(token, str(argv))
            self.assertNotIn(token, str(kw["env"]))
            header = Path(kw["env"]["GIT_CONFIG_GLOBAL"])
            self.assertEqual(header.stat().st_mode & 0o777, 0o400)
            self.assertIn(
                base64.b64encode(("x-access-token:" + token).encode()).decode(),
                header.read_text(),
            )
            args = list(argv)
            args[-2] = str(self.remote)
            ix = args.index("push")
            args[ix:ix] = ["-c", "protocol.file.allow=always"]
            kw["env"] = {**kw["env"], "GIT_ALLOW_PROTOCOL": "file"}
            calls.append(argv[-1])
            return native(args, **kw)

        def write(action):
            with patch.object(stage.subprocess, "run", side_effect=local_remote):
                verdict = stage.push_once(self.view, action, token)
            self.host.review = self.git("-C", self.remote, "rev-parse", REF)
            return verdict

        result = stage.dispatch(
            "publish", self.custody, draft["actionSha256"], self.live, write
        )
        self.assertTrue(result["newCreationByEnrolledTransport"])
        self.assertEqual((result["observed"], result["mainAfter"]), (self.child, None))
        again = stage.dispatch(
            "publish", self.custody, draft["actionSha256"], self.live, write
        )
        self.assertEqual(again["transportAcknowledgement"], "created")
        self.assertEqual(len(calls), 1)
        # Real receive-pack must preserve a conflicting review ref under the same creation-only lease.
        self.git("-C", self.remote, "update-ref", REF, self.parent, self.child)
        with patch.object(stage.subprocess, "run", side_effect=local_remote):
            refused = stage.push_once(self.view, draft["action"], token)
        self.assertEqual(refused, "remote-did-not-acknowledge")
        self.assertEqual(self.git("-C", self.remote, "rev-parse", REF), self.parent)
        allrefs = self.git(
            "-C", self.remote, "for-each-ref", "--format=%(refname)"
        ).splitlines()
        self.assertEqual(allrefs, [REF])

    def test_disposable_smart_https_uses_only_the_exact_role_header(self):
        source = self.root / "server"
        www = source / "fixture"
        www.mkdir(parents=True)
        remote = www / "standard.git"
        self.git(
            "init", "--quiet", "--bare", "--template=", "--initial-branch=main", remote
        )
        self.git("-C", remote, "config", "http.receivepack", "true")
        pem, secret = self.root / "tls.crt", self.root / "tls.key"
        native = subprocess.run
        native(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                secret,
                "-out",
                pem,
            ],
            capture_output=True,
            check=True,
            timeout=20,
        )
        token = "isolated-private-installation-token"
        expected = (
            "Basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()
        )
        exchanges = []

        class SmartHTTP(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.exchange()

            def do_POST(self):
                self.exchange()

            def exchange(self):
                target = urllib.parse.urlsplit(self.path)
                auth = self.headers.get("Authorization")
                exchanges.append((self.command, target.path, auth == expected))
                if auth != expected or target.path not in (
                    "/fixture/standard.git/info/refs",
                    "/fixture/standard.git/git-receive-pack",
                ):
                    self.send_error(403)
                    return
                count = int(self.headers.get("Content-Length", "0"))
                if count > 2 * 1024 * 1024:
                    self.send_error(413)
                    return
                env = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(source),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_PROJECT_ROOT": str(source),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": target.path,
                    "QUERY_STRING": target.query,
                    "REQUEST_METHOD": self.command,
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(count),
                    "REMOTE_USER": "x-access-token",
                    "REMOTE_ADDR": "127.0.0.1",
                }
                backend = native(
                    ["/usr/bin/git", "http-backend"],
                    input=self.rfile.read(count),
                    env=env,
                    capture_output=True,
                    timeout=15,
                    check=True,
                )
                prefix, mark, body = backend.stdout.partition(b"\r\n\r\n")
                if not mark:
                    self.send_error(502)
                    return
                headers = {}
                for line in prefix.decode("ascii").splitlines():
                    key, _, value = line.partition(":")
                    headers[key.lower()] = value.strip()
                code = int(headers.pop("status", "200").split()[0])
                self.send_response(code)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), SmartHTTP) as server:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pem, secret)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            peer = f"https://127.0.0.1:{server.server_port}/fixture/standard.git"
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
            )
            thread.start()
            action = self.live()["action"]

            def only_fixture_address(argv, **kw):
                self.assertEqual(argv[-2], action["remote"])
                self.assertEqual(kw["env"]["GIT_ALLOW_PROTOCOL"], "https")
                cfg = Path(kw["env"]["GIT_CONFIG_GLOBAL"])
                with stage.memory_git_config(
                    cfg.read_text().replace(action["remote"], peer).encode("ascii")
                ) as fd:
                    args = list(argv)
                    args[-2] = peer
                    kw["env"] = {
                        **kw["env"],
                        "GIT_SSL_CAINFO": str(pem),
                        "GIT_CONFIG_GLOBAL": "/proc/self/fd/" + str(fd),
                    }
                    kw["pass_fds"] = (fd,)
                    return native(args, **kw)

            try:
                with patch.object(
                    stage.subprocess, "run", side_effect=only_fixture_address
                ):
                    self.assertEqual(
                        stage.push_once(self.view, action, token), "created"
                    )
            finally:
                server.shutdown()
                thread.join(timeout=3)
        self.assertIn(("GET", "/fixture/standard.git/info/refs", True), exchanges)
        self.assertIn(
            ("POST", "/fixture/standard.git/git-receive-pack", True), exchanges
        )
        self.assertTrue(all(auth for _, _, auth in exchanges))
        self.assertEqual(self.git("-C", remote, "rev-parse", REF), self.child)
        self.assertEqual(
            self.git("-C", remote, "for-each-ref", "--format=%(refname)").splitlines(),
            [REF],
        )

    def test_uncertain_attempt_and_preexisting_object_are_never_new_successes(self):
        original = self.live()
        with self.assertRaisesRegex(ValueError, "confirm"):
            stage.dispatch(
                "publish",
                self.custody,
                original["actionSha256"],
                self.live,
                lambda _: "acknowledgement-unavailable",
            )
        with self.assertRaisesRegex(ValueError, "uncertain"):
            stage.dispatch(
                "publish",
                self.custody,
                original["actionSha256"],
                self.live,
                lambda _: self.fail("second send"),
            )
        self.host.review = self.child
        later = stage.dispatch(
            "confirm",
            self.custody,
            None,
            self.live,
            lambda _: self.fail("readback write"),
        )
        self.assertFalse(later["newCreationByEnrolledTransport"])
        unrelated = self.root / "new"
        unrelated.mkdir(mode=0o700)
        visible = stage.dispatch(
            "confirm",
            unrelated,
            None,
            self.live,
            lambda _: self.fail("preexisting write"),
        )
        self.assertFalse(visible["newCreationByEnrolledTransport"])
        self.assertEqual(visible["canonicalAdmission"], "separate")

    def test_repo_or_role_substitution_refuses(self):
        pins = copy.deepcopy(self.pins)
        pins["roles"]["publisher"]["appId"] = 47
        with self.assertRaises(ValueError):
            stage.preflight(
                self.host, self.p, REF, self.guards, self.local, pins, time.time()
            )
        drift = {**self.p, "publisherAppId": 52}
        with self.assertRaisesRegex(ValueError, "issuer"):
            stage.preflight(
                self.host, drift, REF, self.guards, self.local, self.pins, time.time()
            )
        self.host.review = self.child
        self.host.states[self.child]["parents"] = []
        with self.assertRaisesRegex(ValueError, "single parent"):
            self.live()


class HistoricalStageTests(unittest.TestCase):
    def test_actual_archived_signed_qualification_is_review_evidence_only(self):
        work = Path(__file__).resolve().parents[1]
        common = Path(
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(work),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ],
                text=True,
                timeout=15,
            ).strip()
        )
        root = Path(
            os.environ.get("OCS_SAFE_PUSH_HISTORY", str(common.parent))
        ).resolve()
        d = root / "out/qualification/full/latest"
        assets = root / "out/acceptance/3facf571"
        expected = "9b48d20fa66c191837d364ddaca13d861372df764f86b028150b4624094bb232"
        if not (assets / "observer.pub").is_file():
            self.skipTest("owner's original signed stand data is kept outside Git")
        if (
            not (d / "report.json").is_file()
            or apps.sha((d / "report.json").read_bytes()) != expected
        ):
            match = next(
                (
                    f.parent
                    for f in (root / "out/qualification/full/runs").glob(
                        "*/report.json"
                    )
                    if apps.sha(f.read_bytes()) == expected
                ),
                None,
            )
            if not match:
                self.skipTest("original full signed report is unavailable")
            d = match
        rev = "3facf571910e0799539a77a1a5112e6609a9a5ca"
        verifier = "e09a5d7d0ae15d35910e72243c4a466974f09401"
        with stage.clean_object_view(common / "objects", "sha1") as repo:
            proof = stage.parent_proof(
                repo,
                rev,
                verifier,
                d,
                assets / "independent-enrollment.json",
                assets / "observer.pub",
                expected,
                apps.sha((assets / "observer.pub").read_bytes()),
            )
        self.assertEqual(proof["claimLevels"], 394)
        self.assertEqual(proof["parent"], rev)
        self.assertEqual(proof["metricCount"], 364)
        self.assertIn("previously witnessed", proof["scope"])


if __name__ == "__main__":
    unittest.main()
