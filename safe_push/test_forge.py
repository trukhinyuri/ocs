"""Hosted API readbacks are synthetic. The local verification case uses real Git and Ed25519."""

import copy
import hashlib
import hmac
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from datetime import UTC

from authority import Decision, canonical, framed, immutable, signature

from safe_push import forge

OLD, NEW, TREE = "1" * 40, "2" * 40, "3" * 40
RECEIPT = "7" * 64
KEY = b"disposable-hook-secret-0001"
QUEUE_REF = "refs/heads/gh-readonly-queue/main/pr-4-f00d"


def config(mode):
    return {
        "format": "ocs.safe-push.forge/1",
        "repository": "fixture/project",
        "repositoryId": 42,
        "ownerId": 10,
        "project": "ocs",
        "mode": mode,
        "checkAppId": 70,
        "checkInstallationId": 1234,
        "publisherAppId": 80 if mode == "mirror" else None,
        "mergeQueue": mode != "mirror",
    }


class ApiFixture:
    def __init__(self, mode="mirror"):
        self.cfg = config(mode)
        self.base = "/repos/fixture/project"
        self.repo = {
            "private": True,
            "visibility": "private",
            "owner": {"id": 10},
            "id": 42,
            "full_name": "fixture/project",
            "default_branch": "main",
            "archived": False,
            "disabled": False,
        }
        self.head = OLD
        self.local = {
            "project": "ocs",
            "profile": "ocs-release/1",
            "candidate": NEW,
            "parent": OLD,
            "tree": TREE,
            "receiptSha256": RECEIPT,
            "expiresEpoch": time.time() + 300,
            "localRepository": "/fixture/repo",
        }
        self.obj = {"sha": NEW, "parents": [{"sha": OLD}], "tree": {"sha": TREE}}
        rules = [
            {"type": n}
            for n in (
                "non_fast_forward",
                "deletion",
                "creation",
                "required_linear_history",
            )
        ]
        self.status_rule = {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": "OCS Safe Push", "integration_id": 70}
                ],
            },
        }
        rules.append(self.status_rule)
        self.sets = []
        if mode == "pull-request":
            rules.extend(
                [
                    {
                        "type": "pull_request",
                        "parameters": {
                            "required_approving_review_count": 2,
                            "dismiss_stale_reviews_on_push": True,
                            "require_last_push_approval": True,
                            "require_code_owner_review": True,
                            "allowed_merge_methods": ["squash"],
                            "required_review_thread_resolution": True,
                        },
                    },
                    {
                        "type": "merge_queue",
                        "parameters": {
                            "max_entries_to_build": 1,
                            "min_entries_to_merge": 1,
                            "max_entries_to_merge": 1,
                            "min_entries_to_merge_wait_minutes": 5,
                            "check_response_timeout_minutes": 60,
                            "grouping_strategy": "ALLGREEN",
                            "merge_method": "SQUASH",
                        },
                    },
                ]
            )
        self.add(101, "OCS admission integrity", rules, [])
        if mode == "mirror":
            self.add(
                102,
                "OCS exclusive mirror writer",
                [
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": False},
                    }
                ],
                [
                    {
                        "actor_type": "Integration",
                        "actor_id": 80,
                        "bypass_mode": "always",
                    }
                ],
            )
        self.check = []
        self.legacy = []
        self.classic = None
        self.queue_tip = NEW
        self.pr = {
            "number": 4,
            "state": "open",
            "draft": False,
            "merge_commit_sha": NEW,
            "base": {"ref": "main", "repo": {"id": 42}, "sha": OLD},
            "head": {"ref": "submit", "repo": {"id": 420}, "sha": "4" * 40},
        }
        self.actions = []

    def add(self, rid, name, rules, bypass):
        self.sets.append(
            {
                "id": rid,
                "name": name,
                "source_type": "Repository",
                "source": "fixture/project",
                "target": "branch",
                "enforcement": "active",
                "rules": rules,
                "bypass_actors": bypass,
                "conditions": {
                    "ref_name": {"include": ["refs/heads/main"], "exclude": []}
                },
            }
        )

    def get(self, raw):
        self.actions.append(("GET", raw))
        path = raw.split("?", 1)[0].removeprefix(self.base)
        if not path:
            return copy.deepcopy(self.repo)
        if path == "/rulesets":
            return copy.deepcopy(self.sets)
        if path == "/rules/branches/main":
            return [
                {
                    **row,
                    "ruleset_id": s["id"],
                    "ruleset_source_type": s["source_type"],
                    "ruleset_source": s["source"],
                }
                for s in self.sets
                if s["enforcement"] == "active"
                for row in s["rules"]
            ]
        if path.startswith("/rulesets/"):
            return next(s for s in self.sets if str(s["id"]) == path.split("/")[-1])
        if path == "/branches/main/protection":
            return self.classic
        if path == "/git/ref/heads/main":
            return {"ref": forge.REF, "object": {"sha": self.head, "type": "commit"}}
        if path == "/git/ref/" + QUEUE_REF.removeprefix("refs/"):
            return {
                "ref": QUEUE_REF,
                "object": {"sha": self.queue_tip, "type": "commit"},
            }
        if path == "/git/commits/" + NEW:
            return copy.deepcopy(self.obj)
        if path == "/pulls/4":
            return copy.deepcopy(self.pr)
        if path == "/commits/" + NEW + "/statuses":
            return self.legacy
        if path == "/commits/" + NEW + "/check-runs":
            return {"total_count": len(self.check), "check_runs": self.check}
        raise AssertionError("unexpected API route " + raw)

    def success(self):
        self.check = [
            {
                "id": 92,
                "name": "OCS Safe Push",
                "app": {"id": 70},
                "head_sha": NEW,
                "external_id": RECEIPT,
                "status": "completed",
                "conclusion": "success",
            }
        ]

    def event(self, kind, change=None):
        body = {
            "repository": {"id": 42, "full_name": "fixture/project"},
            "installation": {"id": 1234},
        }
        if kind == "pull_request":
            body.update(
                action="synchronize", number=4, pull_request=copy.deepcopy(self.pr)
            )
        else:
            body.update(
                action="checks_requested",
                merge_group={
                    "base_ref": "refs/heads/main",
                    "base_sha": OLD,
                    "head_ref": QUEUE_REF,
                    "head_sha": NEW,
                },
            )
        if change:
            change(body)
        raw = canonical(body)
        return {
            "kind": kind,
            "raw": raw,
            "signature": "sha256=" + hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
            "webhook_key": KEY,
        }

    def run(self, action, **event):
        return forge.propose(self, self.cfg, lambda: dict(self.local), action, **event)


class ForgeTests(unittest.TestCase):
    def test_rules_installer_and_exact_separate_mirror_lease(self):
        api = ApiFixture()
        rules = forge.rulesets(api.cfg)
        self.assertEqual([], rules[0]["bypass_actors"])
        self.assertEqual(80, rules[1]["bypass_actors"][0]["actor_id"])
        initial = api.run("check-run")
        self.assertEqual(
            ("POST", NEW, "success", RECEIPT),
            (
                initial["method"],
                initial["body"]["head_sha"],
                initial["body"]["conclusion"],
                initial["body"]["external_id"],
            ),
        )
        with self.assertRaisesRegex(Decision, "forge.mirror"):
            api.run("mirror")
        api.success()
        mirror = api.run("mirror")
        self.assertIn("--force-with-lease=refs/heads/main:" + OLD, mirror["argv"])
        self.assertEqual(NEW + ":refs/heads/main", mirror["argv"][-1])
        self.assertEqual(80, mirror["publisherAppId"])
        with self.assertRaisesRegex(Decision, "forge.parent"):
            api.run("confirm")
        api.head = NEW
        self.assertEqual("verified-readback", api.run("confirm")["result"])
        self.assertEqual({"GET"}, {a for a, _ in api.actions})

    def test_authenticated_pr_and_merge_group_target_the_actual_object(self):
        for kind in ("pull_request", "merge_group"):
            api = ApiFixture("pull-request")
            proposal = api.run("check-run", **api.event(kind))
            self.assertEqual(NEW, proposal["event"]["object"])
            self.assertEqual(70, proposal["appId"])
            self.assertEqual(1234, proposal["installationId"])
            with self.subTest(kind=kind):
                args = api.event(kind)
                args["raw"] += b" "
                with self.assertRaisesRegex(Decision, "forge.event"):
                    api.run("check-run", **args)
        api = ApiFixture("pull-request")
        with self.assertRaisesRegex(Decision, "forge.event"):
            api.run(
                "check-run",
                **api.event(
                    "pull_request", lambda ev: ev["installation"].update(id=70)
                ),
            )
        with self.assertRaisesRegex(Decision, "forge.final-object"):
            api.run(
                "check-run",
                **api.event(
                    "pull_request",
                    lambda ev: ev["pull_request"].update(merge_commit_sha="5" * 40),
                ),
            )
        api.queue_tip = "5" * 40
        with self.assertRaisesRegex(Decision, "forge.final-object"):
            api.run("check-run", **api.event("merge_group"))

    def test_parent_profile_repository_tree_and_single_parent(self):
        variants = [
            ("forge.parent", lambda a: setattr(a, "head", "4" * 40)),
            (
                "forge.receipt",
                lambda a: a.local.update(profile="receiver-experiment/1"),
            ),
            ("forge.repository", lambda a: a.repo.update(private=False)),
            ("forge.repository", lambda a: a.repo.update(id=999)),
            ("forge.final-object", lambda a: a.obj["tree"].update(sha="4" * 40)),
            (
                "forge.final-object",
                lambda a: a.obj["parents"].append({"sha": "9" * 40}),
            ),
        ]
        for criterion, alter in variants:
            api = ApiFixture()
            alter(api)
            with (
                self.subTest(criterion=criterion),
                self.assertRaisesRegex(Decision, criterion),
            ):
                api.run("check-run")

    def test_enforcement_bypass_and_actual_source(self):
        variants = [
            ("forge.rules", lambda a: a.sets[0].update(enforcement="evaluate")),
            (
                "forge.rules",
                lambda a: a.status_rule["parameters"]["required_status_checks"][
                    0
                ].update(integration_id=88),
            ),
            ("forge.rules", lambda a: a.sets[0]["rules"].pop(0)),
            ("forge.bypass", lambda a: a.sets[0].pop("bypass_actors")),
            (
                "forge.bypass",
                lambda a: a.sets[0]["bypass_actors"].append(
                    {
                        "actor_type": "RepositoryRole",
                        "actor_id": 5,
                        "bypass_mode": "always",
                    }
                ),
            ),
            (
                "forge.bypass",
                lambda a: a.sets[1]["bypass_actors"][0].update(actor_id=70),
            ),
            (
                "forge.rules",
                lambda a: a.add(
                    900, "another effective set", [{"type": "creation"}], []
                ),
            ),
            (
                "forge.rules",
                lambda a: setattr(a, "classic", {"enforce_admins": {"enabled": False}}),
            ),
        ]
        for criterion, alter in variants:
            api = ApiFixture()
            alter(api)
            with (
                self.subTest(criterion=criterion),
                self.assertRaisesRegex(Decision, criterion),
            ):
                api.run("check-run")

    def test_absence_of_entitlement_returns_no_proposal(self):
        api = ApiFixture()
        get = api.get

        def denied(path):
            if "/rulesets?" in path:
                raise Decision("forge.readback", "GET returned HTTP 403")
            return get(path)

        api.get = denied
        with self.assertRaisesRegex(Decision, "HTTP 403"):
            api.run("check-run")

    def test_read_transport_distinguishes_a_private_denial_from_absent_classic_protection(
        self,
    ):
        api = forge.ReadAPI("fixture-token")
        path = "/repos/fixture/project/branches/main/protection"
        for code, message, known_absence in (
            (403, "Upgrade required", False),
            (404, "Not Found", False),
            (404, "Branch not protected", True),
        ):
            error = urllib.error.HTTPError(
                forge.API + path,
                code,
                "",
                {},
                io.BytesIO(canonical({"message": message})),
            )
            with patch.object(api.opener, "open", side_effect=error) as opened:
                if known_absence:
                    self.assertIsNone(api.get(path))
                else:
                    with self.assertRaisesRegex(Decision, "HTTP " + str(code)):
                        api.get(path)
                self.assertEqual(opened.call_args.args[0].get_method(), "GET")

    def test_host_success_like_states_and_foreign_apps_cannot_authorize_mirror(self):
        for field, value in (
            ("conclusion", "skipped"),
            ("conclusion", "neutral"),
            ("conclusion", "cancelled"),
            ("app", {"id": 80}),
            ("head_sha", "6" * 40),
            ("external_id", "8" * 64),
            ("status", "in_progress"),
        ):
            api = ApiFixture()
            api.success()
            api.check[0][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(Decision, "forge.check"),
            ):
                api.run("mirror")
        api = ApiFixture()
        api.success()
        api.legacy = [{"context": "OCS Safe Push", "state": "success"}]
        with self.assertRaisesRegex(Decision, "forge.check"):
            api.run("mirror")

    def test_only_an_authentic_current_release_receipt_supplies_local_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bare = root / "repo"
            bare.mkdir()
            key = root / "key"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                check=True,
                capture_output=True,
            )
            pem = subprocess.check_output(
                ["openssl", "pkey", "-in", str(key), "-pubout"], text=True
            )

            def git(*args):
                return subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(bare),
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=owner@example.invalid",
                        *args,
                    ],
                    text=True,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": os.defpath,
                        "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                ).strip()

            git("init", "-b", "main")
            git("commit", "--allow-empty", "-m", "enrolled parent")
            old = git("rev-parse", "HEAD")
            git("commit", "--allow-empty", "-m", "qualified candidate")
            child, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
            cfg = {"project": "ocs", "rootDigest": "6" * 64}
            policy = {"keys": {"publisher": pem}, "profile": "ocs-release/1"}
            observed = {
                "profile": "ocs-release/1",
                "tip": child,
                "project": "ocs",
                "certifiedTransitions": 1,
                "status": "verified",
            }
            receipt = {
                "profile": "ocs-release/1",
                "project": "ocs",
                "epoch": 0,
                "policy": framed(policy),
                "format": "ocs.safe-push.prepared/1",
                "parent": old,
                "candidate": child,
                "tree": tree,
                "expiresEpoch": time.time() + 120,
                "verifiedProof": {
                    "status": "pass",
                    "verdict": "accepted",
                    "parent": old,
                    "actualParent": old,
                    "candidate": child,
                    "tree": tree,
                },
            }
            signed = signature(receipt, key)
            immutable(root / "signatures" / (child + ".json"), canonical(signed))
            immutable(root / "committed" / (child + ".json"), canonical(receipt))
            # Independently supplied test enrollment and consumer observation. Real repository
            # object identity, signature verification and exact immutable record are exercised.
            with (
                patch.object(
                    forge, "state", return_value=(cfg, root, root, bare, policy)
                ),
                patch.object(forge, "chain_status", return_value=observed),
                patch("receiver.policy_history", return_value=[policy]),
            ):
                accepted = forge.accepted_local(root / "config", "ocs")
                self.assertEqual(
                    (old, child, tree, framed(signed)),
                    tuple(
                        accepted[k]
                        for k in ("parent", "candidate", "tree", "receiptSha256")
                    ),
                )
                observed["profile"] = "receiver-experiment/1"
                with self.assertRaisesRegex(Decision, "forge.receipt"):
                    forge.accepted_local(root / "config", "ocs")
                observed["profile"] = "ocs-release/1"
                path = root / "signatures" / (child + ".json")
                signed["payload"]["tree"] = "f" * 40
                path.write_bytes(canonical(signed))
                with self.assertRaisesRegex(Decision, "audit.publisher"):
                    forge.accepted_local(root / "config", "ocs")


class BootstrapAPI(ApiFixture):
    STAGE = "5" * 40
    STAGING = "refs/heads/review/safe-push"

    def __init__(self):
        super().__init__()
        self.t = int(time.time())
        self.repo.update(
            private=False, visibility="public", default_branch="review/safe-push"
        )
        self.cfg = {
            **self.cfg,
            "format": "ocs.safe-push.forge/2",
            "expectedVisibility": "public",
            "bootstrap": {
                "stagingRef": self.STAGING,
                "stagingCommit": self.STAGE,
                "genesis": NEW,
                "holdRulesetId": 103,
                "integrityRulesetId": 101,
                "writerRulesetId": 102,
                "publisherInstallationId": 5678,
            },
        }
        self.head = None
        self.staged = self.STAGE
        self.ref_list = None
        self.sets[0]["rules"] = [
            r for r in self.sets[0]["rules"] if r["type"] != "creation"
        ]
        self.sets[1]["rules"].append({"type": "creation"})
        self.add(
            103,
            "OCS main enrollment hold",
            [
                {"type": n}
                for n in ("creation", "update", "deletion", "non_fast_forward")
            ],
            [],
        )
        self.histories = {
            s["id"]: [self.version(s, 500 + s["id"], self.t - 240 + s["id"] % 100)]
            for s in self.sets
        }
        self.installations = {
            "check": {
                "id": 1234,
                "app_id": 70,
                "permissions": {"checks": "write", "contents": "read"},
            },
            "publisher": {
                "id": 5678,
                "app_id": 80,
                "permissions": {"contents": "write", "checks": "read"},
            },
        }
        for v in self.installations.values():
            v.update(
                account={"id": 10, "login": "fixture"},
                target_id=10,
                suspended_at=None,
                repository_selection="selected",
            )

        class Installation:
            def __init__(self, row):
                self.row = row

            def get(self, path):
                if path != "/repos/fixture/project/installation":
                    raise AssertionError(path)
                return copy.deepcopy(self.row)

        self.app_views = {k: Installation(v) for k, v in self.installations.items()}

    @staticmethod
    def iso(t):
        from datetime import datetime

        return datetime.fromtimestamp(t, UTC).isoformat()

    def version(self, row, version_id, t):
        return {
            "version_id": version_id,
            "updated_at": self.iso(t),
            "state": copy.deepcopy(row),
        }

    def hold_config(self):
        return {
            k: v
            for k, v in {
                "format": "ocs.safe-push.forge-hold/1",
                "repository": "fixture/project",
                "repositoryId": 42,
                "ownerId": 10,
                "expectedVisibility": "public",
                "stagingRef": self.STAGING,
                "stagingCommit": self.STAGE,
                "holdRulesetId": 103,
            }.items()
        }

    def disable(self, at=None):
        h = self.sets[2]
        h["enforcement"] = "disabled"
        self.histories[103].append(
            self.version(h, 994, self.t - 15 if at is None else at)
        )

    def get(self, raw):
        path = raw.split("?", 1)[0].removeprefix(self.base)
        if path == "/git/matching-refs/heads/main":
            if self.ref_list is not None:
                return copy.deepcopy(self.ref_list)
            rows = [
                {
                    "ref": "refs/heads/main-review",
                    "object": {"type": "commit", "sha": self.STAGE},
                }
            ]
            if self.head:
                rows.append(
                    {"ref": forge.REF, "object": {"type": "commit", "sha": self.head}}
                )
            return rows
        if path == "/git/ref/heads/review/safe-push":
            return {
                "ref": self.STAGING,
                "object": {"type": "commit", "sha": self.staged},
            }
        if path.startswith("/rulesets/") and "/history" in path:
            _, _, rid, _, *tail = path.split("/")
            vs = self.histories[int(rid)]
            if not tail:
                return [
                    {k: v for k, v in version.items() if k != "state"}
                    for version in reversed(vs)
                ]
            return copy.deepcopy(next(v for v in vs if v["version_id"] == int(tail[0])))
        if path == "/check-runs/92":
            return copy.deepcopy(self.check[0])
        return super().get(raw)


class PublicForgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.private = {}
        cls.public = {}
        for role in ("domain", "independent", "guardian", "publisher"):
            key = Path(cls.tmp.name) / role
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                check=True,
                capture_output=True,
            )
            cls.private[role] = key
            cls.public[role] = subprocess.check_output(
                ["openssl", "pkey", "-in", str(key), "-pubout"], text=True
            )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def target(self, a):
        return {
            "genesis": NEW,
            "project": "ocs",
            "profile": "ocs-release/1",
            "tree": TREE,
            "parents": [OLD],
            "sourceSha256": "c" * 64,
            "genesisReceiptSha256": RECEIPT,
            "genesisRootSha256": "b" * 64,
            "policySha256": "a" * 64,
            "epoch": 0,
            "localRepository": "/fixture/repo",
            "keys": self.public,
            "lifetimeSeconds": 600,
            "expiresEpoch": a.t + 400,
        }

    def run_stage(self, a, action, auth=None, handoff=None):
        return forge.bootstrap_propose(
            a, a.cfg, lambda: self.target(a), action, auth, handoff, a.app_views
        )

    def seal(self, context, issued, expires):
        payload = {
            **context,
            "issuedAt": BootstrapAPI.iso(issued),
            "expiresAt": BootstrapAPI.iso(expires),
        }
        return {
            "payload": payload,
            "signatures": {
                r: signature({**payload, "role": r}, key)
                for r, key in self.private.items()
            },
        }

    def handoff(self, a):
        expected = self.run_stage(a, "bootstrap-context")["context"]
        auth = self.seal(expected, a.t - 110, a.t + 300)
        check = self.run_stage(a, "bootstrap-check", auth)
        self.assertEqual(
            (NEW, "success", 70, 1234),
            (
                check["body"]["head_sha"],
                check["body"]["conclusion"],
                check["appId"],
                check["installationId"],
            ),
        )
        a.success()
        a.check[0].update(external_id=framed(auth), completed_at=a.iso(a.t - 75))
        context = self.run_stage(a, "bootstrap-handoff", auth)["context"]
        return auth, self.seal(context, a.t - 55, a.t + 200)

    def test_selected_gh_keyring_gets_only_the_enrolled_repository_and_visibility(self):
        a = BootstrapAPI()
        with patch.object(forge, "_gh_binary", return_value="/fixed/gh"):
            gh = forge.GhReadAPI("fixture/project")
        calls = []

        def exchange(argv):
            calls.append(argv)
            self.assertEqual(
                ["api", "--hostname", "github.com", "--method", "GET", "--include"],
                argv[1:7],
            )
            self.assertEqual("--", argv[-2])
            return (
                0,
                b"HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + canonical(a.get(argv[-1])),
            )

        with patch.object(forge, "_gh_exchange", side_effect=exchange):
            self.assertEqual(
                "frozen-no-main", forge.audit_hold(gh, a.hold_config())["result"]
            )
            a.repo["private"] = True
            with self.assertRaisesRegex(Decision, "forge.repository"):
                forge.audit_hold(gh, a.hold_config())
            a.repo.update(private=False, owner={"id": 11})
            with self.assertRaisesRegex(Decision, "forge.repository"):
                forge.audit_hold(gh, a.hold_config())
            count = len(calls)
            for method, path in (
                ("POST", "/repos/fixture/project/check-runs"),
                ("GET", "/repos/foreign/project"),
                ("GET", "/repos/fixture/project/../foreign/rulesets"),
                ("GET", "/repos/fixture/project/%2e%2e/x"),
                ("GET", "https://elsewhere.invalid/repos/fixture/project"),
                ("GET", "/repos/fixture/project/installation"),
                ("GET", "/repos/fixture/project/rulesets?scope=unexpected"),
            ):
                with (
                    self.subTest(method=method, path=path),
                    self.assertRaisesRegex(Decision, "forge.origin"),
                ):
                    gh.request(method, path)
            self.assertEqual(len(calls), count)

    def test_gh_all_runs_requires_the_exact_commit_endpoint_and_enrolled_check(self):
        with patch.object(forge, "_gh_binary", return_value="/fixed/gh"):
            gh = forge.GhReadAPI("fixture/project")
        root = "/repos/fixture/project/commits/" + NEW
        endpoint = root + "/check-runs"
        query = "?check_name=OCS+Safe+Push&filter=all&per_page=100&page=2"
        with patch.object(
            forge, "_gh_exchange", return_value=(0, b"HTTP/2.0 200 OK\r\n\r\n{}")
        ) as readback:
            self.assertEqual({}, gh.get(endpoint + query))
            self.assertEqual(endpoint + query, readback.call_args.args[0][-1])
            for path in (
                endpoint + "?filter=all",
                endpoint + query.replace("OCS+Safe+Push", "unrelated"),
                endpoint + query + "&check_name=OCS+Safe+Push",
                endpoint + query + "&includes_parents=true",
                root + "/statuses" + query,
                "/repos/fixture/project/rulesets" + query,
                endpoint.replace("fixture/project", "fixture/another") + query,
                endpoint.replace(NEW, "HEAD") + query,
            ):
                with (
                    self.subTest(path=path),
                    self.assertRaisesRegex(Decision, "forge.origin"),
                ):
                    gh.get(path)
            self.assertEqual(readback.call_count, 1)

    def test_gh_error_and_unbounded_payload_cannot_establish_absence(self):
        with patch.object(forge, "_gh_binary", return_value="/fixed/gh"):
            gh = forge.GhReadAPI("fixture/project")
        base = "/repos/fixture/project/"
        for code, endpoint, msg, missing in (
            (403, "rulesets", "access denied", False),
            (404, "git/matching-refs/heads/main", "Not Found", False),
            (404, "branches/main/protection", "Not Found", False),
            (404, "branches/main/protection", "Branch not protected", True),
        ):
            raw = f"HTTP/2.0 {code} Error\n\n".encode() + canonical({"message": msg})
            with patch.object(forge, "_gh_exchange", return_value=(1, raw)):
                if missing:
                    self.assertIsNone(gh.get(base + endpoint))
                else:
                    with self.assertRaisesRegex(Decision, "HTTP " + str(code)):
                        gh.get(base + endpoint)
        for raw in (
            b"unframed JSON",
            b"HTTP/2.0 200 OK\n\n" + b"x" * (4 * 1024 * 1024 + 1),
            b"HTTP/2.0 301 Redirect\n\n{}",
        ):
            with (
                patch.object(forge, "_gh_exchange", return_value=(0, raw)),
                self.assertRaisesRegex(Decision, "forge.readback"),
            ):
                gh.get(base + "rulesets")

    def test_gh_child_excludes_unselected_token_and_debug_environment(self):
        snippet = "import os,sys;sys.stdout.write(str(any(k in os.environ for k in ('GH_TOKEN','GITHUB_TOKEN','GH_DEBUG'))))"
        with patch.dict(
            os.environ,
            {"GH_TOKEN": "synthetic", "GITHUB_TOKEN": "synthetic", "GH_DEBUG": "api"},
        ):
            code, output = forge._gh_exchange([sys.executable, "-I", "-c", snippet])
        self.assertEqual((0, b"False"), (code, output))

    def test_explicit_gh_executable_requires_a_trusted_installed_path_outside_sources(
        self,
    ):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            installed = root / "installed"
            installed.mkdir()
            binary = installed / "gh"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            self.assertEqual(str(binary), forge._gh_binary(binary))
            with self.assertRaisesRegex(Decision, "forge.credentials"):
                forge._gh_binary("installed/gh")
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / ".git").mkdir()
            symlink = checkout / "gh"
            symlink.symlink_to(binary)
            with self.assertRaisesRegex(Decision, "forge.credentials"):
                forge._gh_binary(symlink)
            binary.chmod(0o777)
            with self.assertRaisesRegex(Decision, "forge.credentials"):
                forge._gh_binary(binary)

    def test_visibility_and_operational_default_require_both_provider_flags(self):
        api = ApiFixture()
        public = {
            **api.cfg,
            "format": "ocs.safe-push.forge/2",
            "expectedVisibility": "public",
            "bootstrap": None,
        }
        with self.assertRaisesRegex(Decision, "forge.repository"):
            forge.audit(api, public)
        api.repo.update(private=False, visibility="public")
        self.assertEqual(OLD, forge.audit(api, public)["tip"])
        with self.assertRaisesRegex(Decision, "forge.repository"):
            forge.audit(api, api.cfg)
        api.repo["private"] = True
        with self.assertRaisesRegex(Decision, "forge.repository"):
            forge.audit(api, public)
        api.repo.update(private=False, default_branch="review/safe-push")
        with self.assertRaisesRegex(Decision, "forge.repository"):
            forge.audit(api, public)
        with self.assertRaisesRegex(Decision, "forge.enrollment"):
            forge.enrollment({**api.cfg, "expectedVisibility": "public"})

    def test_exact_frozen_state_accepts_the_raw_hold_rule_shapes_without_apps(self):
        a = BootstrapAPI()
        p = a.hold_config()
        result = forge.audit_hold(a, p)
        self.assertEqual(
            ("frozen-no-main", "public", "review/safe-push", None, 103),
            (
                result["result"],
                result["visibility"],
                result["defaultBranch"],
                result["tip"],
                result["holdRulesetId"],
            ),
        )
        self.assertNotIn("action", result)
        for adjust, criterion in (
            (lambda x: x.repo.update(id=43), "forge.repository"),
            (lambda x: x.repo.update(private=True), "forge.repository"),
            (lambda x: x.repo.update(default_branch="other"), "forge.repository"),
            (lambda x: setattr(x, "staged", "8" * 40), "forge.hold"),
            (lambda x: setattr(x, "head", NEW), "forge.hold"),
            (
                lambda x: x.sets[2]["bypass_actors"].append(
                    {
                        "actor_id": 80,
                        "actor_type": "Integration",
                        "bypass_mode": "always",
                    }
                ),
                "forge.bypass",
            ),
            (
                lambda x: x.sets[2]["rules"][1].update(
                    parameters={"update_allows_fetch_and_merge": True}
                ),
                "forge.rules",
            ),
            (lambda x: x.sets[2].update(enforcement="evaluate"), "forge.rules"),
            (lambda x: x.sets[2]["rules"].pop(), "forge.rules"),
            (lambda x: setattr(x, "ref_list", {"message": "Not Found"}), "forge.ref"),
        ):
            a = BootstrapAPI()
            adjust(a)
            with (
                self.subTest(criterion=criterion),
                self.assertRaisesRegex(Decision, criterion),
            ):
                forge.audit_hold(a, a.hold_config())
        with self.assertRaisesRegex(Decision, "forge.enrollment"):
            forge.enrollment(p)

    def test_ordinary_v1_rules_stay_unchanged_and_working_v2_closes_creation_for_everyone(
        self,
    ):
        a = BootstrapAPI()
        old = forge.rulesets(config("mirror"))
        self.assertIn("creation", [r["type"] for r in old[0]["rules"]])
        stages = forge.bootstrap_rules(a.cfg)
        blueprint = forge.bootstrap_rule_plan({**a.cfg, "bootstrap": None})
        self.assertEqual(blueprint["permanent"], stages)
        self.assertEqual(blueprint["hold"], forge.hold_rule())
        self.assertEqual(blueprint["closure"], forge.rulesets(a.cfg)[2])
        self.assertNotIn("creation", [r["type"] for r in stages[0]["rules"]])
        self.assertIn("creation", [r["type"] for r in stages[1]["rules"]])
        self.assertEqual(80, stages[1]["bypass_actors"][0]["actor_id"])
        self.assertEqual(forge.rulesets(a.cfg)[2]["bypass_actors"], [])
        self.assertEqual(forge.rulesets(a.cfg)[2]["rules"], [{"type": "creation"}])
        with self.assertRaisesRegex(Decision, "forge.bootstrap"):
            forge.bootstrap_rules(config("mirror"))

    def test_operational_writer_accepts_the_exact_default_shape_from_github(self):
        api = BootstrapAPI()
        writer = api.sets[1]
        # Detail, effective rules and saved history can all omit the false exception.
        # The provider can list creation before update even when submission order differed.
        writer["rules"] = [{"type": "creation"}, {"type": "update"}]
        api.histories[102][0]["state"]["rules"] = copy.deepcopy(writer["rules"])
        overlap = forge.bootstrap_state(api, api.cfg, "overlap")
        self.assertEqual(
            (101, 102, 103),
            tuple(
                overlap[name]
                for name in ("integrityRulesetId", "writerRulesetId", "holdRulesetId")
            ),
        )
        steady = ApiFixture()
        steady.sets[1]["rules"] = [{"type": "update"}]
        self.assertEqual(OLD, forge.audit(steady, steady.cfg)["tip"])

    def test_writer_omission_preserves_strict_parameter_bypass_and_rule_checks(self):
        for value in (
            None,
            {},
            [],
            {"update_allows_fetch_and_merge": True},
            {"update_allows_fetch_and_merge": None},
            {"update_allows_fetch_and_merge": 0},
            {"update_allows_fetch_and_merge": 1},
            {"update_allows_fetch_and_merge": "false"},
            {"update_allows_fetch_and_merge": False, "unrecognized": False},
        ):
            api = BootstrapAPI()
            api.sets[1]["rules"] = [
                {"type": "creation"},
                {"type": "update", "parameters": value},
            ]
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(Decision, "forge.rules"),
            ):
                forge.bootstrap_state(api, api.cfg, "overlap")
        api = BootstrapAPI()
        api.sets[1]["rules"] = [
            {"type": "creation"},
            {"type": "update"},
            {"type": "deletion"},
        ]
        with self.assertRaisesRegex(Decision, "forge.rules"):
            forge.bootstrap_state(api, api.cfg, "overlap")
        api.sets[1]["rules"].pop()
        api.sets[1]["bypass_actors"].append(
            {"actor_type": "User", "actor_id": 12, "bypass_mode": "always"}
        )
        with self.assertRaisesRegex(Decision, "forge.bypass"):
            forge.bootstrap_state(api, api.cfg, "overlap")

    def test_bootstrap_preserves_continuity_and_never_publishes_the_review_tip(self):
        a = BootstrapAPI()
        auth, handoff = self.handoff(a)
        with self.assertRaisesRegex(Decision, "forge.rules"):
            self.run_stage(a, "bootstrap-create", auth, handoff)
        a.disable()
        proposal = self.run_stage(a, "bootstrap-create", auth, handoff)
        self.assertEqual(
            (NEW, "absent", 80),
            (proposal["genesis"], proposal["expectedRef"], proposal["publisherAppId"]),
        )
        self.assertIn("--force-with-lease=refs/heads/main:", proposal["argv"])
        self.assertEqual(NEW + ":refs/heads/main", proposal["argv"][-1])
        self.assertNotIn(a.STAGE + ":refs/heads/main", proposal["argv"])
        a.head = NEW
        confirmed = self.run_stage(a, "bootstrap-confirm", auth, handoff)
        self.assertEqual("verified-genesis-readback", confirmed["result"])
        self.assertFalse(confirmed["normalClosureVerified"])
        a.add(104, "OCS canonical creation closed", [{"type": "creation"}], [])
        a.repo["default_branch"] = "main"
        confirmed = self.run_stage(a, "bootstrap-confirm", auth, handoff)
        self.assertTrue(confirmed["normalClosureVerified"])
        self.assertEqual(NEW, forge.audit(a, a.cfg)["tip"])

    def test_unknown_time_gap_missing_check_wrong_custody_or_scope_withhold_initial_creation(
        self,
    ):
        for alter, criterion in (
            (lambda a: setattr(a, "head", OLD), "forge.bootstrap-ref"),
            (lambda a: a.check[0].update(conclusion="neutral"), "forge.check"),
            (
                lambda a: a.status_rule["parameters"].update(
                    do_not_enforce_on_create=True
                ),
                "forge.rules",
            ),
            (
                lambda a: a.installations["publisher"].update(
                    repository_selection="all"
                ),
                "forge.installation",
            ),
            (lambda a: a.check[0].update(conclusion="skipped"), "forge.check"),
            (lambda a: a.check[0].update(app={"id": 80}), "forge.check"),
            (
                lambda a: a.check[0].update(completed_at=a.iso(a.t - 10)),
                "forge.custody",
            ),
            (lambda a: a.obj.update(tree={"sha": "4" * 40}), "forge.genesis"),
            (
                lambda a: a.sets[1]["bypass_actors"].append(
                    {"actor_type": "User", "actor_id": 123, "bypass_mode": "always"}
                ),
                "forge.bypass",
            ),
            (
                lambda a: a.histories[101].append(a.version(a.sets[0], 9999, a.t - 20)),
                "forge.continuity",
            ),
            (
                lambda a: a.histories[103][1].update(updated_at=a.iso(a.t - 350)),
                "forge.rules",
            ),
            (
                lambda a: a.installations["publisher"].update(
                    suspended_at=a.iso(a.t - 31)
                ),
                "forge.installation",
            ),
            (lambda a: a.installations["check"].update(id=5678), "forge.installation"),
        ):
            a = BootstrapAPI()
            auth, handoff = self.handoff(a)
            a.disable()
            alter(a)
            with (
                self.subTest(criterion=criterion),
                self.assertRaisesRegex(Decision, criterion),
            ):
                self.run_stage(a, "bootstrap-create", auth, handoff)
        a = BootstrapAPI()
        auth, handoff = self.handoff(a)
        a.disable()
        with self.assertRaisesRegex(Decision, "forge.custody"):
            self.run_stage(a, "bootstrap-create", auth, None)
        late = {
            k: v
            for k, v in handoff["payload"].items()
            if k not in ("issuedAt", "expiresAt")
        }
        with self.assertRaisesRegex(Decision, "forge.continuity"):
            self.run_stage(
                a, "bootstrap-create", auth, self.seal(late, a.t - 5, a.t + 120)
            )
        auth["signatures"]["guardian"] = auth["signatures"]["publisher"]
        with self.assertRaisesRegex(Decision, "forge.custody"):
            self.run_stage(a, "bootstrap-create", auth, handoff)

    def test_receiver_experiment_and_any_unenrolled_or_non_genesis_tip_cannot_satisfy_bootstrap(
        self,
    ):
        a = BootstrapAPI()
        for profile, tip, n in (
            ("receiver-experiment/1", NEW, 0),
            ("ocs-release/1", a.STAGE, 1),
            ("ocs-release/1", OLD, 0),
        ):
            policy = {"profile": profile, "requiredOpen": [], "genesis": NEW}
            cfg = {"project": "ocs", "genesis": NEW}
            current = {
                "status": "verified",
                "profile": profile,
                "project": "ocs",
                "certifiedTransitions": n,
                "genesis": NEW,
                "tip": tip,
            }
            with (
                patch.object(
                    forge,
                    "state",
                    return_value=(cfg, None, None, Path("/fixture"), policy),
                ),
                patch.object(forge, "chain_status", return_value=current),
                patch.object(forge, "readref", return_value=tip),
                self.assertRaisesRegex(Decision, "forge.genesis"),
            ):
                forge.qualified_genesis(Path("/fixture/config"), a.cfg)


if __name__ == "__main__":
    unittest.main()
