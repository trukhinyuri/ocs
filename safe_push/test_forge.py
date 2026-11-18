"""Hosted API readbacks are synthetic. The local verification case uses real Git and Ed25519."""

import copy
import hashlib
import hmac
import io
import os
import subprocess
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
