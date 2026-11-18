"""Read the actual receive-pack quarantine and verify evaluator-only Git operands."""

import base64
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import object_view as view
from authority import Decision, canonical, framed
from scope import inventory, subject


def git(repo, *args, raw=None, check=True):
    env = {
        **view.environment(),
        "GIT_AUTHOR_NAME": "Object fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Object fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        input=raw,
        capture_output=True,
        env=env,
        timeout=30,
        check=check,
    )


def oid(repo, *args):
    return git(repo, *args).stdout.decode().strip()


def projection_case(root, algo="sha1", single=False):
    work, store = root / "author", root / "repository.git"
    work.mkdir(parents=True)
    git(work, "init", "--quiet", "--initial-branch=main", "--object-format=" + algo)
    git(
        root,
        "init",
        "--quiet",
        "--bare",
        "--initial-branch=main",
        "--object-format=" + algo,
        str(store),
    )
    (work / "README.md").write_text("Historical publication.\n")
    (work / "old-only.md").write_text("Earlier, outside the selected tree.\n")
    git(work, "add", ".")
    git(work, "commit", "--quiet", "-m", "historical")
    historical = oid(work, "rev-parse", "HEAD")
    (work / "old-only.md").unlink()
    (work / "README.md").write_text("Parent contents.\n")
    git(work, "add", "-A")
    git(work, "commit", "--quiet", "-m", "parent")
    parent = oid(work, "rev-parse", "HEAD")
    git(work, "push", "--quiet", str(store), "HEAD:refs/heads/main")
    (work / "docs").mkdir()
    (work / "docs/source.md").write_text("Candidate contents.\n")
    (work / "docs/parent.md").symlink_to("../README.md")
    git(work, "add", "docs")
    git(work, "commit", "--quiet", "-m", "candidate")
    candidate = oid(work, "rev-parse", "HEAD")
    identity = subject(work, candidate, inventory(work, candidate))
    ctx = {
        "parent": parent,
        "candidate": candidate,
        "tree": oid(work, "rev-parse", "HEAD^{tree}"),
        "sourceSha256": identity["treeSha256"],
    }
    args = {"subject": identity} if single else {"subject": identity, "context": ctx}
    argfile = root / "authorized.json"
    output = root / "observed.json"
    argfile.write_bytes(canonical(args))
    hook = store / "hooks" / "pre-receive"
    hook.write_text(
        "#!"
        + sys.executable
        + " -I\nimport json,os,sys\nfrom pathlib import Path\n"
        + "sys.path.insert(0,"
        + repr(str(HERE))
        + ")\nfrom object_view import maybe_export\nfrom authority import canonical\n"
        + "old,new,ref=sys.stdin.buffer.read().decode('ascii').split()\n"
        + "assert ref=='refs/heads/main' and old=="
        + repr(parent)
        + " and new=="
        + repr(candidate)
        + "\n"
        + "args=json.loads(Path("
        + repr(str(argfile))
        + ").read_bytes())\n"
        + "assert os.environ.get('GIT_QUARANTINE_PATH')\npacket=maybe_export(Path("
        + repr(str(store))
        + "),args)\n"
        + "assert packet is not None\nPath("
        + repr(str(output))
        + ").write_bytes(canonical(packet))\n"
    )
    hook.chmod(0o755)
    git(work, "push", "--quiet", str(store), "HEAD:refs/heads/main")
    return store, args, json.loads(output.read_bytes()), historical


def reseal(packet):
    values = packet["objects"]
    packet["rawBytes"] = sum(v["size"] for v in values.values())
    packet["closureSha256"] = framed(
        {k: [v["type"], v["size"], v["sha256"]] for k, v in values.items()}
    )


class ObjectViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="ocs-private-object-controls-")
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        cls.store, cls.args, cls.packet, cls.historical = projection_case(cls.root)

    def refusal(self, criterion, operation):
        with self.assertRaises(Decision) as caught:
            operation()
        self.assertEqual(caught.exception.criterion, criterion)

    def test_ordinary_receive_pack_exposes_only_selected_objects_and_no_branch(self):
        dest = view.materialize(self.packet, self.args, self.root / "verified.git")
        self.assertIsNone(view.maybe_export(self.store, self.args))
        ctx = self.args["context"]
        self.assertEqual(
            git(dest, "show", ctx["candidate"] + ":docs/source.md").stdout,
            b"Candidate contents.\n",
        )
        self.assertEqual(
            git(dest, "show", ctx["parent"] + ":README.md").stdout,
            b"Parent contents.\n",
        )
        self.assertEqual(
            git(
                dest, "diff", "--name-only", ctx["parent"], ctx["candidate"]
            ).stdout.splitlines(),
            [b"docs/parent.md", b"docs/source.md"],
        )
        self.assertEqual(git(dest, "for-each-ref").stdout, b"")
        self.assertFalse((dest / "objects/info/alternates").exists())
        self.assertEqual(
            set(
                git(
                    dest,
                    "cat-file",
                    "--batch-all-objects",
                    "--batch-check=%(objectname)",
                )
                .stdout.decode()
                .split()
            ),
            set(self.packet["objects"]),
        )
        self.assertNotIn(self.historical, self.packet["objects"])
        self.assertNotEqual(
            git(dest, "cat-file", "-e", self.historical, check=False).returncode, 0
        )
        git(dest, "fsck", "--full", "--strict")
        victim = dest / "objects" / ctx["candidate"][:2] / ctx["candidate"][2:]
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o444)

    def test_subject_only_sha256_exports_no_parent_commit(self):
        root = self.root / "sha256"
        root.mkdir()
        _, args, packet, _ = projection_case(root, "sha256", single=True)
        candidate = args["subject"]["revision"]
        repo = view.materialize(packet, args, root / "verified.git")
        self.assertEqual(packet["objectFormat"], "sha256")
        self.assertEqual(
            [o for o, v in packet["objects"].items() if v["type"] == "commit"],
            [candidate],
        )
        self.assertEqual(
            git(repo, "show", candidate + ":docs/parent.md").stdout, b"../README.md"
        )
        self.assertEqual((repo / "shallow").read_text().strip(), candidate)
        git(repo, "fsck", "--full", "--strict")

    def test_object_substitution_missing_and_rehashed_unselected_object_are_refused(
        self,
    ):
        candidate = self.args["context"]["candidate"]
        missing = copy.deepcopy(self.packet)
        blob = next(o for o, v in missing["objects"].items() if v["type"] == "blob")
        del missing["objects"][blob]
        reseal(missing)
        changed = copy.deepcopy(self.packet)
        data = b"x" * changed["objects"][blob]["size"]
        changed["objects"][blob].update(
            sha256=hashlib.sha256(data).hexdigest(),
            data=base64.b64encode(data).decode(),
        )
        reseal(changed)
        extra = copy.deepcopy(self.packet)
        content = git(self.store, "cat-file", "commit", self.historical).stdout
        extra["objects"][self.historical] = {
            "type": "commit",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "data": base64.b64encode(content).decode(),
        }
        reseal(extra)
        for name, packet, criterion in [
            ("missing", missing, "method.object-closure"),
            ("changed", changed, "method.object-payload"),
            ("extra", extra, "method.object-closure"),
        ]:
            with self.subTest(case=name):
                destination = self.root / ("unchecked-" + candidate[:5] + name)
                self.refusal(
                    criterion,
                    lambda p=packet, d=destination: view.materialize(p, self.args, d),
                )
                self.assertFalse(destination.exists())

    def test_wrong_revision_tree_and_subject_metadata_are_refused(self):
        parent = self.args["context"]["parent"]
        tests = [
            {"subject": {"revision": parent}},
            {
                "subject": {**self.args["subject"], "fileCount": True},
                "context": self.args["context"],
            },
            {
                "subject": self.args["subject"],
                "context": {**self.args["context"], "tree": "b" * 40},
            },
            {
                "subject": {**self.args["subject"], "revision": self.historical},
                "context": self.args["context"],
            },
            {"context": {"candidate": parent}},
            {},
        ]
        for arg in tests:
            with self.subTest(args=arg):
                self.refusal(
                    "method.object-binding",
                    lambda a=arg: view.materialize(
                        self.packet, a, self.root / "rejected.git"
                    ),
                )
        unrelated = {
            "context": {
                "parent": self.historical,
                "candidate": self.args["context"]["candidate"],
            }
        }
        self.refusal(
            "method.object-binding", lambda: view.maybe_export(self.store, unrelated)
        )

    def test_missing_or_foreign_quarantine_and_excessive_views_are_held(self):
        missing = {"subject": {"revision": "f" * 40}}
        with patch.dict(
            os.environ, {"GIT_QUARANTINE_PATH": "", "GIT_OBJECT_DIRECTORY": ""}
        ):
            self.refusal(
                "method.object-missing", lambda: view.maybe_export(self.store, missing)
            )
        foreign = self.root / "other-private-object-directory"
        foreign.mkdir()
        with patch.dict(
            os.environ,
            {"GIT_QUARANTINE_PATH": str(foreign), "GIT_OBJECT_DIRECTORY": str(foreign)},
        ):
            self.refusal(
                "method.object-quarantine",
                lambda: view.maybe_export(self.store, missing),
            )
        with patch.object(view, "MAX_TRANSFER", 3):
            self.refusal(
                "method.object-limit",
                lambda: view.materialize(
                    self.packet, self.args, self.root / "too-large.git"
                ),
            )
        occupied = self.root / "occupied.git"
        occupied.mkdir()
        self.refusal(
            "method.object-destination",
            lambda: view.materialize(self.packet, self.args, occupied),
        )


if __name__ == "__main__":
    unittest.main()
