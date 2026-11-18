"""Exercise receiver custody and restart invariants with disposable independent keys."""

import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import get_parent, state
from authority import (
    ROLES,
    Decision,
    authentic,
    canonical,
    framed,
    immutable,
    load,
    replace_pointer,
    signature,
    validate_policy,
)
from operator_cli import checkpoint, install, rotate
from receiver import chain_status, selected_receipt
from test_receiver import BASE, Experiment, append_note, ensure_key, git


def new_rotation(exp):
    current = state(exp.config)[-1]
    keys_dir = exp.work / "successor-identities"
    keys_dir.mkdir(mode=0o700)
    keys = {role: ensure_key(keys_dir, role) for role in (*ROLES, "publisher")}
    proposed = {**current, "epoch": current["epoch"] + 1, "keys": keys}
    binding = {
        "format": "ocs.safe-push.rotation/1",
        "project": current["project"],
        "old": framed(current),
        "new": framed(proposed),
        "epoch": proposed["epoch"],
    }
    record = {"policy": proposed}
    for side, custody in (("old", exp.keydir), ("new", keys_dir)):
        record[side] = {
            role: signature(
                {**binding, "role": role, "side": side}, custody / (role + ".key")
            )
            for role in ROLES
        }
    return proposed, record, keys_dir


def checkpoint_envelopes(exp):
    cfg, authority, journal, repo, policy = state(exp.config)
    floor = load(Path(cfg["witness"]))
    tip = git(repo, "rev-parse", "refs/heads/main")
    receipt = get_parent(cfg, authority, journal, tip)
    payload = {
        "format": "ocs.safe-push.checkpoint/1",
        "project": policy["project"],
        "epoch": policy["epoch"],
        "policy": framed(policy),
        "priorFloor": floor["branchFloor"],
        "tip": tip,
        "receipt": framed(receipt),
    }
    return payload, {
        role: signature({**payload, "role": role}, exp.keydir / (role + ".key"))
        for role in ("guardian", "independent")
    }


def await_file(path, child):
    deadline = time.monotonic() + 45
    while not path.exists() and time.monotonic() < deadline:
        if child.poll() is not None:
            _, err = child.communicate()
            raise AssertionError(
                "fixture process quit before the durable marker: "
                + err.decode(errors="replace")[-800:]
            )
        time.sleep(0.02)
    if not path.exists():
        raise AssertionError(
            "fixture failed to reach its real Git post-receive boundary"
        )


def interrupted_rotation(config, record, key):
    """Subprocess fixture. End the operator process at its single external pointer write."""
    witness = Path(load(config)["witness"])

    def interrupt(path, data):
        if path != witness:
            raise RuntimeError("unexpected interrupted write")
        proposed = load(record)["policy"]
        if json.loads(data)["policy"] != framed(proposed):
            raise RuntimeError("unexpected checkpoint payload")
        os._exit(72)

    with patch("operator_cli.replace_pointer", side_effect=interrupt):
        rotate(config, record, key)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocs-authority-controls-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.exp = Experiment(self.work, HERE.parent)
        self.floor = Path(self.exp.cfg["witness"])

    def verdict(self, criterion, perform):
        with self.assertRaises(Decision) as caught:
            perform()
        self.assertEqual(caught.exception.criterion, criterion)
        return caught.exception

    def proposal(self, title, parent=BASE):
        rev = self.exp.candidate(parent, title, append_note(title))
        self.exp.stage(rev)
        self.exp.reviews(parent, rev)
        return rev

    def test_roles_and_both_quorums_protect_key_replacement(self):
        exp = self.exp
        original = load(self.floor)
        policy, record, keys = new_rotation(exp)
        duplicated = {
            **exp.policy,
            "keys": {**exp.policy["keys"], "domain": exp.policy["keys"]["guardian"]},
        }
        self.verdict("trust.roles", lambda: validate_policy(duplicated))
        authorized = {"purpose": "isolated signed role check"}
        envelope = signature(authorized, exp.keydir / "domain.key")
        self.assertEqual(
            authentic(envelope, exp.policy["keys"]["domain"], "roles.test"), authorized
        )
        self.verdict(
            "roles.test",
            lambda: authentic(
                envelope, exp.policy["keys"]["independent"], "roles.test"
            ),
        )
        for field in ("old", "new"):
            wrong = copy.deepcopy(record)
            del wrong[field]["guardian"]
            path = self.work / ("incomplete-" + field + ".json")
            immutable(path, canonical(wrong))
            self.verdict(
                "trust.rotation",
                lambda pending=path: rotate(
                    exp.config, pending, keys / "publisher.key"
                ),
            )
            self.assertEqual(load(self.floor), original)
        full = self.work / "rotation.json"
        immutable(full, canonical(record))
        self.verdict("trust.publisher", lambda: rotate(exp.config, full))
        self.verdict(
            "trust.publisher",
            lambda: rotate(exp.config, full, exp.keydir / "publisher.key"),
        )
        self.assertEqual(state(exp.config)[-1]["epoch"], 0)
        stale = self.proposal("reviewed-under-prior-keys")
        rotate(exp.config, full, keys / "publisher.key")
        self.assertEqual(state(exp.config)[-1], policy)
        self.assertEqual(load(self.floor)["epoch"], 1)
        self.assertTrue((exp.a / "rotations" / "000000000001.json").is_file())
        exp.push("old review cannot approve a new epoch", stale, False, "signature")
        exp.keydir = keys
        current = self.proposal("reviewed-under-successor-keys")
        exp.push("registered successor publisher and current roles", current, True)
        seal = load(exp.j / "signatures" / (current + ".json"))
        self.assertEqual(
            authentic(seal, policy["keys"]["publisher"], "audit.test")["epoch"], 1
        )
        self.verdict(
            "audit.test",
            lambda: authentic(seal, exp.policy["keys"]["publisher"], "audit.test"),
        )

    def test_rotation_crash_before_external_floor_and_exact_restart(self):
        exp = self.exp
        initial = load(self.floor)
        policy, record, keys = new_rotation(exp)
        pending = self.work / "pending-rotation.json"
        immutable(pending, canonical(record))
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--interrupt-rotation",
                str(exp.config),
                str(pending),
                str(keys / "publisher.key"),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(
            result.returncode, 72, result.stderr.decode(errors="replace")[-600:]
        )
        record_path = exp.a / "rotations" / "000000000001.json"
        self.assertEqual(load(record_path), record)
        self.assertEqual(load(self.floor), initial)
        self.verdict("trust.rollback", lambda: state(exp.config))
        alternative = self.work / "different-retry.json"
        altered = copy.deepcopy(record)
        del altered["new"]["guardian"]
        immutable(alternative, canonical(altered))
        self.verdict(
            "trust.rotation",
            lambda: rotate(exp.config, alternative, keys / "publisher.key"),
        )
        self.assertEqual(load(self.floor), initial)
        rotate(exp.config, pending)
        self.assertEqual(state(exp.config)[-1], policy)
        self.assertEqual(load(self.floor)["policy"], framed(policy))
        # Restore an older local authority history while its independent floor stays current.
        prior = self.work / "rotation-from-later-snapshot.json"
        os.replace(record_path, prior)
        try:
            self.verdict("trust.rollback", lambda: state(exp.config))
        finally:
            os.replace(prior, record_path)
        self.assertEqual(state(exp.config)[-1]["epoch"], 1)

    def test_external_genesis_floor_binds_the_enrolled_genesis_receipt(self):
        original = load(self.floor)
        self.assertEqual(original["branchFloor"], BASE)
        self.assertEqual(original["receiptDigest"], self.exp.cfg["genesisDigest"])
        stale = {**original, "receiptDigest": framed(self.exp.policy)}
        replace_pointer(self.floor, canonical(stale))
        try:
            self.verdict("trust.rollback", lambda: state(self.exp.config))
        finally:
            replace_pointer(self.floor, canonical(original))

    def test_protected_checkpoint_rejects_old_local_ref_and_stale_external_floor(self):
        exp = self.exp
        rev = self.proposal("checkpoint-witness")
        published_seed = self.work / "earlier-repository.git"
        shutil.copytree(exp.bare, published_seed)
        exp.push("published checkpoint subject", rev, True)
        original = load(self.floor)
        data, envelopes = checkpoint_envelopes(exp)
        wrong = {
            **envelopes,
            "independent": signature(
                {**data, "role": "independent"}, exp.keydir / "domain.key"
            ),
        }
        self.verdict("trust.checkpoint", lambda: checkpoint(exp.config, wrong))
        self.assertEqual(load(self.floor), original)
        checkpoint(exp.config, envelopes)
        current = load(self.floor)
        self.assertEqual(current["branchFloor"], rev)
        self.assertEqual(current["receiptDigest"], data["receipt"])
        self.assertEqual(
            load(exp.a / "checkpoints" / (framed(data) + ".json")), envelopes
        )
        # Keep both authentic commits in the database but restore the older local ref snapshot.
        saved = self.work / "current-repository.git"
        os.replace(exp.bare, saved)
        os.replace(published_seed, exp.bare)
        try:
            self.assertEqual(git(exp.bare, "rev-parse", "refs/heads/main"), BASE)
            self.verdict("trust.rollback", lambda: state(exp.config))
        finally:
            os.replace(exp.bare, published_seed)
            os.replace(saved, exp.bare)
        self.assertEqual(state(exp.config)[-1]["epoch"], 0)
        # A newer authentic branch checkpoint also exposes an older same-epoch witness copy.
        replace_pointer(self.floor, canonical(original))
        self.verdict("trust.rollback", lambda: state(exp.config))
        self.verdict("trust.rollback", lambda: checkpoint(exp.config, wrong))
        self.assertEqual(load(self.floor), original)
        checkpoint(exp.config, envelopes)
        self.assertEqual(load(self.floor), current)
        self.assertEqual(chain_status(exp.config, True)["tip"], rev)

    def test_inconsistent_unsigned_parent_index_cannot_advance_the_real_ref(self):
        exp = self.exp
        parent = self.proposal("authenticated-parent")
        exp.push("authenticated parent", parent, True)
        child = self.proposal("requires-signed-parent", parent)
        index = exp.j / "committed" / (parent + ".json")
        original = load(index)
        envelope = load(exp.j / "signatures" / (parent + ".json"))
        self.assertEqual(selected_receipt(exp.a, exp.cfg, envelope), original)
        replace_pointer(index, canonical({**original, "previousReceipt": "4" * 64}))
        try:
            self.verdict(
                "audit.parent", lambda: get_parent(exp.cfg, exp.a, exp.j, parent)
            )
            exp.push(
                "unsigned restored index disagrees with signed receipt", child, False
            )
            self.assertEqual(exp.readback(), parent)
            self.assertFalse((exp.j / "committed" / (child + ".json")).exists())
        finally:
            replace_pointer(index, canonical(original))
        self.assertEqual(chain_status(exp.config, True)["tip"], parent)

    def test_unresolved_enrolled_claim_keeps_publication_at_the_qualified_parent(self):
        original = self.exp
        holding = {
            **original.policy,
            "requiredOpen": ["authority-fixture.current-independent-claim"],
        }
        path = self.work / "holding-policy.json"
        immutable(path, canonical(holding))
        methods = sorted((original.a / "methods").glob("*.py"))
        other = install(
            self.work / "holding-receiver",
            HERE.parent,
            path,
            self.work / "bootstrap",
            [],
            methods,
            original.keydir / "publisher.key",
            None,
        )
        work = self.work / "holding-client"
        work.mkdir()
        exp = Experiment(work, HERE.parent, cfg=other)
        exp.keydir = original.keydir
        rev = exp.candidate(
            BASE, "unresolved registered claim", append_note("undeclared-observation")
        )
        exp.stage(rev)
        exp.reviews(BASE, rev)
        exp.push(
            "required claim still lacks its independent evidence",
            rev,
            False,
            "unresolved",
        )
        self.assertEqual(exp.readback(), BASE)
        self.assertFalse((exp.j / "committed" / (rev + ".json")).exists())
        self.verdict("scope.open", lambda: chain_status(exp.config, True))

    @unittest.skipUnless(
        sys.platform == "linux" and hasattr(os, "pidfd_open"),
        "Linux owned-process interruption",
    )
    def test_git_commit_precedes_settlement_and_a_restarted_receiver_recovers_once(
        self,
    ):
        exp = self.exp
        rev = self.proposal("recover-real-ref")
        anchor = self.work / "fixture-process.json"
        arrived = self.work / "post-receive.json"
        release = self.work / "resume-post-receive"
        # This extra post-receive observer runs after Git's verified transaction. Both mandatory
        # installed hooks remain intact. It exists only in this disposable receiver.
        hook = Path(git(exp.bare, "config", "--get", "core.hooksPath")) / "post-receive"
        hook_data = (
            "#!"
            + sys.executable
            + "\nimport json,os,sys,time\nfrom pathlib import Path\n"
            + "marker=Path("
            + repr(str(arrived))
            + ")\nrelease=Path("
            + repr(str(release))
            + ")\n"
            + "row=sys.stdin.buffer.read().decode().split()\nscratch=marker.with_suffix('.writing')\n"
            + "scratch.write_text(json.dumps(row));os.replace(scratch,marker)\n"
            + "until=time.monotonic()+45\nwhile not release.exists() and time.monotonic()<until:\n    time.sleep(.02)\n"
        )
        immutable(hook, hook_data.encode())
        hook.chmod(0o755)
        launcher = self.work / "owned-publisher.py"
        launcher.write_text(
            "import os,sys\nfrom pathlib import Path\n"
            + "Path("
            + repr(str(anchor))
            + ").write_text(str(os.getpid()))\n"
            + "os.execv(sys.executable,[sys.executable,'-I',"
            + repr(str(HERE / "receiver.py"))
            + ",'serve',"
            + repr(str(exp.config))
            + ",sys.argv[1]])\n"
        )
        url = f"ext::{sys.executable} -I {launcher} %S"
        child = subprocess.Popen(
            [
                "git",
                "-C",
                str(exp.client),
                "-c",
                "protocol.ext.allow=always",
                "push",
                url,
                rev + ":refs/heads/main",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            await_file(arrived, child)
            old, new, ref = load(arrived)
            self.assertEqual((old, new, ref), (BASE, rev, "refs/heads/main"))
            self.assertEqual(git(exp.bare, "rev-parse", "refs/heads/main"), rev)
            intent = load(exp.j / "inflight.json")
            prepared = load(exp.j / "prepared" / (intent["receipt"] + ".json"))
            self.assertEqual(framed(prepared), intent["receipt"])
            self.assertEqual(
                selected_receipt(exp.a, exp.cfg, prepared)["candidate"], rev
            )
            self.assertFalse((exp.j / "committed" / (rev + ".json")).exists())
            pid = int(anchor.read_text())
            handle = os.pidfd_open(pid)
            try:
                args = (
                    (Path("/proc") / str(pid) / "cmdline")
                    .read_bytes()
                    .split(b"\0")[:-1]
                )
                self.assertEqual(
                    args,
                    [
                        os.fsencode(sys.executable),
                        b"-I",
                        os.fsencode(HERE / "receiver.py"),
                        b"serve",
                        os.fsencode(exp.config),
                        b"git-receive-pack",
                    ],
                )
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            finally:
                os.close(handle)
        finally:
            release.touch(exist_ok=True)
            try:
                child.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        # A new invocation uses the same native verification and reconciliation as startup.
        command = [
            sys.executable,
            "-I",
            str(HERE / "receiver.py"),
            "consume",
            str(exp.config),
        ]
        for _ in range(2):
            record = json.loads(
                subprocess.check_output(command, stderr=subprocess.PIPE, timeout=45)
            )
            self.assertEqual((record["tip"], record["certifiedTransitions"]), (rev, 1))
        self.assertFalse((exp.j / "inflight.json").exists())
        self.assertEqual(load(exp.j / "signatures" / (rev + ".json")), prepared)
        self.assertEqual(
            load(exp.j / "outcomes" / (intent["tx"] + ".json")),
            {"outcome": "committed", "receipt": intent["receipt"], "readback": rev},
        )


if __name__ == "__main__":
    if sys.argv[1:2] == ["--interrupt-rotation"]:
        interrupted_rotation(*(Path(value) for value in sys.argv[2:]))
    else:
        unittest.main()
