"""Check the installed-files and permission model in disposable directories."""

import grp
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import git_remote_ocs
import local_install as native


class NativeInstallationTests(unittest.TestCase):
    def test_single_socket_and_read_only_release(self):
        units = native.unit_text("exercise", "test-clients")
        service = units["ocs-safe-push-exercise@.service"]
        sock = units["ocs-safe-push-exercise.socket"]
        self.assertIn("Accept=yes", sock)
        self.assertIn("SocketMode=0660", sock)
        self.assertIn("SocketGroup=test-clients", sock)
        self.assertIn("StandardInput=socket", service)
        self.assertIn("User=ocs-sp-exercise", service)
        writable = next(
            line for line in service.splitlines() if line.startswith("ReadWritePaths=")
        )
        self.assertEqual(
            [x.rsplit("/", 1)[-1] for x in writable.split("=", 1)[1].split()],
            ["journal", "objects", "reftable"],
        )
        self.assertIn("NoNewPrivileges=yes", service)
        with self.assertRaises(ValueError):
            native.unit_text("../another", "other")
        with tempfile.TemporaryDirectory() as d:
            files = []
            for n, s in units.items():
                f = Path(d) / n
                f.write_text(s)
                files.append(f)
            if shutil.which("systemd-analyze"):
                native.run("/usr/bin/systemd-analyze", "verify", *files)

    def test_evaluator_is_a_separate_resource_bounded_unit(self):
        units = native.unit_text("exercise", "test-clients")
        publisher = units["ocs-safe-push-exercise@.service"]
        worker = units["ocs-safe-method-exercise@.service"]
        socket_unit = units["ocs-safe-method-exercise.socket"]
        self.assertIn("User=ocs-me-exercise", worker)
        self.assertIn("SupplementaryGroups=ocs-sp-exercise", worker)
        self.assertIn("PrivatePIDs=yes", worker)
        self.assertIn("ProtectSystem=strict", worker)
        self.assertIn("CPUQuota=200%", worker)
        self.assertIn("MemoryMax=1G", worker)
        self.assertIn("TasksMax=128", worker)
        self.assertIn("nosuid,nodev,noexec", worker)
        self.assertNotIn("ReadWritePaths=", worker)
        self.assertIn("RestrictSUIDSGID=yes", publisher)
        self.assertNotIn("SupplementaryGroups=", publisher)
        self.assertIn("SocketGroup=ocs-sp-exercise", socket_unit)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("MaxConnections=8", socket_unit)
        self.assertIn(
            "ListenStream=/run/ocs-safe-push-method/exercise.sock", socket_unit
        )
        self.assertEqual(
            len(native.unit_text("exercise", "test-clients", broker=False)), 2
        )

    def test_lean_identity_includes_transitive_library_and_link(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "lean"
            (src / "bin").mkdir(parents=True)
            (src / "lib/lean").mkdir(parents=True)
            binary = src / "bin/lean"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' revision\n")
            binary.chmod(0o755)
            lib = src / "lib/lean/Init.olean"
            lib.write_bytes(b"checked dependency")
            (src / "lib/current").symlink_to("lean/Init.olean")
            original = native.tree_digest(src)
            manifest = {
                "commit": "revision",
                "builds": {
                    native.platform.system() + "/" + native.platform.machine(): {
                        "files": {"bin/lean": native.digest_file(binary)}
                    }
                },
            }
            info = native.pin_lean(
                root / "isolated", manifest, home=src, expected_tree=original
            )
            self.assertEqual(info["treeSha256"], original)
            lib.write_bytes(b"substituted library")
            with self.assertRaisesRegex(ValueError, "source Lean tree"):
                native.pin_lean(
                    root / "altered", manifest, home=src, expected_tree=original
                )
            (src / "lib/current").unlink()
            (src / "lib/current").symlink_to(root)
            with self.assertRaisesRegex(ValueError, "escaping link"):
                native.tree_digest(src)

    def test_prepared_copy_preserves_ref_and_receipts_uses_fresh_hooks(self):
        with tempfile.TemporaryDirectory() as d:
            temp = Path(d)
            src = temp / "old"
            src.mkdir()
            a = src / "authority"
            a.mkdir()
            j = src / "journal"
            j.mkdir()
            keys = src / "publishing"
            keys.mkdir()
            for f in ("root.json", "genesis.json"):
                (a / f).write_bytes(b"{}")
            (j / "fixture-observation.json").write_bytes(b"independent trial data")
            (keys / "fixture.key").write_bytes(b"fixture only")
            repo = src / "repository.git"
            native.run(
                "/usr/bin/git",
                "init",
                "--bare",
                "--initial-branch=main",
                "--template=",
                repo,
            )
            env = {
                k: v
                for role in ("AUTHOR", "COMMITTER")
                for k, v in [
                    ("GIT_" + role + "_NAME", "Fixture"),
                    ("GIT_" + role + "_EMAIL", "fixture@example.invalid"),
                ]
            }
            tree = native.run("/usr/bin/git", "-C", repo, "mktree", input=b"").strip()
            rev = (
                native.run(
                    "/usr/bin/git",
                    "-C",
                    repo,
                    "commit-tree",
                    tree,
                    "-m",
                    "fixture",
                    env=env,
                )
                .decode()
                .strip()
            )
            native.git(repo, "update-ref", "refs/heads/main", rev)
            native.git(
                repo,
                "config",
                "core.hooksPath",
                "/administrator-must-not-use-prepared-hooks",
            )
            cfg = {
                "project": "fixture",
                "genesis": rev,
                "rootDigest": native.sha(b"{}"),
                "genesisDigest": native.sha(b"{}"),
                "repo": str(repo),
                "authority": str(a),
                "journal": str(j),
                "publishingKeys": str(keys),
                "leanHome": str(temp),
            }
            witness = temp / "independent-checkpoint.json"
            witness.write_bytes(
                native.canonical(
                    {
                        "epoch": 0,
                        "project": "fixture",
                        "policy": native.sha(b"{}"),
                        "branchFloor": rev,
                        "receiptDigest": native.sha(b"{}"),
                    }
                )
            )
            cfg["witness"] = str(witness)
            config = src / "receiver.json"
            config.write_bytes(native.canonical(cfg))
            signature = native.sha(config.read_bytes())
            (src / "sealed.json").write_bytes(
                native.canonical({"configuration": signature})
            )
            new = temp / "installed"
            new.mkdir()
            state = new / "state"
            release = new / "release"
            out = native.prepare_copy(config, signature, state, release, new / "lean")
            self.assertEqual(out, state / "receiver.json")
            self.assertEqual(
                (state / "witness/epoch.json").read_bytes(), witness.read_bytes()
            )
            self.assertEqual(
                native.git(
                    state / "repository.git", "rev-parse", "--show-ref-format"
                ).strip(),
                b"reftable",
            )
            self.assertEqual(
                native.git(state / "repository.git", "rev-parse", "HEAD")
                .decode()
                .strip(),
                rev,
            )
            self.assertEqual(
                (state / "journal/fixture-observation.json").read_bytes(),
                b"independent trial data",
            )
            self.assertEqual(
                native.git(repo, "rev-parse", "--show-ref-format").strip(), b"files"
            )
            self.assertEqual(
                native.git(state / "repository.git", "config", "core.hooksPath")
                .decode()
                .strip(),
                str(state / "hooks"),
            )
            with self.assertRaisesRegex(ValueError, "pin"):
                native.signed_config(config, expected="0" * 64)
            (a / "substitute").symlink_to(config)
            with self.assertRaises(OSError):
                native.prepare_copy(
                    config, signature, new / "refused", release, new / "lean"
                )

    def test_reftable_updates_without_bare_root_write(self):
        # In this test an unrelated unprivileged account has write access only to the
        # disposable reference tables; no account, service or socket is installed.
        if os.geteuid() == 0 or not shutil.which("sudo"):
            self.skipTest(
                "requires an ordinary account with an available local UID switch"
            )
        if subprocess.run(
            ["sudo", "-n", "-u", "nobody", "true"], capture_output=True, check=False
        ).returncode:
            self.skipTest("separate test UID unavailable")
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            base.chmod(0o755)
            repo = base / "bare.git"
            native.run(
                "/usr/bin/git",
                "init",
                "--bare",
                "--initial-branch=main",
                "--ref-format=reftable",
                "--template=",
                repo,
            )
            tree = native.run("/usr/bin/git", "-C", repo, "mktree", input=b"").strip()
            env = {
                k: v
                for role in ("AUTHOR", "COMMITTER")
                for k, v in [
                    ("GIT_" + role + "_NAME", "Fixture"),
                    ("GIT_" + role + "_EMAIL", "fixture@example.invalid"),
                ]
            }
            old = native.run(
                "/usr/bin/git", "-C", repo, "commit-tree", tree, "-m", "old", env=env
            ).strip()
            new = native.run(
                "/usr/bin/git",
                "-C",
                repo,
                "commit-tree",
                tree,
                "-p",
                old,
                "-m",
                "new",
                env=env,
            ).strip()
            native.git(repo, "update-ref", "refs/heads/main", old)
            table = repo / "reftable"
            for item in [table, *table.rglob("*")]:
                item.chmod(0o777 if item.is_dir() else 0o666)
            native.run(
                "/usr/bin/sudo",
                "-n",
                "-u",
                "nobody",
                "/usr/bin/git",
                "-c",
                "safe.directory=" + str(repo),
                "-C",
                repo,
                "update-ref",
                "refs/heads/main",
                new,
                old,
            )
            self.assertEqual(
                native.git(repo, "rev-parse", "refs/heads/main").strip(), new
            )
            denied = subprocess.run(
                ["sudo", "-n", "-u", "nobody", "test", "-w", repo / "config"],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(denied.returncode, 0)


class NativeBrokerTests(unittest.TestCase):
    def test_transient_service_replays_registered_method_and_refuses_foreign_uid(self):
        if (
            not Path("/run/systemd/system").is_dir()
            or not shutil.which("sudo")
            or os.geteuid() == 0
            or os.getgid() == 0
            or not shutil.which("bwrap")
        ):
            self.skipTest(
                "needs a Linux system manager and a distinct non-root fixture caller"
            )
        if subprocess.run(
            ["sudo", "-n", "true"], check=False, capture_output=True
        ).returncode:
            self.skipTest("requires authorization to start a disposable evaluator unit")
        work = Path(native.__file__).resolve().parents[1]
        revision = "3facf571910e0799539a77a1a5112e6609a9a5ca"
        publisher = pwd.getpwuid(os.geteuid())
        evaluator = pwd.getpwnam("nobody")
        with tempfile.TemporaryDirectory(
            prefix="ocs-method-fixture-", dir="/var/tmp"
        ) as d:
            fixture = Path(d)
            fixture.chmod(0o750)
            with mock.patch.object(native, "STATE_PARENT", fixture):
                _, state, release, _ = native.private_paths("sample")
                unit = native.unit_text("sample", "fixture-client")[
                    "ocs-safe-method-sample@.service"
                ]
            for name in native.INPUTS:
                dest = release / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(work / name, dest)
            for part in (
                "publishing",
                "journal",
                "witness",
                "hooks",
                "authority/methods",
            ):
                place = state / part
                place.mkdir(parents=True, exist_ok=True)
                place.chmod(0o770)
                (place / "canary").write_text("disposable access probe")
            for family in (
                "reviews",
                "evidence",
                "bootstrap",
                "acquisitions",
                "alerts",
                "counterexamples",
                "checkpoints",
                "adverse",
                "unregistered-future-private",
            ):
                hidden = state / "authority" / family
                hidden.mkdir()
                (hidden / "canary").write_text("private host observation")
            repo = state / "repository.git"
            native.run(
                "/usr/bin/git",
                "init",
                "--bare",
                "--initial-branch=main",
                "--template=",
                "--ref-format=reftable",
                repo,
            )
            (repo / "reftable").chmod(0o770)
            (repo / "objects").chmod(0o770)
            with tempfile.TemporaryFile() as pack:
                subprocess.run(
                    [
                        "git",
                        "--no-replace-objects",
                        "-C",
                        work,
                        "pack-objects",
                        "--revs",
                        "--stdout",
                        "--quiet",
                    ],
                    input=(revision + "\n").encode(),
                    stdout=pack,
                    check=True,
                )
                pack.seek(0)
                native.run(
                    "git", "-C", repo, "index-pack", "--strict", "--stdin", stdin=pack
                )
            authority = state / "authority"
            code = (release / "safe_push/tests/status_adapter.py").read_bytes()
            identity = native.sha(code)
            (authority / "methods" / (identity + ".py")).write_bytes(code)
            policy = {"adapters": {"test-status": identity}, "predicateCheckers": {}}
            (authority / "root.json").write_bytes(native.canonical(policy))
            cfg = {
                "authority": str(authority),
                "repo": str(repo),
                "publishingKeys": str(state / "publishing"),
                "journal": str(state / "journal"),
                "witness": str(state / "witness/canary"),
                "genesis": revision,
                "rootDigest": native.sha(native.canonical(policy)),
            }
            config = state / "receiver.json"
            config.write_bytes(native.canonical(cfg))
            (state / "sealed.json").write_bytes(
                native.canonical({"configuration": native.sha(native.canonical(cfg))})
            )
            broker = native.broker_metadata("sample", publisher, evaluator)
            address = fixture / "fixture.sock"
            broker["socket"] = str(address)
            (authority / "broker.json").write_bytes(native.canonical(broker))
            worker = release / "safe_push/method_worker.py"
            private_probe = """
import os,sys
from pathlib import Path
state=Path(sys.argv[2]).parent
for name in ("publishing","journal","witness","hooks",
             *("authority/"+family for family in ("reviews","evidence","bootstrap","acquisitions","alerts","counterexamples","checkpoints","adverse","unregistered-future-private"))):
    try: f=os.open(state/name/"canary",os.O_RDONLY)
    except (PermissionError,FileNotFoundError): continue
    else:
        os.close(f);raise RuntimeError("unexpected readable protected input")
try: f=os.open(state/"repository.git/reftable/temporary-access-probe",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
except OSError as e:
    if e.errno not in (13,30,1): raise
else:
    os.close(f);raise RuntimeError("unexpected write into protected reference tables")
os.execv(sys.executable,[sys.executable,"-I","-B",sys.argv[1],"serve",sys.argv[2]])
"""
            props = [
                line
                for line in unit.split("[Service]\n", 1)[1].splitlines()
                if "=" in line
                and line.split("=", 1)[0]
                not in (
                    "User",
                    "Group",
                    "SupplementaryGroups",
                    "ExecStart",
                    "StandardInput",
                    "StandardOutput",
                    "StandardError",
                )
            ]
            # The production state lives in /var/lib. Re-expose this disposable fixture
            # beneath the otherwise-private /var/tmp solely for this unit test.
            props.append("BindReadOnlyPaths=" + str(fixture) + ":" + str(fixture))
            transient = [
                "sudo",
                "-n",
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--uid=" + evaluator.pw_name,
                "--gid=" + grp.getgrgid(evaluator.pw_gid).gr_name,
                "--property=SupplementaryGroups=" + grp.getgrgid(os.getgid()).gr_name,
                *("--property=" + v for v in props),
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                private_probe,
                str(worker),
                str(config),
            ]
            results = []
            stop = threading.Event()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(address))
                address.chmod(0o660)
                listener.listen(2)
                listener.settimeout(0.3)

                def serve():
                    while not stop.is_set():
                        try:
                            conn, _ = listener.accept()
                        except TimeoutError:
                            continue
                        with conn:
                            p = subprocess.run(
                                transient,
                                stdin=conn,
                                stdout=conn,
                                stderr=subprocess.PIPE,
                                timeout=120,
                                check=False,
                            )
                            results.append(
                                (p.returncode, p.stderr.decode(errors="replace"))
                            )

                t = threading.Thread(target=serve, daemon=True)
                t.start()
                try:
                    observed = json.loads(
                        native.run(
                            sys.executable, "-I", "-B", worker, "selftest", config
                        )
                    )
                    self.assertEqual(
                        (
                            observed["publisherUid"],
                            observed["evaluatorUid"],
                            observed["wireBytes"],
                        ),
                        (publisher.pw_uid, evaluator.pw_uid, 577),
                    )
                    for name in (
                        "publisherKeyReadable",
                        "journalReadable",
                        "witnessReadable",
                        "refWritable",
                    ):
                        self.assertIs(observed[name], False)
                    self.assertTrue(observed["diagnosticOnly"])
                    evidence = authority / "evidence/trial"
                    evidence.mkdir(parents=True)
                    condition = "a" * 64
                    (evidence / "acquisition.json").write_bytes(
                        native.canonical(
                            {
                                "revision": revision,
                                "conditions": condition,
                                "expiresAt": "2029-01-01T00:00:00Z",
                            }
                        )
                    )
                    from admission import run_adapter

                    output = run_adapter(
                        authority,
                        policy["adapters"],
                        "test-status",
                        {
                            "repo": str(repo),
                            "subject": {"revision": revision},
                            "target": "subject",
                            "conditions": condition,
                            "evidence": str(evidence),
                        },
                        timeout=30,
                    )
                    self.assertEqual(
                        set(output["claims"]), {"S-01", "S-02", "S-03", "S-04"}
                    )
                    self.assertEqual(
                        output["metrics"]["wire.octets"],
                        {"direction": "min", "condition": condition, "value": "577"},
                    )
                    # The connection remains physically reachable for the fixture; changing the
                    # authorization deliberately exercises the kernel peer-UID refusal.
                    (authority / "broker.json").write_bytes(
                        native.canonical(
                            {**broker, "publisherUid": evaluator.pw_uid + 10}
                        )
                    )
                    denied = subprocess.run(
                        [sys.executable, "-I", "-B", worker, "selftest", config],
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertNotEqual(denied.returncode, 0)
                finally:
                    stop.set()
                    t.join(timeout=10)
            self.assertFalse(t.is_alive())
            self.assertEqual([p[0] for p in results], [0, 0, 1], results)
            self.assertIn("unrecognized local evaluator caller", results[-1][1])


class RemoteHelperTests(unittest.TestCase):
    def test_global_helper_never_overwrites_an_unrelated_entry(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "git-remote-ocs"
            owner = os.geteuid()
            native.install_shared_helper(dest, b"reviewed\n", owner=owner)
            inode = dest.stat().st_ino
            native.install_shared_helper(dest, b"reviewed\n", owner=owner)
            self.assertEqual(inode, dest.stat().st_ino)
            with self.assertRaisesRegex(ValueError, "existing Git transport file"):
                native.install_shared_helper(dest, b"other\n", owner=owner)
            self.assertEqual(dest.read_bytes(), b"reviewed\n")
            dest.rename(tmp / "existing")
            dest.symlink_to(tmp / "existing")
            with self.assertRaisesRegex(ValueError, "linked"):
                native.install_shared_helper(dest, b"reviewed\n", owner=owner)
            self.assertTrue(dest.is_symlink())
            for addr in (
                "/tmp/sock",
                "../instance",
                "ocs://elsewhere",
                "instance/name",
                "name with spaces",
                "name;command",
                "--help",
                "",
            ):
                with self.subTest(address=addr), self.assertRaises(ValueError):
                    git_remote_ocs.dispatch(["safe-push", addr])

    def test_coalesced_commands_leave_all_git_bytes_on_stdin(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            payload = b"0012git-packet\x00\xff\n0000"
            reply = b"000coutcome\x00\x01\n0000"
            received = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(tmp / "fixture.sock"))
                listener.listen(1)
                listener.settimeout(10)

                def serve():
                    with listener.accept()[0] as conn:
                        chunks = []
                        while part := conn.recv(4096):
                            chunks.append(part)
                        received.append(b"".join(chunks))
                        conn.sendall(reply)

                server = threading.Thread(target=serve, daemon=True)
                server.start()
                program = "import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from socket_client import git_helper;git_helper('fixture',Path(sys.argv[2]))"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-c",
                        program,
                        Path(native.__file__).parent,
                        tmp,
                    ],
                    input=b"capabilities\nconnect git-receive-pack\n" + payload,
                    capture_output=True,
                    timeout=10,
                    check=True,
                )
                server.join(timeout=10)
            self.assertEqual(received, [b"git-receive-pack\n" + payload])
            self.assertEqual(result.stdout, b"connect\n\n\n" + reply)

    def test_real_git_push_and_ls_remote_use_only_connect(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server_repo = tmp / "server.git"
            client = tmp / "client"
            home = tmp / "home"
            home.mkdir()
            native.run(
                "/usr/bin/git",
                "init",
                "--bare",
                "--initial-branch=main",
                "--template=",
                server_repo,
            )
            native.run(
                "/usr/bin/git", "init", "--initial-branch=main", "--template=", client
            )
            work = Path(native.__file__).resolve().parent
            helpers = tmp / "bin"
            helpers.mkdir()
            clients = tmp / "public"
            instance = clients / "fixture"
            instance.mkdir(parents=True)
            sockets = tmp / "sockets"
            sockets.mkdir()
            ns = []
            if sys.platform == "linux" and shutil.which("bwrap"):
                # Exercise the unmodified installed entrypoints at their real paths without
                # registering any service or helper on the host.
                shutil.copyfile(work / "git_remote_ocs.py", helpers / "git-remote-ocs")
                shutil.copyfile(
                    work / "socket_client.py", instance / "socket_client.py"
                )
                ns = [
                    "/usr/bin/bwrap",
                    "--unshare-all",
                    "--die-with-parent",
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--tmpfs",
                    "/run",
                    "--tmpfs",
                    "/usr/local",
                    "--dir",
                    "/usr/local/libexec",
                    "--ro-bind",
                    str(helpers),
                    "/usr/local/bin",
                    "--ro-bind",
                    str(clients),
                    "/usr/local/libexec/ocs-safe-push",
                    "--ro-bind",
                    str(sockets),
                    "/run/ocs-safe-push",
                    "--bind",
                    str(client),
                    str(client),
                ]
                path = "/usr/local/bin:/usr/bin:/bin"
            else:
                # Redirect only the fixture's compile-time directories; the public address parser,
                # helper session and full-duplex copy are the production functions.
                (helpers / "git-remote-ocs").write_text(
                    "#!/usr/bin/python3 -I\nimport sys\nfrom pathlib import Path\n"
                    + f"sys.path.insert(0,{str(work)!r})\nfrom git_remote_ocs import dispatch\ndispatch(sys.argv[1:],Path({str(clients)!r}))\n"
                )
                (instance / "socket_client.py").write_text(
                    "import sys\nfrom pathlib import Path\n"
                    + f"sys.path.insert(0,{str(work)!r})\nfrom socket_client import git_helper\ngit_helper(sys.argv[2],Path({str(sockets)!r}))\n"
                )
                path = str(helpers) + ":/usr/bin:/bin"
            (helpers / "git-remote-ocs").chmod(0o755)
            env = {
                "PATH": path,
                "HOME": str(home),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "protocol.ext.allow",
                "GIT_CONFIG_VALUE_0": "never",
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }

            def local(*args, transport=False):
                proc = subprocess.run(
                    [*(ns if transport else []), "/usr/bin/git", "-C", client, *args],
                    capture_output=True,
                    check=False,
                    env=env,
                    timeout=20,
                )
                self.assertEqual(
                    proc.returncode, 0, proc.stderr.decode(errors="replace")
                )
                return proc.stdout

            (client / "message").write_text("qualified fixture\n")
            local("add", "message")
            local("commit", "-m", "fixture")
            local("remote", "add", "safe-push", "ocs::fixture")
            local("config", "remote.safe-push.push", "HEAD:refs/heads/main")
            tip = local("rev-parse", "HEAD").strip()
            seen = []
            errors = []
            done = threading.Event()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(sockets / "fixture.sock"))
                listener.listen(4)
                listener.settimeout(0.25)

                def serve():
                    while not done.is_set():
                        try:
                            conn, _ = listener.accept()
                        except TimeoutError:
                            continue
                        except OSError:
                            return
                        with conn:
                            try:
                                header = bytearray()
                                while len(header) < 32:
                                    char = conn.recv(1)
                                    if char in (b"\n", b""):
                                        break
                                    header += char
                                service = bytes(header).decode("ascii")
                                if service not in (
                                    "git-upload-pack",
                                    "git-receive-pack",
                                ):
                                    raise ValueError("unexpected service")
                                seen.append(service)
                                subprocess.run(
                                    [service, server_repo],
                                    stdin=conn,
                                    stdout=conn,
                                    check=True,
                                    stderr=subprocess.PIPE,
                                    timeout=15,
                                )
                            except (
                                OSError,
                                ValueError,
                                subprocess.SubprocessError,
                            ) as exc:
                                errors.append(str(exc))
                                return

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    local("push", "safe-push", transport=True)
                    listing = local(
                        "ls-remote", "safe-push", "refs/heads/main", transport=True
                    )
                    self.assertEqual(listing.split(), [tip, b"refs/heads/main"])
                finally:
                    done.set()
                    thread.join(timeout=3)
            self.assertEqual(errors, [])
            self.assertEqual(seen, ["git-receive-pack", "git-upload-pack"])
            self.assertEqual(
                native.git(server_repo, "rev-parse", "refs/heads/main").strip(), tip
            )


if __name__ == "__main__":
    unittest.main()
