"""Test the public data-only protocol between the publisher and its enrolled method worker."""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import method_worker as worker
from authority import Decision, canonical, digest


class MethodProtocolTests(unittest.TestCase):
    def test_input_is_copied_as_read_only_data_and_pathless_on_wire(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = tmp / "sources"
            src.mkdir()
            (src / "experiment.json").write_text('{"observed":4}')
            cert = tmp / "proof"
            cert.write_bytes(b"test certificate")
            request = worker.encode_inputs(
                {
                    "repo": "/operator/enrolled.git",
                    "subject": {"revision": "1" * 40},
                    "artifact": str(cert),
                    "evidence": str(src),
                }
            )
            self.assertNotIn("/operator", json.dumps(request))
            self.assertNotIn(str(tmp), json.dumps(request))
            scratch = tmp / "worker"
            scratch.mkdir()
            restored = worker.restore_inputs(
                request, scratch, Path("/verified/repository.git")
            )
            self.assertEqual(Path(restored["artifact"]).read_bytes(), cert.read_bytes())
            self.assertEqual(
                (Path(restored["evidence"]) / "experiment.json").read_bytes(),
                (src / "experiment.json").read_bytes(),
            )
            self.assertEqual(restored["repo"], "/verified/repository.git")
            request["args"]["artifact"] = "ambient pathname"
            with self.assertRaisesRegex(Decision, "filesystem operands"):
                worker.restore_inputs(request, tmp / "other", tmp / "repo")

    def test_an_input_link_or_invalid_local_filename_holds_the_call(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "a").write_text("observation")
            dir_ = tmp / "dir"
            dir_.mkdir()
            (dir_ / "linked").symlink_to(tmp / "a")
            with self.assertRaisesRegex(Decision, "linked evidence"):
                worker.encode_inputs({"evidence": str(dir_)})
            for name in (
                "",
                "../outside",
                "nested/../other",
                "/absolute",
                r"windows\file",
            ):
                with self.subTest(name=name), self.assertRaises(Decision):
                    worker.safe_name(name)

    def test_actual_unix_sender_credentials_and_request_digest(self):
        if (
            not sys.platform.startswith("linux")
            or not hasattr(socket, "SO_PASSCRED")
            or os.geteuid() == 0
        ):
            self.fail(
                "This acceptance requires a real unprivileged Linux method sender"
            )
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            path = directory / "qualified.sock"
            uid = os.geteuid()
            for correct_id, correct_hash in (
                (True, True),
                (False, True),
                (True, False),
            ):
                with self.subTest(correct_id=correct_id, correct_hash=correct_hash):
                    config = {
                        "format": "ocs.safe-push.method-broker/1",
                        "socket": str(path),
                        "publisherUid": uid + 3,
                        "evaluatorUid": uid if correct_id else uid + 1,
                    }
                    (directory / "broker.json").write_bytes(canonical(config))
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                        listener.bind(str(path))
                        listener.listen(1)

                        def respond(correct_hash=correct_hash):
                            conn, _ = listener.accept()
                            with conn:
                                head = worker.exactly(conn, worker.LENGTH.size)
                                request = worker.exactly(
                                    conn, worker.LENGTH.unpack(head)[0]
                                )
                                response = canonical(
                                    {
                                        "outcome": "observed",
                                        "output": {"status": "pass"},
                                        "requestSha256": digest(request)
                                        if correct_hash
                                        else "0" * 64,
                                    }
                                )
                                conn.sendall(
                                    worker.LENGTH.pack(len(response)) + response
                                )

                        t = threading.Thread(target=respond)
                        t.start()
                        req = {
                            "format": "ocs.safe-push.method-request/1",
                            "operation": "selftest",
                        }
                        try:
                            if correct_hash and correct_id:
                                self.assertEqual(
                                    worker.request(directory, req, 2),
                                    {"status": "pass"},
                                )
                            else:
                                with self.assertRaises(Decision):
                                    worker.request(directory, req, 2)
                        finally:
                            t.join(3)
                            self.assertFalse(t.is_alive())
                    path.unlink()
