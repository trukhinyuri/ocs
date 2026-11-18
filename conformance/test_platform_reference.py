"""Check the bounded reference cell, real outage and fenced recovery work."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def check_private_peer_route(directory):
    # Isolate the reference imports exactly as the platform probe does.
    sys.path.insert(0, str(ROOT / "assurance/platform"))
    import observe

    sys.path.insert(0, str(ROOT / "reference/platform"))
    from cell import Actor, Cell

    directory = Path(directory)
    snapshot_key = directory / "snapshot-key"
    snapshot_key.write_bytes(b"fixed fixture snapshot key of 32 bytes")
    journal = observe.Journal()
    left, right = [
        observe.Deployment(directory, name, snapshot_key, journal, federated=True)
        for name in ("left", "right")
    ]
    left.neighbour, right.neighbour = right, left
    target = {"peer": "neighbour", "id": "neighbour-resource"}
    try:
        left.launch()
        right.launch()
        left.connect()
        right.connect()
        left.bind(right)
        right.bind(left)
        expected = {"neighbour": {"endpoint": right.endpoint, "tenant": "alice"}}
        assert json.loads(left.peers.read_bytes()) == expected
        assert json.loads(right.peers.read_bytes()) == {
            "neighbour": {"endpoint": left.endpoint, "tenant": "alice"}
        }
        observe.create(right.a, "alice", target["id"], "authoritative peer contents")
        for client, direction in ((left.a, "import"), (right.a, "export")):
            client.call(
                "example.peer.grant",
                {"peer": "neighbour", "direction": direction, "permitted": True},
            )
        assert left.a.call("example.peer.observe", target)["state"] == "ready"
        for route in (
            {"endpoint": left.endpoint, "tenant": "alice"},
            {"endpoint": right.endpoint, "tenant": "bob"},
            {"endpoint": right.endpoint, "tenant": "alice", "token": "public invalid placeholder"},
        ):
            left.peers.write_text(json.dumps({"neighbour": route}))
            observe.refusal("denied", lambda: left.a.call("example.peer.observe", target))
        left.peers.write_text(json.dumps({"other": expected["neighbour"]}))
        observe.refusal(
            "denied",
            lambda: left.a.call(
                "example.peer.grant", {"peer": "other", "direction": "import", "permitted": True}
            ),
        )
        left.bind(right)
        for cell in (left, right):
            cell.stop()
            cell.start()
            assert left.a.call("example.peer.observe", target)["state"] == "ready"

        # Supply the historical operator document as memory to the real legacy
        # reader. Its scoped bearer reaches the same live remote public endpoint.
        legacy = Cell(directory / "legacy", snapshot_key.read_bytes(), left.peers)
        legacy.peers = Mock()
        legacy.peers.read_bytes.return_value = json.dumps(
            {"neighbour": {**expected["neighbour"], "token": right.secrets["peer"]}}
        ).encode()
        owner = Actor("alice", writer="primary", epoch=1)
        legacy.init_owners([owner])
        until = observe.stamp(time.time() + 5)
        legacy.dispatch(
            owner,
            "example.peer.grant",
            {"peer": "neighbour", "direction": "import", "permitted": True},
            until,
            time.monotonic() + 5,
        )
        assert (
            legacy.dispatch(owner, "example.peer.observe", target, until, time.monotonic() + 5)[
                "state"
            ]
            == "ready"
        )
        secrets = [token.encode() for cell in (left, right) for token in cell.secrets.values()]
        evidence = [json.dumps(journal.snapshot()).encode()]
        evidence.extend(p.read_bytes() for p in directory.rglob("*") if p.is_file())
        assert not any(token in data for token in secrets for data in evidence), (
            "credential reached persisted fixture or journal"
        )
    finally:
        left.stop()
        right.stop()


class PlatformReferenceTests(unittest.TestCase):
    def test_invalid_private_peer_input_refuses_without_echoing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "snapshot-key").write_bytes(b"fixed fixture snapshot key of 32 bytes")
            (folder / "peers.json").write_text("{}")
            marker = "unusable-fixture-marker"
            misconfigured = {
                "neighbour": {
                    "tenant": "alice",
                    "endpoint": "http://127.0.0.1:0/ocs",
                    "token": marker,
                }
            }
            run = subprocess.run(
                [
                    sys.executable,
                    "-E",
                    "-s",
                    str(ROOT / "reference/platform/server.py"),
                    "--directory",
                    str(folder / "state"),
                    "--trust-key",
                    str(folder / "snapshot-key"),
                    "--peers",
                    str(folder / "peers.json"),
                    "--peer-credentials-stdin",
                ],
                input=json.dumps(misconfigured) + "\n",
                capture_output=True,
                text=True,
                timeout=8,
                env={
                    **os.environ,
                    "OCS_CELL_IDENTITIES": json.dumps(
                        {"unused-test-principal": {"tenant": "alice", "writer": "primary"}}
                    ),
                },
                check=False,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("invalid private peer credential frame", run.stderr)
            self.assertNotIn(marker, run.stderr + run.stdout)

    def test_private_peer_credential_route_and_legacy_operator_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--private-peer", directory],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=40,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cell_capacity_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "observations.json"
            process = subprocess.run(
                [
                    sys.executable,
                    "assurance/platform/probe.py",
                    "--mode",
                    "runtime",
                    "--check",
                    "platform.capacity",
                    "--check",
                    "platform.partition",
                    "--report",
                    str(report),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            rows = {
                r["id"]: r["observed"]
                for r in json.loads(report.read_bytes())["checks"]
                if r["status"] == "pass"
            }
            capacity, partition = rows["platform.capacity"], rows["platform.partition"]
            self.assertEqual(len(capacity["boundLatencyNs"]), 32)
            self.assertLessEqual(capacity["stats"]["peak"], 4)
            self.assertGreaterEqual(capacity["stats"]["rejected"], 1)
            self.assertEqual(partition["reconciledOutcome"], "unknown")
            self.assertTrue(partition["sameOperationId"])
            self.assertLess(partition["restartToScopedReadNs"], 5_000_000_000)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--private-peer"]:
        check_private_peer_route(sys.argv[2])
    else:
        unittest.main()
