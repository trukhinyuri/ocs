"""Observe two independently owned cells, native files and bounded admission."""

import base64
import hashlib
import http.client
import json
import math
import os
import secrets
import select
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

ORACLE = Path(__file__).resolve().parents[2]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
sys.path[:0] = [str(ORACLE / "reference"), str(ORACLE / "reference/interaction")]
from client import CallError, stamp

sys.path.insert(0, str(ORACLE / "assurance/interaction"))
from contracts import validate, validate_with
from transcripts import Journal

EXPORTS = {
    x["id"]: x for x in json.loads((ORACLE / "reference/platform/ocs.json").read_bytes())["exports"]
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def refusal(kind, fn):
    try:
        fn()
    except CallError as exc:
        require(exc.kind == kind, f"expected {kind}, received {exc.kind}")
        return exc.kind
    raise AssertionError("expected refusal " + kind)


class Client:
    def __init__(self, port, key, journal=None):
        self.journal = journal
        self.port, self.key = port, key
        self.session = ""
        self.pin = ""
        self.wire_bytes = 0
        reply = self.rpc(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.cloud/0.1", "ocs.platform/0.1"],
                "meta": {"deadline": stamp(time.time() + 5)},
            },
        )
        validate("wire", reply, "describeResult")
        self.pin = reply["manifestDigest"]
        require(
            self.pin == sha((SUBJECT / "reference/platform/ocs.json").read_bytes()),
            "unexpected bound descriptor",
        )

    def rpc(self, method, params):
        rid = secrets.token_hex(8)
        body = json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, separators=(",", ":")
        ).encode()
        with closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=6)) as conn:
            conn.request(
                "POST",
                "/ocs",
                body,
                {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.key,
                    "OCS-Session": self.session,
                },
            )
            res = conn.getresponse()
            if res.status != 200:
                raise CallError(f"http-{res.status}", "Transport refused.")
            raw = res.read(65537)
            require(len(raw) <= 65536, "oversize result")
            self.wire_bytes += len(body) + len(raw)
            packet = json.loads(raw)
            validate("wire", packet, "failure" if "error" in packet else "success")
            require(packet["id"] == rid, "correlation changed")
            if "error" in packet:
                raise CallError(packet["error"]["data"]["kind"], packet["error"]["message"])
            if method == "ocs.describe":
                self.session = res.getheader("OCS-Session")
            return packet["result"]

    def call(self, op, inp, seconds=5):
        try:
            result = self.rpc(
                "tool.call",
                {
                    "operation": op,
                    "version": "1.0.0",
                    "input": inp,
                    "meta": {
                        "protocol": "0.1",
                        "manifestDigest": self.pin,
                        "deadline": stamp(time.time() + seconds),
                    },
                },
            )
        except CallError as err:
            if self.journal:
                self.journal.note(op, inp, self.pin, "refusal", code=err.kind)
            raise
        if self.journal:
            self.journal.note(op, inp, self.pin, "result", result["data"])
        validate("wire", result, "callResult")
        validate_with(EXPORTS[op]["outputSchema"], result["data"])
        return result["data"]


class Deployment:
    def __init__(self, base, name, trust, journal, *, federated=False):
        self.journal = journal
        self.base = Path(base)
        self.folder = self.base / name
        self.folder.mkdir()
        self.state = self.folder / "state"
        self.trust = trust
        self.peers = self.folder / "peers.json"
        self.peers.write_text("{}")
        self.auth = {}
        self.secrets = {}
        for label, conf in [
            ("primary", {"tenant": "alice", "writer": "primary"}),
            ("replacement", {"tenant": "alice", "writer": "replacement"}),
            ("bob", {"tenant": "bob", "writer": "primary"}),
            ("peer", {"tenant": "alice", "peer": "neighbour"}),
        ]:
            token = secrets.token_hex(18)
            self.secrets[label] = token
            self.auth[token] = conf
        self.proc = None
        self.port = 0
        self.federated = federated
        self.neighbour = None
        if not self.federated:
            self.start()

    def launch(self):
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-E",
                "-s",
                str(SUBJECT / "reference/platform/server.py"),
                "--directory",
                str(self.state),
                "--trust-key",
                str(self.trust),
                "--peers",
                str(self.peers),
                "--port",
                str(self.port),
                *(["--peer-credentials-stdin"] if self.federated else []),
            ],
            env={**os.environ, "OCS_CELL_IDENTITIES": json.dumps(self.auth)},
            stdin=subprocess.PIPE if self.federated else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require(select.select([self.proc.stdout], [], [], 8)[0], "cell startup timeout")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("Cell failed: " + self.proc.stderr.read()[-240:])
        self.port = json.loads(line)["port"]

    def connect(self):
        if self.federated:
            # Both independently bound ports are known before the cells serve. Restart
            # provisions the same selected recipient from the observing process's memory.
            credentials = {
                "neighbour": {
                    "endpoint": self.neighbour.endpoint,
                    "tenant": "alice",
                    "token": self.neighbour.secrets["peer"],
                }
            }
            with self.proc.stdin as pipe:
                pipe.write(json.dumps(credentials) + "\n")
        self.a, self.replacement, self.bob = [
            Client(self.port, self.secrets[key], self.journal)
            for key in ("primary", "replacement", "bob")
        ]

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}/ocs"

    def start(self):
        self.launch()
        self.connect()

    def bind(self, other):
        require(other is self.neighbour, "peer was not independently selected at startup")
        self.peers.write_text(
            json.dumps({"neighbour": {"endpoint": other.endpoint, "tenant": "alice"}})
        )

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
            self.proc.stdout.close()
            self.proc.stderr.close()
            if self.proc.stdin is not None:
                self.proc.stdin.close()
            self.proc = None

    def asset(self, tenant, rid):
        binding = json.dumps([tenant, rid], separators=(",", ":"), ensure_ascii=False).encode()
        return self.state / ("object-" + sha(binding))


def create(client, owner, rid, text):
    accepted = client.call("example.resource.request", {"id": rid, "revision": 0, "text": text})
    pending = client.call("resource.observe", {"owner": owner, "id": rid})
    client.call("example.resource.materialize", {"id": rid, "revision": accepted["revision"]})
    ready = client.call("resource.observe", {"owner": owner, "id": rid})
    require(
        accepted["accepted"] and pending["state"] == "pending" and ready["state"] == "ready",
        "acceptance confused with readiness",
    )
    return ready


def lifecycle(cx, other):
    a, b = cx.a, cx.bob
    rid = "resource-one"
    text = "a scoped sample α"
    state = create(a, "alice", rid, text)
    terms = a.call("example.cell.terms", {})
    require(
        terms["owner"] == "alice"
        and terms["capacityBytes"] == 32768
        and terms["cost"] == {"amount": "0", "currency": "USD"}
        and terms["metering"] == "unmetered fixture",
        "invalid terms or capacity",
    )
    refusal("denied", lambda: b.call("resource.observe", {"owner": "alice", "id": rid}))
    refusal("method", lambda: a.call("example.resource.unimplemented", {}))
    cx.asset("alice", rid).write_bytes(b"unreconciled")
    require(
        a.call("resource.observe", {"owner": "alice", "id": rid})["state"] == "degraded",
        "failed to observe damaged storage",
    )
    a.call("example.resource.materialize", {"id": rid, "revision": 1})
    saved = a.call("example.resource.export", {"id": rid})
    require(saved["snapshot"]["requiredBytes"] == len(text.encode()), "missing restore capacity")
    nxt = a.call("example.resource.retire", {"id": rid, "revision": 1})["revision"]
    require(
        a.call("resource.observe", {"owner": "alice", "id": rid})["state"] == "deleted",
        "tombstone not visible",
    )
    req = {**saved, "expectedRevision": nxt, "capacityBytes": 32768}
    refusal("busy", lambda: a.call("example.resource.restore", {**req, "capacityBytes": 1}))
    refusal("denied", lambda: b.call("example.resource.restore", req))
    refusal("denied", lambda: a.call("example.resource.restore", {**req, "signature": "0" * 64}))
    require(
        a.call("resource.observe", {"owner": "alice", "id": rid})["state"] == "deleted",
        "failed restore changed live state",
    )
    restored = a.call("example.resource.restore", req)
    refusal("conflict", lambda: a.call("example.resource.restore", req))
    ready = a.call("resource.observe", {"owner": "alice", "id": rid})
    require(
        ready["state"] == "ready"
        and ready["revision"] == str(restored["revision"])
        and cx.asset("alice", rid).read_bytes() == text.encode(),
        "restored resource mismatch",
    )
    other.a.call(
        "example.resource.restore", {**saved, "expectedRevision": 0, "capacityBytes": 32768}
    )
    require(
        other.a.call("resource.observe", {"owner": "alice", "id": rid})["state"] == "ready",
        "compatible cell restore failed",
    )
    return {
        "acceptedRevision": state["revision"],
        "damaged": "degraded",
        "restoredRevision": restored["revision"],
        "digest": saved["snapshot"]["digest"],
        "requiredBytes": saved["snapshot"]["requiredBytes"],
        "terms": terms,
    }


def native(cx, other):
    a, b = cx.a, cx.bob
    rid = "handle"
    raw = "native bytes π"
    create(a, "alice", rid, raw)
    abi = a.call("example.native.describe", {})
    validate("profile-data", abi, "platform")
    req = {"id": rid, "platform": abi}
    for delta in (
        {"revision": "wrong"},
        {"target": "other"},
        {"authority": "bob"},
        {"isolation": "untrusted kernel confinement"},
        {"timing": "hard-deadline", "worstCaseUs": 200, "qualification": "sample p99"},
    ):
        refusal(
            "incompatible",
            lambda change=delta: a.call(
                "example.native.open", {**req, "platform": {**abi, **change}}
            ),
        )
    issued = a.call("example.native.open", req)
    read = {"handle": issued["handle"], "offset": 0, "length": 128}
    data = a.call("example.native.read", read)
    require(
        base64.b64decode(data["base64"], validate=True) == raw.encode()
        and data["digest"] == sha(raw.encode()),
        "native read lost bytes",
    )
    refusal("denied", lambda: b.call("example.native.read", read))
    refusal("input", lambda: a.call("example.native.read", {**read, "offset": 8000}))
    a.call("example.native.close", {"handle": issued["handle"]})
    refusal("denied", lambda: a.call("example.native.read", read))
    held = a.call("example.native.open", req)
    state = a.call("example.cell.cutover", {"writer": "replacement", "epoch": 1})
    require(state["epoch"] == 2, "owner epoch did not advance")
    refusal("denied", lambda: a.call("example.native.read", {**read, "handle": held["handle"]}))
    refusal(
        "denied",
        lambda: a.call(
            "example.resource.request", {"id": rid, "revision": 1, "text": "old-writer"}
        ),
    )
    cx.replacement = Client(cx.port, cx.secrets["replacement"], cx.journal)
    refusal(
        "denied",
        lambda: cx.replacement.call("example.native.read", {**read, "handle": held["handle"]}),
    )
    cx.replacement.call(
        "example.resource.request", {"id": rid, "revision": 1, "text": "replacement"}
    )
    require(
        cx.replacement.call("resource.observe", {"owner": "alice", "id": rid})["state"]
        == "pending",
        "desired revision lost",
    )
    reverse = cx.replacement.call("example.cell.cutover", {"writer": "primary", "epoch": 2})
    require(reverse["epoch"] == 3, "return to original logical owner did not advance fence")
    refusal(
        "denied",
        lambda: a.call("example.resource.request", {"id": rid, "revision": 2, "text": "stale"}),
    )
    rebound = Client(cx.port, cx.secrets["primary"], cx.journal)
    rebound.call("example.cell.cutover", {"writer": "replacement", "epoch": 3})
    cx.stop()
    cx.start()
    require(
        cx.replacement.call("resource.observe", {"owner": "alice", "id": rid})["state"]
        == "pending",
        "restart lost pending state",
    )
    cx.replacement.call("example.resource.materialize", {"id": rid, "revision": 2})
    require(
        cx.asset("alice", rid).read_bytes() == b"replacement", "reconciliation after cutover failed"
    )
    return {
        "abi": abi,
        "decodedBytes": data["bytes"],
        "digest": data["digest"],
        "closedAndRevoked": "denied",
        "replacementEpoch": state["epoch"],
        "mapping": "POSIX pread at exact byte offset; hard timing or changed ABI refused",
    }


def federation(cx, other):
    a = cx.a
    remote = other.a
    rid = "federated"
    create(a, "alice", rid, "local")
    create(remote, "alice", rid, "remote")
    cx.bind(other)
    other.bind(cx)
    target = {"peer": "neighbour", "id": rid}

    def grant(cli, direction, on):
        return cli.call(
            "example.peer.grant", {"peer": "neighbour", "direction": direction, "permitted": on}
        )

    refusal("denied", lambda: a.call("example.peer.observe", target))
    grant(a, "import", True)
    refusal("denied", lambda: a.call("example.peer.observe", target))
    grant(remote, "export", True)
    require(
        a.call("example.peer.observe", target)["state"] == "ready",
        "mutual grant did not produce a read",
    )
    op = a.call("example.remote.reserve", {"peer": "neighbour"})
    require(op["outcome"] == "unknown", "unconfirmed outcome misreported")
    grant(remote, "export", False)
    refusal("denied", lambda: a.call("example.peer.observe", target))
    require(
        remote.call("resource.observe", {"id": rid, "owner": "alice"})["state"] == "ready",
        "revocation disabled state owner",
    )
    grant(remote, "export", True)
    other.stop()
    then = time.perf_counter_ns()
    refusal("unavailable", lambda: a.call("example.peer.observe", target))
    local = a.call("resource.observe", {"id": rid, "owner": "alice"})
    recovered = a.call("example.remote.readback", {"id": op["id"]})
    local_ns = time.perf_counter_ns() - then
    require(
        local["state"] == "ready" and recovered == op and local_ns < 5_000_000_000,
        "failed local partition behavior",
    )
    then = time.perf_counter_ns()
    other.start()
    require(a.call("example.peer.observe", target)["state"] == "ready", "cell did not recover")
    recovery_ns = time.perf_counter_ns() - then
    require(
        recovery_ns < 5_000_000_000 and a.call("example.remote.readback", {"id": op["id"]}) == op,
        "recovery exceeded limit or reissued effect",
    )
    return {
        "grants": ["local-import", "peer-export"],
        "ownerAfterRevocation": "ready",
        "localDuringPartitionNs": local_ns,
        "restartToScopedReadNs": recovery_ns,
        "reconciledOutcome": recovered["outcome"],
        "sameOperationId": op == recovered,
    }


def rank(ns, percent):
    return sorted(ns)[max(0, math.ceil(len(ns) * percent / 100) - 1)]


def capacity(cx, other):
    rid = "capacity"
    payload = "S" * 64
    create(cx.a, "alice", rid, payload)
    create(cx.bob, "bob", rid, payload)
    before = time.perf_counter_ns()
    clients = [
        Client(cx.port, cx.secrets["primary" if n % 2 == 0 else "bob"], cx.journal)
        for n in range(4)
    ]
    init_ns = time.perf_counter_ns() - before

    def request(i):
        cli = clients[i % 4]
        owner = "alice" if i % 2 == 0 else "bob"
        mark = time.perf_counter_ns()
        result = cli.call("resource.observe", {"id": rid, "owner": owner})
        latency = time.perf_counter_ns() - mark
        require(result["state"] == "ready", "unexpected bound resource observation")
        return latency

    latencies = []
    window = time.time()
    initial_bytes = sum(c.wire_bytes for c in clients)
    with ThreadPoolExecutor(max_workers=4) as pool:
        bound_start = time.perf_counter_ns()
        for wave in range(8):
            latencies.extend(pool.map(request, range(wave * 4, wave * 4 + 4)))

        bound_window = time.perf_counter_ns() - bound_start
        bound_bytes = sum(c.wire_bytes for c in clients) - initial_bytes

        def hold(i):
            try:
                clients[i].call("example.work.hold", {"id": "lag" + str(i), "holdMs": 3900})
                return "completed"
            except CallError as e:
                return e.kind

        slow = [pool.submit(hold, i) for i in (0, 2)]
        expire = time.monotonic() + 2
        while cx.a.call("example.work.stats", {})["active"] < 2 and time.monotonic() < expire:
            time.sleep(0.005)
        stats = cx.a.call("example.work.stats", {})
        require(stats["active"] == 2, "slow tenants did not reserve two independent slots")
        refusal("busy", lambda: cx.a.call("resource.observe", {"id": rid, "owner": "alice"}))
        start = time.perf_counter_ns()
        require(
            cx.bob.call("resource.observe", {"id": rid, "owner": "bob"})["state"] == "ready",
            "slow tenant starved unrelated tenant",
        )
        independent_ns = time.perf_counter_ns() - start
        refusal("denied", lambda: cx.bob.call("example.work.cancel", {"id": "lag0"}))
        start = time.perf_counter_ns()
        for i in (0, 2):
            cx.a.call("example.work.cancel", {"id": "lag" + str(i)})
        require(
            [f.result(timeout=2) for f in slow] == ["cancelled", "cancelled"], "cancellation failed"
        )
        cancel_ns = time.perf_counter_ns() - start
    native = []
    files = {tenant: cx.asset(tenant, rid) for tenant in ("alice", "bob")}

    def direct(i):
        path = files["alice" if i % 2 == 0 else "bob"]
        tick = time.perf_counter_ns()
        data = path.read_bytes()
        require(data == payload.encode(), "native baseline read returned incorrect content")
        return time.perf_counter_ns() - tick

    with ThreadPoolExecutor(max_workers=4) as pool:
        mark = time.perf_counter_ns()
        for wave in range(8):
            native.extend(pool.map(direct, range(wave * 4, wave * 4 + 4)))
        native_window = time.perf_counter_ns() - mark
    stats = cx.a.call("example.work.stats", {})
    require(
        len(latencies) == 32
        and max(latencies + [cancel_ns, independent_ns]) < 5_000_000_000
        and stats["peak"] <= 4
        and stats["rejected"] >= 1
        and stats["active"] == 0,
        "soft workload admission or budget failed",
    )
    return {
        "samples": 32,
        "concurrency": 4,
        "tenantCount": 2,
        "desiredBytes": 64,
        "boundMethod": "resource.observe including desired-byte comparison",
        "nativeMethod": "read same tenant file and compare same desired bytes",
        "windowStart": stamp(window),
        "windowEnd": stamp(time.time()),
        "warmCache": "materialized then negotiated",
        "coldClientBootstrapNs": init_ns,
        "firstUsableReadNs": latencies[0],
        "boundWindowNs": bound_window,
        "nativeWindowNs": native_window,
        "boundWireBodyBytes": bound_bytes,
        "nativeBytes": 32 * len(payload.encode()),
        "boundReadsPerSecond": 32e9 / bound_window,
        "nativeReadsPerSecond": 32e9 / native_window,
        "nativeP95Ns": rank(native, 95),
        "nativeP99Ns": rank(native, 99),
        "boundLatencyNs": latencies,
        "nativeLatencyNs": native,
        "p95Ns": rank(latencies, 95),
        "p99Ns": rank(latencies, 99),
        "cancellationNs": cancel_ns,
        "unrelatedTenantNs": independent_ns,
        "stats": stats,
        "maximumAllowedNs": 5_000_000_000,
        "workloadBoundary": "local isolated POSIX product with refused saturation; no hardware worst-case claim",
    }


def run_sample(f):
    with tempfile.TemporaryDirectory(prefix="ocs-cells-") as tmp:
        base = Path(tmp)
        trust = base / "trust"
        trust.write_bytes(secrets.token_bytes(32))
        trust.chmod(0o600)
        journal = Journal()
        federated = f is federation
        cx = Deployment(base, "a", trust, journal, federated=federated)
        other = None
        try:
            other = Deployment(base, "b", trust, journal, federated=federated)
            if federated:
                cx.neighbour, other.neighbour = other, cx
                cx.launch()
                other.launch()
                cx.connect()
                other.connect()
            observed = f(cx, other)
            return {**observed, "registeredExchanges": journal.snapshot()}
        finally:
            cx.stop()
            if other:
                other.stop()
