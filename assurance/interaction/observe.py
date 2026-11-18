"""Independent public-interface observations against a selected interaction endpoint."""

import base64
import fcntl
import hashlib
import json
import os
import pty
import secrets
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ORACLE = Path(__file__).resolve().parents[2]
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
sys.path[:0] = [str(ORACLE / "reference/interaction"), str(ORACLE / "reference")]
from client import Caller, CallError, stamp
from contracts import validate, validate_with
from transcripts import Journal

REGISTRY = {
    i["method"]: i
    for i in json.loads((ORACLE / "spec/profiles/operations.json").read_bytes())["operations"]
}
DECLARED = {
    i["id"]: i
    for i in json.loads((ORACLE / "reference/interaction/ocs.json").read_bytes())["exports"]
}


def insist(condition, message):
    if not condition:
        raise AssertionError(message)


def refused(wanted, call):
    try:
        call()
    except CallError as exc:
        insist(exc.kind == wanted, f"expected {wanted}, received {exc.kind}")
        return exc.kind
    raise AssertionError("Expected a refusal: " + wanted)


class CheckedCaller(Caller):
    def __init__(self, endpoint, key, journal):
        super().__init__(endpoint, key)
        self.journal = journal
        self.open_requests = {}

    def packet(self, raw, rid):
        original = super().packet(raw, rid)
        validate("wire", original, "failure" if "error" in original else "success")
        return original

    def post(self, request, accept="application/json"):
        if request["method"] == "stream.open":
            self.open_requests[request["id"]] = request["params"]
        return super().post(request, accept)

    def request(self, method, params, rid=None):
        public = params.get("operation") if method == "tool.call" else method
        inp = params.get("input") if method == "tool.call" else params
        identifier = rid or f"q{self.serial + 1}"
        try:
            result = super().request(method, params, rid)
        except CallError as e:
            self.journal.note(public, inp, self.pin, "refusal", code=e.kind, rid=identifier)
            raise
        self.journal.note(
            public,
            inp,
            self.pin,
            "result",
            result["data"] if method == "tool.call" else result,
            rid=identifier,
        )
        if method == "ocs.describe":
            validate("wire", result, "describeResult")
        elif method == "tool.call":
            validate("wire", result, "callResult")
        elif method in REGISTRY:
            validate_with({"$ref": REGISTRY[method]["output"]}, result)
        return result

    def stream(self, rid, credit=1, seconds=3, committed=None):
        try:
            return super().stream(rid, credit, seconds, committed)
        except CallError as e:
            self.journal.note(
                "stream.open",
                self.open_requests.pop(rid),
                self.pin,
                "refusal",
                code=e.kind,
                rid=rid,
            )
            raise

    def notify(self, method, params):
        status = super().notify(method, params)
        self.journal.note(
            method,
            params,
            self.pin,
            "notification" if status == 204 else "transport-refusal",
            code=status,
            rid=params.get("requestId"),
        )
        return status

    def call(self, op, inp, seconds=5):
        data = super().call(op, inp, seconds)
        validate_with(DECLARED[op]["outputSchema"], data)
        return data


class Deployment:
    def __init__(self, path, endpoint=None):
        self.database = str(path / "state.sqlite")
        self.journal = Journal()
        self.commit_delay_ms = 0
        self.connection_ms = 6000
        self.relay_delay_ms = 0
        self.proc = None
        self.port = 0
        self.external = bool(endpoint)
        self.endpoint = endpoint
        if self.external:
            if "OCS_INTERACTION_TOKEN" in os.environ:
                self.keys = {os.environ["OCS_INTERACTION_TOKEN"]: {"owner": "alice"}}
            else:
                self.keys = json.loads(os.environ["OCS_FIXTURE_IDENTITIES"])
        else:
            self.keys = {
                secrets.token_hex(24): conf
                for conf in (
                    {"owner": "alice"},
                    {"owner": "bob"},
                    {"owner": "alice", "purpose": "preview-only"},
                    {"owner": "alice", "admin": True},
                )
            }
        self.start()

    def start(self):
        if not self.external:
            env = {**os.environ, "OCS_FIXTURE_IDENTITIES": json.dumps(self.keys)}
            self.proc = subprocess.Popen(
                [
                    sys.executable,
                    "-E",
                    "-s",
                    str(SUBJECT / "reference/interaction/server.py"),
                    "--database",
                    self.database,
                    "--port",
                    str(self.port),
                    "--commit-delivery-ms",
                    str(self.commit_delay_ms),
                    "--connection-ms",
                    str(self.connection_ms),
                    "--relay-delay-ms",
                    str(self.relay_delay_ms),
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if not select.select([self.proc.stdout], [], [], 8)[0]:
                raise RuntimeError("interaction process did not start")
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(
                    "interaction process startup failed: " + self.proc.stderr.read()[-240:]
                )
            binding = json.loads(line)
            self.port = binding["port"]
            self.endpoint = f"http://127.0.0.1:{self.port}/ocs"

        def caller(owner, admin=False, purpose="interactive"):
            key = next(
                k
                for k, v in self.keys.items()
                if v["owner"] == owner
                and bool(v.get("admin")) == admin
                and v.get("purpose", "interactive") == purpose
            )
            c = CheckedCaller(self.endpoint, key, self.journal)
            d = c.describe()
            insist(d["packageId"] == "org.example.interaction", "wrong peer")
            insist(
                d["manifestDigest"]
                == hashlib.sha256(
                    (SUBJECT / "reference/interaction/ocs.json").read_bytes()
                ).hexdigest(),
                "unexpected admitted package bytes",
            )
            return c

        self.a = caller("alice")
        if not self.external:
            self.b, self.admin = caller("bob"), caller("alice", True)
            self.preview = caller("alice", False, "preview-only")

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
            self.proc = None

    def restart(self, path=None):
        if self.external:
            raise ValueError("The remote observation harness cannot restart its target.")
        self.stop()
        if path:
            self.database = path
        self.start()


def chunk(c, res, rid, seq):
    pack = c.sse(res)
    insist(pack is not None and pack[0] == "chunk", "expected a chunk")
    envelope = pack[1]
    validate("wire", envelope, "notification")
    validate("profile-wire", envelope["params"], "chunkParams")
    insist(
        envelope["method"] == "ocs.chunk"
        and envelope["params"]["requestId"] == rid
        and envelope["params"]["seq"] == seq,
        "chunk identity or ordinal mismatch",
    )
    c.journal.note("ocs.chunk", envelope["params"], c.pin, "notification", rid=rid)
    return envelope["params"]


def final(c, res, rid, error=None):
    pack = c.sse(res)
    insist(pack is not None and pack[0] == "response", "expected the single terminal response")
    env = pack[1]
    validate("wire", env, "failure" if error else "success")
    insist(env["id"] == rid, "terminal correlation mismatch")
    if error:
        insist(env["error"]["data"]["kind"] == error, "wrong terminal error")
    c.journal.note(
        "stream.open",
        c.open_requests.pop(rid),
        c.pin,
        "refusal" if error else "result",
        env.get("result"),
        code=error,
        rid=rid,
    )
    insist(c.sse(res) is None, "stream emitted a second terminal result or late chunk")
    return env


def life(d):
    a = d.a
    opened = a.call(
        "surface.open",
        {"surfaceId": "example.status.panel", "scope": {"kind": "tenant", "id": "alice"}},
    )
    rid = secrets.token_hex(8)
    conn, res = a.stream(rid)
    chunk(a, res, rid, 1)
    before = a.call("example.instance.inspect", {})
    refused("denied", lambda: d.b.call("example.instance.retire", {}))
    retired = d.admin.call("example.instance.retire", {})
    final(a, res, rid, "cancelled")
    conn.close()
    refused("denied", lambda: a.call("example.status.read", {"resourceId": "demo"}))
    active = d.admin.call("example.instance.activate", {})
    refused("denied", lambda: a.call("example.status.read", {"resourceId": "demo"}))
    a.describe()
    inspect = a.call("example.instance.inspect", {})
    refused(
        "denied",
        lambda: a.call(
            "surface.event",
            {
                "instanceId": opened["instanceId"],
                "generation": opened["generation"],
                "action": "example.status.read",
                "values": {"resourceId": "demo"},
            },
        ),
    )
    restored = a.call("example.status.read", {"resourceId": "demo"})
    insist(
        before["panels"] == before["streams"] == 1
        and inspect["panels"] == inspect["streams"] == 0
        and not retired["active"]
        and active["active"]
        and active["generation"] > before["generation"]
        and restored["state"] == "ready",
        "lifecycle failure",
    )
    return {"before": before, "retired": retired, "replacement": inspect, "read": restored}


def streams(d):
    a, b = d.a, d.b
    rid = secrets.token_hex(8)
    conn, res = a.stream(rid)
    try:
        first = chunk(a, res, rid, 1)
        snap = a.call("example.stream.inspect", {"requestId": rid})
        insist(
            snap == {"credit": 0, "sent": 1, "granted": 1, "remaining": 2, "finals": 0},
            "stream exceeded initial credit",
        )
        insist(b.notify("ocs.cancel", {"requestId": rid}) == 403, "foreign cancellation accepted")
        insist(
            a.notify("ocs.credit", {"requestId": rid, "add": 9}) == 400, "unbounded credit accepted"
        )
        insist(a.notify("ocs.credit", {"requestId": rid, "add": 2}) == 204, "credit refused")
        second, last = chunk(a, res, rid, 2), chunk(a, res, rid, 3)
        term = final(a, res, rid)
        insist(term["result"]["data"] == {"chunks": 3}, "final summary duplicates output")
    finally:
        conn.close()
    insist(
        a.notify("ocs.credit", {"requestId": rid, "add": 1}) == 204,
        "late control responded with a business value",
    )
    refused("conflict", lambda: a.stream(rid))
    refused("params", lambda: a.stream(secrets.token_hex(8), credit=0))
    refused(
        "incompatible",
        lambda: a.request(
            "stream.open",
            {
                "operation": "example.parts.read",
                "version": "1.0.0",
                "credit": 1,
                "input": {"resourceId": "demo"},
                "meta": a.meta(),
            },
        ),
    )
    rid2 = secrets.token_hex(8)
    conn, res = a.stream(rid2, seconds=0.45)
    try:
        chunk(a, res, rid2, 1)
        final(a, res, rid2, "deadline")
    finally:
        conn.close()
    refused("denied", lambda: a.call("example.receipt.fixture", {"outcome": "applied"}))
    receipt = d.admin.call("example.receipt.fixture", {"outcome": "applied"})["operationId"]
    count = a.call("example.instance.inspect", {})["receipts"]
    rid3 = secrets.token_hex(8)
    conn, res = a.stream(rid3, committed=receipt)
    try:
        chunk(a, res, rid3, 1)
        insist(a.notify("ocs.cancel", {"requestId": rid3}) == 204, "owner cancellation rejected")
        final(a, res, rid3, "cancelled")
    finally:
        conn.close()
    refused("denied", lambda: b.stream(secrets.token_hex(8), committed=receipt))
    unknown = d.admin.call("example.receipt.fixture", {"outcome": "unknown"})["operationId"]
    refused("denied", lambda: a.stream(secrets.token_hex(8), committed=unknown))
    insist(
        a.call("example.receipt.inspect", {"operationId": receipt})["state"] == "applied"
        and a.call("example.instance.inspect", {})["receipts"] == count + 1,
        "streaming or cancel modified the effect",
    )
    rid4 = secrets.token_hex(8)
    conn, res = a.stream(rid4, seconds=0.4)
    chunk(a, res, rid4, 1)
    res.close()
    conn.close()
    end = time.monotonic() + 2
    while a.call("example.instance.inspect", {})["streams"] and time.monotonic() < end:
        time.sleep(0.02)
    insist(
        a.call("example.instance.inspect", {})["streams"] == 0,
        "disconnected consumer retained beyond deadline",
    )
    # Independently import the candidate's consumer, retaining the frozen public wire expectations.
    import importlib.util

    sys.path.insert(0, str(SUBJECT / "reference/interaction"))
    try:
        spec = importlib.util.spec_from_file_location(
            "ocs_candidate_interaction", SUBJECT / "reference/interaction/service.py"
        )
        consumer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = consumer
        spec.loader.exec_module(consumer)
        receiver = consumer.ChunkReceiver(rid, 1)
        insist(
            receiver.ingest(1, first) and not receiver.ingest(1, first),
            "wrong duplicate acceptance",
        )
        for p, g, wanted in [
            (dict(first, data="different"), 1, "conflict"),
            (last, 1, "conflict"),
            (second, 0, "denied"),
        ]:
            try:
                receiver.ingest(g, p)
            except consumer.Refusal as err:
                insist(err.kind == wanted, "wrong receiver error")
            else:
                raise AssertionError("accepted stale, conflicting or missing chunk")
        insist(receiver.ingest(1, second) and receiver.ingest(1, last), "lost contiguous output")
    finally:
        sys.path.pop(0)
    return {
        "ordinals": [first["seq"], second["seq"], last["seq"]],
        "creditPause": snap,
        "terminal": term["result"],
        "disconnect": "unconfirmed; released before bound",
        "committedOutcome": "applied",
        "uncertainOutcome": "unknown",
    }


def events(d):
    a, b = d.a, d.b
    scope = {"kind": "tenant", "id": "alice"}
    source = "fixture-" + secrets.token_hex(5)
    request = {"scope": scope, "source": source, "type": "example.status", "durable": True}
    sub = a.call("events.subscribe", request)
    sid = sub["subscriptionId"]
    start = sub["cursor"]
    ephemeral = a.call("events.subscribe", {**request, "durable": False})
    event = {
        "eventId": "ev1",
        "type": "example.status",
        "source": source,
        "scope": scope,
        "observedAt": stamp(time.time()),
        "data": {"state": "ready"},
    }
    created = a.call("example.event.publish", event)
    duplicate = a.call("example.event.publish", event)
    refused(
        "conflict",
        lambda: a.call("example.event.publish", {**event, "data": {"state": "different"}}),
    )
    refused("denied", lambda: b.call("example.event.publish", event))
    second_source = a.call("example.event.publish", {**event, "source": source + "-another"})
    insist(second_source == created, "event ID collided across genuine sources of the same tenant")
    foreign = b.call("example.event.publish", {**event, "scope": {"kind": "tenant", "id": "bob"}})
    page = a.call("events.resume", {"subscriptionId": sid, "cursor": start})
    insist(
        len(page["events"]) == 1
        and page["events"][0]["eventId"] == "ev1"
        and not page["gap"]
        and created == {"ordinal": 1, "duplicate": False}
        and duplicate == {"ordinal": 1, "duplicate": True}
        and foreign == created,
        "event identity mismatch",
    )
    pos = {"subscriptionId": sid, "cursor": page["nextCursor"]}
    insist(a.call("events.ack", pos)["accepted"], "ACK rejected")
    refused("conflict", lambda: a.call("events.ack", {"subscriptionId": sid, "cursor": start}))
    refused("input", lambda: a.call("events.ack", {"subscriptionId": sid, "cursor": sid + "/999"}))
    refused("denied", lambda: b.call("events.resume", pos))
    refused(
        "incompatible",
        lambda: a.call(
            "events.resume",
            {"subscriptionId": ephemeral["subscriptionId"], "cursor": ephemeral["cursor"]},
        ),
    )
    if not d.external:
        d.restart()
        a = d.a
    if not d.external:
        refused(
            "denied",
            lambda: a.call(
                "events.resume",
                {"subscriptionId": ephemeral["subscriptionId"], "cursor": ephemeral["cursor"]},
            ),
        )
    insist(not a.call("events.resume", pos)["gap"], "durable cursor lost")
    for n in range(2, 8):
        a.call("example.event.publish", {**event, "eventId": "ev" + str(n)})
    gap = a.call("events.resume", pos)
    insist(gap["gap"] and not gap["events"], "missing history masqueraded as complete")
    a.call("example.subscription.close", {"subscriptionId": sid})
    refused("denied", lambda: a.call("events.resume", pos))
    return {
        "first": created,
        "duplicate": duplicate,
        "tenantIndependent": foreign,
        "gap": gap["gap"],
        "release": "denied",
    }


def jobs(d):
    a, b = d.a, d.b
    oid = d.admin.call("example.receipt.fixture", {"outcome": "applied"})["operationId"]
    draft = {"input": "keep", "step": 2}
    j = a.call("example.job.begin", {"draft": draft, "operationId": oid})
    if not d.external:
        d.restart()
        a, b = d.a, d.b
    recovered = a.request("job.status", {"jobId": j["jobId"], "meta": a.meta()})
    insist(
        recovered == j and a.call("example.job.inspect", {"jobId": j["jobId"]})["draft"] == draft,
        "lost durable job data",
    )
    refused("denied", lambda: b.request("job.status", {"jobId": j["jobId"], "meta": b.meta()}))

    def resume(i):
        try:
            return a.request(
                "job.continue",
                {"jobId": j["jobId"], "revision": 1, "input": {"attempt": i}, "meta": a.meta()},
                rid="resume" + str(i),
            )["state"]
        except CallError as exc:
            return exc.kind

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(resume, (1, 2)))
    insist(
        outcomes == ["conflict", "succeeded"],
        "concurrent continuation had the wrong number of winners",
    )
    terminal = a.request("job.cancel", {"jobId": j["jobId"], "meta": a.meta()})
    insist(
        terminal["state"] == "succeeded" and terminal["revision"] == 2 and resume(3) == "conflict",
        "terminal state reopened",
    )
    waiting = a.call("example.job.begin", {"draft": draft, "operationId": oid})
    cancelled = a.request("job.cancel", {"jobId": waiting["jobId"], "meta": a.meta()})
    insist(
        cancelled["state"] == "cancelled"
        and a.call("example.receipt.inspect", {"operationId": oid})["state"] == "applied",
        "cancellation reversed prior effect",
    )
    proposal = a.call("example.compensation.propose", {"original": oid})
    cid = proposal["id"]
    preview = a.call("example.compensation.review", {"id": cid})
    exact = {"id": cid, "intentDigest": preview["intentDigest"]}
    insist(cid != oid and not proposal["approved"], "compensation borrowed approval")
    refused("denied", lambda: a.call("example.compensation.approve", exact))
    refused("denied", lambda: a.call("example.compensation.commit", exact))
    d.admin.call("example.compensation.approve", exact)
    if not d.external:
        d.admin.call("example.store.backup", {})
        d.restart(d.database + ".backup")
        a = d.a
        insist(
            a.request("job.status", {"jobId": j["jobId"], "meta": a.meta()}) == terminal,
            "backup lost job revision",
        )
    finished = a.call("example.compensation.commit", exact)
    insist(
        finished["finished"]
        and a.call("example.compensation.commit", exact) == finished
        and a.call("example.receipt.inspect", {"operationId": oid})["state"] == "applied",
        "wrong compensation or restored receipt",
    )
    return {
        "concurrent": outcomes,
        "terminalRevision": terminal["revision"],
        "cancelOutcome": cancelled["state"],
        "originalEffect": "applied",
        "compensationSeparate": cid != oid,
        "restarted": not d.external,
    }


def artifact(d):
    a, b = d.a, d.b
    handle = a.call("example.artifact.locate", {"repeat": 1800, "ttlMs": 15000})
    data = bytearray()
    sizes = []
    while True:
        page = a.call(
            "artifact.read", {"artifact": handle, "offset": len(data), "maxBytes": 100000}
        )
        raw = base64.b64decode(page["data"], validate=True)
        insist(
            page["artifact"] == handle and page["offset"] == len(data) and (page["eof"] or raw),
            "artifact {state,range} mismatch",
        )
        insist(
            len(
                json.dumps(
                    {"jsonrpc": "2.0", "id": "q1", "result": {"data": page}}, separators=(",", ":")
                ).encode()
            )
            <= 16384,
            "oversize encoded page",
        )
        sizes.append(len(raw))
        data.extend(raw)
        if page["eof"]:
            break
    insist(
        len(data) == handle["bytes"]
        and hashlib.sha256(data).hexdigest() == handle["digest"]
        and data == ("data é ☀ " * 1800).encode(),
        "bad assembled digest/length/content",
    )
    query = {"artifact": handle, "offset": len(data), "maxBytes": 1}
    empty = a.call("artifact.read", query)
    insist(
        empty["data"] == "" and empty["eof"], "byte offset at EOF must yield an empty final page"
    )
    refused("input", lambda: a.call("artifact.read", {**query, "offset": len(data) + 1}))
    refused(
        "pin", lambda: a.call("artifact.read", {**query, "artifact": {**handle, "revision": "2"}})
    )
    refused("denied", lambda: b.call("artifact.read", query))
    refused("denied", lambda: d.preview.call("artifact.read", query))
    refused("denied", lambda: d.preview.call("example.artifact.release", {"id": handle["id"]}))
    refused(
        "pin",
        lambda: a.call(
            "artifact.read", {**query, "artifact": {**handle, "mediaType": "image/png"}}
        ),
    )
    a.call("example.artifact.release", {"id": handle["id"]})
    refused("denied", lambda: a.call("artifact.read", query))
    short = a.call("example.artifact.locate", {"repeat": 1, "ttlMs": 60})
    time.sleep(0.09)
    refused(
        "denied", lambda: a.call("artifact.read", {"artifact": short, "offset": 0, "maxBytes": 1})
    )
    return {
        "pages": sizes,
        "length": len(data),
        "sha256": handle["digest"],
        "emptyAtEnd": True,
        "foreign": "denied",
        "sameTenantUnrelatedPurpose": "denied",
        "releaseWithUnrelatedPurpose": "denied",
        "expired": "denied",
    }


def delegation(d):
    a = d.a
    req = {
        "operation": "example.status.read",
        "resourceId": "demo",
        "depth": 2,
        "cycle": False,
        "reachable": True,
    }
    before = a.call("example.instance.inspect", {})["receipts"]
    ok = a.call("example.delegate.read", req)
    insist(
        ok["data"] == a.call("example.status.read", {"resourceId": "demo"})
        and [(x["caller"], x["receiver"]) for x in ok["trace"]]
        == [("front", "relay"), ("relay", "authority")]
        and ok["trace"][0]["parent"] == "alice"
        and ok["remainingDepth"] == 0,
        "lost peer identity or resource binding",
    )
    d.admin.call("example.peer.replace", {"revision": 2})
    replacement = a.call("example.delegate.read", req)
    insist(replacement["data"] == ok["data"], "private replacement changed public result")
    refused("denied", lambda: a.call("example.delegate.read", {**req, "operation": "quota.reset"}))
    d.admin.call("example.peer.replace", {"revision": 1})
    first, second = ok["trace"]
    insist(
        all(
            row["manifestDigest"] == a.pin
            and row["actualRevision"] == "0.1.0"
            and row["decision"] == "admitted"
            and row["durationNs"] > 0
            for row in ok["trace"]
        )
        and first["durationNs"] >= second["durationNs"]
        and all(c.key not in json.dumps(ok["trace"]) for c in (a, d.b, d.admin)),
        "trace lost subject revision, decision, duration or credential redaction",
    )

    insist(
        first["callId"] == second["parentCallId"]
        and first["retryOwner"] == second["retryOwner"]
        and first["generation"] == second["generation"]
        and first["region"] == second["region"] == "loopback"
        and 0 <= second["remainingMs"] <= first["remainingMs"] <= 5000,
        "causal provenance or budget changed",
    )
    for delta, kind in [
        ({"operation": "quota.reset"}, "denied"),
        ({"resourceId": "other"}, "denied"),
        ({"depth": 1}, "busy"),
        ({"cycle": True, "depth": 6}, "busy"),
        ({"reachable": False}, "unavailable"),
        ({"recipient": "other"}, "input"),
    ]:
        refused(kind, lambda: a.call("example.delegate.read", {**req, **delta}))
    refused("denied", lambda: a.call("example.peer.availability", {"online": False}))
    d.admin.call("example.peer.availability", {"online": False})
    then = time.perf_counter_ns()
    refused("unavailable", lambda: a.call("example.delegate.read", req))
    one = a.call("example.status.read", {"resourceId": "demo"})
    recovery_ns = time.perf_counter_ns() - then
    d.admin.call("example.peer.availability", {"online": True})
    insist(recovery_ns < 5_000_000_000, "local fallback missed its five-second budget")
    head = a.call("example.instance.inspect", {})
    insist(
        one["state"] == "ready" and head["receipts"] == before,
        "peer loss or telemetry changed local authority",
    )
    hook = {"operation": "example.status.read", "depth": 1, "value": " a ", "transform": False}
    observed = a.call("example.hook.observe", hook)
    changed = a.call("example.hook.observe", {**hook, "transform": True})
    insist(
        observed["observed"] == observed["original"] == " a "
        and changed["observed"] == "A"
        and changed["original"] == " a ",
        "observer modified data or ordered transforms failed",
    )
    for delta, kind in [
        ({"depth": 3}, "busy"),
        ({"value": " ", "transform": True}, "input"),
        ({"operation": "quota.reset"}, "denied"),
    ]:
        refused(kind, lambda: a.call("example.hook.observe", {**hook, **delta}))
    insist(
        a.call("example.instance.inspect", {})["receipts"] == before, "unintended hook side effect"
    )
    return {
        "hops": ok["trace"],
        "depthLeft": 0,
        "cycle": "busy",
        "outage": "unavailable",
        "local": one,
        "localDuringOutageNs": recovery_ns,
        "observerValue": observed["observed"],
        "orderedTransforms": changed["observed"],
        "effectsBeforeAfter": [before, head["receipts"]],
    }


def ui(d):
    a, b = d.a, d.b
    job = a.call("example.job.begin", {"draft": "independent"})
    view = a.call(
        "surface.open",
        {"surfaceId": "example.status.panel", "scope": {"kind": "tenant", "id": "alice"}},
    )
    ref = {k: view[k] for k in ("instanceId", "generation")}
    display = view["surface"]["view"]
    src = a.call("example.ui.status", {})
    for key in ("state", "quota", "reset", "recovery", "terms"):
        insist(display["values"][key] == src[key], "UI and API disagree")
    action = {**ref, "action": "example.status.read", "values": {"resourceId": "demo"}}
    res = a.call("surface.event", action)
    insist(res["view"]["values"]["state"] == "ready", "UI event did not dispatch selected read")
    for caller, delta in [
        (b, {}),
        (a, {"action": "quota.reset"}),
        (a, {"values": {"resourceId": "demo", "approved": True}}),
    ]:
        refused("denied", lambda: caller.call("surface.event", {**action, **delta}))
    inspected = {"surface": view["surface"], "action": "example.status.read", "version": "1.0.0"}
    insist(
        a.call("example.surface.inspect", inspected) == {"eligible": True},
        "valid versioned view rejected",
    )
    refused("denied", lambda: a.call("example.surface.inspect", {**inspected, "version": "9.1.0"}))
    refused(
        "denied", lambda: a.call("example.surface.inspect", {**inspected, "action": "quota.reset"})
    )
    altered = {**view["surface"], "view": {**view["surface"]["view"], "values": {"state": 7}}}
    refused("input", lambda: a.call("example.surface.inspect", {**inspected, "surface": altered}))
    web = {
        "instanceId": view["instanceId"],
        "navigation": "same-origin",
        "egress": "none",
        "sandboxRequested": True,
        "event": {"action": "example.status.read", "values": {"resourceId": "demo"}},
        "origin": "https://preview.example.invalid",
        "eventOrigin": "https://preview.example.invalid",
        "digest": hashlib.sha256(b"<p>Scoped resource details</p>").hexdigest(),
        "generation": view["generation"],
    }
    fallback = a.call("example.web.admit", web)
    insist(
        fallback["representation"] == "terminal" and "reason" in fallback,
        "unsafe automatic embedding",
    )
    for delta in (
        {"eventOrigin": "https://other.invalid"},
        {"navigation": "anywhere"},
        {"egress": "network"},
        {"sandboxRequested": False},
        {"instanceId": "other-panel"},
        {"event": {"action": "quota.reset", "values": {"approved": True}}},
        {"digest": "0" * 64},
        {"generation": view["generation"] + 1},
    ):
        refused("denied", lambda: a.call("example.web.admit", {**web, **delta}))
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sink:
        sink.bind(("127.0.0.1", 0))
        sink.listen(1)
        destination = "http://127.0.0.1:" + str(sink.getsockname()[1]) + "/blocked"
        refused(
            "denied",
            lambda: a.call(
                "example.web.admit",
                {**web, "origin": destination, "eventOrigin": destination, "egress": destination},
            ),
        )
        insist(
            not select.select([sink], [], [], 0.05)[0],
            "an unadmitted renderer sent traffic to the blocked destination",
        )
        refused(
            "input", lambda: a.call("example.web.admit", {**web, "event": {"unregistered": True}})
        )
    refused(
        "incompatible",
        lambda: a.call(
            "surface.open",
            {"surfaceId": "example.other.widget", "scope": {"kind": "tenant", "id": "alice"}},
        ),
    )
    a.call("example.surface.close", ref)
    refused("denied", lambda: a.call("surface.event", action))
    inspect = a.call("example.instance.inspect", {})
    insist(
        inspect["focus"] == "workspace"
        and a.request("job.status", {"jobId": job["jobId"], "meta": a.meta()}) == job
        and a.call("example.status.read", {"resourceId": "demo"})["state"] == "ready",
        "closing the panel changed headless job/access",
    )
    return {
        "slot": view["surface"]["slot"],
        "action": display["actions"][0]["operation"],
        "recovery": inspect["focus"],
        "unknownRenderer": fallback,
        "blockedNavigationAndEgress": True,
        "observedUnauthorizedConnections": 0,
        "unknownEventSchema": "input",
        "oldInstance": "denied",
        "jobPreserved": True,
        "accessibleLabels": list(display["values"]),
    }


def keyboard(d):
    observations = []
    for width in (28, 14):
        proposal = None
        expected_review = None
        if not d.external:
            receipt = d.admin.call("example.receipt.fixture", {"outcome": "applied"})["operationId"]
            proposal = d.a.call("example.compensation.propose", {"original": receipt})["id"]
            expected_review = d.a.call("example.compensation.review", {"id": proposal})
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 16, width, 0, 0))
            env = {**os.environ, "OCS_INTERACTION_TOKEN": d.a.key}
            env.pop("OCS_INTERACTION_APPROVER", None)
            if not d.external:
                env["OCS_INTERACTION_APPROVER"] = d.admin.key
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-E",
                    "-s",
                    str(SUBJECT / "reference/interaction/terminal.py"),
                    "--endpoint",
                    d.endpoint,
                    "--owner",
                    "alice",
                    *(["--proposal-id", proposal] if proposal else []),
                ],
                stdin=subprocess.PIPE,
                stdout=slave,
                stderr=subprocess.PIPE,
                env=env,
            )
            os.close(slave)
            slave = -1
            keys = [
                "r",
                "t",
                *(["n", "s"] if not d.external else []),
                "g",
                *(["a"] if proposal else []),
                "q",
            ]
            proc.stdin.write(("\n".join(keys) + "\n").encode())
            proc.stdin.close()
            end = time.monotonic() + 8
            pieces = []
            while time.monotonic() < end:
                if not select.select([master], [], [], max(0, end - time.monotonic()))[0]:
                    break
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                pieces.append(data)
                insist(sum(map(len, pieces)) < 12000, "unbounded terminal output")
            code = proc.wait(timeout=1)
            insist(code == 0, "terminal client failed: " + proc.stderr.read().decode()[:120])
            proc.stderr.close()
            text = b"".join(pieces).decode()
            compact = " ".join(text.split())
            for label in (
                "Resource status",
                "State ready",
                "Quota remaining unknown",
                "Reset unavailable",
                "Last checked",
                "Terms Read plan 0 USD per request",
                "[t] Retry request",
                "[s] Resume saved job",
                "[n] New request",
                "[g] Request permission",
                "[a] Authorize reviewed intent",
                "Retried the selected resource",
                *(
                    ["Created a new owned job", "Resumed saved job succeeded"]
                    if not d.external
                    else []
                ),
                "Recovery Reconnect",
                "[r] Refresh",
                "[q] Close",
                "Workspace",
            ):
                insist(label in compact, "missing keyboard label: " + label)
            insist(
                compact.count("State ready") == 3
                and max(len(z) for z in text.splitlines()) <= width,
                "refresh or wrapping failed",
            )
            if expected_review:
                dense = "".join(text.split())
                intent = expected_review["intent"]
                asserted = [
                    "Trustedownerreview",
                    "Recipient" + intent["recipient"],
                    "Resource" + receipt,
                    "Operation" + intent["operation"],
                    "Amount0USD",
                    "Exactintent" + expected_review["intentDigest"],
                    "Authorizedthedisplayedintent",
                ]
                insist(
                    all(t in dense for t in asserted),
                    "trusted terminal did not disclose and authorize the exact intent",
                )
                d.a.call(
                    "example.compensation.commit",
                    {"id": proposal, "intentDigest": expected_review["intentDigest"]},
                )
            else:
                insist(
                    "Permission review requires an owner-selected proposal" in compact,
                    "grant action silently succeeded",
                )
            observations.append(
                {
                    "columns": width,
                    "keys": keys,
                    "readCount": 3,
                    "trustedReview": bool(expected_review),
                    "maximumColumns": max(len(z) for z in text.splitlines()),
                }
            )
        finally:
            os.close(master)
            if slave >= 0:
                os.close(slave)
    return {
        "terminal": "PTY",
        "viewport": observations,
        "colorsRequired": False,
        "target": "local keyboard terminal using named endpoint",
        "physicalFontScale": "effective terminal column widths only",
    }


def message(c, mid, text, context, **fields):
    return c.call(
        "agent.exchange",
        {
            "messageId": mid,
            "contextId": context,
            "parts": [{"type": "text", "text": text}],
            "accept": ["text/plain"],
            **fields,
        },
    )["message"]


def agent(d):
    a, b = d.a, d.b
    context = secrets.token_hex(6)
    ask = message(
        a, "question", "Read", context, budget={"remainingTurns": 3, "remainingBytes": 2048}
    )
    answer = message(
        a,
        "fact",
        "Read demo",
        context,
        replyTo=ask["messageId"],
        budget=ask["budget"],
        senderLabel="quoted user",
        taskId="task-witness",
    )
    duplicate = message(
        a,
        "fact",
        "Read demo",
        context,
        replyTo=ask["messageId"],
        budget=ask["budget"],
        senderLabel="quoted user",
        taskId="task-witness",
    )
    left = a.call("example.agent.trace", {"contextId": context, "messageId": "fact"})
    message(b, "fact", "Read demo", context, senderLabel="alice", taskId="task-witness")
    right = b.call("example.agent.trace", {"contextId": context, "messageId": "fact"})
    insist(
        left["authenticatedOrigin"] == "alice"
        and right["authenticatedOrigin"] == "bob"
        and left["taskId"] == right["taskId"] == "task-witness",
        "original participant or task was lost in correlation",
    )
    confirm = message(
        a,
        "confirm",
        "Confirm " + answer["parts"][0]["text"],
        context,
        replyTo=answer["messageId"],
        budget=answer["budget"],
    )
    insist(
        ask["kind"] == "clarification"
        and answer == duplicate
        and answer["replyTo"] == "fact"
        and answer["senderLabel"] == "fixture-fact-authority"
        and confirm["parts"][0]["text"] == "confirmed"
        and confirm["budget"]["remainingTurns"] == 0
        and confirm["contextId"] == context,
        "dialogue failed",
    )
    refused("busy", lambda: message(a, "overflow", "Read demo", context, budget=confirm["budget"]))
    refused("conflict", lambda: message(a, "fact", "Read other", context))
    refused(
        "busy",
        lambda: a.call(
            "example.agent.relay",
            {
                "depth": 1,
                "message": {
                    "messageId": "fanout",
                    "parts": [{"type": "text", "text": "Read demo"}],
                    "budget": {"maxFanOut": 0},
                },
            },
        ),
    )
    resources = {"turns": 2, "bytes": 2048, "fanOut": 2, "concurrency": 2, "costUnits": 4}
    share = {"turns": 1, "bytes": 1024, "fanOut": 1, "concurrency": 1, "costUnits": 2}

    def branch(mid):
        return {
            "message": {
                "messageId": mid,
                "contextId": context + "-branches",
                "parts": [{"type": "text", "text": "Read demo"}],
            },
            "reservation": share,
        }

    fanout = {"budget": resources, "children": [branch("one"), branch("two")]}
    oversized = {**fanout, "budget": {**resources, "costUnits": 3}}
    refused("busy", lambda: a.call("example.agent.parallel", oversized))
    refused(
        "denied",
        lambda: a.call(
            "example.agent.trace", {"contextId": context + "-branches", "messageId": "one"}
        ),
    )
    sent = a.call("example.agent.parallel", fanout)
    insist(
        sent["remaining"] == {k: 0 for k in resources}
        and [x["replyTo"] for x in sent["replies"]] == ["one", "two"]
        and all(
            x["budget"]["remainingTurns"] == x["budget"]["maxFanOut"] == 0
            and x["budget"]["remainingCost"] == {"amount": "2", "currency": "USD"}
            for x in sent["replies"]
        ),
        "parallel allocation, origin or ordered result changed",
    )
    before = a.call("example.instance.inspect", {})["receipts"]
    authority = message(a, "request", "Reset demo", context, senderLabel="administrator")
    partial = message(a, "partial", "Partial demo", context)
    insist(
        authority["kind"] == "authorization-required"
        and partial["kind"] == "partial"
        and a.call("example.instance.inspect", {})["receipts"] == before,
        "surface altered authority or hid partial result",
    )
    refused(
        "denied",
        lambda: a.call(
            "example.agent.relay",
            {
                "depth": 1,
                "message": {
                    "messageId": "privacy",
                    "parts": [{"type": "text", "text": "Read demo"}],
                    "purpose": "fixture-secret-redaction",
                },
            },
        ),
    )
    refused("incompatible", lambda: message(a, "image", "Read demo", context, accept=["image/png"]))
    refused("denied", lambda: message(a, "other", "Read other", context))
    refused("denied", lambda: b.call("example.agent.cancel", {"contextId": "different-" + context}))
    b.call("example.agent.cancel", {"contextId": context})
    alive = message(a, "still-open", "Read demo", context)
    insist(alive["kind"] == "answer", "cancelling one owner's same-named context canceled another")
    refused(
        "denied",
        lambda: message(a, "no-secrets", "Read demo", context, purpose="fixture-secret-redaction"),
    )
    a.call("example.agent.cancel", {"contextId": context})
    refused("cancelled", lambda: message(a, "late", "Read demo", context))
    return {
        "kinds": [ask["kind"], answer["kind"], partial["kind"], authority["kind"]],
        "confirmed": True,
        "endTurns": 0,
        "duplicateIdentical": True,
        "parallelParent": resources,
        "childReservations": [share, share],
        "remainingAfterReservation": sent["remaining"],
        "oversubscribedChild": "no downstream transcript",
        "crossTenant": "denied",
        "cancelled": "cancelled",
    }


def comparison(d):
    metrics = []
    for mode in ("direct", "relay-full", "relay-minimum"):
        context = secrets.token_hex(8)
        a = d.a
        history = [
            {"kind": "request", "text": "Find the condition of the selected resource."},
            {"kind": "answer", "text": "The selected authorized resource is demo."},
            {"kind": "request", "text": "Ask its owner for the current private fact."},
        ]
        delegated = {
            "messageId": "task",
            "contextId": context,
            "parts": [{"type": "text", "text": "Read demo"}],
            "accept": ["text/plain"],
        }
        if mode == "relay-full":
            delegated["purpose"] = json.dumps(history, ensure_ascii=False)
        elif mode == "relay-minimum":
            delegated["purpose"] = "Consult demo owner"
        # The relay is a separate authenticated wire call with a fixed, read-only downstream binding.
        wire = []
        initial_bytes = a.body_bytes
        relay_bytes = 0
        t0 = time.perf_counter_ns()
        if mode == "direct":
            response = a.call("agent.exchange", delegated)["message"]
        else:
            relayed = a.call("example.agent.relay", {"message": delegated, "depth": 1})
            response, relay_bytes = relayed["message"], relayed["relayBytes"]
        first = time.perf_counter_ns()
        wire.append((delegated, response))
        follow = {
            "messageId": "check",
            "contextId": context,
            "replyTo": response["messageId"],
            "parts": [{"type": "text", "text": "Confirm " + response["parts"][0]["text"]}],
        }
        verify = a.call("agent.exchange", follow)["message"]
        wire.append((follow, verify))
        end = time.perf_counter_ns()
        n = sum(
            len(json.dumps(p, ensure_ascii=False, separators=(",", ":")).encode())
            for pair in wire
            for p in pair
        )
        insist(verify["parts"][0]["text"] == "confirmed", "quality criterion failed on " + mode)
        total_wire = a.body_bytes - initial_bytes + relay_bytes
        a.call("example.agent.cancel", {"contextId": context})
        metrics.append(
            {
                "mode": mode,
                "confirmed": True,
                "messagePayloadBytes": n,
                "wireBodyBytes": total_wire,
                "firstUsefulNs": first - t0,
                "endToEndNs": end - t0,
                "tokenCount": None,
                "price": {"amount": "0", "currency": "USD"},
            }
        )
    insist(
        metrics[1]["messagePayloadBytes"] > metrics[2]["messagePayloadBytes"],
        "full history produced no additional bytes",
    )
    return {
        "observations": metrics,
        "workload": "one exact fact and independent confirmation per mode",
        "qualityThreshold": "all three confirmations",
        "tokenUnit": "no tokenizer in deterministic peer",
        "costBasis": "fixture makes no billed downstream call",
        "measurementPoint": "caller monotonic clock",
    }


def updated_policy(d):
    a, b = d.a, d.b
    panel = a.call(
        "surface.open",
        {"surfaceId": "example.status.panel", "scope": {"kind": "tenant", "id": "alice"}},
    )
    artifact = a.call("example.artifact.locate", {"repeat": 1, "ttlMs": 3000})
    worker = a.call(
        "example.work-observer.start", {"operation": "example.status.read", "budget": 64}
    )
    wid = {"id": worker["id"]}
    until = time.monotonic() + 1
    while a.call("example.work-observer.status", wid)["steps"] < 1 and time.monotonic() < until:
        time.sleep(0.01)
    first = a.call("example.work-observer.status", wid)
    insist(
        first["steps"] >= 1 and first["identity"].startswith("observer/alice/"),
        "background read never ran under its own binding",
    )
    refused(
        "denied",
        lambda: a.call("example.work-observer.start", {"operation": "quota.reset", "budget": 2}),
    )
    refused("denied", lambda: b.call("example.work-observer.stop", wid))
    rid = secrets.token_hex(8)
    conn, res = a.stream(rid)
    chunk(a, res, rid, 1)
    begin = time.perf_counter_ns()
    blocked = d.admin.call("example.grant.set", {"owner": "alice", "enabled": False})
    refused("denied", lambda: a.call("example.status.read", {"resourceId": "demo"}))
    a.describe()
    refused("denied", lambda: a.call("example.status.read", {"resourceId": "demo"}))
    wall = time.perf_counter_ns() - begin
    insist(
        blocked["maximumStaleAdmissions"] == 0
        and b.call("example.status.read", {"resourceId": "demo"})["state"] == "ready",
        "revocation crossed tenant scope or admitted a stale request",
    )
    final(a, res, rid, "cancelled")
    conn.close()
    enabled = d.admin.call("example.grant.set", {"owner": "alice", "enabled": True})
    refused("denied", lambda: a.call("example.status.read", {"resourceId": "demo"}))
    a.describe()
    refused(
        "denied",
        lambda: a.call(
            "surface.event",
            {
                "instanceId": panel["instanceId"],
                "generation": panel["generation"],
                "action": "example.status.read",
                "values": {"resourceId": "demo"},
            },
        ),
    )
    refused(
        "denied",
        lambda: a.call("artifact.read", {"artifact": artifact, "offset": 0, "maxBytes": 1}),
    )
    still = a.call("example.work-observer.status", wid)
    until = time.monotonic() + 1
    while not still["stopped"] and time.monotonic() < until:
        time.sleep(0.02)
        still = a.call("example.work-observer.status", wid)
    insist(
        still["stopped"]
        and still["steps"] <= still["budget"]
        and enabled["epoch"] > blocked["epoch"],
        "background survived revocation",
    )
    finished = a.call(
        "example.work-observer.start", {"operation": "example.status.read", "budget": 2}
    )
    until = time.monotonic() + 1
    while not finished["stopped"] and time.monotonic() < until:
        time.sleep(0.02)
        finished = a.call("example.work-observer.status", {"id": finished["id"]})
    insist(
        finished["stopped"] and finished["steps"] == 2,
        "bounded background work did not stop at its allocation",
    )
    d.admin.describe()
    d.admin.call("example.peer.availability", {"online": False})
    refused(
        "unavailable",
        lambda: a.call(
            "example.agent.relay",
            {
                "depth": 1,
                "message": {
                    "messageId": "partition",
                    "parts": [{"type": "text", "text": "Read demo"}],
                },
            },
        ),
    )
    d.admin.call("example.peer.availability", {"online": True})
    old_token = a.key
    selected_endpoint = d.endpoint
    conf = d.keys.pop(old_token)
    d.keys[secrets.token_hex(24)] = conf
    start = time.perf_counter_ns()
    d.restart()
    insist(d.endpoint == selected_endpoint, "rotation silently switched endpoints")
    stale = CheckedCaller(selected_endpoint, old_token, d.journal)
    refused("http-403", lambda: stale.describe())
    insist(
        d.a.call("example.status.read", {"resourceId": "demo"})["state"] == "ready"
        and d.b.call("example.status.read", {"resourceId": "demo"})["state"] == "ready",
        "rotation displaced an unrelated owned grant",
    )
    rotation_ns = time.perf_counter_ns() - start
    insist(
        rotation_ns < 5_000_000_000, "controlled restart exceeded the declared observation bound"
    )
    return {
        "rotationOldCredential": "HTTP 403",
        "rotationSameEndpoint": True,
        "restartToRotationObservedNs": rotation_ns,
        "maximumRestartMs": 5000,
        "affectedOwner": "alice",
        "unaffectedOwner": "bob",
        "maxAdmissionsAfterCommit": 0,
        "observedRejectionNs": wall,
        "epochBeforeAfter": [blocked["epoch"], enabled["epoch"]],
        "backgroundIdentity": worker["identity"],
        "beforeRevocationSteps": first["steps"],
        "stoppedAfterRevocationSteps": still["steps"],
        "finiteWorkerSteps": finished["steps"],
    }


def data_policy(d):
    a, b = d.a, d.b
    identifier = secrets.token_hex(6)
    qa = {"owner": "alice", "key": identifier}
    qb = {**qa, "owner": "bob"}
    a.call("example.privacy.save", {**qa, "value": "private-fixture-content", "retentionMs": 350})
    b.call("example.privacy.save", {**qb, "value": "other-owned-content", "retentionMs": 2800})
    payload = a.call("example.privacy.read", qa)
    audit = payload["diagnostic"]
    insist(
        payload["value"] == "private-fixture-content"
        and payload["region"] == audit["region"] == "local-cell"
        and "private-fixture-content" not in json.dumps(audit)
        and a.key not in json.dumps(audit)
        and audit["tenant"] == "alice",
        "private data leaked into diagnostics or escaped residency",
    )
    refused("denied", lambda: b.call("example.privacy.read", qa))
    refused("denied", lambda: b.call("example.privacy.withdraw", qa))
    a.call("example.privacy.withdraw", qa)
    refused("denied", lambda: a.call("example.privacy.read", qa))
    insist(
        b.call("example.privacy.read", qb)["value"] == "other-owned-content",
        "owner erasure touched another tenant",
    )
    until = time.monotonic() + 1
    counts = a.call("example.privacy.counts", qa)
    while (counts["states"] or counts["diagnostics"]) and time.monotonic() < until:
        time.sleep(0.025)
        counts = a.call("example.privacy.counts", qa)
    insist(
        counts["states"] == counts["diagnostics"] == 0
        and b.call("example.privacy.counts", qb)["states"] == 1,
        "expired state/diagnostics physically retained or another tenant lost",
    )
    return {
        "residency": audit["region"],
        "auditFieldNames": sorted(audit),
        "scrubbed": True,
        "onWithdraw": "unreadable",
        "purged": counts,
        "otherTenantRetained": True,
        "retentionMs": 350,
    }


def callback(d):
    a = d.a
    refused("conflict", lambda: a.call("example.exchange.callback", {"channel": "serial"}))
    refused("denied", lambda: a.call("example.callback.observe", {}))
    result = a.call("example.exchange.callback", {"channel": "separate"})
    insist(
        result["returned"]["requestId"] == result["outboundId"]
        and result["returned"]["direction"] == "return"
        and result["returned"]["owner"] == "alice"
        and result["channel"] == "separate-authenticated-return",
        "bidirectional ID collision or unbound return channel",
    )
    return {"correlatedAcrossDirections": True, "serialSelfCall": "refused", "actualHop": result}


def late_job(d):
    d.commit_delay_ms = 250
    d.restart()
    a = d.a
    receipt = d.admin.call("example.receipt.fixture", {"outcome": "applied"})["operationId"]
    observed = {}
    for op, expected in [("job.continue", "succeeded"), ("job.cancel", "cancelled")]:
        handle = a.call("example.job.begin", {"draft": "pre-deadline", "operationId": receipt})[
            "jobId"
        ]
        params = {"jobId": handle, "meta": a.meta(0.12)}
        if op == "job.continue":
            params.update(revision=1, input={})
        try:
            a.request(op, params)
        except CallError as e:
            insist(
                e.kind == "deadline"
                and e.data.get("operationId") == receipt
                and e.data.get("retryable") is False
                and expected in str(e),
                "late committed result lost its scoped operation ID or outcome",
            )
        else:
            raise AssertionError("expected a lost deadline after actual committed storage")
        state = a.request("job.status", {"jobId": handle, "meta": a.meta()})
        insist(
            state["state"] == expected
            and state["revision"] == 2
            and state["operationId"] == receipt,
            "durable job readback mismatch",
        )
        observed[op] = {
            "state": state["state"],
            "revision": state["revision"],
            "operationIdPreserved": True,
        }
    d.restart()
    a = d.a
    insist(
        a.call("example.receipt.inspect", {"operationId": receipt})["state"] == "applied"
        and a.call("example.instance.inspect", {})["receipts"] == 1,
        "post-timeout reconciliation changed external receipt count",
    )
    return {
        "postCommitDelayMs": 250,
        "callerDeadlineMs": 120,
        "outcomes": observed,
        "effectAfterRestart": "applied",
        "receiptCount": 1,
    }


def review_intent(d):
    a, b = d.a, d.b
    receipt = d.admin.call("example.receipt.fixture", {"outcome": "applied"})["operationId"]
    proposal = a.call("example.compensation.propose", {"original": receipt})["id"]
    reviewed = a.call("example.compensation.review", {"id": proposal})
    intent = reviewed["intent"]
    digest = reviewed["intentDigest"]
    reconstructed = hashlib.sha256(
        json.dumps(intent, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    insist(
        reconstructed == digest
        and intent["recipient"] == "example.local-ledger"
        and intent["resource"] == receipt
        and (intent["amount"], intent["currency"]) == ("0", "USD"),
        "review did not bind actual recipient, resource, amount and digest",
    )
    args = {"id": proposal, "intentDigest": digest}
    refused("denied", lambda: b.call("example.compensation.review", {"id": proposal}))
    refused("denied", lambda: a.call("example.compensation.approve", args))
    refused(
        "conflict",
        lambda: d.admin.call("example.compensation.approve", {**args, "intentDigest": "0" * 64}),
    )
    panel = a.call(
        "surface.open",
        {"surfaceId": "example.status.panel", "scope": {"kind": "tenant", "id": "alice"}},
    )
    refused(
        "denied",
        lambda: a.call(
            "surface.event",
            {
                "instanceId": panel["instanceId"],
                "generation": panel["generation"],
                "action": "example.compensation.approve",
                "values": args,
            },
        ),
    )
    refused("denied", lambda: a.call("example.compensation.commit", args))
    d.admin.call("example.compensation.approve", args)
    refused(
        "conflict",
        lambda: a.call("example.compensation.commit", {**args, "intentDigest": "0" * 64}),
    )
    final = a.call("example.compensation.commit", args)
    insist(
        final["finished"]
        and a.call("example.receipt.inspect", {"operationId": receipt})["state"] == "applied",
        "confirmed intent not executed independently",
    )
    return {
        "recipient": intent["recipient"],
        "resourceId": receipt,
        "operation": intent["operation"],
        "amount": intent["amount"],
        "currency": intent["currency"],
        "intentDigest": digest,
        "widgetApproval": "denied",
        "altered": "conflict",
        "committed": True,
    }


def transport_bounds(d):
    import socket
    from datetime import datetime

    d.connection_ms = 550
    d.relay_delay_ms = 260
    d.restart()
    a = d.a
    msg = {
        "messageId": "long",
        "contextId": secrets.token_hex(6),
        "parts": [{"type": "text", "text": "Read demo"}],
    }
    begin = time.time()
    reply = a.call("example.agent.relay", {"message": msg, "depth": 1}, seconds=45)
    forwarded = datetime.fromisoformat(
        reply["forwardedDeadline"].replace("Z", "+00:00")
    ).timestamp()
    insist(
        forwarded < begin + 5.12 and forwarded > begin + 4 and time.time() - begin >= 0.25,
        "relay restarted or extended its effective deadline",
    )
    refused(
        "deadline",
        lambda: a.call(
            "example.agent.relay",
            {"message": {**msg, "messageId": "short"}, "depth": 1},
            seconds=0.12,
        ),
    )
    occupied = {}
    for phase in ("headers", "body"):
        sock = socket.create_connection(a.address, timeout=1)
        try:
            if phase == "headers":
                sock.sendall(b"POST /ocs HTTP/1.1\r\nHost: localhost\r\nX-Drip: ")
            else:
                prefix = (
                    "POST /ocs HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer "
                    + a.key
                    + "\r\nContent-Length: 4096\r\n\r\n{"
                )
                sock.sendall(prefix.encode())
            start = time.monotonic()
            closed = False
            while time.monotonic() - start < 2:
                try:
                    sock.sendall(b"x" if phase == "headers" else b" ")
                except OSError:
                    closed = True
                    break
                if select.select([sock], [], [], 0.03)[0]:
                    try:
                        if not sock.recv(4096):
                            closed = True
                            break
                    except OSError:
                        closed = True
                        break
            elapsed = time.monotonic() - start
            insist(
                closed and elapsed < 1.5,
                "continuously active " + phase + " connection retained its slot",
            )
            occupied[phase] = round(elapsed * 1000)
        finally:
            sock.close()
    insist(
        a.call("example.status.read", {"resourceId": "demo"})["state"] == "ready",
        "slots not recovered",
    )
    return {
        "configuredSocketLifetimeMs": 550,
        "continuousDripUntilClosedMs": occupied,
        "relayDelayMs": 260,
        "parentRequestedMs": 45000,
        "effectiveForwardedMs": round((forwarded - begin) * 1000),
        "shortParentMs": 120,
        "shortResult": "deadline",
    }


def historical_dialog(d):
    import zipfile

    revision = "6f6e22842347806f2963ef1984d9ea592fdddaf0"
    with tempfile.TemporaryDirectory(prefix="ocs-historical-dialog-") as temp:
        package = Path(temp) / "published"
        archive = Path(temp) / "caller.zip"
        for candidate in (SUBJECT, ORACLE):
            git = ["git", "--no-replace-objects", "-C", str(candidate)]
            test = subprocess.run(
                [*git, "cat-file", "-t", revision], capture_output=True, text=True
            )
            if test.returncode == 0 and test.stdout.strip() == "commit":
                break
        else:
            raise ValueError("accepted historical caller commit unavailable")
        subprocess.run(
            [
                *git,
                "archive",
                "--format=zip",
                "-o",
                str(archive),
                revision,
                "reference/host.py",
                "reference/admission.py",
                "reference/contracts.py",
                "schemas",
                "spec/profiles/operations.json",
            ],
            check=True,
        )
        with zipfile.ZipFile(archive) as z:
            z.extractall(package)
        child = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                str(ORACLE / "assurance/interaction/historical.py"),
                "--caller-root",
                str(package),
                "--executor",
                str(SUBJECT / "examples/dialog/executor.py"),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if child.returncode:
            raise ValueError("historical host driver failed: " + child.stderr[-500:])
        results = json.loads(child.stdout)
        old_method = next(
            x
            for x in json.loads((package / "spec/profiles/operations.json").read_bytes())[
                "operations"
            ]
            if x["method"] == "agent.exchange"
        )
        for sample in results.pop("observations"):
            if "refused" in sample:
                d.journal.note(
                    "agent.exchange",
                    sample["input"],
                    results["manifestDigest"],
                    "refusal",
                    code=sample["refused"],
                )
            else:
                d.journal.note(
                    "agent.exchange",
                    sample["input"],
                    results["manifestDigest"],
                    "result",
                    sample["output"],
                )
        return {
            **results,
            "historicalRevision": revision,
            "direction": "published host / working native agent",
            "publishedMethod": old_method,
            "acceptedConfirmations": 1,
            "foreignResource": "denied",
        }
