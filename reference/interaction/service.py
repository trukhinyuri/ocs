"""Local opt-in profile reference, with clock, identity and durable state supplied by the host."""

import base64
import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import kernel
from contracts import now, read_json, utc_at, validate, validate_with
from jsonschema import ValidationError
from privacy import PrivateObservations
from state import Refusal, Store

if Path(kernel.__file__).resolve() != HERE / "kernel.py":
    raise RuntimeError("unexpected source decision module")

FRAME = 16384
CREDIT = 8
MAX_STREAMS = 4
MAX_STREAM_IDS = 256
MAX_ARTIFACT_PAGE = 8192
PREVIEW = b"<p>Scoped resource details</p>"
PREVIEW_ORIGIN = "https://preview.example.invalid"
PREVIEW_DIGEST = hashlib.sha256(PREVIEW).hexdigest()
REGISTRY = {
    row["method"]: row
    for row in read_json((ROOT / "spec/profiles/operations.json").read_bytes())["operations"]
}
MANIFEST_BYTES = (HERE / "ocs.json").read_bytes()
MANIFEST = read_json(MANIFEST_BYTES)
PIN = hashlib.sha256(MANIFEST_BYTES).hexdigest()
SCOPE = {"kind": "tenant", "id": "alice"}


def encode(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def validate_uri(uri, value, error_kind):
    try:
        validate_with({"$ref": uri}, value)
    except ValidationError as exc:
        raise Refusal(error_kind, "Value differs from the registered contract.") from exc


def deadline(meta):
    t = datetime.fromisoformat(meta["deadline"].replace("Z", "+00:00")).timestamp()
    delay = min(t - time.time(), 5)
    if delay <= 0:
        raise Refusal("deadline", "Request expired.")
    return time.monotonic() + delay


@dataclass(frozen=True)
class Principal:
    owner: str
    admin: bool = False
    relay: bool = False
    callback: bool = False
    purpose: str = "interactive"


@dataclass
class Transfer:
    request: str
    owner: str
    generation: int
    data: tuple
    expires: float
    state: tuple
    condition: threading.Condition = field(default_factory=threading.Condition)
    reason: str | None = None

    def step(self, action, amount=0, owned=True):
        self.state = kernel.stream_step(action, owned, *self.state, amount, CREDIT)

    def control(self, method, add=0):
        with self.condition:
            if self.state[4]:
                return
            if method == "ocs.credit":
                before = self.state
                self.step(0, add)
                if before == self.state:
                    raise Refusal("busy", "Outstanding credit exceeds the declared capacity.")
            else:
                self.reason = "cancelled"
                self.step(2)
            self.condition.notify_all()

    def frames(self):
        while True:
            with self.condition:
                credit, sent, _, remaining, finals = self.state
                if not finals and time.monotonic() >= self.expires:
                    self.reason = "deadline"
                    self.step(2)
                if not self.state[4] and remaining == 0:
                    self.step(2)
                if self.state[4]:
                    if self.reason:
                        result = {"error": Refusal(self.reason, "Stream closed.").error()}
                    else:
                        result = {"result": {"data": {"chunks": sent}}}
                    event, envelope = "response", {"jsonrpc": "2.0", "id": self.request, **result}
                elif credit:
                    self.step(1)
                    params = {
                        "requestId": self.request,
                        "seq": self.state[1],
                        "kind": "text",
                        "data": self.data[sent],
                    }
                    validate("profile-wire", params, "chunkParams")
                    event, envelope = (
                        "chunk",
                        {"jsonrpc": "2.0", "method": "ocs.chunk", "params": params},
                    )
                else:
                    self.condition.wait(max(0, self.expires - time.monotonic()))
                    continue
            yield event, envelope
            if event == "response":
                break


class ChunkReceiver:
    """Finite retained sequence domain of the demo stream."""

    def __init__(self, request, generation):
        self.request, self.generation = request, generation
        self.received = []

    def ingest(self, generation, params):
        if not kernel.admit(
            True, True, True, True, params["requestId"] == self.request, self.generation, generation
        ):
            raise Refusal("denied", "Retired or foreign stream.")
        seq = params["seq"]
        stamp = encode(params)
        if 1 <= seq <= len(self.received):
            if self.received[seq - 1] != stamp:
                raise Refusal("conflict", "Conflicting stream duplicate.")
            return False
        if seq != len(self.received) + 1:
            raise Refusal("conflict", "Stream sequence gap.")
        if len(self.received) >= CREDIT:
            raise Refusal("busy", "Retained sequence budget exhausted.")
        self.received.append(stamp)
        return True


class Host:
    def __init__(self, db, commit_delay_ms=0):
        validate("manifest", MANIFEST)
        self.inspected = True
        self.admitted = MANIFEST["id"] == "org.example.interaction" and MANIFEST["runtime"] == {
            "binding": "https"
        }
        self.bound = any(
            x["id"] == "example.status.read" and x["version"] == "1.0.0" and x["effect"] == "read"
            for x in MANIFEST["exports"]
        )
        if not (self.admitted and self.bound):
            raise ValueError("Sealed authority, runtime or required read binding unavailable.")
        if not 0 <= commit_delay_ms <= 1000:
            raise ValueError("fixture delivery delay outside bound")
        self.commit_delay = commit_delay_ms / 1000
        self.privacy = PrivateObservations(utc_at)
        self.owner_epochs = {}
        self.owner_enabled = {}
        self.workers = {}
        self.private_revision = 1
        self.store = Store(db, encode, read_json, utc_at)
        self.lock = threading.RLock()
        self.generation = 1
        self.active = kernel.admit(
            self.inspected, self.admitted, self.bound, True, True, self.generation, self.generation
        )
        self.peer_online = True
        self.secret = secrets.token_bytes(32)
        self.streams = {}
        self.stream_ids = set()
        self.panels = {}
        self.artifacts = {}
        self.focus = {}
        self.fact = secrets.token_hex(8)
        self.dialogues = {}
        self.cancelled = set()
        self.exports = {op["id"]: op for op in MANIFEST["exports"]}

    def session(self, principal):
        mac = hmac.new(
            self.secret,
            encode(
                [
                    principal.owner,
                    principal.admin,
                    principal.relay,
                    principal.callback,
                    principal.purpose,
                    self.generation,
                    self.owner_epochs.get(principal.owner, 0),
                ]
            ),
            "sha256",
        ).hexdigest()
        return f"{self.generation}.{self.owner_epochs.get(principal.owner, 0)}.{mac}"

    def allow(self, principal, session):
        received, sep, rest = session.partition(".")
        if not sep or not received.isascii() or not received.isdigit() or len(received) > 16:
            raise Refusal("denied", "Invalid authenticated instance generation.")
        if not kernel.admit(
            self.inspected,
            self.admitted,
            self.bound,
            self.active and self.owner_enabled.get(principal.owner, True),
            hmac.compare_digest(self.session(principal), session),
            self.generation,
            int(received),
        ):
            raise Refusal("denied", "Inactive instance or wrong authenticated session.")

    def describe(self, params):
        validate("wire", params, "describeParams")
        deadline(params["meta"])
        if "0.1" not in params["protocols"] or not set(params["requiredFeatures"]) <= set(
            MANIFEST["features"]
        ):
            raise Refusal("incompatible", "Required version or feature unavailable.")
        return {
            "protocol": "0.1",
            "packageId": MANIFEST["id"],
            "packageVersion": MANIFEST["version"],
            "manifestDigest": PIN,
            "features": MANIFEST["features"],
            "maxFrameBytes": FRAME,
        }

    def call_meta(self, p):
        if p["meta"]["manifestDigest"] != PIN:
            raise Refusal("pin", "Descriptor changed.")
        return deadline(p["meta"])

    def lifecycle(self, principal, op):
        if not principal.admin:
            raise Refusal("denied", "A host administration grant is required.")
        with self.lock:
            if op == "example.instance.retire" and self.active:
                self.active = False
                self.generation += 1
                for transfer in self.streams.values():
                    transfer.control("ocs.cancel")
                self.panels.clear()
                self.artifacts.clear()
                self.stream_ids.clear()
                self.store.retire_ephemeral()
                self.focus.clear()
                for worker in self.workers.values():
                    worker["stop"].set()
                self.dialogues.clear()
                self.cancelled.clear()
            elif op == "example.instance.activate" and not self.active:
                self.active = True
            return {"active": self.active, "generation": self.generation}

    def open_stream(self, principal, session, rid, params):
        validate_uri(REGISTRY["stream.open"]["input"], params, "params")
        expires = self.call_meta(params)
        with self.lock:
            self.allow(principal, session)
            op = params["operation"]
            if (
                op not in ("example.parts.read", "example.parts.committed")
                or params["version"] != "1.0.0"
            ):
                raise Refusal("denied", "No authorized stream export.")
            validate_with(self.exports[op]["inputSchema"], params["input"])
            if params["input"]["resourceId"] != "demo":
                raise Refusal("denied", "Stream resource outside grant.")
            key = (principal.owner, rid)
            if key in self.stream_ids:
                raise Refusal("conflict", "Stream ID already used in this generation.")
            if (
                len(self.streams) >= MAX_STREAMS
                or len(self.stream_ids) >= MAX_STREAM_IDS
                or params["credit"] > CREDIT
            ):
                raise Refusal("busy", "Stream or credit capacity exhausted.")
            data = ("alpha", "β", "end")
            if op == "example.parts.committed":
                oid = params.get("operationId")
                if not oid or oid != params["input"].get("operationId"):
                    raise Refusal("denied", "Matching committed intent required.")
                state, record = self.store.receipt(principal.owner, oid, PIN)
                if state != "applied" or record["target"] != params["input"]:
                    raise Refusal("denied", "No matching applied output.")
                data = tuple(record["chunks"])
            if not data or len(data) > CREDIT or any(len(encode(v)) > 2048 for v in data):
                raise Refusal("busy", "Output too large.")
            t = Transfer(
                rid,
                principal.owner,
                self.generation,
                data,
                expires,
                (params["credit"], 0, params["credit"], len(data), 0),
            )
            self.stream_ids.add(key)
            self.streams[key] = t
            return t

    def close_stream(self, t):
        with self.lock:
            key = (t.owner, t.request)
            if self.streams.get(key) is t:
                del self.streams[key]

    def control(self, principal, session, method, inp):
        validate_uri(REGISTRY[method]["input"], inp, "params")
        with self.lock:
            self.allow(principal, session)
            key = (principal.owner, inp["requestId"])
            t = self.streams.get(key)
            if not t:
                if key in self.stream_ids:
                    return
                raise Refusal("denied", "Unknown stream for this owner.")
            if t.generation != self.generation:
                raise Refusal("denied", "Retired stream.")
            t.control(method, inp.get("add", 0))

    def rpc(self, principal, session, method, params, rid):
        if method == "tool.call":
            validate("wire", params, "callParams")
            expires = self.call_meta(params)
            op = params["operation"]
            item = self.exports.get(op)
            if not item:
                raise Refusal("method", "Unexported operation.")
            if params["version"] != item["version"]:
                raise Refusal("incompatible", "Unsupported contract version.")
            try:
                validate_with(item["inputSchema"], params["input"])
            except ValidationError as exc:
                raise Refusal("input", "Invalid operation input.") from exc
            if principal.relay and op != "agent.exchange":
                raise Refusal(
                    "denied", "Downstream delegation is restricted to the agent read binding."
                )
            if op == "example.exchange.callback":
                with self.lock:
                    self.allow(principal, session)
                    expected = self.session(Principal(principal.owner, callback=True))
                if not kernel.callback_safe(True, params["input"]["channel"] == "serial", True):
                    raise Refusal(
                        "conflict",
                        "A serial channel cannot wait for its own callback; select the admitted return channel.",
                    )
                data = self.callback(
                    principal.owner,
                    expected,
                    rid,
                    utc_at(time.time() + max(0, expires - time.monotonic())),
                )
            elif op == "example.agent.parallel":
                with self.lock:
                    self.allow(principal, session)
                    if not self.peer_online:
                        raise Refusal("unavailable", "The selected peer is offline.")
                    expected = self.session(Principal(principal.owner, relay=True))
                parts = params["input"]["children"]
                remaining = dict(params["input"]["budget"])
                planned = []
                for order, part in enumerate(parts, 1):
                    share = part["reservation"]
                    if (
                        min(share["turns"], share["bytes"], share["fanOut"], share["concurrency"])
                        < 1
                    ):
                        raise Refusal("busy", "A child needs a positive work and transport share.")
                    if any(v > remaining[k] for k, v in share.items()):
                        raise Refusal("busy", "Parent allocation exhausted before dispatch.")
                    remaining = {k: kernel.reserve(v, share[k]) for k, v in remaining.items()}
                    msg = dict(part["message"])
                    if "budget" in msg:
                        raise Refusal("input", "The child budget comes from the reserved share.")
                    msg["budget"] = {
                        "remainingTurns": share["turns"],
                        "remainingBytes": share["bytes"],
                        "maxConcurrency": share["concurrency"],
                        "maxFanOut": kernel.reserve(share["fanOut"], 1),
                        "remainingCost": {"amount": str(share["costUnits"]), "currency": "USD"},
                    }
                    planned.append(msg)
                deadline_at = utc_at(time.time() + max(0, expires - time.monotonic()))
                with ThreadPoolExecutor(max_workers=len(planned)) as pool:
                    futures = [
                        pool.submit(self.forward, principal.owner, expected, msg, deadline_at)
                        for msg in planned
                    ]
                    replies = [f.result() for f in futures]
                data = {"remaining": remaining, "replies": [r["message"] for r in replies]}
            elif op == "example.agent.relay":
                with self.lock:
                    self.allow(principal, session)
                    if not self.peer_online:
                        raise Refusal("unavailable", "Selected peer is offline.")
                    expected = self.session(Principal(principal.owner, relay=True))
                if params["input"]["depth"] < 1:
                    raise Refusal("busy", "No remaining delegation budget.")
                msg = dict(params["input"]["message"])
                budget = msg.get("budget", {})
                if budget.get("maxFanOut", 1) < 1 or budget.get("maxConcurrency", 1) < 1:
                    raise Refusal("busy", "Insufficient fan-out or concurrency budget.")
                if "maxFanOut" in budget:
                    msg["budget"] = {**budget, "maxFanOut": kernel.reserve(budget["maxFanOut"], 1)}
                data = self.forward(
                    principal.owner,
                    expected,
                    msg,
                    utc_at(time.time() + max(0, expires - time.monotonic())),
                )
            else:
                with self.lock:
                    if op == "example.grant.set":
                        if not principal.admin or params["input"]["owner"] != principal.owner:
                            raise Refusal(
                                "denied", "Only the trusted owner can change this tenant grant."
                            )
                        enabled = params["input"]["enabled"]
                        owner = principal.owner
                        self.owner_enabled[owner] = enabled
                        self.owner_epochs[owner] = self.owner_epochs.get(owner, 0) + 1
                        if not enabled:
                            for t in self.streams.values():
                                if t.owner == owner:
                                    t.control("ocs.cancel")
                            for panel, entry in list(self.panels.items()):
                                if entry[0] == owner:
                                    self.store.unsubscribe(owner, entry[2])
                                    del self.panels[panel]
                            for handle in list(self.artifacts):
                                if handle[0] == owner:
                                    del self.artifacts[handle]
                            self.focus.pop(owner, None)
                            for worker in self.workers.values():
                                if worker["tenant"] == owner:
                                    worker["stop"].set()
                        data = {
                            "owner": owner,
                            "enabled": enabled,
                            "epoch": self.owner_epochs[owner],
                            "maximumStaleAdmissions": 0,
                        }
                    elif op in ("example.instance.retire", "example.instance.activate"):
                        # Host administration has a separate control grant across generations.
                        data = self.lifecycle(principal, op)
                    else:
                        self.allow(principal, session)
                        data = self.export(principal, op, params["input"], rid, expires)
            try:
                validate_with(item["outputSchema"], data)
            except ValidationError as exc:
                raise Refusal("output", "Invalid operation output.") from exc
            result = {"data": data}
        elif method in ("job.status", "job.cancel", "job.continue"):
            validate_uri(REGISTRY[method]["input"], params, "params")
            expires = self.call_meta(params)
            with self.lock:
                self.allow(principal, session)
            # A concurrent continuation is serialized in the state owner's transaction.
            result = self.store.job(principal.owner, method, params)
            validate_uri(REGISTRY[method]["output"], result, "output")
            if method in ("job.continue", "job.cancel") and self.commit_delay:
                time.sleep(self.commit_delay)
            if method in ("job.continue", "job.cancel") and time.monotonic() >= expires:
                raise Refusal(
                    "deadline",
                    f"Job revision {result['revision']} is {result['state']}. Read the scoped job and effect receipt.",
                    result.get("operationId", result["jobId"]),
                )
        else:
            raise Refusal("method", "Unknown control.")
        if time.monotonic() >= expires:
            raise Refusal("deadline", "Deadline elapsed before delivery.")
        return result

    def artifact(self, principal, inp, rid):
        handle = inp["artifact"]
        entry = self.artifacts.get((principal.owner, handle["id"]))
        if not entry:
            raise Refusal("denied", "No active artifact grant.")
        saved, data, expiry, purpose = entry
        if principal.purpose != purpose:
            raise Refusal("denied", "Artifact grant was issued for a different purpose.")
        if expiry <= time.time() or saved["scope"] != handle["scope"]:
            raise Refusal("denied", "Expired or foreign artifact.")
        if saved != handle:
            raise Refusal("pin", "Changed artifact revision or metadata.")
        offset = inp["offset"]
        if offset > len(data):
            raise Refusal("input", "Offset past end.")
        empty = {"artifact": saved, "offset": offset, "data": "", "eof": False}
        overhead = len(encode({"jsonrpc": "2.0", "id": rid, "result": {"data": empty}}))
        capacity = min(MAX_ARTIFACT_PAGE, ((FRAME - overhead) // 4) * 3)
        if capacity < 1:
            raise Refusal("busy", "Frame too small.")
        count = kernel.page_size(len(data), offset, min(inp["maxBytes"], capacity))
        return {
            **empty,
            "data": base64.b64encode(data[offset : offset + count]).decode(),
            "eof": offset + count == len(data),
        }

    def export(self, principal, op, inp, rid, expires=None):
        owner = principal.owner
        if op.startswith("example.privacy."):
            return self.privacy.operate(
                owner, self.owner_epochs.get(owner, 0), op.rsplit(".", 1)[1], inp
            )
        if op == "example.callback.observe":
            if not principal.callback:
                raise Refusal("denied", "Separate callback channel grant required.")
            return {"requestId": rid, "direction": "return", "resourceId": "demo", "owner": owner}
        if op == "example.agent.trace":
            rec = self.dialogues.get((owner, inp["contextId"]), {}).get(inp["messageId"])
            if not rec:
                raise Refusal("denied", "No scoped correlation record.")
            return rec[2]
        if op.startswith("example.work-observer."):
            return self.observer(principal, op.rsplit(".", 1)[1], inp)
        if op == "example.surface.inspect":
            candidate = inp["surface"]
            try:
                validate_with(candidate["view"]["dataSchema"], candidate["view"]["values"])
            except (ValidationError, KeyError):
                raise Refusal("input", "Invalid declarative view or values.")
            if not self.eligible(candidate, inp["action"], inp["version"], True):
                raise Refusal(
                    "denied", "The requested versioned action is outside the intersection."
                )
            return {"eligible": True}
        if op == "example.peer.replace":
            if not principal.admin:
                raise Refusal("denied", "Only the host can replace a binding.")
            self.private_revision = inp["revision"]
            return {"revision": self.private_revision}
        if op == "example.peer.availability":
            if not principal.admin:
                raise Refusal("denied", "Host owns the peer route.")
            self.peer_online = inp["online"]
            return {"online": self.peer_online}
        if op == "example.stream.inspect":
            t = self.streams.get((owner, inp["requestId"]))
            if not t:
                raise Refusal("denied", "No active stream for this tenant.")
            with t.condition:
                return dict(
                    zip(("credit", "sent", "granted", "remaining", "finals"), t.state, strict=True)
                )
        if op == "example.ui.status":
            return self.ui_state()
        if op == "example.web.admit":
            if (
                inp["origin"] != PREVIEW_ORIGIN
                or inp["eventOrigin"] != PREVIEW_ORIGIN
                or inp["digest"] != PREVIEW_DIGEST
            ):
                raise Refusal("denied", "Configured origin and integrity are required.")
            panel = self.panels.get(inp["instanceId"])
            if not panel or panel[0] != owner or panel[1] != inp["generation"]:
                raise Refusal("denied", "Web event identifies an unadmitted surface instance.")
            if (
                inp["navigation"] != "same-origin"
                or inp["egress"] != "none"
                or not inp["sandboxRequested"]
            ):
                raise Refusal(
                    "denied",
                    "Cross-origin navigation, network privileges or shared host context refused.",
                )
            event = inp["event"]
            if event["action"] != "example.status.read" or event["values"] != {
                "resourceId": "demo"
            }:
                raise Refusal(
                    "denied", "Web event is outside the registered action schema or grant."
                )
            if not kernel.admit(
                True, True, True, self.active, True, self.generation, inp["generation"]
            ):
                raise Refusal("denied", "Retired web context.")
            return {
                "representation": "terminal",
                "action": "example.status.read",
                "reason": "Isolated renderer unavailable",
            }
        if op == "agent.exchange":
            return self.agent(principal, inp)
        if op == "example.agent.cancel":
            key = (owner, inp["contextId"])
            if key not in self.dialogues:
                raise Refusal("denied", "Unknown scoped conversation.")
            if len(self.cancelled) >= 128:
                raise Refusal("busy", "Closed-context retention capacity exhausted.")
            self.cancelled.add(key)
            self.dialogues.pop(key)
            return {"accepted": True}
        if op.startswith("example.compensation."):
            return self.store.compensation(principal, op.rsplit(".", 1)[1], inp, PIN)
        if op == "example.status.read":
            if inp["resourceId"] != "demo":
                raise Refusal("denied", "Out-of-scope resource.")
            return {"resourceId": "demo", "state": "ready"}
        if op == "example.delegate.read":
            return self.delegate(principal, inp, rid, expires)
        if op == "example.instance.inspect":
            return {
                "active": self.active,
                "generation": self.generation,
                "streams": len(self.streams),
                "panels": len(self.panels),
                "receipts": self.store.receipt_count(owner),
                "focus": self.focus.get(owner, "workspace"),
            }
        if op == "example.receipt.fixture":
            if not principal.admin:
                raise Refusal(
                    "denied", "A separate synthetic effect authority issues this receipt."
                )
            # Synthetic sealed authority. This export records a local test receipt and never calls a billing service.
            oid = secrets.token_hex(12)
            target = {"resourceId": "demo", "operationId": oid}
            self.store.seed_receipt(
                owner,
                oid,
                PIN,
                {"target": target, "chunks": ["applied", "receipt"]},
                inp["outcome"],
            )
            return {"operationId": oid}
        if op == "example.receipt.inspect":
            state, rec = self.store.receipt(owner, inp["operationId"], PIN)
            return {"state": state, "target": rec["target"]}
        if op == "example.artifact.locate":
            self.artifacts = {k: v for k, v in self.artifacts.items() if v[2] > time.time()}
            if len(self.artifacts) >= 32:
                raise Refusal("busy", "Artifact capacity exhausted.")
            id_ = secrets.token_hex(12)
            data = ("data é ☀ " * inp["repeat"]).encode()
            expiry = (int(time.time() * 1000) + inp["ttlMs"]) / 1000
            handle = {
                "id": id_,
                "mediaType": "text/plain",
                "revision": "1",
                "digest": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "expiresAt": utc_at(expiry),
                "scope": {"kind": "tenant", "id": owner},
            }
            self.artifacts[(owner, id_)] = (handle, data, expiry, principal.purpose)
            return handle
        if op == "artifact.read":
            return self.artifact(principal, inp, rid)
        if op == "example.artifact.release":
            prior = self.artifacts.get((owner, inp["id"]))
            if prior and prior[3] != principal.purpose:
                raise Refusal("denied", "Different handle purpose.")
            return {"accepted": self.artifacts.pop((owner, inp["id"]), None) is not None}
        if op == "example.event.publish":
            return self.store.publish(owner, inp)
        if op == "events.subscribe":
            return self.store.subscribe(owner, inp)
        if op in ("events.ack", "events.resume"):
            return self.store.event_position(owner, inp, op == "events.ack")
        if op == "example.subscription.close":
            return {"accepted": self.store.unsubscribe(owner, inp["subscriptionId"])}
        if op == "example.job.begin":
            return self.store.begin_job(owner, inp["draft"], inp.get("operationId"))
        if op == "example.job.inspect":
            return self.store.job(owner, op, inp)
        if op == "example.store.backup":
            if not principal.admin:
                raise Refusal("denied", "Host backup grant required.")
            self.store.backup(self.store.path + ".backup")
            return {"accepted": True}
        if op in ("surface.open", "surface.event", "example.surface.close"):
            return self.surface(principal, op, inp)
        if op == "example.hook.observe":
            return self.hook(principal, inp)
        raise Refusal("method", "Operation available only through its stream binding.")

    def delegate(self, principal, inp, rid, expires):
        # These directional bindings are host configuration. Input cannot supply a destination or a grant.
        routes = {
            "front": "relay",
            "relay": "authority",
            "cycle-a": "cycle-b",
            "cycle-b": "cycle-a",
        }
        route = "cycle-a" if inp["cycle"] else "front"
        depth = inp["depth"]
        permitted = True
        seen = set()
        if inp["operation"] != "example.status.read" or inp["resourceId"] != "demo":
            raise Refusal("denied", "Named binding admits only the selected resource read.")
        if not self.peer_online or not inp["reachable"]:
            raise Refusal("unavailable", "The selected recipient is unavailable.")
        trace = []
        started = []
        while route in routes:
            started.append(time.perf_counter_ns())
            if not depth or route in seen:
                raise Refusal("busy", "Causal depth or cycle limit.")
            dest = routes[route]
            permitted = kernel.grant(
                permitted,
                (route, dest) in routes.items(),
                inp["operation"] == "example.status.read",
                inp["resourceId"] == "demo",
            )
            if not permitted:
                raise Refusal("denied", "Binding intersection refused.")
            trace.append(
                {
                    "callId": f"{rid}.{len(trace) + 1}",
                    "parentCallId": trace[-1]["callId"] if trace else rid,
                    "retryOwner": rid,
                    "generation": self.generation,
                    "region": "loopback",
                    "manifestDigest": PIN,
                    "actualRevision": MANIFEST["version"],
                    "decision": "admitted",
                    "remainingMs": max(0, int((expires - time.monotonic()) * 1000)),
                    "caller": route,
                    "receiver": dest,
                    "parent": trace[-1]["receiver"] if trace else principal.owner,
                }
            )
            seen.add(route)
            depth = kernel.reserve(depth, 1)
            route = dest
        if self.private_revision == 1:
            result = self.export(
                principal, "example.status.read", {"resourceId": inp["resourceId"]}, "internal"
            )
        else:
            # An internal service uses a Boolean readiness field.
            native = {"resource": inp["resourceId"], "available": inp["resourceId"] == "demo"}
            if not native["available"]:
                raise Refusal("denied", "Unsupported resource.")
            result = {
                "resourceId": native["resource"],
                "state": "ready" if native["available"] else "degraded",
            }
        finished = time.perf_counter_ns()
        for row, stamp_ns in zip(trace, started, strict=True):
            row["durationNs"] = finished - stamp_ns
        return {"data": result, "trace": trace, "remainingDepth": depth}

    def agent(self, principal, msg):
        key = (principal.owner, msg.get("contextId", "default"))
        if key in self.cancelled:
            raise Refusal("cancelled", "The owned conversation is closed.")
        if key not in self.dialogues and len(self.dialogues) >= 16:
            raise Refusal("busy", "Context limit.")
        memory = self.dialogues.setdefault(key, {})
        stamp = encode(msg)
        old = memory.get(msg["messageId"])
        if old is not None:
            if old[0] != stamp:
                raise Refusal("conflict", "A message ID was reused with different content.")
            return old[1]
        if len(memory) >= 16:
            raise Refusal("busy", "Retained turn budget exhausted.")
        if (
            len(msg["parts"]) != 1
            or msg["parts"][0]["type"] != "text"
            or "text/plain" not in msg.get("accept", ["text/plain"])
        ):
            raise Refusal("incompatible", "This participant requires a text part and a text reply.")
        budget = msg.get("budget", {})
        if budget.get("remainingTurns", 1) < 1 or budget.get("maxConcurrency", 1) < 1:
            raise Refusal("busy", "Turn budget exhausted.")
        if "remainingCost" in budget and budget["remainingCost"]["currency"] != "USD":
            raise Refusal("incompatible", "This fixture accounts zero cost in USD.")
        current = msg["parts"][0]["text"]
        if current == "Read":
            kind, answer = "clarification", "Which resource?"
        elif current == "Read demo":
            kind, answer = "answer", self.fact
        elif current == "Partial demo":
            kind, answer = "partial", self.fact[:4]
        elif current == "Reset demo":
            kind, answer = "authorization-required", "Host authorization needed."
        elif current == "Confirm " + self.fact:
            kind, answer = "answer", "confirmed"
        else:
            raise Refusal("denied", "No selected read binding for this request.")
        # Include every forwarded field and reply content in this profile's byte budget.
        count = len(stamp) + len(answer.encode())
        if budget.get("remainingBytes", FRAME) < count:
            raise Refusal("busy", "Message byte budget exhausted.")
        reply = {
            "messageId": "reply-" + msg["messageId"],
            "replyTo": msg["messageId"],
            "kind": kind,
            "parts": [{"type": "text", "text": answer}],
            "senderLabel": "fixture-fact-authority",
        }
        for key_name in ("contextId", "taskId"):
            if key_name in msg:
                reply[key_name] = msg[key_name]
        if budget:
            reply["budget"] = dict(budget)
            if "remainingTurns" in budget:
                reply["budget"]["remainingTurns"] = kernel.reserve(budget["remainingTurns"], 1)
            if "remainingBytes" in budget:
                reply["budget"]["remainingBytes"] = kernel.reserve(budget["remainingBytes"], count)
        result = {"kind": "message", "message": reply}
        memory[msg["messageId"]] = (
            stamp,
            result,
            {
                "authenticatedOrigin": principal.owner,
                "messageId": msg["messageId"],
                "replyId": reply["messageId"],
                "author": reply["senderLabel"],
                "contextId": msg.get("contextId", "default"),
                "taskId": msg.get("taskId"),
            },
        )
        return result

    def observer(self, principal, action, inp):
        owner = principal.owner
        if action == "start":
            if inp["operation"] != "example.status.read":
                raise Refusal("denied", "Background grant is read-only.")
            if len(self.workers) >= 32:
                completed = next((wid for wid, w in self.workers.items() if w["done"]), None)
                if completed is not None:
                    del self.workers[completed]
            if len(self.workers) >= 32:
                raise Refusal("busy", "Background work capacity exhausted.")
            wid = secrets.token_hex(8)
            identity = "observer/" + owner + "/" + wid
            wk = {
                "tenant": owner,
                "identity": identity,
                "epoch": self.generation,
                "ownerEpoch": self.owner_epochs.get(owner, 0),
                "steps": 0,
                "budget": inp["budget"],
                "stop": threading.Event(),
                "done": False,
            }
            self.workers[wid] = wk

            def run():
                role = Principal(owner, purpose="background-read")
                try:
                    while not wk["stop"].wait(0.03):
                        with self.lock:
                            if (
                                not self.active
                                or self.generation != wk["epoch"]
                                or not self.owner_enabled.get(owner, True)
                                or self.owner_epochs.get(owner, 0) != wk["ownerEpoch"]
                                or wk["steps"] >= wk["budget"]
                            ):
                                break
                            result = self.export(
                                role, "example.status.read", {"resourceId": "demo"}, identity
                            )
                            if result["state"] != "ready":
                                break
                            wk["steps"] += 1
                finally:
                    with self.lock:
                        wk["done"] = True

            threading.Thread(target=run, name="ocs-" + identity, daemon=True).start()
        else:
            wid = inp["id"]
            wk = self.workers.get(wid)
            if not wk or wk["tenant"] != owner:
                raise Refusal("denied", "No current owner work grant.")
            if action == "stop":
                wk["stop"].set()
        return {
            "id": wid,
            "identity": wk["identity"],
            "steps": wk["steps"],
            "budget": wk["budget"],
            "stopped": wk["done"],
            "epoch": wk["epoch"],
        }

    def eligible(self, surface, action, version, valid):
        export = self.exports.get(action)
        return kernel.surface_eligible(
            valid,
            bool(export and export["version"] == version),
            action in surface["operations"],
            any(
                a["operation"] == action and a["version"] == version
                for a in surface["view"]["actions"]
            ),
            action == "example.status.read",
        )

    def hook(self, principal, inp):
        # A fresh copy is supplied to every observer. Transform identifiers are admitted by the host.
        if inp["depth"] > 2:
            raise Refusal("busy", "Hook causal budget exhausted.")
        if inp["operation"] != "example.status.read":
            raise Refusal("denied", "Observer has a read grant.")
        original = inp["value"]
        if inp["transform"]:
            observed = original.strip()
            observed = observed.upper()
        else:
            observed = original
        if not observed or len(observed) > 80:
            raise Refusal("input", "Invalid transformed value.")
        return {
            "original": original,
            "observed": observed,
            "owner": principal.owner,
            "sideEffects": 0,
        }

    def ui_state(self):
        return {
            "state": "ready",
            "quota": "unknown",
            "reset": "unavailable",
            "checkedAt": now(),
            "recovery": "Reconnect",
            "terms": "Read plan 0 USD per request",
        }

    def surface(self, principal, op, inp):
        owner = principal.owner
        if op == "surface.open":
            if inp["scope"] != {"kind": "tenant", "id": owner}:
                raise Refusal("denied", "Surface owner differs.")
            if inp["surfaceId"] != "example.status.panel":
                raise Refusal("incompatible", "Use the status CLI for this representation.")
            if len(self.panels) >= 16:
                raise Refusal("busy", "Panel capacity exhausted.")
            panel = secrets.token_hex(12)
            view = read_json((ROOT / "examples/records/surface.json").read_bytes())
            view["view"]["values"] = self.ui_state()
            view["view"]["dataSchema"] = {
                "type": "object",
                "additionalProperties": False,
                "required": list(view["view"]["values"]),
                "properties": {
                    key: {"type": "string", "readOnly": True} for key in view["view"]["values"]
                },
            }
            validate("profile-data", view, "surface")
            validate_with(view["view"]["dataSchema"], view["view"]["values"])
            sub = self.store.subscribe(
                owner,
                {
                    "scope": inp["scope"],
                    "source": "fixture",
                    "type": "example.status",
                    "durable": False,
                },
            )
            self.panels[panel] = (owner, self.generation, sub["subscriptionId"], view)
            self.focus[owner] = panel
            return {"instanceId": panel, "generation": self.generation, "surface": view}
        rec = self.panels.get(inp["instanceId"])
        if not rec or not kernel.admit(
            True, True, True, self.active, rec[0] == owner, rec[1], inp["generation"]
        ):
            raise Refusal("denied", "Stale or foreign panel.")
        if op == "example.surface.close":
            self.store.unsubscribe(owner, rec[2])
            self.panels.pop(inp["instanceId"])
            self.focus[owner] = "workspace"
            return {"state": "closed"}
        if not self.eligible(rec[3], inp["action"], "1.0.0", True) or not kernel.grant(
            True,
            inp["action"] in rec[3]["operations"],
            inp["action"] == "example.status.read",
            inp["values"] == {"resourceId": "demo"},
        ):
            raise Refusal("denied", "Action not bound to the current view, resource and grant.")
        data = self.export(principal, inp["action"], inp["values"], "surface")
        return {
            "state": "updated",
            "view": {**rec[3]["view"], "values": {**self.ui_state(), "state": data["state"]}},
        }
