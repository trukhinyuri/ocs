"""A cell owning real POSIX files, durable desired state, and revocable file descriptors."""

import base64
import hashlib
import hmac
import json
import os
import platform
import secrets
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "reference/interaction"), str(ROOT / "reference")]
import native_decisions
from client import Caller, CallError
from contracts import now, read_json, validate
from state import Refusal

if (
    Path(native_decisions.__file__).resolve()
    != Path(__file__).with_name("native_decisions.py").resolve()
):
    raise RuntimeError("unexpected source decision module")

LIMIT = 32768
FRAME = 65536
SLOTS = 4
TENANT_SLOTS = 2
MAX_RESOURCES = 128
METADATA_RESERVE = 65536
META = (Path(__file__).with_name("ocs.json")).read_bytes()
MANIFEST = read_json(META)
PIN = hashlib.sha256(META).hexdigest()
EXPORTS = {op["id"]: op for op in MANIFEST["exports"]}


def canonical(data):
    return json.dumps(
        data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Actor:
    tenant: str
    writer: str = ""
    peer: str = ""
    epoch: int = 0


class Cell:
    def __init__(self, directory, key, peers):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        self.key = key
        self.peers = Path(peers)
        self.lock = threading.RLock()
        self.handles = {}
        self.holds = {}
        self.used = {}
        self.maximum = 0
        self.refused = 0
        with closing(sqlite3.connect(self.root / "state.sqlite")) as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS fence (tenant TEXT PRIMARY KEY, writer TEXT, epoch INTEGER);
              CREATE TABLE IF NOT EXISTS resource (
                tenant TEXT, rid TEXT, revision INTEGER, desired BLOB, materialized INTEGER, tombstone INTEGER,
                PRIMARY KEY(tenant,rid));
              CREATE TABLE IF NOT EXISTS edge (
                tenant TEXT, peer TEXT, direction TEXT, permitted INTEGER,PRIMARY KEY(tenant,peer,direction));
              CREATE TABLE IF NOT EXISTS remote_op (tenant TEXT, oid TEXT, peer TEXT, outcome TEXT,
                PRIMARY KEY(tenant,oid));
            """)
        validate("manifest", MANIFEST)

    @contextmanager
    def tx(self):
        with closing(sqlite3.connect(self.root / "state.sqlite", timeout=4)) as db:
            db.row_factory = sqlite3.Row
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    def init_owners(self, actors):
        with self.tx() as db:
            for actor in actors:
                if actor.writer == "primary":
                    db.execute(
                        "INSERT OR IGNORE INTO fence VALUES (?,?,1)", (actor.tenant, actor.writer)
                    )

    def asset(self, tenant, rid):
        return self.root / ("object-" + digest(canonical([tenant, rid])))

    def fence(self, db, actor, require):
        row = db.execute("SELECT * FROM fence WHERE tenant=?", (actor.tenant,)).fetchone()
        if not row or (
            require
            and not native_decisions.may_write(
                actor.tenant == row["tenant"],
                bool(actor.writer) and actor.writer == row["writer"],
                row["epoch"],
                actor.epoch,
            )
        ):
            raise Refusal("denied", "Current write owner required.")
        return row

    def edge(self, db, tenant, peer, direction):
        row = db.execute(
            "SELECT permitted FROM edge WHERE tenant=? AND peer=? AND direction=?",
            (tenant, peer, direction),
        ).fetchone()
        return bool(row and row[0])

    def resource(self, db, tenant, rid):
        row = db.execute(
            "SELECT * FROM resource WHERE tenant=? AND rid=?", (tenant, rid)
        ).fetchone()
        if not row:
            raise Refusal("denied", "No resource binding in this tenant.")
        return row

    def admit(self, actor):
        with self.lock:
            used = self.used.get(actor.tenant, 0)
            if not native_decisions.enter_cell(sum(self.used.values()), used, SLOTS, TENANT_SLOTS):
                self.refused += 1
                raise Refusal("busy", "Tenant or cell capacity exhausted.")
            self.used[actor.tenant] = used + 1
            self.maximum = max(self.maximum, sum(self.used.values()))

    def release(self, actor):
        with self.lock:
            self.used[actor.tenant] -= 1

    def contract(self, actor):
        return {
            "tenant": actor.tenant,
            "owner": actor.tenant,
            "placement": "this isolated POSIX cell",
            "terms": "public fixture terms version 1",
            "expiry": "revoked authority denies access; scoped export is retained",
            "support": "local cell operator",
            "entitlement": "named tenant grants",
            "distribution": "reviewed local checkout",
            "metering": "unmetered fixture",
            "cost": {"amount": "0", "currency": "USD"},
            "residency": "selected cell directory",
            "capacityBytes": LIMIT,
            "slots": SLOTS,
            "tenantSlots": TENANT_SLOTS,
            "export": "authenticated snapshot",
            "continuity": "restore requires signature, logical capacity, 65536 spare metadata bytes and active writer",
            "evidenceAt": now(),
            "lifecycle": [
                "request",
                "materialize",
                "observe",
                "retire",
                "export",
                "restore",
                "cutover",
            ],
        }

    def platform(self, actor):
        return {
            "target": sys.platform + "/" + platform.machine(),
            "interface": "posix-pread",
            "revision": f"fd-v1-{struct.calcsize('P') * 8}",
            "placement": "isolated-process",
            "authority": actor.tenant,
            "isolation": "reviewed owner process",
            "handleLifetime": "active tenant epoch and materialized resource revision",
            "recovery": "close retired descriptors and reopen under current fenced state",
            "timing": "soft-deadline",
        }

    def observe(self, actor, inp):
        if inp["owner"] != actor.tenant:
            raise Refusal("denied", "Owner field differs from the authenticated tenant.")
        with self.tx() as db:
            if actor.peer and not self.edge(db, actor.tenant, actor.peer, "export"):
                raise Refusal("denied", "Owner has not exported a read to this peer.")
            row = self.resource(db, actor.tenant, inp["id"])
            state = "pending"
            reason = "Awaiting local materialization."
            if row["tombstone"]:
                state, reason = "deleted", "Reversible tombstone with retained owner state."
            elif row["materialized"] == row["revision"]:
                try:
                    fd = os.open(
                        self.asset(actor.tenant, inp["id"]),
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    )
                    try:
                        info = os.fstat(fd)
                        data = (
                            os.pread(fd, len(row["desired"]) + 1, 0)
                            if stat.S_ISREG(info.st_mode) and info.st_size == len(row["desired"])
                            else None
                        )
                    finally:
                        os.close(fd)
                except OSError:
                    data = None
                if data is None or data != row["desired"]:
                    state, reason = (
                        "degraded",
                        "File missing or contents differ from the durable desired revision.",
                    )
                else:
                    state, reason = "ready", "Observed current descriptor bytes."
            rec = {
                "id": inp["id"],
                "owner": actor.tenant,
                "revision": str(row["revision"]),
                "state": state,
                "observedAt": now(),
                "conditions": [
                    {
                        "type": "materialized",
                        "status": "true" if state == "ready" else "false",
                        "reason": reason,
                    }
                ],
            }
            validate("profile-data", rec, "resource")
            return rec

    def active_bytes(self, db, tenant, except_id):
        return db.execute(
            "SELECT COALESCE(SUM(length(desired)),0) FROM resource WHERE tenant=? AND rid<>?",
            (tenant, except_id),
        ).fetchone()[0]

    def install(self, tenant, rid, data):
        path = self.asset(tenant, rid)
        with tempfile.NamedTemporaryFile(dir=self.root, delete=False) as f:
            stage = Path(f.name)
            try:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            except BaseException:
                stage.unlink(missing_ok=True)
                raise
        try:
            os.replace(stage, path)
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            stage.unlink(missing_ok=True)

    def mutate(self, actor, op, inp):
        rid = inp.get("id", "")
        with self.tx() as db:
            fence = self.fence(db, actor, True)
            if op == "example.cell.cutover":
                if inp["epoch"] != fence["epoch"] or inp["writer"] == actor.writer:
                    raise Refusal("conflict", "Stale or redundant cutover.")
                if inp["writer"] not in ("primary", "replacement"):
                    raise Refusal("incompatible", "Unknown writer.")
                db.execute(
                    "UPDATE fence SET writer=?,epoch=epoch+1 WHERE tenant=?",
                    (inp["writer"], actor.tenant),
                )
                return {"writer": inp["writer"], "epoch": fence["epoch"] + 1}
            if op == "example.resource.request":
                raw = inp["text"].encode()
                if len(raw) + self.active_bytes(db, actor.tenant, rid) > LIMIT:
                    raise Refusal("busy", "Tenant capacity exhausted.")
                row = db.execute(
                    "SELECT revision FROM resource WHERE tenant=? AND rid=?", (actor.tenant, rid)
                ).fetchone()
                if (
                    not row
                    and db.execute(
                        "SELECT COUNT(*) FROM resource WHERE tenant=?", (actor.tenant,)
                    ).fetchone()[0]
                    >= MAX_RESOURCES
                ):
                    raise Refusal("busy", "Tenant identity capacity exhausted.")
                current = row[0] if row else 0
                if inp["revision"] != current:
                    raise Refusal("conflict", "Unexpected resource revision.")
                db.execute(
                    "INSERT OR REPLACE INTO resource VALUES (?,?,?,?,0,0)",
                    (actor.tenant, rid, current + 1, raw),
                )
                return {"accepted": True, "revision": current + 1}
            row = self.resource(db, actor.tenant, rid)
            if inp["revision"] != row["revision"]:
                raise Refusal("conflict", "Unexpected resource revision.")
            if op == "example.resource.materialize":
                if row["tombstone"]:
                    raise Refusal("conflict", "A retired generation cannot materialize.")
                self.install(actor.tenant, rid, row["desired"])
                db.execute(
                    "UPDATE resource SET materialized=revision WHERE tenant=? AND rid=?",
                    (actor.tenant, rid),
                )
                return {"accepted": True, "revision": row["revision"]}
            db.execute(
                "UPDATE resource SET tombstone=1,revision=revision+1 WHERE tenant=? AND rid=?",
                (actor.tenant, rid),
            )
            return {"accepted": True, "revision": row["revision"] + 1}

    def export(self, actor, rid):
        with self.tx() as db:
            fence = self.fence(db, actor, True)
            row = self.resource(db, actor.tenant, rid)
            raw = row["desired"]
            snap = {
                "owner": actor.tenant,
                "id": rid,
                "revision": row["revision"],
                "materialized": row["materialized"],
                "retired": bool(row["tombstone"]),
                "requiredBytes": len(raw),
                "data": base64.b64encode(raw).decode(),
                "digest": digest(raw),
                "writerEpoch": fence["epoch"],
            }
            signature = hmac.new(self.key, canonical(snap), "sha256").hexdigest()
            return {"snapshot": snap, "signature": signature}

    def restore(self, actor, inp):
        snap = inp["snapshot"]
        signature = hmac.new(self.key, canonical(snap), "sha256").hexdigest()
        if not hmac.compare_digest(signature, inp["signature"]) or snap["owner"] != actor.tenant:
            raise Refusal("denied", "Snapshot authenticity or owner scope failed.")
        raw = base64.b64decode(snap["data"], validate=True)
        if len(raw) != snap["requiredBytes"] or digest(raw) != snap["digest"]:
            raise Refusal("pin", "Snapshot integrity failed.")
        rid = snap["id"]
        with self.tx() as db:
            self.fence(db, actor, True)
            capacity = min(
                inp["capacityBytes"],
                LIMIT - self.active_bytes(db, actor.tenant, rid),
                max(0, shutil.disk_usage(self.root).free - METADATA_RESERVE),
            )
            if len(raw) > capacity:
                raise Refusal("busy", "Restore capacity is insufficient.")
            old = db.execute(
                "SELECT revision FROM resource WHERE tenant=? AND rid=?", (actor.tenant, rid)
            ).fetchone()
            if (
                not old
                and db.execute(
                    "SELECT COUNT(*) FROM resource WHERE tenant=?", (actor.tenant,)
                ).fetchone()[0]
                >= MAX_RESOURCES
            ):
                raise Refusal("busy", "Restore identity capacity unavailable.")
            if inp["expectedRevision"] != (old[0] if old else 0):
                raise Refusal("conflict", "Restore target changed.")
            revision = max(snap["revision"], (old[0] + 1) if old else 1)
            valid_materialization = snap["revision"] == snap["materialized"]
            if valid_materialization:
                self.install(actor.tenant, rid, raw)
            db.execute(
                "INSERT OR REPLACE INTO resource VALUES (?,?,?,?,?,?)",
                (
                    actor.tenant,
                    rid,
                    revision,
                    raw,
                    revision if valid_materialization else 0,
                    snap["retired"],
                ),
            )
            return {"accepted": True, "revision": revision}

    def lease(self, actor, op, inp):
        with self.lock, self.tx() as db:
            current = self.fence(db, actor, False)
            if op == "example.native.open":
                desc = inp["platform"]
                validate("profile-data", desc, "platform")
                target = self.platform(actor)
                hard = desc["timing"] == "hard-deadline"
                same_target = all(
                    desc.get(k) == target[k]
                    for k in ("target", "interface", "placement", "recovery", "handleLifetime")
                )
                confinement = (
                    desc["isolation"] == target["isolation"] and desc["timing"] == target["timing"]
                )
                if not native_decisions.admit_native(
                    same_target,
                    desc["revision"] == target["revision"],
                    desc["authority"] == target["authority"],
                    confinement,
                    hard,
                ):
                    raise Refusal(
                        "incompatible",
                        "Named platform, ABI, confinement or timing bound unavailable.",
                    )
                row = self.resource(db, actor.tenant, inp["id"])
                if row["tombstone"] or row["revision"] != row["materialized"]:
                    raise Refusal("unavailable", "Resource is not materialized.")
                if len(self.handles) >= 8:
                    raise Refusal("busy", "Descriptor budget exhausted.")
                path = self.asset(actor.tenant, inp["id"])
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                if (
                    not stat.S_ISREG(os.fstat(fd).st_mode)
                    or os.fstat(fd).st_size != len(row["desired"])
                    or os.pread(fd, len(row["desired"]) + 1, 0) != row["desired"]
                ):
                    os.close(fd)
                    raise Refusal("pin", "Materialized contents changed.")
                handle = secrets.token_hex(16)
                self.handles[handle] = (
                    actor.tenant,
                    current["epoch"],
                    inp["id"],
                    row["revision"],
                    fd,
                )
                return {"handle": handle, "epoch": current["epoch"], "revision": row["revision"]}
            handle = inp["handle"]
            entry = self.handles.get(handle)
            if not entry or entry[0] != actor.tenant:
                raise Refusal("denied", "No owned descriptor.")
            if op == "example.native.close":
                os.close(entry[4])
                del self.handles[handle]
                return {"accepted": True}
            row = self.resource(db, actor.tenant, entry[2])
            if entry[1] != current["epoch"] or entry[3] != row["revision"] or row["tombstone"]:
                os.close(entry[4])
                del self.handles[handle]
                raise Refusal("denied", "Retired descriptor generation.")
            if inp["offset"] > len(row["desired"]):
                raise Refusal("input", "Offset beyond file.")
            data = os.pread(entry[4], inp["length"], inp["offset"])
            return {
                "base64": base64.b64encode(data).decode(),
                "bytes": len(data),
                "digest": digest(data),
            }

    def peer(self, actor, op, inp, deadline):
        peer = inp["peer"]
        if peer not in json.loads(self.peers.read_bytes()):
            raise Refusal("denied", "Unknown peer binding in the operator configuration.")
        if op == "example.peer.grant":
            with self.tx() as db:
                self.fence(db, actor, True)
                db.execute(
                    "INSERT OR REPLACE INTO edge VALUES (?,?,?,?)",
                    (actor.tenant, peer, inp["direction"], inp["permitted"]),
                )
            return {"accepted": True}
        with self.tx() as db:
            if not self.edge(db, actor.tenant, peer, "import"):
                raise Refusal("denied", "Missing local import.")
        configs = json.loads(self.peers.read_bytes())
        dest = configs.get(peer)
        if not dest or dest["tenant"] != actor.tenant:
            raise Refusal("denied", "No independently configured destination.")
        client = Caller(dest["endpoint"], dest["token"])
        try:
            desc = client.request(
                "ocs.describe",
                {
                    "protocols": ["0.1"],
                    "requiredFeatures": ["ocs.cloud/0.1"],
                    "meta": {"deadline": deadline},
                },
            )
            if desc["manifestDigest"] != PIN:
                raise Refusal("pin", "Peer package changed.")
            result = client.request(
                "tool.call",
                {
                    "operation": "resource.observe",
                    "version": "1.0.0",
                    "input": {"id": inp["id"], "owner": actor.tenant},
                    "meta": {"manifestDigest": PIN, "protocol": "0.1", "deadline": deadline},
                },
            )
        except CallError as exc:
            raise Refusal(
                exc.kind if exc.kind in Refusal.CODES else "unavailable", "Selected peer refused."
            ) from exc
        except (ConnectionError, OSError):
            raise Refusal("unavailable", "Selected peer unavailable.")
        return result["data"]

    def dispatch(self, actor, op, inp, deadline, expires):
        if actor.peer and op != "resource.observe":
            raise Refusal("denied", "Peer export is a single scoped observation.")
        if op == "resource.observe":
            self.admit(actor)
            try:
                return self.observe(actor, inp)
            finally:
                self.release(actor)
        if op == "example.cell.terms":
            return self.contract(actor)
        if op == "example.native.describe":
            return self.platform(actor)
        if op.startswith("example.native."):
            return self.lease(actor, op, inp)
        if op in (
            "example.resource.request",
            "example.resource.materialize",
            "example.resource.retire",
            "example.cell.cutover",
        ):
            result = self.mutate(actor, op, inp)
            if op == "example.cell.cutover":
                with self.lock:
                    for handle, entry in list(self.handles.items()):
                        if entry[0] == actor.tenant and entry[1] < result["epoch"]:
                            os.close(entry[4])
                            del self.handles[handle]
            return result
        if op == "example.resource.export":
            return self.export(actor, inp["id"])
        if op == "example.resource.restore":
            return self.restore(actor, inp)
        if op.startswith("example.peer."):
            return self.peer(actor, op, inp, deadline)
        if op == "example.remote.reserve":
            with self.tx() as db:
                self.fence(db, actor, True)
                if not self.edge(db, actor.tenant, inp["peer"], "import"):
                    raise Refusal("denied", "No approved recipient.")
                if (
                    db.execute(
                        "SELECT COUNT(*) FROM remote_op WHERE tenant=?", (actor.tenant,)
                    ).fetchone()[0]
                    >= MAX_RESOURCES
                ):
                    raise Refusal("busy", "Tenant reconciliation capacity exhausted.")
                oid = secrets.token_hex(12)
                db.execute(
                    "INSERT INTO remote_op VALUES (?,?,?,'unknown')",
                    (actor.tenant, oid, inp["peer"]),
                )
                return {"id": oid, "outcome": "unknown"}
        if op == "example.remote.readback":
            with self.tx() as db:
                row = db.execute(
                    "SELECT * FROM remote_op WHERE tenant=? AND oid=?", (actor.tenant, inp["id"])
                ).fetchone()
                if not row:
                    raise Refusal("denied", "No own pending operation.")
                return {"id": row["oid"], "outcome": row["outcome"]}
        if op == "example.work.stats":
            with self.lock:
                return {
                    "active": sum(self.used.values()),
                    "peak": self.maximum,
                    "rejected": self.refused,
                    "cap": SLOTS,
                }
        key = (actor.tenant, inp["id"])
        if op == "example.work.cancel":
            with self.lock:
                flag = self.holds.get(key)
                if not flag:
                    raise Refusal("denied", "No active work for this tenant.")
                flag.set()
                return {"accepted": True}
        if op == "example.work.hold":
            self.admit(actor)
            flag = threading.Event()
            registered = False
            try:
                with self.lock:
                    if key in self.holds:
                        raise Refusal("conflict", "Work ID already in use.")
                    self.holds[key] = flag
                    registered = True
                if flag.wait(max(0, min(inp["holdMs"] / 1000, expires - time.monotonic()))):
                    raise Refusal("cancelled", "Caller cancelled selected work.")
                if time.monotonic() >= expires:
                    raise Refusal("deadline", "Deadline elapsed.")
                return {"accepted": True}
            finally:
                with self.lock:
                    if registered:
                        self.holds.pop(key, None)
                self.release(actor)
        raise Refusal("method", "Operation not exported.")
