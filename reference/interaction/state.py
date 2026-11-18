"""Owner-local durable state for the reference HTTP interaction profile."""

import hashlib
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager

import kernel


class Refusal(Exception):
    CODES = {
        "input": -33009,
        "denied": -33001,
        "conflict": -32002,
        "busy": -32003,
        "pin": -33014,
        "deadline": -33005,
        "cancelled": -33004,
        "method": -32601,
        "incompatible": -33008,
        "params": -32602,
        "request": -32600,
        "parse": -32700,
        "output": -32001,
        "unavailable": -32004,
        "internal": -32603,
    }

    def __init__(self, kind, message, operation_id=None):
        super().__init__(message)
        self.kind = kind
        self.operation_id = operation_id

    def error(self):
        data = {"kind": self.kind}
        if self.operation_id is not None:
            data.update(operationId=self.operation_id, retryable=False)
        return {"code": self.CODES[self.kind], "message": str(self), "data": data}


class Store:
    HISTORY = 4
    RETENTION = 60

    def __init__(self, path, encode, decode, stamp):
        self.path, self.encode, self.decode, self.stamp = path, encode, decode, stamp
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS event (
                    owner TEXT, source TEXT, eid TEXT, ordinal INTEGER, at REAL, body BLOB,
                    PRIMARY KEY(owner,source,eid), UNIQUE(owner,source,ordinal));
                CREATE TABLE IF NOT EXISTS head (
                    owner TEXT, source TEXT, last INTEGER, PRIMARY KEY(owner,source));
                CREATE TABLE IF NOT EXISTS sub (
                    sid TEXT PRIMARY KEY, owner TEXT, source TEXT, kind TEXT, durable INTEGER,
                    ack INTEGER, expires REAL);
                CREATE TABLE IF NOT EXISTS job (
                    jid TEXT PRIMARY KEY, owner TEXT, phase TEXT, rev INTEGER,
                    draft BLOB, effect TEXT, updated REAL);
                CREATE TABLE IF NOT EXISTS compensation (
                    cid TEXT PRIMARY KEY, owner TEXT, original TEXT, approved INTEGER, finished INTEGER);
                CREATE TABLE IF NOT EXISTS receipt (
                    oid TEXT PRIMARY KEY, owner TEXT, outcome TEXT, pin TEXT, data BLOB);
            """)
            columns = {r[1] for r in db.execute("PRAGMA table_info(compensation)")}
            if "approved_digest" not in columns:
                db.execute("ALTER TABLE compensation ADD COLUMN approved_digest TEXT")
                db.execute("UPDATE compensation SET approved=0 WHERE finished=0")
            db.execute("DELETE FROM sub WHERE durable=0")
            db.commit()

    @contextmanager
    def tx(self):
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    def head(self, db, owner, source):
        row = db.execute(
            "SELECT last FROM head WHERE owner=? AND source=?", (owner, source)
        ).fetchone()
        return row["last"] if row else 0

    def publish(self, owner, inp):
        if inp["scope"] != {"kind": "tenant", "id": owner}:
            raise Refusal("denied", "Event belongs to another tenant.")
        source, eid = inp["source"], inp["eventId"]
        stamp = time.time()
        encoded = self.encode(inp)
        with self.tx() as db:
            # Retention of source identifiers equals the published replay interval.
            db.execute("DELETE FROM event WHERE at<=?", (stamp - self.RETENTION,))
            row = db.execute(
                "SELECT ordinal, body FROM event WHERE owner=? AND source=? AND eid=?",
                (owner, source, eid),
            ).fetchone()
            if row:
                if row["body"] != encoded:
                    raise Refusal("conflict", "Event identity already has different content.")
                return {"ordinal": row["ordinal"], "duplicate": True}
            if (
                db.execute("SELECT COUNT(*) FROM event WHERE owner=?", (owner,)).fetchone()[0]
                >= 128
            ):
                raise Refusal("busy", "Event identity retention capacity exhausted.")
            previous_head = self.head(db, owner, source)
            if (
                not previous_head
                and db.execute("SELECT COUNT(*) FROM head WHERE owner=?", (owner,)).fetchone()[0]
                >= 32
            ):
                raise Refusal("busy", "Retained source capacity exhausted.")
            seq = previous_head + 1
            db.execute("INSERT OR REPLACE INTO head VALUES (?,?,?)", (owner, source, seq))
            db.execute(
                "INSERT INTO event VALUES (?,?,?,?,?,?)", (owner, source, eid, seq, stamp, encoded)
            )
            return {"ordinal": seq, "duplicate": False}

    def subscribe(self, owner, inp):
        if inp["scope"] != {"kind": "tenant", "id": owner}:
            raise Refusal("denied", "Subscription scope differs from the authenticated tenant.")
        with self.tx() as db:
            now = time.time()
            db.execute("DELETE FROM sub WHERE expires<=?", (now,))
            if db.execute("SELECT COUNT(*) FROM sub WHERE owner=?", (owner,)).fetchone()[0] >= 32:
                raise Refusal("busy", "Subscription budget exhausted.")
            sid = secrets.token_hex(12)
            position = self.head(db, owner, inp["source"])
            db.execute(
                "INSERT INTO sub VALUES (?,?,?,?,?,?,?)",
                (
                    sid,
                    owner,
                    inp["source"],
                    inp["type"],
                    int(inp["durable"]),
                    position,
                    now + self.RETENTION,
                ),
            )
            return {
                "subscriptionId": sid,
                "scope": inp["scope"],
                "retentionSeconds": self.RETENTION,
                "cursor": f"{sid}/{position}",
            }

    def event_position(self, owner, inp, acknowledge):
        sid = inp["subscriptionId"]
        prefix, _, suffix = inp["cursor"].partition("/")
        if prefix != sid or not suffix.isascii() or not suffix.isdigit() or len(suffix) > 16:
            raise Refusal("input", "Cursor outside the selected subscription.")
        position = int(suffix)
        with self.tx() as db:
            sub = db.execute(
                "SELECT * FROM sub WHERE sid=? AND owner=? AND expires>?", (sid, owner, time.time())
            ).fetchone()
            if not sub:
                raise Refusal("denied", "No current subscription grant.")
            if not sub["durable"]:
                raise Refusal("incompatible", "Resume and acknowledgment require durable delivery.")
            head = self.head(db, owner, sub["source"])
            if position > head:
                raise Refusal("input", "Cursor beyond the source head.")
            low = max(0, head - self.HISTORY)
            first = db.execute(
                "SELECT MIN(ordinal) FROM event WHERE owner=? AND source=? AND at>?",
                (owner, sub["source"], time.time() - self.RETENTION),
            ).fetchone()[0]
            low = max(low, (first - 1) if first is not None else head)
            if acknowledge:
                if position < low:
                    raise Refusal("conflict", "Cursor precedes retained history.")
                next_ack = kernel.ack_position(sub["ack"], position, head)
                if next_ack != position:
                    raise Refusal("conflict", "Acknowledgment would move backward.")
                db.execute("UPDATE sub SET ack=? WHERE sid=?", (next_ack, sid))
                return {"accepted": True}
            if position < low:
                return {"events": [], "gap": True, "nextCursor": f"{sid}/{head}"}
            rows = db.execute(
                "SELECT ordinal,body FROM event WHERE owner=? AND source=? AND ordinal>? ORDER BY ordinal LIMIT ?",
                (owner, sub["source"], position, self.HISTORY),
            ).fetchall()
            events = []
            for row in rows:
                item = self.decode(row["body"])
                if item["type"] == sub["kind"]:
                    events.append({**item, "cursor": f"{sid}/{row['ordinal']}"})
            return {"events": events, "gap": False, "nextCursor": f"{sid}/{head}"}

    def unsubscribe(self, owner, sid):
        with self.tx() as db:
            return db.execute("DELETE FROM sub WHERE sid=? AND owner=?", (sid, owner)).rowcount == 1

    def retire_ephemeral(self):
        with self.tx() as db:
            db.execute("DELETE FROM sub WHERE durable=0")

    def begin_job(self, owner, draft, effect=None):
        with self.tx() as db:
            if (
                effect is not None
                and not db.execute(
                    "SELECT 1 FROM receipt WHERE oid=? AND owner=?", (effect, owner)
                ).fetchone()
            ):
                raise Refusal("denied", "The job cannot adopt another owner's effect.")
            if db.execute("SELECT COUNT(*) FROM job WHERE owner=?", (owner,)).fetchone()[0] >= 128:
                raise Refusal("busy", "Durable job capacity exhausted.")
            jid = secrets.token_hex(12)
            db.execute(
                "INSERT INTO job VALUES (?,?,?,?,?,?,?)",
                (jid, owner, "waiting-input", 1, self.encode(draft), effect, time.time()),
            )
            return self._job(db, owner, jid)[1]

    def _job(self, db, owner, jid):
        row = db.execute("SELECT * FROM job WHERE jid=? AND owner=?", (jid, owner)).fetchone()
        if not row:
            raise Refusal("denied", "No job grant for this owner.")
        record = {
            "jobId": jid,
            "scope": {"kind": "tenant", "id": owner},
            "revision": row["rev"],
            "state": row["phase"],
            "updatedAt": self.stamp(row["updated"]),
        }
        if row["effect"]:
            record["operationId"] = row["effect"]
        return row, record

    def job(self, owner, method, inp):
        jid = inp["jobId"]
        with self.tx() as db:
            row, record = self._job(db, owner, jid)
            if method == "job.status":
                return record
            if method == "example.job.inspect":
                return {"draft": self.decode(row["draft"]), "record": record}
            if method == "job.cancel":
                if row["phase"] != "waiting-input":
                    return record
                new_state = "cancelled"
            else:
                if not kernel.can_continue(
                    row["phase"] == "waiting-input",
                    row["owner"] == owner,
                    row["rev"],
                    inp["revision"],
                ):
                    raise Refusal("conflict", "Saved job revision cannot be resumed.")
                new_state = "succeeded"
            changed = db.execute(
                "UPDATE job SET phase=?,rev=rev+1,updated=? WHERE jid=? AND owner=? AND rev=? AND phase='waiting-input'",
                (new_state, time.time(), jid, owner, row["rev"]),
            ).rowcount
            if changed != 1:
                raise Refusal("conflict", "Job changed before reservation.")
            return self._job(db, owner, jid)[1]

    def seed_receipt(self, owner, oid, pin, chunks, outcome):
        with self.tx() as db:
            if (
                db.execute("SELECT COUNT(*) FROM receipt WHERE owner=?", (owner,)).fetchone()[0]
                >= 128
            ):
                raise Refusal("busy", "Durable receipt capacity exhausted.")
            db.execute(
                "INSERT INTO receipt VALUES (?,?,?,?,?)",
                (oid, owner, outcome, pin, self.encode(chunks)),
            )

    def receipt(self, owner, oid, pin):
        with self.tx() as db:
            row = db.execute(
                "SELECT * FROM receipt WHERE oid=? AND owner=?", (oid, owner)
            ).fetchone()
            if not row:
                raise Refusal("denied", "No read grant for this receipt.")
            if row["pin"] != pin:
                raise Refusal("pin", "Receipt belongs to another package.")
            return row["outcome"], self.decode(row["data"])

    def receipt_count(self, owner):
        with self.tx() as db:
            return db.execute("SELECT COUNT(*) FROM receipt WHERE owner=?", (owner,)).fetchone()[0]

    def review(self, row, pin):
        intent = {
            "issuer": "org.example.interaction",
            "subject": row["owner"],
            "scope": {"kind": "tenant", "id": row["owner"]},
            "recipient": "example.local-ledger",
            "resource": row["original"],
            "operation": "example.compensation.commit",
            "version": "1.0.0",
            "proposal": row["cid"],
            "manifestDigest": pin,
            "amount": "0",
            "currency": "USD",
        }
        return {"intent": intent, "intentDigest": hashlib.sha256(self.encode(intent)).hexdigest()}

    def compensation(self, who, action, inp, pin):
        with self.tx() as db:
            if action == "propose":
                original = db.execute(
                    "SELECT * FROM receipt WHERE owner=? AND oid=? AND outcome='applied'",
                    (who.owner, inp["original"]),
                ).fetchone()
                if not original:
                    raise Refusal("denied", "No own applied receipt to compensate.")
                if (
                    db.execute(
                        "SELECT COUNT(*) FROM compensation WHERE owner=?", (who.owner,)
                    ).fetchone()[0]
                    >= 32
                ):
                    raise Refusal("busy", "Proposal capacity exhausted.")
                cid = secrets.token_hex(12)
                db.execute(
                    "INSERT INTO compensation(cid,owner,original,approved,finished) VALUES (?,?,?,0,0)",
                    (cid, who.owner, inp["original"]),
                )
            else:
                cid = inp["id"]
                c = db.execute(
                    "SELECT * FROM compensation WHERE cid=? AND owner=?", (cid, who.owner)
                ).fetchone()
                if not c:
                    raise Refusal("denied", "No scoped compensation proposal.")
                review = self.review(c, pin)
                if action == "review":
                    return review
                if inp["intentDigest"] != review["intentDigest"]:
                    raise Refusal(
                        "conflict", "The supplied approval differs from the exact reviewed intent."
                    )
                if action == "approve":
                    if not who.admin:
                        raise Refusal("denied", "Trusted approval is required.")
                    db.execute(
                        "UPDATE compensation SET approved=1,approved_digest=? WHERE cid=?",
                        (review["intentDigest"], cid),
                    )
                elif not c["approved"] or c["approved_digest"] != review["intentDigest"]:
                    raise Refusal("denied", "This new operation has its own authorization.")
                else:
                    db.execute(
                        "UPDATE compensation SET finished=1 WHERE cid=? AND finished=0", (cid,)
                    )
            row = db.execute("SELECT * FROM compensation WHERE cid=?", (cid,)).fetchone()
            return {
                "id": row["cid"],
                "original": row["original"],
                "approved": bool(row["approved"]),
                "finished": bool(row["finished"]),
            }

    def backup(self, dest):
        with (
            closing(sqlite3.connect(self.path)) as source,
            closing(sqlite3.connect(dest)) as target,
        ):
            source.backup(target)
