"""Synthetic reset authority with atomic grants, proposals and receipts."""

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone


class Refused(ValueError):
    """The message is the protocol error kind for this fixture."""


def timestamp(second):
    return (
        datetime.fromtimestamp(second, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def intent_hash(intent):
    # All field names and values in this sealed intent are ASCII strings, arrays
    # and objects. For this subset sorting keys and compact JSON are JCS.
    raw = json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if not raw.isascii():
        raise ValueError("intent outside the fixture's canonicalization subset")
    return hashlib.sha256(raw.encode()).hexdigest()


class Ledger:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    account TEXT PRIMARY KEY, owner TEXT NOT NULL, can_write INTEGER NOT NULL,
                    credits INTEGER NOT NULL CHECK (credits >= 0), revision INTEGER NOT NULL,
                    remaining INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY, issuer TEXT NOT NULL, owner TEXT NOT NULL,
                    account TEXT NOT NULL, request_key TEXT NOT NULL, intent TEXT NOT NULL,
                    digest TEXT NOT NULL, expires INTEGER NOT NULL, approved INTEGER DEFAULT 0,
                    applied_at INTEGER, UNIQUE(issuer, owner, account, request_key)
                );
            """)

    @contextmanager
    def transaction(self):
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    def add_fixture_account(self, owner, account, credits=1):
        with self.transaction() as db:
            db.execute("INSERT INTO accounts VALUES (?, ?, 1, ?, 1, 0)", (account, owner, credits))

    def set_write_grant(self, owner, account, enabled):
        # Trusted administration entry, separate from all exported calls.
        with self.transaction() as db:
            db.execute(
                "UPDATE accounts SET can_write=? WHERE account=? AND owner=?",
                (enabled, account, owner),
            )

    @staticmethod
    def account(db, owner, account):
        row = db.execute(
            "SELECT * FROM accounts WHERE account=? AND owner=?", (account, owner)
        ).fetchone()
        if row is None:
            raise Refused("denied")
        return row

    @staticmethod
    def proposal(db, owner, operation_id):
        row = db.execute(
            "SELECT * FROM proposals WHERE id=? AND owner=?", (operation_id, owner)
        ).fetchone()
        if row is None:
            raise Refused("denied")
        return row

    def balance(self, owner, account):
        with self.transaction() as db:
            row = self.account(db, owner, account)
            return row["credits"], row["remaining"], row["revision"]

    def prepare(self, owner, account, key, pin, expected_revision, now):
        issuer = "example.ledger"
        intent = {
            "issuer": issuer,
            "packageId": "org.example.reset",
            "packageVersion": "0.1.0",
            "manifestDigest": pin,
            "subject": owner,
            "scope": {"kind": "account", "id": account},
            "operation": "quota.reset",
            "version": "1.0.0",
            "target": "example.window",
            "input": {"accountId": account, "grantId": "trial", "windows": ["weekly"]},
            "preconditions": {
                "revision": str(expected_revision),
                "creditsConsumed": "1",
                "charge": {"amount": "0", "currency": "USD"},
            },
        }
        digest = intent_hash(intent)
        with self.transaction() as db:
            state = self.account(db, owner, account)
            if not state["can_write"]:
                raise Refused("denied")
            row = db.execute(
                "SELECT * FROM proposals WHERE issuer=? AND owner=? AND account=? AND request_key=?",
                (issuer, owner, account, key),
            ).fetchone()
            if row is None:
                if state["revision"] != expected_revision or state["credits"] < 1:
                    raise Refused("conflict")
                operation_id = secrets.token_hex(16)
                db.execute(
                    """INSERT INTO proposals(id, issuer, owner, account, request_key, intent, digest, expires)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        operation_id,
                        issuer,
                        owner,
                        account,
                        key,
                        json.dumps(intent),
                        digest,
                        now + 60,
                    ),
                )
                row = self.proposal(db, owner, operation_id)
            if row["digest"] != digest:
                raise Refused("conflict")
            return {
                "operationId": row["id"],
                "intentDigest": digest,
                "intent": intent,
                "expiresAt": timestamp(row["expires"]),
                "summary": "Reset the weekly window.",
                "consequences": ["Consumes one trial credit.", "Restores 100 requests."],
                "reversible": False,
            }

    def record_approval(self, owner, operation_id, digest, now):
        # Called only by the fixture's trusted approval surface, never by a plugin.
        with self.transaction() as db:
            row = self.proposal(db, owner, operation_id)
            if row["digest"] != digest or now >= row["expires"]:
                raise Refused("denied")
            db.execute("UPDATE proposals SET approved=1 WHERE id=?", (operation_id,))

    def commit(self, owner, operation_id, digest, current_pin, now):
        with self.transaction() as db:
            row = self.proposal(db, owner, operation_id)
            state = self.account(db, owner, row["account"])
            intent = json.loads(row["intent"])
            if row["digest"] != digest:
                raise Refused("conflict")
            if row["applied_at"] is not None:
                return self.receipt(row, now)
            if not state["can_write"] or not row["approved"]:
                raise Refused("denied")
            if now >= row["expires"]:
                raise Refused("deadline")
            if intent["manifestDigest"] != current_pin:
                raise Refused("pin")
            if (
                state["credits"] < 1
                or str(state["revision"]) != intent["preconditions"]["revision"]
            ):
                raise Refused("conflict")
            db.execute(
                "UPDATE accounts SET credits=credits-1, remaining=100, revision=revision+1 WHERE account=?",
                (row["account"],),
            )
            db.execute("UPDATE proposals SET applied_at=? WHERE id=?", (now, operation_id))
            return self.receipt(self.proposal(db, owner, operation_id), now)

    @staticmethod
    def receipt(row, now):
        applied = row["applied_at"] is not None
        return {
            "operationId": row["id"],
            "intentDigest": row["digest"],
            "scope": {"kind": "account", "id": row["account"]},
            "state": "applied" if applied else "not-applied",
            "observedAt": timestamp(row["applied_at"] if applied else now),
        }

    def readback(self, owner, operation_id, now):
        with self.transaction() as db:
            row = self.proposal(db, owner, operation_id)
            self.account(db, owner, row["account"])
            return self.receipt(row, now)
