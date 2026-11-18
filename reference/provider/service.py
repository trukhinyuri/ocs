"""A local, tenant-scoped provider and its durable observation store."""

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import MAX_EMAX, MIN_EMIN, Decimal, localcontext
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference"))
sys.path.insert(0, str(ROOT / "examples/reset"))
from contracts import validate
from engine import Unsupported, invoke, tokenize
from ledger import Ledger, Refused, timestamp
from policy import (
    accept_amount,
    authorize_handle,
    grant_generation,
    meter_decision,
    publish_complete,
)

ISSUER = "example.ledger"
PRODUCT = "local-language"
ORIGIN = "urn:ocs:local-broker"
ROUTE = "local-primary"
PLAN = "shared-trial"
MODEL = "reference-colour"
PAGE = 2
RETENTION = 90 * 24 * 3600
BURST_SECONDS = 2
BURST_LIMIT = 1000


def evidence(source, at, status="verified", reason=None):
    record = {"source": source, "observedAt": timestamp(at), "status": status}
    if reason:
        record["reason"] = reason
    return record


def scope(kind, value):
    return {"kind": kind, "id": value}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def seconds(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def independent_total(windows, unit, period, independent_keys):
    """Deduplicate authoritative pool IDs. Unknown or incompatible windows stay separate."""
    seen = {}
    separate = []
    for item in windows:
        identity = (item["scope"]["kind"], item["scope"]["id"])
        comparable = item["unit"] == unit and item.get("period") == period
        known = item["state"] == "known" and "remaining" in item
        if (
            comparable
            and known
            and identity in seen
            and seen[identity] != Decimal(item["remaining"])
        ):
            raise Refused("conflict")
        if accept_amount(comparable, identity in independent_keys, known, identity in seen):
            seen[identity] = Decimal(item["remaining"])
        elif not (comparable and known and identity in independent_keys and identity in seen):
            separate.append(item)
    total = None
    if seen:
        # Finite decimal quantities retain every digit, regardless of the
        # process-wide context or the decimal scale selected by this provider.
        values = seen.values()
        with localcontext() as precision:
            precision.prec = (
                max(1, max(v.adjusted() + 1 for v in values))
                + max(0, max(-v.as_tuple().exponent for v in values))
                + len(str(len(seen)))
            )
            precision.Emax = MAX_EMAX
            precision.Emin = MIN_EMIN
            total = format(sum(values, Decimal(0)), "f")
    return {
        "remaining": total,
        "pools": len(seen),
        "separate": separate,
    }


def complete_snapshot(previous, pages, identity, kind):
    """A single publication decision for model and account pages. Return the old value on a gap."""
    if not pages:
        return previous
    expected = None
    followed = set()
    seen_rows = set()
    values = []
    revision = pages[0]["page"]["revision"]
    key = "models" if kind == "catalog" else "accounts"
    for i, entry in enumerate(pages):
        page = entry["page"]
        validate(
            "profile-data" if kind == "catalog" else "profile-wire",
            page,
            "catalog" if kind == "catalog" else "accountPage",
        )
        if entry["token"] != expected or (expected is not None and expected in followed):
            return previous
        followed.add(expected)
        if entry["origin"] != identity or page["revision"] != revision:
            return previous
        if kind == "catalog" and (
            page["provider"],
            page["product"],
            page["route"],
            page["scope"],
            page.get("region"),
            page.get("planId"),
            page.get("authMethod"),
        ) != (
            identity["provider"],
            identity["product"],
            identity["route"],
            identity["scope"],
            identity["region"],
            identity["plan"],
            identity["auth"],
        ):
            return previous
        if kind == "accounts" and any(
            (a["provider"], a["product"]) != (identity["provider"], identity["product"])
            for a in page[key]
        ):
            return previous
        for row in page[key]:
            rowid = row["id" if kind == "catalog" else "accountId"]
            if rowid in seen_rows:
                return previous
            seen_rows.add(rowid)
            values.append(row)
        expected = page.get("nextPageToken")
        last = i + 1 == len(pages)
        if not last and (page["complete"] or not expected):
            return previous
        if last and publish_complete(
            entry["origin"] == identity, page["complete"], expected is None
        ):
            return {"revision": revision, "rows": values, "evidence": page["evidence"]}
    return previous


class Provider(Ledger):
    def __init__(self, path):
        super().__init__(path)
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS connections (
                    account TEXT PRIMARY KEY, label TEXT NOT NULL, org TEXT NOT NULL, auth TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, signed INTEGER NOT NULL DEFAULT 1,
                    archived INTEGER NOT NULL DEFAULT 0, last_model TEXT, last_mode TEXT, last_reply INTEGER
                );
                CREATE TABLE IF NOT EXISTS editions (owner TEXT PRIMARY KEY, revision INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, issuer TEXT NOT NULL, origin TEXT NOT NULL,
                    expires INTEGER NOT NULL, label TEXT NOT NULL, org TEXT NOT NULL, account TEXT, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS handles (
                    hash TEXT PRIMARY KEY, flow TEXT NOT NULL, owner TEXT NOT NULL, issuer TEXT NOT NULL,
                    origin TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS cursors (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, context TEXT NOT NULL, revision TEXT NOT NULL,
                    offset INTEGER NOT NULL, expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    owner TEXT NOT NULL, context TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(owner,context)
                );
                CREATE TABLE IF NOT EXISTS notices (
                    owner TEXT NOT NULL, context TEXT NOT NULL, identity TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(owner,context,identity)
                );
                CREATE TABLE IF NOT EXISTS meters (
                    owner TEXT NOT NULL, account TEXT NOT NULL, meter TEXT NOT NULL, event_key TEXT NOT NULL,
                    interval_id TEXT NOT NULL, unit TEXT NOT NULL, amount_minor INTEGER NOT NULL,
                    quantity INTEGER NOT NULL, kind TEXT NOT NULL, signature TEXT NOT NULL,
                    at INTEGER NOT NULL, output TEXT,
                    PRIMARY KEY(owner,account,meter,interval_id,event_key)
                );
                CREATE TABLE IF NOT EXISTS entitlements (
                    owner TEXT NOT NULL, org TEXT NOT NULL, plan TEXT NOT NULL, expires INTEGER NOT NULL,
                    PRIMARY KEY(owner,org,plan)
                );
                CREATE TABLE IF NOT EXISTS period_state (account TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS pools (
                    owner TEXT NOT NULL, org TEXT NOT NULL, epoch INTEGER NOT NULL,
                    remaining INTEGER NOT NULL, PRIMARY KEY(owner,org)
                );
                CREATE TABLE IF NOT EXISTS pricing_uncertainty (
                    owner TEXT NOT NULL, org TEXT NOT NULL, PRIMARY KEY(owner,org)
                );
                CREATE TABLE IF NOT EXISTS selections (
                    owner TEXT NOT NULL, account TEXT NOT NULL, model TEXT NOT NULL,
                    route TEXT NOT NULL, parameters TEXT NOT NULL, chosen_at INTEGER NOT NULL,
                    PRIMARY KEY(owner,account)
                );
                CREATE TABLE IF NOT EXISTS conversation_turns (
                    owner TEXT NOT NULL, account TEXT NOT NULL, context TEXT NOT NULL, request_key TEXT NOT NULL,
                    input TEXT NOT NULL, result TEXT NOT NULL, at INTEGER NOT NULL,
                    PRIMARY KEY(owner,account,context,request_key)
                );
            """)

    @staticmethod
    def bump(db, owner):
        db.execute(
            """INSERT INTO editions VALUES (?,1) ON CONFLICT(owner)
                    DO UPDATE SET revision=revision+1""",
            (owner,),
        )

    @staticmethod
    def check_product(args):
        if args["provider"] != ISSUER or args["product"] != PRODUCT:
            raise Refused("denied")

    @staticmethod
    def connection(db, owner, account):
        r = db.execute(
            """SELECT a.*,c.*,e.expires AS term_expires,b.remaining AS pool_remaining,
               EXISTS(SELECT 1 FROM pricing_uncertainty t WHERE t.owner=a.owner AND t.org=c.org) AS ambiguous_price,
               EXISTS(SELECT 1 FROM proposals p JOIN dispatch_reservations d ON p.id=d.id
                      WHERE p.owner=a.owner AND p.account=a.account AND p.applied_at IS NULL) AS uncertain
               FROM accounts a JOIN connections c USING(account)
               LEFT JOIN entitlements e ON e.owner=a.owner AND e.org=c.org AND e.plan=?
               LEFT JOIN pools b ON b.owner=a.owner AND b.org=c.org
               WHERE a.owner=? AND a.account=? AND c.archived=0""",
            (PLAN, owner, account),
        ).fetchone()
        if r is None:
            raise Refused("denied")
        return r

    def current_grant(self, db, state, now):
        r = self.connection(db, state["owner"], state["account"])
        term = db.execute(
            "SELECT expires FROM entitlements WHERE owner=? AND org=? AND plan=?",
            (r["owner"], r["org"], PLAN),
        ).fetchone()
        return bool(state["can_write"] and term and now < term["expires"])

    def revision_for_prepare(self, owner, account, request_key):
        with self.transaction() as db:
            state = self.account(db, owner, account)
            old = db.execute(
                "SELECT intent FROM proposals WHERE issuer=? AND owner=? AND account=? AND request_key=?",
                (ISSUER, owner, account, request_key),
            ).fetchone()
            return (
                int(json.loads(old["intent"])["preconditions"]["revision"])
                if old
                else state["revision"]
            )

    def observe_period(self, db, row, now):
        epoch = now // (7 * 86400)
        last = db.execute(
            "SELECT epoch FROM period_state WHERE account=?", (row["account"],)
        ).fetchone()
        if last is None or epoch > last["epoch"]:
            db.execute("INSERT OR REPLACE INTO period_state VALUES(?,?)", (row["account"], epoch))
            if last is not None:
                db.execute(
                    "UPDATE accounts SET remaining=100, revision=revision+1 WHERE account=?",
                    (row["account"],),
                )
                self.bump(db, row["owner"])
        pool = db.execute(
            "SELECT epoch,remaining FROM pools WHERE owner=? AND org=?", (row["owner"], row["org"])
        ).fetchone()
        if pool is None or epoch > pool["epoch"]:
            db.execute(
                "INSERT OR REPLACE INTO pools VALUES(?,?,?,500)", (row["owner"], row["org"], epoch)
            )
        return self.connection(db, row["owner"], row["account"])

    @staticmethod
    def account_view(row, now):
        if not row["enabled"]:
            state, why = "disabled", "Enable local routing to resume."
        elif not row["signed"]:
            state, why = "needs-auth", "Reauthenticate this account."
        elif row["term_expires"] is None or now >= row["term_expires"]:
            state, why = "denied", "Renew the scoped entitlement with its owner."
        elif row["uncertain"]:
            state, why = "unknown", "Reconcile the original operation with its authority."
        elif row["remaining"] <= 0 or row["pool_remaining"] == 0:
            state, why = "exhausted", "Observe the next window or review the reset grant."
        elif row["last_reply"] is None:
            state, why = "unverified", "Run a scoped reply probe."
        else:
            state, why = "working", "The selected local endpoint returned a scoped reply."
        a = {
            "accountId": row["account"],
            "provider": ISSUER,
            "product": PRODUCT,
            "route": ROUTE,
            "authMethod": row["auth"],
            "label": row["label"],
            "enabled": bool(row["enabled"]),
            "signedIn": bool(row["signed"]),
            "planCandidates": [PLAN, "shared-flex"] if row["ambiguous_price"] else [PLAN],
            "state": state,
            "reason": why,
            "evidence": evidence("urn:ocs:fixture:accounts", now),
        }
        if row["last_reply"] is not None:
            a["lastReply"] = {
                "model": row["last_model"],
                "mode": row["last_mode"],
                "at": timestamp(row["last_reply"]),
            }
        return a

    def add_connection(self, db, owner, label, org, method, now):
        account = secrets.token_hex(10)
        db.execute("INSERT INTO accounts VALUES(?,?,1,1,1,100)", (account, owner))
        db.execute(
            "INSERT INTO connections(account,label,org,auth) VALUES(?,?,?,?)",
            (account, label, org, method),
        )
        db.execute(
            "INSERT OR IGNORE INTO entitlements VALUES (?,?,?,?)",
            (owner, org, PLAN, now + 30 * 86400),
        )
        self.bump(db, owner)
        return self.account_view(self.connection(db, owner, account), now)

    def flow(self, db, owner, label, org, account, now):
        flow = secrets.token_hex(16)
        expires = now + 90
        db.execute(
            "INSERT INTO flows(id,owner,issuer,origin,expires,label,org,account) VALUES(?,?,?,?,?,?,?,?)",
            (flow, owner, ISSUER, ORIGIN, expires, label, org, account),
        )
        return {"kind": "waiting", "flowId": flow, "expiresAt": timestamp(expires)}

    def mint(self, owner, flow, issuer, origin, expires):
        """Trusted broker operation. Only the digest of the opaque grant is retained."""
        handle = secrets.token_hex(24)
        with self.transaction() as db:
            db.execute(
                "INSERT INTO handles(hash,flow,owner,issuer,origin,expires) VALUES(?,?,?,?,?,?)",
                (digest(handle), flow, owner, issuer, origin, expires),
            )
        return handle

    def connect(self, owner, args, now):
        self.check_product(args)
        settings = args.get("settings", {})
        if set(settings) - {"label", "organization"} or "connectionHandle" in args:
            raise Refused("input")
        label = settings.get("label", "Local account")
        org = settings.get("organization", "example-org")
        if not all(isinstance(v, str) and 0 < len(v) <= 100 for v in (label, org)):
            raise Refused("input")
        with self.transaction() as db:
            if args["authMethod"] == "local-none":
                return {
                    "kind": "ready",
                    "account": self.add_connection(db, owner, label, org, "local-none", now),
                }
            if args["authMethod"] == "managed-ticket":
                return self.flow(db, owner, label, org, None, now)
            raise Refused("incompatible")

    def continue_flow(self, owner, args, now):
        if "values" in args:
            raise Refused("input")
        with self.transaction() as db:
            f = db.execute("SELECT * FROM flows WHERE id=?", (args["flowId"],)).fetchone()
            h = db.execute(
                "SELECT * FROM handles WHERE hash=?", (digest(args.get("connectionHandle", "")),)
            ).fetchone()
            if (
                f is None
                or h is None
                or not authorize_handle(
                    owner == f["owner"] == h["owner"],
                    f["issuer"] == h["issuer"] == ISSUER,
                    f["origin"] == h["origin"] == ORIGIN,
                    f["id"] == h["flow"],
                    now < min(f["expires"], h["expires"]),
                    not f["used"] and not h["used"],
                )
            ):
                raise Refused("denied")
            db.execute("UPDATE flows SET used=1 WHERE id=?", (f["id"],))
            db.execute("UPDATE handles SET used=1 WHERE hash=?", (h["hash"],))
            if f["account"] is None:
                a = self.add_connection(db, owner, f["label"], f["org"], "managed-ticket", now)
            else:
                self.connection(db, owner, f["account"])
                db.execute("UPDATE connections SET signed=1 WHERE account=?", (f["account"],))
                db.execute(
                    "UPDATE accounts SET can_write=(SELECT enabled FROM connections WHERE account=?) WHERE account=?",
                    (f["account"], f["account"]),
                )
                self.bump(db, owner)
                a = self.account_view(self.connection(db, owner, f["account"]), now)
            return {"kind": "ready", "account": a}

    def manage(self, owner, operation, args, now):
        account = args["accountId"]
        with self.transaction() as db:
            row = self.connection(db, owner, account)
            if operation == "account.reauthenticate" and row["auth"] == "managed-ticket":
                return self.flow(db, owner, row["label"], row["org"], account, now)
            if operation == "account.reauthenticate":
                db.execute("UPDATE connections SET signed=1 WHERE account=?", (account,))
            elif operation == "account.enable":
                db.execute(
                    "UPDATE connections SET enabled=? WHERE account=?", (args["enabled"], account)
                )
            elif operation == "account.signout":
                db.execute("UPDATE connections SET signed=0 WHERE account=?", (account,))
            elif operation == "account.remove":
                db.execute(
                    "UPDATE connections SET archived=1,enabled=0 WHERE account=?", (account,)
                )
            else:
                raise Refused("method")
            db.execute(
                """UPDATE accounts SET can_write=(SELECT enabled AND signed AND NOT archived
                       FROM connections WHERE account=?) WHERE account=?""",
                (account, account),
            )
            self.bump(db, owner)
            if operation in ("account.signout", "account.remove"):
                return {"accepted": True}
            a = self.account_view(self.connection(db, owner, account), now)
            return {"kind": "ready", "account": a} if operation == "account.reauthenticate" else a

    def page(self, db, owner, context, revision, rows, token, now):
        offset = 0
        context = canonical(context)
        if token is None:
            # A fresh inventory is a maintenance point for this owner's temporary pages.
            db.execute("DELETE FROM cursors WHERE owner=? AND expires<=?", (owner, now))
        else:
            t = db.execute("SELECT * FROM cursors WHERE id=?", (token,)).fetchone()
            if (
                t is None
                or t["owner"] != owner
                or t["context"] != context
                or t["revision"] != revision
                or now >= t["expires"]
            ):
                raise Refused("conflict")
            offset = t["offset"]
        chunk = rows[offset : offset + PAGE]
        extra = {}
        if offset + len(chunk) < len(rows):
            next_token = secrets.token_hex(16)
            db.execute(
                "INSERT INTO cursors VALUES(?,?,?,?,?,?)",
                (next_token, owner, context, revision, offset + len(chunk), now + 90),
            )
            extra = {"nextPageToken": next_token, "reason": "More scoped records remain."}
        return chunk, extra

    def accounts(self, owner, args, now):
        self.check_product(args)
        with self.transaction() as db:
            keys = db.execute(
                """SELECT a.account FROM accounts a JOIN connections c USING(account)
                            WHERE a.owner=? AND c.archived=0 ORDER BY a.account""",
                (owner,),
            ).fetchall()
            rows = [
                self.account_view(
                    self.observe_period(db, self.connection(db, owner, k[0]), now), now
                )
                for k in keys
            ]
            r = db.execute("SELECT revision FROM editions WHERE owner=?", (owner,)).fetchone()
            revision = digest(
                [r[0] if r else 0, [(row["accountId"], row["state"]) for row in rows]]
            )
            chunk, extra = self.page(
                db,
                owner,
                {"provider": ISSUER, "product": PRODUCT},
                revision,
                rows,
                args.get("pageToken"),
                now,
            )
            return {
                "accounts": chunk,
                "revision": revision,
                "complete": not extra,
                "evidence": evidence("urn:ocs:fixture:accounts", now),
                **extra,
            }

    @staticmethod
    def identity(row):
        return {
            "provider": ISSUER,
            "product": PRODUCT,
            "route": ROUTE,
            "scope": scope("account", row["account"]),
            "region": "fixture-region",
            "plan": PLAN,
            "auth": row["auth"],
        }

    @staticmethod
    def default_models():
        return [
            {
                "id": MODEL,
                "kind": "generation",
                "entitled": True,
                "adapterSupported": True,
                "officiallyListed": True,
                "aliases": ["colour-stable"],
                "inputModalities": ["text/plain"],
                "outputModalities": ["text/plain"],
                "reasoning": ["off"],
                "tiers": ["standard", "fast"],
                "contextLimit": 250,
                "outputLimit": 8,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reasoning": {"const": "off"},
                        "tier": {"enum": ["standard", "fast"]},
                    },
                    "required": ["reasoning", "tier"],
                    "additionalProperties": False,
                },
            },
            {
                "id": "preview-lattice",
                "kind": "generation",
                "entitled": None,
                "adapterSupported": False,
                "officiallyListed": True,
                "unrecognized": ["depth-vector"],
            },
            {
                "id": "previous-colour",
                "kind": "generation",
                "entitled": False,
                "adapterSupported": False,
                "officiallyListed": True,
                "eol": {
                    "noticeId": "n1",
                    "announcedAt": "2026-01-01T00:00:00.000Z",
                    "effectiveAt": "2030-01-01T00:00:00.000Z",
                    "source": "urn:ocs:fixture:official-notice:n1",
                    "replacement": MODEL,
                },
            },
        ]

    @staticmethod
    def adapter_model(upstream):
        record = dict(upstream)
        # The catalogue source reports listing and entitlement. Only this
        # adapter can report its implementation map or a completed native call.
        record.pop("verifiedAt", None)
        record.pop("verifiedOptions", None)
        record["adapterSupported"] = (
            record["id"] == MODEL
            and record["kind"] == "generation"
            and "text/plain" in record.get("inputModalities", [])
            and "text/plain" in record.get("outputModalities", [])
        )
        if record["id"] == MODEL:
            unknown = (
                set(record.get("unrecognized", []))
                | (set(record.get("tiers", [])) - {"standard", "fast"})
                | (set(record.get("reasoning", [])) - {"off"})
            )
            declared = record.get("parameters", {})
            if isinstance(declared, dict):
                unknown |= set(declared.get("properties", {})) - {"reasoning", "tier"}
            if unknown:
                record["unrecognized"] = sorted(unknown)
        return record

    def snapshot(self, owner, kind, ident, pages):
        key = canonical({"kind": kind, **ident})
        with self.transaction() as db:
            if kind == "catalog":
                r = self.connection(db, owner, ident["scope"]["id"])
                if ident != self.identity(r):
                    raise Refused("denied")
            elif kind != "accounts" or ident != {
                "provider": ISSUER,
                "product": PRODUCT,
                "owner": owner,
            }:
                raise Refused("denied")
            old = db.execute(
                "SELECT value FROM snapshots WHERE owner=? AND context=?", (owner, key)
            ).fetchone()
            previous = json.loads(old[0]) if old else None
            updated = complete_snapshot(previous, pages, ident, kind)
            if updated is previous:
                return False
            if kind == "catalog":
                updated["rows"] = [self.adapter_model(row) for row in updated["rows"]]
            db.execute(
                "INSERT OR REPLACE INTO snapshots VALUES(?,?,?)", (owner, key, canonical(updated))
            )
            if kind == "catalog":
                for model in updated["rows"]:
                    if "eol" in model:
                        notice = model["eol"]
                        # A source in a synthetic owner's published notice namespace is independently allowlisted.
                        if not notice["source"].startswith("urn:ocs:fixture:official-notice:"):
                            raise Refused("input")
                        nid = canonical(
                            [
                                model["id"],
                                notice.get("noticeId", notice["source"]),
                                notice["announcedAt"],
                            ]
                        )
                        db.execute(
                            "INSERT OR IGNORE INTO notices VALUES(?,?,?,?)",
                            (owner, key, nid, canonical(notice)),
                        )
            return True

    def models(self, owner, args, now):
        with self.transaction() as db:
            r = self.connection(db, owner, args["accountId"])
            if args["route"] != ROUTE:
                raise Refused("denied")
            ident = self.identity(r)
            saved = db.execute(
                "SELECT value FROM snapshots WHERE owner=? AND context=?",
                (owner, canonical({"kind": "catalog", **ident})),
            ).fetchone()
            snap = (
                json.loads(saved[0])
                if saved
                else {"rows": self.default_models(), "revision": "local-1"}
            )
            rows = [self.adapter_model(row) for row in snap["rows"]]
            for m in rows:
                if m["id"] == r["last_model"] and r["last_reply"] is not None:
                    m["verifiedAt"] = timestamp(r["last_reply"])
                    m["verifiedOptions"] = [
                        {
                            "parameters": {"reasoning": "off", "tier": r["last_mode"]},
                            "at": timestamp(r["last_reply"]),
                            "evidence": evidence(
                                "urn:ocs:fixture:completed-reply", r["last_reply"]
                            ),
                        }
                    ]
            chunk, extra = self.page(
                db,
                owner,
                {**ident, "observationRevision": digest(rows)},
                snap["revision"],
                rows,
                args.get("pageToken"),
                now,
            )
            return {
                "provider": ISSUER,
                "product": PRODUCT,
                "route": ROUTE,
                "scope": ident["scope"],
                "authMethod": r["auth"],
                "planId": PLAN,
                "region": ident["region"],
                "revision": snap["revision"],
                "complete": not extra,
                "models": chunk,
                "evidence": evidence("urn:ocs:fixture:catalog", now),
                **extra,
            }

    def windows(self, owner, account, now):
        with self.transaction() as db:
            r = self.observe_period(db, self.connection(db, owner, account), now)
            next_week = (now // (7 * 86400) + 1) * 7 * 86400
            unknown = db.execute(
                """SELECT 1 FROM dispatch_reservations d JOIN proposals p ON p.id=d.id
                               WHERE p.owner=? AND p.account=? AND p.applied_at IS NULL""",
                (owner, account),
            ).fetchone()
            e = evidence("urn:ocs:fixture:window-ledger", now)
            entitlement = db.execute(
                "SELECT expires FROM entitlements WHERE owner=? AND org=? AND plan=?",
                (owner, r["org"], PLAN),
            ).fetchone()
            pool = db.execute(
                "SELECT remaining FROM pools WHERE owner=? AND org=?", (owner, r["org"])
            ).fetchone()
            start = now - now % BURST_SECONDS
            used = db.execute(
                "SELECT COUNT(*) FROM meters WHERE meter='reply' AND owner=? AND account=? AND at>=? AND at<?",
                (owner, account, start, start + BURST_SECONDS),
            ).fetchone()[0]
            windows = [
                {
                    "windowId": "weekly",
                    "scope": scope("account", account),
                    "unit": "requests",
                    "period": "P7D",
                    "state": "unknown" if unknown else "known",
                    "resetAt": timestamp(next_week),
                    "models": [MODEL],
                    "evidence": evidence(
                        "urn:ocs:fixture:window-ledger",
                        now,
                        "unknown",
                        "Remote outcome awaits evidence.",
                    )
                    if unknown
                    else e,
                },
                {
                    "windowId": "shared-" + account,
                    "scope": scope("pool", digest(["pool", owner, r["org"]])),
                    "unit": "requests",
                    "period": "P7D",
                    "state": "known",
                    "remaining": str(pool["remaining"]),
                    "total": "500",
                    "resetAt": timestamp(next_week),
                    "evidence": e,
                },
                {
                    "windowId": "burst",
                    "scope": scope("account", account),
                    "unit": "requests",
                    "period": "PT2S",
                    "state": "known",
                    "total": str(BURST_LIMIT),
                    "remaining": str(max(0, BURST_LIMIT - used)),
                    "models": [MODEL],
                    "resetAt": timestamp(start + BURST_SECONDS),
                    "evidence": e,
                },
                {
                    "windowId": "percentage",
                    "scope": scope("model-group", "other"),
                    "unit": "tokens",
                    "period": "P1D",
                    "state": "known",
                    "remainingPercent": 40,
                    "evidence": e,
                },
                {
                    "windowId": "metadata",
                    "scope": scope("product", PRODUCT),
                    "unit": "requests",
                    "state": "unlimited",
                    "evidence": e,
                },
                {
                    "windowId": "optional",
                    "scope": scope("mode", "optional"),
                    "unit": "requests",
                    "state": "unknown",
                    "evidence": evidence(
                        "urn:ocs:fixture:window-ledger",
                        now,
                        "unknown",
                        "No billed limit is published for this mode.",
                    ),
                },
                {
                    "windowId": "old",
                    "scope": scope("model", "retired"),
                    "unit": "requests",
                    "state": "stale",
                    "remaining": "3",
                    "evidence": evidence(
                        "urn:ocs:fixture:window-ledger",
                        now - 86400,
                        "stale",
                        "Last observation belongs to an earlier day.",
                    ),
                },
                {
                    "windowId": "absent",
                    "scope": scope("mode", "audio"),
                    "unit": "seconds",
                    "state": "unsupported",
                    "evidence": evidence(
                        "urn:ocs:fixture:window-ledger",
                        now,
                        "unsupported",
                        "The local text endpoint does not expose this limit.",
                    ),
                },
            ]
            if not unknown:
                windows[0].update({"remaining": str(r["remaining"]), "total": "100"})
            eligible = r["can_write"] and r["credits"] > 0 and now < entitlement["expires"]
            grant = {
                "grantId": "trial",
                "scope": scope("account", account),
                "affectedWindows": ["weekly"],
                "eligibility": "eligible" if eligible else "ineligible",
                "count": r["credits"],
                "charge": {"amount": "0", "currency": "USD"},
                "expiresAt": timestamp(entitlement["expires"]),
                "reason": "One synthetic trial credit per reset.",
                "evidence": e,
            }
            return {"accountId": account, "windows": windows, "resetGrants": [grant], "evidence": e}

    def prices(self, owner, args, now):
        self.check_product(args)
        if args["region"] != "fixture-region":
            raise Refused("unavailable")
        basis = {
            "planId": PLAN,
            "region": args["region"],
            "period": "P30D",
            "basis": "organization",
            "tax": "included",
            "annualTerms": "No annual commitment.",
            "termsUrl": "https://example.invalid/local-terms",
            "evidence": evidence("urn:ocs:fixture:published-terms", now, "reported"),
        }
        rows = [
            {**basis, "status": "published", "price": {"amount": "2.50", "currency": "USD"}},
            {**basis, "planId": "negotiated-price", "status": "by-contract"},
            {**basis, "planId": "unlisted-price", "status": "unpublished"},
        ]
        if "accountId" in args:
            with self.transaction() as db:
                ref = self.connection(db, owner, args["accountId"])
            if ref["ambiguous_price"]:
                return {
                    "plans": [
                        rows[0],
                        {
                            **basis,
                            "planId": "shared-flex",
                            "status": "published",
                            "price": {"amount": "4.75", "currency": "USD"},
                            "termsUrl": "https://example.invalid/local-terms/flex",
                        },
                    ]
                }
            rows.append(
                {
                    **basis,
                    "status": "account-confirmed",
                    "price": {"amount": "0", "currency": "USD"},
                    "evidence": evidence("urn:ocs:fixture:trial-entitlement", now),
                }
            )
        return {"plans": rows}

    @staticmethod
    def meter(
        db,
        owner,
        account,
        meter,
        key,
        interval,
        unit,
        minor,
        quantity,
        kind,
        signature,
        now,
        output,
    ):
        old = db.execute(
            """SELECT * FROM meters WHERE owner=? AND account=? AND meter=? AND interval_id=? AND event_key=?""",
            (owner, account, meter, interval, key),
        ).fetchone()
        action = meter_decision(old is not None, old is not None and old["signature"] == signature)
        if action == "conflict":
            raise Refused("conflict")
        if action == "replay":
            return False, json.loads(old["output"]) if old["output"] is not None else None
        db.execute(
            "INSERT INTO meters VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                owner,
                account,
                meter,
                key,
                interval,
                unit,
                minor,
                quantity,
                kind,
                signature,
                now,
                canonical(output) if output is not None else None,
            ),
        )
        return True, output

    def generate(self, owner, args, key, now, kind="work", conversation=None):
        if not key:
            raise Refused("params")
        account = args["accountId"]
        params = args.get("parameters", {"reasoning": "off", "tier": "standard"})
        with self.transaction() as db:
            r = self.observe_period(db, self.connection(db, owner, account), now)
            e = db.execute(
                "SELECT expires FROM entitlements WHERE owner=? AND org=? AND plan=?",
                (owner, r["org"], PLAN),
            ).fetchone()
            saved = db.execute(
                "SELECT value FROM snapshots WHERE owner=? AND context=?",
                (owner, canonical({"kind": "catalog", **self.identity(r)})),
            ).fetchone()
            listed = json.loads(saved[0])["rows"] if saved else self.default_models()
            listed = [self.adapter_model(row) for row in listed]
            m = next((m for m in listed if m["id"] == args["model"]), {})
            text_ok = all(p["type"] == "text" for p in args["input"])
            supported = bool(m.get("adapterSupported")) and args["model"] == MODEL
            entitled = bool(m.get("entitled")) and now < e["expires"]
            options_ok = (
                set(params) == {"reasoning", "tier"}
                and params["reasoning"] == "off"
                and params["tier"] in ("standard", "fast")
                and params["tier"] in m.get("tiers", [])
                and params["reasoning"] in m.get("reasoning", [])
                and text_ok
                and 1 <= args.get("maxOutputTokens", 1) <= 8
            )
            if not grant_generation(
                bool(r["enabled"]),
                bool(r["signed"]),
                entitled,
                supported,
                args["route"] == ROUTE,
                options_ok,
            ):
                raise Refused("incompatible" if not supported or not options_ok else "denied")
            prompt = " ".join(p["text"] for p in args["input"])
            if len(tokenize(prompt)) > 250:
                raise Refused("input")
            if db.execute(
                """SELECT 1 FROM dispatch_reservations d JOIN proposals p ON p.id=d.id
                          WHERE p.owner=? AND p.account=? AND p.applied_at IS NULL""",
                (owner, account),
            ).fetchone():
                raise Refused("unavailable")
            sent = params.copy()
            try:
                execution = invoke(
                    r["account"],
                    args["route"],
                    args["model"],
                    prompt,
                    sent,
                    args.get("maxOutputTokens", 1),
                )
            except Unsupported as exc:
                raise Refused("output") from exc
            if (
                execution["account"],
                execution["route"],
                execution["model"],
                execution["used"],
            ) != (account, args["route"], args["model"], sent):
                raise Refused("output")
            observed = {
                "accountId": execution["account"],
                "route": execution["route"],
                "model": execution["model"],
                "parts": [{"type": "text", "text": execution["text"]}],
                "sent": sent,
                "confirmed": execution["used"],
                "finish": "end",
                "inputTokens": execution["readTokens"],
                "outputTokens": execution["emittedTokens"],
            }
            sig = digest(
                [owner, args, kind] if conversation is None else [owner, args, kind, conversation]
            )
            first, returned = self.meter(
                db,
                owner,
                account,
                "reply",
                key,
                "account-lifetime",
                "request",
                0,
                1,
                kind,
                sig,
                now,
                observed,
            )
            if first:
                if r["remaining"] <= 0:
                    raise Refused("busy")
                start = now - now % BURST_SECONDS
                used = db.execute(
                    "SELECT COUNT(*) FROM meters WHERE meter='reply' AND owner=? AND account=? AND at>=? AND at<?",
                    (owner, account, start, start + BURST_SECONDS),
                ).fetchone()[0]
                if used > BURST_LIMIT:
                    raise Refused("busy")
                updated = db.execute(
                    "UPDATE pools SET remaining=remaining-1 WHERE owner=? AND org=? AND remaining>0",
                    (owner, r["org"]),
                )
                if updated.rowcount != 1:
                    raise Refused("busy")
                db.execute(
                    "UPDATE accounts SET remaining=remaining-1,revision=revision+1 WHERE account=?",
                    (account,),
                )
                db.execute(
                    "UPDATE connections SET last_model=?,last_mode=?,last_reply=? WHERE account=?",
                    (MODEL, params["tier"], now, account),
                )
                if conversation is not None:
                    # Only this explicitly retained conversation operation stores input contents.
                    db.execute(
                        "INSERT INTO conversation_turns VALUES(?,?,?,?,?,?,?)",
                        (
                            owner,
                            account,
                            conversation,
                            key,
                            canonical(args),
                            canonical(returned),
                            now,
                        ),
                    )
                self.bump(db, owner)
            return returned

    def ingest_meter(self, owner, account, meter, key, interval, quantity, unit_minor, at):
        """Trusted entry for a settled, scoped accounting observation."""
        if (
            type(quantity) is not int
            or quantity < 0
            or type(unit_minor) is not int
            or unit_minor < 0
            or max(quantity, unit_minor, quantity * unit_minor) > 2**53 - 1
        ):
            raise Refused("input")
        with self.transaction() as db:
            if account != "_unattributed":
                self.connection(db, owner, account)
            account_kind = "unattributed" if account == "_unattributed" else "settled"
            sig = digest([owner, account, meter, key, interval, "unit", quantity, unit_minor, at])
            first, _ = self.meter(
                db,
                owner,
                account,
                meter,
                key,
                interval,
                "unit",
                quantity * unit_minor,
                quantity,
                account_kind,
                sig,
                at,
                None,
            )
            return first

    def usage(self, owner, args, now):
        s = args["scope"]
        a, b = seconds(args["from"]), seconds(args["to"])
        if a >= b:
            raise Refused("input")
        with self.transaction() as db:
            if s["kind"] == "account":
                self.connection(db, owner, s["id"])
                extra = " AND account=?"
                where = [owner, a, b, s["id"]]
            elif s == scope("tenant", owner):
                extra = ""
                where = [owner, a, b]
            else:
                raise Refused("denied")
            rows = db.execute(
                "SELECT at,kind,quantity,amount_minor FROM meters WHERE owner=? AND at>=? AND at<?"
                + extra,
                where,
            ).fetchall()
            work = [r for r in rows if r["kind"] == "work"]
            return {
                "scope": s,
                "from": args["from"],
                "to": args["to"],
                "workRequests": len(work),
                "successful": len(work),
                "probeRequests": sum(r["kind"] == "probe" for r in rows),
                "fallbackUses": sum(r["kind"] == "fallback" for r in rows),
                "activeDays": len({r["at"] // 86400 for r in work}),
                "attribution": "partial"
                if any(r["kind"] == "unattributed" for r in rows)
                else "account",
                "spend": {
                    "amount": str(Decimal(sum(r["amount_minor"] for r in rows)) / 100),
                    "currency": "USD",
                },
                "retainedUntil": timestamp(now + RETENTION),
                "evidence": evidence("urn:ocs:fixture:scoped-meters", now),
                **({"lastUsedAt": timestamp(max(r["at"] for r in work))} if work else {}),
            }

    def terms(self, owner, account, now):
        with self.transaction() as db:
            r = self.connection(db, owner, account)
            e = db.execute(
                "SELECT * FROM entitlements WHERE owner=? AND org=? AND plan=?",
                (owner, r["org"], PLAN),
            ).fetchone()
            return {
                "scope": scope("account", account),
                "organization": r["org"],
                "owner": owner,
                "plan": PLAN,
                "billingPlanCandidates": [PLAN, "shared-flex"] if r["ambiguous_price"] else [PLAN],
                "billingPlanKnown": not bool(r["ambiguous_price"]),
                "currency": "USD",
                "period": "P30D",
                "basis": "organization",
                "expiresAt": timestamp(e["expires"]),
                "expiry": "Deny generation and reset after the term.",
                "support": "Local fixture operator.",
                "continuity": "Restore a consistent SQLite backup on a local filesystem.",
                "retentionSeconds": RETENTION,
                "retentionPolicy": "At least 90 days of local usage evidence; intent and replay keys survive until the owning database is retired.",
                "distribution": "Release-owned repository image; upgrade to an admitted immutable revision.",
                "catalogVisibility": "Published project terms and tenant-scoped account catalog.",
                "exportPolicy": "Read own observations. Administrative whole-store backup requires the database owner.",
                "deletionPolicy": "Archive local routing; organization entitlement and replay history survive.",
                "source": "urn:ocs:fixture:terms",
                "observedAt": timestamp(now),
            }

    def current_models(self, db, owner, account):
        key = canonical({"kind": "catalog", **self.identity(account)})
        saved = db.execute(
            "SELECT value FROM snapshots WHERE owner=? AND context=?", (owner, key)
        ).fetchone()
        rows = json.loads(saved[0])["rows"] if saved else self.default_models()
        return [self.adapter_model(row) for row in rows]

    def plan_observation(self, owner, account, ambiguous):
        """Trusted billing observer records whether the source distinguished its plan."""
        with self.transaction() as db:
            r = self.connection(db, owner, account)
            if ambiguous:
                db.execute(
                    "INSERT OR IGNORE INTO pricing_uncertainty VALUES(?,?)", (owner, r["org"])
                )
            else:
                db.execute(
                    "DELETE FROM pricing_uncertainty WHERE owner=? AND org=?", (owner, r["org"])
                )
            self.bump(db, owner)

    def selected(self, owner, account, now, choice=None):
        with self.transaction() as db:
            r = self.connection(db, owner, account)
            models = self.current_models(db, owner, r)
            if choice is not None:
                m = next((m for m in models if m["id"] == choice["model"]), None)
                if (
                    choice["route"] != ROUTE
                    or m is None
                    or not m["entitled"]
                    or not m["adapterSupported"]
                ):
                    raise Refused("denied")
                parameters = choice["parameters"]
                if (
                    set(parameters) != {"reasoning", "tier"}
                    or parameters["reasoning"] not in m.get("reasoning", [])
                    or parameters["tier"] not in m.get("tiers", [])
                ):
                    raise Refused("incompatible")
                db.execute(
                    "INSERT OR REPLACE INTO selections VALUES(?,?,?,?,?,?)",
                    (owner, account, m["id"], ROUTE, canonical(parameters), now),
                )
            row = db.execute(
                "SELECT * FROM selections WHERE owner=? AND account=?", (owner, account)
            ).fetchone()
            if row is None:
                return {"selection": None, "advertisedNow": False, "notices": []}
            sel = {
                "accountId": account,
                "route": row["route"],
                "model": row["model"],
                "parameters": json.loads(row["parameters"]),
                "chosenAt": timestamp(row["chosen_at"]),
            }
            ctx = canonical({"kind": "catalog", **self.identity(r)})
            notices = []
            for n in db.execute(
                "SELECT identity,body FROM notices WHERE owner=? AND context=? ORDER BY identity",
                (owner, ctx),
            ):
                model, _, _ = json.loads(n["identity"])
                if model == sel["model"]:
                    notices.append({"notice": json.loads(n["body"]), "affectedSelection": sel})
            visible = any(m["id"] == sel["model"] for m in models)
            return {"selection": sel, "advertisedNow": visible, "notices": notices}

    def conversation(self, owner, args, now, key=None, purpose="work"):
        account = args["accountId"]
        context = args["contextId"]
        if "text" in args:
            pick = self.selected(owner, account, now)["selection"]
            if not pick:
                raise Refused("incompatible")
            return self.generate(
                owner,
                {
                    "accountId": account,
                    "route": pick["route"],
                    "model": pick["model"],
                    "parameters": pick["parameters"],
                    "input": [{"type": "text", "text": args["text"]}],
                },
                key,
                now,
                purpose,
                conversation=context,
            )
        with self.transaction() as db:
            self.connection(db, owner, account)
            rows = db.execute(
                "SELECT * FROM conversation_turns WHERE owner=? AND account=? AND context=? ORDER BY rowid",
                (owner, account, context),
            )
            return {
                "accountId": account,
                "contextId": context,
                "turns": [
                    {
                        "requestId": r["request_key"],
                        "at": timestamp(r["at"]),
                        "input": json.loads(r["input"]),
                        "output": json.loads(r["result"]),
                    }
                    for r in rows
                ],
            }

    def overview(self, owner, now, query=None):
        query = query or {}
        selected_model = query.get("model", MODEL)
        zone = query.get("timeZone", "UTC")
        try:
            offset = re.fullmatch(r"UTC([+-])(\d{2}):(\d{2})", zone)
            if offset:
                h, m = map(int, offset.group(2, 3))
                if h > 14 or m > 59 or (h == 14 and m != 0):
                    raise Refused("input")
                location = timezone(
                    timedelta(minutes=(h * 60 + m) * (1 if offset[1] == "+" else -1))
                )
            else:
                location = timezone.utc if zone == "UTC" else ZoneInfo(zone)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise Refused("input") from exc
        with self.transaction() as db:
            ids = [
                r[0]
                for r in db.execute(
                    "SELECT a.account FROM accounts a JOIN connections c USING(account) WHERE owner=? AND archived=0 ORDER BY a.account",
                    (owner,),
                )
            ]
            all_records = {}
            for account in ids:
                r = self.observe_period(db, self.connection(db, owner, account), now)
                view = self.account_view(r, now)
                models = self.current_models(db, owner, r)
                usable = {
                    (m["id"], tier, reasoning)
                    for m in models
                    for tier in m.get("tiers", [])
                    for reasoning in m.get("reasoning", [])
                    if m["id"] == MODEL
                    and m.get("entitled")
                    and m.get("adapterSupported")
                    and tier in ("standard", "fast")
                    and reasoning == "off"
                }
                permitted = usable if view["state"] in ("working", "unverified") else set()
                all_records[account] = (
                    view,
                    r["org"],
                    bool(r["ambiguous_price"]),
                    {m["id"] for m in models},
                    usable,
                    permitted,
                )
        rows = []
        pools = []
        organizations = set()
        ambiguous_orgs = set()
        for account, (view, org, ambiguous, listed, usable, permitted) in all_records.items():
            if (
                query.get("provider", ISSUER) != ISSUER
                or query.get("status", view["state"]) != view["state"]
                or ("model" in query and selected_model not in listed)
            ):
                continue
            rows.append(view)
            organizations.add(org)
            if ambiguous:
                ambiguous_orgs.add(org)
            win = self.windows(owner, account, now)["windows"]
            pools.extend(win)
            model_usable = any(x[0] == selected_model for x in usable)
            relevant = [
                w
                for w in win
                if w["unit"] == "requests"
                and model_usable
                and (
                    selected_model in w.get("models", [])
                    or (w["scope"]["kind"] == "pool" and not w.get("models"))
                )
            ]
            uncertain = next(
                (w for w in relevant if w["state"] in ("unknown", "stale", "unsupported")), None
            )
            known = [w for w in relevant if w["state"] == "known" and "remaining" in w]
            limiting = uncertain or (
                min(known, key=lambda w: Decimal(w["remaining"]))
                if known
                else {
                    "windowId": "unverified",
                    "scope": scope("model", selected_model),
                    "unit": "requests",
                    "state": "unknown",
                    "evidence": evidence(
                        "urn:ocs:fixture:catalog",
                        now,
                        "unknown",
                        "No confirmed applicable request window.",
                    ),
                }
            )
            view["selectedModel"] = selected_model
            view["limitingWindow"] = limiting
            view["timeZone"] = zone
            moment = seconds(limiting["resetAt"]) if limiting.get("resetAt") else None
            view["secondsUntilReset"] = max(0, int(moment - now)) if moment is not None else None
            view["resetAtLocal"] = (
                datetime.fromtimestamp(moment, location).isoformat(timespec="seconds")
                if moment is not None
                else None
            )
            alternatives = set().union(
                *(item[5] for k, item in all_records.items() if k != account)
            )
            modes = sorted(permitted - alternatives)
            view["disableImpact"] = sorted({m for m, _, _ in modes})
            view["disableImpactModes"] = [
                {"model": m, "tier": tier, "reasoning": reasoning} for m, tier, reasoning in modes
            ]
            view["usage"] = {
                str(days): self.usage(
                    owner,
                    {
                        "scope": scope("account", account),
                        "from": timestamp(now + 1 - days * 86400),
                        "to": timestamp(now + 1),
                    },
                    now,
                )
                for days in (7, 30)
            }
        known_keys = {("pool", digest(["pool", owner, org])) for org in organizations}
        total = independent_total(pools, "requests", "P7D", known_keys)
        counts = {
            "count": len(rows),
            "enabled": sum(a["enabled"] for a in rows),
            "working": sum(a["state"] == "working" for a in rows),
            "attention": sum(a["state"] not in ("working", "disabled") for a in rows),
            "unit": "accounts",
        }
        return {
            "provider": ISSUER,
            "accounts": rows,
            **counts,
            "totalOwned": len(ids),
            "filter": dict(query),
            "groups": [{"provider": ISSUER, "product": PRODUCT, **counts}] if rows else [],
            "sharedPoolRemaining": total["remaining"],
            "sharedPools": total["pools"],
            "observedAt": timestamp(now),
            "organizationPlans": len(organizations),
            "unknownOrganizationPrices": len(ambiguous_orgs),
            "listPriceTotal": None
            if ambiguous_orgs
            else {"amount": str(Decimal("2.50") * len(organizations)), "currency": "USD"},
            "confirmedPriceTotal": None if ambiguous_orgs else {"amount": "0", "currency": "USD"},
        }

    def backup(self, destination):
        destination = Path(destination)
        if destination.exists() or destination.resolve() == Path(self.path).resolve():
            raise Refused("conflict")
        with closing(sqlite3.connect(self.path)) as src:
            required = (
                src.execute("PRAGMA page_size").fetchone()[0]
                * src.execute("PRAGMA page_count").fetchone()[0]
            )
            available = shutil.disk_usage(destination.parent).free
            if required > available:
                raise Refused("busy")
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as staged:
                stage = Path(staged.name)
            try:
                with closing(sqlite3.connect(stage)) as target:
                    src.backup(target)
                    if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise Refused("unavailable")
                # Atomic publish without replacing another operator's successful backup.
                try:
                    os.link(stage, destination)
                except FileExistsError as exc:
                    raise Refused("conflict") from exc
            finally:
                stage.unlink(missing_ok=True)
        return {
            "bytes": destination.stat().st_size,
            "sourceBytes": Path(self.path).stat().st_size,
            "requiredBytes": required,
            "availableBytesBeforeBackup": available,
        }
