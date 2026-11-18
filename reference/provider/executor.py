#!/usr/bin/env python3
"""Run the sealed local provider over OCS stdio. Principal and purpose belong to the host."""

import argparse
import hashlib
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
from contracts import LIMIT, read_json, validate, validate_with
from jsonschema import ValidationError
from policy import permit_invocation
from service import (
    ISSUER,
    PRODUCT,
    ROUTE,
    Provider,
    Refused,
    canonical,
    evidence,
    seconds,
)

RAW = (HERE / "ocs.json").read_bytes()
MANIFEST = read_json(RAW)
PIN = hashlib.sha256(RAW).hexdigest()
EXPORTS = {o["id"]: o for o in MANIFEST["exports"]}
CONTROLS = {
    "effect.prepare": "prepareParams",
    "effect.commit": "commitParams",
    "effect.readback": "opControl",
}
CODES = {
    "parse": -32700,
    "request": -32600,
    "method": -32601,
    "params": -32602,
    "internal": -32603,
    "denied": -33001,
    "deadline": -33005,
    "incompatible": -33008,
    "input": -33009,
    "pin": -33014,
    "output": -32001,
    "conflict": -32002,
    "busy": -32003,
    "unavailable": -32004,
    "unknown_effect": -32005,
}


class Session:
    def __init__(self, db, owner, purpose, delivery, downstream, refresh_failure, clock=None):
        self.store = Provider(db)
        self.owner = owner
        self.purpose = purpose
        self.delivery = delivery
        self.downstream = downstream
        self.refresh_failure = refresh_failure
        self.clock = clock
        self.ready = False

    @classmethod
    def for_http(cls, store, owner, purpose="probe"):
        """An already authenticated HTTP binding. Every invocation is independently pinned."""
        if (
            not isinstance(store, Provider)
            or not isinstance(owner, str)
            or not owner
            or purpose not in ("probe", "work", "fallback")
        ):
            raise ValueError("invalid authenticated provider binding")
        s = cls.__new__(cls)
        s.store = store
        s.owner = owner
        s.purpose = purpose
        s.delivery = "local"
        s.downstream = None
        s.refresh_failure = False
        s.clock = None
        s.ready = True
        return s

    def now(self):
        return int(time.time()) if self.clock is None else self.clock

    def deliver(self, op, digest, owner, account):
        # Independent local authority. The deliberately non-idempotent destination
        # would record a second delivery if the upstream replay guard failed.
        with sqlite3.connect(self.downstream) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS deliveries (op TEXT,digest TEXT,owner TEXT,account TEXT)"
            )
            db.execute("INSERT INTO deliveries VALUES(?,?,?,?)", (op, digest, owner, account))
        return self.delivery == "external-confirmed"

    def run(self, method, p):
        now = self.now()
        if method == "ocs.describe":
            self.ready = False
            self.shape("wire", p, "describeParams")
            if seconds(p["meta"]["deadline"]) <= time.time():
                raise Refused("deadline")
            if "0.1" not in p["protocols"] or not set(p["requiredFeatures"]) <= set(
                MANIFEST["features"]
            ):
                raise Refused("incompatible")
            self.ready = True
            return {
                "protocol": "0.1",
                "packageId": MANIFEST["id"],
                "packageVersion": MANIFEST["version"],
                "manifestDigest": PIN,
                "features": MANIFEST["features"],
                "maxFrameBytes": LIMIT,
            }
        if method not in CONTROLS and method != "tool.call":
            raise Refused("method")
        self.shape(
            "wire" if method == "tool.call" else "profile-wire",
            p,
            "callParams" if method == "tool.call" else CONTROLS[method],
        )
        meta = p["meta"]
        if not self.ready:
            raise Refused("incompatible")
        if meta["manifestDigest"] != PIN:
            raise Refused("pin")
        until = seconds(meta["deadline"])
        if until <= time.time():
            raise Refused("deadline")
        if method in ("tool.call", "effect.prepare"):
            name = p["operation"]
            if p["version"] != "1.0.0":
                raise Refused("incompatible")
            op = EXPORTS.get(name)
            if op is None:
                raise Refused("method")
            try:
                validate_with(op["inputSchema"], p["input"])
            except ValidationError as exc:
                raise Refused("input") from exc
        if method == "effect.prepare":
            if name != "quota.reset":
                raise Refused("incompatible")
            a = p["input"]
            if a["grantId"] != "trial" or a["windows"] != ["weekly"]:
                raise Refused("denied")
            revision = self.store.revision_for_prepare(
                self.owner, a["accountId"], meta["idempotencyKey"]
            )
            result = self.store.prepare(
                self.owner, a["accountId"], meta["idempotencyKey"], PIN, revision, now
            )
            validate("profile-wire", result, "proposal")
            return result
        if method in ("effect.commit", "effect.readback"):
            if method == "effect.readback":
                result = self.store.readback(self.owner, p["operationId"], now)
            else:
                result = self.store.commit(
                    self.owner,
                    p["operationId"],
                    p["intentDigest"],
                    PIN,
                    now,
                    deliver=self.deliver if self.delivery != "local" else None,
                )
            if result["state"] == "applied" and self.refresh_failure:
                result["refreshError"] = "Read-after-write observation is unavailable."
            validate("profile-data", result, "effectReceipt")
            return result
        flags = op.get("flags", [])
        if not permit_invocation(
            op["effect"] == "external-write",
            "monetary" in flags,
            "destructive" in flags,
            "irreversible" in flags,
        ):
            raise Refused("denied")
        a = p["input"]
        if name == "provider.describe":
            result = {
                "provider": ISSUER,
                "product": PRODUCT,
                "routes": [ROUTE],
                "authMethods": [
                    {
                        "id": "local-none",
                        "kind": "local-none",
                        "label": "Local identity",
                        "requirements": [],
                    },
                    {
                        "id": "managed-ticket",
                        "kind": "managed",
                        "label": "Scoped broker handle",
                        "requirements": ["trusted-local-broker"],
                    },
                ],
                "operations": sorted(EXPORTS),
                "evidence": evidence("urn:ocs:fixture:adapter", now),
            }
        elif name == "account.connect":
            result = self.store.connect(self.owner, a, now)
        elif name == "account.continue":
            result = self.store.continue_flow(self.owner, a, now)
        elif name == "account.list":
            result = self.store.accounts(self.owner, a, now)
        elif name.startswith("account."):
            result = self.store.manage(self.owner, name, a, now)
        elif name == "limits.read":
            result = self.store.windows(self.owner, a["accountId"], now)
        elif name == "plans.price":
            result = self.store.prices(self.owner, a, now)
        elif name == "model.list":
            result = self.store.models(self.owner, a, now)
        elif name == "model.generate":
            result = self.store.generate(
                self.owner, a, meta.get("idempotencyKey"), now, self.purpose
            )
        elif name == "example.classify":
            reply = self.store.generate(
                self.owner,
                {
                    "accountId": a["accountId"],
                    "route": a["route"],
                    "model": "reference-colour",
                    "input": [{"type": "text", "text": a["text"]}],
                },
                meta.get("idempotencyKey"),
                now,
                self.purpose,
            )
            result = {
                "accountId": reply["accountId"],
                "route": reply["route"],
                "model": reply["model"],
                "label": reply["parts"][0]["text"],
            }
        elif name == "usage.read":
            result = self.store.usage(self.owner, a, now)
        elif name in ("example.model.select", "example.model.selection"):
            result = self.store.selected(
                self.owner, a["accountId"], now, a if name == "example.model.select" else None
            )
        elif name in ("example.conversation.exchange", "example.conversation.read"):
            result = self.store.conversation(
                self.owner, a, now, meta.get("idempotencyKey"), self.purpose
            )
        elif name == "example.product.terms":
            result = self.store.terms(self.owner, a["accountId"], now)
        elif name == "example.account.overview":
            result = self.store.overview(self.owner, now, a)
        else:
            raise Refused("method")
        try:
            validate_with(op["outputSchema"], result)
        except ValidationError as exc:
            raise Refused("output") from exc
        if op["effect"] == "read" and time.time() >= until:
            raise Refused("deadline")
        return {"data": result}

    @staticmethod
    def shape(schema, value, kind):
        try:
            validate(schema, value, kind)
        except ValidationError as exc:
            raise Refused("params") from exc


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--store", type=Path, required=True)
    args.add_argument("--principal", required=True)
    args.add_argument("--purpose", choices=("work", "probe", "fallback"), default="work")
    args.add_argument(
        "--delivery", choices=("local", "external-lost", "external-confirmed"), default="local"
    )
    args.add_argument("--downstream", type=Path)
    args.add_argument("--refresh-failure", action="store_true")
    args.add_argument(
        "--fixture-clock",
        type=int,
        help="sealed synthetic provider time only; RPC deadlines use wall time",
    )
    o = args.parse_args()
    if o.delivery != "local" and (
        o.downstream is None or o.store.resolve() == o.downstream.resolve()
    ):
        args.error("configure a separate local downstream file")
    session = Session(
        o.store,
        o.principal,
        o.purpose,
        o.delivery,
        o.downstream,
        o.refresh_failure,
        o.fixture_clock,
    )
    while frame := sys.stdin.buffer.readline(LIMIT + 2):
        if not frame.endswith(b"\n") or len(frame) - 1 > LIMIT:
            return 2
        rid = None
        try:
            try:
                msg = read_json(frame[:-1])
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise Refused("parse") from exc
            if (
                isinstance(msg, dict)
                and isinstance(msg.get("id"), str)
                and 1 <= len(msg["id"]) <= 128
            ):
                rid = msg["id"]
            try:
                if isinstance(msg, dict) and "id" not in msg:
                    validate("wire", msg, "notification")
                    continue
                validate("wire", msg, "request")
            except ValidationError as exc:
                raise Refused("request") from exc
            response = {"result": session.run(msg["method"], msg["params"])}
        except Refused as exc:
            kind = str(exc)
            response = {
                "error": {
                    "code": CODES[kind],
                    "message": "Provider " + kind + ".",
                    "data": {"kind": kind},
                }
            }
        except (OSError, sqlite3.Error):
            response = {
                "error": {
                    "code": -32004,
                    "message": "Fixture storage unavailable.",
                    "data": {"kind": "unavailable"},
                }
            }
        except ValidationError:
            response = {
                "error": {
                    "code": -32001,
                    "message": "Invalid fixture output.",
                    "data": {"kind": "output"},
                }
            }
        result = canonical({"jsonrpc": "2.0", "id": rid, **response}).encode()
        if len(result) > LIMIT:
            return 2
        sys.stdout.buffer.write(result + b"\n")
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
