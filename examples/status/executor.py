#!/usr/bin/env python3
"""A sealed, read-only OCS executor for the synthetic resource 'demo'."""

import datetime as dt
import hashlib
import json
import math
import re
import sys
from pathlib import Path

LIMIT = 1_048_576
MAX_INTEGER = (1 << 53) - 1
MANIFEST = Path(__file__).with_name("ocs.json").read_bytes()
DESCRIPTOR = json.loads(MANIFEST)
DIGEST = hashlib.sha256(MANIFEST).hexdigest()
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")


NAME = re.compile(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+")
IDENT = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*)"
VERSION = re.compile(
    rf"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){{2}}(?:-{IDENT}(?:\.{IDENT})*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?"
)


class Fault(Exception):
    def __init__(self, code, kind, message, path=None):
        super().__init__(message)
        self.error = {"code": code, "message": message, "data": {"kind": kind}}
        if path is not None:
            self.error["data"]["path"] = path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def check_values(value):
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif type(value) is int and abs(value) > MAX_INTEGER:
        raise ValueError("integer outside portable range")
    elif isinstance(value, float) and (
        not math.isfinite(value) or (value.is_integer() and abs(value) > (1 << 53) - 1)
    ):
        raise ValueError("nonportable number")
    elif isinstance(value, dict):
        for key, item in value.items():
            check_values(key)
            check_values(item)
    elif isinstance(value, list):
        for item in value:
            check_values(item)


def parse(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    check_values(value)
    return value


def fields(obj, required, optional=(), code=-32602, kind="params"):
    if not isinstance(obj, dict) or not set(required) <= obj.keys() <= set(required) | set(
        optional
    ):
        raise Fault(code, kind, "Unexpected or missing object members.")


def deadline(meta):
    if (
        not isinstance(meta, dict)
        or not isinstance(meta.get("deadline"), str)
        or not STAMP.fullmatch(meta["deadline"])
    ):
        raise Fault(-32602, "params", "Expected a UTC millisecond deadline.", "/meta/deadline")
    try:
        until = dt.datetime.fromisoformat(meta["deadline"][:-1] + "+00:00")
    except ValueError as exc:
        raise Fault(-32602, "params", "Invalid date.", "/meta/deadline") from exc
    if dt.datetime.now(dt.timezone.utc) >= until:
        raise Fault(-33005, "deadline", "The deadline elapsed.")


def strings(value):
    return (
        isinstance(value, list)
        and all(isinstance(x, str) and x for x in value)
        and len(value) == len(set(value))
    )


class Session:
    def __init__(self):
        self.ready = False

    def run(self, method, params):
        if method == "ocs.describe":
            self.ready = False
            fields(params, ["protocols", "requiredFeatures", "meta"])
            fields(params["meta"], ["deadline"], ["traceId"])
            deadline(params["meta"])
            if (
                not strings(params["protocols"])
                or not params["protocols"]
                or not strings(params["requiredFeatures"])
            ):
                raise Fault(-32602, "params", "Invalid negotiation lists.")
            if "traceId" in params["meta"] and not (
                isinstance(params["meta"]["traceId"], str) and params["meta"]["traceId"]
            ):
                raise Fault(-32602, "params", "Invalid trace ID.")
            if any(
                not re.fullmatch(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+/[0-9]+\.[0-9]+", f)
                for f in params["requiredFeatures"]
            ):
                raise Fault(-32602, "params", "Invalid feature identifier.")
            if "0.1" not in params["protocols"] or params["requiredFeatures"]:
                raise Fault(-33008, "incompatible", "No compatible protocol or required feature.")
            self.ready = True
            return {
                "protocol": "0.1",
                "packageId": DESCRIPTOR["id"],
                "packageVersion": DESCRIPTOR["version"],
                "manifestDigest": DIGEST,
                "features": [],
                "maxFrameBytes": LIMIT,
            }
        if method != "tool.call":
            raise Fault(-32601, "method", "Unknown method.")
        fields(params, ["operation", "version", "input", "meta"])
        meta = params["meta"]
        fields(
            meta,
            ["deadline", "protocol", "manifestDigest"],
            ["traceId", "parentCallId", "idempotencyKey"],
        )
        deadline(meta)
        if any(
            not (isinstance(meta[key], str) and meta[key])
            for key in ("traceId", "parentCallId", "idempotencyKey")
            if key in meta
        ):
            raise Fault(-32602, "params", "Invalid correlation metadata.")
        if not isinstance(meta["manifestDigest"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", meta["manifestDigest"]
        ):
            raise Fault(-32602, "params", "Malformed descriptor pin.")
        if (
            not isinstance(params["operation"], str)
            or len(params["operation"]) > 160
            or not NAME.fullmatch(params["operation"])
        ):
            raise Fault(-32602, "params", "Malformed operation ID.")
        if (
            not isinstance(params["version"], str)
            or len(params["version"]) > 128
            or not VERSION.fullmatch(params["version"])
        ):
            raise Fault(-32602, "params", "Malformed contract version.")
        if not self.ready or meta["protocol"] != "0.1":
            raise Fault(-33008, "incompatible", "Negotiate the supported protocol first.")
        if meta["manifestDigest"] != DIGEST:
            raise Fault(-33014, "pin", "The descriptor pin does not match.")
        if params["operation"] != "example.status.read":
            raise Fault(-32601, "method", "Unknown operation.")
        if params["version"] != "1.0.0":
            raise Fault(-33008, "incompatible", "Unsupported contract version.")
        value = params["input"]
        if (
            not isinstance(value, dict)
            or set(value) != {"resourceId"}
            or not isinstance(value.get("resourceId"), str)
            or not 1 <= len(value["resourceId"]) <= 80
        ):
            raise Fault(-33009, "input", "Expected a resource identifier.", "/resourceId")
        if value["resourceId"] != "demo":
            raise Fault(-33001, "denied", "The resource is outside the fixture scope.")
        return {"data": {"resourceId": "demo", "state": "ready"}}


def serve():
    session = Session()
    while raw := sys.stdin.buffer.readline(LIMIT + 2):
        if not raw.endswith(b"\n") or len(raw) - 1 > LIMIT:
            return 2
        rid = None
        try:
            msg = parse(raw[:-1])
            if (
                isinstance(msg, dict)
                and isinstance(msg.get("id"), str)
                and 1 <= len(msg["id"]) <= 128
            ):
                rid = msg["id"]
            if (
                isinstance(msg, dict)
                and "id" not in msg
                and set(msg) == {"jsonrpc", "method", "params"}
                and msg["jsonrpc"] == "2.0"
                and isinstance(msg["method"], str)
                and msg["method"]
                and isinstance(msg["params"], dict)
            ):
                continue
            fields(msg, ["jsonrpc", "id", "method", "params"], code=-32600, kind="request")
            if (
                rid is None
                or msg["jsonrpc"] != "2.0"
                or not isinstance(msg["method"], str)
                or not msg["method"]
                or not isinstance(msg["params"], dict)
            ):
                raise Fault(-32600, "request", "Invalid request envelope.")
            reply = {"result": session.run(msg["method"], msg["params"])}
        except Fault as exc:
            reply = {"error": exc.error}
        except (ValueError, UnicodeError, RecursionError):
            reply = {
                "error": {
                    "code": -32700,
                    "message": "Invalid JSON input.",
                    "data": {"kind": "parse"},
                }
            }
        print(json.dumps({"jsonrpc": "2.0", "id": rid, **reply}, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
