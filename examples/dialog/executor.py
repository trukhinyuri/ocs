#!/usr/bin/env python3
"""A deterministic message peer with one private random fact per admitted session."""

import hashlib
import json
import math
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

LIMIT = 1_048_576
PIN = hashlib.sha256(Path(__file__).with_name("ocs.json").read_bytes()).hexdigest()
FEATURE = "ocs.agents/0.1"
SCOPE = "demo"
MAX_MESSAGES = 32


class Fault(Exception):
    def __init__(self, code, kind, message):
        self.error = {"code": code, "data": {"kind": kind}, "message": message}


def pairs(items):
    obj = dict(items)
    if len(obj) != len(items):
        raise ValueError("duplicate key")
    return obj


def portable(v):
    if isinstance(v, str):
        v.encode("utf-8")
    elif type(v) in (int, float):
        if not math.isfinite(v) or (v == int(v) and abs(v) > 2**53 - 1):
            raise ValueError("nonportable number")
    elif isinstance(v, dict):
        for k, item in v.items():
            portable(k)
            portable(item)
    elif isinstance(v, list):
        for item in v:
            portable(item)


def string_list(value):
    return (
        isinstance(value, list)
        and all(isinstance(v, str) and v for v in value)
        and len(value) == len(set(value))
    )


class Peer:
    def __init__(self):
        self.ready = False
        self.fact = secrets.token_hex(8)
        self.replies = {}

    def exchange(self, msg):
        # A sealed subset of the message profile. Unsupported modalities are refused.
        if (
            not isinstance(msg, dict)
            or not isinstance(msg.get("messageId"), str)
            or not msg["messageId"]
        ):
            raise Fault(-33009, "input", "A message ID is required.")
        if not set(msg) <= {
            "messageId",
            "contextId",
            "replyTo",
            "parts",
            "kind",
            "senderLabel",
            "purpose",
            "budget",
            "accept",
        }:
            raise Fault(-33009, "input", "Unknown message field.")
        for key in ("contextId", "replyTo", "senderLabel", "purpose"):
            if key in msg and not (isinstance(msg[key], str) and msg[key]):
                raise Fault(-33009, "input", "Invalid message metadata.")
        if "kind" in msg and msg["kind"] not in (
            "request",
            "answer",
            "clarification",
            "partial",
            "authorization-required",
        ):
            raise Fault(-33009, "input", "Invalid message kind.")
        if "accept" in msg and not string_list(msg["accept"]):
            raise Fault(-33009, "input", "Invalid reply media list.")
        parts = msg.get("parts")
        if not isinstance(parts, list) or not parts:
            raise Fault(-33009, "input", "Message parts are required.")
        if len(parts) != 1 or not isinstance(parts[0], dict) or parts[0].get("type") != "text":
            raise Fault(-33008, "incompatible", "This fixture supports one text part.")
        part = parts[0]
        if set(part) != {"type", "text"} or not isinstance(part["text"], str):
            raise Fault(-33009, "input", "Invalid text part.")
        if "accept" in msg and "text/plain" not in msg["accept"]:
            raise Fault(-33008, "incompatible", "Text reply is required.")
        previous = self.replies.get(msg["messageId"])
        if previous is not None:
            if previous[0] != msg:
                raise Fault(-32002, "conflict", "Message ID already identifies different content.")
            return previous[1]
        budget = msg.get("budget", {})
        if not isinstance(budget, dict) or set(budget) - {
            "remainingTurns",
            "remainingBytes",
            "maxFanOut",
            "maxConcurrency",
        }:
            raise Fault(-33008, "incompatible", "Unsupported budget dimension.")
        if any(type(n) is not int or n < 0 for n in budget.values()):
            raise Fault(-33009, "input", "Invalid budget.")
        if budget.get("remainingTurns", 1) < 1 or len(self.replies) >= MAX_MESSAGES:
            raise Fault(-32003, "busy", "Turn or session capacity exhausted.")
        prompt = part["text"]
        if prompt == "Read":
            kind, answer = "clarification", "Which resource?"
        elif prompt == "Read " + SCOPE:
            kind, answer = "answer", self.fact
        elif prompt.startswith("Confirm "):
            kind, answer = "answer", "confirmed" if prompt[8:] == self.fact else "unrecognized"
        else:
            raise Fault(-33001, "denied", "Resource outside the read binding.")
        size = len(prompt.encode()) + len(answer.encode())
        if size > budget.get("remainingBytes", LIMIT):
            raise Fault(-32003, "busy", "Content byte budget exhausted.")
        reply = {
            "messageId": "reply-" + msg["messageId"],
            "replyTo": msg["messageId"],
            "kind": kind,
            "parts": [{"type": "text", "text": answer}],
        }
        if "contextId" in msg:
            reply["contextId"] = msg["contextId"]
        if budget:
            reply["budget"] = dict(budget)
            if "remainingTurns" in budget:
                reply["budget"]["remainingTurns"] -= 1
            if "remainingBytes" in budget:
                reply["budget"]["remainingBytes"] -= size
        result = {"data": {"kind": "message", "message": reply}}
        self.replies[msg["messageId"]] = (msg, result)
        return result

    def dispatch(self, method, p):
        if method not in ("ocs.describe", "tool.call"):
            raise Fault(-32601, "method", "Unknown method.")
        if method == "ocs.describe":
            self.ready = False
        meta = p.get("meta")
        if not isinstance(meta, dict) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
            str(meta.get("deadline")),
        ):
            raise Fault(-32602, "params", "UTC deadline required.")
        try:
            until = datetime.fromisoformat(meta["deadline"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise Fault(-32602, "params", "Invalid date.") from exc
        if datetime.now(timezone.utc) >= until:
            raise Fault(-33005, "deadline", "Deadline elapsed.")
        if method == "ocs.describe":
            if set(p) != {"protocols", "requiredFeatures", "meta"} or set(meta) - {
                "deadline",
                "traceId",
            }:
                raise Fault(-32602, "params", "Invalid negotiation fields.")
            if "traceId" in meta and not (isinstance(meta["traceId"], str) and meta["traceId"]):
                raise Fault(-32602, "params", "Invalid trace identifier.")
            if (
                not string_list(p.get("protocols"))
                or not p["protocols"]
                or not string_list(p.get("requiredFeatures"))
            ):
                raise Fault(-32602, "params", "Malformed negotiation.")
            if "0.1" not in p["protocols"] or any(f != FEATURE for f in p["requiredFeatures"]):
                raise Fault(-33008, "incompatible", "Unsupported feature or protocol.")
            self.ready = True
            return {
                "protocol": "0.1",
                "packageId": "org.example.fact-agent",
                "packageVersion": "0.1.0",
                "manifestDigest": PIN,
                "features": [FEATURE],
                "maxFrameBytes": LIMIT,
            }
        if set(p) != {"operation", "version", "input", "meta"} or not {
            "deadline",
            "protocol",
            "manifestDigest",
        } <= set(meta) <= {
            "deadline",
            "protocol",
            "manifestDigest",
            "traceId",
            "parentCallId",
            "idempotencyKey",
        }:
            raise Fault(-32602, "params", "Unexpected invocation fields.")
        if any(not (isinstance(v, str) and v) for v in meta.values()) or not re.fullmatch(
            r"[0-9a-f]{64}", meta["manifestDigest"]
        ):
            raise Fault(-32602, "params", "Malformed invocation metadata.")
        if not self.ready or meta.get("protocol") != "0.1" or p.get("version") != "1.0.0":
            raise Fault(-33008, "incompatible", "A compatible negotiated binding is required.")
        if meta.get("manifestDigest") != PIN:
            raise Fault(-33014, "pin", "Changed descriptor.")
        if p.get("operation") != "agent.exchange":
            raise Fault(-33001, "denied", "Only message exchange is granted.")
        return self.exchange(p.get("input"))


def main():
    peer = Peer()
    while raw := sys.stdin.buffer.readline(LIMIT + 2):
        if not raw.endswith(b"\n") or len(raw) - 1 > LIMIT:
            return 2
        rid = None
        try:
            req = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
            portable(req)
            if (
                not isinstance(req, dict)
                or req.get("jsonrpc") != "2.0"
                or not isinstance(req.get("method"), str)
                or not req["method"]
                or not isinstance(req.get("params"), dict)
            ):
                raise Fault(-32600, "request", "Invalid request.")
            if "id" not in req and set(req) == {"jsonrpc", "method", "params"}:
                continue
            if isinstance(req.get("id"), str) and 1 <= len(req["id"]) <= 128:
                rid = req["id"]
            if rid is None or set(req) != {"jsonrpc", "method", "params", "id"}:
                raise Fault(-32600, "request", "Invalid request identity or envelope.")
            reply = {"result": peer.dispatch(req["method"], req["params"])}
        except Fault as exc:
            reply = {"error": exc.error}
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            reply = {
                "error": {"code": -32700, "data": {"kind": "parse"}, "message": "Invalid JSON."}
            }
        print(json.dumps({"jsonrpc": "2.0", "id": rid, **reply}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
