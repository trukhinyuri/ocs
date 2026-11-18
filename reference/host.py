#!/usr/bin/env python3
"""Small, explicit read binding for a reviewed package in a development environment."""

import argparse
import hashlib
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

from admission import check_manifest
from contracts import LIMIT, ROOT, pointer, read_json, utc_at, validate, validate_with
from jsonschema import ValidationError


class Failure(Exception):
    def __init__(self, code, kind, message, path=None):
        super().__init__(message)
        self.error = {"code": code, "message": message, "data": {"kind": kind}}
        if path is not None:
            self.error["data"]["path"] = path


class Channel:
    def __init__(self, entry, budget):
        self.process = subprocess.Popen(
            [sys.executable, "-I", str(entry)],
            cwd=entry.parent,
            env={},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self.end = time.monotonic() + budget
        self.sequence = 0
        self.buffer = bytearray()
        self.limit = LIMIT

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()

    def request(self, method, params):
        self.sequence += 1
        rid = str(self.sequence)
        frame = (
            json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        if len(frame) - 1 > self.limit:
            raise Failure(-32003, "busy", "Frame budget exceeded.")
        # The fixture sends small read requests. A stalled process cannot hold this host's writer.
        fd = self.process.stdin.fileno()
        os.set_blocking(fd, False)
        rest = memoryview(frame)
        while rest:
            remaining = self.end - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise Failure(-33005, "deadline", "Executor write timed out.")
            try:
                rest = rest[os.write(fd, rest) :]
            except BlockingIOError:
                continue
            except BrokenPipeError as exc:
                raise Failure(-32004, "unavailable", "Executor closed its input.") from exc
        while b"\n" not in self.buffer:
            remaining = self.end - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise Failure(-33005, "deadline", "Executor read timed out.")
            chunk = os.read(
                self.process.stdout.fileno(), min(65536, self.limit + 1 - len(self.buffer))
            )
            if not chunk:
                raise Failure(-32004, "unavailable", "Executor closed its output.")
            self.buffer.extend(chunk)
            if len(self.buffer) > self.limit and b"\n" not in self.buffer:
                raise Failure(-32001, "output", "Response is too large.")
        line, _, tail = self.buffer.partition(b"\n")
        self.buffer = bytearray(tail)
        if len(line) > self.limit:
            raise Failure(-32001, "output", "Response exceeds the negotiated frame limit.")
        try:
            reply = read_json(bytes(line))
            validate("wire", reply, "failure" if "error" in reply else "success")
        except (ValidationError, ValueError, TypeError, RecursionError) as exc:
            raise Failure(-32001, "output", "Invalid response envelope.") from exc
        if reply["id"] != rid:
            raise Failure(-32001, "output", "Wrong response identifier.")
        if time.monotonic() >= self.end:
            raise Failure(-33005, "deadline", "Reply arrived after deadline.")
        if "error" in reply:
            err = reply["error"]
            raise Failure(err["code"], err["data"]["kind"], err["message"], err["data"].get("path"))
        return reply["result"]


def status(manifest_path, resource, deadline=None, expected_pin=None):
    manifest_path = Path(manifest_path).resolve()
    raw = manifest_path.read_bytes()
    pin = hashlib.sha256(raw).hexdigest()
    if expected_pin is not None and pin != expected_pin:
        raise Failure(-33014, "pin", "Admitted descriptor changed.")
    descriptor = read_json(raw)
    check_manifest(descriptor)
    if descriptor.get("requiresFeatures") or any(
        not dep.get("optional", False) for dep in descriptor.get("imports", [])
    ):
        raise Failure(
            -33008, "incompatible", "The sealed read binding cannot satisfy these requirements."
        )
    op = next(
        (
            o
            for o in descriptor["exports"]
            if (o["id"], o["version"]) == ("example.status.read", "1.0.0")
        ),
        None,
    )
    if op is None or op["effect"] != "read" or op.get("flags") or descriptor.get("needs"):
        raise Failure(-33001, "denied", "Only the reviewed read operation is allowed.")
    if descriptor["id"] != "org.example.status" or descriptor["version"] != "0.1.0":
        raise Failure(-33014, "pin", "Unbound package identity.")
    if descriptor["runtime"] != {"binding": "stdio", "entry": "executor.py", "engine": "python3"}:
        raise Failure(-33008, "incompatible", "Unsupported runtime.")
    entry = manifest_path.parent / "executor.py"
    if entry.is_symlink() or not entry.is_file():
        raise Failure(-33001, "denied", "Untrusted entry.")
    payload = {"resourceId": resource}
    try:
        validate_with(op["inputSchema"], payload)
    except ValidationError as exc:
        raise Failure(-33009, "input", "Invalid input.", pointer(exc)) from exc
    if resource != "demo":
        raise Failure(-33001, "denied", "No grant for this resource.")
    expires = min(deadline if deadline is not None else time.time() + 5, time.time() + 5)
    budget = expires - time.time()
    if budget <= 0:
        raise Failure(-33005, "deadline", "Expired request.")
    stamp = utc_at(expires)
    channel = Channel(entry, budget)
    try:
        desc = channel.request(
            "ocs.describe",
            {"protocols": ["0.1"], "requiredFeatures": [], "meta": {"deadline": stamp}},
        )
        try:
            validate("wire", desc, "describeResult")
        except ValidationError as exc:
            raise Failure(-32001, "output", "Invalid negotiation result.") from exc
        if (desc["packageId"], desc["packageVersion"], desc["manifestDigest"]) != (
            descriptor["id"],
            descriptor["version"],
            pin,
        ):
            raise Failure(-33014, "pin", "Executor did not match the admitted descriptor.")
        channel.limit = min(LIMIT, desc["maxFrameBytes"])
        result = channel.request(
            "tool.call",
            {
                "operation": op["id"],
                "version": op["version"],
                "input": payload,
                "meta": {"deadline": stamp, "protocol": "0.1", "manifestDigest": pin},
            },
        )
        try:
            validate("wire", result, "callResult")
            validate_with(op["outputSchema"], result["data"])
        except ValidationError as exc:
            raise Failure(-32001, "output", "Invalid operation result.", pointer(exc)) from exc
        if result["data"]["resourceId"] != resource:
            raise Failure(-32001, "output", "Result belongs to another resource.")
        return result["data"]
    finally:
        channel.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "examples/status/ocs.json")
    parser.add_argument("--resource", default="demo")
    args = parser.parse_args()
    try:
        print(json.dumps(status(args.manifest, args.resource)))
    except Failure as exc:
        print(json.dumps(exc.error), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, ValidationError) as exc:
        print(
            json.dumps({"error": "invalid development package", "detail": str(exc)[:150]}),
            file=sys.stderr,
        )
        raise SystemExit(2)
