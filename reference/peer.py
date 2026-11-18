#!/usr/bin/env python3
"""Loopback-only receiving host for an explicit, single-resource federation fixture."""

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from admission import check_manifest
from contracts import LIMIT, ROOT, read_json, validate, validate_with
from host import Failure, status
from jsonschema import ValidationError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status_code, reply):
        body = json.dumps(reply, separators=(",", ":")).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.connection.settimeout(5)
        if self.path != "/ocs":
            return self.send(404, {"error": "unknown endpoint"})
        auth = self.headers.get("Authorization", "").encode()
        if not hmac.compare_digest(auth, self.server.credential):
            return self.send(403, {"error": "peer grant denied"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send(411, {"error": "length required"})
        if length < 1 or length > LIMIT:
            return self.send(413, {"error": "frame limit"})
        if self.headers.get_content_type() != "application/json":
            return self.send(415, {"error": "JSON required"})
        rid = None
        try:
            req = read_json(self.rfile.read(length))
            if (
                isinstance(req, dict)
                and isinstance(req.get("id"), str)
                and 1 <= len(req["id"]) <= 128
            ):
                rid = req["id"]
            if isinstance(req, dict) and "id" not in req:
                validate("wire", req, "notification")
                self.send_response(204)
                self.end_headers()
                return
            validate("wire", req, "request")
            method = req["method"]
            if method not in ("ocs.describe", "tool.call"):
                raise Failure(-32601, "method", "Unexported method.")
            params = req["params"]
            try:
                validate(
                    "wire", params, "describeParams" if method == "ocs.describe" else "callParams"
                )
            except ValidationError as exc:
                raise Failure(-32602, "params", "Malformed protocol parameters.") from exc
            expires = dt.datetime.fromisoformat(
                params["meta"]["deadline"].replace("Z", "+00:00")
            ).timestamp()
            if expires <= time.time():
                raise Failure(-33005, "deadline", "Expired request.")
            pin = self.server.descriptor_pin
            if method == "ocs.describe":
                if "0.1" not in params["protocols"] or params["requiredFeatures"]:
                    raise Failure(-33008, "incompatible", "Unsupported protocol or feature.")
                result = {
                    "protocol": "0.1",
                    "packageId": "org.example.status",
                    "packageVersion": "0.1.0",
                    "manifestDigest": pin,
                    "features": [],
                    "maxFrameBytes": LIMIT,
                }
            else:
                if params["meta"]["manifestDigest"] != pin:
                    raise Failure(-33014, "pin", "Descriptor pin changed.")
                if params["operation"] != "example.status.read":
                    raise Failure(-33001, "denied", "Peer grant covers only the status read.")
                if params["version"] != "1.0.0":
                    raise Failure(-33008, "incompatible", "Unsupported operation version.")
                try:
                    validate_with(self.server.operation["inputSchema"], params["input"])
                except ValidationError as exc:
                    raise Failure(
                        -33009, "input", "Invalid resource identifier.", "/resourceId"
                    ) from exc
                result = {
                    "data": status(
                        self.server.manifest_path,
                        params["input"]["resourceId"],
                        expires,
                        expected_pin=pin,
                    )
                }
            reply = {"result": result}
        except Failure as exc:
            reply = {"error": exc.error}
        except ValidationError:
            reply = {
                "error": {
                    "code": -32600,
                    "message": "Invalid request.",
                    "data": {"kind": "request"},
                }
            }
        except (ValueError, UnicodeError, RecursionError):
            reply = {
                "error": {"code": -32700, "message": "Invalid JSON.", "data": {"kind": "parse"}}
            }
        self.send(200, {"jsonrpc": "2.0", "id": rid, **reply})


def start(manifest, token):
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.credential = ("Bearer " + token).encode()
    server.manifest_path = Path(manifest)
    raw = server.manifest_path.read_bytes()
    server.manifest = read_json(raw)
    check_manifest(server.manifest)
    service = next(
        (
            op
            for op in server.manifest["exports"]
            if op["id"] == "example.status.read" and op["version"] == "1.0.0"
        ),
        None,
    )
    if service is None or service["effect"] != "read" or service.get("flags"):
        server.server_close()
        raise ValueError("expected an admitted status read")
    server.operation = service
    server.descriptor_pin = hashlib.sha256(raw).hexdigest()
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=ROOT / "examples/status/ocs.json")
    args = parser.parse_args()
    token = os.getenv("OCS_DEMO_TOKEN")
    if not token:
        parser.error("set a disposable OCS_DEMO_TOKEN for this loopback test")
    with start(args.manifest, token) as server:
        print("http://127.0.0.1:%d/ocs" % server.server_port, flush=True)
        server.serve_forever()
