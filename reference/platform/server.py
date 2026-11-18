#!/usr/bin/env python3
"""Serve the isolated POSIX reference product over authenticated loopback JSON-RPC."""

import argparse
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cell import (
    EXPORTS,
    FRAME,
    MANIFEST,
    PIN,
    Actor,
    Cell,
    Refusal,
    canonical,
    read_json,
    validate,
)
from contracts import validate_with
from jsonschema import ValidationError


class Endpoint(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cell, identities, port):
        self.cell = cell
        self.identities = identities
        cell.init_owners(identities.values())
        self.session_secret = secrets.token_bytes(32)
        self.connections = threading.BoundedSemaphore(12)
        super().__init__(("127.0.0.1", port), Handler)

    def session(self, token, epoch):
        return hmac.new(self.session_secret, f"{token}/{epoch}".encode(), "sha256").hexdigest()

    def process_request(self, req, addr):
        req.settimeout(5)
        if not self.connections.acquire(blocking=False):
            try:
                req.sendall(b"HTTP/1.1 503 Busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(req)
            return
        try:
            super().process_request(req, addr)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, req, addr):
        try:
            super().process_request_thread(req, addr)
        finally:
            self.connections.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, code, body=b"", session=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if session:
            self.send_header("OCS-Session", session)
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        if self.path != "/ocs":
            return self.send(404)
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return self.send(403)
        token = authorization[7:]
        actor = self.server.identities.get(token)
        if actor is None:
            return self.send(403)
        if self.headers.get_content_type() != "application/json":
            return self.send(415)
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send(411)
        if not 0 < n <= FRAME:
            return self.send(413)
        rid = None
        try:
            try:
                msg = read_json(self.rfile.read(n))
            except (RecursionError, ValueError, UnicodeError) as exc:
                raise Refusal("parse", "Invalid JSON.") from exc
            if (
                isinstance(msg, dict)
                and isinstance(msg.get("id"), str)
                and 0 < len(msg["id"]) <= 128
            ):
                rid = msg["id"]
            if isinstance(msg, dict) and "id" not in msg:
                validate("wire", msg, "notification")
                return self.send(204)
            try:
                validate("wire", msg, "request")
            except ValidationError as exc:
                raise Refusal("request", "Invalid request envelope.") from exc
            method, p = msg["method"], msg["params"]
            if method not in ("ocs.describe", "tool.call"):
                raise Refusal("method", "Unknown RPC.")
            validate("wire", p, "describeParams" if method == "ocs.describe" else "callParams")
            deadline = p["meta"]["deadline"]
            left = min(
                5, datetime.fromisoformat(deadline.replace("Z", "+00:00")).timestamp() - time.time()
            )
            if left <= 0:
                raise Refusal("deadline", "Request expired.")
            expires = time.monotonic() + left
            with self.server.cell.tx() as db:
                epoch = self.server.cell.fence(db, actor, False)["epoch"]
            if method == "ocs.describe":
                if "0.1" not in p["protocols"] or not set(p["requiredFeatures"]) <= set(
                    MANIFEST["features"]
                ):
                    raise Refusal("incompatible", "Incompatible version or feature.")
                result = {
                    "protocol": "0.1",
                    "packageId": MANIFEST["id"],
                    "packageVersion": MANIFEST["version"],
                    "manifestDigest": PIN,
                    "features": MANIFEST["features"],
                    "maxFrameBytes": FRAME,
                }
                return self.send(
                    200,
                    canonical({"jsonrpc": "2.0", "id": rid, "result": result}),
                    self.server.session(token, epoch),
                )
            if not hmac.compare_digest(
                self.server.session(token, epoch), self.headers.get("OCS-Session", "")
            ):
                raise Refusal("denied", "No matching admitted session.")
            actor = replace(actor, epoch=epoch)
            if p["meta"]["manifestDigest"] != PIN:
                raise Refusal("pin", "Descriptor changed.")
            export = EXPORTS.get(p["operation"])
            if not export:
                raise Refusal("method", "Unexported operation.")
            if export["version"] != p["version"]:
                raise Refusal("incompatible", "Unbound contract version.")
            try:
                validate_with(export["inputSchema"], p["input"])
            except ValidationError as exc:
                raise Refusal("input", "Invalid input.") from exc
            result = self.server.cell.dispatch(actor, export["id"], p["input"], deadline, expires)
            try:
                validate_with(export["outputSchema"], result)
            except ValidationError as exc:
                raise Refusal("output", "Unexpected resource result.") from exc
            if time.monotonic() >= expires:
                raise Refusal("deadline", "Late read or independently recoverable local operation.")
            body = canonical({"jsonrpc": "2.0", "id": rid, "result": {"data": result}})
            if len(body) > FRAME:
                raise Refusal("busy", "Response outside frame budget.")
            return self.send(200, body)
        except (OSError, sqlite3.Error):
            error = Refusal(
                "unavailable", "Local storage unavailable. Observe the resource to reconcile."
            ).error()
            return self.send(200, canonical({"jsonrpc": "2.0", "id": rid, "error": error}))
        except (Refusal, ValidationError) as err:
            fault = (
                err
                if isinstance(err, Refusal)
                else Refusal("params", "Invalid control parameters.")
            )
            return self.send(200, canonical({"jsonrpc": "2.0", "id": rid, "error": fault.error()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--peers", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    key = args.trust_key.read_bytes()
    if len(key) < 32:
        parser.error("supply a reviewed snapshot trust key of at least 32 bytes")
    actors = {k: Actor(**a) for k, a in json.loads(os.environ["OCS_CELL_IDENTITIES"]).items()}
    if not actors:
        parser.error("supply configured synthetic identities")
    with Endpoint(Cell(args.directory, key, args.peers), actors, args.port) as endpoint:
        print(json.dumps({"host": "127.0.0.1", "port": endpoint.server_port}), flush=True)
        endpoint.serve_forever()


if __name__ == "__main__":
    main()
