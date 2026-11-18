#!/usr/bin/env python3
"""Run the sealed interaction profiles on an authenticated loopback HTTP endpoint."""

import argparse
import http.server
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path

from client import Caller, CallError
from jsonschema import ValidationError
from service import FRAME, PIN, Host, Principal, Refusal, encode, read_json, validate


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, db, keys, port=0, commit_delay_ms=0, connection_ms=6000, relay_delay_ms=0):
        self.host = Host(str(db), commit_delay_ms)
        if not 80 <= connection_ms <= 7000 or not 0 <= relay_delay_ms <= 1000:
            raise ValueError("invalid fixture time bound")
        self.connection_seconds = connection_ms / 1000
        self.relay_delay = relay_delay_ms / 1000
        self.lifetimes = {}
        self.lifetime_lock = threading.Lock()
        self.identities = dict(keys)
        self.delegations = {}
        self.callbacks = {}
        for actor in keys.values():
            if actor.owner not in self.delegations:
                token = secrets.token_hex(24)
                self.delegations[actor.owner] = token
                self.identities[token] = Principal(actor.owner, relay=True)
                callback = secrets.token_hex(24)
                self.callbacks[actor.owner] = callback
                self.identities[callback] = Principal(actor.owner, callback=True)
        self.host.forward = self.forward
        self.host.callback = self.callback
        self.work = threading.BoundedSemaphore(12)
        super().__init__(("127.0.0.1", port), Handler)

    def server_close(self):
        self.host.privacy.close()
        super().server_close()

    def callback(self, owner, expected_session, rid, expires):
        client = Caller(f"http://127.0.0.1:{self.server_port}/ocs", self.callbacks[owner])
        reply = client.request(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.peers/0.1"],
                "meta": {"deadline": expires},
            },
        )
        if reply["manifestDigest"] != PIN or client.session != expected_session:
            raise Refusal("pin", "Callback target changed.")
        result = client.request(
            "tool.call",
            {
                "operation": "example.callback.observe",
                "version": "1.0.0",
                "input": {},
                "meta": {"deadline": expires, "manifestDigest": PIN, "protocol": "0.1"},
            },
            rid=rid,
        )
        return {
            "outboundId": rid,
            "returned": result["data"],
            "channel": "separate-authenticated-return",
        }

    def reject_broker_content(self, message):
        wire = encode(message)
        if b"fixture-secret-redaction" in wire or any(
            tok.encode() in wire for tok in self.identities
        ):
            raise Refusal("denied", "Broker secrets cannot be supplied to an agent.")

    def forward(self, owner, expected_session, message, expires):
        self.reject_broker_content(message)
        if self.relay_delay:
            time.sleep(self.relay_delay)
        downstream = Caller(f"http://127.0.0.1:{self.server_port}/ocs", self.delegations[owner])
        try:
            desc = downstream.request(
                "ocs.describe",
                {
                    "protocols": ["0.1"],
                    "requiredFeatures": ["ocs.agents/0.1"],
                    "meta": {"deadline": expires},
                },
            )
            if desc["manifestDigest"] != PIN or downstream.session != expected_session:
                raise Refusal("pin", "The selected downstream session changed.")
            reply = downstream.request(
                "tool.call",
                {
                    "operation": "agent.exchange",
                    "version": "1.0.0",
                    "input": message,
                    "meta": {"protocol": "0.1", "manifestDigest": PIN, "deadline": expires},
                },
            )
        except CallError as exc:
            raise Refusal(
                exc.kind if exc.kind in Refusal.CODES else "unavailable",
                "Selected agent refused the relay.",
            ) from exc
        return {
            "message": reply["data"]["message"],
            "relayBytes": downstream.body_bytes,
            "forwardedDeadline": expires,
        }

    def handle_error(self, req, addr):
        import sys

        if not isinstance(sys.exc_info()[1], (ConnectionError, OSError)):
            super().handle_error(req, addr)

    def process_request(self, req, addr):
        req.settimeout(5)
        if not self.work.acquire(blocking=False):
            try:
                req.sendall(b"HTTP/1.1 503 Busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(req)
            return

        def expire():
            try:
                req.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(self.connection_seconds, expire)
        timer.daemon = True
        with self.lifetime_lock:
            self.lifetimes[req] = timer
        timer.start()
        try:
            super().process_request(req, addr)
        except BaseException:
            with self.lifetime_lock:
                self.lifetimes.pop(req).cancel()
            self.work.release()
            raise

    def process_request_thread(self, req, addr):
        try:
            super().process_request_thread(req, addr)
        finally:
            with self.lifetime_lock:
                self.lifetimes.pop(req).cancel()
            self.work.release()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def respond(self, code, body=b"", mime="application/json", session=None):
        self.send_response(code)
        self.send_header("Content-Type", mime)
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
            return self.respond(404)
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return self.respond(403)
        token = authorization[7:]
        actor = self.server.identities.get(token)
        if not actor:
            return self.respond(403)
        if self.headers.get_content_type() != "application/json":
            return self.respond(415)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.respond(411)
        if length < 1 or length > FRAME:
            return self.respond(413)
        host = self.server.host
        rid = None
        notify = False
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.respond(400)
            try:
                req = read_json(raw)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise Refusal("parse", "Invalid wire data.") from exc
            if (
                isinstance(req, dict)
                and isinstance(req.get("id"), str)
                and 1 <= len(req["id"]) <= 128
            ):
                rid = req["id"]
            notify = isinstance(req, dict) and "id" not in req
            try:
                validate("wire", req, "notification" if notify else "request")
            except ValidationError as exc:
                raise Refusal("request", "Invalid envelope.") from exc
            method, params = req["method"], req["params"]
            session = self.headers.get("OCS-Session", "")
            if (actor.relay or actor.callback) and (
                notify
                or (
                    method != "ocs.describe"
                    and (
                        method != "tool.call"
                        or not isinstance(params, dict)
                        or params.get("operation")
                        != ("agent.exchange" if actor.relay else "example.callback.observe")
                    )
                )
            ):
                raise Refusal("denied", "Restricted downstream capability.")
            if notify:
                if method in ("ocs.cancel", "ocs.credit"):
                    host.control(actor, session, method, params)
                return self.respond(204)
            if method == "ocs.describe":
                data = host.describe(params)
                return self.respond(
                    200,
                    encode({"jsonrpc": "2.0", "id": rid, "result": data}),
                    session=host.session(actor),
                )
            if method == "stream.open":
                if self.headers.get("Accept") != "text/event-stream":
                    raise Refusal(
                        "incompatible", "Negotiate the supported event-stream representation."
                    )
                transfer = host.open_stream(actor, session, rid, params)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for tag, data in transfer.frames():
                        payload = encode(data)
                        if len(payload) > FRAME:
                            raise ValueError("response exceeds stream frame budget")
                        self.wfile.write(
                            b"event: " + tag.encode() + b"\ndata: " + payload + b"\n\n"
                        )
                        self.wfile.flush()
                except (ConnectionError, socket.timeout):
                    pass
                finally:
                    host.close_stream(transfer)
                    self.close_connection = True
                return
            if method == "tool.call" and params.get("operation") == "agent.exchange":
                self.server.reject_broker_content(params.get("input"))
            result = host.rpc(actor, session, method, params, rid)
            body = encode({"jsonrpc": "2.0", "id": rid, "result": result})
            if len(body) > FRAME:
                raise Refusal("busy", "Response frame budget exhausted.")
            self.respond(200, body)
        except (Refusal, ValidationError) as err:
            fault = (
                err
                if isinstance(err, Refusal)
                else Refusal("params", "Invalid protocol parameters.")
            )
            if notify:
                self.respond(403 if fault.kind == "denied" else 400)
            else:
                self.respond(200, encode({"jsonrpc": "2.0", "id": rid, "error": fault.error()}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument(
        "--port", type=int, default=0, help="numeric loopback port; zero requests an available port"
    )
    p.add_argument(
        "--commit-delivery-ms",
        type=int,
        default=0,
        help="host-selected bounded post-commit delivery delay for the local fixture",
    )
    p.add_argument(
        "--connection-ms",
        type=int,
        default=6000,
        help="total socket lifetime cap, including incomplete headers or body",
    )
    p.add_argument(
        "--relay-delay-ms",
        type=int,
        default=0,
        help="host-selected pre-forward delay for deadline qualification",
    )
    opts = p.parse_args()
    keys = json.loads(os.environ["OCS_FIXTURE_IDENTITIES"])
    if (
        not isinstance(keys, dict)
        or not keys
        or any(not k or not isinstance(v, dict) for k, v in keys.items())
    ):
        p.error("configured fixture identities are required")
    actors = {k: Principal(**v) for k, v in keys.items()}
    with Server(
        opts.database,
        actors,
        opts.port,
        opts.commit_delivery_ms,
        opts.connection_ms,
        opts.relay_delay_ms,
    ) as server:
        print(json.dumps({"host": "127.0.0.1", "port": server.server_port}), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
