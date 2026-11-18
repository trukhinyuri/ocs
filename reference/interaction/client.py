"""A bounded caller for the sealed loopback HTTP binding."""

import datetime as dt
import http.client
import ipaddress
import json
import time
from urllib.parse import urlsplit

FRAME = 16384


class CallError(Exception):
    def __init__(self, kind, detail, data=None):
        super().__init__(str(detail))
        self.kind = kind
        self.data = data or {"kind": kind}


def stamp(seconds):
    return (
        dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class Caller:
    def __init__(self, endpoint, key):
        url = urlsplit(endpoint)
        if (
            url.scheme != "http"
            or not ipaddress.ip_address(url.hostname).is_loopback
            or not url.port
            or url.path != "/ocs"
            or url.query
            or url.fragment
            or url.username
            or url.password
        ):
            raise ValueError("this caller requires an explicitly bound numeric loopback URL")
        self.address = url.hostname, url.port
        self.key = key
        self.session = ""
        self.pin = ""
        self.serial = 0
        self.body_bytes = 0

    def meta(self, seconds=5):
        return {
            "protocol": "0.1",
            "manifestDigest": self.pin,
            "deadline": stamp(time.time() + seconds),
        }

    def post(self, request, accept="application/json"):
        connection = http.client.HTTPConnection(*self.address, timeout=7)
        headers = {
            "Content-Type": "application/json",
            "Accept": accept,
            "Authorization": "Bearer " + self.key,
            "OCS-Session": self.session,
        }
        body = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
        connection.request("POST", "/ocs", body, headers)
        try:
            response = connection.getresponse()
            self.body_bytes += len(body) + int(response.getheader("Content-Length", "0"))
            return connection, response
        except BaseException:
            connection.close()
            raise

    def packet(self, raw, rid):
        if len(raw) > FRAME:
            raise CallError("frame", "Response exceeded the selected frame budget.")
        response = json.loads(raw)
        if (
            not isinstance(response, dict)
            or response.get("jsonrpc") != "2.0"
            or response.get("id") != rid
        ):
            raise CallError("correlation", "Invalid response or unexpected request ID.")
        if set(response) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}):
            raise CallError("output", "Expected one result or error.")
        return response

    def request(self, method, params, rid=None):
        self.serial += 1
        rid = rid or f"q{self.serial}"
        conn, res = self.post({"jsonrpc": "2.0", "method": method, "params": params, "id": rid})
        try:
            if res.status != 200:
                raise CallError(f"http-{res.status}", "Request not admitted.")
            raw = res.read(FRAME + 1)
            packet = self.packet(raw, rid)
            if "error" in packet:
                raise CallError(
                    packet["error"]["data"]["kind"],
                    packet["error"]["message"],
                    packet["error"]["data"],
                )
            if method == "ocs.describe":
                self.session = res.getheader("OCS-Session")
                self.pin = packet["result"]["manifestDigest"]
            return packet["result"]
        finally:
            conn.close()

    def describe(self):
        return self.request(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": [],
                "meta": {"deadline": stamp(time.time() + 5)},
            },
        )

    def call(self, op, inp, seconds=5):
        return self.request(
            "tool.call",
            {"operation": op, "version": "1.0.0", "input": inp, "meta": self.meta(seconds)},
        )["data"]

    def notify(self, method, params):
        conn, res = self.post({"jsonrpc": "2.0", "method": method, "params": params})
        try:
            res.read(FRAME + 1)
            return res.status
        finally:
            conn.close()

    def stream(self, rid, credit=1, seconds=3, committed=None):
        inp = {"resourceId": "demo"}
        params = {
            "operation": "example.parts.read",
            "version": "1.0.0",
            "credit": credit,
            "input": inp,
            "meta": self.meta(seconds),
        }
        if committed is not None:
            inp["operationId"] = committed
            params.update(operation="example.parts.committed", operationId=committed)
        conn, res = self.post(
            {"jsonrpc": "2.0", "id": rid, "method": "stream.open", "params": params},
            "text/event-stream",
        )
        if res.getheader("Content-Type") != "text/event-stream":
            try:
                if res.status != 200:
                    raise CallError(f"http-{res.status}", "Stream was not admitted.")
                msg = self.packet(res.read(FRAME + 1), rid)["error"]
                raise CallError(msg["data"]["kind"], msg["message"], msg["data"])
            finally:
                conn.close()
        return conn, res

    @staticmethod
    def sse(response):
        tag = response.readline(128)
        if not tag:
            return None
        data = response.readline(FRAME + 8)
        if (
            not tag.startswith(b"event: ")
            or not data.startswith(b"data: ")
            or response.readline(3) != b"\n"
        ):
            raise CallError("frame", "Malformed SSE event.")
        if not data.endswith(b"\n") or len(data[6:-1]) > FRAME:
            raise CallError("frame", "SSE data exceeded the selected frame budget.")
        return tag[7:].strip().decode(), json.loads(data[6:])
