"""A separate, capability-limited HTTPS hop for the three-path inference workload."""

import hmac
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference"))
from bounded_http import BoundedServer
from contracts import LIMIT, read_json, validate
from jsonschema import ValidationError


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("unbound redirect")


class Relay(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, raw):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-OCS-Relay-Pod", os.environ["POD_UID"])
        if hasattr(self, "upstream_sizes"):
            self.send_header("X-OCS-Upstream-Request-Bytes", str(self.upstream_sizes[0]))
            self.send_header("X-OCS-Upstream-Response-Bytes", str(self.upstream_sizes[1]))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.send(200 if self.path == "/health" else 404, b"{}")

    def do_POST(self):
        if self.path != "/ocs":
            return self.send(404, b"{}")
        if not hmac.compare_digest(
            self.headers.get("Authorization", "").encode(), self.server.inbound
        ):
            return self.send(403, b"{}")
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send(411, b"{}")
        if size < 1 or size > LIMIT:
            return self.send(413, b"{}")
        if self.headers.get_content_type() != "application/json":
            return self.send(415, b"{}")
        try:
            raw = self.rfile.read(size)
            message = read_json(raw)
            validate("wire", message, "request")
            m = message["method"]
            if m != "ocs.describe" and not (
                m == "tool.call" and message["params"].get("operation") == "model.generate"
            ):
                return self.send(403, b"{}")
            req = request.Request(
                self.server.endpoint,
                data=raw,
                headers={
                    "Authorization": self.server.downstream,
                    "Content-Type": "application/json",
                },
            )
            with self.server.opener.open(req, timeout=5) as response:
                body = response.read(LIMIT + 1)
                if len(body) > LIMIT or response.status != 200:
                    raise ValueError("invalid upstream reply")
            value = read_json(body)
            validate("wire", value, "failure" if "error" in value else "success")
            if value["id"] != message["id"]:
                raise ValueError("upstream correlation mismatch")
            self.upstream_sizes = (len(raw), len(body))
            self.send(200, body)
        except (ValidationError, ValueError, UnicodeError):
            self.send(400, b"{}")
        except (OSError, error.URLError):
            self.send(503, b"{}")


def main():
    keys = Path("/var/run/ocs/relay")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(keys / "relay.crt", keys / "relay.key")
    with BoundedServer(("0.0.0.0", 8443), Relay, tls=tls) as server:
        server.inbound = b"Bearer " + (keys / "relay-client").read_bytes().strip()
        server.downstream = "Bearer " + (keys / "relay-upstream").read_text().strip()
        server.endpoint = "https://ocs-provider." + os.environ["POD_NAMESPACE"] + ".svc/ocs"
        server.opener = request.build_opener(
            request.ProxyHandler({}),
            NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context(cafile=str(keys / "ca.crt"))),
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
