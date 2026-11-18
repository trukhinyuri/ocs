"""Authenticated HTTPS transport for the repository's provider and resource fixtures."""

import argparse
import hmac
import html
import json
import os
import ssl
import sys
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "reference/provider"), str(ROOT / "reference")]
from bounded_http import BoundedServer
from contracts import LIMIT, read_json, validate, validate_with
from executor import CODES, EXPORTS, PIN, Session
from jsonschema import ValidationError
from service import Provider, Refused


def esc(value):
    return html.escape(str(value), quote=True)


def console(overview, store, owner, now):
    rows = []
    for account in overview["accounts"]:
        account_id = account["accountId"]
        quota = store.windows(owner, account_id, now)
        win = account.get("limitingWindow") or {
            "state": "unknown",
            "unit": "requests",
            "evidence": {"observedAt": overview["observedAt"]},
        }
        amount = win.get(
            "remaining", f"{win['remainingPercent']}%" if "remainingPercent" in win else "Unknown"
        )
        if win["state"] == "stale":
            amount = f"Stale (last reported {amount})" if amount != "Unknown" else "Stale"
        elif win["state"] != "known":
            amount = win["state"].capitalize()
        prices = store.prices(
            owner,
            {
                "provider": overview["provider"],
                "product": account["product"],
                "accountId": account_id,
                "region": "fixture-region",
            },
            now,
        )["plans"]
        actual = next((p for p in prices if p["status"] == "account-confirmed"), None)
        price = (
            "Unknown"
            if actual is None
            else f"{actual['price']['amount']} {actual['price']['currency']} / {actual['period']}"
        )
        published = [q for q in prices if q["status"] == "published"]
        list_price = (
            ", ".join(
                f"{q['planId']} {q['price']['amount']} {q['price']['currency']} / {q['period']}"
                for q in published
            )
            or "Unknown"
        )
        rows.append(
            f"<section><h2>{esc(account['label'])}</h2><p>Connection: {esc(account['state'])}</p>"
            f"<p>Remaining: {esc(amount)} {esc(win['unit'])}</p>"
            f"<details><summary>Account details</summary><dl><dt>Account</dt><dd>{esc(account_id)}</dd>"
            f"<dt>Route</dt><dd>{esc(account['route'])}</dd><dt>Next reset</dt><dd>{esc(win.get('resetAt', 'Unknown'))}</dd>"
            f"<dt>Local reset time</dt><dd>{esc(account.get('resetAtLocal') or 'Unknown')}</dd>"
            f"<dt>Time zone</dt><dd>{esc(account.get('timeZone', 'UTC'))}</dd><dt>Reset in</dt><dd>{esc(account['secondsUntilReset'] if account.get('secondsUntilReset') is not None else 'Unknown')} seconds</dd>"
            f"<dt>List price</dt><dd>{esc(list_price)}</dd><dt>Account price</dt><dd>{esc(price)}</dd><dt>Observed at</dt><dd>{esc(win['evidence']['observedAt'])}</dd>"
            f"<dt>Reset rights</dt><dd>{esc(', '.join(g['eligibility'] for g in quota['resetGrants']) or 'Unknown')}</dd></dl></details></section>"
        )
    return (
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Connected accounts</title><style>body{font:110% system-ui;margin:1rem auto;padding:0 1rem;max-width:40rem}"
        "button,summary{font:inherit;cursor:pointer}main{min-width:0;overflow-wrap:anywhere}form,label{display:block;min-width:0}input,select,button{box-sizing:border-box;max-width:100%;font:inherit;white-space:normal}input{width:min(100%,18rem)}dd{margin-inline-start:1rem}section{border-top:1px solid;padding-block:.8rem}"
        ":focus-visible{outline:3px solid currentColor;outline-offset:3px}</style>"
        f"<main><h1>Connected accounts</h1><p>{overview['count']} connected · {overview['enabled']} enabled</p>"
        "<form action='/console'><button>Refresh accounts</button></form>"
        + "".join(rows)
        + "<form action='/console'><label>Model <input name=model></label>"
        + "<label>Account status <input name=status></label><label>Time zone <input name=timeZone value=UTC></label>"
        + "<button>Filter accounts</button></form></main></html>"
    ).encode()


class Gateway(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def response(self, code, data, media="application/json"):
        payload = (
            data if isinstance(data, bytes) else json.dumps(data, separators=(",", ":")).encode()
        )
        self.send_response(code)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def identity(self):
        header = self.headers.get("Authorization", "")
        if not header and self.command == "GET" and self.path.split("?", 1)[0] == "/console":
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except CookieError:
                return None
            value = cookie.get("ocs_view")
            if value is not None:
                header = "Bearer " + value.value
        for token, owner, purpose in self.server.identities:
            if hmac.compare_digest(header.encode(), token):
                return owner, purpose
        return None

    def do_GET(self):
        if self.path == "/health":
            return self.response(200, {"ready": True})
        auth = self.identity()
        if not auth:
            return self.response(401, {"error": "authentication required"})
        if auth[1] == "relay":
            return self.response(403, {"error": "operation outside delegated grant"})
        if self.path.split("?", 1)[0] == "/console":
            store = self.server.stores[auth[0]]
            now = int(time.time())
            try:
                raw_query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=False,
                    max_num_fields=4,
                    strict_parsing=True,
                )
                if any(len(v) != 1 for v in raw_query.values()):
                    raise ValueError("duplicate filter")
                query = {k: v[0] for k, v in raw_query.items()}
                validate_with(EXPORTS["example.account.overview"]["inputSchema"], query)
                view = store.overview(auth[0], now, query)
            except (Refused, ValueError, ValidationError):
                return self.response(400, {"error": "unavailable filter"})
            return self.response(
                200,
                console(view, store, auth[0], now),
                "text/html; charset=utf-8",
            )
        if self.path == "/identity":
            return self.response(
                200,
                {
                    "manifestDigest": PIN,
                    "pod": os.environ["POD_UID"],
                    "namespace": os.environ["POD_NAMESPACE"],
                    "role": auth[1],
                    "sourceRevision": os.environ["OCS_REVISION"],
                },
            )
        return self.response(404, {"error": "unknown resource"})

    def do_POST(self):
        if self.path != "/ocs":
            return self.response(404, {"error": "unknown endpoint"})
        auth = self.identity()
        if not auth:
            return self.response(403, {"error": "peer grant denied"})
        if self.headers.get_content_type() != "application/json":
            return self.response(415, {"error": "expected JSON"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.response(411, {"error": "length required"})
        if not 0 < length <= LIMIT:
            return self.response(413, {"error": "frame limit"})
        rid = None
        try:
            value = read_json(self.rfile.read(length))
            if (
                isinstance(value, dict)
                and isinstance(value.get("id"), str)
                and 1 <= len(value["id"]) <= 128
            ):
                rid = value["id"]
            if isinstance(value, dict) and "id" not in value:
                validate("wire", value, "notification")
                return self.response(204, b"")
            validate("wire", value, "request")
            # Each HTTP invocation authenticates anew under the sealed endpoint and
            # the descriptor pin. The underlying provider validates call parameters.
            if auth[1] == "relay" and not (
                value["method"] == "ocs.describe"
                or value["method"] == "tool.call"
                and value["params"].get("operation") == "model.generate"
            ):
                return self.response(403, {"error": "operation outside delegated grant"})
            session = Session.for_http(
                self.server.stores[auth[0]], auth[0], "probe" if auth[1] == "relay" else auth[1]
            )
            result = session.run(value["method"], value["params"])
            return self.response(200, {"jsonrpc": "2.0", "id": rid, "result": result})
        except Refused as exc:
            kind = str(exc)
        except ValidationError:
            kind = "request"
        except (ValueError, UnicodeError, RecursionError):
            kind = "parse"
        except Exception:
            kind = "internal"
        return self.response(
            200,
            {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {
                    "code": CODES.get(kind, -32603),
                    "message": "Request refused.",
                    "data": {"kind": kind if kind in CODES else "internal"},
                },
            },
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys", type=Path, default=Path("/var/run/ocs/keys"))
    parser.add_argument("--store", type=Path, default=Path("/data/provider.sqlite"))
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.keys / "tls.crt", args.keys / "tls.key")
    with BoundedServer(("0.0.0.0", args.port), Gateway, tls=tls) as server:
        server.identities = []
        for filename, owner, purpose in (
            ("probe", "qualification-account", "probe"),
            ("work", "qualification-account", "work"),
            ("relay-upstream", "qualification-account", "relay"),
            ("other", "other-owner", "probe"),
        ):
            secret = (args.keys / filename).read_text().strip()
            if len(secret) < 32:
                raise ValueError("incomplete stand credential")
            server.identities.append((("Bearer " + secret).encode(), owner, purpose))
        server.stores = {owner: Provider(args.store) for _, owner, _ in server.identities}
        server.serve_forever()


if __name__ == "__main__":
    main()
