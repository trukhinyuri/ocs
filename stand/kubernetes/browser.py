#!/usr/bin/env python3
"""Qualify keyboard, text scaling and account evidence on the authenticated stand console."""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
PRODUCT = {"provider": "example.ledger", "product": "local-language"}
PIN = hashlib.sha256((HERE.parents[1] / "reference/provider/ocs.json").read_bytes()).hexdigest()
ELEMENT = "element-6066-11e4-a52e-4f735466cecf"
LIMIT = 1048576


class Refused(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def stamp(offset=0):
    return (
        (datetime.now(timezone.utc) + timedelta(seconds=offset))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def doc(raw):
    return json.loads(raw.decode("utf-8"))


class Stand:
    """The authenticated connection is validated and leaf-pinned before sending headers."""

    def __init__(self, url, ca, certificate, token_file):
        u = urlsplit(url)
        require(
            u.scheme == "https"
            and u.hostname
            and not u.username
            and not u.password
            and u.path in ("", "/", "/ocs")
            and not u.query
            and not u.fragment,
            "invalid HTTPS stand origin",
        )
        self.host, self.port = u.hostname, u.port or 443
        self.origin = urlunsplit((u.scheme, u.netloc, "", "", ""))
        self.context = ssl.create_default_context(cafile=str(ca))
        self.token = token_file.read_text().strip()
        require(
            len(self.token) >= 32
            and self.token.isascii()
            and not re.search(r'[\s;,"\\]', self.token),
            "missing or malformed scoped credential",
        )
        pem = re.search(
            r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", certificate.read_text()
        ).group()
        self.cert = ssl.PEM_cert_to_DER_cert(pem)
        pub = subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout"],
            input=pem.encode(),
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout
        key = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=pub,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout
        self.spki = base64.b64encode(hashlib.sha256(key).digest()).decode()
        self.sequence = 0

    def http(self, method, path, body=None, auth=False, expected=200):
        connection = http.client.HTTPSConnection(
            self.host, self.port, timeout=5, context=self.context
        )
        try:
            connection.connect()
            require(
                connection.sock.getpeercert(binary_form=True) == self.cert,
                "stand certificate mismatch",
            )
            headers = {}
            if auth:
                headers["Authorization"] = "Bearer " + self.token
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            require(
                response.status == expected, f"unexpected stand HTTP {response.status} for {path}"
            )
            raw = response.read(LIMIT + 1)
            require(len(raw) <= LIMIT, "stand response exceeded the frame limit")
            return raw
        finally:
            connection.close()

    def rpc(self, method, params):
        self.sequence += 1
        rid = f"console-observation-{self.sequence}"
        frame = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        response = doc(
            self.http("POST", "/ocs", json.dumps(frame, separators=(",", ":")).encode(), True)
        )
        require(
            response.get("id") == rid
            and response.get("jsonrpc") == "2.0"
            and "result" in response
            and "error" not in response,
            "stand refused the named read observation",
        )
        return response["result"]

    def describe(self):
        result = self.rpc(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.providers/0.1"],
                "meta": {"deadline": stamp(5)},
            },
        )
        require(
            result.get("manifestDigest") == PIN and result.get("protocol") == "0.1",
            "unbound provider package",
        )

    def read(self, operation, data):
        return self.rpc(
            "tool.call",
            {
                "operation": operation,
                "version": "1.0.0",
                "input": data,
                "meta": {"protocol": "0.1", "manifestDigest": PIN, "deadline": stamp(5)},
            },
        )["data"]

    def accounts(self):
        out = {}
        seen = set()
        revision = None
        args = PRODUCT.copy()
        for _ in range(64):
            page = self.read("account.list", args)
            revision = revision or page["revision"]
            require(revision == page["revision"], "inventory revision changed across pages")
            for account in page["accounts"]:
                require(account["accountId"] not in out, "duplicate account in inventory")
                out[account["accountId"]] = account
            cursor = page.get("nextPageToken")
            if page["complete"]:
                require(not cursor, "complete inventory returned a continuation")
                return out
            require(cursor and cursor not in seen, "inventory cursor gap or cycle")
            seen.add(cursor)
            args = {**PRODUCT, "pageToken": cursor}
        raise Refused("inventory exceeded the qualification bound")

    def named_model(self, account, model):
        args = {"accountId": account["accountId"], "route": account["route"]}
        revision = None
        cursors = set()
        match = None
        for _ in range(64):
            page = self.read("model.list", args)
            revision = revision or page["revision"]
            require(
                page["revision"] == revision
                and page["scope"]["id"] == account["accountId"]
                and page["route"] == account["route"],
                "catalog scope changed during UI comparison",
            )
            for item in page["models"]:
                if item["id"] == model:
                    require(match is None, "duplicate selected model in catalog")
                    match = item
            cursor = page.get("nextPageToken")
            if page["complete"]:
                require(not cursor, "complete catalog returned a continuation")
                return match
            require(cursor and cursor not in cursors, "catalog cursor gap or cycle")
            cursors.add(cursor)
            args = {**args, "pageToken": cursor}
        raise Refused("model catalog exceeded the qualification bound")

    def projection(self, account, model):
        who = {"accountId": account["accountId"]}
        quota = self.read("limits.read", who)
        prices = self.read("plans.price", {**PRODUCT, **who, "region": "fixture-region"})["plans"]
        admitted = self.named_model(account, model)
        applicable = [
            w
            for w in quota["windows"]
            if w["unit"] == "requests"
            and (
                model in w.get("models", [])
                or (w["scope"]["kind"] == "pool" and not w.get("models"))
            )
        ]
        if (
            not admitted
            or admitted["entitled"] is not True
            or admitted["adapterSupported"] is not True
        ):
            applicable = []
        uncertain = [w for w in applicable if w["state"] in ("unknown", "stale", "unsupported")]
        numeric = [w for w in applicable if w["state"] == "known" and "remaining" in w]
        window = (
            uncertain[0]
            if uncertain
            else min(numeric, key=lambda w: Decimal(w["remaining"]))
            if numeric
            else {"state": "unknown", "unit": "requests", "evidence": quota["evidence"]}
        )
        actual = next((p for p in prices if p["status"] == "account-confirmed"), None)
        list_price = (
            ", ".join(
                f"{p['planId']} {p['price']['amount']} {p['price']['currency']} / {p['period']}"
                for p in prices
                if p["status"] == "published"
            )
            or "Unknown"
        )
        current_at = quota["evidence"]["observedAt"]
        reset = instant(window["resetAt"]) if window.get("resetAt") else None
        state = window["state"]
        if state == "known":
            remaining = window.get("remaining")
            if remaining is None:
                remaining = (
                    f"{window['remainingPercent']}%" if "remainingPercent" in window else "Unknown"
                )
        elif state == "stale" and window.get("remaining") is not None:
            remaining = f"Stale (last reported {window['remaining']})"
        else:
            remaining = state.capitalize()
        price = (
            "Unknown"
            if actual is None
            else f"{actual['price']['amount']} {actual['price']['currency']} / {actual['period']}"
        )
        return {
            "authorityAt": current_at,
            "label": account["label"],
            "connection": "Connection: " + account["state"],
            "remaining": f"Remaining: {remaining} {window['unit']}",
            "table": {
                "Account": who["accountId"],
                "Route": account["route"],
                "Next reset": window.get("resetAt", "Unknown"),
                "Time zone": "UTC",
                "Local reset time": datetime.fromtimestamp(reset, timezone.utc).isoformat(
                    timespec="seconds"
                )
                if reset is not None
                else "Unknown",
                "List price": list_price,
                "Account price": price,
                "Observed at": window["evidence"]["observedAt"],
                "Reset rights": ", ".join(g["eligibility"] for g in quota["resetGrants"])
                or "Unknown",
            },
        }


class Driver:
    """W3C commands use a short-lived local driver. Errors cannot echo credentials."""

    def __init__(self, stand, profile, default_font):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.proc = subprocess.Popen(
            ["chromedriver", f"--port={self.port}", "--allowed-ips=127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.session = None
        try:
            deadline = time.monotonic() + 6
            while True:
                try:
                    if self.request("GET", "/status").get("ready"):
                        break
                except (OSError, Refused):
                    pass
                require(
                    self.proc.poll() is None and time.monotonic() < deadline,
                    "local WebDriver did not start",
                )
                time.sleep(0.08)
            options = {
                "binary": shutil_which("chromium"),
                "args": [
                    "--headless=new",
                    "--incognito",
                    "--no-proxy-server",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--disable-component-update",
                    "--disable-dev-shm-usage",
                    "--remote-debugging-pipe",
                    "--window-size=960,840",
                    "--user-data-dir=" + str(profile),
                    "--ignore-certificate-errors-spki-list=" + stand.spki,
                ],
                "prefs": {
                    "webkit.webprefs.default_font_size": default_font,
                    "webkit.webprefs.default_fixed_font_size": default_font,
                },
            }
            reply = self.request(
                "POST",
                "/session",
                {
                    "capabilities": {
                        "alwaysMatch": {
                            "browserName": "chrome",
                            "acceptInsecureCerts": False,
                            "goog:chromeOptions": options,
                        }
                    }
                },
            )
            self.session = reply["sessionId"]
            self.browser_version = reply["capabilities"]["browserVersion"]
            self.cmd("POST", "/timeouts", {"pageLoad": 6000, "script": 4000, "implicit": 0})
        except BaseException:
            self.close()
            raise

    def request(self, method, path, data=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            body = None if data is None else json.dumps(data, separators=(",", ":"))
            connection.request(
                method, path, body, {"Content-Type": "application/json;charset=UTF-8"}
            )
            response = connection.getresponse()
            raw = response.read(2 * LIMIT + 1)
            require(len(raw) <= 2 * LIMIT, "WebDriver response exceeded the evidence bound")
            value = doc(raw).get("value")
            if response.status >= 400:
                code = (
                    value.get("error", "command failed")
                    if isinstance(value, dict)
                    else "command failed"
                )
                if not re.fullmatch(r"[a-z ]{1,45}", code):
                    code = "command failed"
                raise Refused("WebDriver " + code + " for " + path.rsplit("/", 1)[-1])
            return value
        finally:
            connection.close()

    def cmd(self, method, path, data=None):
        return self.request(method, "/session/" + self.session + path, data)

    def js(self, script, *args):
        return self.cmd("POST", "/execute/sync", {"script": script, "args": args})

    def cdp(self, method, params):
        return self.cmd("POST", "/goog/cdp/execute", {"cmd": method, "params": params})

    def key(self, value):
        self.cmd(
            "POST",
            "/actions",
            {
                "actions": [
                    {
                        "type": "key",
                        "id": "keyboard",
                        "actions": [
                            {"type": "keyDown", "value": value},
                            {"type": "keyUp", "value": value},
                        ],
                    }
                ]
            },
        )

    def focus(self):
        return self.js("""const a=document.activeElement;
            return {tag:a.tagName, label:a.textContent.trim().slice(0,80),
                section:a.closest('section')?.querySelector('h2')?.textContent,
                visible:a.matches(':focus-visible') && parseFloat(getComputedStyle(a).outlineWidth)>0};""")

    def focused_name(self):
        element = self.cmd("GET", "/element/active")[ELEMENT]
        return (
            self.cmd("GET", "/element/" + element + "/computedrole"),
            self.cmd("GET", "/element/" + element + "/computedlabel"),
        )

    def ensure_origin(self, stand, path):
        seen = urlsplit(self.cmd("GET", "/url"))
        require(
            urlunsplit((seen.scheme, seen.netloc, "", "", "")) == stand.origin
            and seen.path == path,
            "unexpected browser navigation",
        )
        certificates = self.cdp("Network.getCertificate", {"origin": stand.origin}).get(
            "tableNames", []
        )
        require(
            certificates and base64.b64decode(certificates[0], validate=True) == stand.cert,
            "browser did not report the pinned leaf certificate",
        )

    def close(self):
        if self.session:
            try:
                self.cmd("DELETE", "")
            except (OSError, Refused, ValueError, http.client.HTTPException):
                pass
            self.session = None
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=3)


def shutil_which(binary):
    from shutil import which

    path = which(binary)
    require(path is not None, binary + " is required on this stand verifier")
    return path


SNAPSHOT = """
const d=document, root=d.documentElement, page=d.querySelector('main');
if(!page)return null;
return {heading:page.querySelector('h1')?.textContent, count:page.querySelector(':scope > p')?.textContent,
 width:root.clientWidth, scrollWidth:Math.max(root.scrollWidth,d.body.scrollWidth),
 rootFont:parseFloat(getComputedStyle(root).fontSize), buttonFont:parseFloat(getComputedStyle(page.querySelector('button')).fontSize),
 start:performance.timeOrigin,
 rows:[...page.querySelectorAll('section')].map(s=>{const ds=s.querySelector('details'), ps=s.querySelectorAll(':scope > p');
 return {label:s.querySelector('h2')?.textContent,connection:ps[0]?.textContent,remaining:ps[1]?.textContent,
 open:ds.open,visible:ds.querySelector('dl').getBoundingClientRect().height>0,
 table:Object.fromEntries([...ds.querySelectorAll('dt')].map(t=>[t.textContent,t.nextElementSibling?.textContent]))};})};
"""


def compare(snapshot, earlier, later, account):
    require(
        snapshot and snapshot["heading"] == "Connected accounts", "missing account overview heading"
    )
    require(len(snapshot["rows"]) == len(later), "visible inventory count differs from the service")
    require(
        snapshot["scrollWidth"] <= snapshot["width"], "horizontal overflow at the observed viewport"
    )
    by_account = {row["table"]["Account"]: row for row in snapshot["rows"]}
    require(
        set(by_account) == set(earlier) == set(later),
        "visible account identities changed or were duplicated",
    )

    def fields(row):
        return (
            row["label"],
            row["connection"],
            row["remaining"],
            {k: v for k, v in row["table"].items() if k not in ("Observed at", "Reset in")},
        )

    for account_id, actual in by_account.items():
        before, after = earlier[account_id], later[account_id]
        require(
            fields(actual) in (fields(before), fields(after)),
            "console projection differs from authenticated account observations",
        )
        low, high = instant(before["table"]["Observed at"]), instant(after["table"]["Observed at"])
        require(
            low <= instant(actual["table"]["Observed at"]) <= high,
            "console freshness time is outside the server observation interval",
        )
        countdown = actual["table"].get("Reset in")
        if actual["table"]["Next reset"] == "Unknown":
            require(countdown == "Unknown seconds", "unknown reset gained a numeric countdown")
        else:
            match = re.fullmatch(r"(\d+) seconds", countdown or "")
            require(match is not None, "reset countdown lacks the reported unit")
            reset = instant(actual["table"]["Next reset"])
            lower = max(0, int(reset - instant(after["authorityAt"])))
            upper = max(0, int(reset - instant(before["authorityAt"])))
            require(
                lower <= int(match[1]) <= upper,
                "countdown differs from the authority observation interval",
            )
    return by_account[account]


def inventory(stand, model):
    accounts = stand.accounts()
    require(accounts, "the qualified context must contain a connected account")
    return accounts, {k: stand.projection(v, model) for k, v in accounts.items()}


def test_view(stand, policy, work, font, width):
    accounts, before = inventory(stand, policy["model"])
    eligible = sorted(
        account_id
        for account_id, data in accounts.items()
        if data["enabled"]
        and data["route"] == policy["route"]
        and data["product"] == PRODUCT["product"]
    )
    require(eligible, "no enabled qualification account on the selected route")
    account = eligible[0]
    driver = Driver(stand, work / f"browser-{font}", font)
    try:
        driver.cdp("Network.enable", {})
        driver.cdp(
            "Emulation.setDeviceMetricsOverride",
            {"width": width, "height": 720, "mobile": False, "deviceScaleFactor": 1},
        )
        driver.cmd("POST", "/url", {"url": stand.origin + "/health"})
        driver.ensure_origin(stand, "/health")
        driver.cmd(
            "POST",
            "/cookie",
            {
                "cookie": {
                    "name": "ocs_view",
                    "value": stand.token,
                    "path": "/console",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Strict",
                }
            },
        )
        driver.cmd("POST", "/url", {"url": stand.origin + "/console"})
        driver.ensure_origin(stand, "/console")
        cookie = driver.cmd("GET", "/cookie/ocs_view")
        require(
            cookie["domain"] == stand.host
            and cookie["path"] == "/console"
            and cookie["httpOnly"]
            and cookie["secure"]
            and cookie["sameSite"] == "Strict",
            "browser cookie scope or storage attributes changed",
        )
        require(
            not driver.js(
                "return document.cookie.split(';').some(x=>x.trim().startsWith('ocs_view='));"
            ),
            "credential was exposed to page script",
        )
        initial = driver.js(SNAPSHOT)
        require(
            initial and (width - 25) <= initial["width"] <= width,
            "browser did not exercise the requested viewport",
        )
        require(
            initial["rootFont"] >= font and initial["buttonFont"] >= font,
            "text preference did not enlarge the actual controls",
        )
        driver.key("\ue004")
        focus = driver.focus()
        require(
            focus["tag"] == "BUTTON"
            and focus["visible"]
            and driver.focused_name() == ("button", "Refresh accounts"),
            "keyboard refresh has no discoverable, visible focus",
        )
        driver.key("\ue007")
        deadline = time.monotonic() + 6
        while True:
            page = driver.js(SNAPSHOT)
            if page and page["start"] != initial["start"]:
                break
            require(time.monotonic() < deadline, "keyboard refresh did not cause a new observation")
            time.sleep(0.05)
        driver.ensure_origin(stand, "/console")
        target = accounts[account]["label"]
        for _ in range(len(accounts) + 4):
            candidate = driver.focus()
            if candidate["tag"] == "SUMMARY" and candidate["section"] == target:
                break
            driver.key("\ue004")
        else:
            raise Refused("account details are unreachable from the keyboard")
        role, label = driver.focused_name()
        require(
            label == "Account details" and bool(role) and driver.focus()["visible"],
            "disclosure has no accessible name or visible focus",
        )
        driver.key(" ")
        expanded = driver.js(SNAPSHOT)
        current, after = inventory(stand, policy["model"])
        displayed = compare(expanded, before, after, account)
        require(
            expanded["count"]
            == f"{len(current)} connected · {sum(a['enabled'] for a in current.values())} enabled",
            "overview totals or units differ from the authority",
        )
        require(
            displayed["open"] and displayed["visible"] and driver.focus()["tag"] == "SUMMARY",
            "keyboard disclosure did not present the selected details",
        )
        driver.key("\ue007")
        collapsed = driver.js(SNAPSHOT)
        selected = [r for r in collapsed["rows"] if r["table"]["Account"] == account][0]
        require(
            not selected["open"]
            and driver.focus()["tag"] == "SUMMARY"
            and driver.focus()["section"] == target
            and driver.focus()["visible"],
            "closing account details lost focus or left the disclosure open",
        )
        return {
            "requestedCssWidth": width,
            "observedCssWidth": expanded["width"],
            "scrollWidth": expanded["scrollWidth"],
            "rootFontPx": expanded["rootFont"],
            "controlFontPx": expanded["buttonFont"],
            "accessibleDisclosureRole": role,
            "keyboard": [
                "Tab to refresh",
                "Enter to refresh document",
                "Tab to selected account",
                "Space to open",
                "Enter to close",
            ],
            "focusVisibleAfterClose": True,
            "countLabel": expanded["count"],
            "accountRowsChecked": len(current),
            "displayed": {k: displayed[k] for k in ("label", "connection", "remaining", "table")},
            "browserVersion": driver.browser_version,
        }
    finally:
        driver.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True)
    p.add_argument("--ca", type=Path, required=True)
    p.add_argument("--cert", type=Path, required=True)
    p.add_argument("--token-file", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    observed = stamp()
    report = {
        "scope": "Authenticated stand console with host-scoped credential and observed TLS leaf on both paths.",
        "observedAt": observed,
        "checks": [],
    }
    try:
        stand = Stand(a.url, a.ca, a.cert, a.token_file)
        policy = doc((HERE / "policy.json").read_bytes())["workload"]
        require(doc(stand.http("GET", "/health")).get("ready") is True, "stand is not ready")
        stand.http("GET", "/console", expected=401)
        identity = doc(stand.http("GET", "/identity", auth=True))
        require(
            identity["manifestDigest"] == PIN and identity["role"] == "probe",
            "unexpected provider identity or role",
        )
        stand.describe()
        with tempfile.TemporaryDirectory(prefix="ocs-browser-") as tmp:
            views = [
                test_view(stand, policy, Path(tmp), 16, 960),
                test_view(stand, policy, Path(tmp), 32, 320),
            ]
        require(
            views[1]["rootFontPx"] >= 2 * views[0]["rootFontPx"],
            "observed text enlargement is less than double",
        )
        report["checks"] = [
            {
                "id": "stand.accessibility",
                "level": "deployment",
                "claims": ["U-03.accessibility"],
                "status": "pass",
                "observedAt": observed,
                "observed": {
                    "views": views,
                    "pod": identity["pod"],
                    "namespace": identity["namespace"],
                    "sourceRevision": identity["sourceRevision"],
                    "certificateSha256": hashlib.sha256(stand.cert).hexdigest(),
                    "hostCookiePath": "/console",
                    "scriptCanReadCredential": False,
                },
            },
            {
                "id": "stand.text-and-keyboard",
                "level": "measurement",
                "claims": ["U-03.accessibility"],
                "status": "pass",
                "observedAt": observed,
                "observed": {
                    "cssWidths": [v["observedCssWidth"] for v in views],
                    "fontPixels": [v["rootFontPx"] for v in views],
                    "horizontalOverflowPixels": [
                        v["scrollWidth"] - v["observedCssWidth"] for v in views
                    ],
                    "checkedKeyboardOperations": sum(len(v["keyboard"]) for v in views),
                },
            },
        ]
    except Refused as e:
        report["checks"] = [
            {
                "id": "stand.accessibility",
                "level": "deployment",
                "claims": ["U-03.accessibility"],
                "status": "fail",
                "observedAt": observed,
                "observed": str(e),
            }
        ]
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        subprocess.SubprocessError,
    ) as e:
        report["checks"] = [
            {
                "id": "stand.accessibility",
                "level": "deployment",
                "claims": ["U-03.accessibility"],
                "status": "fail",
                "observedAt": observed,
                "observed": "browser observation failed (" + type(e).__name__ + ")",
            }
        ]
    a.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=a.report.parent, delete=False) as file:
        json.dump(report, file, indent=2)
        file.write("\n")
        name = file.name
    os.replace(name, a.report)
    failed = [row for row in report["checks"] if row["status"] != "pass"]
    if failed:
        print("FAIL", failed[0]["observed"], file=sys.stderr)
    else:
        print("Verified live account console, keyboard interaction and enlarged narrow layout.")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
