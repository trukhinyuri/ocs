#!/usr/bin/env python3
"""Independent qualification of the candidate's local provider, ledger and product."""

import argparse
import hashlib
import json
import math
import os
import platform
import select
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

ORACLE = Path(__file__).resolve().parents[2]
TARGET = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
sys.path.insert(0, str(ORACLE / "reference"))
from contracts import LIMIT, read_json, utc_at, validate, validate_with
from refinement import sha, verify

RULES = read_json((ORACLE / "assurance/provider/criteria.json").read_bytes())
OPS = {
    row["method"]: row
    for row in read_json((ORACLE / "spec/profiles/operations.json").read_bytes())["operations"]
}
ADAPTER = TARGET / "reference/provider"
MANIFEST = read_json((ADAPTER / "ocs.json").read_bytes())
PIN = sha(ADAPTER / "ocs.json")
PROVIDER, PRODUCT, MODEL, ROUTE = (
    "example.ledger",
    "local-language",
    "reference-colour",
    "local-primary",
)
BASE = 1893456000
PRODUCT_ARGS = {"provider": PROVIDER, "product": PRODUCT}
FEATURES = {
    k: v for k, v in OPS.items() if v["profile"] in ("ocs.providers/0.1", "ocs.effects/0.1")
}
WITNESSES = {}
PREPARED = {}
WITNESS_LOCK = threading.Lock()


def check(value, description):
    if not value:
        raise AssertionError(description)


def capture(method, arg, outcome, framed, ok):
    entry = FEATURES.get(method)
    if entry is None:
        return
    if ok:
        # Both references are resolved in the independently selected oracle's schema registry.
        validate_with({"$ref": entry["input"]}, arg)
        validate_with({"$ref": entry["output"]}, outcome)
    key = hashlib.sha256(
        json.dumps(
            [PIN, method, arg, outcome, framed, ok],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with WITNESS_LOCK:
        rec = WITNESSES.setdefault(method, {"positive": [], "refusal": []})
        rec["positive" if ok else "refusal"].append(key)


def feature_matrix():
    matrix = {}
    for name, entry in FEATURES.items():
        hits = WITNESSES.get(name, {"positive": [], "refusal": []})
        matrix[name] = {
            "feature": entry["profile"],
            "channel": entry["channel"],
            "contractVersion": entry.get("version"),
            "publishedMethodSha256": hashlib.sha256(
                json.dumps(
                    entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
            "inputSchema": entry["input"],
            "outputSchema": entry["output"],
            "protocol": "0.1",
            "targetPin": PIN,
            "accepted": len(hits["positive"]),
            "refusals": len(hits["refusal"]),
            "witnessSha256": hashlib.sha256(
                json.dumps(
                    {k: sorted(values) for k, values in hits.items()},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "direction": "published method schemas and wire observer -> working provider on stdio",
            "reverseExecutable": "The accepted 6f6e228 edition publishes this profile contract without a native provider executor.",
        }
    return matrix


def local_admin(db, principal, *args, clock=BASE, success=True):
    p = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ADAPTER / "admin.py"),
            "--store",
            str(db),
            "--principal",
            principal,
            "--fixture-clock",
            str(clock),
            *map(str, args),
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    if success:
        check(p.returncode == 0, "trusted administrative entry failed: " + p.stderr[:200])
    else:
        check(p.returncode != 0, "ungranted administrative operation succeeded")
        return p.stderr.strip()
    return p.stdout.rstrip() if "--human" in args else read_json(p.stdout)


class Client:
    def __init__(
        self,
        db,
        principal="alpha",
        *,
        purpose="work",
        clock=BASE,
        delivery="local",
        downstream=None,
        refresh=False,
    ):
        argv = [
            sys.executable,
            "-I",
            str(ADAPTER / "executor.py"),
            "--store",
            str(db),
            "--principal",
            principal,
            "--purpose",
            purpose,
            "--fixture-clock",
            str(clock),
            "--delivery",
            delivery,
        ]
        if downstream:
            argv += ["--downstream", str(downstream)]
        if refresh:
            argv += ["--refresh-failure"]
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self.counter = 0
        self.owner = principal
        self.pin = PIN
        self.buffer = bytearray()

    def __enter__(self):
        try:
            op = self.rpc(
                "ocs.describe",
                {
                    "protocols": ["9", "0.1"],
                    "requiredFeatures": ["ocs.providers/0.1", "ocs.effects/0.1"],
                    "meta": {"deadline": utc_at(time.time() + 6)},
                },
            )
            validate("wire", op, "describeResult")
            check(op["manifestDigest"] == self.pin, "negotiated provider descriptor changed")
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()

    def rpc(self, method, params, expect=None):
        self.counter += 1
        rid = str(self.counter)
        raw = (
            json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        check(len(raw) < 4096, "qualification request unexpectedly large")
        self.proc.stdin.write(raw)
        end = time.monotonic() + 6
        while b"\n" not in self.buffer:
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.proc.stdout], [], [], left)[0]:
                raise AssertionError("local endpoint missed the qualification deadline")
            chunk = os.read(self.proc.stdout.fileno(), min(65536, LIMIT + 1 - len(self.buffer)))
            check(
                chunk and len(self.buffer) + len(chunk) <= LIMIT + 1, "missing or oversized reply"
            )
            self.buffer.extend(chunk)
        line, _, tail = self.buffer.partition(b"\n")
        self.buffer = bytearray(tail)
        reply = read_json(bytes(line))
        self.framed = hashlib.sha256(raw[:-1] + b"\x00" + bytes(line)).hexdigest()
        check(reply["id"] == rid, "wrong request correlation")
        validate("wire", reply, "failure" if "error" in reply else "success")
        if expect:
            check(
                reply.get("error", {}).get("data", {}).get("kind") == expect,
                f"{method} expected {expect}, saw {reply}",
            )
            if method in FEATURES and FEATURES[method]["channel"] != "export":
                capture(method, params, reply["error"], self.framed, False)
            return reply["error"]
        check("result" in reply, f"{method} failed: {reply.get('error')}")
        if method in OPS and OPS[method]["channel"] != "export":
            capture(method, params, reply["result"], self.framed, True)
            if method == "effect.prepare":
                proposal = reply["result"]
                validate_with({"$ref": FEATURES[params["operation"]]["input"]}, params["input"])
                with WITNESS_LOCK:
                    PREPARED[(self.owner, proposal["operationId"])] = (
                        params["operation"],
                        params["input"],
                        proposal["intentDigest"],
                        self.framed,
                    )
            if method == "effect.commit" and reply["result"]["state"] == "applied":
                with WITNESS_LOCK:
                    prepared = PREPARED.get((self.owner, params["operationId"]))
                if prepared is not None:
                    name, input_data, original_intent, prepare_frame = prepared
                    check(
                        reply["result"]["intentDigest"] == original_intent,
                        "effect receipt belongs to a different accepted export",
                    )
                    capture(name, input_data, reply["result"], [prepare_frame, self.framed], True)
        return reply["result"]

    def meta(self, **extra):
        return {
            "protocol": "0.1",
            "deadline": utc_at(time.time() + 5),
            "manifestDigest": self.pin,
            **extra,
        }

    def call(self, op, args, expect=None, key=None):
        res = self.rpc(
            "tool.call",
            {
                "operation": op,
                "version": "1.0.0",
                "input": args,
                "meta": self.meta(**({"idempotencyKey": key} if key else {})),
            },
            expect,
        )
        if expect:
            capture(op, args, res, self.framed, False)
            return res
        validate("wire", res, "callResult")
        if op in OPS:
            capture(op, args, res["data"], self.framed, True)
        return res["data"]

    def connect(self, label="Example user", org="org-a", method="local-none"):
        return self.call(
            "account.connect",
            {
                **PRODUCT_ARGS,
                "authMethod": method,
                "settings": {"label": label, "organization": org},
            },
        )

    def prepare(self, id, key, **kwargs):
        return self.rpc(
            "effect.prepare",
            {
                "operation": "quota.reset",
                "version": "1.0.0",
                "input": {"accountId": id, "grantId": "trial", "windows": ["weekly"]},
                "meta": self.meta(idempotencyKey=key),
            },
            **kwargs,
        )

    def commit(self, op, digest, expect=None, **meta):
        return self.rpc(
            "effect.commit",
            {"operationId": op, "intentDigest": digest, "meta": self.meta(**meta)},
            expect,
        )

    def receipt(self, op, expect=None):
        return self.rpc("effect.readback", {"operationId": op, "meta": self.meta()}, expect)

    def request(self, id, text, **other):
        return {
            "accountId": id,
            "route": ROUTE,
            "model": MODEL,
            "parameters": {"reasoning": "off", "tier": "standard"},
            "input": [{"type": "text", "text": text}],
            **other,
        }


def authority(db):
    with Client(db) as a, Client(db, "beta") as b:
        descriptor = a.call("provider.describe", {})
        check(
            descriptor["routes"] == [ROUTE]
            and {v["id"] for v in descriptor["authMethods"]} == {"local-none", "managed-ticket"},
            "capability discovery or credential choice",
        )
        first = a.connect("First")["account"]["accountId"]
        check(
            a.call("example.account.overview", {})["accounts"][0]["disableImpact"] == [MODEL],
            "last selected route impact",
        )
        flow = a.connect("Brokered", method="managed-ticket")
        fid = flow["flowId"]
        for args in [("--issuer", "other"), ("--origin", "other"), ("--lifetime", "0")]:
            handle = local_admin(db, "alpha", "mint", fid, *args)["connectionHandle"]
            a.call("account.continue", {"flowId": fid, "connectionHandle": handle}, "denied")
        handle = local_admin(db, "beta", "mint", fid)["connectionHandle"]
        b.call("account.continue", {"flowId": fid, "connectionHandle": handle}, "denied")
        handle = local_admin(db, "alpha", "mint", fid)["connectionHandle"]
        joined = a.call("account.continue", {"flowId": fid, "connectionHandle": handle})
        tag = joined["account"]["accountId"]
        a.call("account.continue", {"flowId": fid, "connectionHandle": handle}, "denied")
        check(handle not in json.dumps(joined), "handle disclosed in account")
        a.connect("Third")
        page = a.call("account.list", PRODUCT_ARGS)
        check(
            not page["complete"] and len(page["accounts"]) == 2,
            "expected scoped partial account page",
        )
        b.call("account.list", {**PRODUCT_ARGS, "pageToken": page["nextPageToken"]}, "conflict")
        check(b.call("account.list", PRODUCT_ARGS)["accounts"] == [], "tenant saw another account")
        a.call("account.signout", {"accountId": tag})
        a.call("account.list", {**PRODUCT_ARGS, "pageToken": page["nextPageToken"]}, "conflict")
        a.call("model.generate", a.request(tag, "sky"), "denied", key="signed-out")
        reauth = a.call("account.reauthenticate", {"accountId": tag})
        renewed = local_admin(db, "alpha", "mint", reauth["flowId"])["connectionHandle"]
        check(
            a.call("account.continue", {"flowId": reauth["flowId"], "connectionHandle": renewed})[
                "account"
            ]["accountId"]
            == tag,
            "reauthentication changed account",
        )
        check(
            not a.call("account.enable", {"accountId": tag, "enabled": False})["enabled"],
            "route stayed enabled",
        )
        a.call("model.generate", a.request(tag, "sky"), "denied", key="disabled")
        b.call("account.remove", {"accountId": first}, "denied")
        check(a.call("account.remove", {"accountId": tag})["accepted"], "archive failed")
        a.call("limits.read", {"accountId": tag}, "denied")
        terms = a.call("example.product.terms", {"accountId": first})
        check(terms["plan"] == "shared-trial", "removal cancelled organization entitlement")
        overview = a.call("example.account.overview", {})
        human = local_admin(db, "alpha", "overview", "--human")
        check(
            "Accounts " + str(overview["count"]) + " |" in human
            and all(x["accountId"] in human and x["state"] in human for x in overview["accounts"]),
            "terminal and machine account views disagree",
        )
        check(
            overview["count"] == 2
            and overview["organizationPlans"] == 1
            and overview["listPriceTotal"]["amount"] == "2.50",
            "duplicated organization plan",
        )
        return {
            "partialPage": len(page["accounts"]),
            "finalAccounts": overview["count"],
            "scopedHandleFailures": 4,
            "verifiedFlows": ["local-none", "managed-ticket"],
            "terminalMatches": True,
        }


def snapshots(db):
    with Client(db) as a:
        id = a.connect()["account"]["accountId"]
        args = {"accountId": id, "route": ROUTE}
        page = a.call("model.list", args)
        next_page = a.call("model.list", {**args, "pageToken": page["nextPageToken"]})
        ident = {
            "provider": PROVIDER,
            "product": PRODUCT,
            "route": ROUTE,
            "scope": {"kind": "account", "id": id},
            "region": "fixture-region",
            "plan": "shared-trial",
            "auth": "local-none",
        }
        records = [
            {"origin": ident, "token": None, "page": page},
            {"origin": ident, "token": page["nextPageToken"], "page": next_page},
        ]
        work = Path(db).parent

        def ingest(kind, identity, parts):
            f = work / "snapshot.json"
            f.write_text(json.dumps({"identity": identity, "pages": parts}))
            return local_admin(db, "alpha", "sync", kind, f)

        def get(kind, identity):
            f = work / "identity.json"
            f.write_text(json.dumps(identity))
            return local_admin(db, "alpha", "cache", kind, f)

        check(
            ingest("catalog", ident, records)["published"], "complete comparable catalog rejected"
        )
        claimed = json.loads(json.dumps(records))
        injected = next(
            row
            for page in claimed
            for row in page["page"]["models"]
            if row["id"] == "preview-lattice"
        )
        injected.update(
            {
                "adapterSupported": True,
                "verifiedAt": utc_at(BASE),
                "verifiedOptions": [
                    {
                        "parameters": {"tier": "ultrafast"},
                        "at": utc_at(BASE),
                        "evidence": claimed[0]["page"]["evidence"],
                    }
                ],
            }
        )
        check(ingest("catalog", ident, claimed)["published"], "valid upstream observations refused")
        candidate = next(
            m for m in a.call("model.list", args)["models"] if m["id"] == "preview-lattice"
        )
        check(
            candidate["officiallyListed"]
            and candidate["adapterSupported"] is False
            and "verifiedAt" not in candidate
            and "verifiedOptions" not in candidate,
            "upstream listing invented adapter support or a verified reply",
        )
        stored = get("catalog", ident)
        check(stored["notices"] == 1, "official EOL notice absent")
        check(
            not ingest("catalog", ident, records[:1])["published"],
            "partial catalog replaced complete snapshot",
        )
        mismatch = json.loads(json.dumps(records))
        mismatch[-1]["origin"]["route"] = "other"
        check(
            not ingest("catalog", ident, mismatch)["published"],
            "mismatched route replaced accepted catalog",
        )
        gap = json.loads(json.dumps(records))
        gap[-1]["token"] = "stale-cursor"
        check(not ingest("catalog", ident, gap)["published"], "broken continuation published")
        check(get("catalog", ident) == stored, "last comparable complete catalog lost")
        check(
            ingest("catalog", ident, records)["published"]
            and get("catalog", ident)["notices"] == 1,
            "duplicate EOL notices",
        )
        newer = json.loads(json.dumps(records))
        for item in newer:
            item["page"]["revision"] = "revision-2"
        newer[0]["page"]["models"] = [m for m in newer[0]["page"]["models"] if m["id"] != MODEL]
        check(
            ingest("catalog", ident, newer)["published"] and get("catalog", ident)["notices"] == 1,
            "disappearance invented EOL",
        )
        a.call("model.generate", a.request(id, "sky"), "incompatible", key="vanished")
        inventory = a.call("account.list", PRODUCT_ARGS)
        origin = {**PRODUCT_ARGS, "owner": "alpha"}
        row = {"origin": origin, "token": None, "page": inventory}
        check(ingest("accounts", origin, [row])["published"], "complete inventory refused")
        old = get("accounts", origin)
        incomplete = json.loads(json.dumps(row))
        incomplete["page"].update(
            {"complete": False, "reason": "source unavailable", "accounts": []}
        )
        check(
            not ingest("accounts", origin, [incomplete])["published"]
            and get("accounts", origin) == old,
            "partial inventory deleted account",
        )
        return {
            "oldRevision": stored["snapshot"]["revision"],
            "newRevision": get("catalog", ident)["snapshot"]["revision"],
            "retainedOfficialNotices": 1,
            "rejectedGaps": 3,
            "retainedAccountCount": len(old["snapshot"]["rows"]),
        }


def amounts(db):
    with Client(db) as a:
        id = a.connect("A")["account"]["accountId"]
        a.connect("B")
        a.connect("C", org="different-org")
        periods = a.call("limits.read", {"accountId": id})
        st = {w["state"] for w in periods["windows"]}
        check(
            st == {"known", "unknown", "stale", "unsupported", "unlimited"}
            and any("remainingPercent" in w and "total" not in w for w in periods["windows"]),
            "lossy unavailable or percent-only amount",
        )
        overview = a.call("example.account.overview", {})
        check(
            overview["sharedPools"] == 2
            and overview["sharedPoolRemaining"] == "1000"
            and overview["listPriceTotal"]["amount"] == "5.00",
            "shared pool or price counted per credential",
        )
        price = a.call("plans.price", {**PRODUCT_ARGS, "region": "fixture-region", "accountId": id})
        statuses = {p["status"]: p for p in price["plans"]}
        check(
            statuses["published"]["price"] == {"amount": "2.50", "currency": "USD"}
            and statuses["account-confirmed"]["price"]["amount"] == "0"
            and "price" not in statuses["unpublished"]
            and "price" not in statuses["by-contract"],
            "price provenance or zero confused with unavailable",
        )
        for k in ("region", "period", "basis", "tax", "annualTerms", "termsUrl", "evidence"):
            check(k in statuses["published"], "published terms missing " + k)
        a.call("plans.price", {**PRODUCT_ARGS, "region": "unknown"}, "unavailable")
        initial = periods["windows"][0]
        for count in range(100):
            a.call("model.generate", a.request(id, "grass"), key="spend-" + str(count))
        a.call("model.generate", a.request(id, "grass"), "busy", key="beyond-window")
        end = a.call("limits.read", {"accountId": id})
        check(
            end["windows"][0]["remaining"] == "0"
            and end["windows"][1]["remaining"] == "400"
            and end["resetGrants"][0]["count"] == 1,
            "distinct account, shared window and reset right corrupted",
        )
    with Client(db, clock=BASE + 7 * 86400) as advanced:
        changed = advanced.call("limits.read", {"accountId": id})
        check(
            changed["windows"][0]["remaining"] == "100"
            and changed["windows"][0]["resetAt"] > initial["resetAt"]
            and changed["resetGrants"][0]["count"] == 1,
            "window recovery consumed a reset or kept an expired observation",
        )
    return {
        "states": sorted(st),
        "sharedPools": 2,
        "sharedAccounts": 3,
        "limitsAfterWork": "0",
        "distinctOrganizationPriceTotal": "5.00",
        "resetCreditsAfterDiscovery": 1,
        "nextReset": changed["windows"][0]["resetAt"],
    }


def inference(db):
    with Client(db, purpose="probe") as p:
        id = p.connect()["account"]["accountId"]
        questions = RULES["workload"]["questions"]
        options = RULES["workload"]["parameters"]
        samples = []
        correct = 0
        bytes_in = 0
        tokens = 0
        p.call("model.generate", p.request(id, "sky"), key="warmup")
        for k, (q, target) in enumerate(questions):
            start = time.monotonic_ns()
            out = p.call("model.generate", p.request(id, q), key="heldout-" + str(k))
            samples.append((time.monotonic_ns() - start) / 1e6)
            check(
                (out["accountId"], out["route"], out["model"], out["sent"], out["confirmed"])
                == (id, ROUTE, MODEL, options, options),
                "reply route/options substitution",
            )
            correct += out["parts"][0]["text"] == target
            bytes_in += len(q.encode())
            tokens += out["inputTokens"]
        p95 = sorted(samples)[math.ceil(0.95 * len(samples)) - 1]
        check(
            correct >= RULES["workload"]["minimumCorrect"]
            and p95 <= RULES["workload"]["maxP95Milliseconds"],
            "held-out local measurement failed",
        )
        for changes, kind in [
            ({"model": "preview-lattice"}, "incompatible"),
            ({"route": "wrong"}, "denied"),
            ({"parameters": {"reasoning": "high", "tier": "standard"}}, "incompatible"),
            ({"parameters": {"reasoning": "off", "tier": "ultrafast"}}, "incompatible"),
            ({"parameters": {"surprise": True}}, "incompatible"),
            ({"maxOutputTokens": 9}, "incompatible"),
            ({"input": [{"type": "text", "text": "-".join(["sky"] * 251)}]}, "input"),
            ({"input": [{"type": "data", "schema": "example.image/1", "data": 1}]}, "incompatible"),
        ]:
            p.call("model.generate", p.request(id, "sky", **changes), kind, key="bad")
        p.call(
            "example.classify",
            {"accountId": id, "route": ROUTE, "text": False},
            "input",
            key="typed-classify",
        )
        check(
            p.call(
                "example.classify",
                {"accountId": id, "route": ROUTE, "text": "mint"},
                key="classify",
            )["label"]
            == "green",
            "specialized typed export",
        )
        fast_request = p.request(id, "fern", parameters={"reasoning": "off", "tier": "fast"})
        fast = p.call("model.generate", fast_request, key="native-fast")
        check(
            fast["confirmed"] == fast_request["parameters"] and fast["parts"][0]["text"] == "green",
            "native cached inference tier or returned options changed",
        )
        row = p.call("model.list", {"accountId": id, "route": ROUTE})["models"]
        current, unmapped = row[:2]
        check(
            current["entitled"]
            and current["adapterSupported"]
            and current["officiallyListed"]
            and current["verifiedOptions"]
            and not unmapped["adapterSupported"]
            and unmapped["entitled"] is None
            and "depth-vector" in unmapped["unrecognized"],
            "catalog support and verified axes merged",
        )
        with Client(db, purpose="work") as worker, Client(db, purpose="fallback") as fallback:
            for connection, key in [(worker, "explicit-work"), (fallback, "explicit-fallback")]:
                answer = connection.call("model.generate", connection.request(id, "grass"), key=key)
                check(
                    (answer["accountId"], answer["route"], answer["model"]) == (id, ROUTE, MODEL),
                    "attributed alternate path changed identity",
                )
        meter = p.call(
            "usage.read",
            {
                "scope": {"kind": "account", "id": id},
                "from": utc_at(BASE - 1),
                "to": utc_at(BASE + 1),
            },
        )
        check(
            (meter["workRequests"], meter["probeRequests"], meter["fallbackUses"])
            == (1, len(questions) + 3, 1),
            "probe attributed to productive or fallback work",
        )
        return {
            "samples": len(samples),
            "correct": correct,
            "p95Ms": round(p95, 3),
            "thresholdMs": RULES["workload"]["maxP95Milliseconds"],
            "route": ROUTE,
            "model": MODEL,
            "options": options,
            "account": id,
            "quality": "sealed text classification",
            "scopedUsage": {
                "work": meter["workRequests"],
                "probes": meter["probeRequests"],
                "fallback": meter["fallbackUses"],
            },
            "inputContentBytes": bytes_in,
            "inputTokens": tokens,
            "outputTokens": len(samples),
        }


def absent_right(db):
    with Client(db) as client:
        account = client.connect()["account"]["accountId"]
        lookup = {"accountId": account, "route": ROUTE}
        observations = client.call("limits.read", {"accountId": account})
        unknown = next(w for w in observations["windows"] if w["state"] == "unknown")
        unlimited = next(w for w in observations["windows"] if w["state"] == "unlimited")
        check(
            not any(k in unknown for k in ("remaining", "remainingPercent", "total"))
            and unknown["scope"] != unlimited["scope"],
            "unreported quota granted a numerical or unlimited balance",
        )
        page = client.call("model.list", lookup)
        end = client.call("model.list", {**lookup, "pageToken": page["nextPageToken"]})
        origin = {
            "provider": PROVIDER,
            "product": PRODUCT,
            "route": ROUTE,
            "scope": {"kind": "account", "id": account},
            "region": "fixture-region",
            "plan": "shared-trial",
            "auth": "local-none",
        }
        requested = next(m for m in page["models"] if m["id"] == MODEL)
        check(
            requested["adapterSupported"] and requested["entitled"],
            "admitted local model is not a usable positive control",
        )
        client.call("model.generate", client.request(account, "sky"), key="right-present")
        requested["entitled"] = None
        page["revision"] = end["revision"] = "unknown-right"
        envelope = {
            "identity": origin,
            "pages": [
                {"origin": origin, "token": None, "page": page},
                {"origin": origin, "token": page["nextPageToken"], "page": end},
            ],
        }
        path = Path(db).with_name("unknown-right.json")
        path.write_text(json.dumps(envelope))
        check(
            local_admin(db, "alpha", "sync", "catalog", path)["published"],
            "independently scoped unknown-entitlement snapshot refused",
        )
        before = client.call("limits.read", {"accountId": account})
        client.call(
            "model.generate", client.request(account, "sky"), "denied", key="no-entitlement"
        )
        check(
            client.call("limits.read", {"accountId": account}) == before,
            "unreported entitlement consumed a request or a grant",
        )
        client.call("account.signout", {"accountId": account})
        client.call("model.generate", client.request(account, "sky"), "denied", key="signed-out")
        meter = client.call(
            "usage.read",
            {"scope": origin["scope"], "from": utc_at(BASE - 1), "to": utc_at(BASE + 1)},
        )
        check(
            meter["workRequests"] == 1 and meter["successful"] == 1,
            "denials were counted as actual replies",
        )
        return {
            "unknownQuota": unknown,
            "unlimitedScope": unlimited["scope"],
            "supported": True,
            "entitled": None,
            "missingRight": "denied",
            "signedOut": "denied",
            "realReplies": meter["successful"],
            "unchangedResource": True,
        }


def business(db):
    with Client(db, clock=BASE - 9 * 86400) as early:
        id = early.connect()["account"]["accountId"]
        early.call("model.generate", early.request(id, "sky"), key="past")
    with (
        Client(db) as a,
        Client(db, purpose="probe") as p,
        Client(db, purpose="fallback") as fallback,
    ):
        payload = a.request(id, "grass")
        reply = a.call("model.generate", payload, key="work")
        check(reply == a.call("model.generate", payload, key="work"), "generation replay changed")
        a.call("model.generate", a.request(id, "sky"), "conflict", key="work")
        p.call("model.generate", payload, key="probe")
        fallback.call("model.generate", payload, key="fallback")
        usage = a.call("example.account.overview", {})["accounts"][0]["usage"]
        small, large = usage["7"], usage["30"]
        check(
            (
                small["workRequests"],
                large["workRequests"],
                small["probeRequests"],
                small["fallbackUses"],
            )
            == (1, 2, 1, 1),
            "scoped dated attribution error",
        )
        admin = (id, "external.units", "stable", "2030-W01", 3, 10, BASE - 400)
        check(
            local_admin(db, "alpha", "meter", *admin)["added"]
            and not local_admin(db, "alpha", "meter", *admin)["added"],
            "meter replay counted twice",
        )
        changed = list(admin)
        changed[4] = 4
        check(
            local_admin(db, "alpha", "meter", *changed, success=False) == "conflict",
            "conflicting meter replay",
        )
        check(
            local_admin(db, "beta", "meter", *admin, success=False) == "denied",
            "cross-tenant meter",
        )
        local_admin(
            db,
            "alpha",
            "meter",
            "_unattributed",
            "external.units",
            "u",
            "2030-W01",
            2,
            10,
            BASE - 5,
        )
        params = {
            "scope": {"kind": "account", "id": id},
            "from": utc_at(BASE - 86400),
            "to": utc_at(BASE + 1),
        }
        scoped = a.call("usage.read", params)
        total = a.call("usage.read", {**params, "scope": {"kind": "tenant", "id": "alpha"}})
        check(
            scoped["spend"] == {"amount": "0.3", "currency": "USD"}
            and total["spend"]["amount"] == "0.5"
            and total["attribution"] == "partial",
            "backfill attribution or currency",
        )
        terms = a.call("example.product.terms", {"accountId": id})
        for key in (
            "owner",
            "organization",
            "plan",
            "expiresAt",
            "support",
            "continuity",
            "retentionSeconds",
            "source",
            "observedAt",
        ):
            check(terms.get(key), "missing product terms " + key)
        backup = Path(db).with_name("restored.db")
        b = local_admin(db, "alpha", "backup", backup)
        check(
            b["bytes"] > 0
            and b["sourceBytes"] > 0
            and b["availableBytesBeforeBackup"] >= b["requiredBytes"] == b["bytes"],
            "backup fitness",
        )
        check(
            local_admin(db, "alpha", "backup", backup, success=False) == "conflict",
            "backup overwrote existing archive",
        )
    with Client(backup) as restored:
        check(restored.call("usage.read", params) == scoped, "restored meter diverged")
        check(not local_admin(backup, "alpha", "meter", *admin)["added"], "restore lost replay key")
        local_admin(backup, "alpha", "expire", id)
        restored.call("model.generate", restored.request(id, "sky"), "denied", key="expired-term")
        restored.prepare(id, "expired-right", expect="denied")
        expired_inventory = restored.call("account.list", PRODUCT_ARGS)
        check(
            expired_inventory["accounts"][0]["state"] == "denied",
            "expired entitlement still reports working",
        )
    return {
        "scopedWork7": small["workRequests"],
        "scopedWork30": large["workRequests"],
        "probes": small["probeRequests"],
        "fallback": small["fallbackUses"],
        "scopedSpend": scoped["spend"],
        "tenantSpend": total["spend"],
        "retentionSeconds": terms["retentionSeconds"],
        "backupBytes": b["bytes"],
        "restoredPriorEventReplayed": True,
    }


def views_and_history(db):
    with Client(db) as c, Client(db, principal="other") as foreign:
        one = c.connect("Selected", "org-x")["account"]["accountId"]
        two = c.connect("Alternative", "org-y")["account"]["accountId"]
        c.call("model.generate", c.request(one, "sky"), key="positive")
        opts = {"provider": PROVIDER, "model": MODEL, "status": "working", "timeZone": "UTC+02:00"}
        overview = c.call("example.account.overview", opts)
        check(
            overview["count"] == 1
            and overview["unit"] == "accounts"
            and overview["totalOwned"] == 2
            and overview["filter"] == opts
            and overview["groups"][0]["provider"] == PROVIDER
            and overview["accounts"][0]["accountId"] == one,
            "incorrect scoped provider/model/status grouping",
        )
        view = overview["accounts"][0]
        win = view["limitingWindow"]
        independent = c.call("limits.read", {"accountId": one})["windows"]
        selected = min(
            (
                v
                for v in independent
                if v["state"] == "known"
                and v["unit"] == "requests"
                and (MODEL in v.get("models", []) or v["scope"]["kind"] == "pool")
            ),
            key=lambda v: int(v["remaining"]),
        )
        check(win == selected and view["selectedModel"] == MODEL, "wrong limiting model/window")
        check(
            view["secondsUntilReset"]
            == int(datetime.fromisoformat(win["resetAt"]).timestamp()) - BASE
            and view["resetAtLocal"].endswith("+02:00")
            and datetime.fromisoformat(view["resetAtLocal"]).timestamp()
            == datetime.fromisoformat(win["resetAt"]).timestamp(),
            "local reset loses absolute instant or countdown",
        )
        plain = c.call(
            "example.account.overview", {"model": MODEL, "status": "working", "timeZone": "UTC"}
        )
        check(
            plain["accounts"][0]["secondsUntilReset"] == view["secondsUntilReset"]
            and plain["accounts"][0]["resetAtLocal"] != view["resetAtLocal"],
            "timezone conversion not applied",
        )
        check(
            c.call("example.account.overview", {"model": "not-listed"})["count"] == 0
            and c.call("example.account.overview", {"provider": "foreign"})["count"] == 0,
            "filter leaked an outside account",
        )
        unknown = c.call("example.account.overview", {"model": "preview-lattice"})["accounts"][0]
        check(
            unknown["limitingWindow"]["state"] == "unknown" and unknown["resetAtLocal"] is None,
            "unmapped model got claimed usable quota",
        )
        check(view["disableImpact"] == [], "hidden valid route disappeared under the view filter")
        c.call("account.enable", {"accountId": two, "enabled": False})
        last = c.call("example.account.overview", opts)["accounts"][0]
        check(
            last["disableImpact"] == [MODEL]
            and {m["tier"] for m in last["disableImpactModes"]} == {"standard", "fast"},
            "last admitted route or mode impact absent",
        )
        check(
            set(last["usage"]) == {"7", "30"}
            and all(
                v["lastUsedAt"]
                and v["activeDays"] == 1
                and v["retainedUntil"] > v["to"]
                and v["workRequests"] == 1
                and v["probeRequests"] == 0
                for v in last["usage"].values()
            ),
            "7/30-day attribution, observation or retention missing",
        )
        check(
            "UTC+02:00"
            in local_admin(
                db,
                "alpha",
                "overview",
                "--human",
                "--time-zone",
                "UTC+02:00",
                "--model",
                MODEL,
                "--status",
                "working",
            ),
            "human selected-model/zone view diverged",
        )
        local_admin(db, "alpha", "billing-plan", one, "ambiguous")
        prices = c.call(
            "plans.price", {**PRODUCT_ARGS, "region": "fixture-region", "accountId": one}
        )["plans"]
        listed = {r["planId"]: r for r in prices}
        check(
            set(listed) == {"shared-trial", "shared-flex"}
            and all(
                r["status"] == "published" and r["termsUrl"] and r["evidence"]["source"]
                for r in prices
            )
            and listed["shared-flex"]["price"]["amount"]
            != listed["shared-trial"]["price"]["amount"],
            "ambiguous source silently selected a price",
        )
        oneview = c.call("example.account.overview", opts)
        check(
            set(oneview["accounts"][0]["planCandidates"]) == set(listed)
            and oneview["confirmedPriceTotal"] is None
            and oneview["unknownOrganizationPrices"] == 1,
            "ambiguous billing was marked account-confirmed",
        )
        resolved = c.call(
            "plans.price", {**PRODUCT_ARGS, "region": "fixture-region", "accountId": two}
        )["plans"]
        check(
            any(r["status"] == "account-confirmed" for r in resolved),
            "another organization's confirmed price lost",
        )
        choice = {
            "accountId": one,
            "model": MODEL,
            "route": ROUTE,
            "parameters": {"tier": "fast", "reasoning": "off"},
        }
        chosen = c.call("example.model.select", choice)["selection"]
        conversation = {"accountId": one, "contextId": "kept-history"}
        turn = {**conversation, "text": "Name the colour of a fern."}
        answer = c.call("example.conversation.exchange", turn, key="turn-1")
        c.call("example.conversation.exchange", turn, key="turn-1")
        before = c.call("example.conversation.read", conversation)
        check(
            len(before["turns"]) == 1
            and before["turns"][0]["input"]["input"][0]["text"] == turn["text"]
            and before["turns"][0]["output"] == answer,
            "explicit conversation replay/history lost",
        )
        foreign.call("example.conversation.read", conversation, "denied")
        pages = []
        params = {"accountId": one, "route": ROUTE}
        tok = None
        origin = {
            "provider": PROVIDER,
            "product": PRODUCT,
            "route": ROUTE,
            "scope": {"kind": "account", "id": one},
            "region": "fixture-region",
            "plan": "shared-trial",
            "auth": "local-none",
        }
        while True:
            page = c.call("model.list", {**params, **({"pageToken": tok} if tok else {})})
            pages.append({"origin": origin, "token": tok, "page": page})
            tok = page.get("nextPageToken")
            if not tok:
                break
        notice = {
            "noticeId": "current-retirement",
            "announcedAt": utc_at(BASE),
            "effectiveAt": utc_at(BASE + 86400),
            "source": "urn:ocs:fixture:official-notice:current-retirement",
            "replacement": "candidate-model",
        }
        for e in pages:
            e["page"]["revision"] = "notice-release"
            for m in e["page"]["models"]:
                if m["id"] == MODEL:
                    m["eol"] = notice
        path = Path(db).with_name("selection-notice.json")

        def publish():
            path.write_text(json.dumps({"identity": origin, "pages": pages}))
            check(
                local_admin(db, "alpha", "sync", "catalog", path)["published"],
                "complete catalog refused",
            )

        publish()
        publish()
        affected = c.call("example.model.selection", {"accountId": one})
        check(
            affected["selection"] == chosen
            and affected["advertisedNow"]
            and affected["notices"] == [{"affectedSelection": chosen, "notice": notice}],
            "official notice changed selection or duplicated affected-choice notification",
        )
        for e in pages:
            e["page"]["revision"] = "retired-release"
            e["page"]["models"] = [m for m in e["page"]["models"] if m["id"] != MODEL]
        publish()
        retired = c.call("example.model.selection", {"accountId": one})
        check(
            retired["selection"] == chosen
            and not retired["advertisedNow"]
            and retired["notices"] == affected["notices"],
            "retirement replaced selection or invented a new EOL",
        )
        c.call("example.conversation.exchange", turn, "incompatible", key="turn-after-retirement")
    with Client(db) as reopened:
        check(
            reopened.call("example.conversation.read", conversation) == before
            and reopened.call("example.model.selection", {"accountId": one}) == retired,
            "reopening lost history or explicit selection",
        )
    return {
        "account": one,
        "selectedModel": MODEL,
        "filteredCount": overview["count"],
        "totalOwned": overview["totalOwned"],
        "unit": overview["unit"],
        "limitingWindow": win["windowId"],
        "resetAtLocal": view["resetAtLocal"],
        "secondsUntilReset": view["secondsUntilReset"],
        "timeZone": view["timeZone"],
        "otherRouteHiddenByFilterRetained": True,
        "affectedModes": last["disableImpactModes"],
        "retainedUsagePeriods": list(last["usage"]),
        "uncertainPlanChoices": sorted(listed),
        "confirmedPriceWhenAmbiguous": None,
        "retainedSelection": chosen,
        "retainedTurns": len(before["turns"]),
        "officialNotice": notice,
        "retiredModelStillSelected": True,
    }


def effects(db):
    with Client(db) as a, Client(db, "beta") as other:
        id = a.connect()["account"]["accountId"]
        g = a.call("limits.read", {"accountId": id})
        p = a.prepare(id, "one")
        oid, pin = p["operationId"], p["intentDigest"]
        check(p == a.prepare(id, "one"), "new proposal for a replay")
        expected = hashlib.sha256(
            json.dumps(
                p["intent"], ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode()
        ).hexdigest()
        check(
            pin == expected
            and p["intent"]["subject"] == "alpha"
            and p["intent"]["manifestDigest"] == PIN
            and p["intent"]["scope"]["id"] == id,
            "scoped canonical intent",
        )
        for field in (
            "issuer",
            "subject",
            "scope",
            "packageId",
            "packageVersion",
            "manifestDigest",
            "operation",
            "version",
            "input",
            "target",
            "preconditions",
        ):
            material = {**p["intent"], field: "different"}
            check(
                hashlib.sha256(
                    json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                != pin,
                "unbound intent field " + field,
            )
        check(
            a.receipt(oid)["state"] == "not-applied"
            and a.call("limits.read", {"accountId": id}) == g,
            "prepare mutated right",
        )
        a.call("quota.reset", p["intent"]["input"], "denied", key="unapproved-direct")
        other.commit(oid, pin, "denied")
        a.commit(oid, pin, "denied")
        a.commit(oid, "f" * 64, "conflict")
        a.commit(oid, pin, "pin", manifestDigest="b" * 64)
        other.receipt(oid, "denied")
        check(
            local_admin(db, "beta", "approve", oid, pin, success=False) == "denied",
            "wrong human owner",
        )
        local_admin(db, "alpha", "approve", oid, pin)
        backup = Path(db).with_name("approval-backup.db")
        local_admin(db, "alpha", "backup", backup)
        with Client(backup) as restored:
            check(
                restored.commit(oid, pin)["state"] == "applied",
                "pending scoped approval was not restored",
            )
        other_proposal = a.prepare(id, "second")
        local_admin(
            db, "alpha", "approve", other_proposal["operationId"], other_proposal["intentDigest"]
        )
        a.call("account.enable", {"accountId": id, "enabled": False})
        a.commit(oid, pin, "denied")
        a.call("account.enable", {"accountId": id, "enabled": True})
        with Client(db, clock=BASE + 60) as expired:
            expired.commit(oid, pin, "deadline")
        with Client(db) as contestant, ThreadPoolExecutor(max_workers=2) as pool:
            r1 = pool.submit(a.commit, oid, pin)
            r2 = pool.submit(contestant.commit, oid, pin)
            receipt = r1.result(timeout=8)
            check(
                receipt == r2.result(timeout=8) and receipt["state"] == "applied",
                "concurrent receipts or state diverged",
            )
        a.commit(other_proposal["operationId"], other_proposal["intentDigest"], "conflict")
        check(a.prepare(id, "one") == p, "retry after commit recomputed earlier intent")
        check(
            a.call("limits.read", {"accountId": id})["resetGrants"][0]["count"] == 0,
            "wrong credit spend",
        )
    with Client(db, clock=BASE + 500, refresh=True) as later:
        reread = later.commit(oid, pin)
        check(
            reread["state"] == "applied"
            and reread["refreshError"]
            and reread["intentDigest"] == pin,
            "refresh failure became effect failure",
        )
    return {
        "resolvedIssuer": p["intent"]["issuer"],
        "originalCredits": g["resetGrants"][0]["count"],
        "remainingCredits": 0,
        "concurrentCommittedReceipts": 2,
        "actualDistinctEffects": 1,
        "restoredApproval": True,
        "refreshOutcome": reread["state"],
    }


def unknown(db):
    downstream = Path(db).with_name("independent-authority.db")
    with Client(db, delivery="external-lost", downstream=downstream) as a:
        id = a.connect()["account"]["accountId"]
        p = a.prepare(id, "unique")
        oid, d = p["operationId"], p["intentDigest"]
        local_admin(db, "alpha", "approve", oid, d)
        first = a.commit(oid, d)
        a.call("model.generate", a.request(id, "sky"), "unavailable", key="uncertain-read")
        check(
            first["state"] == "unknown"
            and a.call("limits.read", {"accountId": id})["windows"][0]["state"] == "unknown",
            "uncertain delivery claimed successful",
        )
    with Client(db, delivery="external-lost", downstream=downstream) as a:
        check(
            a.commit(oid, d)["state"] == "unknown" and a.receipt(oid)["state"] == "unknown",
            "uncertain retry after restart",
        )
        with sqlite3.connect(downstream) as observer:
            deliveries = observer.execute(
                "SELECT COUNT(*) FROM deliveries WHERE op=? AND digest=? AND owner=? AND account=?",
                (oid, d, "alpha", id),
            ).fetchone()[0]
        check(deliveries == 1, "non-idempotent external service received duplicate")
        settled = local_admin(db, "alpha", "reconcile", oid, d, downstream)
        check(
            settled["state"] == "applied" and a.commit(oid, d)["state"] == "applied",
            "readback did not retain settled result",
        )
        check(
            a.call("limits.read", {"accountId": id})["resetGrants"][0]["count"] == 0,
            "reconciliation consumed another credit",
        )
    return {
        "stateAfterDisconnect": "unknown",
        "stateAfterRestartBeforeReconciliation": "unknown",
        "observedDownstreamDeliveries": deliveries,
        "afterIndependentReceipt": settled["state"],
        "remainingCredits": 0,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path, required=True)
    opts = ap.parse_args()
    checks = []
    facts = {}
    funcs = {
        "authority": authority,
        "snapshots": snapshots,
        "amounts": amounts,
        "inference": inference,
        "absent-right": absent_right,
        "business": business,
        "selected-view": views_and_history,
        "effects": effects,
        "unknown": unknown,
    }
    with tempfile.TemporaryDirectory(prefix="ocs-provider-accept-") as d:
        for n, f in funcs.items():
            folder = Path(d) / n
            folder.mkdir()
            try:
                facts[n] = ("pass", f(folder / "store.db"))
            except Exception as err:
                facts[n] = ("fail", str(err))
    try:
        proof = verify(TARGET, opts.report.with_name(opts.report.stem + "-source.lean"))
        proof_status = "pass"
    except Exception as err:
        proof = {"error": str(err)}
        proof_status = "fail"
    manifest = read_json((ORACLE / "assurance/provider/evidence.json").read_bytes())
    for group, entries in manifest.items():
        for atom, gate in entries.items():
            if "probe" in gate:
                probe = gate["probe"]
                state, observation = facts[probe]
                checks.append(
                    {
                        "id": group + "." + atom,
                        "obligations": [atom],
                        "level": "runtime-observation",
                        "status": state,
                        "observed": observation,
                        "targets": ["reference/provider/executor.py", str(ADAPTER / "ocs.json")],
                        "probe": probe,
                    }
                )
                if gate.get("measurement"):
                    checks.append({**checks[-1], "level": "measurement"})
            for field, level, inventory in (
                ("model", "model", "theorems"),
                ("source", "source-refinement", "sourceTheorems"),
            ):
                if field in gate:
                    names = gate[field]
                    status = (
                        proof_status
                        if all(n in proof.get(inventory, []) for n in names)
                        else "fail"
                    )
                    checks.append(
                        {
                            "id": group + "." + atom,
                            "obligations": [atom],
                            "level": level,
                            "status": status,
                            "theorem": ["OCS.Provider." + n for n in names],
                            "observed": proof.get("error", names),
                            "assumptions": RULES["assumptions"],
                        }
                    )
    report = {
        "scope": "local provider, synthetic terms, deterministic inference, local ledger and independent downstream",
        "subject": str(TARGET),
        "pin": PIN,
        "featureMatrix": feature_matrix(),
        "targetDigests": {
            str(p.relative_to(TARGET)): sha(p)
            for p in [
                *sorted(ADAPTER.glob("*.py")),
                ADAPTER / "ocs.json",
                TARGET / "examples/reset/ledger.py",
                TARGET / "examples/reset/decision.py",
                TARGET / "reference/contracts.py",
                *sorted((TARGET / "schemas").glob("*.schema.json")),
            ]
        },
        "checks": checks,
        "proof": proof,
        "observedAt": utc_at(time.time()),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "sqlite": sqlite3.sqlite_version,
            "interpreterSha256": sha(Path(sys.executable).resolve()),
        },
        "assumptions": RULES["assumptions"],
    }
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    opts.report.write_text(json.dumps(report, indent=2) + "\n")
    failures = {n: v for n, (s, v) in facts.items() if s != "pass"}
    missing = [name for name, row in report["featureMatrix"].items() if not row["accepted"]]
    if missing:
        failures["featureMatrix"] = (
            "Published provider/effect methods without a validated, positive native observation: "
            + ", ".join(missing)
        )
    if proof_status != "pass":
        failures["proof"] = proof["error"]
    for n, detail in failures.items():
        print("FAIL", n, detail, file=sys.stderr)
    print(
        f"Provider: {sum(c['status'] == 'pass' for c in checks)}/{len(checks)} evidence items, report {opts.report}"
    )
    return int(bool(failures) or any(c["status"] != "pass" for c in checks))


if __name__ == "__main__":
    raise SystemExit(main())
