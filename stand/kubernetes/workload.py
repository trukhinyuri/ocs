#!/usr/bin/env python3
"""Observe the named provider over CA-verified HTTPS, then verify its state after recovery."""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import ssl
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference"))
from contracts import LIMIT, read_json, utc_at, validate, validate_with
from jsonschema import ValidationError

PLAN = read_json((ROOT / "assurance/provider/criteria.json").read_bytes())["workload"]
REGISTRY = {
    r["method"]: r
    for r in read_json((ROOT / "spec/profiles/operations.json").read_bytes())["operations"]
}
PIN = hashlib.sha256((ROOT / "reference/provider/ocs.json").read_bytes()).hexdigest()
PRODUCT = {"provider": "example.ledger", "product": "local-language"}


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp.write("\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        staged = Path(tmp.name)
    os.replace(staged, path)


def instant(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise ValueError("bound endpoint returned a redirect")


class Stand:
    def __init__(self, url, ca, tokenfile, *, relay=False):
        parts = parse.urlsplit(url)
        require(
            parts.scheme == "https"
            and parts.hostname
            and not parts.username
            and not parts.password
            and not parts.fragment
            and not parts.query,
            "expected an independently bound HTTPS endpoint",
        )
        require(parts.path in ("", "/", "/ocs"), "expected the provider /ocs endpoint")
        self.url = parse.urlunsplit((parts.scheme, parts.netloc, "/ocs", "", ""))
        self.token = tokenfile.read_text().strip()
        require(
            self.token and not any(c in self.token for c in "\r\n"),
            "missing or malformed scoped token",
        )
        self.ca_hash = hashlib.sha256(ca.read_bytes()).hexdigest()
        ctx = ssl.create_default_context(cafile=str(ca))
        self.open = request.build_opener(
            request.ProxyHandler({}), request.HTTPSHandler(context=ctx), NoRedirect()
        ).open
        self.count = 0
        self.last_metrics = {}
        self.relay = relay
        self.relay_pod = None

    def rpc(self, method, p, expected=None):
        self.count += 1
        rid = "qualification-" + str(self.count)
        frame = json.dumps(
            {"jsonrpc": "2.0", "method": method, "id": rid, "params": p}, separators=(",", ":")
        ).encode()
        req = request.Request(
            self.url,
            method="POST",
            data=frame,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token},
        )
        start = time.monotonic_ns()
        try:
            with self.open(req, timeout=5) as response:
                require(
                    response.status == 200
                    and response.headers.get_content_type() == "application/json",
                    "unexpected authenticated media type or status",
                )
                uid = response.headers.get("X-OCS-Relay-Pod")
                upstream_request = upstream_response = 0
                if self.relay:
                    require(
                        isinstance(uid, str)
                        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uid),
                        "authenticated relay did not name its Kubernetes pod",
                    )
                    require(
                        self.relay_pod is None or self.relay_pod == uid,
                        "relay implementation changed during measurement",
                    )
                    self.relay_pod = uid
                    for header in ("X-OCS-Upstream-Request-Bytes", "X-OCS-Upstream-Response-Bytes"):
                        raw_count = response.headers.get(header)
                        require(
                            isinstance(raw_count, str)
                            and re.fullmatch(r"[1-9][0-9]{0,7}", raw_count)
                            and int(raw_count) <= LIMIT,
                            "missing or invalid forwarded JSON byte observation",
                        )
                    upstream_request = int(response.headers["X-OCS-Upstream-Request-Bytes"])
                    upstream_response = int(response.headers["X-OCS-Upstream-Response-Bytes"])
                else:
                    require(uid is None, "direct provider path unexpectedly traversed the relay")
                raw = response.read(LIMIT + 1)
        except error.HTTPError as e:
            raise ValueError("authenticated provider returned HTTP " + str(e.code)) from e
        spent = (time.monotonic_ns() - start) / 1e6
        require(len(raw) <= LIMIT, "provider frame budget exceeded")
        body = read_json(raw)
        validate("wire", body, "failure" if "error" in body else "success")
        require(body["id"] == rid, "response correlation changed")
        self.last_metrics = {
            "jsonRequestBytes": len(frame),
            "jsonResponseBytes": len(raw),
            "forwardedRequestJsonBytes": upstream_request,
            "forwardedResponseJsonBytes": upstream_response,
            "firstUsefulMs": spent,
            "endToEndMs": spent,
        }
        if expected:
            require(
                body.get("error", {}).get("data", {}).get("kind") == expected,
                "unexpected refusal for " + method,
            )
            return body["error"]
        require(
            "result" in body,
            method + " refused with " + str(body.get("error", {}).get("data", {}).get("kind")),
        )
        return body["result"]

    def describe(self):
        d = self.rpc(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.providers/0.1"]
                if self.relay
                else ["ocs.providers/0.1", "ocs.effects/0.1"],
                "meta": {"deadline": utc_at(time.time() + 5)},
            },
        )
        validate("wire", d, "describeResult")
        require(
            d["manifestDigest"] == PIN and d["packageId"] == "org.example.reset",
            "unexpected authenticated manifest or package",
        )
        return d

    def call(self, op, body, key=None, expected=None):
        meta = {"protocol": "0.1", "manifestDigest": PIN, "deadline": utc_at(time.time() + 5)}
        if key:
            meta["idempotencyKey"] = key
        result = self.rpc(
            "tool.call",
            {"operation": op, "version": "1.0.0", "input": body, "meta": meta},
            expected,
        )
        if expected:
            return result
        validate("wire", result, "callResult")
        if op in REGISTRY:
            validate_with({"$ref": REGISTRY[op]["output"]}, result["data"])
        return result["data"]

    def accounts(self):
        result = {}
        q = PRODUCT.copy()
        seen = set()
        revision = None
        for _ in range(256):
            page = self.call("account.list", q)
            revision = revision or page["revision"]
            require(page["revision"] == revision, "account inventory changed during observation")
            for a in page["accounts"]:
                require(a["accountId"] not in result, "duplicate in account inventory")
                result[a["accountId"]] = a
            t = page.get("nextPageToken")
            if page["complete"]:
                require(not t, "complete account page still has continuation")
                return result
            require(t and t not in seen, "account cursor gap or cycle")
            seen.add(t)
            q = {**PRODUCT, "pageToken": t}
        raise ValueError("account inventory exceeds qualification budget")


def quantiles(ms):
    s = sorted(ms)

    def q(p):
        return round(s[math.ceil(p * len(s)) - 1], 3)

    return {"n": len(s), "p50": q(0.50), "p95": q(0.95), "p99": q(0.99), "max": round(max(s), 3)}


def now_stamp():
    return utc_at(time.time())


def qualify(api, state, statefile, record, relay=None):
    account = state.get("accountId")
    listed = api.accounts()
    if account is None:
        hits = [a for a in listed.values() if a["label"] == state["label"]]
        require(len(hits) <= 1, "ambiguous qualification account")
        if hits:
            account = hits[0]["accountId"]
        else:
            enrolled = api.call(
                "account.connect",
                {
                    **PRODUCT,
                    "authMethod": "local-none",
                    "settings": {"label": state["label"], "organization": "qualification-owners"},
                },
            )
            require(enrolled["kind"] == "ready", "local account not ready")
            account = enrolled["account"]["accountId"]
        state["accountId"] = account
        save(statefile, state)
    else:
        require(account in listed, "saved qualification account unavailable")
    args = {"accountId": account}
    price = api.call("plans.price", {**PRODUCT, "region": "fixture-region", **args})
    prices = {p["status"]: p for p in price["plans"]}
    require(
        prices["published"]["basis"] == "organization"
        and prices["published"]["price"] == {"amount": "2.50", "currency": "USD"}
        and prices["account-confirmed"]["price"] == {"amount": "0", "currency": "USD"}
        and prices["published"]["period"] == "P30D",
        "unexpected named service terms",
    )
    require(
        "price" not in prices["by-contract"] and "price" not in prices["unpublished"],
        "unknown price represented as numerical zero",
    )
    record(
        "P-03.basis",
        {
            "source": prices["published"]["evidence"]["source"],
            "published": prices["published"],
            "observedAccountPrice": prices["account-confirmed"],
            "purpose": "terms charged by this stand",
        },
    )
    terms = api.call("example.product.terms", args)
    require(
        all(
            terms.get(k)
            for k in (
                "owner",
                "organization",
                "plan",
                "expiresAt",
                "support",
                "continuity",
                "retentionSeconds",
                "observedAt",
            )
        ),
        "incomplete observed product obligations",
    )
    record("L-06.terms", terms)
    first_limits = api.call("limits.read", args)
    nonce = secrets.token_hex(6)
    stamp0 = now_stamp()
    questions = PLAN["questions"]
    policy = PLAN["parameters"]
    observed_scope = {"kind": "account", "id": account}
    range_start = utc_at(math.floor(instant(stamp0)) - 1)
    before_usage = api.call(
        "usage.read",
        {"scope": observed_scope, "from": range_start, "to": utc_at(math.floor(time.time()) + 1)},
    )

    def infer(parts, key, expected=None, endpoint=api):
        body = {
            **args,
            "route": PLAN["route"],
            "model": PLAN["model"],
            "parameters": policy,
            "input": [{"type": "text", "text": x} for x in parts],
        }
        output = endpoint.call("model.generate", body, key, expected)
        if expected:
            return output
        require(
            (
                output["accountId"],
                output["route"],
                output["model"],
                output["sent"],
                output["confirmed"],
            )
            == (account, PLAN["route"], PLAN["model"], policy, policy),
            "stand substituted route, model or options",
        )
        return output

    preamble = "Which numbered archive item was received in the previous neutral receipt?"
    prior = infer([preamble], nonce + "-prelude")
    history = [preamble, prior["parts"][0]["text"]]
    require(history[-1] == "unknown", "unexpected neutral conversation fact")
    stats = {}
    for strategy in ("direct", "full-admissible-history", "minimum-facts"):
        endpoint = api if strategy == "direct" or relay is None else relay
        samples = []
        first = []
        correct = 0
        request_bytes = 0
        response_bytes = 0
        forwarded_request = forwarded_response = 0
        tin = 0
        tout = 0
        for j, (question, label) in enumerate(questions):
            # Only the published neutral prelude and this public classification task
            # are permitted for relay. No private context is added to either path.
            parts = [*history, question] if strategy == "full-admissible-history" else [question]
            result = infer(parts, nonce + "-" + strategy + "-" + str(j), endpoint=endpoint)
            correct += result["parts"][0]["text"] == label
            samples.append(endpoint.last_metrics["endToEndMs"])
            first.append(endpoint.last_metrics["firstUsefulMs"])
            request_bytes += endpoint.last_metrics["jsonRequestBytes"]
            response_bytes += endpoint.last_metrics["jsonResponseBytes"]
            forwarded_request += endpoint.last_metrics["forwardedRequestJsonBytes"]
            forwarded_response += endpoint.last_metrics["forwardedResponseJsonBytes"]
            tin += result["inputTokens"]
            tout += result["outputTokens"]
        stats[strategy] = {
            "recipient": endpoint.url,
            "relayPodUID": endpoint.relay_pod,
            "correct": correct,
            "tasks": len(questions),
            "requestJsonBytes": request_bytes,
            "responseJsonBytes": response_bytes,
            "upstreamRequestJsonBytes": forwarded_request,
            "upstreamResponseJsonBytes": forwarded_response,
            "allHopJsonBytes": request_bytes
            + response_bytes
            + forwarded_request
            + forwarded_response,
            "byteScope": "Application JSON bytes across the observed hops, excluding HTTP framing and TLS ciphertext overhead.",
            "inputTokens": tin,
            "outputTokens": tout,
            "synchronousFirstUsefulMs": quantiles(first),
            "endToEndMs": quantiles(samples),
        }
        require(
            correct >= PLAN["minimumCorrect"]
            and stats[strategy]["endToEndMs"]["p95"] <= PLAN["maxP95Milliseconds"],
            "quality or elapsed-time contract failed for " + strategy,
        )
    require(
        stats["full-admissible-history"]["inputTokens"] > stats["minimum-facts"]["inputTokens"]
        and stats["full-admissible-history"]["requestJsonBytes"]
        > stats["minimum-facts"]["requestJsonBytes"],
        "relay encodings failed to demonstrate the scoped reduction",
    )
    after = api.call("limits.read", args)
    grant = after["resetGrants"][0]
    require(
        grant["count"] == first_limits["resetGrants"][0]["count"]
        and grant["affectedWindows"] == ["weekly"]
        and grant["charge"] == {"amount": "0", "currency": "USD"},
        "inspection consumed or substituted a provider reset",
    )
    record(
        "Q-02.read-only",
        {
            "account": account,
            "grant": grant,
            "beforeCount": first_limits["resetGrants"][0]["count"],
            "afterCount": grant["count"],
            "operations": ["limits.read"],
        },
    )
    burst = next(w for w in after["windows"] if w["windowId"] == "burst")
    until = instant(burst["resetAt"]) - time.time()
    require(until < 4 and until > -3, "stand clock outside declared telemetry window")
    if until >= 0:
        time.sleep(until + 0.12)
    fresh = api.call("limits.read", args)
    burst2 = next(w for w in fresh["windows"] if w["windowId"] == "burst")
    require(
        burst2["resetAt"] > burst["resetAt"]
        and instant(burst2["evidence"]["observedAt"]) >= instant(burst["resetAt"]),
        "expired burst quota was not re-observed",
    )
    record(
        "Q-01.reobserve",
        {"before": burst, "after": burst2, "sampledThrough": "limits.read on authenticated stand"},
    )
    catalog = api.call("model.list", {**args, "route": PLAN["route"]})
    model = next(v for v in catalog["models"] if v["id"] == PLAN["model"])
    unmapped = next(v for v in catalog["models"] if v["id"] == "preview-lattice")
    require(
        model["officiallyListed"]
        and model["entitled"]
        and model["adapterSupported"]
        and model["verifiedOptions"]
        and unmapped["entitled"] is None
        and not unmapped["adapterSupported"],
        "catalog/entitlement/adapter evidence collapsed",
    )
    record(
        "M-01.axes",
        {
            "scope": catalog["scope"],
            "revision": catalog["revision"],
            "current": model,
            "unmapped": unmapped,
        },
    )
    body = {
        **args,
        "route": PLAN["route"],
        "model": PLAN["model"],
        "input": [{"type": "text", "text": "mint"}],
        "parameters": {"reasoning": "off", "tier": "ultrafast"},
    }
    api.call("model.generate", body, nonce + "-invalid-mode", expected="incompatible")
    record(
        "M-02.response",
        {
            "accountId": account,
            "route": PLAN["route"],
            "model": PLAN["model"],
            "requested": policy,
            "sent": prior["sent"],
            "confirmed": prior["confirmed"],
            "verifiedCombinations": 3 * len(questions),
            "unsupportedTier": "incompatible",
        },
    )
    # Meter timestamps on this product have second precision. Round outwards to
    # include the full measured session, then keep exactly that old interval.
    range_args = {
        "scope": observed_scope,
        "from": range_start,
        "to": utc_at(math.floor(time.time()) + 1),
    }
    usage = api.call("usage.read", range_args)
    require(
        usage["probeRequests"] - before_usage["probeRequests"] == 3 * len(questions) + 1
        and usage["workRequests"] == before_usage["workRequests"]
        and usage["fallbackUses"] == before_usage["fallbackUses"]
        and usage["spend"] == before_usage["spend"] == {"amount": "0", "currency": "USD"},
        "stand failed to attribute actual probes or reported unexpected charges",
    )
    facts = {
        "accountId": account,
        "route": PLAN["route"],
        "model": PLAN["model"],
        "mode": policy,
        "usage": usage,
        "priorUsage": before_usage,
        "thresholds": {k: PLAN[k] for k in ("minimumCorrect", "maxP95Milliseconds")},
    }
    record("A-02.probe", facts)
    if relay is not None:
        require(
            relay.url != api.url
            and relay.relay_pod
            and all(
                stats[k]["relayPodUID"] == relay.relay_pod
                for k in ("full-admissible-history", "minimum-facts")
            )
            and stats["direct"]["relayPodUID"] is None,
            "no distinct authenticated relay measurement",
        )
        record(
            "G-04.comparison",
            {
                **facts,
                "results": stats,
                "history": "actual public prelude/reply sent by the qualified stand",
                "relay": {
                    "url": relay.url,
                    "podUID": relay.relay_pod,
                    "authorization": "independently scoped relay bearer",
                },
                "benchmark": "same eight sealed tasks, actual remote inference; local classifier",
            },
        )
    state.update(
        {
            "phase": "qualified",
            "range": range_args,
            "usage": usage,
            "termPlan": terms["plan"],
            "lastReplyAt": model["verifiedAt"],
            "manifestDigest": PIN,
            "resetGrantCount": grant["count"],
            "capturedAt": now_stamp(),
        }
    )
    save(statefile, state)


def resume(api, state, record):
    require(
        state.get("phase") == "qualified"
        and state.get("manifestDigest", state.get("sourceRevision")) == PIN,
        "a complete prior target observation is required",
    )
    id = state["accountId"]
    rows = api.accounts()
    require(
        id in rows and rows[id]["lastReply"]["at"] == state["lastReplyAt"],
        "restored identity or last reply diverged",
    )
    usage = api.call("usage.read", state["range"])
    comparable = (
        "scope",
        "from",
        "to",
        "workRequests",
        "successful",
        "activeDays",
        "probeRequests",
        "fallbackUses",
        "attribution",
        "spend",
    )
    require(
        all(usage[k] == state["usage"][k] for k in comparable),
        "restored scoped meter interval differs",
    )
    grant = api.call("limits.read", {"accountId": id})["resetGrants"][0]
    terms = api.call("example.product.terms", {"accountId": id})
    require(
        grant["count"] == state["resetGrantCount"] and terms["plan"] == state["termPlan"],
        "restored grant or entitlement diverged",
    )
    record(
        "L-06.recovery",
        {
            "accountId": id,
            "durableLastReply": state["lastReplyAt"],
            "usage": usage,
            "grants": grant["count"],
            "previousObservation": state["capturedAt"],
            "observedRecovery": "authenticated readback of previously captured scope; controller supplies backup/restore event evidence",
        },
    )


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--url", required=True)
    arg.add_argument("--ca", required=True, type=Path)
    arg.add_argument("--token-file", required=True, type=Path)
    arg.add_argument("--report", required=True, type=Path)
    arg.add_argument("--state", required=True, type=Path)
    arg.add_argument("--resume", action="store_true")
    arg.add_argument("--relay-url", help="separately deployed CA-verified OCS relay")
    arg.add_argument(
        "--relay-token-file",
        type=Path,
        help="distinct inward credential authorized only at the relay",
    )
    arg.add_argument(
        "--transport-diagnostic",
        action="store_true",
        help="local one-hop check that makes no deployment claim about relay comparison",
    )
    o = arg.parse_args()
    if bool(o.relay_url) != bool(o.relay_token_file):
        arg.error("supply both --relay-url and --relay-token-file")
    if not (o.resume or o.transport_diagnostic or o.relay_url):
        arg.error("normal live qualification requires a distinct scoped relay")
    report = {
        "scope": "real owner-selected HTTPS stand running the sealed provider",
        "level": "deployment",
        "checks": [],
        "observedAt": now_stamp(),
        "manifestDigest": PIN,
        "client": {
            "python": platform.python_version(),
            "platform": platform.system() + " " + platform.machine(),
        },
        "mode": "restored-readback"
        if o.resume
        else ("single-hop-diagnostic" if o.transport_diagnostic else "live-qualified"),
    }

    def record(id, data):
        report["checks"].append(
            {
                "id": id,
                "obligations": [id],
                "level": "deployment",
                "status": "pass",
                "observedAt": now_stamp(),
                "observed": data,
            }
        )

    try:
        api = Stand(o.url, o.ca, o.token_file)
        report["target"] = {
            "url": api.url,
            "caSha256": api.ca_hash,
            "service": "org.example.reset",
            "route": "local-primary",
            "model": PLAN["model"],
        }
        api.describe()
        if o.state.exists():
            state = read_json(o.state.read_bytes())
            require(
                (state["url"], state["caSha256"]) == (api.url, api.ca_hash),
                "saved state belongs to another deployment trust binding",
            )
        else:
            require(not o.resume, "initial qualification state missing")
            state = {
                "url": api.url,
                "caSha256": api.ca_hash,
                "label": "qualification-" + secrets.token_hex(8),
                "phase": "enrolling",
            }
            save(o.state, state)
        if o.resume:
            resume(api, state, record)
        else:
            relay = None
            if o.relay_url:
                relay = Stand(o.relay_url, o.ca, o.relay_token_file, relay=True)
                require(
                    relay.url != api.url and not secrets.compare_digest(relay.token, api.token),
                    "relay must use its own endpoint and least-privilege credential",
                )
                relay.describe()
            qualify(api, state, o.state, record, relay)
        report["status"] = "pass"
    except ValidationError as exc:
        report["status"] = "fail"
        report["failure"] = "Invalid authenticated response at /" + "/".join(
            map(str, exc.absolute_path)
        )
    except (
        OSError,
        TimeoutError,
        ValueError,
        KeyError,
        RuntimeError,
        error.URLError,
        StopIteration,
    ) as exc:
        report["status"] = "fail"
        report["failure"] = str(exc)
    finally:
        report["finishedAt"] = now_stamp()
        save(o.report, report)
    print(report["status"], "stand provider checks", len(report["checks"]), o.report)
    if report["status"] != "pass":
        print(report.get("failure", "stand failure"), file=sys.stderr)
    return int(report["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
