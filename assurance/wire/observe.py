"""Measure both real status executors and callers through their public command lines."""

import hashlib
import http.client
import json
import os
import secrets
import select
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from time import monotonic
from urllib.parse import urlsplit

LIMIT = 1048576


def ensure(ok, message):
    if not ok:
        raise AssertionError(message)


def rpc(command, frames, expect_exit=0):
    encoded = b"".join(
        (frame if isinstance(frame, bytes) else json.dumps(frame).encode()) + b"\n"
        for frame in frames
    )
    p = subprocess.run(command, input=encoded, capture_output=True, timeout=12)
    ensure((p.returncode == 0) == (expect_exit == 0), "unexpected status for raw stdio frame")
    if not p.stdout:
        return []
    ensure(p.stdout.endswith(b"\n"), "unterminated stdout response")
    return [json.loads(line) for line in p.stdout[:-1].split(b"\n")]


def request(rid, method, params):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def before(seconds):
    return (
        (datetime.now(timezone.utc) + timedelta(seconds=seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def run_executor(command, manifest, reporter):
    raw = manifest.read_bytes()
    descriptor = json.loads(raw)
    pin = hashlib.sha256(raw).hexdigest()
    when = before(50)
    hello = request(
        "des",
        "ocs.describe",
        {"protocols": ["9.0", "0.1"], "requiredFeatures": [], "meta": {"deadline": when}},
    )
    call = request(
        "invoke",
        "tool.call",
        {
            "operation": "example.status.read",
            "version": "1.0.0",
            "input": {"resourceId": "demo"},
            "meta": {"protocol": "0.1", "manifestDigest": pin, "deadline": when},
        },
    )

    def variant(rid, *, top=None, meta=None, payload=None):
        result = json.loads(json.dumps(call))
        result["id"] = rid
        result["params"].update(top or {})
        result["params"]["meta"].update(meta or {})
        if payload is not None:
            result["params"]["input"] = payload
        return result

    def fault(response, code, kind, rid):
        ensure(
            response.get("id") == rid
            and response.get("jsonrpc") == "2.0"
            and set(response) == {"jsonrpc", "id", "error"},
            "wrong fault envelope/correlation",
        )
        error = response["error"]
        ensure(
            (error.get("code"), error.get("data", {}).get("kind")) == (code, kind)
            and isinstance(error.get("message"), str)
            and error["message"],
            "wrong fault classification",
        )

    first = rpc(command, [call, hello, call])
    fault(first[0], -33008, "incompatible", "invoke")
    ensure(
        first[1]
        == {
            "jsonrpc": "2.0",
            "id": "des",
            "result": {
                "protocol": "0.1",
                "packageId": descriptor["id"],
                "packageVersion": descriptor["version"],
                "manifestDigest": pin,
                "features": [],
                "maxFrameBytes": LIMIT,
            },
        },
        "wrong descriptor/selection/frame bound",
    )
    ensure(
        first[2]
        == {
            "jsonrpc": "2.0",
            "id": "invoke",
            "result": {"data": {"resourceId": "demo", "state": "ready"}},
        },
        "public status response differs from the accepted contract",
    )
    reporter(
        "admitted-read",
        {"verifiedPin": pin, "unnegotiatedRefused": True, "wire": "0.1", "limit": LIMIT},
    )

    cases = [
        (variant("bad-input", payload={"resourceId": False}), -33009, "input"),
        (
            variant("denied", meta={"traceId": "administrator"}, payload={"resourceId": "other"}),
            -33001,
            "denied",
        ),
        (variant("bad-pin", meta={"manifestDigest": "0" * 64}), -33014, "pin"),
        (variant("wrong-op", top={"operation": "example.status.change"}), -32601, "method"),
        (variant("old-contract", top={"version": "3.2.1"}), -33008, "incompatible"),
        (
            variant("malformed-date", meta={"deadline": "2030-02-30T12:15:01.000Z"}),
            -32602,
            "params",
        ),
        (variant("expired", meta={"deadline": before(-5)}), -33005, "deadline"),
    ]
    attempts = [hello]
    for msg, _, _ in cases:
        attempts.extend(
            [msg, {"jsonrpc": "2.0", "method": "ocs.cancel", "params": {"requestId": "unknown"}}]
        )
    attempts += [variant("opaque-id"), variant("denied", meta={"traceId": "non-authoritative"})]
    answers = rpc(command, attempts)
    ensure(len(answers) == 1 + len(cases) + 2, "unexpected reply to notification")
    for (msg, code, kind), answer in zip(cases, answers[1 : 1 + len(cases)], strict=True):
        fault(answer, code, kind, msg["id"])
    ensure(
        answers[1]["error"]["data"]["path"] == "/resourceId",
        "input pointer is not relative to the payload",
    )
    for response, rid in zip(answers[-2:], ["opaque-id", "denied"], strict=True):
        ensure(
            response
            == {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"data": {"resourceId": "demo", "state": "ready"}},
            },
            "recover-after-input-error failed after ordinary refused calls",
        )
    reporter(
        "recovered-calls",
        {
            "refusals": [kind for _, _, kind in cases],
            "notificationReplies": 0,
            "postFailureReadIds": [r["id"] for r in answers[-2:]],
        },
    )

    renegotiation = json.loads(json.dumps(hello))
    renegotiation["params"]["requiredFeatures"] = ["example.missing/1.0"]
    output = rpc(command, [hello, renegotiation, call])
    fault(output[1], -33008, "incompatible", "des")
    fault(output[2], -33008, "incompatible", "invoke")
    reporter("renegotiate", {"unknownMandatoryRejected": True, "retiredNegotiationRejected": True})

    malformed = [
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e80}',
        b'{"a":9007199254740992}',
        b'{"a":9007199254740992.0}',
        b'{"a":"\\ud800"}',
    ]
    output = rpc(command, [*malformed, b"[]", b'{"id":22}'])
    for reply in output[: len(malformed)]:
        fault(reply, -32700, "parse", None)
    for reply in output[len(malformed) :]:
        fault(reply, -32600, "request", None)
    exact = json.dumps(hello, ensure_ascii=False).encode()
    payload = exact + b" " * (LIMIT - len(exact))
    good = rpc(command, [payload])
    ensure(good[0] == first[1], "exact-frame boundary rejected")
    ensure(rpc(command, [payload + b" "], 1) == [], "oversized frame produced a response")
    raw = subprocess.run(command, input=exact, capture_output=True, timeout=10)
    ensure(raw.returncode != 0 and not raw.stdout, "unterminated frame succeeded")
    reporter(
        "framing",
        {
            "rawEncodingRefusals": len(malformed),
            "invalidEnvelopes": 2,
            "exactBytes": len(payload),
            "firstRejectedBytes": len(payload) + 1,
            "partialRejected": True,
        },
    )


PEER = """import datetime, hashlib, json, sys, time
from pathlib import Path
root = Path(__file__).parent
manifest = root.joinpath("ocs.json").read_bytes()
desc = json.loads(manifest)
settings = json.loads(root.joinpath("behavior.json").read_bytes())
for line in sys.stdin:
    msg = json.loads(line)
    if msg["method"] == "ocs.describe":
        result = {"protocol":"0.1", "packageId":desc["id"], "packageVersion":desc["version"],
                  "manifestDigest":hashlib.sha256(manifest).hexdigest(), "features": [], "maxFrameBytes": 1048576}
        result.update(settings.get("describe", {}))
    else:
        root.joinpath("received-call").write_text(msg["params"]["meta"]["deadline"])
        if settings.get("delay"):
            time.sleep(settings["delay"])
        result = {"data":{"resourceId":"demo","state":"ready"}}
        result.update(settings.get("result",{}))
    reply_id = "substituted" if settings.get("wrongId") else msg["id"]
    print(json.dumps({"jsonrpc":"2.0","id":reply_id,"result":result}),flush=True)
    if msg["method"]=="tool.call":
        root.joinpath("delivered-read").write_text(str(time.time()))
if settings.get("closeDelay"):
    time.sleep(settings["closeDelay"])
"""


def check_hosts(root, go_binary, work):
    manifest = root / "examples/status/ocs.json"
    commands = {"python": [sys.executable, str(root / "reference/host.py")], "go": [str(go_binary)]}
    variants = {
        "identity": ({"describe": {"packageId": "org.example.other"}}, False),
        "revision": ({"describe": {"packageVersion": "2.0.0"}}, False),
        "pin": ({"describe": {"manifestDigest": "b" * 64}}, False),
        "bounds": ({"describe": {"maxFrameBytes": 1}}, False),
        "correlation": ({"wrongId": True}, False),
        "output": ({"result": {"data": {"resourceId": "substituted", "state": "ready"}}}, True),
        "deadline": ({"delay": 5.5}, True),
        "teardown": ({"closeDelay": 5.5}, True),
    }

    def run(lang):
        directory = work / ("host-probe-" + lang)
        directory.mkdir()
        shutil.copy2(manifest, directory / "ocs.json")
        (directory / "executor.py").write_text(PEER)
        durations = {}
        for case, (config, should_call) in variants.items():
            if case == "teardown" and lang == "python":
                # The Python caller's shorter inbound deadline is driven through
                # its real authenticated HTTP peer in child_deadlines below.
                continue
            marker = directory / "received-call"
            marker.unlink(missing_ok=True)
            delivered = directory / "delivered-read"
            delivered.unlink(missing_ok=True)
            (directory / "behavior.json").write_text(json.dumps(config))
            start = monotonic()
            p = subprocess.run(
                [*commands[lang], "--manifest", str(directory / "ocs.json"), "--resource", "demo"],
                capture_output=True,
                timeout=12,
            )
            durations[case] = round(monotonic() - start, 6)
            ensure(p.returncode != 0 and not p.stdout, f"{lang} host wrongly accepted {case}")
            ensure(
                marker.exists() == should_call,
                f"{lang} host reached an unauthorized call for {case}",
            )
            if case in ("deadline", "teardown"):
                ensure(
                    b"deadline" in p.stderr.lower(),
                    f"{lang} late-read diagnostic was {p.stderr[-180:]!r}",
                )
            if case == "teardown":
                cutoff = datetime.fromisoformat(
                    marker.read_text().replace("Z", "+00:00")
                ).timestamp()
                ensure(
                    delivered.is_file() and float(delivered.read_text()) < cutoff,
                    "Go teardown failure did not follow a timely completed service result",
                )
        return {
            "failedBeforeCall": [s for s, (_, call) in variants.items() if not call],
            "failedAfterCall": [name for name in durations if variants[name][1]],
            "latencySeconds": durations,
        }

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        jobs = {language: pool.submit(run, language) for language in commands}
        return {language: job.result() for language, job in jobs.items()}


def child_deadlines(root, work):
    directory = work / "parent-deadline"
    directory.mkdir()
    shutil.copy2(root / "examples/status/ocs.json", directory / "ocs.json")
    (directory / "behavior.json").write_text("{}")
    (directory / "executor.py").write_text(PEER)
    marker = directory / "received-call"
    token = secrets.token_hex(24)
    process = subprocess.Popen(
        [
            sys.executable,
            str(root / "reference/peer.py"),
            "--manifest",
            str(directory / "ocs.json"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={**os.environ, "OCS_DEMO_TOKEN": token},
    )
    samples = []
    try:
        ensure(select.select([process.stdout], [], [], 5)[0], "deadline peer did not start")
        origin = urlsplit(process.stdout.readline().strip())
        ensure(
            origin.scheme == "http" and origin.hostname == "127.0.0.1" and origin.path == "/ocs",
            "unexpected peer",
        )
        pin = hashlib.sha256((directory / "ocs.json").read_bytes()).hexdigest()
        for parent_seconds in (2, 30, 0.24):
            inbound = before(parent_seconds)
            teardown = parent_seconds < 1
            (directory / "behavior.json").write_text(
                json.dumps({"closeDelay": 2} if teardown else {})
            )
            (directory / "delivered-read").unlink(missing_ok=True)
            frame = request(
                "parent",
                "tool.call",
                {
                    "operation": "example.status.read",
                    "version": "1.0.0",
                    "input": {"resourceId": "demo"},
                    "meta": {"protocol": "0.1", "manifestDigest": pin, "deadline": inbound},
                },
            )
            connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=5)
            try:
                connection.request(
                    "POST",
                    origin.path,
                    json.dumps(frame),
                    {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                )
                response = connection.getresponse()
                raw = response.read(LIMIT + 1)
                ensure(
                    response.status == 200 and len(raw) <= LIMIT,
                    "parent returned an invalid response",
                )
                reply = json.loads(raw)
                if teardown:
                    ensure(
                        "result" not in reply
                        and reply.get("error", {}).get("data", {}).get("kind") == "deadline",
                        "Python parent delivered a success after teardown exhausted its original deadline",
                    )
                    sent_at = float((directory / "delivered-read").read_text())
                    ensure(
                        sent_at
                        < datetime.fromisoformat(inbound.replace("Z", "+00:00")).timestamp(),
                        "delayed-cleanup probe did not receive an on-time service reply",
                    )
                else:
                    ensure(
                        reply.get("result") == {"data": {"resourceId": "demo", "state": "ready"}},
                        "parent call was not fulfilled",
                    )
            finally:
                connection.close()
            child = marker.read_text()
            parent_end = datetime.fromisoformat(inbound.replace("Z", "+00:00"))
            child_end = datetime.fromisoformat(child.replace("Z", "+00:00"))
            ensure(child_end <= parent_end, "delegation increased the parent's deadline")
            if parent_seconds == 30:
                ensure(
                    (parent_end - child_end).total_seconds() >= 23,
                    "local child budget did not clamp the long parent deadline",
                )
            samples.append(
                {
                    "parent": inbound,
                    "child": child,
                    "offeredSeconds": parent_seconds,
                    "outcome": "deadline after timely service reply and delayed cleanup"
                    if teardown
                    else "ready",
                }
            )
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
    return samples
