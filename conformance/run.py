#!/usr/bin/env python3
"""Black-box core-executor cases plus independent host and peer smoke tests."""

import argparse
import hashlib
import json
import os
import platform
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from contracts import LIMIT, read_json, validate, validate_with


def stamp(offset=0):
    instant = datetime.now(timezone.utc) + timedelta(seconds=offset)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def expand(value, variables):
    if isinstance(value, str):
        return variables.get(value, value)
    if isinstance(value, list):
        return [expand(x, variables) for x in value]
    if isinstance(value, dict):
        return {k: expand(v, variables) for k, v in value.items()}
    return value


def matches(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and matches(v, actual[k]) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(matches(wanted, item) for wanted, item in zip(expected, actual, strict=True))
        )
    return type(expected) is type(actual) and expected == actual


def exchange(command, frames):
    payload = b"".join(frame.encode() + b"\n" for frame in frames)
    # Corpus requests fit in one pipe write. Never wait for output without a deadline.
    if len(payload) > 4096:
        raise ValueError("case exceeds the runner's batch input bound")
    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
        end = time.monotonic() + 8
        raw = bytearray()
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([proc.stdout], [], [], left)[0]:
                raise TimeoutError("target exceeded case deadline")
            part = os.read(proc.stdout.fileno(), 65536)
            if not part:
                break
            raw.extend(part)
            if len(raw) > (LIMIT + 1) * len(frames):
                raise ValueError("target exceeded byte limit")
        if proc.wait(timeout=max(0.01, end - time.monotonic())) != 0:
            raise ValueError("target exited with an error")
        if raw and not raw.endswith(b"\n"):
            raise ValueError("unterminated frame")
        lines = raw[:-1].split(b"\n") if raw else []
        if any(len(line) > LIMIT for line in lines):
            raise ValueError("frame limit")
        return [read_json(line) for line in lines]
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        if not proc.stdin.closed:
            proc.stdin.close()
        proc.stdout.close()


def run_case(command, case, variables, outputs):
    expected = []
    frames = []
    for i, step in enumerate(case["steps"], 1):
        rid = step.get("responseId", str(i))
        if "raw" in step:
            frames.append(step["raw"])
        else:
            msg = {
                "jsonrpc": "2.0",
                "id": rid,
                "method": step["method"],
                "params": expand(step["params"], variables),
            }
            frames.append(json.dumps(msg))
        if not step.get("noReply", False):
            expected.append(
                (step, {"jsonrpc": "2.0", "id": rid, **expand(step["expect"], variables)})
            )
    replies = exchange(command, frames)
    if len(replies) != len(expected):
        raise AssertionError("wrong response count")
    for (step, wanted), got in zip(expected, replies):
        validate("wire", got, "failure" if "error" in wanted else "success")
        if "result" in wanted and step.get("method") == "ocs.describe":
            validate("wire", got["result"], "describeResult")
            if not set(step["params"]["requiredFeatures"]).issubset(got["result"]["features"]):
                raise AssertionError("negotiated feature missing")
        if "result" in wanted and step.get("method") == "tool.call":
            validate("wire", got["result"], "callResult")
            key = (step["params"]["operation"], step["params"]["version"])
            validate_with(outputs[key], got["result"]["data"])
        if not matches(wanted, got):
            raise AssertionError("response did not match the published case")


def collect(checks, case_id, rule, function):
    try:
        function()
    except Exception as exc:
        checks.append(
            {
                "id": case_id,
                "rule": rule,
                "status": "fail",
                "detail": (str(exc) or type(exc).__name__)[:250],
            }
        )
    else:
        checks.append(
            {"id": case_id, "rule": rule, "status": "pass", "detail": "Observed expected behavior."}
        )


def process_check(command, refusal=None, env=None):
    r = subprocess.run(command, capture_output=True, timeout=12, env=env)
    if refusal is None:
        if r.returncode or read_json(r.stdout) != {"resourceId": "demo", "state": "ready"}:
            raise AssertionError("read path did not return the expected fixture")
    elif not r.returncode or refusal not in r.stderr.decode(errors="replace").lower():
        raise AssertionError("expected refusal was not observed")


def executor_cases(checks, command, manifest, cases, prefix=""):
    raw = manifest.read_bytes()
    descriptor = read_json(raw)
    validate("manifest", descriptor)
    outputs = {(op["id"], op["version"]): op["outputSchema"] for op in descriptor["exports"]}
    for case in cases:
        variables = {
            "${deadline}": stamp(6),
            "${past}": stamp(-10),
            "${manifestDigest}": hashlib.sha256(raw).hexdigest(),
            "${packageId}": descriptor["id"],
            "${packageVersion}": descriptor["version"],
        }
        collect(
            checks,
            prefix + case["id"],
            case["rule"],
            lambda: run_case(command, case, variables, outputs),
        )


def host_cases(checks, manifest, cases):
    with tempfile.TemporaryDirectory() as temp:
        go = str(Path(temp) / "host")
        subprocess.run(
            ["go", "build", "-o", go, "./reference/go"], cwd=ROOT, check=True, timeout=120
        )
        go_manifest = ROOT / "reference/go/ocs.json"
        executor_cases(
            checks,
            [go, "--serve", "--manifest", str(go_manifest)],
            go_manifest,
            cases,
            "go-executor-",
        )
        for name, cmd in [
            ("python", [sys.executable, str(ROOT / "reference/host.py")]),
            ("go", [go]),
        ]:
            base = [*cmd, "--manifest", str(manifest)]
            collect(checks, name + "-host-read", "W-06", lambda: process_check(base))
            collect(
                checks,
                name + "-host-scope",
                "B-03",
                lambda: process_check([*base, "--resource", "private"], "denied"),
            )

        faulty = Path(temp) / "invalid-output-package"
        shutil.copytree(manifest.parent, faulty)
        entry = faulty / "executor.py"
        before = entry.read_text()
        after = before.replace('"state": "ready"', '"state": "unrecognized"')
        if after == before:
            raise ValueError("could not construct the invalid-output fixture")
        entry.write_text(after)
        for name, cmd in [
            ("python", [sys.executable, str(ROOT / "reference/host.py")]),
            ("go", [go]),
        ]:
            collect(
                checks,
                name + "-rejects-invalid-output",
                "C-05",
                lambda: process_check([*cmd, "--manifest", str(faulty / "ocs.json")], "output"),
            )

        env = {**os.environ, "OCS_DEMO_TOKEN": secrets.token_hex(24)}
        peer = subprocess.Popen(
            [sys.executable, str(ROOT / "reference/peer.py"), "--manifest", str(manifest)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
        )
        try:
            if not select.select([peer.stdout], [], [], 8)[0]:
                raise TimeoutError("peer did not start")
            endpoint = peer.stdout.readline().strip()
            if not endpoint.startswith("http://127.0.0.1:"):
                raise ValueError("unexpected peer address")
            base = [go, "--manifest", str(manifest), "--loopback-peer", endpoint]
            collect(
                checks,
                "read-through-independent-peer",
                "B-04",
                lambda: process_check(base, env=env),
            )
            collect(
                checks,
                "peer-credential-denied",
                "B-03",
                lambda: process_check(base, "403", {**env, "OCS_DEMO_TOKEN": "ungranted"}),
            )

            def refused_write():
                pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
                data = {
                    "jsonrpc": "2.0",
                    "id": "refusal",
                    "method": "tool.call",
                    "params": {
                        "operation": "quota.reset",
                        "version": "1.0.0",
                        "input": {},
                        "meta": {"protocol": "0.1", "deadline": stamp(5), "manifestDigest": pin},
                    },
                }
                opener = request.build_opener(request.ProxyHandler({}))
                req = request.Request(
                    endpoint,
                    data=json.dumps(data).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + env["OCS_DEMO_TOKEN"],
                    },
                )
                with opener.open(req, timeout=5) as response:
                    answer = read_json(response.read(LIMIT + 1))
                if answer.get("error", {}).get("code") != -33001:
                    raise AssertionError("read grant did not refuse a write")

            collect(checks, "peer-denies-write-on-read-grant", "B-03", refused_write)
        finally:
            peer.terminate()
            peer.wait(timeout=5)
            peer.stdout.close()
        collect(
            checks,
            "local-owner-survives-peer-loss",
            "B-05",
            lambda: process_check([go, "--manifest", str(manifest)]),
        )


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--manifest", type=Path, default=ROOT / "examples/status/ocs.json")
    args.add_argument("--cases", type=Path, default=ROOT / "conformance/cases/core.json")
    args.add_argument("--report", type=Path, default=ROOT / "out/conformance.json")
    args.add_argument(
        "--target",
        nargs=argparse.REMAINDER,
        help="explicit reviewed executor command; runs executor cases only",
    )
    options = args.parse_args()
    manifest = options.manifest.resolve()
    raw = manifest.read_bytes()
    meta = read_json(raw)
    validate("manifest", meta)
    if options.target is None and (
        manifest != (ROOT / "examples/status/ocs.json")
        or options.cases.resolve() != (ROOT / "conformance/cases/core.json")
    ):
        args.error("select the executor with --target for a custom manifest or corpus")
    command = (
        options.target
        if options.target is not None
        else [sys.executable, "-I", str(manifest.parent / "executor.py")]
    )
    if not command:
        args.error("--target needs an explicit command")
    checks = []
    case_bytes = options.cases.read_bytes()
    cases = read_json(case_bytes)
    executor_cases(checks, command, manifest, cases)
    full = options.target is None
    if full:
        collect(
            checks,
            "host-and-peer-fixture-boot",
            "B-01",
            lambda: host_cases(checks, manifest, cases),
        )
    passed = {check["id"] for check in checks if check["status"] == "pass"}
    contracts = set()
    negotiated = set()
    for case in cases:
        if case["id"] not in passed:
            continue
        for step in case["steps"]:
            if "result" not in step.get("expect", {}):
                continue
            if step.get("method") == "tool.call":
                contracts.add((step["params"]["operation"], step["params"]["version"]))
            if step.get("method") == "ocs.describe":
                negotiated.update(step["params"]["requiredFeatures"])
    report = {
        "edition": "0.1.0-draft.1",
        "suite": (
            "core-status-fixtures/0.1"
            if options.cases.resolve() == ROOT / "conformance/cases/core.json"
            else options.cases.stem
        ),
        "suiteDigest": hashlib.sha256(case_bytes).hexdigest(),
        "target": meta["id"],
        "role": "mixed" if full else "executor",
        "binding": "stdio+loopback-http" if full else "stdio",
        "packageVersion": meta["version"],
        "platform": f"{platform.system()} {platform.machine()}",
        "features": sorted(negotiated),
        "contracts": [{"operation": op, "version": version} for op, version in sorted(contracts)],
        "observedAt": stamp(),
        "scope": (
            "Synthetic status read, explicit grants and published executor cases."
            if full
            else "Explicit executor command against the identified case corpus."
        ),
        "checks": checks,
        "implementations": (
            [
                "Python executor",
                "Go executor (org.example.status-go@0.1.0)",
                "Python host and peer",
                "Go host",
            ]
            if full
            else [meta["id"]]
        ),
        "limitations": [
            "Isolated synthetic fixture. Production transport, privileged execution, paid operations and model inference require separate evidence."
        ],
    }
    validate("report", report)
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps(report, indent=2) + "\n")
    failed = [c for c in checks if c["status"] == "fail"]
    for check in failed:
        print("FAIL", check["id"], check["detail"], file=sys.stderr)
    print(f"{len(checks) - len(failed)}/{len(checks)} passed; report: {options.report}")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
