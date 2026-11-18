#!/usr/bin/env python3
"""Exercise a reviewed historical stdio caller against the selected working agent package."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--caller-root", type=Path, required=True)
    p.add_argument("--executor", type=Path, required=True)
    args = p.parse_args()
    sys.path.insert(0, str(args.caller_root / "reference"))
    import host
    from contracts import utc_at, validate

    if Path(host.__file__).resolve() != args.caller_root / "reference/host.py":
        raise ValueError("wrong archived caller")
    executor = args.executor.resolve()
    pin = hashlib.sha256((executor.parent / "ocs.json").read_bytes()).hexdigest()
    channel = host.Channel(executor, 5)
    until = utc_at(time.time() + 5)
    observations = []
    try:
        description = channel.request(
            "ocs.describe",
            {
                "protocols": ["0.1"],
                "requiredFeatures": ["ocs.agents/0.1"],
                "meta": {"deadline": until},
            },
        )
        validate("wire", description, "describeResult")
        if (
            description["manifestDigest"] != pin
            or description["packageId"] != "org.example.fact-agent"
        ):
            raise ValueError("wrong executor identity")

        def call(mid, text):
            message = {
                "messageId": mid,
                "contextId": "prior-client",
                "parts": [{"type": "text", "text": text}],
            }
            validate("profile-data", message, "message")
            params = {
                "operation": "agent.exchange",
                "version": "1.0.0",
                "input": message,
                "meta": {"protocol": "0.1", "manifestDigest": pin, "deadline": until},
            }
            try:
                result = channel.request("tool.call", params)
            except host.Failure as error:
                validate("wire", error.error, "error")
                observations.append({"input": message, "refused": error.error["data"]["kind"]})
                return None
            validate("wire", result, "callResult")
            validate("profile-wire", result["data"], "agentReply")
            answer = result["data"]["message"]
            if answer["replyTo"] != mid or answer["contextId"] != "prior-client":
                raise ValueError("wrong response context")
            observations.append({"input": message, "output": result["data"]})
            return answer

        b = call("q1", "Read demo")
        if not b:
            raise ValueError("held-out fact was denied")
        confirmation = call("q2", "Confirm " + b["parts"][0]["text"])
        if confirmation["parts"][0]["text"] != "confirmed":
            raise ValueError("wrong confirmation")
        if call("q3", "Read other") is not None or observations[-1].get("refused") != "denied":
            raise ValueError("wrong denial")
        print(
            json.dumps(
                {
                    "manifestDigest": pin,
                    "callerSha256": hashlib.sha256(Path(host.__file__).read_bytes()).hexdigest(),
                    "executorSha256": hashlib.sha256(executor.read_bytes()).hexdigest(),
                    "observations": observations,
                }
            )
        )
    finally:
        channel.close()


if __name__ == "__main__":
    main()
