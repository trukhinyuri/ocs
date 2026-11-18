"""Evidence of public registry traffic validated with the verifier checkout's schemas."""

import hashlib
import json
import threading
from pathlib import Path

from contracts import validate_with
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[2]
METHODS = {
    r["method"]: r
    for r in json.loads((ROOT / "spec/profiles/operations.json").read_bytes())["operations"]
}


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def valid(uri, value):
    if uri is None:
        return value is None
    try:
        validate_with({"$ref": uri}, value)
    except ValidationError:
        return False
    return True


class Journal:
    def __init__(self):
        self.rows = {}
        self.lock = threading.RLock()

    def note(self, method, inp, pin, outcome, output=None, code=None, rid=None):
        interface = METHODS.get(method)
        if not interface:
            return
        input_valid = valid(interface["input"], inp)
        output_valid = (
            valid(interface["output"], output) if outcome in ("result", "notification") else None
        )
        if outcome == "result" and (not input_valid or not output_valid):
            raise AssertionError(
                f"Successful {method} is outside the published input/output contract"
            )
        if outcome == "notification" and (not input_valid or not output_valid):
            raise AssertionError(
                f"Accepted {method} notification is outside the published contract"
            )
        with self.lock:
            row = self.rows.setdefault(
                method,
                {
                    "profile": interface["profile"],
                    "method": method,
                    "channel": interface["channel"],
                    "version": interface.get("version", "wire-0.1"),
                    "inputSchema": interface["input"],
                    "outputSchema": interface["output"],
                    "publishedMethodSha256": digest(interface),
                    "counts": {},
                    "examples": {},
                },
            )
            row["counts"][outcome] = row["counts"].get(outcome, 0) + 1
            key = outcome + ("/" + str(code) if code is not None else "")
            if key not in row["examples"]:
                row["examples"][key] = {
                    "manifestDigest": pin,
                    "requestId": rid,
                    "inputSha256": digest(inp),
                    "outputSha256": digest(output) if output is not None else None,
                    "inputMatchesPublishedShape": input_valid,
                    "outputMatchesPublishedShape": output_valid,
                    "code": code,
                }

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.rows))
