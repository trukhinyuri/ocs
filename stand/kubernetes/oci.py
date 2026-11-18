"""Resolve runtime image IDs against the exact OCI manifest or multi-platform index."""

import base64
import hashlib
import json
import re


def approved(raw, digest):
    for data in (raw, raw[:-1] if raw.endswith(b"\n") else raw):
        if "sha256:" + hashlib.sha256(data).hexdigest() == digest:
            return data
    raise ValueError("registry returned different content for " + digest)


def collect(ref, fetch):
    repo, digest = ref.rsplit("@", 1)
    stored = {}

    def read(d):
        if not re.fullmatch("sha256:[0-9a-f]{64}", d):
            raise ValueError("invalid OCI digest")
        if d not in stored:
            value = approved(fetch(repo, d), d)
            if len(value) > 5_000_000:
                raise ValueError("OCI manifest outside the accepted bound")
            stored[d] = base64.b64encode(value).decode()
        return json.loads(base64.b64decode(stored[d], validate=True))

    top = read(digest)
    for row in top.get("manifests", []):
        platform = row.get("platform", {})
        if platform.get("os") == "linux" and platform.get("architecture") in ("arm64", "amd64"):
            read(row["digest"])
    return stored


def accepted_ids(ref, proof, arch):
    _, digest = ref.rsplit("@", 1)

    def read(d):
        return json.loads(approved(base64.b64decode(proof[d], validate=True), d))

    top = read(digest)
    if "manifests" in top:
        selected = [
            m["digest"]
            for m in top["manifests"]
            if m.get("platform", {}).get("os") == "linux"
            and m["platform"].get("architecture") == arch
        ]
        if not selected:
            raise ValueError("no executable image for the scheduled node")
    else:
        selected = [digest]
    allowed = {digest}
    for leaf in selected:
        m = read(leaf)
        if "layers" not in m or not re.fullmatch(
            "sha256:[0-9a-f]{64}", m.get("config", {}).get("digest", "")
        ):
            raise ValueError("malformed executable OCI manifest")
        allowed.update((leaf, m["config"]["digest"]))
    return allowed
