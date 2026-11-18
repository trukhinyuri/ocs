"""Strict public evidence envelopes and the independently selected policy epoch."""

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROLES = ("domain", "independent", "guardian")
OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\Z")


class Decision(ValueError):
    def __init__(self, criterion, reason, outcome="undetermined"):
        self.criterion = criterion
        self.outcome = outcome
        super().__init__(f"{outcome} [{criterion}] {reason}")


def require(condition, criterion, reason, outcome="undetermined"):
    if not condition:
        raise Decision(criterion, reason, outcome)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def framed(value):
    return digest(canonical(value))


def pairs(items):
    data = {}
    for key, value in items:
        require(key not in data, "evidence.encoding", "duplicate JSON field")
        data[key] = value
    return data


def read(path, cap=16 * 1024 * 1024):
    path = Path(path)
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        require(
            stat.S_ISREG(st.st_mode) and st.st_size <= cap,
            "evidence.object",
            "expected bounded regular file",
        )
        b = f.read(cap + 1)
        require(len(b) == st.st_size, "evidence.object", "evidence changed while read")
        return b


def load(path):
    def bad(value):
        raise Decision("evidence.encoding", "nonfinite number " + value)

    return json.loads(read(path), object_pairs_hook=pairs, parse_constant=bad)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def immutable(path, data):
    """Publish complete bytes exactly once. Replaying the same bytes is idempotent."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        staging = Path(out.name)
        out.write(data)
        out.flush()
        os.fchmod(out.fileno(), 0o644)
        os.fsync(out.fileno())
    try:
        try:
            os.link(staging, path)
        except FileExistsError:
            require(
                read(path, len(data)) == data,
                "audit.conflict",
                "different data already registered for " + path.name,
                "rejected",
            )
        fsync_dir(path.parent)
    finally:
        staging.unlink(missing_ok=True)


def replace_pointer(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        new = Path(stream.name)
        stream.write(data)
        os.fchmod(stream.fileno(), 0o644)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(new, path)
        fsync_dir(path.parent)
    finally:
        new.unlink(missing_ok=True)


def stamp():
    return datetime.now(UTC).isoformat()


def instant(value):
    require(isinstance(value, str), "evidence.clock", "missing observation time")
    dt = datetime.fromisoformat(value)
    require(dt.tzinfo is not None, "evidence.clock", "time requires UTC offset")
    return dt.timestamp()


def fresh(issued, expires, now, lifetime):
    a, b = instant(issued), instant(expires)
    require(
        a <= now < b and 0 < b - a <= lifetime,
        "evidence.freshness",
        "expired, future or overlong evidence",
    )


def public_der(pem):
    require(
        isinstance(pem, str) and len(pem) <= 4096, "trust.key", "missing public key"
    )
    proc = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        check=False,
        input=pem.encode(),
        capture_output=True,
        timeout=10,
    )
    prefix = bytes.fromhex("302a300506032b6570032100")
    require(
        proc.returncode == 0
        and proc.stdout.startswith(prefix)
        and len(proc.stdout) == 44,
        "trust.key",
        "expected Ed25519 public key",
    )
    return proc.stdout


def signature(payload, private):
    """Operator action. The caller supplies their own key outside the receiver."""
    with tempfile.TemporaryDirectory() as tmp:
        msg = Path(tmp) / "message"
        msg.write_bytes(canonical(payload))
        sig = subprocess.check_output(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private),
                "-in",
                str(msg),
            ],
            timeout=10,
        )
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def authentic(envelope, pem, criterion):
    require(
        isinstance(envelope, dict) and set(envelope) == {"payload", "signature"},
        criterion,
        "invalid signed envelope",
    )
    payload = envelope["payload"]
    sig = base64.b64decode(envelope["signature"], validate=True)
    require(len(sig) == 64, criterion, "invalid Ed25519 signature length", "rejected")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "public").write_text(pem)
        (tmp / "sig").write_bytes(sig)
        (tmp / "message").write_bytes(canonical(payload))
        p = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(tmp / "public"),
                "-rawin",
                "-in",
                str(tmp / "message"),
                "-sigfile",
                str(tmp / "sig"),
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
    require(p.returncode == 0, criterion, "independent signature mismatch", "rejected")
    return payload


def validate_policy(p):
    fields = {
        "format",
        "project",
        "profile",
        "epoch",
        "genesis",
        "assurancePin",
        "targets",
        "keys",
        "lifetimeSeconds",
        "receiveTimeoutSeconds",
        "receiverCost",
        "requiredOpen",
        "adapters",
        "predicateCheckers",
    }
    require(
        isinstance(p, dict)
        and set(p) == fields
        and p["format"] == "ocs.safe-push.policy/1",
        "trust.policy",
        "unrecognized policy",
    )
    require(
        isinstance(p["project"], str)
        and NAME.fullmatch(p["project"])
        and type(p["epoch"]) is int
        and p["epoch"] >= 0
        and OBJECT.fullmatch(p["genesis"])
        and OBJECT.fullmatch(p["assurancePin"])
        and type(p["lifetimeSeconds"]) is int
        and 0 < p["lifetimeSeconds"] <= 86400,
        "trust.policy",
        "invalid project, epoch, revision or validity interval",
    )
    require(
        type(p["receiveTimeoutSeconds"]) is int
        and 0 < p["receiveTimeoutSeconds"] <= p["lifetimeSeconds"],
        "trust.timeout",
        "bounded receiver service duration required",
    )
    require(
        p["receiverCost"] is None or isinstance(p["receiverCost"], dict),
        "trust.cost",
        "invalid cost enrollment",
    )
    require(
        set(p["keys"]) == {*ROLES, "publisher"}
        and len({public_der(pem) for pem in p["keys"].values()}) == len(ROLES) + 1,
        "trust.roles",
        "independent trust roles require distinct public keys",
    )
    require(
        isinstance(p["targets"], dict) and p["targets"],
        "trust.targets",
        "no qualified target",
    )
    require(
        p["profile"] in ("ocs-release/1", "receiver-experiment/1"),
        "trust.profile",
        "unknown acceptance profile",
    )
    from cost import EXPERIMENT, validate_profile

    validate_profile(p["receiverCost"])
    require(
        p["receiverCost"] is None or p["receiverCost"].get("profile") == p["profile"],
        "trust.cost",
        "verifier measurement scope differs from the enrolled release profile",
    )
    require(
        p["profile"] != "ocs-release/1" or p["receiverCost"] != EXPERIMENT,
        "trust.cost",
        "an experiment-only cost observation cannot qualify an OCS release",
    )
    if p["profile"] == "ocs-release/1":
        require(
            any(v.get("adapter") == "ocs-dossier/1" for v in p["targets"].values()),
            "trust.profile",
            "canonical OCS requires its independently pinned full qualification",
        )
    for name, target in p["targets"].items():
        require(
            NAME.fullmatch(name)
            and set(target) == {"adapter", "observerSha256", "conditions"}
            and (
                (
                    target["adapter"] == "ocs-dossier/1"
                    and SHA256.fullmatch(target["observerSha256"])
                )
                or (
                    target["adapter"] in p["adapters"]
                    and target["observerSha256"] is None
                )
            )
            and SHA256.fullmatch(target["conditions"]),
            "trust.targets",
            "unqualified target",
        )
    for family in ("adapters", "predicateCheckers"):
        require(isinstance(p[family], dict), "trust.method", "invalid method inventory")
        for method, enrolled in p[family].items():
            sha = enrolled
            if family == "predicateCheckers":
                require(
                    isinstance(enrolled, dict)
                    and set(enrolled) == {"sha256", "requirements", "pathPrefixes"}
                    and all(
                        isinstance(enrolled[k], list)
                        and enrolled[k]
                        and all(
                            isinstance(v, str) and v and v != "*" for v in enrolled[k]
                        )
                        for k in ("requirements", "pathPrefixes")
                    ),
                    "trust.method",
                    "replay method lacks its exact authorized purpose",
                )
                sha = enrolled["sha256"]
            require(
                NAME.fullmatch(method) and SHA256.fullmatch(sha),
                "trust.method",
                "invalid independently installed method",
            )
    require(
        isinstance(p["requiredOpen"], list)
        and all(isinstance(v, str) and v for v in p["requiredOpen"])
        and len(set(p["requiredOpen"])) == len(p["requiredOpen"]),
        "trust.scope",
        "invalid list of outstanding mandatory claims",
    )


def policy_history(authority, trusted_digest):
    root = load(authority / "root.json")
    require(
        SHA256.fullmatch(trusted_digest) and framed(root) == trusted_digest,
        "trust.root",
        "trust root differs from separately installed anchor",
        "rejected",
    )
    validate_policy(root)
    require(root["epoch"] == 0, "trust.root", "genesis root must have epoch zero")
    history = [root]
    directory = authority / "rotations"
    for index, file in enumerate(sorted(directory.glob("*.json")), 1):
        require(
            file.name == f"{index:012}.json", "trust.rotation", "gap in policy history"
        )
        rotation = load(file)
        proposed = rotation["policy"]
        validate_policy(proposed)
        require(proposed["epoch"] == index, "trust.rotation", "nonmonotonic epoch")
        if "evolution" in rotation:
            from evolution import evolution_signature_payload

            transition = evolution_signature_payload(
                root, proposed, rotation["evolution"]
            )
        else:
            require(
                {k: v for k, v in root.items() if k not in {"epoch", "keys"}}
                == {k: v for k, v in proposed.items() if k not in {"epoch", "keys"}},
                "trust.rotation",
                "key rotation changed enrolled semantics",
                "rejected",
            )
            transition = {
                "format": "ocs.safe-push.rotation/1",
                "project": root["project"],
                "old": framed(root),
                "new": framed(proposed),
                "epoch": index,
            }
        for label, policy in (("old", root), ("new", proposed)):
            require(
                set(rotation[label]) == set(ROLES),
                "trust.rotation",
                "incomplete quorum",
            )
            for role in ROLES:
                require(
                    authentic(
                        rotation[label][role], policy["keys"][role], "trust.rotation"
                    )
                    == {**transition, "role": role, "side": label},
                    "trust.rotation",
                    "misbound transition signature",
                    "rejected",
                )
        if "evolution" in rotation:
            from evolution import verify_evolution

            require(
                verify_evolution(authority, root, proposed, rotation) == transition,
                "trust.evolution",
                "old-root proof does not match the independently approved transition",
            )
        root = proposed
        history.append(root)
    return history


def active_policy(authority, trusted_digest):
    return policy_history(authority, trusted_digest)[-1]
