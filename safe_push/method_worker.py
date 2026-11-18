#!/usr/bin/env python3
"""Replay an independently installed method in a separate, credentialless evaluator process."""

import argparse
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from authority import (
    NAME,
    ROLES,
    SHA256,
    Decision,
    authentic,
    canonical,
    digest,
    framed,
    load,
    pairs,
    read,
    require,
)

WIRE = 80 * 1024 * 1024
INPUT = 48 * 1024 * 1024
OUTPUT = 16 * 1024 * 1024
CREDENTIAL = struct.Struct("3i")
LENGTH = struct.Struct("!I")
FILES = ("evidence", "artifact", "counterexample")


def exactly(conn, n):
    result = bytearray()
    while len(result) < n:
        b = conn.recv(min(n - len(result), 65536))
        require(b, "method.transport", "incomplete evaluator message")
        result.extend(b)
    return bytes(result)


def decode(raw):
    def nonfinite(_):
        raise Decision("method.encoding", "nonfinite numeric evidence")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def metadata(authority):
    d = load(authority / "broker.json")
    require(
        d.get("format") == "ocs.safe-push.method-broker/1"
        and type(d.get("publisherUid")) is int
        and type(d.get("evaluatorUid")) is int
        and d["publisherUid"] > 0
        and d["evaluatorUid"] > 0
        and d["publisherUid"] != d["evaluatorUid"]
        and Path(d["socket"]).is_absolute(),
        "isolation.custody",
        "invalid independent evaluator enrollment",
    )
    return d


def safe_name(name):
    path = PurePosixPath(name)
    require(
        isinstance(name, str)
        and 0 < len(name) < 4096
        and not path.is_absolute()
        and path.as_posix() == name
        and all(k not in {"", ".", ".."} for k in path.parts)
        and not any(c in name for c in ("\\", "\0", ":")),
        "method.input",
        "invalid data object name",
    )
    return name


def encode_inputs(args):
    args = dict(args)
    repository = args.pop("repo", None) is not None
    items = {}
    size = 0
    for field in FILES:
        if field not in args:
            continue
        path = Path(args.pop(field))
        require(
            not path.is_symlink(), "method.input", "method expects sealed regular files"
        )
        directory = path.is_dir()
        members = {}
        for file in sorted(path.rglob("*")) if directory else (path,):
            require(
                not file.is_symlink(), "method.input", "linked evidence is not sealed"
            )
            if file.is_dir():
                continue
            key = safe_name(file.relative_to(path).as_posix()) if directory else "input"
            raw = read(file, min(INPUT - size, 16 * 1024 * 1024))
            size += len(raw)
            require(
                size <= INPUT and len(members) < 4096,
                "method.input",
                "method evidence exceeds its registered transport bound",
            )
            members[key] = base64.b64encode(raw).decode("ascii")
        items[field] = {"directory": directory, "files": members}
    return {"args": args, "repository": repository, "inputs": items}


def restore_inputs(packet, folder, repo):
    require(
        isinstance(packet["args"], dict)
        and not ({"repo", *FILES} & set(packet["args"])),
        "method.input",
        "only the evaluator supplies filesystem operands",
    )
    require(
        type(packet["repository"]) is bool and set(packet["inputs"]).issubset(FILES),
        "method.input",
        "unknown input family",
    )
    args = dict(packet["args"])
    size = 0
    if packet["repository"]:
        args["repo"] = str(repo)
    for field, obj in packet["inputs"].items():
        require(
            set(obj) == {"directory", "files"}
            and type(obj["directory"]) is bool
            and isinstance(obj["files"], dict)
            and len(obj["files"]) <= 4096,
            "method.input",
            "invalid data inventory",
        )
        dest = folder / field
        dest.mkdir()
        if not obj["directory"]:
            require(
                set(obj["files"]) == {"input"},
                "method.input",
                "expected one evidence object",
            )
        for name, v in obj["files"].items():
            raw = base64.b64decode(v, validate=True)
            size += len(raw)
            require(
                len(raw) <= 16 * 1024 * 1024 and size <= INPUT,
                "method.input",
                "oversized evidence",
            )
            file = dest / safe_name(name)
            file.parent.mkdir(parents=True, exist_ok=True)
            with file.open("xb") as out:
                out.write(raw)
        args[field] = str(dest if obj["directory"] else dest / "input")
    return args


def request(authority, packet, timeout):
    config = metadata(authority)
    msg = canonical(packet)
    require(len(msg) <= WIRE, "method.transport", "oversized method request")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout + 10)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        conn.connect(config["socket"])
        conn.sendall(LENGTH.pack(len(msg)) + msg)
        header, anc, flags, _ = conn.recvmsg(
            LENGTH.size, socket.CMSG_SPACE(CREDENTIAL.size)
        )
        who = [
            CREDENTIAL.unpack(v[: CREDENTIAL.size])
            for lev, kind, v in anc
            if lev == socket.SOL_SOCKET
            and kind == socket.SCM_CREDENTIALS
            and len(v) >= CREDENTIAL.size
        ]
        require(
            not flags & socket.MSG_CTRUNC
            and len(who) == 1
            and who[0][1] == config["evaluatorUid"],
            "isolation.identity",
            "kernel credentials do not match the independently enrolled evaluator",
        )
        header += exactly(conn, LENGTH.size - len(header))
        n = LENGTH.unpack(header)[0]
        require(0 < n <= OUTPUT, "method.transport", "invalid evaluator response size")
        reply = decode(exactly(conn, n))
    require(
        isinstance(reply, dict) and reply.get("requestSha256") == digest(msg),
        "method.transport",
        "response belongs to a different method input",
    )
    if reply.get("outcome") != "observed":
        raise Decision(
            reply.get("criterion", "method.unavailable"),
            reply.get("reason", "evaluator unavailable"),
            "rejected" if reply.get("outcome") == "rejected" else "undetermined",
        )
    return reply["output"]


def remote_method(authority, name, sha, args, timeout):
    from object_view import maybe_export

    data = encode_inputs(args)
    data["objectView"] = (
        maybe_export(Path(args["repo"]), args) if "repo" in args else None
    )
    return request(
        authority,
        {
            "format": "ocs.safe-push.method-request/1",
            "operation": "replay",
            "name": name,
            "methodSha256": sha,
            "timeout": timeout,
            **data,
        },
        timeout,
    )


def signed_policies(authority, config):
    # The release authority separately replays semantic transitions. The worker
    # only uses the independently signed history to constrain executable identities.
    from evolution import evolution_signature_payload

    root = load(authority / "root.json")
    require(
        framed(root) == config["rootDigest"],
        "method.registry",
        "invalid initial method registry",
    )
    policies = [root]
    for i, file in enumerate(sorted((authority / "rotations").glob("*.json")), 1):
        rec = load(file)
        new = rec["policy"]
        require(
            file.name == f"{i:012}.json"
            and new["epoch"] == i
            and new["project"] == root["project"],
            "method.registry",
            "invalid method epoch",
        )
        if "evolution" in rec:
            transition = evolution_signature_payload(root, new, rec["evolution"])
        else:
            transition = {
                "format": "ocs.safe-push.rotation/1",
                "project": root["project"],
                "old": framed(root),
                "new": framed(new),
                "epoch": i,
            }
        for side, p in (("old", root), ("new", new)):
            for role in ROLES:
                require(
                    authentic(rec[side][role], p["keys"][role], "method.custody")
                    == {**transition, "side": side, "role": role},
                    "method.custody",
                    "missing authorization for method registry",
                )
        policies.append(new)
        root = new
    return policies


def normalized_method(authority, config, packet):
    from admission import execute_method

    name, sha = packet["name"], packet["methodSha256"]
    require(
        isinstance(name, str)
        and NAME.fullmatch(name)
        and isinstance(sha, str)
        and SHA256.fullmatch(sha)
        and type(packet["timeout"]) is int
        and 1 <= packet["timeout"] <= 90,
        "method.registry",
        "unknown method or time budget",
    )
    require(
        any(
            p["adapters"].get(name) == sha
            or p["predicateCheckers"].get(name, {}).get("sha256") == sha
            for p in signed_policies(authority, config)
        ),
        "method.registry",
        "not an independently authorized executable",
    )
    program = read(authority / "methods" / (sha + ".py"), 4 * 1024 * 1024)
    require(digest(program) == sha, "method.registry", "changed installed method")
    with tempfile.TemporaryDirectory(prefix="ocs-method-input-") as t:
        repo = Path(config["repo"])
        if packet["objectView"] is not None:
            from object_view import materialize

            require(
                packet["repository"],
                "method.object",
                "projection without an authorized repository",
            )
            repo = materialize(
                packet["objectView"], packet["args"], Path(t) / "quarantined.git"
            )
        args = restore_inputs(packet, Path(t), repo)
        return execute_method(program, name, args, packet["timeout"])


def self_observation(cfg, authority):
    from admission import execute_method
    from scope import inventory, subject

    meta = metadata(authority)
    uid = os.geteuid()
    require(
        uid == meta["evaluatorUid"],
        "isolation.identity",
        "self-test must run as the dedicated evaluator",
    )
    private = Path(cfg["publishingKeys"])
    journal = Path(cfg["journal"])
    witness = Path(cfg["witness"])
    repo = Path(cfg["repo"])
    inaccessible = {
        "publisherKeyReadable": os.access(private, os.R_OK),
        "journalReadable": os.access(journal, os.R_OK),
        "witnessReadable": os.access(witness, os.R_OK),
        "refWritable": any(
            os.access(p, os.W_OK)
            for p in (repo, repo / "config", repo / "objects", repo / "reftable")
        ),
    }
    require(
        not any(inaccessible.values()),
        "isolation.custody",
        "worker can access protected publishing state",
    )
    revision = cfg["genesis"]
    condition = digest(b"ocs-method-worker-selftest-v1")
    program = read(HERE / "tests" / "status_adapter.py", 4 * 1024 * 1024)
    with tempfile.TemporaryDirectory() as d:
        sample = {
            "revision": revision,
            "conditions": condition,
            "expiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        }
        (Path(d) / "acquisition.json").write_bytes(canonical(sample))
        ident = subject(repo, revision, inventory(repo, revision))
        result = execute_method(
            program,
            "selftest-status",
            {
                "repo": str(repo),
                "subject": ident,
                "target": "selftest",
                "conditions": condition,
                "evidence": d,
            },
            45,
        )
    require(
        set(result.get("claims", {})) == {"S-01", "S-02", "S-03", "S-04"}
        and int(result["metrics"]["wire.octets"]["value"]) > 0,
        "isolation.selftest",
        "four-frame readback missing",
    )
    return {
        "status": "pass",
        "diagnosticOnly": True,
        "evaluatorUid": uid,
        "publisherUid": meta["publisherUid"],
        **inaccessible,
        "target": "four-frame isolated status executor",
        "claims": sorted(result["claims"]),
        "wireBytes": int(result["metrics"]["wire.octets"]["value"]),
        "subject": revision,
        "reportSha256": result["reportSha256"],
        "result": result,
    }


def serve(config_path):
    cfg = load(config_path)
    authority = Path(cfg["authority"])
    broker = metadata(authority)
    require(
        os.geteuid() == broker["evaluatorUid"]
        and framed(cfg) == load(config_path.parent / "sealed.json")["configuration"],
        "isolation.identity",
        "incorrect evaluator identity or configuration",
    )
    with socket.socket(fileno=os.dup(0)) as conn:
        peer = CREDENTIAL.unpack(
            conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIAL.size)
        )
        require(
            peer[1] in {broker["publisherUid"], 0},
            "isolation.peer",
            "unrecognized local evaluator caller",
        )
        conn.settimeout(100)
        n = LENGTH.unpack(exactly(conn, LENGTH.size))[0]
        require(0 < n <= WIRE, "method.transport", "oversized method input")
        raw = exactly(conn, n)
        try:
            packet = decode(raw)
            require(
                packet.get("format") == "ocs.safe-push.method-request/1",
                "method.transport",
                "unknown method protocol",
            )
            if packet["operation"] == "selftest":
                require(
                    set(packet) == {"format", "operation"},
                    "method.transport",
                    "unexpected selftest operands",
                )
                result = self_observation(cfg, authority)
            else:
                require(
                    packet["operation"] == "replay"
                    and set(packet)
                    == {
                        "format",
                        "operation",
                        "args",
                        "repository",
                        "inputs",
                        "objectView",
                        "methodSha256",
                        "name",
                        "timeout",
                    },
                    "method.transport",
                    "unexpected method request",
                )
                result = normalized_method(authority, cfg, packet)
            response = {"outcome": "observed", "output": result}
        except (
            ValueError,
            OSError,
            KeyError,
            TypeError,
            ArithmeticError,
            subprocess.SubprocessError,
        ) as e:
            response = {
                "outcome": getattr(e, "outcome", "undetermined"),
                "criterion": getattr(e, "criterion", "method.unavailable"),
                "reason": str(e)[:640],
            }
        data = canonical({**response, "requestSha256": digest(raw)})
        require(len(data) <= OUTPUT, "method.transport", "oversized method output")
        conn.sendall(LENGTH.pack(len(data)) + data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("serve", "selftest"))
    p.add_argument("config", type=Path)
    a = p.parse_args()
    if a.action == "serve":
        serve(a.config)
    else:
        config = load(a.config)
        print(
            canonical(
                request(
                    Path(config["authority"]),
                    {
                        "format": "ocs.safe-push.method-request/1",
                        "operation": "selftest",
                    },
                    55,
                )
            ).decode()
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, TimeoutError) as error:
        print(str(error)[:700], file=sys.stderr)
        sys.exit(1)
