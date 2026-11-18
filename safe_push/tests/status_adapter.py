"""A byte-count calibration target used only for receiver acceptance experiments."""

import hashlib
import json
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


def compact(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_AS, (300 * 1024 * 1024, 300 * 1024 * 1024))


def main():
    req = json.load(sys.stdin)
    ident = req["subject"]
    sample = json.loads((Path(req["evidence"]) / "acquisition.json").read_bytes())
    assert (
        sample["revision"] == ident["revision"]
        and sample["conditions"] == req["conditions"]
    )
    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "subject"
        work.mkdir()
        for name in ("executor.py", "ocs.json"):
            source = subprocess.check_output(
                [
                    "git",
                    "--no-replace-objects",
                    "-c",
                    "safe.directory=" + str(Path(req["repo"]).resolve()),
                    "-C",
                    req["repo"],
                    "show",
                    ident["revision"] + ":examples/status/" + name,
                ]
            )
            (work / name).write_bytes(source)
        descriptor = sha((work / "ocs.json").read_bytes())
        deadline = "2099-11-01T00:00:00.000Z"
        meta = {"deadline": deadline, "protocol": "0.1", "manifestDigest": descriptor}

        def call(i, r):
            return {
                "jsonrpc": "2.0",
                "id": str(i),
                "method": "tool.call",
                "params": {
                    "operation": "example.status.read",
                    "version": "1.0.0",
                    "input": {"resourceId": r},
                    "meta": meta,
                },
            }

        messages = [
            {
                "jsonrpc": "2.0",
                "id": "1",
                "method": "ocs.describe",
                "params": {
                    "protocols": ["0.1"],
                    "requiredFeatures": [],
                    "meta": {"deadline": deadline},
                },
            },
            call(2, "demo"),
            call(3, "outside"),
            call(4, "demo"),
        ]
        # Execution receives only the native runtime and two public fixture files.
        # It cannot see the parent repository, review inputs, receiver keys or network.
        command = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/bin",
            "/bin",
            "--dev",
            "/dev",
            "--ro-bind",
            str(work),
            "/subject",
            "--chdir",
            "/subject",
            "--clearenv",
            "/usr/bin/python3",
            "-I",
            "/subject/executor.py",
        ]
        output = Path(td) / "readback"
        with output.open("wb") as write:
            p = subprocess.run(
                command,
                check=False,
                input=b"\n".join(map(compact, messages)) + b"\n",
                stdout=write,
                stderr=subprocess.DEVNULL,
                preexec_fn=limits,
                timeout=12,
            )
        assert p.returncode == 0
        raw = output.read_bytes()
        rows = [json.loads(line) for line in raw.splitlines()]
        assert len(rows) == 4
        assert rows[0]["result"]["manifestDigest"] == descriptor
        ready = (
            rows[1]["result"]["data"]
            == rows[3]["result"]["data"]
            == {"resourceId": "demo", "state": "ready"}
        )
        if not ready:
            print(
                json.dumps(
                    {
                        "verdict": "refuted",
                        "candidate": ident["revision"],
                        "criterion": "S-02",
                        "evidenceSha256": sha(raw),
                    }
                )
            )
            return
        assert rows[2]["error"]["data"]["kind"] == "denied"
        claims = {
            k: sha(v.encode())
            for k, v in {
                "S-01": "admit pinned descriptor",
                "S-02": "read exact ready state",
                "S-03": "deny foreign resource",
                "S-04": "recover after refusal",
            }.items()
        }
        print(
            json.dumps(
                {
                    "reportSha256": sha(compact([ident, sample, sha(raw)])),
                    "claims": claims,
                    "metrics": {
                        "wire.octets": {
                            "direction": "min",
                            "condition": req["conditions"],
                            "value": str(len(raw)),
                        }
                    },
                    "expiresAt": sample["expiresAt"],
                    "metricGaps": [],
                }
            )
        )


if __name__ == "__main__":
    main()
