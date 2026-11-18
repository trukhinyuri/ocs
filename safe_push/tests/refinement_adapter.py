"""Recheck the two narrowly enrolled receiver-experiment predicates against actual Git bytes."""

import hashlib
import json
import marshal
import subprocess
import sys
from pathlib import Path

EXECUTOR = "examples/status/executor.py"
DOC = "docs/receiver-recovery.md"
TEXT = b"# Receiver recovery\n\nThe status example accepts a valid read after refusing a foreign resource.\n"
ALERT = (
    b"Missing executable-example documentation of recovery after a refused status read."
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def main():
    r = json.load(sys.stdin)
    ctx = r["context"]
    need = r["criterion"]
    cp = [
        "git",
        "--no-replace-objects",
        "-c",
        "safe.directory=" + str(Path(r["repo"]).resolve()),
        "-C",
        r["repo"],
    ]

    def get(rev, name):
        return subprocess.run(
            [*cp, "show", rev + ":" + name],
            check=False,
            capture_output=True,
            timeout=10,
        )

    paths = subprocess.check_output(
        [
            *cp,
            "diff",
            "--no-ext-diff",
            "--name-only",
            "-z",
            ctx["parent"],
            ctx["candidate"],
        ]
    ).split(b"\0")[:-1]
    raw = Path(r["artifact"]).read_bytes()
    if need["id"] == "source.refinement":
        assert paths == [EXECUTOR.encode()]
        left = get(ctx["parent"], EXECUTOR)
        right = get(ctx["candidate"], EXECUTOR)
        assert left.returncode == right.returncode == 0
        suffix = right.stdout.removeprefix(left.stdout)
        assert (
            right.stdout.startswith(left.stdout)
            and suffix.startswith(b"\n# ")
            and suffix.endswith(b"\n")
        )
        assert len(suffix) < 300 and b"\n" not in suffix[1:-1] and suffix.isascii()
        assert len(left.stdout) < 100_000
        left_bytecode = marshal.dumps(
            compile(left.stdout, EXECUTOR, "exec", dont_inherit=True, optimize=0)
        )
        right_bytecode = marshal.dumps(
            compile(right.stdout, EXECUTOR, "exec", dont_inherit=True, optimize=0)
        )
        assert left_bytecode == right_bytecode
        witness = {
            "predicate": "sealed-status-eof-comment",
            "parent": ctx["parent"],
            "candidate": ctx["candidate"],
            "left": sha(left.stdout),
            "right": sha(right.stdout),
        }
        assert json.loads(raw) == witness
    elif need["id"] == "remediation/fixture-document":
        assert paths == [DOC.encode()] and get(ctx["parent"], DOC).returncode != 0
        assert get(ctx["candidate"], DOC).stdout == TEXT and r.get("counterexample")
        assert Path(r["counterexample"]).read_bytes() == ALERT and json.loads(raw) == {
            "fix": sha(TEXT),
            "original": sha(ALERT),
        }
    else:
        raise ValueError("unregistered property")
    print(
        json.dumps(
            {
                "status": "accepted",
                "criterion": need["digest"],
                "context": sha(compact(ctx)),
                "artifact": sha(raw),
            }
        )
    )


if __name__ == "__main__":
    main()
