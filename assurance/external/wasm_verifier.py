#!/usr/bin/env python3
"""Operator-enrolled checker for an inert stack certificate over a sealed Wasm module."""

import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def term(value, depth=0):
    if depth > 32:
        raise ValueError("witness term depth")
    if value in ("imported", "offered"):
        return "Term." + value
    if isinstance(value, list) and len(value) == 3 and value[0] == "and":
        return "(Term.band " + term(value[1], depth + 1) + " " + term(value[2], depth + 1) + ")"
    raise ValueError("unknown witness term")


def vector(values, fn):
    if not isinstance(values, list) or len(values) > 64:
        raise ValueError("witness vector size")
    return "[" + ", ".join(fn(v) for v in values) + "]"


def operation(value):
    if value not in ("imported", "offered", "band"):
        raise ValueError("unknown instruction")
    return "Op." + value


def checked(args, directory, env):
    completed = subprocess.run(
        args, cwd=directory, env=env, capture_output=True, text=True, timeout=60
    )
    if completed.returncode:
        raise ValueError("kernel rejected the declared artifact property or its symbolic trace")
    return completed.stdout


def verify(request):
    binding = request["binding"]
    proof = request["certificate"]
    if (
        set(proof) != {"format", "bindingSha256", "instructions", "frames", "final"}
        or proof["format"] != "ocs.wasm-stack/1"
    ):
        raise ValueError("unsupported certificate fields")
    if proof["bindingSha256"] != request["bindingSha256"]:
        raise ValueError("certificate belongs to another binding")
    statement = base64.b64decode(request["statement"], validate=True)
    artifact = base64.b64decode(request["artifact"], validate=True)
    if (
        hashlib.sha256(statement).hexdigest() != binding["statementSha256"]
        or hashlib.sha256(artifact).hexdigest() != binding["artifactSha256"]
    ):
        raise ValueError("checker received mismatched input bytes")
    if len(artifact) > 256:
        raise ValueError("outside enrolled straight-line Wasm scope")
    if len(proof["frames"]) != len(proof["instructions"]):
        raise ValueError("witness step count")
    approval = request["checkerResources"]["kernel"]
    target = platform.system() + "/" + platform.machine()
    build = approval["builds"].get(target)
    if build is None:
        raise ValueError("no approved checker build for this platform")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "ELAN_TOOLCHAIN": approval["release"],
    }
    prefix = (
        Path(
            subprocess.check_output(
                ["elan", "which", "lean"], env=env, text=True, timeout=10
            ).strip()
        )
        .resolve()
        .parent.parent
    )
    for name, sha in build["files"].items():
        if checksum(prefix / name) != sha:
            raise ValueError("different verifier binary/library " + name)
    if (
        subprocess.check_output(
            [str(prefix / "bin/lean"), "--githash"], env=env, text=True, timeout=10
        ).strip()
        != approval["commit"]
    ):
        raise ValueError("wrong verifier revision")
    # All candidate-supplied data below are restricted decimal byte/operation/
    # constructor literals. Only the operator's hashed statement is elaborated as source.
    code = (
        "import Grant\nnamespace ExternalGrant\n"
        + "def actualBytes : List Nat := "
        + str(list(artifact))
        + "\n"
        + "def proposedOps : List Op := "
        + vector(proof["instructions"], operation)
        + "\n"
        + "def proposedFrames : List (List Term) := "
        + vector(proof["frames"], lambda row: vector(row, term))
        + "\n"
        + "def proposedFinal : List Term := "
        + vector(proof["final"], term)
        + "\n"
        + """theorem checkedArtifact : Statement actualBytes := by
  refine ⟨proposedOps, ?_, ?_⟩
  · decide
  · intro x y
    have h : certify proposedOps [] proposedFrames = some proposedFinal := by decide
    have sound := certificateSound x y proposedOps [] proposedFrames proposedFinal h
    simpa [proposedFinal, denote, BitVec.and_comm] using sound
#print axioms ExternalGrant.checkedArtifact
end ExternalGrant
"""
    )
    with tempfile.TemporaryDirectory(prefix="ocs-exported-proof-") as tmp:
        directory = Path(tmp)
        env["LEAN_PATH"] = tmp
        (directory / "Grant.lean").write_bytes(statement)
        (directory / "Evidence.lean").write_text(code)
        checked(
            [str(prefix / "bin/lean"), "-DwarningAsError=true", "-o", "Grant.olean", "Grant.lean"],
            directory,
            env,
        )
        output = checked(
            [
                str(prefix / "bin/lean"),
                "-DwarningAsError=true",
                "-o",
                "Evidence.olean",
                "Evidence.lean",
            ],
            directory,
            env,
        )
        checked([str(prefix / "bin/leanchecker"), "--silent", "Grant", "Evidence"], directory, env)
    audit = re.search(
        r"'ExternalGrant\.checkedArtifact' (?:does not depend on any axioms|depends on axioms: \[([^\]]*)\])",
        output,
    )
    if audit is None:
        raise ValueError("missing certificate dependency audit")
    axioms = sorted(a.strip() for a in (audit[1] or "").split(",") if a.strip())
    if set(axioms) - set(approval["axioms"]):
        raise ValueError("unapproved proof axiom")
    return {
        "format": "ocs.external-check-result/1",
        "nonce": request["nonce"],
        "bindingSha256": request["bindingSha256"],
        "certificateSha256": request["certificateSha256"],
        "accepted": True,
        "witness": {
            "theorem": "ExternalGrant.checkedArtifact",
            "checkedInstructions": len(proof["instructions"]),
            "verifierRevision": approval["commit"],
            "checkerSha256": checksum(prefix / "bin/leanchecker"),
            "axioms": axioms,
        },
    }


if __name__ == "__main__":
    try:
        print(json.dumps(verify(json.load(sys.stdin)), separators=(",", ":"), allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as err:
        print(str(err), file=sys.stderr)
        raise SystemExit(1)
