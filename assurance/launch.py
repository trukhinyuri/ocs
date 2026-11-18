#!/usr/bin/env python3
"""Execute the qualification checker from an independently selected immutable commit."""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("kind", choices=("local", "full"))
    p.add_argument("--subject", type=Path, default=Path.cwd())
    p.add_argument("--accepted", required=True, help="full SHA chosen by the release owner")
    p.add_argument("--output", type=Path)
    p.add_argument("--context")
    p.add_argument("--kubeconfig")
    p.add_argument("--image")
    p.add_argument("--namespace")
    p.add_argument("--storage")
    p.add_argument("--oci_proof")
    args = p.parse_args()
    root = args.subject.resolve()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.accepted):
        p.error("an immutable full commit is required")
    git = ["git", "--no-replace-objects", "-C", str(root)]
    obj = subprocess.run([*git, "cat-file", "-t", args.accepted], capture_output=True, text=True)
    if obj.returncode or obj.stdout.strip() != "commit":
        p.error("accepted assurance commit unavailable")
    output = args.output or root / "out/qualification" / args.kind
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "runs").mkdir(exist_ok=True)
    run_dir = output / "runs" / uuid4().hex
    run_dir.mkdir()
    with tempfile.TemporaryDirectory(prefix=".assurance-oracle-", dir=root / "out") as tmp:
        edition = Path(tmp) / "oracle"
        archive = Path(tmp) / "snapshot.zip"
        subprocess.run(
            [*git, "archive", "--format=zip", "-o", str(archive), args.accepted], check=True
        )
        with ZipFile(archive) as z:
            z.extractall(edition)
        if not (edition / "assurance/evidence-index.json").is_file():
            p.error("chosen edition lacks a reviewed evidence index")
        cmd = [
            sys.executable,
            "-I",
            str(edition / "assurance/gate.py"),
            args.kind,
            "--subject",
            str(root),
            "--accepted",
            args.accepted,
            "--output",
            str(run_dir),
        ]
        for name in ("context", "kubeconfig", "image", "namespace", "storage", "oci_proof"):
            value = getattr(args, name) or os.getenv("OCS_" + name.upper())
            if value:
                cmd.extend(["--" + name, value])
        result = subprocess.run(cmd, cwd=root, env={**os.environ, "OCS_SUBJECT_ROOT": str(root)})
        if (run_dir / "report.json").is_file():
            pointer = output / (".latest-" + run_dir.name)
            pointer.symlink_to(run_dir.relative_to(output))
            pointer.replace(output / "latest")
            # Preserve the established report paths. Qualification itself consumes
            # only the independently regenerated run-local copies.
            for original in (run_dir / "reference").rglob("*.json"):
                relative = original.relative_to(run_dir / "reference")
                legacy = root / "out" / relative
                legacy.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=legacy.parent, delete=False) as f:
                    f.write(original.read_bytes())
                    staged = Path(f.name)
                try:
                    staged.replace(legacy)
                finally:
                    staged.unlink(missing_ok=True)
            print("Qualification dossier", output / "latest/report.json", flush=True)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
