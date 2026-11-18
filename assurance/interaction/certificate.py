"""Verify released proof-tool binaries and independently replay exported statements."""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from lean_tools import checked_run


def pinned_kernels(oracle, directory, release, commit):
    policy = json.loads((oracle / "assurance/wire/toolchain.json").read_bytes())
    system = platform.system() + "/" + platform.machine()
    if policy["release"] != release or policy["commit"] != commit or system not in policy["builds"]:
        raise ValueError("unapproved proof checker release or platform")
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("LEAN_PATH", "LEAN_SRC_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH")
    }
    env["ELAN_TOOLCHAIN"] = release
    installed = checked_run(["elan", "toolchain", "list"], directory, env)
    if not any(line.split()[:1] == [release] for line in installed.splitlines()):
        raise ValueError("install the pinned proof kernel before offline qualification")
    prefix = Path(checked_run(["lean", "--print-prefix"], directory, env).strip())
    for name, expected in policy["builds"][system]["files"].items():
        with (prefix / name).open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("substituted proof kernel or shared library: " + name)
    env["LEAN_PATH"] = str(directory)
    if checked_run([str(prefix / "bin/lean"), "--githash"], directory, env).strip() != commit:
        raise ValueError("wrong proof kernel revision")
    return prefix / "bin", env, policy["builds"][system]["files"]


def external_certificate(binaries, env, directory, names, output):
    cert = directory / "cert.ndjson"
    with cert.open("wb") as stream:
        result = subprocess.run(
            [str(binaries / "leanexport"), "Challenge", "--", *names],
            cwd=directory,
            env=env,
            stdout=stream,
            stderr=subprocess.PIPE,
            timeout=100,
        )
        if result.returncode:
            raise ValueError(
                "certificate export failed: " + result.stderr.decode(errors="replace")[:500]
            )
    config = {
        "export_file_path": str(cert),
        "pp_to_stdout": True,
        "pp_declars": names,
        "pp_options": {"proofs": False},
        "permitted_axioms": ["propext", "Classical.choice", "Quot.sound"],
        "unpermitted_axiom_hard_error": True,
        "nat_extension": True,
        "string_extension": True,
        "print_success_message": True,
    }
    (directory / "certificate.json").write_text(json.dumps(config))
    diagnostics = checked_run(
        [str(binaries / "nanoda_bin"), str(directory / "certificate.json")], directory, env
    )
    confirmation = re.search(r"Checked ([0-9]+) declarations with no errors", diagnostics)
    if not confirmation or not all(
        re.search(r"(?m)^theorem " + re.escape(name) + r"\b", diagnostics) for name in names
    ):
        raise ValueError("independent checker did not confirm every accepted statement")
    with cert.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as staged,
        cert.open("rb") as source,
    ):
        shutil.copyfileobj(source, staged)
        tmp = Path(staged.name)
    tmp.replace(output)
    return {
        "file": output.name,
        "sha256": digest,
        "declarations": int(confirmation[1]),
        "checker": "nanoda_bin",
    }
