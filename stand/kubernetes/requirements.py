"""Generate pip's hashed, binary-only build inputs from the repository's uv lock."""

import tomllib
from pathlib import Path

for package in sorted(
    tomllib.loads(Path("uv.lock").read_text())["package"], key=lambda row: row["name"]
):
    if "registry" not in package["source"]:
        continue
    hashes = sorted({wheel["hash"] for wheel in package["wheels"]})
    if not hashes:
        raise ValueError("missing pinned wheel for " + package["name"])
    print(
        package["name"]
        + "=="
        + package["version"]
        + " "
        + " ".join("--hash=" + item for item in hashes)
    )
