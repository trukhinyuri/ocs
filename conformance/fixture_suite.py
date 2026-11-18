"""Run the hermetic fixtures and fail if a declared evidence case was skipped."""

import json
import subprocess
import sys
import unittest
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    tests = root / "conformance"
    index = json.loads((tests / "scenarios.json").read_text())
    mandatory = {p for s in index["scenarios"].values() for p in s["checks"] if "#" in p}
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover(str(tests), pattern="test_*.py")
    )
    failed = not result.wasSuccessful()
    for case, reason in [*result.skipped, *result.expectedFailures]:
        name = case.id().split(".")
        path = f"conformance/{name[0]}.py#{name[-1]}"
        if path in mandatory:
            print(
                "FAIL required fixture did not produce a passing observation", path, file=sys.stderr
            )
            failed = True
    run = subprocess.run(
        ["go", "test", "-json", "./..."],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=150,
    )
    go = {}
    logs = []
    for line in run.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            logs.append(line)
            continue
        if row.get("Action") == "output":
            logs.append(row.get("Output", "").rstrip())
        if row.get("Test") and row["Action"] in ("pass", "fail", "skip"):
            go[(row["Package"].split("/", 1)[-1], row["Test"])] = row["Action"]
    if run.returncode:
        print("\n".join(logs[-55:]), file=sys.stderr)
        failed = True
    for path in mandatory:
        source, _, name = path.partition("#")
        if source.endswith("_test.go"):
            module = "/".join(Path(source).parent.parts)
            if not any(
                pkg.endswith("/" + module) or pkg == module
                for (pkg, test), status in go.items()
                if test == name and status == "pass"
            ):
                print("FAIL required Go fixture did not pass", path, file=sys.stderr)
                failed = True
    print("Go fixtures", sum(s == "pass" for s in go.values()), "passed")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
