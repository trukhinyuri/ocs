"""Check the scenario index and replay the accepted Git edition against this checkout."""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from contracts import read_json
from run import matches

INDEX = "conformance/scenarios.json"
CORPUS = "conformance/cases/core.json"


def load(root, name):
    return read_json((root / name).read_bytes())


def rule_index(root):
    rules = {}
    for document in sorted((root / "spec").rglob("*.md")):
        ids = re.findall(r"\*\*([A-Z]-[0-9]{2})\b", document.read_text())
        if ids:
            rules[str(document.relative_to(root))] = set(ids)
    return rules


def named_tests(root):
    found = set()
    for glob, pattern in (
        ("conformance/test_*.py", r"^\s*def (test_\w+)\("),
        ("reference/go/**/*_test.go", r"^func (Test\w+)\("),
    ):
        for path in root.glob(glob):
            for name in re.findall(pattern, path.read_text(), re.MULTILINE):
                found.add(f"{path.relative_to(root)}#{name}")
    return found


def difference(label, expected, actual):
    return [f"{label}: {item}" for item in sorted(set(expected) - set(actual))]


def same_json(left, right):
    return matches(left, right) and matches(right, left)


def case_changes(published, candidate):
    problems = difference("removed published case", published, candidate)
    for name in sorted(published.keys() & candidate.keys()):
        before, after = published[name], candidate[name]
        if same_json(before, after):
            continue
        remaining = iter(after["steps"])
        for number, original in enumerate(before["steps"], start=1):
            request = {k: v for k, v in original.items() if k != "expect"}
            for step in remaining:
                frame = {k: v for k, v in step.items() if k != "expect"}
                if same_json(request, frame) and matches(
                    original.get("expect"), step.get("expect")
                ):
                    break
            else:
                problems.append(
                    f"changed or weakened published interaction: {name} (step {number})"
                )
                break
    return problems


def audit_index(index, report, cases, rules, tests):
    problems = []
    indexed_rules = index["requirements"]
    scenarios = index["scenarios"]
    linked = set()
    covered = {}
    for document in sorted(rules.keys() | indexed_rules.keys()):
        entries = indexed_rules.get(document, {})
        declared = rules.get(document, set())
        problems += difference("unindexed rule in " + document, declared, entries)
        problems += difference("unknown rule in " + document, entries, declared)
        for rule, names in entries.items():
            if not names or len(names) != len(set(names)):
                problems.append(f"expected distinct scenarios for {rule}")
            linked.update(names)
            problems += difference(f"unknown scenario for {rule}", names, scenarios)
            covered[rule] = {
                check for name in names if name in scenarios for check in scenarios[name]["checks"]
            }
    problems += difference("scenario without a requirement", scenarios, linked)
    report_rows = {row["id"]: row for row in report["checks"]}
    if len(report_rows) != len(report["checks"]):
        problems.append("duplicate check ID in candidate report")
    go_cases = {"go-executor-" + key for key in cases}
    problems += difference(
        "declared case missing from candidate report", set(cases) | go_cases, report_rows
    )
    public_checks = report_rows.keys() - go_cases
    available = public_checks | tests
    indexed = set()
    for name, scenario in scenarios.items():
        checks = scenario["checks"]
        if not scenario["scope"].strip() or not scenario["expect"].strip():
            problems.append(f"missing scope or expected behavior: {name}")
        if not checks and not scenario.get("qualification", "").strip():
            problems.append(f"missing evidence or qualification: {name}")
        problems += difference(f"missing candidate check for {name}", checks, available)
        indexed.update(checks)
    problems += difference("unindexed reported scenario", public_checks, indexed)
    for name, row in report_rows.items():
        if row["status"] != "pass":
            problems.append(f"candidate check {name}: {row['status']}")
    for name in public_checks:
        rule = report_rows[name]["rule"]
        if name not in covered.get(rule, set()):
            problems.append(f"missing link from {rule} to reported check {name}")
    return problems


def unpack_edition(revision, directory):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("the baseline must be a full Git commit ID")
    git = ["git", "--no-replace-objects", "-C", str(ROOT)]
    obj = subprocess.run([*git, "cat-file", "-t", revision], capture_output=True, text=True)
    if obj.returncode or obj.stdout.strip() != "commit":
        raise ValueError(
            f"baseline commit {revision} unavailable; use a checkout containing the accepted edition"
        )
    archive = directory.parent / "edition.zip"
    subprocess.run([*git, "archive", "--format=zip", "-o", str(archive), revision], check=True)
    with ZipFile(archive) as package:
        package.extractall(directory)


def deploy_reference_targets(edition):
    # The published runner, its schema validator, scenarios and original status
    # package stay together. Its hosts and peer invoke the historical status service.
    for relative in (
        "reference/host.py",
        "reference/peer.py",
        "reference/admission.py",
        "tools/package.py",
        "go.mod",
    ):
        path = edition / relative
        if not (ROOT / relative).is_file():
            raise ValueError(f"missing candidate implementation: {relative}")
        path.unlink()
        path.symlink_to(ROOT / relative)
    (edition / "go.sum").unlink(missing_ok=True)
    if (ROOT / "go.sum").is_file():
        shutil.copy2(ROOT / "go.sum", edition / "go.sum")

    # Package entry points need their own adjacent manifest. Go's original test
    # files remain the independent oracle when building the candidate Go sources.
    for relative in ("reference/go", "examples/dialog", "examples/reset"):
        dest = edition / relative
        original_tests = {p.relative_to(dest): p.read_bytes() for p in dest.rglob("*_test.go")}
        shutil.rmtree(dest)
        shutil.copytree(
            ROOT / relative, dest, ignore=shutil.ignore_patterns("__pycache__", "*_test.go")
        )
        for path, contents in original_tests.items():
            (dest / path).parent.mkdir(parents=True, exist_ok=True)
            (dest / path).write_bytes(contents)


def run_report(edition, path, *args):
    generated = edition / "out" / path.name
    command = [
        sys.executable,
        "-I",
        str(edition / "conformance/run.py"),
        "--report",
        str(generated),
        *args,
    ]
    run = subprocess.run(command, cwd=edition, stdout=subprocess.PIPE, text=True, timeout=240)
    if not generated.is_file():
        raise ValueError(
            f"published runner produced no report ({path.name}, exit {run.returncode})"
        )
    report = read_json(generated.read_bytes())
    generated.replace(path)
    passed = sum(row["status"] == "pass" for row in report["checks"])
    print(f"{passed}/{len(report['checks'])} passed ({path.relative_to(ROOT)})", flush=True)
    return report, run.returncode


def check(revision):
    current_report = load(ROOT, "out/conformance.json")
    current_cases = {case["id"]: case for case in load(ROOT, CORPUS)}
    current_index = load(ROOT, INDEX)
    current_rules = rule_index(ROOT)
    current_tests = named_tests(ROOT)
    problems = audit_index(
        current_index, current_report, current_cases, current_rules, current_tests
    )

    reports = ROOT / "out/baseline" / revision
    with tempfile.TemporaryDirectory(prefix=".ocs-compat-", dir=ROOT / "out") as temp:
        edition = Path(temp) / "edition"
        unpack_edition(revision, edition)
        old_cases = {case["id"]: case for case in load(edition, CORPUS)}
        old_rules = set().union(*rule_index(edition).values())
        problems += difference(
            "removed published rule", old_rules, set().union(*current_rules.values())
        )
        for name in sorted(old_cases.keys() & current_cases.keys()):
            if not same_json(old_cases[name], current_cases[name]):
                print(f"Changed case {name}. Replaying its published expectations.", flush=True)
        problems += case_changes(old_cases, current_cases)
        for message in difference(
            "published fixture locator moved or removed", named_tests(edition), current_tests
        ):
            print(message, flush=True)
        if (edition / INDEX).is_file():
            old_scenarios = load(edition, INDEX)["scenarios"]
            new_scenarios = current_index["scenarios"]
            problems += difference("removed published scenario", old_scenarios, new_scenarios)
            for name in old_scenarios.keys() & new_scenarios.keys():
                if old_scenarios[name]["checks"] and not new_scenarios[name]["checks"]:
                    problems.append(f"published scenario lost all candidate evidence: {name}")

        print(f"Replaying accepted edition {revision}", flush=True)
        reports.mkdir(parents=True, exist_ok=True)
        deploy_reference_targets(edition)
        historical, mixed_exit = run_report(edition, reports / "hosts-and-go.json")
        python_target = ROOT / "examples/status"
        executor, executor_exit = run_report(
            edition,
            reports / "python-executor.json",
            "--manifest",
            str(python_target / "ocs.json"),
            "--target",
            sys.executable,
            "-I",
            str(python_target / "executor.py"),
        )
        problems += difference(
            "missing published Python replay result",
            old_cases,
            (row["id"] for row in executor["checks"]),
        )
        current_ids = {row["id"] for row in current_report["checks"]}
        problems += difference(
            "missing published check in candidate report",
            (row["id"] for row in historical["checks"]),
            current_ids,
        )
        for label, report, code in (
            ("published host suite", historical, mixed_exit),
            ("published caller / current Python executor", executor, executor_exit),
        ):
            failed = [row for row in report["checks"] if row["status"] != "pass"]
            problems.extend(f"{label}: {row['id']} ({row['status']})" for row in failed)
            if code and not failed:
                problems.append(f"{label} exited with status {code}")

        fixture = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "conformance"],
            cwd=edition,
            timeout=90,
        )
        # Older public data must also be readable through the current schema registry.
        validator = edition / "reference/contracts.py"
        validator.unlink()
        validator.symlink_to(ROOT / "reference/contracts.py")
        records = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "test_profiles",
                "test_contracts.ContractTests.test_record_corpus",
            ],
            cwd=edition / "conformance",
            timeout=90,
        )
        go = subprocess.run(["go", "test", "-count=1", "./reference/go"], cwd=edition, timeout=120)
        if fixture.returncode or records.returncode or go.returncode:
            problems.append("published fixtures or candidate reading published records failed")

    for problem in problems:
        print("FAIL", problem, file=sys.stderr)
    if not problems:
        print(
            f"Indexed {sum(map(len, current_rules.values()))} requirements and {len(current_index['scenarios'])} scenarios. Baseline compatibility passed."
        )
    return int(bool(problems))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision", help="full commit ID of the accepted edition")
    try:
        raise SystemExit(check(parser.parse_args().revision))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"compatibility check failed: {error}\n")
