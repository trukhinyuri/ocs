"""Exercise the enrolled receiver through real Git pushes using disposable review identities."""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import prepare, state
from authority import ROLES, canonical, digest, framed, immutable, load, signature
from operator_cli import import_object, install, stage_files
from receiver import chain_status

BASE = "3facf571910e0799539a77a1a5112e6609a9a5ca"
ORACLE = "e09a5d7d0ae15d35910e72243c4a466974f09401"


def client_command(repo, args):
    command = [
        "git",
        "-c",
        "safe.directory=" + str(Path(repo).resolve()),
        "-C",
        str(repo),
        *args,
    ]
    caller = os.environ.get("OCS_ACCEPTANCE_CLIENT")
    if caller and any(value in ("push", "ls-remote") for value in args):
        import pwd

        user = pwd.getpwnam(caller)
        if os.geteuid() != 0 or user.pw_uid == 0:
            raise ValueError(
                "the separated native test requires a non-root socket client and an administrator for evidence intake"
            )
        command = [
            "setpriv",
            "--reuid=" + str(user.pw_uid),
            "--regid=" + str(user.pw_gid),
            "--clear-groups",
            "--no-new-privs",
            "--bounding-set=-all",
            *command,
        ]
    return command


def git(repo, *args, env=None, data=None, check=True):
    e = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Fixture Operator",
        "GIT_COMMITTER_NAME": "Fixture Operator",
        "GIT_AUTHOR_EMAIL": "operator@example.invalid",
        "GIT_COMMITTER_EMAIL": "operator@example.invalid",
        **(env or {}),
    }
    if os.environ.get("OCS_ACCEPTANCE_CLIENT") and os.geteuid() == 0:
        import pwd

        e["HOME"] = pwd.getpwnam(os.environ["OCS_ACCEPTANCE_CLIENT"]).pw_dir
    p = subprocess.run(
        client_command(repo, args),
        check=False,
        capture_output=True,
        input=data,
        env=e,
    )
    if check and p.returncode:
        raise RuntimeError((p.stderr + p.stdout).decode(errors="replace")[-1800:])
    return p if not check else p.stdout.decode().strip()


def ensure_key(dir, role):
    key = dir / (role + ".key")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    return subprocess.check_output(
        ["openssl", "pkey", "-in", str(key), "-pubout"], text=True
    )


def acquire(directory, rev, condition):
    directory.mkdir(parents=True)
    until = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    immutable(
        directory / "acquisition.json",
        canonical({"revision": rev, "conditions": condition, "expiresAt": until}),
    )


class Experiment:
    def __init__(self, work, source, cfg=None, url=None):
        work, source = work.resolve(), source.resolve()
        self.work = work
        self.source = source
        self.client = work / "client"
        self.keydir = work / "custodians"
        self.condition = digest(b"sealed-status-4-frame-posix-python3-wire-bytes-v1")
        if not self.client.exists():
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--no-hardlinks",
                    str(source),
                    str(self.client),
                ],
                check=True,
            )
            git(self.client, "checkout", "--quiet", "--detach", BASE)
        self.records = []
        if cfg is None:
            self.keydir.mkdir(mode=0o700)
            keys = {r: ensure_key(self.keydir, r) for r in (*ROLES, "publisher")}
            adapter = HERE / "tests/status_adapter.py"
            refinement = HERE / "tests/refinement_adapter.py"
            policy = {
                "format": "ocs.safe-push.policy/1",
                "project": "ocs-receiver-calibration",
                "profile": "receiver-experiment/1",
                "epoch": 0,
                "genesis": BASE,
                "assurancePin": ORACLE,
                "keys": keys,
                "lifetimeSeconds": 86400,
                "receiveTimeoutSeconds": 180,
                "receiverCost": {
                    "profile": "receiver-experiment/1",
                    "mode": "observation-only",
                },
                "requiredOpen": [],
                "adapters": {"status-bytes": digest(adapter.read_bytes())},
                "predicateCheckers": {
                    "sealed-example": {
                        "sha256": digest(refinement.read_bytes()),
                        "requirements": [
                            "source.refinement",
                            "remediation/fixture-document",
                        ],
                        "pathPrefixes": [
                            "examples/status/executor.py",
                            "docs/receiver-recovery.md",
                        ],
                    }
                },
                "targets": {
                    "stdio": {
                        "adapter": "status-bytes",
                        "observerSha256": None,
                        "conditions": self.condition,
                    }
                },
            }
            acquire(work / "bootstrap/stdio", BASE, self.condition)
            pp = work / "policy.json"
            immutable(pp, canonical(policy))
            lean = os.environ.get("SAFE_PUSH_LEAN_HOME")
            self.config = install(
                work / "receiver",
                source,
                pp,
                work / "bootstrap",
                [],
                [adapter, refinement],
                self.keydir / "publisher.key",
                Path(lean) if lean else None,
            )
        else:
            self.config = cfg
        self.cfg, self.a, self.j, self.bare, self.policy = state(self.config)
        svc = HERE / "receiver.py"
        self.url = url or f"ext::{sys.executable} -I {svc} serve {self.config} %S"
        self.standard = self.url.startswith("ocs::")
        self.remote = "safe-push" if self.standard else self.url
        self.protocol_options = (
            [] if self.standard else ["-c", "protocol.ext.allow=always"]
        )
        if self.standard:
            git(self.client, "config", "remote.safe-push.url", self.url)
            git(self.client, "config", "remote.safe-push.push", "HEAD:refs/heads/main")

    def candidate(self, parent, label, edit):
        git(self.client, "checkout", "--quiet", "--detach", parent)
        git(self.client, "reset", "--hard", "--quiet", parent)
        edit(self.client)
        git(self.client, "add", "-A")
        git(self.client, "commit", "--quiet", "--allow-empty", "-m", label)
        return git(self.client, "rev-parse", "HEAD")

    def stage(self, candidate):
        # Trusted evaluator's candidate-object input. No reference is published.
        import_object(self.config, self.client, candidate)
        f = self.work / "inputs" / candidate
        acquire(f, candidate, self.condition)
        stage_files(self.config, "evidence", candidate, f, "stdio")

    def reviews(self, parent, candidate, portable=False):
        req = prepare(self.config, parent, candidate, want_context="context")
        folder = self.work / "review-inputs" / candidate
        folder.mkdir(parents=True)
        now = datetime.now(UTC)
        replays = {}
        if portable:
            from tests import refinement_adapter as ref

            for key, item in req["requirements"].items():
                if item["kind"] != "portable-proof":
                    continue
                if key == "source.refinement":
                    old = subprocess.check_output(
                        [
                            "git",
                            "-C",
                            str(self.client),
                            "show",
                            parent + ":" + ref.EXECUTOR,
                        ]
                    )
                    new = subprocess.check_output(
                        [
                            "git",
                            "-C",
                            str(self.client),
                            "show",
                            candidate + ":" + ref.EXECUTOR,
                        ]
                    )
                    content = {
                        "predicate": "sealed-status-eof-comment",
                        "parent": parent,
                        "candidate": candidate,
                        "left": digest(old),
                        "right": digest(new),
                    }
                elif key == "remediation/fixture-document":
                    content = {"fix": digest(ref.TEXT), "original": digest(ref.ALERT)}
                else:
                    raise AssertionError("no fixture proof for " + key)
                raw = canonical(content)
                mark = digest(raw)
                immutable(folder / "proofs" / mark, raw)
                replays[key] = {"method": "sealed-example", "artifact": mark}
            immutable(folder / "proofs.json", canonical(replays))
            if "remediation/fixture-document" in replays:
                alert = load(self.a / "alerts/fixture-document.json")
                ground = {
                    "case": "fixture-document",
                    "original": digest(ref.ALERT),
                    "source": digest(ref.TEXT),
                    "replay": "remediation/fixture-document",
                }
                mark = framed(ground)
                immutable(folder / "findings" / (mark + ".json"), canonical(ground))
                base = {
                    "format": "ocs.safe-push.remediation/1",
                    "context": req["context"],
                    "id": "fixture-document",
                    "alert": framed(alert),
                    "regressionEvidence": mark,
                    "replay": "remediation/fixture-document",
                }
                res = {
                    "regressionEvidence": mark,
                    "replay": "remediation/fixture-document",
                }
                for role in ROLES:
                    res[role] = signature(
                        {**base, "role": role}, self.keydir / (role + ".key")
                    )
                immutable(
                    folder / "resolutions.json", canonical({"fixture-document": res})
                )
        for role in ("domain", "independent"):
            findings = {}
            for key, item in req["requirements"].items():
                if item["ownerRole"] != role:
                    continue
                detail = {
                    "requirement": item["digest"],
                    "candidate": candidate,
                    "conclusion": "satisfied",
                    "unresolved": [],
                    "method": "Review the four-frame public reference and the exact supplemental text in a disposable receiver experiment.",
                    "domain": "Receiver calibration on the registered stdio status target only.",
                    "falsifier": "Unexpected status, accepted foreign resource, changed response bytes, or different source.",
                    "sources": [req["context"]["sourceSha256"], item["digest"]],
                    "observations": req["context"]["targetReports"]["stdio"],
                    "counterevidence": [],
                    "facets": {},
                }
                for facet in item["evidence"]:
                    material = {
                        "facet": facet,
                        "criterion": item["digest"],
                        "paths": item["paths"],
                        "claims": item["claims"],
                        "sources": [
                            req["context"]["sourceSha256"],
                            *req["context"]["targetReports"]["stdio"],
                        ],
                        "finding": "In this disposable calibration the declared four-frame workload and scoped Git delta provide the recorded "
                        + facet
                        + " observation.",
                    }
                    data = canonical(material)
                    mark = digest(data)
                    immutable(folder / "materials" / (mark + ".json"), data)
                    detail["facets"][facet] = mark
                raw = canonical(detail)
                sha = digest(raw)
                immutable(folder / "findings" / (sha + ".json"), raw)
                findings[key] = sha
            message = {
                "format": "ocs.safe-push.review/1",
                "role": role,
                "context": req["context"],
                "issuedAt": (now - timedelta(seconds=1)).isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "findings": findings,
            }
            immutable(
                folder / (role + ".json"),
                canonical(signature(message, self.keydir / (role + ".key"))),
            )
        stage_files(self.config, "reviews", candidate, folder)

    def push(self, label, rev, expected, diagnostic=None):
        before = self.readback()
        if self.standard:
            assert git(self.client, "rev-parse", "HEAD") == rev
        args = (
            ["push", self.remote]
            if self.standard
            else [*self.protocol_options, "push", self.remote, rev + ":refs/heads/main"]
        )
        p = git(self.client, *args, check=False)
        after = self.readback()
        log = (p.stdout + p.stderr).decode(errors="replace")
        actual = p.returncode == 0 and after == rev
        self.records.append(
            {
                "case": label,
                "candidate": rev,
                "before": before,
                "after": after,
                "gitExit": p.returncode,
                "accepted": actual,
                "clientCommand": ["git", *args],
                "clientAccount": os.environ.get(
                    "OCS_ACCEPTANCE_CLIENT", "disposable contributor"
                ),
                "diagnostic": log[-1800:],
            }
        )
        assert actual == expected and (actual or before == after), self.records[-1]
        if diagnostic:
            assert diagnostic.lower() in log.lower(), self.records[-1]
        return actual

    def readback(self):
        remote = git(
            self.client,
            *self.protocol_options,
            "ls-remote",
            self.remote,
            "refs/heads/main",
        ).split()
        direct = git(self.bare, "rev-parse", "refs/heads/main")
        assert remote == [direct, "refs/heads/main"]
        return direct


def text_change(path, old, new):
    def edit(repo):
        p = repo / path
        body = p.read_text()
        assert body.count(old) == 1, (path, old)
        p.write_text(body.replace(old, new))

    return edit


def append_note(title):
    return lambda repo: (repo / "docs" / (title + ".md")).write_text(
        "# Status example\n\nThe sealed example reads the resource `demo`.\n"
    )


def run(exp):
    parent = exp.readback()
    assert parent == BASE
    unregistered = exp.candidate(
        parent,
        "Submit a fresh candidate without external qualification",
        append_note("unregistered-incoming"),
    )
    exp.push(
        "fresh quarantined Git tree requires independent evidence",
        unregistered,
        False,
        "qualification.missing",
    )
    req = exp.candidate(
        parent, "Remove a published public case", lambda repo: remove_case(repo)
    )
    exp.stage(req)
    exp.push(
        "deleted requirement and published test",
        req,
        False,
        "recover-after-input-error",
    )
    code = exp.candidate(
        parent,
        "Change required ready state",
        text_change(
            "examples/status/executor.py", '"state": "ready"', '"state": "unavailable"'
        ),
    )
    exp.stage(code)
    exp.push("public executable regression", code, False, "evidence.method")
    metric = exp.candidate(
        parent,
        "Preserve reply value but add wire bytes",
        text_change(
            "examples/status/executor.py",
            "allow_nan=False), flush=True)",
            'allow_nan=False) + " ", flush=True)',
        ),
    )
    exp.stage(metric)
    exp.push(
        "strict comparable measurement regression", metric, False, "metrics.regression"
    )
    repeated = exp.candidate(
        parent,
        "Same observable bytes under a second commit ID",
        text_change(
            "examples/status/executor.py",
            "allow_nan=False), flush=True)",
            'allow_nan=False) + " ", flush=True)',
        ),
    )
    exp.stage(repeated)
    exp.push(
        "retained adverse observation across commit identities",
        repeated,
        False,
        "metrics.prior-regression",
    )
    guard = exp.candidate(
        parent,
        "Modify qualification policy selector",
        text_change(
            "Makefile", "OCS_ASSURANCE_BASELINE ?= ", "OCS_ASSURANCE_BASELINE := "
        ),
    )
    exp.stage(guard)
    exp.reviews(parent, guard)
    exp.push(
        "guardian replacement lacks incumbent transition proof", guard, False, "proof"
    )
    unclassified = exp.candidate(
        parent,
        "Introduce a new object kind",
        lambda repo: (repo / "new.unknown-object").write_bytes(b"example"),
    )
    exp.stage(unclassified)
    exp.push("unclassified file", unclassified, False)
    no_review = exp.candidate(
        parent,
        "Document status output while omitting a review",
        append_note("example-review"),
    )
    exp.stage(no_review)
    exp.push("missing independent review", no_review, False)
    yes = exp.candidate(
        parent,
        "Document the registered status fixture",
        append_note("qualified-status"),
    )
    exp.stage(yes)
    exp.reviews(parent, yes)
    exp.push("positive qualified commit", yes, True)
    audit = chain_status(exp.config, True)
    assert audit["certifiedTransitions"] == 1 and audit["tip"] == yes
    # Both siblings receive full independently scoped reviews before competing for the same ref.
    siblings = []
    for n in ("first", "second"):
        rev = exp.candidate(
            yes, n + " qualified sibling", append_note("qualified-" + n)
        )
        exp.stage(rev)
        exp.reviews(yes, rev)
        siblings.append(rev)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda rev: (
                    git(
                        exp.client,
                        *exp.protocol_options,
                        "push",
                        exp.remote,
                        rev + ":refs/heads/main",
                        check=False,
                    ).returncode
                ),
                siblings,
            )
        )
    tip = exp.readback()
    assert sorted(statuses) == [0, 1] and tip == siblings[statuses.index(0)], (
        statuses,
        tip,
    )
    exp.records.append(
        {
            "case": "concurrent siblings",
            "before": yes,
            "candidates": siblings,
            "gitExit": statuses,
            "after": tip,
        }
    )
    from tests import refinement_adapter as ref

    def equivalent(repo):
        with (repo / ref.EXECUTOR).open("ab") as f:
            f.write(b"\n# The public read remains usable after a denied resource.\n")

    same = exp.candidate(
        tip, "Retain the exact bytecode and public outcomes", equivalent
    )
    exp.stage(same)
    exp.reviews(tip, same, portable=True)
    exp.push(
        "equivalent implementation with an enrolled exact-bytecode check", same, True
    )
    flaw = exp.work / "case-material"
    flaw.write_bytes(ref.ALERT)
    alert = {
        "format": "ocs.safe-push.counterexample/1",
        "project": exp.policy["project"],
        "epoch": exp.policy["epoch"],
        "id": "fixture-document",
        "scope": same,
        "evidence": digest(ref.ALERT),
    }
    ap = exp.work / "counterexample.json"
    immutable(ap, canonical(signature(alert, exp.keydir / "guardian.key")))
    subprocess.run(
        [
            sys.executable,
            "-I",
            str(HERE / "operator_cli.py"),
            "alert",
            str(exp.config),
            str(ap),
            "--evidence",
            str(flaw),
        ],
        check=True,
    )
    try:
        chain_status(exp.config, True)
    except ValueError as err:
        assert "counterexample" in str(err), err
    else:
        raise AssertionError("current consumption ignored the confirmed counterexample")
    broken = exp.candidate(
        same,
        "Unrelated text cannot repair confirmed evidence",
        append_note("unrelated"),
    )
    exp.stage(broken)
    exp.reviews(same, broken)
    exp.push(
        "confirmed parent counterexample blocks a descendant",
        broken,
        False,
        "remediation",
    )
    fix = exp.candidate(
        same,
        "Supply verified recovery example",
        lambda repo: (repo / ref.DOC).write_bytes(ref.TEXT),
    )
    exp.stage(fix)
    exp.reviews(same, fix, portable=True)
    exp.push("qualified remediation with retained contrary evidence", fix, True)
    # A two-commit fast forward must not introduce an unchecked intermediate object.
    intermediate = exp.candidate(
        fix, "Unreviewed intermediate", append_note("intermediate")
    )
    double = exp.candidate(
        intermediate, "Final tip cannot hide an intermediate", append_note("final-tip")
    )
    exp.push("unqualified intermediate rejected", double, False, "direct child")
    return chain_status(exp.config, True)


def remove_case(repo):
    f = repo / "conformance/cases/core.json"
    doc = json.loads(f.read_bytes())
    if isinstance(doc, list):
        rows = doc
    else:
        rows = doc["cases"]
    rows[:] = [r for r in rows if r["id"] != "recover-after-input-error"]
    f.write_text(json.dumps(doc, indent=2) + "\n")
    f = repo / "conformance/scenarios.json"
    doc = json.loads(f.read_bytes())
    doc["scenarios"]["status-call"]["checks"].remove("recover-after-input-error")
    f.write_text(json.dumps(doc, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, default=HERE.parent)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--config", type=Path)
    p.add_argument("--url")
    p.add_argument("--initialize", action="store_true")
    args = p.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    exp = Experiment(args.work, args.source, args.config, args.url)
    if args.initialize:
        print(exp.config)
        return
    try:
        audit = run(exp)
    finally:
        (args.work / "experiments.json").write_bytes(canonical(exp.records))
    print(json.dumps({"status": "pass", "cases": len(exp.records), "chain": audit}))


if __name__ == "__main__":
    main()
