#!/usr/bin/env python3
"""Install a reference receiver, prepare independent review requests, and stage public evidence."""

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from datetime import UTC

from admission import bundle_inventory, get_parent, git, observe, state, target_attempts
from authority import (
    NAME,
    OBJECT,
    ROLES,
    SHA256,
    authentic,
    canonical,
    digest,
    framed,
    fsync_dir,
    immutable,
    load,
    public_der,
    read,
    replace_pointer,
    require,
    signature,
    validate_policy,
)
from receiver import publication_lock, recover
from scope import change_requirements, inventory, subject


def copy_tree(src, dest):
    """Custodian imports regular files into a never-modified snapshot."""
    src = src.resolve()
    require(src.is_dir(), "evidence.copy", "missing evidence directory")
    dest.mkdir(mode=0o755)
    total = 0
    for path in sorted(src.rglob("*")):
        if path.is_symlink():
            raise ValueError(
                "evidence links require materializing the original target first"
            )
        name = dest / path.relative_to(src)
        if path.is_dir():
            name.mkdir(mode=0o755)
        else:
            contents = read(path, 64 * 1024 * 1024)
            total += len(contents)
            require(
                total <= 512 * 1024 * 1024, "evidence.copy", "oversized evidence bundle"
            )
            immutable(name, contents)


def hook_files(directory, config):
    hooks = directory / "hooks"
    hooks.mkdir(mode=0o755)
    for hook in ("pre-receive", "reference-transaction"):
        cmd = " ".join(
            map(
                shlex.quote,
                (
                    sys.executable,
                    "-I",
                    str(HERE / "receiver.py"),
                    "hook",
                    str(config),
                    hook,
                ),
            )
        )
        file = hooks / hook
        immutable(file, ("#!/bin/sh\nexec " + cmd + ' "$@"\n').encode())
        file.chmod(0o755)
    return hooks


def install(
    root,
    source,
    policy_path,
    evidence,
    observer_keys,
    methods,
    publisher_key,
    lean,
    witness=None,
    cost_baseline=None,
):
    """The caller independently chooses the release, policies, inputs and initial public keys."""
    root, source = root.resolve(), source.resolve()
    require(
        not root.exists(),
        "install.location",
        "refusing to replace an existing receiver",
    )
    policy = load(policy_path)
    validate_policy(policy)
    require(policy["epoch"] == 0, "install.epoch", "bootstrap requires epoch zero")
    require(
        git(source, "rev-parse", "--verify", policy["genesis"]) == policy["genesis"],
        "install.genesis",
        "missing exact initial commit",
    )
    require(
        git(source, "rev-parse", "--verify", policy["assurancePin"])
        == policy["assurancePin"],
        "install.verifier",
        "missing pinned qualification verifier",
    )
    root.mkdir(parents=True, mode=0o700)
    authority, journal, repo = (
        root / "authority",
        root / "journal",
        root / "repository.git",
    )
    for p in (authority, journal):
        p.mkdir(mode=0o755)
    # Only the enrolled main lineage is exposed. Independent verifier objects can
    # be transferred by a temporary administrative fetch before hooks are installed.
    clean_env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(source),
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_VALUE_1": str(repo),
    }

    def call(*argv):
        subprocess.run(
            argv,
            check=True,
            env=clean_env,
            capture_output=True,
        )

    call("git", "init", "--bare", "--initial-branch=main", str(repo))
    call(
        "git",
        "-C",
        str(repo),
        "fetch",
        "--no-tags",
        str(source),
        policy["genesis"],
        policy["assurancePin"],
    )
    call("git", "-C", str(repo), "update-ref", "refs/heads/main", policy["genesis"])
    for key_path in observer_keys:
        b = read(key_path)
        public_der(b.decode("ascii"))
        immutable(authority / "observers" / (digest(b) + ".pem"), b)
    hashes = set(policy["adapters"].values()) | {
        v["sha256"] for v in policy["predicateCheckers"].values()
    }
    files = {digest(read(p)): p for p in methods}
    require(
        set(files) == hashes,
        "install.method",
        "installed method set differs from enrollment",
    )
    for sha, path in files.items():
        immutable(authority / "methods" / (sha + ".py"), read(path))
    immutable(authority / "root.json", canonical(policy))
    base_inventory = inventory(repo, policy["genesis"])
    base_plan = change_requirements(
        repo, policy["genesis"], policy["genesis"], base_inventory, base_inventory
    )
    ident = subject(repo, policy["genesis"], base_inventory)
    claims, metrics, reports, gaps, limits, expiry = {}, {}, {}, [], {}, []
    for target in sorted(policy["targets"]):
        stage = authority / "bootstrap" / target
        stage.parent.mkdir(parents=True, exist_ok=True)
        copy_tree(evidence / target, stage)
        result = observe(authority, repo, policy, target, stage, ident)
        if policy["targets"][target]["adapter"] == "ocs-dossier/1":
            levels = base_plan["requirements"]["qualification.full"]["levels"]
            require(
                all(
                    atom + "@" + level in result["claims"]
                    for atom, needed in levels.items()
                    for level in needed
                ),
                "install.qualification",
                "missing original OCS obligation at required level",
            )
        claims.update({target + "/" + k: v for k, v in result["claims"].items()})
        metrics.update({target + "/" + k: v for k, v in result["metrics"].items()})
        reports[target] = result["reportSha256"]
        gaps.extend(target + "/" + g for g in result.get("metricGaps", []))
        limits[target] = result.get("coverageLimits", [])
        from authority import instant

        expiry.append(instant(result["expiresAt"]))
    require(
        not gaps,
        "install.metric-inventory",
        "incomplete enrolled measurements: " + ", ".join(gaps),
    )
    seed = {
        "format": "ocs.safe-push.genesis/1",
        "project": policy["project"],
        "profile": policy["profile"],
        "candidate": policy["genesis"],
        "tree": git(repo, "rev-parse", policy["genesis"] + "^{tree}"),
        "policy": framed(policy),
        "subject": ident,
        "wholeTreeSha256": base_plan["wholeTreeSha256"],
        "claims": claims,
        "metrics": metrics,
        "targetReports": reports,
        "coverageLimits": limits,
        "expiresEpoch": min(expiry),
    }
    if cost_baseline is not None:
        require(
            isinstance(policy["receiverCost"], dict)
            and digest(read(cost_baseline))
            == policy["receiverCost"]["baselineEvidenceSha256"],
            "install.cost",
            "baseline does not match the independently selected observation",
        )
        seed["receiverCost"] = load(cost_baseline)
    elif (
        isinstance(policy["receiverCost"], dict)
        and policy["receiverCost"].get("mode") != "observation-only"
    ):
        raise ValueError("enrolled receiver cost baseline missing")
    immutable(authority / "genesis.json", canonical(seed))
    witness = (
        Path(witness).resolve()
        if witness is not None
        else root / "witness" / "epoch.json"
    )
    immutable(
        witness,
        canonical(
            {
                "project": policy["project"],
                "policy": framed(policy),
                "epoch": 0,
                "branchFloor": policy["genesis"],
                "receiptDigest": framed(seed),
            }
        ),
    )
    config = root / "receiver.json"
    credentials = root / "publishing"
    credentials.mkdir(mode=0o700)
    signing = credentials / (digest(public_der(policy["keys"]["publisher"])) + ".key")
    shutil.copyfile(publisher_key, signing)
    signing.chmod(0o600)
    require(
        authentic(
            signature(seed, signing), policy["keys"]["publisher"], "install.publisher"
        )
        == seed,
        "install.publisher",
        "publishing key differs from enrolled public key",
    )
    immutable(
        config,
        canonical(
            {
                "rootDigest": framed(policy),
                "genesisDigest": framed(seed),
                "project": policy["project"],
                "genesis": policy["genesis"],
                "repo": str(repo),
                "authority": str(authority),
                "journal": str(journal),
                "publishingKeys": str(credentials),
                "witness": str(witness),
                "leanHome": str(lean.resolve()) if lean else "",
            }
        ),
    )
    hooks = hook_files(root, config)
    for k, v in (
        ("core.hooksPath", str(hooks)),
        ("receive.denyDeletes", "true"),
        ("receive.denyNonFastForwards", "true"),
        ("receive.fsckObjects", "true"),
        ("core.logAllRefUpdates", "true"),
        ("core.fsync", "committed"),
        ("gc.auto", "0"),
    ):
        call("git", "-C", str(repo), "config", k, v)
    immutable(root / "sealed.json", canonical({"configuration": framed(load(config))}))
    root.chmod(0o755)
    fsync_dir(root)
    return config


def stage_files(config, category, candidate, source, target=None):
    cfg, a, j, repo, policy = state(config)
    require(OBJECT.fullmatch(candidate), "evidence.identity", "full commit required")
    require(category in ("reviews", "evidence"), "evidence.stage", "unknown category")
    require(
        category == "reviews" or target in policy["targets"],
        "evidence.target",
        "unknown target",
    )
    with publication_lock(j):
        cfg, a, j, repo, policy = state(config)
        recover(cfg, a, j, repo)
        if category == "reviews":
            dest = a / "reviews" / candidate
        else:
            dest = a / "evidence" / candidate / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=dest.parent) as td:
            scratch = Path(td) / "data"
            copy_tree(source, scratch)
            files = {
                x.relative_to(scratch).as_posix(): digest(read(x, 64 * 1024 * 1024))
                for x in scratch.rglob("*")
                if x.is_file()
            }
            key = framed(files)
            home = dest
            if category == "evidence":
                dest.mkdir(exist_ok=True)
                dest = dest / key
            else:
                (home / "runs").mkdir(parents=True, exist_ok=True)
                dest = home / "runs" / key
                active = home / "current.json"
                original = load(active)["bundle"] if active.is_file() else None
                if original not in (None, key):
                    for role in ("domain", "independent"):
                        new = authentic(
                            load(scratch / (role + ".json")),
                            policy["keys"][role],
                            "review.renewal",
                        )
                        require(
                            new.get("role") == role
                            and new.get("context", {}).get("candidate") == candidate
                            and new.get("supersedes") == original,
                            "review.renewal",
                            "renewal must bind the preceding signed bundle",
                        )
            if dest.exists():
                require(
                    bundle_inventory(dest) == files,
                    "evidence.conflict",
                    "registered bytes changed",
                    "rejected",
                )
            else:
                os.rename(scratch, dest)
                fsync_dir(dest.parent)
            if category == "reviews":
                tree = git(repo, "rev-parse", candidate + "^{tree}")
                for role in ("domain", "independent"):
                    message = authentic(
                        load(dest / (role + ".json")),
                        policy["keys"][role],
                        "review.custody",
                    )
                    require(
                        message.get("role") == role
                        and message["context"]["candidate"] == candidate
                        and message["context"]["tree"] == tree,
                        "review.custody",
                        "misbound review",
                    )
                    for id_, mark in message["findings"].items():
                        require(
                            SHA256.fullmatch(mark), "review.custody", "invalid finding"
                        )
                        f = dest / "findings" / (mark + ".json")
                        raw = read(f)
                        require(
                            digest(raw) == mark,
                            "review.custody",
                            "changed signed finding",
                        )
                        finding = load(f)
                        if finding.get("conclusion") == "rejected" or finding.get(
                            "unresolved"
                        ):
                            immutable(
                                a / "review-adverse" / tree / (mark + ".json"),
                                canonical(
                                    {
                                        "role": role,
                                        "criterion": id_,
                                        "finding": mark,
                                        "bundle": key,
                                    }
                                ),
                            )
                replace_pointer(active, canonical({"bundle": key}))
        if category == "evidence":
            # Record contrary observations as soon as the custodian receives them,
            # even when the contributor never submits that commit to main.
            parent = git(repo, "show", "-s", "--format=%P", candidate)
            tree = git(repo, "rev-parse", candidate + "^{tree}")
            recorded = a / "acquisitions" / candidate / target / (dest.name + ".json")
            if recorded.is_file():
                return dest
            record = {
                "candidate": candidate,
                "parent": parent,
                "target": target,
                "tree": tree,
                "input": dest.name,
                "policy": framed(policy),
            }
            try:
                previous = get_parent(cfg, a, j, parent)
                ident = subject(repo, candidate, inventory(repo, candidate))
                positive, cells, reports, gaps, until = target_attempts(
                    a, a, repo, policy, target, ident, tree, previous, single=dest
                )
                from datetime import datetime

                record["verified"] = {
                    "claims": positive,
                    "metrics": cells,
                    "reportSha256": reports[0],
                    "metricGaps": gaps,
                    "expiresAt": datetime.fromtimestamp(until, UTC).isoformat(),
                }
                record["outcome"] = "observed"
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                subprocess.SubprocessError,
            ) as error:
                record.update(
                    outcome=getattr(error, "outcome", "undetermined"),
                    reason=str(error)[:900],
                )
            immutable(recorded, canonical(record))
        return dest


def sign_input(role, key, input_file, output):
    data = load(input_file)
    require(data.get("role") == role, "sign.role", "operator selected a different role")
    immutable(output, canonical(signature(data, key)))


def import_object(config, source, candidate):
    """Transfer a candidate's Git objects for offline evaluation without writing any refs."""
    cfg, authority, journal, repo, policy = state(config)
    require(
        OBJECT.fullmatch(candidate)
        and git(source, "cat-file", "-t", candidate) == "commit",
        "evidence.identity",
        "expected a full candidate commit from a local evaluator",
    )
    with publication_lock(journal):
        recover(cfg, authority, journal, repo)
        before = git(repo, "rev-parse", "refs/heads/main")
        with tempfile.TemporaryFile() as pack:
            subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-c",
                    "safe.directory=" + str(Path(source).resolve()),
                    "-C",
                    str(source),
                    "pack-objects",
                    "--stdout",
                    "--revs",
                    "-q",
                ],
                input=(candidate + "\n^" + policy["genesis"] + "\n").encode(),
                stdout=pack,
                check=True,
                timeout=90,
            )
            pack.seek(0)
            subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-c",
                    "safe.directory=" + str(repo),
                    "-C",
                    str(repo),
                    "index-pack",
                    "--stdin",
                    "--strict",
                    "--fix-thin",
                ],
                stdin=pack,
                stdout=subprocess.DEVNULL,
                check=True,
                timeout=90,
            )
        require(
            git(repo, "rev-parse", "refs/heads/main") == before
            and git(repo, "cat-file", "-t", candidate) == "commit",
            "evidence.objects",
            "candidate transfer failed readback",
        )


def rotate(config, rotation, publisher_key=None):
    cfg = load(config)
    require(
        load(Path(config).parent / "sealed.json")["configuration"] == framed(cfg),
        "trust.installation",
        "unsealed receiver",
    )
    a, j, repo = (Path(cfg[key]) for key in ("authority", "journal", "repo"))
    from authority import policy_history

    record = load(rotation)
    with publication_lock(j):
        floor = load(Path(cfg["witness"]))
        chain = policy_history(a, cfg["rootDigest"])
        if len(chain) == floor["epoch"] + 2:
            last = a / "rotations" / f"{chain[-1]['epoch']:012}.json"
            require(
                framed(chain[-2]) == floor["policy"] and load(last) == record,
                "trust.rotation",
                "another incomplete rotation or an inconsistent floor",
            )
            if (
                chain[-2]["receiverCost"] is None
                and isinstance(chain[-1]["receiverCost"], dict)
                and "ceilings" in chain[-1]["receiverCost"]
            ):
                from cost_acquisition import elected_material

                elected_material(cfg, a, j, chain[-2], chain[-1], record)
            key = Path(cfg["publishingKeys"]) / (
                digest(public_der(chain[-1]["keys"]["publisher"])) + ".key"
            )
            require(
                authentic(
                    signature(record["policy"], key),
                    chain[-1]["keys"]["publisher"],
                    "trust.publisher",
                )
                == record["policy"],
                "trust.publisher",
                "incomplete key installation",
            )
            replace_pointer(
                Path(cfg["witness"]),
                canonical(
                    {**floor, "epoch": chain[-1]["epoch"], "policy": framed(chain[-1])}
                ),
            )
            return
        cfg, a, j, repo, old = state(config)
        recover(cfg, a, j, repo)
        target = a / "rotations" / (f"{old['epoch'] + 1:012}.json")
        # Verify the proposed extension of the entire chain before exposing its bytes.
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            immutable(t / "root.json", read(a / "root.json"))
            if (a / "rotations").exists():
                shutil.copytree(a / "rotations", t / "rotations")
            for kind in ("evolution", "methods", "observers"):
                if (a / kind).is_dir():
                    (t / kind).symlink_to(
                        (a / kind).resolve(), target_is_directory=True
                    )
            if (a / "broker.json").is_file():
                immutable(t / "broker.json", read(a / "broker.json"))
            immutable(t / "rotations" / target.name, canonical(record))
            history = policy_history(t, cfg["rootDigest"])
            require(
                len(history) == old["epoch"] + 2, "trust.rotation", "invalid next epoch"
            )
            if (
                old["receiverCost"] is None
                and isinstance(history[-1]["receiverCost"], dict)
                and "ceilings" in history[-1]["receiverCost"]
            ):
                from cost_acquisition import elected_material

                elected_material(cfg, a, j, old, history[-1], record)
            new_public = history[-1]["keys"]["publisher"]
            if new_public != old["keys"]["publisher"]:
                require(
                    publisher_key is not None,
                    "trust.publisher",
                    "new publishing key required",
                )
                require(
                    authentic(
                        signature(record["policy"], publisher_key),
                        new_public,
                        "trust.publisher",
                    )
                    == record["policy"],
                    "trust.publisher",
                    "new publishing key differs from enrollment",
                )
                key_path = Path(cfg["publishingKeys"]) / (
                    digest(public_der(new_public)) + ".key"
                )
                key_data = read(publisher_key, 4096)
                with tempfile.NamedTemporaryFile(
                    dir=key_path.parent, delete=False
                ) as out:
                    tmp_key = Path(out.name)
                    os.fchmod(out.fileno(), 0o600)
                    out.write(key_data)
                    out.flush()
                    os.fsync(out.fileno())
                try:
                    try:
                        os.link(tmp_key, key_path)
                    except FileExistsError:
                        require(
                            read(key_path, 4096) == key_data,
                            "trust.publisher",
                            "previous installation differs",
                        )
                finally:
                    tmp_key.unlink()
                if os.name == "posix" and os.geteuid() == 0:
                    owner = Path(cfg["publishingKeys"]).stat()
                    os.chown(key_path, owner.st_uid, owner.st_gid)
                    if owner.st_mode & 0o050:
                        key_path.chmod(0o440)
                fsync_dir(key_path.parent)
        floor = load(Path(cfg["witness"]))
        immutable(target, canonical(record))
        replace_pointer(
            Path(cfg["witness"]),
            canonical(
                {**floor, "epoch": history[-1]["epoch"], "policy": framed(history[-1])}
            ),
        )


def checkpoint(config, envelopes):
    cfg, a, j, repo, policy = state(config, pending_checkpoint=envelopes)
    with publication_lock(j):
        cfg, a, j, repo, policy = state(config, pending_checkpoint=envelopes)
        recover(cfg, a, j, repo)
        floor = load(Path(cfg["witness"]))
        tip = git(repo, "rev-parse", "refs/heads/main")
        record = get_parent(cfg, a, j, tip)
        payload = {
            "format": "ocs.safe-push.checkpoint/1",
            "project": policy["project"],
            "epoch": policy["epoch"],
            "policy": framed(policy),
            "priorFloor": floor["branchFloor"],
            "tip": tip,
            "receipt": framed(record),
        }
        for role in ("guardian", "independent"):
            require(
                authentic(envelopes[role], policy["keys"][role], "trust.checkpoint")
                == {**payload, "role": role},
                "trust.checkpoint",
                "missing independent checkpoint authorization",
            )
        immutable(a / "checkpoints" / (framed(payload) + ".json"), canonical(envelopes))
        replace_pointer(
            Path(cfg["witness"]),
            canonical({**floor, "branchFloor": tip, "receiptDigest": framed(record)}),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="op", required=True)
    p = sub.add_parser("install")
    for name in ("root", "source", "policy", "evidence", "publisher-key"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--observer-key", type=Path, action="append", default=[])
    p.add_argument("--method", type=Path, action="append", default=[])
    p.add_argument("--lean-home", type=Path)
    p.add_argument("--witness", type=Path)
    p.add_argument("--cost-baseline", type=Path)
    p = sub.add_parser("stage")
    p.add_argument("config", type=Path)
    p.add_argument("category", choices=("reviews", "evidence"))
    p.add_argument("candidate")
    p.add_argument("source", type=Path)
    p.add_argument("--target")
    p = sub.add_parser("sign")
    p.add_argument("role", choices=ROLES)
    p.add_argument("key", type=Path)
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p = sub.add_parser("object")
    p.add_argument("config", type=Path)
    p.add_argument("source", type=Path)
    p.add_argument("candidate")
    p = sub.add_parser("rotate")
    p.add_argument("config", type=Path)
    p.add_argument("envelope", type=Path)
    p.add_argument("--new-publisher-key", type=Path)
    p = sub.add_parser("evolution-input")
    p.add_argument("config", type=Path)
    p.add_argument("kind", choices=("subject-or-proof", "method", "observer"))
    p.add_argument("expected")
    p.add_argument("file", type=Path)
    p = sub.add_parser(
        "cost-source",
        help="compare the actually executing incumbent's bytes with a selected Git revision",
    )
    p.add_argument("repository", type=Path)
    p.add_argument("revision")
    sub.add_parser(
        "cost-context",
        help="observe the current process's publicly comparable native execution conditions",
    )
    for command in ("cost-plan", "cost-acquire"):
        p = sub.add_parser(command)
        p.add_argument("config", type=Path)
        p.add_argument("candidate")
        p.add_argument("protocol", type=Path)
        p.add_argument("--incumbent-repo", type=Path)
        if command == "cost-acquire":
            p.add_argument("authorization", type=Path)
    p = sub.add_parser("checkpoint")
    p.add_argument("config", type=Path)
    p.add_argument("envelope", type=Path)
    p = sub.add_parser("alert")
    p.add_argument("config", type=Path)
    p.add_argument("envelope", type=Path)
    p.add_argument("--evidence", type=Path, required=True)
    a = parser.parse_args()
    if a.op == "install":
        print(
            install(
                a.root,
                a.source,
                a.policy,
                a.evidence,
                a.observer_key,
                a.method,
                a.publisher_key,
                a.lean_home,
                a.witness,
                a.cost_baseline,
            )
        )
    elif a.op == "stage":
        print(stage_files(a.config, a.category, a.candidate, a.source, a.target))
    elif a.op == "sign":
        sign_input(a.role, a.key, a.input, a.output)
    elif a.op == "object":
        import_object(a.config, a.source, a.candidate)
    elif a.op == "rotate":
        rotate(a.config, a.envelope, a.new_publisher_key)
    elif a.op == "cost-context":
        from cost_acquisition import execution_context

        context = execution_context()
        print(
            canonical(
                {"execution": context, "executionContextSha256": framed(context)}
            ).decode()
        )
    elif a.op == "cost-source":
        from cost_acquisition import source_identity

        selected = source_identity(a.repository, a.revision)
        print(
            canonical(
                {"source": selected, "incumbentSourceSha256": framed(selected)}
            ).decode()
        )
    elif a.op in ("cost-plan", "cost-acquire"):
        from cost_acquisition import acquire, plan_for

        protocol = load(a.protocol)
        if a.op == "cost-plan":
            cfg, authority, journal, repo, policy = state(a.config)
            with publication_lock(journal):
                cfg, authority, journal, repo, policy = state(a.config)
                result, _, _ = plan_for(
                    cfg,
                    authority,
                    journal,
                    repo,
                    policy,
                    a.candidate,
                    protocol,
                    a.incumbent_repo,
                )
        else:
            result = acquire(
                a.config, a.candidate, protocol, load(a.authorization), a.incumbent_repo
            )
        print(canonical(result).decode())
    elif a.op == "evolution-input":
        cfg, authority, journal, repo, policy = state(a.config)
        with publication_lock(journal):
            state(a.config)
            data = read(a.file, 32 * 1024 * 1024)
            require(
                SHA256.fullmatch(a.expected) and digest(data) == a.expected,
                "trust.evolution",
                "content differs from independently selected evolution input",
                "rejected",
            )
            if a.kind == "subject-or-proof":
                dest = authority / "evolution" / "objects" / a.expected
            elif a.kind == "method":
                dest = authority / "methods" / (a.expected + ".py")
            else:
                public_der(data.decode("ascii"))
                dest = authority / "observers" / (a.expected + ".pem")
            immutable(dest, data)
    elif a.op == "checkpoint":
        checkpoint(a.config, load(a.envelope))
    else:
        cfg, authority, j, repo, policy = state(a.config)
        with publication_lock(j):
            cfg, authority, j, repo, policy = state(a.config)
            recover(cfg, authority, j, repo)
            data = load(a.envelope)
            msg = authentic(data, policy["keys"]["guardian"], "counterexample.custody")
            require(
                msg.get("format") == "ocs.safe-push.counterexample/1"
                and msg.get("project") == policy["project"]
                and msg.get("epoch") == policy["epoch"]
                and isinstance(msg.get("id"), str)
                and NAME.fullmatch(msg["id"])
                and (msg.get("scope") == "all" or OBJECT.fullmatch(msg["scope"]))
                and SHA256.fullmatch(msg["evidence"]),
                "counterexample.binding",
                "invalid counterexample",
            )
            material = read(a.evidence)
            require(
                digest(material) == msg["evidence"],
                "counterexample.material",
                "reproducer digest differs",
            )
            immutable(authority / "counterexamples" / msg["evidence"], material)
            immutable(authority / "alerts" / (msg["id"] + ".json"), canonical(data))


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
