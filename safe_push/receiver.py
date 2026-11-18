#!/usr/bin/env python3
"""Serve a restricted Git receive-pack and recover its durable admission intent."""

import argparse
import contextlib
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import (
    active_holds,
    commit_binding,
    get_parent,
    git,
    prepare,
    readref,
    state,
)
from authority import (
    Decision,
    authentic,
    canonical,
    digest,
    framed,
    fsync_dir,
    immutable,
    load,
    policy_history,
    public_der,
    require,
    signature,
    stamp,
)


@contextlib.contextmanager
def publication_lock(journal):
    path = journal / "publication.lock"
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def selected_receipt(authority, cfg, envelope, chain=None):
    chain = policy_history(authority, cfg["rootDigest"]) if chain is None else chain
    epoch = envelope["payload"]["epoch"]
    require(
        type(epoch) is int and 0 <= epoch < len(chain),
        "audit.epoch",
        "unknown receiver epoch",
    )
    policy = chain[epoch]
    receipt = authentic(envelope, policy["keys"]["publisher"], "audit.publisher")
    require(
        receipt["format"] == "ocs.safe-push.prepared/1"
        and receipt["project"] == cfg["project"]
        and receipt["profile"] == policy["profile"]
        and receipt["policy"] == framed(policy),
        "audit.binding",
        "receipt belongs to another authority",
        "rejected",
    )
    return receipt


def recover(cfg, authority, journal, repo):
    """Only called under the single writer lock, including on boot and before a push."""
    intent_path = journal / "inflight.json"
    if not intent_path.exists():
        return None
    intent = load(intent_path)
    envelope = load(journal / "prepared" / (intent["receipt"] + ".json"))
    require(framed(envelope) == intent["receipt"], "audit.intent", "unbound intent")
    receipt = selected_receipt(authority, cfg, envelope)
    actual = readref(repo)
    if actual == receipt["candidate"]:
        immutable(journal / "committed" / (actual + ".json"), canonical(receipt))
        immutable(journal / "signatures" / (actual + ".json"), canonical(envelope))
        result = "committed"
    elif actual == receipt["parent"]:
        result = "aborted"
    else:
        raise Decision(
            "audit.recovery",
            "actual ref is neither the prepared candidate nor its parent",
        )
    immutable(
        journal / "outcomes" / (intent["tx"] + ".json"),
        canonical(
            {"outcome": result, "receipt": intent["receipt"], "readback": actual}
        ),
    )
    intent_path.unlink()
    fsync_dir(journal)
    return result


def parse_updates(raw, repo):
    require(len(raw) <= 4096, "reference.batch", "oversized ref transaction")
    rows = [s.decode("ascii").split() for s in raw.splitlines()]
    require(all(len(row) == 3 for row in rows), "reference.batch", "invalid ref record")
    main = [x for x in rows if x[2] == "refs/heads/main"]
    require(
        len(main) == 1 and all(x[2] in ("HEAD", "refs/heads/main") for x in rows),
        "reference.batch",
        "receiver only accepts one canonical branch update",
        "rejected",
    )
    if len(rows) != 1:
        require(
            len(rows) == 2
            and git(repo, "symbolic-ref", "HEAD") == "refs/heads/main"
            and all(x[:2] == main[0][:2] for x in rows),
            "reference.batch",
            "unexpected symbolic ref update",
            "rejected",
        )
    return main[0][:2]


def run_hook(config, hook, stage, raw):
    cfg, authority, journal, repo, policy = state(config)
    require(
        os.environ.get("OCS_SAFE_RECEIVER") == str(Path(config).resolve())
        and len(os.environ.get("OCS_SAFE_TX", "")) == 32,
        "reference.writer",
        "ref update did not originate from the enrolled receiver",
    )
    if hook == "reference-transaction" and stage != "prepared":
        return
    old, new = parse_updates(raw, repo)
    binding = commit_binding(repo, old, new)
    tx = os.environ["OCS_SAFE_TX"]
    preflight = journal / "preflight" / (tx + ".json")
    if hook == "reference-transaction":
        envelope = load(preflight)
        receipt = selected_receipt(authority, cfg, envelope)
        require(
            receipt.get("transaction") == tx
            and receipt["epoch"] == policy["epoch"]
            and all(receipt[k] == v for k, v in binding.items())
            and readref(repo) == old,
            "reference.preflight",
            "signed decision does not match the locked Git transaction",
            "rejected",
        )
        require(
            time.time() < receipt["expiresEpoch"],
            "evidence.freshness",
            "decision expired before ref update",
        )
        key = framed(envelope)
        immutable(journal / "prepared" / (key + ".json"), canonical(envelope))
        immutable(journal / "inflight.json", canonical({"tx": tx, "receipt": key}))
        require(
            time.time() < receipt["expiresEpoch"],
            "evidence.freshness",
            "decision expired during durable preparation",
        )
        return
    require(hook == "pre-receive", "reference.hook", "unknown release hook")
    from cost import CostError, finish_cost, start_cost
    from cost_acquisition import reference

    prior = get_parent(cfg, authority, journal, old)
    prior_cost = reference(cfg, authority, journal, policy, prior, executing=True)
    before = start_cost()
    receipt = prepare(config, old, new)
    receipt["transaction"] = tx
    try:
        receipt["receiverCost"] = finish_cost(
            before, policy["receiverCost"], prior_cost
        )
    except CostError as failure:
        observed = {
            "tree": receipt["tree"],
            "parent": old,
            "candidate": new,
            "criterion": failure.criterion,
            "reason": str(failure),
            "observation": failure.observation,
        }
        immutable(
            journal / "cost-observations" / (os.environ["OCS_SAFE_TX"] + ".json"),
            canonical(observed),
        )
        if failure.outcome == "rejected":
            immutable(
                journal / "adverse" / receipt["tree"] / (framed(observed) + ".json"),
                canonical(observed),
            )
        raise
    key = Path(cfg["publishingKeys"]) / (
        digest(public_der(policy["keys"]["publisher"])) + ".key"
    )
    envelope = signature(receipt, key)
    require(
        authentic(envelope, policy["keys"]["publisher"], "audit.publisher") == receipt,
        "audit.publisher",
        "unrecognized publishing key",
    )
    # Git transports pre-receive diagnostics to the contributor. Keep the
    # state-changing decision in the later, locked reference transaction.
    immutable(preflight, canonical(envelope))
    require(
        time.time() < receipt["expiresEpoch"],
        "evidence.freshness",
        "evidence expired before ref update",
    )


def serve(config, service):
    cfg, authority, journal, repo, current_policy = state(config)
    require(
        service in ("git-upload-pack", "git-receive-pack"),
        "reference.service",
        "unsupported Git service",
    )
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(repo),
        "OCS_SAFE_RECEIVER": str(Path(config).resolve()),
        "OCS_SAFE_TX": uuid.uuid4().hex,
    }
    if cfg.get("leanHome"):
        env["SAFE_PUSH_LEAN_HOME"] = cfg["leanHome"]
    if (authority / "broker.json").is_file():
        env["OCS_NATIVE_METHODS_REQUIRED"] = "1"
    if service == "git-upload-pack":
        return subprocess.run(
            ["git-upload-pack", str(repo)], check=False, env=env
        ).returncode
    with publication_lock(journal):
        recover(cfg, authority, journal, repo)
        before = readref(repo)
        immutable(
            journal / "requests" / (env["OCS_SAFE_TX"] + ".json"),
            canonical(
                {"project": cfg["project"], "started": stamp(), "before": before}
            ),
        )
        try:
            child = subprocess.Popen(
                ["git-receive-pack", str(repo)],
                env=env,
                start_new_session=os.name == "posix",
            )
            try:
                status = child.wait(timeout=current_policy["receiveTimeoutSeconds"])
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
                child.wait()
                raise Decision(
                    "reference.timeout", "bounded receiver duration exceeded"
                )
        finally:
            recover(cfg, authority, journal, repo)
            immutable(
                journal / "readbacks" / (env["OCS_SAFE_TX"] + ".json"),
                canonical(
                    {"before": before, "after": readref(repo), "finished": stamp()}
                ),
            )
        return status


def chain_status(config, require_current=False):
    cfg, authority, journal, repo, policy = state(config)
    with publication_lock(journal):
        cfg, authority, journal, repo, policy = state(config)
        recover(cfg, authority, journal, repo)
        if require_current:
            require(
                not policy["requiredOpen"],
                "scope.open",
                "unresolved mandatory obligations: "
                + ", ".join(policy["requiredOpen"]),
            )
            if policy["profile"] == "ocs-release/1":
                require(
                    policy["receiverCost"] is not None,
                    "verification.cost.registration",
                    "no qualified receiver cost baseline",
                )
        tip = readref(repo)
        current, downstream = tip, None
        chain = policy_history(authority, cfg["rootDigest"])
        records = []
        length = 0
        while current != cfg["genesis"]:
            receipt = selected_receipt(
                authority,
                cfg,
                load(journal / "signatures" / (current + ".json")),
                chain,
            )
            require(
                receipt == load(journal / "committed" / (current + ".json"))
                and receipt["candidate"] == current,
                "audit.chain",
                "receipt index mismatch",
            )
            binding = commit_binding(repo, receipt["parent"], current)
            require(
                receipt["tree"] == binding["tree"],
                "audit.chain",
                "Git object differs from receipt",
            )
            records.append(receipt)
            if downstream is not None:
                require(
                    downstream == framed(receipt),
                    "audit.chain",
                    "broken historical link",
                )
            downstream, current = receipt["previousReceipt"], receipt["parent"]
            length += 1
        anchor = get_parent(cfg, authority, journal, current)
        require(
            downstream is None or downstream == framed(anchor),
            "audit.chain",
            "genesis mismatch",
        )
        if require_current:
            from proof import REQUIRED_FACTS, replay_certificate

            prev = anchor
            if (
                not records
                and anchor.get("receiverCost") is None
                and isinstance(policy["receiverCost"], dict)
                and "ceilings" in policy["receiverCost"]
            ):
                from cost_acquisition import reference

                initial = reference(cfg, authority, journal, policy, anchor)
                require(
                    framed(initial) == policy["receiverCost"]["baselineEvidenceSha256"],
                    "verification.cost.baseline",
                    "supplemental initial baseline did not verify",
                )
            for receipt in reversed(records):
                if policy["profile"] == "ocs-release/1":
                    require(
                        receipt.get("receiverCost", {}).get("status") == "accepted",
                        "verification.cost",
                        "unqualified receiver performance",
                    )
                if receipt["candidate"] == tip:
                    prev = receipt
                    continue
                checked = replay_certificate(
                    receipt["verifiedProof"],
                    previous_claims=prev["claims"],
                    current_claims=receipt["claims"],
                    previous_metrics=prev["metrics"],
                    current_metrics=receipt["metrics"],
                    parent=receipt["parent"],
                    actual_parent=receipt["parent"],
                    candidate=receipt["candidate"],
                    tree=receipt["tree"],
                    facts={f: True for f in REQUIRED_FACTS},
                )
                require(
                    checked.get("verdict") == "accepted",
                    "audit.proof",
                    "refused publication certificate",
                )
                prev = receipt
            require(
                not active_holds(
                    authority,
                    cfg,
                    repo,
                    {
                        "parent": prev.get("parent", tip),
                        "candidate": tip,
                        "tree": prev["tree"],
                    },
                    prev.get("resolvedCounterexamples", {}),
                ),
                "counterexample.open",
                "active alert",
            )
            for directory in (
                authority / "adverse",
                journal / "adverse",
                authority / "review-adverse",
            ):
                require(
                    not any((directory / prev["tree"]).glob("*.json")),
                    "audit.adverse",
                    "contrary registered evidence for the current published tree",
                )
            if records:
                reconstructed = prepare(config, prev["parent"], tip, published=prev)
                require(
                    all(
                        prev[k] == v
                        for k, v in reconstructed.items()
                        if k != "preparedAt"
                    ),
                    "audit.evidence",
                    "current protected source, review, evidence or proof differs from the signed receipt",
                )
            else:
                from admission import observe

                for name in policy["targets"]:
                    observed = observe(
                        authority,
                        repo,
                        policy,
                        name,
                        authority / "bootstrap" / name,
                        prev["subject"],
                    )
                    require(
                        observed["reportSha256"] == prev["targetReports"][name],
                        "audit.evidence",
                        "bootstrap measurements are no longer available or valid",
                    )
            require(
                readref(repo) == tip and time.time() < prev["expiresEpoch"],
                "audit.expired",
                "ref changed or evidence expired",
            )
        return {
            "project": cfg["project"],
            "profile": policy["profile"],
            "epoch": policy["epoch"],
            "tip": tip,
            "genesis": current,
            "certifiedTransitions": length,
            "status": "verified",
        }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "action",
        choices=("serve", "socket", "hook", "context", "scope", "audit", "consume"),
    )
    p.add_argument("config", type=Path)
    p.add_argument("args", nargs="*")
    a = p.parse_args()
    try:
        if a.action == "socket":
            # Read exactly one service line without consuming Git protocol bytes.
            header = bytearray()
            while len(header) < 32:
                ch = os.read(0, 1)
                if ch in (b"\n", b""):
                    break
                header.extend(ch)
            return serve(a.config, header.decode("ascii"))
        if a.action == "serve":
            return serve(a.config, a.args[0])
        if a.action == "hook":
            raw = sys.stdin.buffer.read(4097)
            try:
                run_hook(a.config, a.args[0], a.args[1] if len(a.args) > 1 else "", raw)
            except Exception as failure:
                if (
                    os.environ.get("OCS_SAFE_RECEIVER") == str(a.config.resolve())
                    and len(os.environ.get("OCS_SAFE_TX", "")) == 32
                ):
                    cfg = load(a.config)
                    detail = {
                        "updates": raw.decode("ascii", errors="replace")[:1024],
                        "time": stamp(),
                        "phase": a.args,
                        "outcome": getattr(failure, "outcome", "undetermined"),
                        "criterion": getattr(failure, "criterion", "scope-or-evidence"),
                        "reason": str(failure)[:900],
                    }
                    if getattr(failure, "certificate", None) is not None:
                        detail["refutation"] = failure.certificate
                    immutable(
                        Path(cfg["journal"])
                        / "refusals"
                        / (os.environ["OCS_SAFE_TX"] + ".json"),
                        canonical(detail),
                    )
                raise
        elif a.action in ("context", "scope"):
            print(canonical(prepare(a.config, *a.args, want_context=a.action)).decode())
        else:
            print(canonical(chain_status(a.config, a.action == "consume")).decode())
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        ArithmeticError,
        subprocess.SubprocessError,
    ) as e:
        outcome = getattr(e, "outcome", "undetermined")
        print("Safe Push " + outcome + ": " + str(e)[:900], file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
