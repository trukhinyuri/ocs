"""One-shot enrollment of the first measured pre-CAS workload. Also an isolated old-purpose checker."""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from decimal import Decimal
from itertools import pairwise
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROLES = ("domain", "independent", "guardian")
BOUNDARY = "independent-prepare-entry-to-verified-receipt-before-sign-and-ref-cas/1"
UNITS = {
    "wallNs": "nanoseconds",
    "selfCpuNs": "nanoseconds",
    "waitedChildCpuUs": "microseconds",
    "selfPeakRssBytes": "bytes",
    "largestWaitedChildPeakRssBytes": "bytes",
    "inputBlocks": "kernel block-input operations",
    "outputBlocks": "kernel block-output operations",
}
PEAKS = {"selfPeakRssBytes", "largestWaitedChildPeakRssBytes"}
LABELS = {
    "costProtocol",
    "costPlan",
    "costGenesis",
    "costReceipt",
    "costObservation",
    "costOutcome",
    "costReviews",
    "costSource",
}
SOURCE_PATHS = tuple(
    "safe_push/" + s
    for s in (
        "admission.py",
        "authority.py",
        "cost.py",
        "cost_acquisition.py",
        "evolution.py",
        "method_worker.py",
        "object_view.py",
        "operator_cli.py",
        "proof.py",
        "qualification.py",
        "receiver.py",
        "scope.py",
        "Admission.lean",
        "coverage.json",
        "metrics.json",
    )
) + (
    "assurance/wire/toolchain.json",
    "assurance/structure.py",
    "assurance/interaction/lean_tools.py",
)
HEX = re.compile(r"[0-9a-f]{64}\Z")
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def canonical(x):
    return json.dumps(
        x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mark(x):
    return sha(canonical(x))


def pairs(entries):
    result = {}
    for k, v in entries:
        check(k not in result, "duplicate field")
        result[k] = v
    return result


def decode(data):
    return json.loads(
        data,
        object_pairs_hook=pairs,
        parse_constant=lambda _: check(False, "nonfinite value"),
    )


def check(ok, reason):
    if not ok:
        raise ValueError("verification.cost.acquisition: " + reason)


def as_time(stamp):
    value = datetime.fromisoformat(stamp)
    check(value.utcoffset() is not None, "missing UTC offset")
    return value.timestamp()


def auth(envelope, pem):
    """The old-purpose checker can replay these Ed25519 signatures without importing candidate code."""
    check(
        type(envelope) is dict and set(envelope) == {"payload", "signature"},
        "malformed signed envelope",
    )
    sig = base64.b64decode(envelope["signature"], validate=True)
    check(len(sig) == 64, "invalid Ed25519 signature length")
    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)
        (temp / "message").write_bytes(canonical(envelope["payload"]))
        (temp / "key").write_text(pem)
        (temp / "signature").write_bytes(sig)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(temp / "key"),
                "-sigfile",
                str(temp / "signature"),
                "-in",
                str(temp / "message"),
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
    check(result.returncode == 0, "incorrect custody signature")
    return envelope["payload"]


def protocol_valid(protocol):
    fields = {
        "format",
        "incumbentRevision",
        "incumbentSourceSha256",
        "platformSha256",
        "conditions",
        "ceilings",
    }
    check(
        type(protocol) is dict
        and set(protocol) in (fields, fields | {"executionContextSha256"})
        and (
            "executionContextSha256" not in protocol
            or (
                type(protocol["executionContextSha256"]) is str
                and HEX.fullmatch(protocol["executionContextSha256"])
            )
        )
        and protocol["format"] == "ocs.safe-push.cost-protocol/1"
        and type(protocol["incumbentRevision"]) is str
        and OID.fullmatch(protocol["incumbentRevision"])
        and all(
            type(protocol[k]) is str and HEX.fullmatch(protocol[k])
            for k in ("incumbentSourceSha256", "platformSha256")
        ),
        "unbound protocol, source or platform",
    )
    conditions = protocol["conditions"]
    check(
        type(conditions) is dict
        and set(conditions)
        == {
            "target",
            "workload",
            "cache",
            "concurrency",
            "observer",
            "uncertainty",
            "exclusions",
        }
        and all(type(v) is str and v.strip() for v in conditions.values()),
        "predeclare the target, workload, cache, concurrency, observer, uncertainty and exclusions",
    )
    ceiling = protocol["ceilings"]
    check(
        ceiling == "first-eligible-observation"
        or (
            type(ceiling) is dict
            and set(ceiling) == set(UNITS)
            and all(type(v) is int and v >= 0 for v in ceiling.values())
        ),
        "unregistered ceiling selection",
    )


def registration(old, protocol, baseline):
    ceiling = protocol["ceilings"]
    return {
        "format": "ocs.safe-push.verifier-cost-policy/1",
        "profile": old["profile"],
        "workloadSha256": mark(protocol),
        "platformSha256": protocol["platformSha256"],
        "baselineEvidenceSha256": mark(baseline),
        "ceilings": baseline["observed"]
        if ceiling == "first-eligible-observation"
        else ceiling,
    }


def execution_context():
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    interfaces = sorted(
        line.split(":", 1)[0].strip()
        for line in Path("/proc/net/dev").read_text().splitlines()
        if ":" in line
    )
    with Path(sys.executable).resolve().open("rb") as stream:
        executable = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "groups": sorted(os.getgroups()),
        "noNewPrivileges": int(fields["NoNewPrivs"]),
        "effectiveCaps": int(fields["CapEff"], 16),
        "boundingCaps": int(fields["CapBnd"], 16),
        "seccomp": int(fields["Seccomp"]),
        "interfaces": interfaces,
        "interpreterSha256": executable,
    }


def context_valid(profile, protocol, context, uid):
    expected = protocol.get("executionContextSha256")
    if expected is not None:
        check(
            mark(context) == expected,
            "wrong independently selected native execution context",
        )
    if profile == "ocs-release/1":
        check(
            expected is not None
            and type(uid) is int
            and uid > 0
            and context["uid"] == uid
            and context["noNewPrivileges"] == 1
            and context["boundingCaps"] == context["effectiveCaps"] == 0
            and context["interfaces"] == ["lo"],
            "release workload lacks the enrolled native receiver's confinement",
        )


def verify_witness(plan, genesis, receipt, source):
    import zlib

    bound = receipt["verifiedProof"]
    witness = bound["witness"]
    size = witness["uncompressedBytes"]
    check(
        witness["format"] == "ocs.safe-push-packet/1"
        and witness["encoding"] == "zlib+base64"
        and type(size) is int
        and 0 < size <= 16 * 1024 * 1024
        and len(witness["data"]) <= 2 * size + 128,
        "invalid finite witness framing",
    )
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(witness["data"], validate=True), size + 1)
    check(
        len(raw) == size
        and decoder.eof
        and not decoder.unused_data
        and not decoder.unconsumed_tail
        and sha(raw) == bound["inputSha256"],
        "altered ground witness",
    )
    flags = (
        "singleParent",
        "inventory",
        "qualification",
        "domainReview",
        "independentReview",
        "fresh",
        "noCounterexample",
        "policyContinuity",
        "priorEvidence",
    )
    packet = {
        "parent": plan["parent"],
        "actualParent": plan["parent"],
        "candidate": plan["candidate"],
        "tree": plan["tree"],
        "facts": {k: True for k in flags},
        "previousClaims": genesis["claims"],
        "currentClaims": receipt["claims"],
    }
    for name, ledger in (("previousMetrics", genesis), ("currentMetrics", receipt)):
        rows = {}
        for key, metric in ledger["metrics"].items():
            value = metric["value"]
            check(
                type(value) is str and len(value) <= 1024,
                "metric exceeds the enrolled exact-decimal bound",
            )
            number = Decimal(value)
            check(
                number.is_finite()
                and max(abs(number.adjusted()), abs(number.as_tuple().exponent))
                <= 1024,
                "unbounded metric in finite witness",
            )
            n, d = number.as_integer_ratio()
            rows[key] = {
                "direction": metric["direction"],
                "condition": metric["condition"],
                "numerator": str(n),
                "denominator": str(d),
            }
        packet[name] = rows
    check(
        raw == canonical(packet),
        "ground proof packet lost an inherited or proposed input",
    )
    kernel = bound["kernel"]
    check(
        kernel["semanticsSha256"] == source["files"]["safe_push/Admission.lean"]
        and kernel["toolchainManifestSha256"]
        == source["files"]["assurance/wire/toolchain.json"]
        and kernel["independentKernel"] == "nanoda"
        and HEX.fullmatch(kernel["proofSha256"])
        and "SafePushCandidate.checked" in kernel["theorems"]
        and "SafePushCandidate.consequence" in kernel["theorems"],
        "unbound incumbent decision semantics, proof kernel or concrete result",
    )


def replay_prepared(genesis, receipt):
    from proof import REQUIRED_FACTS, replay_certificate

    result = replay_certificate(
        receipt["verifiedProof"],
        previous_claims=genesis["claims"],
        current_claims=receipt["claims"],
        previous_metrics=genesis["metrics"],
        current_metrics=receipt["metrics"],
        parent=receipt["parent"],
        actual_parent=receipt["parent"],
        candidate=receipt["candidate"],
        tree=receipt["tree"],
        facts={k: True for k in REQUIRED_FACTS},
    )
    check(
        result["verdict"] == "accepted",
        "independent kernel refused the archived successful decision",
    )


def verify_packet(old, new, material):
    """Independently reconstruct trial ordering, authenticated source/results, seven cells and their registration."""
    check(set(material) == LABELS, "incomplete acquisition artifacts")
    proto = material["costProtocol"]
    protocol_valid(proto)
    approval = material["costPlan"]
    plan = approval["payload"]
    genesis = material["costGenesis"]
    receipt = material["costReceipt"]
    baseline = material["costObservation"]
    observation = auth(material["costOutcome"], old["keys"]["publisher"])
    context_valid(
        old["profile"], proto, observation["executionContext"], plan["publisherUid"]
    )
    source = material["costSource"]
    reviews = material["costReviews"]
    check(
        old["receiverCost"] is None
        and not old["requiredOpen"]
        and new["epoch"] == old["epoch"] + 1
        and all(new[k] == old[k] for k in ("project", "profile", "genesis")),
        "only a completed non-cost scope can elect its first genuine baseline",
    )
    check(
        plan["format"] == "ocs.safe-push.cost-plan/1"
        and plan["profile"] == old["profile"]
        and plan["project"] == old["project"]
        and plan["epoch"] == old["epoch"]
        and plan["policySha256"] == mark(old)
        and plan["parent"] == old["genesis"]
        and plan["parent"] != plan["candidate"]
        and all(
            type(plan[k]) is str and OID.fullmatch(plan[k])
            for k in ("parent", "candidate", "tree")
        )
        and len({len(plan[k]) for k in ("parent", "candidate", "tree")}) == 1,
        "trial belongs to another policy, epoch or Git transition",
    )
    check(
        set(approval) == {"payload", "signatures"}
        and set(approval["signatures"]) == set(ROLES),
        "missing preregistration quorum",
    )
    for role in ROLES:
        check(
            auth(approval["signatures"][role], old["keys"][role])
            == {**plan, "role": role},
            "misbound preregistration role",
        )
    check(
        source["revision"] == proto["incumbentRevision"]
        and mark(source) == proto["incumbentSourceSha256"]
        and set(source["files"]) == set(SOURCE_PATHS)
        and all(HEX.fullmatch(v) for v in source["files"].values())
        and plan["incumbentSourceSha256"] == mark(source)
        and plan["workloadSha256"] == mark(proto)
        and plan["platformSha256"] == proto["platformSha256"]
        and plan["genesisReceiptSha256"] == mark(genesis),
        "changed externally selected source, platform, protocol or genesis",
    )
    check(
        genesis["format"] == "ocs.safe-push.genesis/1"
        and genesis["profile"] == old["profile"]
        and genesis["candidate"] == old["genesis"]
        and genesis["project"] == old["project"]
        and genesis["policy"] == plan["rootSha256"]
        and genesis.get("receiverCost") is None,
        "incorrect original genesis ledger",
    )
    check(
        observation["format"] == "ocs.safe-push.cost-outcome/1"
        and observation["status"] == "accepted"
        and observation["planSha256"] == mark(approval)
        and observation["receiptSha256"] == mark(receipt)
        and observation["observationSha256"] == mark(baseline)
        and observation["reviewsSha256"] == mark(reviews)
        and observation["slot"]
        == mark({"genesis": mark(genesis), "tree": plan["tree"]})
        and set(observation["readbacks"]) == {"before", "after"}
        and all(v == plan["parent"] for v in observation["readbacks"].values()),
        "observed execution does not bind the complete prepared result and unchanged ref",
    )
    issued, started, finished, expires = map(
        as_time,
        (
            plan["issuedAt"],
            observation["startedAt"],
            observation["finishedAt"],
            plan["expiresAt"],
        ),
    )
    check(
        issued <= started <= finished < expires
        and expires - issued <= old["lifetimeSeconds"]
        and started
        <= as_time(receipt["preparedAt"])
        <= finished
        < receipt["expiresEpoch"],
        "invalid original observation interval",
    )
    check(
        receipt["format"] == "ocs.safe-push.prepared/1"
        and receipt["profile"] == old["profile"]
        and receipt["project"] == old["project"]
        and receipt["policy"] == mark(old)
        and receipt["epoch"] == old["epoch"]
        and receipt["previousReceipt"] == mark(genesis)
        and receipt["sourceSha256"] == plan["candidateSourceSha256"]
        and all(receipt[k] == plan[k] for k in ("parent", "candidate", "tree"))
        and receipt["verifiedProof"]["verdict"] == "accepted"
        and receipt["verifiedProof"]["status"] == "pass"
        and receipt["verifiedProof"]["actualParent"] == plan["parent"]
        and all(
            receipt["verifiedProof"][k] == plan[k]
            for k in ("parent", "candidate", "tree")
        ),
        "earlier PREPARE did not actually certify this exact transition",
    )
    verify_witness(plan, genesis, receipt, source)
    for k, v in genesis["claims"].items():
        check(receipt["claims"].get(k) == v, "previous accepted claim changed")
    for k, v in genesis["metrics"].items():
        nxt = receipt["metrics"][k]
        check(
            nxt["direction"] == v["direction"]
            and nxt["condition"] == v["condition"]
            and v["direction"] in ("min", "max"),
            "metric scope changed",
        )
        a, b = Decimal(v["value"]), Decimal(nxt["value"])
        check(
            a.is_finite()
            and b.is_finite()
            and (b <= a if v["direction"] == "min" else b >= a),
            "registered metric regressed",
        )
    inventory = reviews["inventory"]
    check(
        mark(inventory) == receipt["evidenceManifest"]["reviewBundle"],
        "review evidence inventory changed",
    )
    for role, encoded in reviews["signedBytes"].items():
        encoded_bytes = base64.b64decode(encoded, validate=True)
        check(
            sha(encoded_bytes) == inventory[role + ".json"]
            and canonical(decode(encoded_bytes)) == canonical(reviews[role]),
            "signed raw review evidence changed",
        )
    needed = {"domain", "independent"}
    if receipt["evidenceManifest"]["guardian"] is not None:
        needed.add("guardian")
    if receipt["evidenceManifest"]["remediations"] is not None:
        needed.add("resolutions")
    check(
        set(reviews["signedBytes"]) == needed,
        "missing original role or scoped remediation artifact",
    )
    for role in ("domain", "independent"):
        signed = auth(reviews[role], old["keys"][role])
        check(
            signed["format"] == "ocs.safe-push.review/1"
            and signed["role"] == role
            and mark(signed) == receipt["reviews"][role]
            and all(
                signed["context"][k] == receipt[k]
                for k in (
                    "project",
                    "profile",
                    "epoch",
                    "policy",
                    "parent",
                    "candidate",
                    "tree",
                    "sourceSha256",
                    "changeSha256",
                    "targetReports",
                )
            )
            and as_time(signed["issuedAt"]) <= finished < as_time(signed["expiresAt"]),
            "missing actual signed review",
        )
    guardian = receipt["evidenceManifest"]["guardian"]
    if receipt["evidenceManifest"]["remediations"] is not None:
        resolutions = reviews["resolutions"]
        inherited = genesis.get("resolvedCounterexamples", {})
        newly_resolved = {
            k: v
            for k, v in receipt["resolvedCounterexamples"].items()
            if inherited.get(k) != v
        }
        check(
            set(resolutions) == set(newly_resolved),
            "incomplete scoped remediation history",
        )
        for name, resolution in resolutions.items():
            regression = resolution["regressionEvidence"]
            check(
                HEX.fullmatch(regression)
                and inventory.get("findings/" + regression + ".json") == regression
                and resolution["replay"] == "remediation/" + name
                and resolution["replay"]
                in receipt["evidenceManifest"]["portableReplays"],
                "unbound original regression or incumbent replay",
            )
            binding = {
                "format": "ocs.safe-push.remediation/1",
                "context": reviews["domain"]["payload"]["context"],
                "id": name,
                "alert": newly_resolved[name],
                "regressionEvidence": regression,
                "replay": resolution["replay"],
            }
            for signer in ROLES:
                check(
                    auth(resolution[signer], old["keys"][signer])
                    == {**binding, "role": signer},
                    "unverified remediation role",
                )
    if guardian is not None:
        g = auth(reviews["guardian"], old["keys"]["guardian"])
        check(
            g["format"] == "ocs.safe-push.guardian/1"
            and g["context"] == reviews["domain"]["payload"]["context"]
            and g["proofs"] == mark(receipt["evidenceManifest"]["portableReplays"]),
            "missing policy transition evidence",
        )
    check(
        baseline["format"] == "ocs.safe-push.verifier-cost/1"
        and baseline["status"] == "baseline-observation"
        and baseline["boundary"] == BOUNDARY
        and baseline["acquisition"]
        == {
            "parent": plan["parent"],
            "candidate": plan["candidate"],
            "verifiedReceiptSha256": mark(receipt),
            "planSha256": mark(approval),
            "genesisReceiptSha256": mark(genesis),
        }
        and baseline["condition"]
        == mark(
            {
                "platformSha256": proto["platformSha256"],
                "workloadSha256": mark(proto),
                "boundary": BOUNDARY,
                "units": UNITS,
            }
        )
        and baseline["platformSha256"] == proto["platformSha256"]
        and baseline["workloadSha256"] == mark(proto),
        "incorrect original collector boundary, acquisition or condition",
    )
    provenance = baseline["provenance"]
    first, last = provenance["first"], provenance["last"]
    check(
        provenance["units"] == UNITS
        and provenance["platform"]["collectorSha256"]
        == source["files"]["safe_push/cost.py"]
        and mark(provenance["platform"])
        == baseline["platformSha256"]
        == provenance["finalPlatformSha256"]
        and "unavailable" not in provenance["platform"]
        and first["pid"] == last["pid"]
        and type(first["pid"]) is int
        and first["pid"] > 0,
        "different or incomplete observer",
    )
    for sample in (first, last):
        check(
            sample["unavailable"] is None
            and sample["inFlightChildren"] == 0
            and set(sample["counters"]) == set(UNITS)
            and all(type(v) is int and v >= 0 for v in sample["counters"].values()),
            "incomplete authenticated raw counters",
        )
    measured = {}
    for k in UNITS:
        a, b = first["counters"][k], last["counters"][k]
        check(b >= a, "nonmonotonic raw counter")
        measured[k] = b if k in PEAKS else b - a
    check(
        measured == baseline["observed"]
        and all(type(v) is int for v in baseline["observed"].values()),
        "reported cells do not equal the raw samples",
    )
    check(
        new["receiverCost"] == registration(old, proto, baseline)
        and all(measured[k] <= new["receiverCost"]["ceilings"][k] for k in measured),
        "wrong scope, baseline or exceeded preregistered limit",
    )
    return baseline


def method_main():
    """Isolated incumbent method. It receives only mounted data and the selected protected code."""
    q = decode(sys.stdin.buffer.read())
    context = q["context"]
    raw = Path(q["artifact"]).read_bytes()
    artifact = decode(raw)
    ok = False
    try:
        evidence = Path(q["evidence"])
        policies = decode((evidence / "policies.json").read_bytes())
        subjects = decode((evidence / "subjects.json").read_bytes())
        new = subjects["new"]
        check(
            sha(raw) == context["artifactSha256"]
            and artifact["format"] == "ocs.safe-push.evolution-proof/1"
            and artifact["scopeSha256"] == context["scopeSha256"]
            and artifact["subjects"] == context["subjects"]
            and artifact["purpose"] == context["purpose"]
            and context["purpose"] == "evolution/receiver-cost"
            and context["policyScope"] == "policy/receiverCost"
            and context["old"] == mark(policies["old"])
            and context["new"] == mark(policies["new"])
            and context["subjects"] == {k: mark(v) for k, v in subjects.items()},
            "wrong incumbent purpose or subjects",
        )
        material = {}
        for k in LABELS:
            b = (evidence / "new" / k).read_bytes()
            check(
                new["artifacts"][k] == sha(b), "changed archived acquisition artifact"
            )
            material[k] = decode(b)
        baseline = verify_packet(policies["old"], policies["new"], material)
        check(
            artifact["body"]
            == {
                "positiveReceiptSha256": mark(material["costReceipt"]),
                "observed": baseline["observed"],
                "registrationSha256": mark(policies["new"]["receiverCost"]),
            },
            "invalid proof of registered observed values",
        )
        ok = True
    except (
        KeyError,
        ValueError,
        TypeError,
        ArithmeticError,
        OSError,
        subprocess.SubprocessError,
    ):
        pass
    print(
        json.dumps(
            {
                "status": "accepted" if ok else "refused",
                "contextSha256": mark(context),
                "artifactSha256": sha(raw),
            }
        )
    )


def source_identity(repository, revision):
    """Match the actually loaded receiver and collector to bytes in an independently selected Git revision."""
    from admission import git
    from authority import read

    check(
        type(revision) is str
        and OID.fullmatch(revision)
        and git(repository, "cat-file", "-t", revision) == "commit",
        "missing independently selected incumbent Git commit",
    )
    files = {}
    for relative in SOURCE_PATHS:
        object_id = git(repository, "rev-parse", revision + ":" + relative)
        raw = subprocess.check_output(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "safe.directory=" + str(Path(repository).resolve()),
                "-C",
                str(repository),
                "cat-file",
                "blob",
                object_id,
            ],
            timeout=15,
            env={
                "PATH": os.defpath,
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
        )
        installed = read(HERE.parent / relative, 4 * 1024 * 1024)
        check(
            installed == raw,
            "installed source differs from elected commit: " + relative,
        )
        files[relative] = sha(installed)
    return {
        "format": "ocs.safe-push.cost-source/1",
        "revision": revision,
        "files": files,
    }


def plan_for(cfg, a, j, repo, old, candidate, protocol, source_repo):
    from admission import commit_binding, get_parent, readref
    from scope import inventory, subject

    protocol_valid(protocol)
    check(
        old["receiverCost"] is None
        and readref(repo) == old["genesis"] == cfg["genesis"],
        "first-cost acquisition requires the original genesis and an unregistered operating cost",
    )
    bind = commit_binding(repo, cfg["genesis"], candidate)
    seed = get_parent(cfg, a, j, cfg["genesis"])
    check(
        seed.get("receiverCost") is None and mark(seed) == cfg["genesisDigest"],
        "genesis already has a measured baseline",
    )
    src = source_identity(source_repo or repo, protocol["incumbentRevision"])
    check(
        mark(src) == protocol["incumbentSourceSha256"],
        "incumbent source not elected by the workload protocol",
    )
    ident = subject(repo, candidate, inventory(repo, candidate))
    broker = a / "broker.json"
    from authority import load

    publisher_uid = load(broker)["publisherUid"] if broker.is_file() else None
    if old["profile"] == "ocs-release/1":
        check(
            type(publisher_uid) is int and publisher_uid > 0,
            "full operating trial requires independent native evaluator custody",
        )
        check(
            "executionContextSha256" in protocol,
            "register the actual protected native receiver context",
        )
    plan = {
        "format": "ocs.safe-push.cost-plan/1",
        "project": old["project"],
        "profile": old["profile"],
        "rootSha256": cfg["rootDigest"],
        "policySha256": mark(old),
        "epoch": old["epoch"],
        **bind,
        "genesisReceiptSha256": mark(seed),
        "candidateSourceSha256": ident["treeSha256"],
        "workloadSha256": mark(protocol),
        "platformSha256": protocol["platformSha256"],
        "incumbentSourceSha256": mark(src),
        "publisherUid": publisher_uid,
    }
    return plan, seed, src


def store_blob(home, label, data):
    from authority import immutable

    check(type(data) is dict, "malformed " + label + " acquisition material")
    value = canonical(data)
    key = sha(value)
    immutable(home / "objects" / key, value)
    return key


def result_key(cfg, old):
    from authority import public_der

    return Path(cfg["publishingKeys"]) / (
        sha(public_der(old["keys"]["publisher"])) + ".key"
    )


def measure_worker(config, parent, candidate, workload, challenge):
    """Only the incumbent pre-CAS module runs in this fresh process. The calling custodian owns the lock."""
    import secrets

    from admission import commit_binding, get_parent, prepare, readref, state
    from authority import immutable, load, stamp
    from cost import baseline_cost, observation, start_cost

    cfg, a, j, repo, old = state(config)
    seed = get_parent(cfg, a, j, parent)
    binding = commit_binding(repo, parent, candidate)
    check(
        mark(seed) == cfg["genesisDigest"] and parent == cfg["genesis"],
        "measurement worker is not at the original genesis",
    )
    slot = mark({"genesis": mark(seed), "tree": binding["tree"]})
    home = j / "cost-acquisitions" / cfg["genesisDigest"]
    attempt = home / "attempts" / slot
    reserved = load(attempt / "started.json")
    approval = load(home / "objects" / reserved["planSha256"])
    plan = approval["payload"]
    check(
        mark(approval) == reserved["planSha256"]
        and len(challenge) == 32
        and sha(challenge) == reserved["workerChallengeSha256"]
        and plan["workloadSha256"] == workload
        and plan["policySha256"] == mark(old)
        and all(plan[k] == v for k, v in binding.items())
        and not (attempt / "outcome.json").exists()
        and not (home / "first-positive.json").exists(),
        "unreserved, spent or substituted private measurement",
    )
    # One physical execution per durable intent, including a direct invocation of this worker.
    immutable(
        attempt / "worker-started.json",
        canonical({"pid": os.getpid(), "nonce": secrets.token_hex(16), "slot": slot}),
    )
    before = readref(repo)
    started = stamp()
    receipt = None
    token = None
    context = None
    try:
        context = execution_context()
        context_valid(
            old["profile"], load(home / "protocol.json"), context, plan["publisherUid"]
        )
        token = start_cost()
        receipt = prepare(config, parent, candidate)
        measured = baseline_cost(token, workload)
        row = {"status": "accepted", "prepared": receipt, "measurement": measured}
    except (
        ArithmeticError,
        ValueError,
        OSError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        row = {
            "status": getattr(error, "outcome", "undetermined"),
            "criterion": getattr(error, "criterion", "verification.cost.acquisition"),
            "reason": str(error)[:900],
            "prepared": receipt,
            "refutation": getattr(error, "certificate", None),
            "diagnostic": getattr(error, "observation", None),
        }
        if token is not None and row["diagnostic"] is None:
            try:
                row["diagnostic"] = observation(token, workload)
            except (ValueError, OSError, ArithmeticError) as issue:
                row["diagnostic"] = getattr(issue, "observation", None)
    return {
        **row,
        "startedAt": started,
        "finishedAt": stamp(),
        "readbacks": {"before": before, "after": readref(repo)},
        "executionContext": context,
    }


def _measured(config, plan, workload, timeout, lean_home, challenge):
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if lean_home:
        env["SAFE_PUSH_LEAN_HOME"] = lean_home
    if plan["publisherUid"] is not None:
        env["OCS_NATIVE_METHODS_REQUIRED"] = "1"
    with tempfile.TemporaryFile() as out:
        p = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--measurement",
                str(config),
                plan["parent"],
                plan["candidate"],
                workload,
            ],
            env=env,
            input=challenge,
            stdout=out,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        out.seek(0)
        raw = out.read(32 * 1024 * 1024 + 1)
    check(
        p.returncode == 0 and len(raw) <= 32 * 1024 * 1024,
        "incumbent measurement process did not return an audited result",
    )
    return decode(raw)


def acquire(config, candidate, protocol, approval, source_repo=None):
    from admission import bundle_inventory, readref, state
    from authority import Decision, immutable, load, read, signature, stamp
    from receiver import publication_lock, recover

    _, _, journal, _, _ = state(config)
    with publication_lock(journal):
        cfg, a, j, repo, old = state(config)
        recover(cfg, a, j, repo)
        plan, seed, src = plan_for(
            cfg, a, j, repo, old, candidate, protocol, source_repo
        )
        payload = approval["payload"]
        check(
            set(payload) == set(plan) | {"issuedAt", "expiresAt"}
            and all(payload[k] == v for k, v in plan.items())
            and set(approval) == {"payload", "signatures"}
            and set(approval["signatures"]) == set(ROLES),
            "misbound trial election",
        )
        for role in ROLES:
            check(
                auth(approval["signatures"][role], old["keys"][role])
                == {**payload, "role": role},
                "invalid old trial election",
            )
        now = stamp()
        check(
            as_time(payload["issuedAt"]) <= as_time(now) < as_time(payload["expiresAt"])
            and as_time(payload["expiresAt"]) - as_time(payload["issuedAt"])
            <= old["lifetimeSeconds"],
            "expired/future preregistration",
        )
        check(
            plan["publisherUid"] is None or os.geteuid() == plan["publisherUid"],
            "run acquisition as the elected native publisher",
        )
        home = j / "cost-acquisitions" / cfg["genesisDigest"]
        slot = mark({"genesis": mark(seed), "tree": plan["tree"]})
        attempts = home / "attempts"
        reserve = attempts / slot / "started.json"
        outcome = attempts / slot / "outcome.json"
        # A durable intent is a spent trial even if the process was killed. Recover while
        # holding the same canonical lock, before allowing a different material candidate.
        key = result_key(cfg, old)
        for pending in sorted(attempts.glob("*/started.json")):
            final = pending.parent / "outcome.json"
            if not final.exists():
                index = pending.parent / "artifacts.json"
                if index.exists():
                    recovered_refs = load(index)
                    check(
                        set(recovered_refs) == LABELS
                        and all(
                            type(k) is str and HEX.fullmatch(k)
                            for k in recovered_refs.values()
                        ),
                        "incomplete first-positive recovery index",
                    )
                    recovered = load(home / "objects" / recovered_refs["costOutcome"])
                    check(
                        mark(recovered) == recovered_refs["costOutcome"]
                        and auth(recovered, old["keys"]["publisher"])["slot"]
                        == pending.parent.name
                        and recovered["payload"]["status"] == "accepted",
                        "invalid completed positive during recovery",
                    )
                    immutable(final, canonical(recovered))
            if not final.exists():
                started = load(pending)
                interrupted = {
                    "format": "ocs.safe-push.cost-outcome/1",
                    "slot": pending.parent.name,
                    "planSha256": started["planSha256"],
                    "startedAt": started["startedAt"],
                    "finishedAt": now,
                    "status": "undetermined",
                    "criterion": "verification.cost.interrupted",
                    "reason": "measurement interrupted; scope spent",
                }
                immutable(final, canonical(signature(interrupted, key)))
            envelope = load(final)
            prior = envelope["payload"]
            if prior["status"] == "accepted":
                check(
                    auth(envelope, old["keys"]["publisher"]) == prior,
                    "unauthenticated earlier first-positive record",
                )
                immutable(
                    home / "first-positive.json",
                    canonical(
                        {
                            "slot": pending.parent.name,
                            "outcomeSha256": mark(envelope),
                        }
                    ),
                )
        if outcome.exists() or (home / "first-positive.json").exists():
            raise Decision(
                "verification.cost.spent",
                "this tree was already measured or the first eligible result was elected",
            )
        immutable(home / "protocol.json", canonical(protocol))
        basis = {
            "costProtocol": protocol,
            "costPlan": approval,
            "costGenesis": seed,
            "costSource": src,
        }
        refs = {label: store_blob(home, label, value) for label, value in basis.items()}
        challenge = os.urandom(32)
        immutable(
            reserve,
            canonical(
                {
                    "slot": slot,
                    "planSha256": mark(approval),
                    "startedAt": now,
                    "objects": refs,
                    "workerChallengeSha256": sha(challenge),
                }
            ),
        )
        measured = None
        receipt = None
        workload = plan["workloadSha256"]
        try:
            trial = _measured(
                config,
                plan,
                workload,
                old["receiveTimeoutSeconds"],
                cfg.get("leanHome") or os.getenv("SAFE_PUSH_LEAN_HOME"),
                challenge,
            )
            receipt = trial["prepared"]
            if trial["status"] != "accepted":
                error = Decision(trial["criterion"], trial["reason"], trial["status"])
                error.observation = trial["diagnostic"]
                error.certificate = trial["refutation"]
                raise error
            measured = trial["measurement"]
            measured["acquisition"] = {
                "parent": plan["parent"],
                "candidate": candidate,
                "verifiedReceiptSha256": mark(receipt),
                "planSha256": mark(approval),
                "genesisReceiptSha256": mark(seed),
            }
            refs["costReceipt"] = store_blob(home, "costReceipt", receipt)
            refs["costObservation"] = store_blob(home, "costObservation", measured)
            if type(protocol["ceilings"]) is dict:
                for cell, value in measured["observed"].items():
                    if value > protocol["ceilings"][cell]:
                        raise Decision(
                            "verification.cost.regression/" + cell,
                            "measured cost exceeds the preregistered ceiling",
                            "rejected",
                        )
            folder = (
                a
                / "reviews"
                / candidate
                / "runs"
                / receipt["evidenceManifest"]["reviewBundle"]
            )
            reviews = {
                role: load(folder / (role + ".json"))
                for role in ("domain", "independent")
            }
            if receipt["evidenceManifest"]["guardian"] is not None:
                reviews["guardian"] = load(folder / "guardian.json")
            if receipt["evidenceManifest"]["remediations"] is not None:
                reviews["resolutions"] = load(folder / "resolutions.json")
            reviews["signedBytes"] = {
                role: base64.b64encode(read(folder / (role + ".json"))).decode("ascii")
                for role in list(reviews)
            }
            reviews["inventory"] = bundle_inventory(folder)
            refs["costReviews"] = store_blob(home, "costReviews", reviews)
            details = {
                "format": "ocs.safe-push.cost-outcome/1",
                "status": "accepted",
                "slot": slot,
                "planSha256": mark(approval),
                "receiptSha256": mark(receipt),
                "observationSha256": mark(measured),
                "reviewsSha256": mark(reviews),
                "readbacks": trial["readbacks"],
                "executionContext": trial["executionContext"],
                "startedAt": trial["startedAt"],
                "finishedAt": trial["finishedAt"],
            }
            signed = signature(details, key)
            material = {
                **basis,
                "costReceipt": receipt,
                "costReviews": reviews,
                "costOutcome": signed,
                "costObservation": measured,
            }
            reg = registration(old, protocol, measured)
            verify_packet(
                old, {**old, "epoch": old["epoch"] + 1, "receiverCost": reg}, material
            )
            replay_prepared(seed, receipt)
        except (
            ArithmeticError,
            ValueError,
            OSError,
            KeyError,
            TypeError,
            subprocess.SubprocessError,
        ) as error:
            if receipt is not None and "costReceipt" not in refs:
                refs["costReceipt"] = store_blob(home, "costReceipt", receipt)
            details = {
                "format": "ocs.safe-push.cost-outcome/1",
                "status": getattr(error, "outcome", "undetermined"),
                "slot": slot,
                "planSha256": mark(approval),
                "startedAt": now,
                "finishedAt": stamp(),
                "criterion": getattr(
                    error, "criterion", "verification.cost.acquisition"
                ),
                "reason": str(error)[:900],
                "readback": readref(repo),
                "objects": refs,
            }
            if getattr(error, "certificate", None) is not None:
                details["refutationSha256"] = store_blob(
                    home, "refutation", error.certificate
                )
            if getattr(error, "observation", None) is not None:
                details["incompleteObservationSha256"] = store_blob(
                    home, "incomplete", error.observation
                )
            if details["status"] == "rejected" and details["criterion"].startswith(
                "verification.cost.regression/"
            ):
                immutable(
                    j / "adverse" / plan["tree"] / (mark(details) + ".json"),
                    canonical(details),
                )
            immutable(outcome, canonical(signature(details, key)))
            raise
        refs["costOutcome"] = store_blob(home, "costOutcome", signed)
        immutable(attempts / slot / "artifacts.json", canonical(refs))
        immutable(outcome, canonical(signed))
        immutable(
            home / "first-positive.json",
            canonical({"slot": slot, "outcomeSha256": mark(signed)}),
        )
        return {
            "status": "accepted",
            "slot": slot,
            "artifacts": refs,
            "registration": reg,
            "proofBody": {
                "positiveReceiptSha256": mark(receipt),
                "observed": measured["observed"],
                "registrationSha256": mark(reg),
            },
        }


def elected_material(cfg, a, j, old, new, transition):
    """Require the identical witnessed first success in both local history and the dual-quorum evolution subject."""
    from authority import load, read
    from evolution import evolution_signature_payload

    check(
        old["receiverCost"] is None
        and type(new["receiverCost"]) is dict
        and "ceilings" in new["receiverCost"]
        and "evolution" in transition,
        "first registration needs protected evolution",
    )
    ev = transition["evolution"]
    check(transition["policy"] == new, "misbound proposed operating policy")
    election = evolution_signature_payload(old, new, ev)
    for side, policy in (("old", old), ("new", new)):
        check(set(transition[side]) == set(ROLES), "missing baseline-election quorum")
        for role in ROLES:
            check(
                auth(transition[side][role], policy["keys"][role])
                == {**election, "role": role, "side": side},
                "misbound baseline-election role",
            )
    checker = ev["proofs"]["evolution/receiver-cost"]["method"]
    enrolled = old["predicateCheckers"][checker]
    check(
        "evolution/receiver-cost" in enrolled["requirements"]
        and any(
            p == "policy/receiverCost" or p == "policy"
            for p in enrolled["pathPrefixes"]
        ),
        "first registration needs the incumbent narrow acquisition proof",
    )
    home = j / "cost-acquisitions" / cfg["genesisDigest"]
    first = load(home / "first-positive.json")
    check(
        set(first) == {"slot", "outcomeSha256"}
        and all(type(v) is str and HEX.fullmatch(v) for v in first.values()),
        "invalid first-positive index",
    )
    attempt = home / "attempts" / first["slot"]
    refs = load(attempt / "artifacts.json")
    check(
        set(refs) == LABELS
        and refs["costOutcome"]
        == first["outcomeSha256"]
        == mark(load(attempt / "outcome.json")),
        "inconsistent first-positive journal record",
    )
    subj_raw = read(a / "evolution" / "objects" / ev["subjects"]["new"])
    check(sha(subj_raw) == ev["subjects"]["new"], "unbound evolution subject")
    attrs = decode(subj_raw)["artifacts"]
    material = {}
    for lab, k in refs.items():
        check(
            type(k) is str and HEX.fullmatch(k) and attrs.get(lab) == k,
            "evolution omitted elected positive evidence: " + lab,
        )
        raw = read(home / "objects" / k)
        check(
            sha(raw) == k and read(a / "evolution" / "objects" / k) == raw,
            "acquisition archive changed: " + lab,
        )
        material[lab] = decode(raw)
    check(
        material["costPlan"]["payload"]["rootSha256"] == cfg["rootDigest"]
        and mark(material["costGenesis"]) == cfg["genesisDigest"],
        "wrong original operating authority",
    )
    check(
        enrolled["sha256"]
        == material["costSource"]["files"]["safe_push/cost_acquisition.py"],
        "the elected checker differs from the authenticated incumbent source",
    )
    baseline = verify_packet(old, new, material)
    replay_prepared(material["costGenesis"], material["costReceipt"])
    return baseline


def reference(cfg, a, j, policy, prior, *, executing=False):
    """Only a cost-less unchanged genesis can use its elected attachment. Later edges use their signed predecessor."""
    home = j / "cost-acquisitions" / cfg["genesisDigest"]
    if (
        executing
        and (home / "first-positive.json").exists()
        and isinstance(policy.get("receiverCost"), dict)
    ):
        from authority import load

        elected = load(home / "protocol.json")
        check(
            mark(elected) == policy["receiverCost"].get("workloadSha256"),
            "actual workload differs from the elected initial sample",
        )
        uid = (
            load(a / "broker.json")["publisherUid"]
            if (a / "broker.json").is_file()
            else None
        )
        context_valid(policy["profile"], elected, execution_context(), uid)
    if (
        prior.get("candidate") != cfg["genesis"]
        or prior.get("format") != "ocs.safe-push.genesis/1"
        or prior.get("receiverCost") is not None
        or policy.get("receiverCost") is None
        or "ceilings" not in policy["receiverCost"]
    ):
        return prior.get("receiverCost")
    from authority import load, policy_history

    check(mark(prior) == cfg["genesisDigest"], "genesis was substituted")
    chain = policy_history(a, cfg["rootDigest"])
    for old, new in pairwise(chain):
        if old["receiverCost"] is None and new["receiverCost"] is not None:
            transition = load(a / "rotations" / f"{new['epoch']:012}.json")
            baseline = elected_material(cfg, a, j, old, new, transition)
            check(
                mark(baseline) == policy["receiverCost"]["baselineEvidenceSha256"],
                "registered baseline changed",
            )
            return baseline
    raise ValueError(
        "verification.cost.acquisition: missing old-governed first baseline"
    )


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--measurement":
        sys.path.insert(0, str(HERE))
        sys.stdout.buffer.write(
            canonical(
                measure_worker(
                    Path(sys.argv[2]), *sys.argv[3:], sys.stdin.buffer.read(33)
                )
            )
        )
    else:
        method_main()
