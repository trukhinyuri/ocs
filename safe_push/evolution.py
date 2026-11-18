"""Adjudicate policy changes under the predecessor's independently installed semantics."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authority import (
    NAME,
    OBJECT,
    SHA256,
    Decision,
    canonical,
    digest,
    framed,
    pairs,
    public_der,
    read,
    require,
)
from cost import EXPERIMENT, validate_profile


def _require(ok, criterion, reason, outcome="rejected"):
    require(ok, "evolution." + criterion, reason, outcome)


def _sha(value):
    return type(value) is str and SHA256.fullmatch(value) is not None


def _git(value):
    return type(value) is str and OBJECT.fullmatch(value) and int(value, 16) != 0


def _bytes(authority, sha):
    _require(_sha(sha), "object", "expected SHA-256 identifier")
    try:
        raw = read(authority / "evolution" / "objects" / sha)
    except OSError as error:
        raise Decision(
            "evolution.object", "missing independently staged evolution object " + sha
        ) from error
    _require(digest(raw) == sha, "object", "changed evolution object " + sha)
    return raw


def _object(authority, sha):
    raw = _bytes(authority, sha)
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        encoded = canonical(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Decision(
            "evolution.object", "invalid canonical JSON object", "rejected"
        ) from error
    _require(
        type(value) is dict and encoded == raw,
        "object",
        "expected canonical JSON object",
    )
    return value


def _subset_scope(previous, current):
    return set(previous["requirements"]) <= set(current["requirements"]) and all(
        any(
            item == prefix or item.startswith(prefix.rstrip("/") + "/")
            for prefix in current["pathPrefixes"]
        )
        for item in previous["pathPrefixes"]
    )


def evolution_scope(old, new):
    """Native hard bounds and the exact outstanding predecessor-authorized proof purposes."""
    _require(
        new["epoch"] == old["epoch"] + 1
        and all(old[k] == new[k] for k in ("format", "project", "profile", "genesis")),
        "identity",
        "changed lineage or nonconsecutive epochs",
    )
    purposes = {}

    def purpose(name, path):
        purposes["evolution/" + name] = path

    if old["assurancePin"] != new["assurancePin"]:
        purpose("assurance-pin", "policy/assurancePin")
    for name in ("lifetimeSeconds", "receiveTimeoutSeconds"):
        _require(
            type(new[name]) is int and 0 < new[name] <= old[name],
            "bound",
            name + " was loosened",
        )
        if old[name] != new[name]:
            purpose(name, "policy/" + name)
    a, b = old["receiverCost"], new["receiverCost"]
    validate_profile(a)
    validate_profile(b)
    if a != b:
        if a not in (None, EXPERIMENT):
            _require(
                type(b) is dict
                and b != EXPERIMENT
                and {k: v for k, v in a.items() if k != "ceilings"}
                == {k: v for k, v in b.items() if k != "ceilings"},
                "cost",
                "old measuring conditions or baseline changed",
            )
            _require(
                set(a["ceilings"]) == set(b["ceilings"])
                and all(b["ceilings"][k] <= v for k, v in a["ceilings"].items()),
                "cost",
                "protected cell or its original maximum was weakened",
            )
        else:
            _require(
                b not in (None, EXPERIMENT),
                "cost",
                "cost enrollment weakened or still unregistered",
            )
        purpose("receiver-cost", "policy/receiverCost")
    for key in sorted(set(old["requiredOpen"]) - set(new["requiredOpen"])):
        purpose("close/" + key, "policy/requiredOpen")

    for family in ("targets", "adapters", "predicateCheckers"):
        _require(
            set(old[family]) <= set(new[family]),
            "retention",
            "removed old " + family + " binding",
        )
    for name, definition in new["targets"].items():
        prior = old["targets"].get(name)
        if prior is not None:
            _require(
                definition["conditions"] == prior["conditions"],
                "conditions",
                "protected condition changed for target " + name,
            )
        # Even for a byte-identical descriptor under a new name, custom target adapters
        # receive that name. The old verifier must establish possible successful use.
        if prior != definition:
            purpose("target/" + name, "policy/targets/" + name)
    for name, sha in new["adapters"].items():
        if old["adapters"].get(name) != sha and (
            name in old["adapters"] or sha not in old["adapters"].values()
        ):
            purpose("adapter/" + name, "policy/adapters/" + name)
    for name, definition in new["predicateCheckers"].items():
        prior = old["predicateCheckers"].get(name)
        if prior == definition:
            continue
        if prior is not None:
            _require(
                _subset_scope(prior, definition),
                "domain",
                "old predicate purpose or path domain was withdrawn",
            )
        equivalent_alias = any(
            row["sha256"] == definition["sha256"] and _subset_scope(definition, row)
            for row in old["predicateCheckers"].values()
        )
        if prior is not None or not equivalent_alias:
            purpose("predicate/" + name, "policy/predicateCheckers/" + name)
    return {
        "format": "ocs.safe-push.evolution-scope/1",
        "project": old["project"],
        "fromEpoch": old["epoch"],
        "epoch": new["epoch"],
        "old": framed(old),
        "new": framed(new),
        "inheritedTargets": sorted(old["targets"]),
        "purposes": dict(sorted(purposes.items())),
    }


def evolution_signature_payload(old, new, evolution):
    scope = evolution_scope(old, new)
    _require(
        type(evolution) is dict
        and set(evolution)
        == {"format", "scopeSha256", "subjects", "controls", "proofs"}
        and evolution["format"] == "ocs.safe-push.evolution/1"
        and evolution["scopeSha256"] == framed(scope),
        "scope",
        "signed change scope differs from the predecessor's interpretation",
    )
    for key, labels in (
        ("subjects", {"old", "new"}),
        ("controls", {"positive", "refusal"}),
    ):
        _require(
            type(evolution[key]) is dict
            and set(evolution[key]) == labels
            and all(_sha(sha) for sha in evolution[key].values())
            and len(set(evolution[key].values())) == 2,
            "binding",
            "missing or indistinguishable " + key,
        )
    _require(
        type(evolution["proofs"]) is dict
        and set(evolution["proofs"]) == set(scope["purposes"]),
        "proofs",
        "complete set of predecessor proof obligations required",
        "undetermined",
    )
    for row in evolution["proofs"].values():
        _require(
            type(row) is dict
            and set(row) == {"method", "artifact"}
            and type(row["method"]) is str
            and NAME.fullmatch(row["method"])
            and _sha(row["artifact"]),
            "proofs",
            "invalid replay binding",
        )
    return {
        "format": "ocs.safe-push.rotation/1",
        "project": old["project"],
        "old": framed(old),
        "new": framed(new),
        "fromEpoch": old["epoch"],
        "epoch": new["epoch"],
        "evolutionSha256": framed(evolution),
        "scopeSha256": evolution["scopeSha256"],
        "subjects": evolution["subjects"],
        "controlsSha256": framed(evolution["controls"]),
        "proofsSha256": framed(evolution["proofs"]),
    }


def _installed(authority, policy):
    """Read candidate method bytes as inert data. Only a method selected from the old scope can execute."""
    for sha in set(policy["adapters"].values()) | {
        v["sha256"] for v in policy["predicateCheckers"].values()
    }:
        try:
            raw = read(authority / "methods" / (sha + ".py"), 4 * 1024 * 1024)
        except OSError as error:
            raise Decision(
                "evolution.installation",
                "method bytes must be staged before evolution: " + sha,
            ) from error
        _require(
            digest(raw) == sha, "installation", "substituted registered method bytes"
        )
    for target in policy["targets"].values():
        sha = target["observerSha256"]
        if sha is not None:
            try:
                raw = read(authority / "observers" / (sha + ".pem"), 4096)
            except OSError as error:
                raise Decision(
                    "evolution.installation",
                    "observer public key must be staged before evolution",
                ) from error
            _require(digest(raw) == sha, "installation", "substituted target observer")
            public_der(raw.decode("ascii"))


def _subject(authority, sha, policy):
    x = _object(authority, sha)
    fields = {"format", "policySha256", "assuranceRevision", "epoch", "data"}
    _require(
        set(x) in (fields, fields | {"artifacts"})
        and x["format"] == "ocs.safe-push.policy-subject/1"
        and x["policySha256"] == framed(policy)
        and x["assuranceRevision"] == policy["assurancePin"]
        and type(x["epoch"]) is int
        and x["epoch"] == policy["epoch"]
        and type(x["data"]) is dict,
        "subject",
        "subject differs from the exact policy, verifier or epoch",
    )
    artifacts = x.get("artifacts", {})
    _require(
        type(artifacts) is dict
        and len(artifacts) <= 128
        and all(
            type(name) is str and NAME.fullmatch(name) and _sha(mark)
            for name, mark in artifacts.items()
        ),
        "subject",
        "invalid content-addressed subject artifact manifest",
    )
    return x


def _case(authority, sha, scope):
    x = _object(authority, sha)
    _require(
        set(x)
        == {
            "format",
            "scopeSha256",
            "parent",
            "actualParent",
            "candidate",
            "ageSeconds",
            "serviceSeconds",
            "targetConditions",
            "costs",
            "criterion",
            "refutations",
        }
        and x["format"] == "ocs.safe-push.policy-control/1"
        and x["scopeSha256"] == scope
        and all(_git(x[k]) for k in ("parent", "actualParent", "candidate"))
        and len({len(x[k]) for k in ("parent", "actualParent", "candidate")}) == 1
        and all(
            type(x[k]) is int and x[k] >= 0 for k in ("ageSeconds", "serviceSeconds")
        )
        and type(x["targetConditions"]) is dict
        and all(
            type(k) is str and NAME.fullmatch(k) and _sha(v)
            for k, v in x["targetConditions"].items()
        )
        and type(x["costs"]) is dict
        and all(
            type(k) is str and type(v) is int and v >= 0 for k, v in x["costs"].items()
        )
        and type(x["refutations"]) is dict
        and all(_sha(v) for v in x["refutations"].values())
        and (x["criterion"] is None or type(x["criterion"]) is str),
        "control",
        "malformed finite control",
    )
    return x


def _verdict(policy, case):
    if case["parent"] != case["actualParent"] or case["candidate"] == case["parent"]:
        return "reference.parent"
    if policy["requiredOpen"]:
        return "scope.open"
    if case["ageSeconds"] >= policy["lifetimeSeconds"]:
        return "evidence.freshness"
    if case["serviceSeconds"] > policy["receiveTimeoutSeconds"]:
        return "reference.timeout"
    for name, target in sorted(policy["targets"].items()):
        if case["targetConditions"].get(name) != target["conditions"]:
            return "qualification.target/" + name
    cost = policy["receiverCost"]
    if cost not in (None, EXPERIMENT):
        for name, maximum in sorted(cost["ceilings"].items()):
            if name not in case["costs"] or case["costs"][name] > maximum:
                return "verification.cost/" + name
    elif cost is None:
        return "verification.cost.unregistered"
    return None


def _artifact(authority, sha, purpose, scope_sha, subjects):
    row = _object(authority, sha)
    _require(
        set(row) == {"format", "purpose", "scopeSha256", "subjects", "body"}
        and row["format"] == "ocs.safe-push.evolution-proof/1"
        and row["purpose"] == purpose
        and row["scopeSha256"] == scope_sha
        and row["subjects"] == subjects
        and type(row["body"]) is dict,
        "artifact",
        "proof artifact is for another claim or subject",
    )
    return row


def verify_evolution(authority: Path, old: dict, new: dict, record: dict):
    """Check policy evolution before admitting its quorum. Return the exact quorum payload."""
    from admission import run_adapter
    from authority import validate_policy

    validate_policy(old)
    validate_policy(new)
    _require(
        record.get("policy") == new, "policy", "record changed the proposed policy"
    )
    ev = record.get("evolution")
    binding = evolution_signature_payload(old, new, ev)
    scope = evolution_scope(old, new)
    subjects = {
        side: _subject(authority, ev["subjects"][side], pol)
        for side, pol in (("old", old), ("new", new))
    }
    controls = {
        label: _case(authority, sha, ev["scopeSha256"])
        for label, sha in ev["controls"].items()
    }
    before, after = controls["positive"], controls["refusal"]
    _require(
        before["criterion"] is None
        and not before["refutations"]
        and _verdict(new, before) is None,
        "realizability",
        "no concrete permitted case for proposed policy",
    )
    prior_positive = _verdict(old, before)
    _require(
        prior_positive is None
        or (prior_positive == "scope.open" and old["requiredOpen"])
        or (
            prior_positive == "verification.cost.unregistered"
            and old["receiverCost"] is None
        ),
        "realizability",
        "permitted example displaced a protected requirement",
    )
    _require(
        after["criterion"] is not None
        and after["criterion"] == _verdict(new, after)
        and set(after["refutations"]) == set(scope["purposes"]),
        "control",
        "refusal control did not reproduce the declared reason or cover all replays",
    )
    changed = [
        k
        for k in (
            "parent",
            "actualParent",
            "candidate",
            "ageSeconds",
            "serviceSeconds",
            "targetConditions",
            "costs",
        )
        if before[k] != after[k]
    ]
    _require(
        len(changed) == 1, "control", "refusal must isolate one actual input difference"
    )
    stale = {**before, "actualParent": before["candidate"]}
    _require(
        _verdict(old, stale) == _verdict(new, stale) == "reference.parent",
        "control",
        "original refused ref transaction became permitted",
    )
    _installed(authority, old)
    _installed(authority, new)
    # Only JSON evidence and the single enrolled incumbent verifier enter the isolated process.
    # New executable bytes are available purely as content-addressed data for proof/source binding.
    with tempfile.TemporaryDirectory(prefix="ocs-policy-proof-") as directory:
        evidence = Path(directory)
        (evidence / "subjects.json").write_bytes(canonical(subjects))
        (evidence / "policies.json").write_bytes(canonical({"old": old, "new": new}))
        (evidence / "controls.json").write_bytes(canonical(controls))
        material_size = 0
        for side, subject in subjects.items():
            (evidence / side).mkdir()
            for label, sha in subject.get("artifacts", {}).items():
                content = _bytes(authority, sha)
                material_size += len(content)
                _require(
                    material_size <= 64 * 1024 * 1024,
                    "budget",
                    "subject materials exceed bounded replay",
                    "undetermined",
                )
                (evidence / side / label).write_bytes(content)
        if not scope["purposes"]:
            return binding
        for pol in (old, new):
            for sha in set(pol["adapters"].values()) | {
                row["sha256"] for row in pol["predicateCheckers"].values()
            }:
                (evidence / (sha + ".data")).write_bytes(
                    read(authority / "methods" / (sha + ".py"), 4 * 1024 * 1024)
                )
        for purpose, path in scope["purposes"].items():
            row = ev["proofs"][purpose]
            method = old["predicateCheckers"].get(row["method"])
            names = {purpose}
            for family, registry, addition in (
                ("target", "targets", "add-target"),
                ("predicate", "predicateCheckers", "add-predicate"),
                ("adapter", "adapters", "add-adapter"),
            ):
                prefix = "evolution/" + family + "/"
                if (
                    purpose.startswith(prefix)
                    and purpose.removeprefix(prefix) not in old[registry]
                ):
                    names.add("evolution/" + addition)
            _require(
                method is not None
                and not names.isdisjoint(method["requirements"])
                and any(
                    path == prefix or path.startswith(prefix.rstrip("/") + "/")
                    for prefix in method["pathPrefixes"]
                ),
                "authority",
                "proof requires a purpose-specific method already enrolled by the predecessor",
                "undetermined",
            )
            good, bad = row["artifact"], after["refutations"][purpose]
            _require(
                good != bad, "control", "identical positive and adverse proof objects"
            )
            for sha, wanted in ((good, "accepted"), (bad, "refused")):
                proof = _artifact(
                    authority, sha, purpose, ev["scopeSha256"], ev["subjects"]
                )
                artifact = evidence / "input.json"
                artifact.write_bytes(canonical(proof))
                context = {
                    "format": "ocs.safe-push.evolution-replay/1",
                    "purpose": purpose,
                    "policyScope": path,
                    "scopeSha256": ev["scopeSha256"],
                    "subjects": ev["subjects"],
                    "old": framed(old),
                    "new": framed(new),
                    "fromEpoch": old["epoch"],
                    "epoch": new["epoch"],
                    "artifactSha256": sha,
                }
                result = run_adapter(
                    authority,
                    old["predicateCheckers"],
                    row["method"],
                    {
                        "context": context,
                        "artifact": str(artifact),
                        "evidence": str(evidence),
                    },
                )
                _require(
                    result
                    == {
                        "status": wanted,
                        "contextSha256": framed(context),
                        "artifactSha256": sha,
                    },
                    "refinement",
                    "incumbent verifier did not independently establish the required positive/refusal",
                )
    return binding
