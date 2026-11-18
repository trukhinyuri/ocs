"""Replay a filed OCS metric regression and prepare a failure-only GitHub check."""

import argparse
import math
import subprocess
import sys
import tempfile
import time
import urllib.parse
from decimal import Decimal, InvalidOperation
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from admission import commit_binding, git
from authority import (
    NAME,
    SHA256,
    Decision,
    canonical,
    digest,
    framed,
    instant,
    load,
    read,
    require,
    validate_policy,
)
from forge import (
    CHECK,
    PROFILE,
    GhReadAPI,
    ReadAPI,
    _repository,
    _staging,
    oid,
    pages,
    positive,
    ref_sha,
)
from forge_apps import (
    CLIENT,
    PERMISSIONS,
    SLUG,
    identity_target,
    installation_readback,
    permission_map,
    repo_ok,
)
from qualification import inspect_dossier
from scope import change_requirements, inventory, subject

TRUST = "ocs.safe-push.hosted-refusal-enrollment/1"
RECEIPT = "ocs.safe-push.hosted-measured-refusal/1"
PIN_FIELDS = (
    "releasePolicySha256",
    "previousReceiptSha256",
    "metricProfileSha256",
    "baseEnrollmentSha256",
    "candidateEnrollmentSha256",
)


def valid_sha(s):
    return type(s) is str and SHA256.fullmatch(s) is not None


def registration(trust, expected_hash):
    fields = {
        "format",
        "project",
        "measurementProject",
        "repository",
        "repositoryId",
        "ownerId",
        "ownerType",
        "expectedVisibility",
        "target",
        "stagingRef",
        "parent",
        "candidate",
        *PIN_FIELDS,
    }
    require(
        type(trust) is dict
        and set(trust) == fields
        and trust["format"] == TRUST
        and valid_sha(expected_hash)
        and framed(trust) == expected_hash,
        "refusal.enrollment",
        "missing or substituted independent refusal enrollment",
    )
    identity_target(trust)
    require(
        all(
            isinstance(trust[k], str) and NAME.fullmatch(trust[k])
            for k in ("project", "measurementProject", "target")
        )
        and trust["expectedVisibility"] in ("private", "public")
        and _staging(trust["stagingRef"])
        and oid(trust["parent"])
        and oid(trust["candidate"])
        and trust["parent"] != trust["candidate"]
        and len(trust["parent"]) == len(trust["candidate"])
        and all(valid_sha(trust[k]) for k in PIN_FIELDS),
        "refusal.enrollment",
        "unknown repository, scope, revision or evidence identity",
    )
    return trust


def rooted(trust, policy, seed):
    t = trust["target"]
    require(
        framed(policy) == trust["releasePolicySha256"]
        and framed(seed) == trust["previousReceiptSha256"],
        "refusal.basis",
        "previously enrolled policy or receipt differs",
    )
    validate_policy(policy)
    require(
        policy["format"] == "ocs.safe-push.policy/1"
        and policy["profile"] == PROFILE
        and policy["epoch"] == 0
        and policy["project"] == trust["measurementProject"]
        and t in policy["targets"]
        and policy["targets"][t]["adapter"] == "ocs-dossier/1"
        and policy["genesis"] == trust["parent"]
        and seed["format"] == "ocs.safe-push.genesis/1"
        and seed["project"] == policy["project"]
        and seed["profile"] == PROFILE
        and seed["policy"] == framed(policy)
        and seed["candidate"] == trust["parent"],
        "refusal.basis",
        "not the enrolled OCS release-observation genesis and target",
    )
    require(
        digest(read(HERE / "metrics.json")) == trust["metricProfileSha256"],
        "refusal.metric-profile",
        "the trusted metric decoder differs from the prior metric profile",
    )
    return policy["targets"][t]


def compare(old, new):
    require(
        isinstance(old, dict)
        and old
        and isinstance(new, dict)
        and set(old) <= set(new),
        "refusal.incomplete",
        "a registered comparison cell is missing",
    )
    adverse = []
    improved = equal = 0
    for name in sorted(old):
        a, b = old[name], new[name]
        require(
            type(name) is str
            and name
            and isinstance(a, dict)
            and isinstance(b, dict)
            and a.get("direction") in ("min", "max")
            and a["direction"] == b.get("direction")
            and valid_sha(a.get("condition"))
            and a["condition"] == b.get("condition"),
            "refusal.incomparable",
            "missing or different measurement conditions",
        )
        try:
            require(
                type(a.get("value")) is str and type(b.get("value")) is str,
                "refusal.incomparable",
                "non-decimal measurement",
            )
            before, after = Decimal(a["value"]), Decimal(b["value"])
        except InvalidOperation as e:
            raise Decision("refusal.incomparable", "invalid decimal observation") from e
        require(
            before.is_finite() and after.is_finite(),
            "refusal.incomparable",
            "non-finite observation",
        )
        if before == after:
            equal += 1
        elif after > before if a["direction"] == "min" else after < before:
            adverse.append(
                {
                    "cell": name,
                    "direction": a["direction"],
                    "condition": a["condition"],
                    "before": str(before),
                    "after": str(after),
                }
            )
        else:
            improved += 1
    require(
        adverse,
        "refusal.unproved",
        "no authenticated strictly worse comparable measurement",
    )
    return {
        "compared": len(old),
        "worse": len(adverse),
        "improved": improved,
        "equal": equal,
        "adverseObservationsSha256": framed(adverse),
    }


def adjudicate(
    trust,
    hash_pin,
    repo,
    policy_path,
    seed_path,
    base_dossier,
    base_enrollment,
    candidate_dossier,
    candidate_enrollment,
    observer,
):
    registration(trust, hash_pin)
    p, seed = load(policy_path), load(seed_path)
    target = rooted(trust, p, seed)
    target_name = trust["target"]
    revisions = (trust["parent"], trust["candidate"])
    binding = commit_binding(repo, *revisions)
    before, after = (inventory(repo, v) for v in revisions)
    old_ident, new_ident = (
        subject(repo, rev, inv)
        for rev, inv in zip(revisions, (before, after), strict=True)
    )
    require(
        seed["tree"] == git(repo, "rev-parse", revisions[0] + "^{tree}")
        and seed["subject"] == old_ident
        and seed["wholeTreeSha256"] == framed(before),
        "refusal.basis",
        "Git parent differs from original receipt",
    )
    previous = change_requirements(repo, revisions[0], revisions[0], before, before)
    expected = {
        claim + "@" + level
        for claim, levels in previous["requirements"]["qualification.full"][
            "levels"
        ].items()
        for level in levels
    }
    require(
        len(expected) >= 394,
        "refusal.incomplete",
        "original full OCS obligation contour is unavailable",
    )
    public = read(observer, 32768)
    require(
        digest(public) == target["observerSha256"],
        "refusal.issuer",
        "observer public key differs from enrollment",
    )
    with tempfile.TemporaryDirectory(prefix="ocs-refusal-replay-") as d:
        independent = Path(d)
        observer_copy = independent / "observer.pub"
        observer_copy.write_bytes(public)
        verified = []
        for side, dossier, enroll, ident in (
            ("base", base_dossier, base_enrollment, old_ident),
            ("candidate", candidate_dossier, candidate_enrollment, new_ident),
        ):
            root = Path(dossier).resolve(strict=True)
            require(
                not Path(enroll).resolve(strict=True).is_relative_to(root)
                and not Path(observer).resolve(strict=True).is_relative_to(root),
                "refusal.enrollment",
                "stand enrollment and trust keys must be independent of the submitted dossier",
            )
            raw = read(enroll)
            require(
                digest(raw) == trust[side + "EnrollmentSha256"],
                "refusal.enrollment",
                "submitted stand enrollment differs from the separately registered digest",
            )
            pinned = independent / (side + ".json")
            pinned.write_bytes(raw)
            verified.append(
                inspect_dossier(
                    root, pinned, observer_copy, repo, p["assurancePin"], ident
                )
            )
    base, candidate = verified
    require(
        base["scope"] == candidate["scope"]
        and set(base["claims"]) == expected
        and set(candidate["claims"]) >= expected
        and all(base["claims"][k] == candidate["claims"][k] for k in expected),
        "refusal.contour",
        "missing or incompatible inherited claim, evidence level or witness",
    )
    for row, ident in zip(verified, (old_ident, new_ident), strict=True):
        require(
            row["subject"] == ident
            and row["acceptedVerifier"] == p["assurancePin"]
            and row["metricProfileSha256"] == trust["metricProfileSha256"]
            and row["targetConditionSha256"] == target["conditions"]
            and row["metricGaps"] == []
            and row["witnesses"] > 0
            and row["controls"] > 0
            and valid_sha(row["reportSha256"])
            and valid_sha(row["standReceiptSha256"]),
            "refusal.contour",
            "signed full observation or independent conditions differ",
        )
    prefix = target_name + "/"
    require(
        {
            k.removeprefix(prefix): v
            for k, v in seed["claims"].items()
            if k.startswith(prefix)
        }
        == base["claims"]
        and {
            k.removeprefix(prefix): v
            for k, v in seed["metrics"].items()
            if k.startswith(prefix)
        }
        == base["metrics"]
        and seed["targetReports"][target_name] == base["reportSha256"]
        and seed["coverageLimits"][target_name] == base["coverageLimits"],
        "refusal.basis",
        "replayed original observations differ from the registered comparison basis",
    )
    result = compare(base["metrics"], candidate["metrics"])
    expires = min(instant(row["expiresAt"]) for row in verified)
    require(
        type(seed["expiresEpoch"]) in (int, float)
        and math.isfinite(seed["expiresEpoch"]),
        "refusal.expired",
        "invalid previous observation expiry",
    )
    expires = min(expires, seed["expiresEpoch"])
    require(
        time.time() < expires, "refusal.expired", "enrolled measurement has expired"
    )
    return {
        "format": RECEIPT,
        "verdict": "measured-regression",
        "profile": PROFILE,
        "enrollmentSha256": hash_pin,
        "project": trust["project"],
        "measurementProject": p["project"],
        "repository": trust["repository"],
        "repositoryId": trust["repositoryId"],
        "ownerId": trust["ownerId"],
        "visibility": trust["expectedVisibility"],
        "stagingRef": trust["stagingRef"],
        "target": target_name,
        "scope": base["scope"],
        **binding,
        "baseSourceSha256": old_ident["treeSha256"],
        "candidateSourceSha256": new_ident["treeSha256"],
        "acceptedVerifier": p["assurancePin"],
        "observerSha256": target["observerSha256"],
        "targetConditionSha256": target["conditions"],
        "metricProfileSha256": trust["metricProfileSha256"],
        "policySha256": framed(p),
        "previousReceiptSha256": framed(seed),
        "baseReportSha256": base["reportSha256"],
        "candidateReportSha256": candidate["reportSha256"],
        "baseStandReceiptSha256": base["standReceiptSha256"],
        "candidateStandReceiptSha256": candidate["standReceiptSha256"],
        "requiredClaimLevels": len(expected),
        "candidateClaimLevels": len(candidate["claims"]),
        "validBefore": expires,
        **result,
    }


def reporter_pin(trust, reported, expected):
    public_fields = {
        "format",
        "role",
        "custodianUid",
        "repository",
        "repositoryId",
        "ownerId",
        "ownerType",
        "appId",
        "clientId",
        "slug",
        "permissions",
        "publicKeySha256",
        "installationId",
        "repositoryVisibility",
    }
    require(
        isinstance(reported, dict)
        and set(reported) == public_fields
        and valid_sha(expected)
        and framed(reported) == expected
        and reported.get("format") == "ocs.safe-push.app-installation/1"
        and reported.get("role") == "reporter"
        and identity_target(reported) == identity_target(trust)
        and reported.get("repositoryVisibility") == trust["expectedVisibility"]
        and all(
            positive(reported.get(k))
            for k in ("appId", "installationId", "custodianUid")
        )
        and isinstance(reported.get("slug"), str)
        and SLUG.fullmatch(reported["slug"])
        and isinstance(reported.get("clientId"), str)
        and CLIENT.fullmatch(reported["clientId"])
        and valid_sha(reported.get("publicKeySha256"))
        and permission_map(reported["permissions"]) == PERMISSIONS["reporter"],
        "refusal.reporter",
        "registered checking App, owner, repository, permissions or installation differs",
    )
    return reported


def host_state(api, issuer_api, trust, reporter, receipt, external, body):
    root, _ = _repository(
        api, trust, {"main", trust["stagingRef"].removeprefix("refs/heads/")}
    )
    require(
        repo_ok(api.get(root), trust),
        "refusal.repository",
        "wrong registered repository owner or account type",
    )
    installation_readback(
        issuer_api.get(root + "/installation"), reporter, reporter["installationId"]
    )
    sha = receipt["candidate"]
    require(
        ref_sha(api, root, trust["stagingRef"]) == sha,
        "refusal.staging",
        "staged branch moved",
    )
    commit = api.get(root + "/git/commits/" + sha)
    require(
        commit.get("sha") == sha
        and commit.get("tree", {}).get("sha") == receipt["tree"]
        and [p.get("sha") for p in commit.get("parents", [])] == [receipt["parent"]],
        "refusal.staging",
        "hosted object, tree or direct parent differs",
    )
    require(
        all(
            isinstance(s, dict)
            and type(s.get("context")) is str
            and s["context"] != CHECK
            for s in pages(api, root + "/commits/" + sha + "/statuses")
        ),
        "refusal.check",
        "reserved name also appears as a legacy commit status",
    )
    q = urllib.parse.urlencode({"check_name": CHECK, "filter": "all", "per_page": 100})
    page = api.get(root + "/commits/" + sha + "/check-runs?" + q)
    rows = page.get("check_runs")
    require(
        type(rows) is list
        and type(page.get("total_count")) is int
        and len(rows) == page["total_count"]
        and len(rows) <= 1,
        "refusal.check",
        "duplicate, incomplete or ambiguous check-run readback",
    )
    if not rows:
        return None
    run = rows[0]
    require(
        positive(run.get("id"))
        and run.get("app", {}).get("id") == reporter["appId"]
        and run.get("head_sha") == sha
        and run.get("name") == CHECK
        and run.get("external_id") == external
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and all(run.get("output", {}).get(k) == v for k, v in body["output"].items())
        and run["output"].get("text") in (None, "")
        and run["output"].get("annotations_count", 0) == 0
        and run["output"].get("images") in (None, []),
        "refusal.check",
        "reserved check belongs to a different issuer, evidence, or result",
    )
    return run["id"]


def draft(trust, trust_sha, reporter, reporter_sha, verify):
    registration(trust, trust_sha)
    reporter_pin(trust, reporter, reporter_sha)
    # The CLI passes only the installed independent replay. No caller-supplied public JSON constitutes a verdict.
    receipt = verify()
    require(
        receipt.get("format") == RECEIPT
        and receipt.get("verdict") == "measured-regression"
        and receipt.get("enrollmentSha256") == trust_sha
        and receipt.get("project") == trust["project"]
        and receipt.get("measurementProject") == trust["measurementProject"]
        and receipt.get("repositoryId") == trust["repositoryId"]
        and receipt.get("ownerId") == trust["ownerId"]
        and receipt.get("parent") == trust["parent"]
        and receipt.get("candidate") == trust["candidate"]
        and receipt.get("worse", 0) > 0
        and receipt.get("requiredClaimLevels", 0) >= 394
        and time.time() < receipt["validBefore"],
        "refusal.proof",
        "authenticated full adverse observation is unavailable",
    )
    external = "refused:" + framed(
        {"evidence": framed(receipt), "reporter": reporter_sha}
    )
    body = {
        "name": CHECK,
        "head_sha": receipt["candidate"],
        "status": "completed",
        "conclusion": "failure",
        "external_id": external,
        "output": {
            "title": "Registered OCS measurements regressed",
            "summary": f"{receipt['worse']} of {receipt['compared']} comparable measurements worsened on the enrolled "
            f"{receipt['target']} target. Both signed observations cover {receipt['requiredClaimLevels']} inherited "
            f"evidence levels. Measurement project {receipt['measurementProject']}. Parent {receipt['parent']}. "
            f"Refusal evidence {external}.",
        },
    }
    common = {
        "repositoryId": trust["repositoryId"],
        "ownerId": trust["ownerId"],
        "project": trust["project"],
        "measurementProject": trust["measurementProject"],
        "appId": reporter["appId"],
        "installationId": reporter["installationId"],
        "candidate": receipt["candidate"],
        "parent": receipt["parent"],
        "tree": receipt["tree"],
        "evidenceSha256": framed(receipt),
        "reporterPinSha256": reporter_sha,
        "externalId": external,
        "validBefore": receipt["validBefore"],
    }
    return {
        **common,
        "result": "offline-proposal-requires-live-readback",
        "action": "check-run-failure",
        "method": "POST",
        "path": "/repos/" + trust["repository"] + "/check-runs",
        "body": body,
    }


def propose(
    api, issuer_api, trust, trust_sha, reporter, reporter_sha, verify, *, readback=False
):
    result = draft(trust, trust_sha, reporter, reporter_sha, verify)
    first = host_state(
        api, issuer_api, trust, reporter, result, result["externalId"], result["body"]
    )
    require(
        first
        == host_state(
            api,
            issuer_api,
            trust,
            reporter,
            result,
            result["externalId"],
            result["body"],
        )
        and time.time() < result["validBefore"],
        "refusal.preflight",
        "host state or observation freshness changed",
    )
    if first is not None:
        common = {
            k: v
            for k, v in result.items()
            if k not in ("result", "action", "method", "path", "body")
        }
        return {
            **common,
            "result": "verified-failure-readback" if readback else "already-reported",
            "checkRunId": first,
        }
    require(
        not readback, "refusal.check", "expected measured failure has not been reported"
    )
    return {**result, "result": "proposal"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "preview", "proposal", "readback"))
    for name in (
        "trust",
        "repo",
        "old-policy",
        "old-genesis",
        "base-dossier",
        "base-enrollment",
        "candidate-dossier",
        "candidate-enrollment",
        "observer",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--trust-sha256", required=True)
    parser.add_argument("--reporter", type=Path)
    parser.add_argument("--reporter-sha256")
    parser.add_argument("--reporter-jwt-file", type=Path)
    reg = parser.add_mutually_exclusive_group()
    reg.add_argument("--gh-read", action="store_true")
    parser.add_argument("--gh-executable", type=Path)
    reg.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    trust = load(args.trust)

    def verify():
        return adjudicate(
            trust,
            args.trust_sha256,
            args.repo,
            args.old_policy,
            args.old_genesis,
            args.base_dossier,
            args.base_enrollment,
            args.candidate_dossier,
            args.candidate_enrollment,
            args.observer,
        )

    if args.action == "verify":
        result = verify()
    elif args.action == "preview":
        require(
            args.reporter,
            "refusal.reporter",
            "supply the enrolled public checking App installation record",
        )
        result = draft(
            trust, args.trust_sha256, load(args.reporter), args.reporter_sha256, verify
        )
    else:
        require(
            args.reporter
            and args.reporter_jwt_file
            and (args.gh_read or args.token_file),
            "refusal.reporter",
            "select actual checking App installation and read-only GitHub readback",
        )
        api = (
            GhReadAPI(trust["repository"], executable=args.gh_executable)
            if args.gh_read
            else ReadAPI(read(args.token_file, 4096).decode("ascii").strip())
        )
        issuer = ReadAPI(read(args.reporter_jwt_file, 4096).decode("ascii").strip())
        result = propose(
            api,
            issuer,
            trust,
            args.trust_sha256,
            load(args.reporter),
            args.reporter_sha256,
            verify,
            readback=args.action == "readback",
        )
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        KeyError,
        ValueError,
        TypeError,
        AttributeError,
        ArithmeticError,
        subprocess.SubprocessError,
    ) as err:
        # Diagnostics never disclose submitted material, filesystem paths or bearer contents.
        print(
            "OCS refusal proposal unavailable ["
            + str(getattr(err, "criterion", "refusal.evidence"))
            + "]",
            file=sys.stderr,
        )
        sys.exit(1)
