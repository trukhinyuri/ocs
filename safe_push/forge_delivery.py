#!/usr/bin/env python3
"""Deliver an independently replayed adverse observation as the separately enrolled checking App."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from authority import SHA256, canonical, framed, immutable, load, require
from forge import CHECK, ReadAPI
from forge_apps import (
    APIClient,
    installation_session,
    read_identity,
    read_pins,
    role_lock,
    role_receipt,
    sign_jwt,
)
from forge_refusals import adjudicate, propose, registration


def requested(body, expected, candidate):
    require(
        isinstance(expected, str)
        and SHA256.fullmatch(expected)
        and framed(body) == expected
        and body.get("name") == CHECK
        and body.get("head_sha") == candidate
        and body.get("status") == "completed"
        and body.get("conclusion") == "failure"
        and isinstance(body.get("external_id"), str)
        and body["external_id"].startswith("refused:"),
        "delivery.approval",
        "approved bytes do not match this measured failure",
        "rejected",
    )


def deliver(custody, trust, approval, live, post, branch_read, clock=time.time):
    """Serialize with the role's caller lock. One armed intent may cause at most one POST."""
    current = live(False)
    if current["result"] == "already-reported":
        report = live(True)
        return {**report, "submission": "previous exact result confirmed"}
    require(
        current["result"] == "proposal",
        "delivery.proposal",
        "fresh reportable adverse observation required",
    )
    body = current["body"]
    requested(body, approval, trust["candidate"])
    require(
        clock() < current["validBefore"],
        "delivery.expiry",
        "measurement expired before submission",
    )
    ref_before = branch_read()
    directory = custody / "hosted-refusals"
    directory.mkdir(mode=0o700, exist_ok=True)
    address = framed(
        {
            "repositoryId": trust["repositoryId"],
            "sha": trust["candidate"],
            "check": CHECK,
            "issuer": current["appId"],
        }
    )
    intent = directory / (address + ".json")
    require(
        not intent.exists(),
        "delivery.uncertain",
        "an intent already exists and its expected run is not visible. Reconcile externally before any retry.",
    )
    data = {
        "format": "ocs.safe-push.failure-intent/1",
        "repositoryId": trust["repositoryId"],
        "candidate": trust["candidate"],
        "refBefore": ref_before,
        "appId": current["appId"],
        "bodySha256": approval,
        "externalId": body["external_id"],
    }
    immutable(intent, canonical(data))
    # A changed rule, identity or evidence cannot transform this operation into
    # a green report or a ref write. The only outward operation is this exact POST.
    require(
        clock() < current["validBefore"],
        "delivery.expiry",
        "measurement expired at the durable intent",
    )
    sent = post(body)
    require(
        type(sent.get("id")) is int
        and sent["id"] > 0
        and sent.get("head_sha") == trust["candidate"]
        and sent.get("app", {}).get("id") == current["appId"],
        "delivery.response",
        "unrecognized submission response. Reconcile by source and external ID.",
    )
    after = live(True)
    require(
        after.get("checkRunId") == sent["id"] and branch_read() == ref_before,
        "delivery.confirm",
        "remote result or canonical ref disagrees with the preflight",
    )
    immutable(
        directory / (address + ".confirmed.json"),
        canonical({**data, "checkRunId": sent["id"], "refAfter": ref_before}),
    )
    return {
        **after,
        "submission": "new measured failure confirmed",
        "refBefore": ref_before,
        "refAfter": ref_before,
    }


def sole_main(api, repository):
    rows = api.get("/repos/" + repository + "/git/matching-refs/heads/main")
    require(isinstance(rows, list), "delivery.ref", "unavailable ref inventory")
    refs = [x for x in rows if x.get("ref") == "refs/heads/main"]
    require(len(refs) <= 1, "delivery.ref", "ambiguous canonical ref")
    if not refs:
        return None
    obj = refs[0].get("object", {})
    require(
        obj.get("type") == "commit" and isinstance(obj.get("sha"), str),
        "delivery.ref",
        "invalid ref readback",
    )
    return obj["sha"]


def run(args):
    inputs = args.inputs.resolve()
    trust = load(inputs / "trust.json")
    registration(trust, args.trust_sha256)
    custody = args.custody.resolve()
    require(
        os.geteuid() > 0,
        "delivery.custody",
        "run as the separately enrolled checking custodian",
    )
    pins = read_pins(args.pins)
    reporter = pins["roles"]["reporter"]
    require(
        pins["repositoryId"] == trust["repositoryId"]
        and pins["ownerId"] == trust["ownerId"]
        and pins["repository"] == trust["repository"]
        and pins["project"] == trust["project"]
        and reporter["custodianUid"] == os.geteuid(),
        "delivery.custody",
        "incorrect enrollment or role",
    )
    api = APIClient()
    with (
        role_lock(custody),
        installation_session(api, custody, "reporter", pins) as (token, _),
    ):
        old_identity = read_identity(custody, "reporter", uid=os.geteuid())
        require(
            old_identity["appId"] == reporter["appId"]
            and role_receipt(custody, "reporter", os.geteuid()) == reporter,
            "delivery.custody",
            "registered checking App changed",
        )
        # The App assertion and short-lived installation token remain with this UID.
        jwt = sign_jwt(
            custody / "registration/private-key.pem",
            old_identity["clientId"],
            time.time(),
        )
        host = ReadAPI(token)
        issuer = ReadAPI(jwt)

        def verify():
            return adjudicate(
                trust,
                args.trust_sha256,
                inputs / "repository.git",
                inputs / "policy.json",
                inputs / "genesis.json",
                inputs / "base" / "dossier",
                inputs / "base" / "enrollment.json",
                inputs / "candidate" / "dossier",
                inputs / "candidate" / "enrollment.json",
                inputs / "observer.pub",
            )

        def live(readback):
            return propose(
                host,
                issuer,
                trust,
                args.trust_sha256,
                reporter,
                framed(reporter),
                verify,
                readback=readback,
            )

        if args.action == "readback":
            return live(True)
        if args.action == "preview":
            result = live(False)
            return (
                {**result, "bodySha256": framed(result["body"])}
                if "body" in result
                else result
            )
        return deliver(
            custody,
            trust,
            args.approved_body_sha256,
            live,
            lambda body: api.call(
                "POST",
                "/repos/" + trust["repository"] + "/check-runs",
                token,
                body,
                operation="post the measured refusal",
            ),
            lambda: sole_main(host, trust["repository"]),
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("preview", "post-refusal", "readback"))
    for field in ("inputs", "pins", "custody"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--trust-sha256", required=True)
    p.add_argument("--approved-body-sha256")
    a = p.parse_args()
    if a.action == "post-refusal" and a.approved_body_sha256 is None:
        p.error(
            "an independently approved fingerprint of the displayed POST body is required"
        )
    if a.action != "post-refusal" and a.approved_body_sha256 is not None:
        p.error("approval is accepted only for post-refusal")
    try:
        print(canonical(run(a)).decode())
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(
            json.dumps(
                {
                    "result": "pending/not-qualified",
                    "criterion": getattr(error, "criterion", "delivery.input"),
                    "reason": str(error)[:320],
                }
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
