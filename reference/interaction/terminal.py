#!/usr/bin/env python3
"""Keyboard-only local declarative client. Output wraps to the active terminal."""

import argparse
import os
import shutil
import sys
import textwrap

from client import Caller, CallError


def label(text):
    size = max(8, shutil.get_terminal_size((50, 20)).columns)
    print(
        "\n".join(textwrap.wrap(text, width=size, break_long_words=True, break_on_hyphens=False)),
        flush=True,
    )


def display(view):
    values = view["values"]
    for line in (
        view["title"],
        "State " + values["state"],
        "Quota remaining " + values["quota"],
        "Last checked " + values["checkedAt"],
        "Reset " + values["reset"],
        "Terms " + values["terms"],
        "Recovery " + values["recovery"],
        "[r] " + view["actions"][0]["label"],
        "[t] Retry request",
        "[s] Resume saved job",
        "[n] New request",
        "[g] Request permission",
        "[a] Authorize reviewed intent",
        "[q] Close",
    ):
        label(line)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--endpoint", required=True)
    args.add_argument("--owner", required=True)
    args.add_argument("--proposal-id", help="owner-selected local compensation proposal")
    opt = args.parse_args()
    client = Caller(opt.endpoint, os.environ["OCS_INTERACTION_TOKEN"])
    client.describe()
    presented = client.call(
        "surface.open",
        {"surfaceId": "example.status.panel", "scope": {"kind": "tenant", "id": opt.owner}},
    )
    ref = {k: presented[k] for k in ("generation", "instanceId")}
    pending_job = None
    review = None
    try:
        display(presented["surface"]["view"])
        for line in sys.stdin:
            key = line.strip().lower()
            if key == "q":
                break
            try:
                if key in ("r", "t"):
                    result = client.call(
                        "surface.event",
                        {**ref, "action": "example.status.read", "values": {"resourceId": "demo"}},
                    )
                    if key == "t":
                        label("Retried the selected resource")
                    display(result["view"])
                elif key == "n":
                    pending_job = client.call(
                        "example.job.begin", {"draft": "new keyboard request"}
                    )
                    label("Created a new owned job")
                elif key == "s":
                    if not pending_job:
                        label("Select an owned saved job")
                    else:
                        current = client.request(
                            "job.status", {"jobId": pending_job["jobId"], "meta": client.meta()}
                        )
                        done = client.request(
                            "job.continue",
                            {
                                "jobId": current["jobId"],
                                "revision": current["revision"],
                                "input": {},
                                "meta": client.meta(),
                            },
                        )
                        label("Resumed saved job " + done["state"])
                elif key == "g":
                    if not opt.proposal_id:
                        label("Permission review requires an owner-selected proposal")
                    else:
                        review = client.call("example.compensation.review", {"id": opt.proposal_id})
                        intent = review["intent"]
                        for text in (
                            "Trusted owner review",
                            "Recipient " + intent["recipient"],
                            "Resource " + intent["resource"],
                            "Operation " + intent["operation"],
                            "Amount " + intent["amount"] + " " + intent["currency"],
                            "Exact intent " + review["intentDigest"],
                        ):
                            label(text)
                elif key == "a":
                    approval = os.environ.get("OCS_INTERACTION_APPROVER")
                    if not review or not approval:
                        label("Trusted review and owner authority required")
                    else:
                        authorized = Caller(opt.endpoint, approval)
                        authorized.describe()
                        authorized.call(
                            "example.compensation.approve",
                            {"id": opt.proposal_id, "intentDigest": review["intentDigest"]},
                        )
                        label("Authorized the displayed intent")
                else:
                    label("Choose a labelled action")
            except CallError as e:
                label("Action unavailable " + e.kind)
    finally:
        try:
            client.call("example.surface.close", ref)
            print("Workspace", flush=True)
        except CallError as exc:
            print("Reconnect: " + exc.kind, flush=True)


if __name__ == "__main__":
    main()
