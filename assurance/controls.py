"""Challenge scope, certificate admission, freshness and schema evolution."""

import subprocess
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from jsonschema import Draft202012Validator
from structure import compare, fingerprint, schema_items
from trust import (
    admit_reports,
    compare_policy,
    observer_keys,
    save,
    sign,
    validate_time,
    verify_signature,
    verify_stand,
)


def schema_inventory(obj):
    return {
        "schemas/test.schema.json#" + pos: {
            "kind": "schema-declaration",
            "owner": "edition-schema",
            "sha256": fingerprint(v),
        }
        for pos, v in schema_items(obj)
    }


def checks(catalog, scope, work):
    outcomes = []

    def check(id, expected, action):
        try:
            ok = bool(action())
            detail = "accepted" if ok else "refused"
        except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
            ok = False
            detail = str(e)
        outcomes.append(
            {
                "id": id,
                "expectedAcceptance": expected,
                "observedAcceptance": ok,
                "result": "pass" if expected == ok else "fail",
                "reason": detail,
            }
        )

    atom = next(k for k, v in catalog.items() if "model" in v["levels"])
    removed = dict(catalog)
    del removed[atom]
    check(
        "remove-obligation/" + atom,
        False,
        lambda: not compare_policy(catalog, removed, scope, scope),
    )
    smaller = deepcopy(catalog)
    smaller[atom]["levels"].remove("model")
    check(
        "lower-proof-level/" + atom,
        False,
        lambda: not compare_policy(catalog, smaller, scope, scope),
    )
    text = deepcopy(catalog)
    text[atom]["expected"] = "True."
    check("weaken-property/" + atom, False, lambda: not compare_policy(catalog, text, scope, scope))
    assumption = deepcopy(scope)
    assumption["qualificationTargets"]["localCapacity"]["samples"] = 1
    check("narrow-workload", False, lambda: not compare_policy(catalog, catalog, scope, assumption))
    new = deepcopy(catalog)
    new["example.additional"] = {**new[atom], "id": "additional"}
    check(
        "compatible-extra-obligation", True, lambda: not compare_policy(catalog, new, scope, scope)
    )
    req = {"type": "object", "required": ["a", "b"], "properties": {"a": {}, "b": {}}}
    reordered = {**req, "required": ["b", "a"]}
    check(
        "equivalent-required-order",
        True,
        lambda: not compare(schema_inventory(req), schema_inventory(reordered)),
    )
    check(
        "equivalent-new-optional-property",
        True,
        lambda: (
            not compare(
                schema_inventory(req),
                schema_inventory({**req, "properties": {**req["properties"], "extra": {}}}),
            )
        ),
    )
    reject_all = {**req, "not": {}}
    check(
        "new-validation-forbids-previous-witness",
        False,
        lambda: not compare(schema_inventory(req), schema_inventory(reject_all)),
    )
    if not Draft202012Validator(req).is_valid({"a": 1, "b": 2}) or Draft202012Validator(
        reject_all
    ).is_valid({"a": 1, "b": 2}):
        raise ValueError("schema mutation was not discriminating")
    model = {
        "checks": [
            {
                "id": "proof",
                "level": "model",
                "status": "pass",
                "claims": [atom],
                "observed": "synthetic control only",
            }
        ]
    }
    reference = work / "control.json"
    save(reference, model)
    bound = {"core/proof@model": [atom]}
    identity = {"treeSha256": "0" * 64}
    altered = deepcopy(model)
    second = next(k for k in catalog if k != atom)
    altered["checks"][0]["claims"].append(second)
    check(
        "reuse-certificate-for-unrelated-property",
        False,
        lambda: (
            not admit_reports(catalog, {"core": (altered, reference, [])}, identity, False, bound)[
                "failures"
            ]
        ),
    )
    now = datetime.now(timezone.utc)
    check(
        "expired-observation",
        False,
        lambda: (
            validate_time((now - timedelta(days=2)).isoformat(), now.timestamp(), 86400) is None
        ),
    )
    check(
        "future-observation",
        False,
        lambda: (
            validate_time((now + timedelta(minutes=2)).isoformat(), now.timestamp(), 86400) is None
        ),
    )
    check(
        "current-observation",
        True,
        lambda: validate_time(now.isoformat(), now.timestamp(), 86400) is None,
    )
    pri, pub = observer_keys(work / "operator")
    _, foreign = observer_keys(work / "different-operator")
    sig = work / "sample.sig"
    sign(reference, pri, sig)
    check("signed-observation", True, lambda: verify_signature(reference, pub, sig) is None)
    check("foreign-observer", False, lambda: verify_signature(reference, foreign, sig) is None)
    save(reference, altered)
    check(
        "substituted-signed-content", False, lambda: verify_signature(reference, pub, sig) is None
    )
    return outcomes


def stand_controls(original, policy, subject):
    now = datetime.now(timezone.utc).timestamp()
    target = original["target"]
    variants = []
    for id, adjust in (
        (
            "omit-cancellation",
            lambda d: next(r for r in d["checks"] if r["id"] == "stand.load")["observed"].pop(
                "cancellation"
            ),
        ),
        ("substitute-image", lambda d: d["target"].update(image="invalid-image")),
        ("stale-component", lambda d: d["checks"][0].update(observedAt="2000-01-01T00:00:00Z")),
        (
            "unrelated-time-window",
            lambda d: d["checks"][0].update(
                observedAt=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            ),
        ),
        (
            "change-latency-budget",
            lambda d: next(r for r in d["checks"] if r["id"] == "stand.load")["observed"].update(
                p95Ms=0.0
            ),
        ),
    ):
        bad = deepcopy(original)
        adjust(bad)
        try:
            verify_stand(bad, policy, subject, target, now)
        except (ValueError, KeyError, TypeError) as e:
            variants.append(
                {"id": id, "result": "pass", "observedAcceptance": False, "reason": str(e)}
            )
        else:
            variants.append({"id": id, "result": "fail", "observedAcceptance": True})
    return variants
