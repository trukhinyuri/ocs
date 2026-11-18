"""Black-box controls for obligations found during independent normative review."""

import argparse
import copy
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib import error, request

ORACLE = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ.get("OCS_SUBJECT_ROOT", ORACLE)).resolve()
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "reference")]
from contracts import read_json, utc_at
from package import install, pack
from peer import start
from resolution import bind, compiled_schema


def ensure(v, msg):
    if not v:
        raise AssertionError(msg)


def refuse(fn, word):
    try:
        fn()
    except ValueError as exc:
        ensure(word in str(exc), f"incorrect refusal, expected {word!r}")
        return str(exc)
    raise AssertionError("invalid admission succeeded")


def probes(tmp):
    template = read_json((ROOT / "examples/peer/assembly.json").read_bytes())
    seed = {
        key: (ROOT / loc / "ocs.json").read_bytes()
        for key, loc in (("authority", "examples/status"), ("reader", "examples/workflow"))
    }
    authority = {
        i["instance"]: {
            **i,
            "issuer": "reviewed:" + i["domain"],
            "executionPolicy": "reviewed-local",
        }
        for i in template["instances"]
    }

    def modify(package):
        a = copy.deepcopy(template)
        m = dict(seed)
        t = copy.deepcopy(authority)
        raw = json.dumps(package, sort_keys=True).encode()
        m["authority"] = raw
        a["instances"][1]["manifestDigest"] = t["authority"]["manifestDigest"] = hashlib.sha256(
            raw
        ).hexdigest()
        return a, m, t

    def semantics():
        package = read_json(seed["authority"])
        package["exports"].append({**package["exports"][0], "id": "quota.reset"})
        bad = refuse(lambda: bind(*modify(package)), "contradicts")
        package["exports"][1]["effect"] = "external-write"
        good = bind(*modify(package))
        ensure(len(good["bindings"]) == 1, "extra unbound effect was granted")
        return {"refusal": bad, "retainedGrants": good["bindings"]}

    def confinement():
        ensure(
            len(bind(template, seed, authority)["bindings"]) == 1, "reviewed local grant refused"
        )
        outcomes = []
        for replacement in (
            {"executionPolicy": "unreviewed"},
            {"executionPolicy": "reviewed-local", "requiresConfinement": "sandbox"},
        ):
            t = copy.deepcopy(authority)
            t["authority"].update(replacement)
            outcomes.append(refuse(lambda: bind(template, seed, t), "confinement"))
        return {"explicitTrustedDevelopment": "admitted", "unimplementedConfinement": outcomes}

    def dialect():
        for schema in (
            {"$schema": "https://unsupported.invalid/meta", "type": "string"},
            {"$vocabulary": {"urn:example:mandatory": True}, "type": "string"},
            {"$defs": {"nested": {"$vocabulary": {"urn:example:mandatory": True}}}},
        ):
            refuse(lambda: compiled_schema(schema, {}), "mandatory")
        compiled_schema(
            {"type": "string", "$vocabulary": {"urn:example:optional": False}}, {}
        ).validate("ok")
        return {
            "unsupportedDialect": "refused",
            "mandatoryVocabulary": "refused",
            "optionalVocabulary": "accepted",
        }

    def immutable():
        base = tmp / "package"
        shutil.copytree(ROOT / "examples/status", base)
        archive = tmp / "original.ocsx"
        store = tmp / "store"
        pack(base, archive)
        pin = hashlib.sha256(archive.read_bytes()).hexdigest()
        install(archive, store, pin)
        (base / "executor.py").write_text(
            (base / "executor.py").read_text() + "\n# changed implementation\n"
        )
        newer = tmp / "changed.ocsx"
        pack(base, newer)
        newpin = hashlib.sha256(newer.read_bytes()).hexdigest()
        refuse(lambda: install(newer, store, newpin), "different artifact")
        ensure(os.readlink(store / "current") == pin, "failed revision replacement changed current")
        manifest = read_json((base / "ocs.json").read_bytes())
        manifest["version"] = "0.1.1"
        (base / "ocs.json").write_text(json.dumps(manifest) + "\n")
        pack(base, newer)
        v2 = hashlib.sha256(newer.read_bytes()).hexdigest()
        install(newer, store, v2)
        ensure(
            os.readlink(store / "current") == v2
            and (store / pin / "executor.py").read_bytes()
            != (store / v2 / "executor.py").read_bytes(),
            "versioned installation failed",
        )
        return {"old": pin, "sameRevisionDifferentCode": newpin, "newRevision": v2}

    def cache():
        key = secrets.token_hex(32)
        other = secrets.token_hex(32)
        manifest = ROOT / "examples/status/ocs.json"
        pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        with start(manifest, key) as first, start(manifest, other) as second:
            threads = [
                threading.Thread(target=s.serve_forever, daemon=True) for s in (first, second)
            ]
            for t in threads:
                t.start()
            opener = request.build_opener(request.ProxyHandler({}))

            def invoke(s, token, method, p):
                raw = json.dumps(
                    {"jsonrpc": "2.0", "id": "scope-test", "method": method, "params": p}
                ).encode()
                url = f"http://127.0.0.1:{s.server_port}/ocs"
                try:
                    with opener.open(
                        request.Request(
                            url,
                            data=raw,
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": "Bearer " + token,
                            },
                        ),
                        timeout=3,
                    ) as res:
                        return read_json(res.read(65536))
                except error.HTTPError as exc:
                    return exc.code

            try:
                meta = {
                    "protocol": "0.1",
                    "deadline": utc_at(time.time() + 5),
                    "manifestDigest": pin,
                }
                call = {
                    "operation": "example.status.read",
                    "version": "1.0.0",
                    "input": {"resourceId": "demo"},
                    "meta": meta,
                }
                desc = invoke(
                    first,
                    key,
                    "ocs.describe",
                    {
                        "protocols": ["0.1"],
                        "requiredFeatures": [],
                        "meta": {"deadline": meta["deadline"]},
                    },
                )
                ensure(desc["result"]["manifestDigest"] == pin, "negotiation pin mismatch")
                ensure(
                    invoke(first, key, "tool.call", call)["result"]["data"]["state"] == "ready",
                    "positive scope rejected",
                )
                ensure(
                    invoke(second, key, "tool.call", call) == 403
                    and invoke(first, other, "tool.call", call) == 403,
                    "admission leaked across endpoint/principal",
                )
                stale = invoke(
                    first, key, "tool.call", {**call, "meta": {**meta, "manifestDigest": "f" * 64}}
                )
                narrow = invoke(
                    first, key, "tool.call", {**call, "input": {"resourceId": "ungranted"}}
                )
                ensure(
                    stale["error"]["code"] == -33014 and narrow["error"]["code"] == -33001,
                    "cached negotiation changed pin or scope",
                )
                return {
                    "bootstrap": pin,
                    "otherEndpoint": 403,
                    "otherPrincipal": 403,
                    "wrongRevision": -33014,
                    "wrongScope": -33001,
                }
            finally:
                for s in (first, second):
                    s.shutdown()
                for t in threads:
                    t.join(5)

    def release():
        version = read_json((ROOT / "version.json").read_bytes())
        digests = {
            n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in version["normative"]
        }
        ensure(
            digests
            == {
                n: hashlib.sha256((ORACLE / n).read_bytes()).hexdigest()
                for n in version["normative"]
            },
            "published normative bytes changed",
        )
        notes = (ROOT / "CHANGELOG.md").read_text()
        migration = (ROOT / "docs/compatibility.md").read_text()
        ensure(
            version["edition"] in notes
            and all(t in migration.lower() for t in ("cutover", "grant", "rollback", "state")),
            "missing release notes or migration procedure",
        )
        return {
            "edition": version["edition"],
            "artifactDigests": digests,
            "notesSha256": hashlib.sha256(notes.encode()).hexdigest(),
            "migrationSha256": hashlib.sha256(migration.encode()).hexdigest(),
        }

    rows = []
    for id, claims, fn in (
        ("effect-conflict", ["core.interpretation.conflict"], semantics),
        ("untrusted-execution", ["composition.deployment.confinement"], confinement),
        ("unknown-vocabulary", ["C-05.vocabulary"], dialect),
        ("sealed-revision", ["C-03.package-revision"], immutable),
        ("bootstrap-scope", ["W-08.cache-scope"], cache),
        ("release-record", ["T-04.release-record"], release),
    ):
        try:
            observed = fn()
            status = "pass"
        except Exception as exc:
            status = "fail"
            observed = str(exc)[:300]
        rows.append(
            {
                "id": "admission." + id,
                "level": "reference",
                "claims": claims,
                "status": status,
                "observed": observed,
                "observedAt": utc_at(time.time()),
            }
        )
    return rows


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        rows = probes(Path(tmp))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(
            {"scope": "local sealed host and reviewed publisher store", "checks": rows}, indent=2
        )
        + "\n"
    )
    for row in rows:
        if row["status"] != "pass":
            print(row["id"], row["observed"], file=sys.stderr)
    raise SystemExit(int(any(row["status"] != "pass" for row in rows)))
