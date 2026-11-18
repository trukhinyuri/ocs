"""Black-box and scoped library witnesses with independent expected values."""

import copy
import hashlib
import json
import math
import os
import secrets
import selectors
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib import error, request
from zipfile import ZipFile

from jsonschema import ValidationError


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def rejected(fn, *types):
    try:
        fn()
    except types as exc:
        return type(exc).__name__
    raise AssertionError("a forbidden operation succeeded")


def observe(root, oracle, tmp, rows):
    sys.path[:0] = [str(root / "tools"), str(root / "reference")]
    from admission import check_manifest, check_names
    from contracts import (
        LIMIT,
        REGISTRY,
        SCHEMAS,
        read_json,
        utc_at,
        validate,
    )
    from package import install, pack, verify
    from resolution import (
        bind,
        compatible_replacement,
        compiled_schema,
        forward_operation_contract,
    )

    def jsonfile(path):
        return read_json((root / path).read_bytes())

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def case(name, claims, fn, level="reference"):
        try:
            observed = fn()
            require(observed is not None, "missing observable result")
            status = "pass"
        except Exception as exc:
            status = "fail"
            observed = f"{type(exc).__name__}: {str(exc)[:300]}"
        rows.append(
            {
                "id": "core." + name,
                "level": level,
                "claims": claims.split(),
                "status": status,
                "observed": observed,
                "observedAt": utc_at(time.time()),
                "scope": "reviewed local status packages, isolated processes and loopback peers",
            }
        )

    assembly = jsonfile("examples/peer/assembly.json")
    inputs = {
        "authority": (root / "examples/status/ocs.json").read_bytes(),
        "reader": (root / "examples/workflow/ocs.json").read_bytes(),
    }
    trust = {
        i["instance"]: {
            **i,
            "issuer": "reviewed:" + i["domain"],
            "capabilities": [],
            "executionPolicy": "reviewed-local",
        }
        for i in assembly["instances"]
    }

    def fixture(new_pkg, instance, old_assembly, old_inputs, old_trust):
        pkg = json.dumps(new_pkg, sort_keys=True, separators=(",", ":")).encode()
        a = copy.deepcopy(old_assembly)
        data = dict(old_inputs)
        policies = copy.deepcopy(old_trust)
        obj = next(item for item in a["instances"] if item["instance"] == instance)
        obj["manifestDigest"] = digest(pkg)
        policies[instance]["manifestDigest"] = obj["manifestDigest"]
        data[instance] = pkg
        return a, data, policies

    def binding():
        good = bind(assembly, inputs, trust)
        require(good["activationOrder"] == ["authority", "reader"], "activation order")
        require(good["issuers"]["authority"] == "reviewed:example-service", "issuer not preserved")
        for field in ("domain", "packageId", "packageVersion", "manifestDigest", "issuer"):
            bad = copy.deepcopy(trust)
            bad["authority"][field] = "" if field == "issuer" else "different"
            rejected(lambda: bind(assembly, inputs, bad), ValueError)
        rejected(
            lambda: bind(assembly, {**inputs, "authority": inputs["reader"]}, trust), ValueError
        )
        rejected(lambda: bind(assembly, inputs, {}), ValueError)
        alt = copy.deepcopy(assembly)
        alt["edges"][0]["grantedEffects"] = ["external-write"]
        rejected(lambda: bind(alt, inputs, trust), ValueError)
        rev = copy.deepcopy(assembly)
        rev["edges"][0]["caller"], rev["edges"][0]["receiver"] = "authority", "reader"
        rejected(lambda: bind(rev, inputs, trust), ValueError)
        raw_pkg = read_json(inputs["authority"])
        perm = fixture(
            {**raw_pkg, "needs": ["example.admin"]}, "authority", assembly, inputs, trust
        )
        rejected(lambda: bind(*perm), ValueError)
        return {
            "order": good["activationOrder"],
            "issuers": good["issuers"],
            "scopedEdge": good["bindings"][0],
            "refused": 9,
        }

    case(
        "directional-binding",
        "C-01.admit C-02.issuer C-03.immutable C-07.request C-07.effect B-01.direction B-01.independence B-02.admission B-02.fresh-authority",
        binding,
    )

    def imports():
        raw = read_json(inputs["reader"])
        required = {"id": "example.missing", "version": "1.0.0"}
        for optional in (True, False):
            package = {**raw, "imports": [*raw["imports"], {**required, "optional": optional}]}
            args = fixture(package, "reader", assembly, inputs, trust)
            if optional:
                require(
                    bind(*args)["activationOrder"] == ["authority", "reader"],
                    "optional import blocked a read",
                )
            else:
                rejected(lambda: bind(*args), ValueError)
        d = read_json(inputs["authority"])
        op = d["exports"][0]
        d["imports"] = [{"id": op["id"], "version": op["version"]}]
        args = fixture(d, "authority", assembly, inputs, trust)
        args[0]["edges"].append({**assembly["edges"][0], "caller": "authority"})
        rejected(lambda: bind(*args), ValueError)
        repeated = {**d, "exports": d["exports"] * 2}
        rejected(lambda: check_manifest(repeated), ValueError)
        return {
            "unresolved": "denied",
            "optional": "ready",
            "requiredCycle": "denied",
            "duplicateExport": "denied",
        }

    case("import-resolution", "C-04.exports C-04.required C-04.cycles", imports)

    def optional_activation():
        status = jsonfile("examples/status/ocs.json")
        reader = jsonfile("examples/workflow/ocs.json")
        base = status["exports"][0]
        contract = {"id": "example.status.enriched", "version": base["version"]}
        prerequisite = {"id": "example.lookup.read", "version": "1.0.0"}
        selected = "resource:demo"
        annotation = [
            {
                "operation": contract["id"],
                "version": contract["version"],
                "needs": [
                    {
                        "operation": prerequisite["id"],
                        "version": prerequisite["version"],
                        "scope": selected,
                    }
                ],
            }
        ]
        provider = {
            **status,
            "exports": [base, {**base, **contract}],
            "imports": [{**prerequisite, "optional": True}],
            "extensions": {"org.example.operation-imports": annotation},
        }
        caller = {**reader, "imports": [*reader["imports"], {**contract, "optional": True}]}
        cfg, raws, auth = fixture(provider, "authority", assembly, inputs, trust)
        cfg, raws, auth = fixture(caller, "reader", cfg, raws, auth)
        cfg["edges"].append({**cfg["edges"][0], "operation": contract["id"], "optional": True})
        absent = bind(cfg, raws, auth)
        require(
            [e["operation"] for e in absent["bindings"]] == [base["id"]]
            and absent["unavailableExports"]
            == [
                {
                    "instance": "authority",
                    **{"operation": contract["id"], "version": contract["version"]},
                    "missing": annotation[0]["needs"],
                }
            ],
            "unavailable optional prerequisite was dispatched or disabled a sibling",
        )
        mandatory = copy.deepcopy(caller)
        mandatory["imports"][-1]["optional"] = False
        rejected(lambda: bind(*fixture(mandatory, "reader", cfg, raws, auth)), ValueError)
        look = {**status, "id": "org.example.lookup", "exports": [{**base, **prerequisite}]}
        encoded = json.dumps(look, sort_keys=True, separators=(",", ":")).encode()
        target = {
            "instance": "lookup",
            "packageId": look["id"],
            "packageVersion": look["version"],
            "manifestDigest": digest(encoded),
            "domain": "lookup-owner",
        }
        cfg["instances"].append(target)
        raws["lookup"] = encoded
        auth["lookup"] = {
            **target,
            "issuer": "reviewed:lookup",
            "executionPolicy": "reviewed-local",
            "capabilities": [],
        }
        cfg["edges"].append(
            {
                "caller": "authority",
                "receiver": "lookup",
                "operation": prerequisite["id"],
                "version": prerequisite["version"],
                "scope": "resource:other",
                "grantedEffects": ["read"],
                "optional": True,
            }
        )
        wrong_scope = bind(cfg, raws, auth)
        require(
            all(e["operation"] != contract["id"] for e in wrong_scope["bindings"]),
            "wrong scope enabled a dependent export",
        )
        cfg["edges"][-1]["scope"] = selected
        present = bind(cfg, raws, auth)
        require(
            not present["unavailableExports"]
            and {e["operation"] for e in present["bindings"]}
            == {base["id"], contract["id"], prerequisite["id"]},
            "admitted optional prerequisite did not enable dependent read",
        )
        undeclared = copy.deepcopy(provider)
        undeclared["extensions"]["org.example.operation-imports"][0]["needs"][0]["operation"] = (
            "example.hidden.read"
        )
        rejected(lambda: bind(*fixture(undeclared, "authority", cfg, raws, auth)), ValueError)
        cycle = copy.deepcopy(provider)
        cycle["imports"] = [{**contract, "optional": True}]
        cycle["extensions"]["org.example.operation-imports"][0]["needs"][0]["operation"] = contract[
            "id"
        ]
        cy, cyraw, cyauth = fixture(cycle, "authority", cfg, raws, auth)
        cy["edges"][-1] = {
            "caller": "authority",
            "receiver": "authority",
            "operation": contract["id"],
            "version": contract["version"],
            "scope": selected,
            "grantedEffects": ["read"],
            "optional": True,
        }
        cyclic = bind(cy, cyraw, cyauth)
        require(
            [e["operation"] for e in cyclic["bindings"]] == [base["id"]],
            "an optional self-cycle supplied its own requirement",
        )
        return {
            "whenAbsent": [e["operation"] for e in absent["bindings"]],
            "whenAvailable": [e["operation"] for e in present["bindings"]],
            "wrongScope": wrong_scope["unavailableExports"],
            "optionalCycle": cyclic["unavailableExports"],
            "requiredDependent": "refused",
            "undeclaredImport": "refused",
        }

    case("optional-export-activation", "C-04.optional", optional_activation)

    def lossless_conversion():
        original = jsonfile("examples/status/ocs.json")
        feature = "example.exact/1.0"
        source = {
            **original,
            "requiresFeatures": [feature],
            "needs": ["example.resource.read"],
            "extensions": {
                "org.example.opaque": {
                    "nested": [None, {"amount": "9007199254740993.0002", "modality": "audio"}]
                }
            },
        }
        receiver = {**source, "extensions": {}}
        forwarded = forward_operation_contract(source, receiver, [feature])
        require(
            forwarded == source and forwarded is not source,
            "forwarder dropped opaque or essential data",
        )
        forwarded["extensions"]["org.example.opaque"]["nested"].clear()
        require(
            len(source["extensions"]["org.example.opaque"]["nested"]) == 2,
            "opaque source data was aliased",
        )
        rejected(lambda: forward_operation_contract(source, receiver, []), ValueError)
        refused = []
        for dimension, field, value in [
            ("identity", "id", "org.example.unrelated"),
            ("revision", "version", "2.0.0"),
            ("authority", "needs", []),
        ]:
            rejected(
                lambda f=field, v=value: forward_operation_contract(
                    source, {**receiver, f: v}, [feature]
                ),
                ValueError,
            )
            refused.append(dimension)
        for dimension, field, value in [
            ("effect", "effect", "external-write"),
            (
                "modality",
                "inputSchema",
                {
                    "type": "object",
                    "properties": {"audio": {"type": "string"}},
                    "required": ["audio"],
                },
            ),
            ("precision", "outputSchema", {"type": "number"}),
        ]:
            changed = copy.deepcopy(receiver)
            changed["exports"][0][field] = value
            rejected(lambda: forward_operation_contract(source, changed, [feature]), ValueError)
            refused.append(dimension)
        return {
            "opaque": source["extensions"],
            "unsupportedRequired": "refused",
            "essentialLossRefused": refused,
        }

    case("lossless-contract-forwarding", "C-06.opaque", lossless_conversion)

    def extension():
        old = read_json(inputs["authority"])
        data = {"org.example.vendor": {"opaque": [None, 8, {"tokenAlias": "fixture"}]}}
        new = {**old, "extensions": data}
        require(compatible_replacement(old, new)["extensions"] == data, "opaque data lost")
        for field, value in (
            ("effect", "local-write"),
            ("version", "2.0.0"),
            ("outputSchema", True),
        ):
            bad = copy.deepcopy(new)
            bad["exports"][0][field] = value
            rejected(lambda: compatible_replacement(old, bad), ValueError)
        rejected(
            lambda: compatible_replacement(
                old, {**new, "requiresFeatures": ["unknown.required/9.0"]}
            ),
            ValueError,
        )
        rejected(
            lambda: compatible_replacement(old, {**new, "needs": ["account.write"]}), ValueError
        )
        rejected(lambda: check_manifest({**new, "unexpectedCoreField": 5}), ValidationError)
        return {
            "preserved": data,
            "compatibleOptional": True,
            "requiredOrChanged": ["permission", "feature", "effect", "version", "outputSchema"],
        }

    case(
        "optional-extension",
        "C-06.namespace C-09.refinement C-09.migration B-06.replacement T-03.drift L-05.mapping",
        extension,
    )

    def resources():
        members = {
            "typed/p.json": b'{"$defs":{"S":{"$ref":"s.json#/$defs/T"}}}',
            "typed/s.json": b'{"$defs":{"T":{"type":"integer","minimum":0}}}',
        }
        v = compiled_schema({"$ref": "typed/p.json#/$defs/S"}, members)
        v.validate(0)
        for invalid in (-1, True, "zero"):
            rejected(lambda: v.validate(invalid), ValidationError)
        local = compiled_schema({"$defs": {"N": {"type": "boolean"}}, "$ref": "#/$defs/N"}, {})
        local.validate(False)
        fail = []
        for ref in (
            "https://untrusted.invalid/schema",
            "../other.json",
            "typed/x%2Ffile",
            "typed/absent",
            "typed/p.json#/$defs/absent",
        ):
            fail.append(rejected(lambda: compiled_schema({"$ref": ref}, members), Exception))
        rejected(
            lambda: compiled_schema({"allOf": [{"$id": "dup.json"}, {"$id": "dup.json"}]}, {}),
            ValueError,
        )
        for s in SCHEMAS.values():
            require(
                REGISTRY.resolver().lookup(s["$id"]).contents["$id"] == s["$id"],
                "lost immutable URN",
            )
        return {"resolved": list(members), "negative": fail, "editionResources": len(SCHEMAS)}

    case(
        "private-resources",
        "C-05.resolver core.schema-resources.fragments core.schema-resources.escape core.schema-resources.urns",
        resources,
    )

    def package():
        copy_dir = tmp / "data-only"
        shutil.copytree(root / "examples/workflow", copy_dir)
        marker = tmp / "should-never-execute"
        (copy_dir / "probe.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        )
        arc = tmp / "guide.ocsx"
        pack(copy_dir, arc)
        manifest = verify(arc)
        require(
            manifest["exports"] == [] and manifest["runtime"]["binding"] == "data", "data package"
        )
        dest = tmp / "installed"
        pin = digest(arc.read_bytes())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [
                f.result(timeout=10)
                for f in [pool.submit(install, arc, dest, pin) for _ in range(2)]
            ]
        require(all(m["id"] == manifest["id"] for m in results), "concurrent activation mismatch")
        active = os.readlink(dest / "current")
        require(
            active == pin and (dest / "current" / "workflow.md").is_file(),
            "wrong immutable revision",
        )
        rejected(lambda: install(arc, dest, "f" * 64), ValueError)
        with ZipFile(arc) as original:
            members = {n: original.read(n) for n in original.namelist()}
        wrong = tmp / "wrong.ocsx"
        with ZipFile(wrong, "w") as changed:
            for name, content in members.items():
                changed.writestr(name, b"unlisted change" if name == "workflow.md" else content)
        rejected(lambda: install(wrong, dest, digest(wrong.read_bytes())), ValueError)
        for names in (
            ["../a"],
            ["/a"],
            ["a", "a/b"],
            ["a", "A"],
            ["a", "a"],
            ["b\\x"],
            ["NUL.txt"],
            ["café", "cafe\u0301"],
        ):
            rejected(lambda: check_names(names), ValueError)
        with ZipFile(wrong, "w") as bomb:
            bomb.writestr("ocs.json", b"X" * (8 * 1024 * 1024 + 1))
            bomb.writestr("ocs.sum", b"{}")
        rejected(lambda: verify(wrong), ValueError)
        require(
            os.readlink(dest / "current") == active and not marker.exists(),
            "admission or update executed a hook or changed stored state",
        )
        return {
            "packageId": manifest["id"],
            "wholeSha256": active,
            "failedUpdates": 2,
            "concurrentInstallers": 2,
            "unexecutedMarker": True,
        }

    case(
        "install",
        "C-01.inspect C-01.data C-02.package-id core.package-distribution.paths core.package-distribution.inventory core.package-distribution.limits core.package-distribution.atomic-install core.package-distribution.authenticity core.package-distribution.no-hook",
        package,
    )

    def receipt():
        path = tmp / "receipt.json"
        cmd = [
            sys.executable,
            str(root / "reference/host.py"),
            "--manifest",
            str(root / "examples/status/ocs.json"),
            "--receipt",
            str(path),
        ]
        first = subprocess.run(cmd, capture_output=True, timeout=8, check=True)
        hello = read_json(path.read_bytes())
        require(
            read_json(first.stdout) == {"resourceId": "demo", "state": "ready"}
            and hello["outcome"] == "allowed"
            and hello["actualTarget"]["manifestDigest"] == digest(inputs["authority"])
            and hello["elapsedNs"] > 0,
            "unattributed result",
        )
        private = "fixture-private-do-not-log"
        deny = subprocess.run([*cmd, "--resource", private], capture_output=True, timeout=8)
        refused = read_json(path.read_bytes())
        require(
            deny.returncode and refused["outcome"] == "denied" and refused["actualTarget"] is None,
            "false positive attribution",
        )
        require(
            hello["requestId"] != refused["requestId"]
            and private.encode() not in path.read_bytes() + deny.stderr + deny.stdout,
            "redaction failure",
        )
        missing = subprocess.run(
            [sys.executable, str(root / "reference/host.py"), "--manifest", str(tmp / "absent")],
            capture_output=True,
            timeout=8,
        )
        require(
            missing.returncode != 0 and read_json(missing.stderr)["class"] == "FileNotFoundError",
            "missing descriptor classification",
        )
        return {"allowed": hello, "denied": refused, "missing": "FileNotFoundError"}

    case(
        "public-receipts",
        "C-10.attribution C-10.redaction B-02.attribution",
        receipt,
    )

    def diagnostic_classes():
        folder = tmp / "diagnostic-targets"
        folder.mkdir()
        manifest = folder / "ocs.json"
        program = folder / "executor.py"
        original = jsonfile("examples/status/ocs.json")
        private = "diagnostic-private-canary"
        actual = {}
        for kind in (
            "missing",
            "incompatible",
            "denied",
            "unavailable",
            "output",
            "unknown_effect",
        ):
            artifact = dict(original)
            resource = "demo"
            if kind == "incompatible":
                artifact["requiresFeatures"] = ["private.unknown/8.0"]
            if kind == "denied":
                resource = private
            manifest.write_text(json.dumps(artifact))
            if kind == "missing":
                manifest.unlink()
            if kind == "unavailable":
                program.write_text("import sys\nsys.stdin.readline()\n")
            elif kind == "unknown_effect":
                program.write_text(
                    "import json, sys\nfrom pathlib import Path\nq=json.loads(sys.stdin.readline())\n"
                    "with Path(__file__).with_name('unknown-attempts').open('a') as f: f.write('1')\n"
                    "print(json.dumps({'jsonrpc':'2.0','id':q['id'],'error':{'code':-32005,'message':"
                    + repr(private)
                    + ",'data':{'kind':'unknown_effect','operationId':'synthetic-uncertain','retryable':True,'retryAfterMs':0}}}),flush=True)\n"
                )
            else:
                program.write_text("import sys\nsys.stdin.readline()\nprint('[]', flush=True)\n")
            receipt_path = folder / (kind + ".json")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(root / "reference/host.py"),
                    "--manifest",
                    str(manifest),
                    "--resource",
                    resource,
                    "--receipt",
                    str(receipt_path),
                ],
                capture_output=True,
                timeout=8,
            )
            diagnostic = read_json(proc.stderr)
            logged = read_json(receipt_path.read_bytes())
            require(
                proc.returncode
                and not proc.stdout
                and private.encode() not in proc.stderr + receipt_path.read_bytes(),
                "refusal leaked user content or returned a successful result",
            )
            if kind == "missing":
                require(
                    diagnostic["class"] == "FileNotFoundError"
                    and logged["outcome"] == "invalid-package",
                    "missing descriptor lost diagnostic classification",
                )
            else:
                require(
                    diagnostic["data"]["kind"] == kind and logged["outcome"] == kind,
                    "disagreeing refusal classification",
                )
            actual[kind] = diagnostic.get("data", {}).get("kind", diagnostic.get("class"))
        require(len(set(actual.values())) == len(actual), "distinct diagnostic classes collapsed")
        require(
            (folder / "unknown-attempts").read_text() == "1",
            "retry hint silently reissued an uncertain call",
        )
        return {
            "publicClasses": actual,
            "sourceMessagesRedacted": True,
            "unknownWithMatchingRequestIdAndImmediateRetryHint": actual["unknown_effect"],
            "uncertainAttempts": 1,
        }

    case("diagnostic-classes", "C-10.diagnosis C-10.redaction W-07.retry", diagnostic_classes)

    def observation_authority():
        sys.path.insert(0, str(root / "reference/provider"))
        from service import ISSUER, MODEL, PRODUCT, ROUTE, Provider, Refused, timestamp

        store = tmp / "observations.db"
        source = Provider(store)
        owner, other = "observation-owner", "unrelated-owner"
        epoch = 1893456000
        product = {"provider": ISSUER, "product": PRODUCT}
        setup = {
            **product,
            "authMethod": "local-none",
            "settings": {"label": "demo", "organization": "observed-org"},
        }
        first = source.connect(owner, setup, epoch)["account"]
        second = source.connect(owner, setup, epoch)["account"]
        a, b = first["accountId"], second["accountId"]
        require(
            first["label"] == second["label"] == "demo"
            and a != b
            and first["state"] == "unverified"
            and "lastReply" not in first,
            "a label, login or inferred plan was treated as a verified reply",
        )
        for wrong in ("demo", "example.status.read", "session-for-third-party"):
            rejected(lambda key=wrong: source.windows(owner, key, epoch), Refused)
        rejected(lambda: source.windows(other, a, epoch), Refused)
        rejected(lambda: source.readback(owner, a, epoch), Refused)
        # The same byte string is a distinct context in two legitimate accounts.
        pick = {
            "route": ROUTE,
            "model": MODEL,
            "parameters": {"reasoning": "off", "tier": "standard"},
        }
        source.selected(owner, a, epoch, pick)
        answered = source.conversation(
            owner,
            {"accountId": a, "contextId": b, "text": "sky"},
            epoch + 1,
            "public-probe",
            "probe",
        )
        history = source.conversation(owner, {"accountId": a, "contextId": b}, epoch + 2)["turns"]
        require(
            answered["accountId"] == a
            and answered["model"] == MODEL
            and len(history) == 1
            and source.conversation(owner, {"accountId": b, "contextId": b}, epoch + 2)["turns"]
            == [],
            "account and conversation namespaces aliased",
        )
        checked = next(
            ac
            for ac in source.accounts(owner, product, epoch + 2)["accounts"]
            if ac["accountId"] == a
        )
        require(
            checked["state"] == "working"
            and checked["lastReply"]["model"] == MODEL
            and checked["lastReply"]["at"] == timestamp(epoch + 1),
            "successful reply did not supply dated evidence",
        )
        limits = {w["windowId"]: w for w in source.windows(owner, a, epoch + 3)["windows"]}
        require(
            limits["weekly"]["evidence"]["status"] == "verified"
            and limits["weekly"]["evidence"]["observedAt"] == timestamp(epoch + 3)
            and limits["old"]["state"] == limits["old"]["evidence"]["status"] == "stale"
            and limits["old"]["evidence"]["observedAt"] < limits["weekly"]["evidence"]["observedAt"]
            and "remaining" not in limits["optional"]
            and limits["optional"]["state"] == "unknown",
            "older or unknown observations became confirmed balances",
        )
        source.ingest_meter(
            owner, "_unattributed", "external", "u1", "observation-interval", 3, 10, epoch + 2
        )
        interval = {"from": timestamp(epoch), "to": timestamp(epoch + 4)}
        account_usage = source.usage(
            owner, {**interval, "scope": {"kind": "account", "id": a}}, epoch + 3
        )
        tenant_usage = source.usage(
            owner, {**interval, "scope": {"kind": "tenant", "id": owner}}, epoch + 3
        )
        terms = source.terms(owner, a, epoch + 3)
        retention = terms["retentionSeconds"]
        require(
            tenant_usage["attribution"] == "partial"
            and account_usage["attribution"] == "account"
            and account_usage["probeRequests"] == 1
            and account_usage["retainedUntil"] == timestamp(epoch + 3 + retention)
            and retention > 0,
            "unattributed observations crossed accounts or lacked their declared retention",
        )
        reopened = Provider(store)
        retained = reopened.usage(
            owner,
            {**interval, "scope": {"kind": "account", "id": a}},
            epoch + max(1, retention // 2),
        )
        rejected(
            lambda: reopened.usage(
                other, {**interval, "scope": {"kind": "account", "id": a}}, epoch + 4
            ),
            Refused,
        )
        require(
            retained["probeRequests"] == account_usage["probeRequests"]
            and retained["spend"] == account_usage["spend"],
            "authorized scoped observations disappeared inside the promised retention",
        )
        return {
            "unverifiedBeforeReply": first["state"],
            "inferredPlanCandidates": first["planCandidates"],
            "confirmedReply": checked["lastReply"],
            "staleObservation": limits["old"]["evidence"],
            "freshObservation": limits["weekly"]["evidence"],
            "unattributed": tenant_usage["attribution"],
            "scopedRetentionSeconds": retention,
            "retainedProbeCount": retained["probeRequests"],
            "identities": {
                "sameDisplayDistinctAccounts": a != b,
                "sameTokenScopedAsContext": len(history),
                "foreignScope": "denied",
                "accountAsOperation": "denied",
            },
        }

    case("scoped-observation-authority", "B-06.freshness C-02.object-id", observation_authority)

    def registry():
        registry = jsonfile("spec/profiles/operations.json")["operations"]
        fields = {row["method"]: row for row in registry}
        require(
            fields["quota.reset"]["channel"] == "export"
            and fields["effect.commit"]["channel"] == "control",
            "effect channel drift",
        )
        require(
            fields["ocs.chunk"]["output"] is None
            and fields["ocs.chunk"]["channel"] == "notification",
            "notification shape drift",
        )
        for row in registry:
            for key in ("input", "output"):
                if row[key] is not None:
                    REGISTRY.resolver().lookup(row[key])
        for n in ("effect.prepare", "effect.commit", "effect.readback"):
            require(fields[n]["condition"] == "baseline", "effects controls must be a set")
        candidate = jsonfile("reference/provider/ocs.json")
        check_manifest(candidate)
        supported = set(candidate["features"])
        require(
            "ocs.effects/0.1" in supported and "ocs.providers/0.1" in supported,
            "provider lost capabilities",
        )
        require(
            "ocs.platform/0.1" not in supported, "test provider incorrectly claims platform support"
        )
        return {
            "registered": len(registry),
            "declaredProfiles": sorted(supported),
            "baselineEffects": 3,
        }

    case(
        "registry-channel-contract",
        "P-01.profile P-01.control P-02.applicability interface.registry.channels interface.registry.notification interface.registry.conditional",
        registry,
    )

    def normative_shapes():
        # Independent old format and real decoder acceptance including every published error class.
        manifest = read_json(inputs["authority"])
        for field in ("format", "id", "version", "runtime", "exports"):
            broken = dict(manifest)
            del broken[field]
            rejected(lambda: validate("manifest", broken), ValidationError)
        changed = {**manifest, "extensions": {"org.example.addition": {}}}
        validate("manifest", changed)
        rejected(
            lambda: validate("manifest", {**manifest, "extensions": {"not dotted!": {}}}),
            ValidationError,
        )
        casecodes = {
            -32700: "parse",
            -32600: "request",
            -32601: "method",
            -32602: "params",
            -32603: "internal",
            -33001: "denied",
            -33004: "cancelled",
            -33005: "deadline",
            -33008: "incompatible",
            -33009: "input",
            -33014: "pin",
            -32001: "output",
            -32002: "conflict",
            -32003: "busy",
            -32004: "unavailable",
            -32005: "unknown_effect",
        }
        shape = SCHEMAS["wire"]["$defs"]["error"]["properties"]
        require(
            set(shape["code"]["enum"]) == set(casecodes)
            and set(shape["data"]["properties"]["kind"]["enum"]) == set(casecodes.values()),
            "published wire error discriminator set grew or shrank",
        )
        rejected(
            lambda: validate(
                "wire", {"code": 0, "message": "observed", "data": {"kind": "parse"}}, "error"
            ),
            ValidationError,
        )
        rejected(
            lambda: validate(
                "wire",
                {"code": -32700, "message": "observed", "data": {"kind": "unlisted"}},
                "error",
            ),
            ValidationError,
        )
        for code, kind in casecodes.items():
            value = {"code": code, "message": "observed", "data": {"kind": kind}}
            validate("wire", value, "error")
            for different in set(casecodes.values()) - {kind}:
                rejected(
                    lambda wrong=different: validate(
                        "wire", {**value, "data": {"kind": wrong}}, "error"
                    ),
                    ValidationError,
                )
        return {
            "codes": casecodes,
            "distinctInvalidPairings": len(casecodes) * (len(casecodes) - 1),
            "sealedManifestFields": 5,
            "schemaIdentity": SCHEMAS["wire"]["$id"],
            "registry": registry(),
        }

    case(
        "published-schema-boundaries",
        "C-02.package-id C-06.namespace core.schema-resources.urns wire.error-table.code-kind interface.registry.channels",
        normative_shapes,
        "schema",
    )
    case("wire-error-public-shape", "wire.error-table.code-kind", normative_shapes)

    def report_claims():
        original = read_json((oracle / "version.json").read_bytes())
        expected = read_json((root / "version.json").read_bytes())
        require(
            expected["edition"] == original["edition"] and expected["stage"] == original["stage"],
            "edition identity or release stage requires independent review",
        )
        for name in original["normative"]:
            require(
                (oracle / name).read_bytes() == (root / name).read_bytes(),
                "changed bytes of immutable edition " + name,
            )
        path = Path(os.environ.get("OCS_REFERENCE_REPORT", root / "out/conformance.json"))
        report = read_json(path.read_bytes())
        validate("report", report)
        require(
            report["suiteDigest"] == digest((root / "conformance/cases/core.json").read_bytes())
            and report["role"] == "mixed"
            and report["contracts"] == [{"operation": "example.status.read", "version": "1.0.0"}]
            and report["platform"],
            "wrong conformance subject",
        )
        require(
            all(c["status"] == "pass" for c in report["checks"]),
            "candidate conformance has failed/skipped rows",
        )
        stable = (
            Path(os.environ.get("OCS_LEGACY_REPORTS", root / "out/baseline"))
            / "6f6e22842347806f2963ef1984d9ea592fdddaf0"
        )
        results = {}
        for name in ("hosts-and-go", "python-executor"):
            old = read_json((stable / (name + ".json")).read_bytes())
            validate("report", old)
            require(
                all(r["status"] == "pass" for r in old["checks"]), "old caller missed a scenario"
            )
            require(
                any(c["id"] == "recover-after-input-error" for c in old["checks"]),
                "published recovery case missing",
            )
            results[name] = {"digest": old["suiteDigest"], "checks": len(old["checks"])}
        return {
            "edition": expected["edition"],
            "stage": expected["stage"],
            "contracts": report["contracts"],
            "wireCases": len(report["checks"]),
            "mixedVersions": results,
            "implementations": report["implementations"],
        }

    case(
        "qualify-edition",
        "C-09.refinement T-01.receipt T-01.outcome T-02.independence T-03.directions T-04.edition T-04.release",
        report_claims,
    )

    def consent_and_state():
        # Genuine cross-edition storage. A separate old process owns the first
        # transaction. The caller observes the same lost acknowledgement in
        # both cases. An out-of-band test barrier pins the point of the failure.
        sys.path.insert(0, str(root / "examples/reset"))
        from ledger import Ledger, Refused

        revision = "6f6e22842347806f2963ef1984d9ea592fdddaf0"
        old = tmp / "published-ledger"
        old.mkdir()
        source = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                str(root),
                "show",
                revision + ":examples/reset/ledger.py",
            ],
            capture_output=True,
            check=True,
        ).stdout
        (old / "ledger.py").write_bytes(source)
        writer = """
import json, os, sys
sys.path.insert(0,sys.argv[1])
from ledger import Ledger
db = Ledger(sys.argv[2])
t = 1893456000
db.add_fixture_account('owner', 'one', 1)
p = db.prepare('owner','one','key','a'*64,1,t)
db.record_approval('owner',p['operationId'],p['intentDigest'],t+1)
print(json.dumps([p['operationId'],p['intentDigest']]),flush=True)
if sys.stdin.readline().strip() != 'commit': raise SystemExit(2)
if sys.argv[3] == 'after-commit':
    db.commit('owner',p['operationId'],p['intentDigest'],'a'*64,t+2)
os.write(int(sys.argv[4]),b'R')
sys.stdin.readline()   # wait forever for a reply-permission that the harness withholds
"""
        observations = {}
        t = 1893456000
        for phase in ("before-commit", "after-commit"):
            path = tmp / (phase + ".sqlite")
            rd, wr = os.pipe()
            proc = subprocess.Popen(
                [sys.executable, "-I", "-c", writer, str(old), str(path), phase, str(wr)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(wr,),
            )
            os.close(wr)
            try:
                with selectors.DefaultSelector() as src:
                    src.register(proc.stdout, selectors.EVENT_READ)
                    require(src.select(5), "published writer did not prepare")
                    op, intent = json.loads(proc.stdout.readline())
                    proc.stdin.write(b"commit\n")
                    proc.stdin.flush()
                    with selectors.DefaultSelector() as barrier:
                        barrier.register(rd, selectors.EVENT_READ)
                        require(
                            barrier.select(5) and os.read(rd, 1) == b"R",
                            "writer missed the selected failure point",
                        )
                    start = time.monotonic_ns()
                    require(
                        not src.select(0.12), "unexpected acknowledgement before caller deadline"
                    )
                    elapsed = time.monotonic_ns() - start
            finally:
                os.close(rd)
                proc.kill()
                proc.wait(timeout=3)
                proc.stdin.close()
                proc.stdout.close()
            current = Ledger(path)
            actual = current.readback("owner", op, t + 100)
            expected = "applied" if phase == "after-commit" else "not-applied"
            expected_balance = (0, 100, 2) if phase == "after-commit" else (1, 0, 1)
            require(
                actual["operationId"] == op
                and actual["intentDigest"] == intent
                and actual["scope"] == {"kind": "account", "id": "one"}
                and actual["state"] == expected
                and current.balance("owner", "one") == expected_balance,
                "historic intent, scope or outcome changed",
            )
            rejected(lambda: current.readback("outsider", op, t + 101), Refused)
            if phase == "after-commit":
                require(
                    current.commit("owner", op, intent, "a" * 64, t + 101) == actual
                    and current.balance("owner", "one") == expected_balance,
                    "replayed archived commit charged a second time",
                )
            observations[phase] = {
                "clientObservation": "acknowledgement deadline expired",
                "waitNs": elapsed,
                "retainedOperation": op,
                "state": actual["state"],
                "balance": list(expected_balance),
            }
        return {
            "writerRevision": revision,
            "writerSourceSha256": digest(source),
            "readerSourceSha256": digest((root / "examples/reset/ledger.py").read_bytes()),
            "observations": observations,
        }

    case("durable-replayed-effect", "T-02.state T-03.restore W-04.write-timeout", consent_and_state)

    def http_admission():
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from threading import Thread

        from peer import start

        token = secrets.token_hex(24)
        manifest = root / "examples/status/ocs.json"
        with start(manifest, token) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}/ocs"
            opener = request.build_opener(request.ProxyHandler({}))
            query = {
                "jsonrpc": "2.0",
                "id": "read-1",
                "method": "ocs.describe",
                "params": {
                    "protocols": ["0.1"],
                    "requiredFeatures": [],
                    "meta": {"deadline": utc_at(time.time() + 5)},
                },
            }

            def post(blob, t=None, media="application/json"):
                headers = {"Content-Type": media}
                if t:
                    headers["Authorization"] = "Bearer " + t
                return opener.open(
                    request.Request(url, data=json.dumps(blob).encode(), headers=headers), timeout=5
                )

            try:
                with post(query, token) as reply:
                    desc = read_json(reply.read(LIMIT))
                    require(
                        desc["id"] == "read-1"
                        and desc["result"]["manifestDigest"] == digest(inputs["authority"]),
                        "wrong authenticated pin",
                    )
                for wrong, media, code in (
                    ("ungranted", "application/json", 403),
                    (token, "text/plain", 415),
                ):
                    try:
                        post(query, wrong, media)
                    except error.HTTPError as exc:
                        require(exc.code == code, "unexpected transport denial")
                    else:
                        raise AssertionError("unadmitted HTTP request reached an executor")
                note = {"jsonrpc": "2.0", "method": "ocs.cancel", "params": {"requestId": "other"}}
                with post(note, token) as reply:
                    require(
                        reply.status == 204 and reply.read() == b"",
                        "unsupported notification changed the exchange",
                    )
            finally:
                server.shutdown()
                thread.join(5)

        # Verify the actual compiled caller does not follow a redirect or forward a credential.
        class Sink(BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.seen += 1
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        class Redirect(Sink):
            def do_POST(self):
                self.server.seen += 1
                self.send_response(307)
                self.send_header("Location", self.server.location)
                self.end_headers()

        exe = tmp / "redirect-host"
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(exe), "./reference/go"],
            cwd=root,
            timeout=120,
            check=True,
        )
        with (
            HTTPServer(("127.0.0.1", 0), Sink) as sink,
            HTTPServer(("127.0.0.1", 0), Redirect) as redirect,
        ):
            redirect.location = f"http://127.0.0.1:{sink.server_port}/ocs"
            redirect.seen = sink.seen = 0
            threads = [Thread(target=s.serve_forever, daemon=True) for s in (sink, redirect)]
            for th in threads:
                th.start()
            try:
                run = subprocess.run(
                    [
                        str(exe),
                        "--manifest",
                        str(manifest),
                        "--loopback-peer",
                        f"http://127.0.0.1:{redirect.server_port}/ocs",
                    ],
                    env={**os.environ, "OCS_DEMO_TOKEN": token},
                    capture_output=True,
                    timeout=7,
                )
                require(
                    run.returncode
                    and b"307" in run.stderr
                    and redirect.seen == 1
                    and sink.seen == 0,
                    "redirect changed binding",
                )
            finally:
                sink.shutdown()
                redirect.shutdown()
                for t in threads:
                    t.join(3)
        return {
            "unauthorized": 403,
            "wrongMedia": 415,
            "notification": 204,
            "redirect": 307,
            "foreignRequests": sink.seen,
        }

    case(
        "strict-http-admission",
        "W-08.http W-08.origin interface.registry.notification",
        http_admission,
    )

    def budgets():
        exe = tmp / "ocs-host"
        subprocess.run(
            ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(exe), "./reference/go"],
            cwd=root,
            timeout=120,
            check=True,
        )
        manifest = root / "examples/status/ocs.json"
        base = [str(exe), "--manifest", str(manifest)]
        env = {**os.environ, "OCS_DEMO_TOKEN": secrets.token_hex(32)}

        def spawn():
            p = subprocess.Popen(
                [sys.executable, str(root / "reference/peer.py"), "--manifest", str(manifest)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            with selectors.DefaultSelector() as sel:
                sel.register(p.stdout, selectors.EVENT_READ)
                if not sel.select(9):
                    p.kill()
                    p.wait()
                    raise TimeoutError("peer boot")
            url = p.stdout.readline().strip()
            require(url.startswith("http://127.0.0.1:"), "unexpected peer")
            return p, url

        busy_retries = []

        def run(cmd):
            start = time.monotonic_ns()
            deadline = time.monotonic() + 5
            while True:
                q = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    timeout=max(0.01, deadline - time.monotonic()),
                )
                if q.returncode == 0:
                    require(
                        read_json(q.stdout) == {"resourceId": "demo", "state": "ready"},
                        "wrong resource or state",
                    )
                    return (time.monotonic_ns() - start) / 1e6
                reason = q.stderr.decode(errors="replace").strip()[:180]
                if "503" not in reason or time.monotonic() + 0.025 >= deadline:
                    raise AssertionError("scoped status read failed: " + reason)
                busy_retries.append(reason)
                time.sleep(0.025)

        cold = time.monotonic_ns()
        peer, url = spawn()
        coldms = (time.monotonic_ns() - cold) / 1e6
        other, otherurl = spawn()
        held = []
        try:
            remote = [*base, "--loopback-peer", url]
            local = [run(base) for _ in range(4)]
            with ThreadPoolExecutor(max_workers=4) as workers:
                samples = list(workers.map(lambda _: run(remote), range(32)))
            serverport = int(url.split(":")[2].split("/")[0])
            for n in range(4):
                s = socket.create_connection(("127.0.0.1", serverport), 2)
                s.sendall(b"POST /ocs HTTP/1.0\r\nX-Partial: ")
                held.append(s)
                if n == 0:
                    slowPeer = run(remote)
            with socket.create_connection(("127.0.0.1", serverport), 2) as s:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                busy = s.recv(256)
            require(b"503" in busy, "fifth simultaneous handler entered capacity-limited peer")
            for s in held:
                s.close()
            held.clear()
            time.sleep(0.05)
            first_result = run(remote)
            peer.terminate()
            peer.wait(timeout=5)
            restored = run([*base, "--loopback-peer", otherurl])
            require(
                max(samples) < 5000 and first_result < 5000 and restored < 5000,
                "local soft budget exceeded",
            )
            return {
                "operation": "example.status.read@1.0.0",
                "scope": "resource:demo",
                "payload": "demo",
                "samplesMs": samples,
                "p95Ms": sorted(samples)[math.ceil(0.95 * len(samples)) - 1],
                "nativeStdioMs": local,
                "slowTenantNeighborMs": slowPeer,
                "coldPeerMs": coldms,
                "firstReadAfterOverloadMs": first_result,
                "otherCellAfterLossMs": restored,
                "maximumHandlers": 4,
                "busyReadRetries": len(busy_retries),
                "overload": 503,
                "binarySha256": digest(exe.read_bytes()),
                "manifestDigest": digest(inputs["authority"]),
            }
        finally:
            for s in held:
                s.close()
            for p in (peer, other):
                if p.poll() is None:
                    p.terminate()
                    p.wait(timeout=5)
                p.stdout.close()

    case(
        "independent-cell-capacity",
        "W-03.queues B-07.limits B-07.workload L-02.partition L-04.workload L-04.tail L-04.recovery",
        budgets,
        "measurement",
    )
