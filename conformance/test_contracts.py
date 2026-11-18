"""Check public artifacts, schema identities, bindings and profile examples."""

import copy
import hashlib
import re
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from admission import check_assembly, check_manifest
from contracts import REGISTRY, SCHEMAS, read_json, validate


def load(path):
    return read_json((ROOT / path).read_bytes())


def references(value):
    if isinstance(value, dict):
        if "$ref" in value:
            yield value["$ref"]
        for child in value.values():
            yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


class ContractTests(unittest.TestCase):
    def test_edition_contains_every_normative_file(self):
        edition = load("version.json")
        expected = {
            str(p.relative_to(ROOT))
            for folder in ("spec", "schemas")
            for p in (ROOT / folder).rglob("*")
            if p.is_file()
        }
        self.assertEqual(expected, set(edition["normative"]))
        self.assertEqual(len(expected), len(edition["normative"]))
        self.assertEqual(edition["license"], "Apache-2.0")
        self.assertEqual(
            edition["schemaResources"],
            {f"schemas/{key}.schema.json": schema["$id"] for key, schema in SCHEMAS.items()},
        )

    def test_schema_dialect_and_every_reference_offline(self):
        identifiers = {v["$id"] for v in SCHEMAS.values()}
        self.assertEqual(len(identifiers), len(SCHEMAS))
        for schema in SCHEMAS.values():
            Draft202012Validator.check_schema(schema)
            for ref in references(schema):
                uri = schema["$id"] + ref if ref.startswith("#") else ref
                with self.subTest(uri=uri):
                    REGISTRY.resolver().lookup(uri)

    def test_public_profiles_and_operation_schemas(self):
        profiles = load("spec/profiles/index.json")["profiles"]
        rows = load("spec/profiles/operations.json")["operations"]
        expected = set()
        for profile in profiles:
            pid = profile["id"]
            validate("common", pid, "feature")
            self.assertTrue((ROOT / "spec/profiles" / profile["document"]).is_file())
            for record in profile["records"]:
                self.assertIn(record, SCHEMAS["profile-data"]["$defs"])
            expected |= {(pid, name, True) for name in profile["controlMethods"]}
            expected |= {(pid, name, False) for name in profile["domainOperations"]}
        self.assertEqual(
            expected, {(r["profile"], r["method"], r["channel"] != "export") for r in rows}
        )
        self.assertEqual(len(rows), len({r["method"] for r in rows}))
        for row in rows:
            for k in ("input", "output"):
                if row[k] is not None:
                    REGISTRY.resolver().lookup(row[k])
            self.assertEqual(row["output"] is None, row["channel"] == "notification")

    def test_record_corpus(self):
        index = load("examples/records/index.json")
        self.assertEqual(
            set(index),
            {p.name for p in (ROOT / "examples/records").glob("*.json") if p.name != "index.json"},
        )
        for name, definition in index.items():
            with self.subTest(name=name):
                validate("profile-data", load("examples/records/" + name), definition)

    def test_static_bindings_pin_actual_packages_and_contracts(self):
        assembly = load("examples/peer/assembly.json")
        check_assembly(assembly)
        descriptors = {}
        for instance, path in zip(
            assembly["instances"],
            ("examples/workflow/ocs.json", "examples/status/ocs.json"),
            strict=True,
        ):
            raw = (ROOT / path).read_bytes()
            desc = read_json(raw)
            check_manifest(desc, {p.name for p in (ROOT / path).parent.iterdir() if p.is_file()})
            self.assertEqual(instance["manifestDigest"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(
                (instance["packageId"], instance["packageVersion"]), (desc["id"], desc["version"])
            )
            descriptors[instance["instance"]] = desc
        (edge,) = assembly["edges"]
        (imp,) = descriptors[edge["caller"]]["imports"]
        (op,) = descriptors[edge["receiver"]]["exports"]
        self.assertEqual((imp["id"], imp["version"]), (edge["operation"], edge["version"]))
        self.assertEqual((op["id"], op["version"]), (imp["id"], imp["version"]))
        self.assertEqual(edge["grantedEffects"], [op["effect"]])
        for change in ("absent", "ambiguous", "collision"):
            bad = copy.deepcopy(assembly)
            if change == "absent":
                bad["edges"][0]["receiver"] = "gone"
            elif change == "ambiguous":
                bad["edges"].append(bad["edges"][0])
            else:
                bad["instances"].append(bad["instances"][0])
            with self.assertRaises(ValueError):
                check_assembly(bad)

    def test_data_packages_and_duplicate_exports(self):
        data = load("examples/workflow/ocs.json")
        check_manifest(data, {"workflow.md"})
        bad = load("examples/status/ocs.json")
        with self.assertRaises(ValueError):
            check_manifest(data, set())
        with self.assertRaises(ValidationError):
            check_manifest({**data, "exports": bad["exports"]})
        with self.assertRaises(ValidationError):
            check_manifest({**bad, "exports": []})
        with self.assertRaises(ValueError):
            check_manifest({**bad, "exports": bad["exports"] * 2})

    def test_portability_of_identifiers_times_and_numbers(self):
        for version in ("0.0.0", "2.3.1-rc.1+build.004", "1.0.0-001word"):
            validate("common", version, "version")
        for version in ("v1.2.3", "2.0.1-x.00", "01.2.3", "1.0.0\n"):
            with self.assertRaises(ValidationError):
                validate("common", version, "version")
        for stamp in ("2030-02-30T00:00:00.000Z", "2030-01-01T00:00:00Z"):
            with self.assertRaises(ValidationError):
                validate("common", stamp, "timestamp")
        for raw in (
            b'{"v":1,"v":2}',
            b"1e90",
            b"9007199254740992.0",
            b"NaN",
            b'"\\ud800"',
            b"\xef\xbb\xbf{}",
        ):
            with self.assertRaises(ValueError):
                read_json(raw)

    def test_provider_unavailable_price_quota_and_page(self):
        zero = load("examples/records/exhausted-quota.json")
        self.assertEqual(zero["remaining"], "0")
        unknown = load("examples/records/unknown-quota.json")
        price = load("examples/records/published-price.json")
        catalog = load("examples/records/catalog.json")
        invalid = [
            (dict(unknown, remaining="0"), "quotaWindow"),
            (dict(price, status="unknown"), "price"),
            (dict(catalog, complete=False), "catalog"),
            (dict(catalog, nextPageToken="cursor"), "catalog"),
        ]
        for value, definition in invalid:
            with self.assertRaises(ValidationError):
                validate("profile-data", value, definition)
        validate(
            "profile-data",
            {
                **catalog,
                "complete": False,
                "reason": "another page exists",
                "nextPageToken": "cursor",
            },
            "catalog",
        )
        del catalog["models"][0]["eol"]["source"]
        with self.assertRaises(ValidationError):
            validate("profile-data", catalog, "catalog")

    def test_effect_key_receipt_and_platform_qualification(self):
        params = {
            "operation": "quota.reset",
            "version": "1.0.0",
            "input": {},
            "meta": {
                "protocol": "0.1",
                "deadline": "2030-01-01T00:00:00.000Z",
                "manifestDigest": "a" * 64,
            },
        }
        with self.assertRaises(ValidationError):
            validate("profile-wire", params, "prepareParams")
        params["meta"]["idempotencyKey"] = "fixed"
        validate("profile-wire", params, "prepareParams")
        receipt = load("examples/records/uncertain-effect.json")
        with self.assertRaises(ValidationError):
            validate("profile-data", {**receipt, "result": {"data": "ready"}}, "effectReceipt")
        native = load("examples/records/platform.json")
        with self.assertRaises(ValidationError):
            validate("profile-data", {**native, "timing": "hard-deadline"}, "platform")
        validate(
            "profile-data",
            {
                **native,
                "timing": "hard-deadline",
                "worstCaseUs": 50,
                "qualification": "sealed timing fixture",
            },
            "platform",
        )

    def test_document_links_and_requirement_ids(self):
        top = list(ROOT.glob("*.md"))
        paths = top + [
            p
            for d in ("spec", "examples", "docs", "conformance", "proposals", "reference")
            for p in (ROOT / d).rglob("*.md")
        ]
        ids = []
        for path in paths:
            body = path.read_text()
            if ROOT / "spec" in path.parents:
                ids.extend(re.findall(r"\*\*([A-Z]-[0-9]{2})\b", body))
            for url in re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", body):
                if url.startswith(("https://", "http://", "#")):
                    continue
                name, _, fragment = url.partition("#")
                linked = (path.parent / name).resolve()
                with self.subTest(source=path.name, link=url):
                    self.assertTrue(linked.is_relative_to(ROOT) and linked.exists())
                    if fragment.startswith("/$defs/") and linked.is_file():
                        self.assertIn(
                            fragment.removeprefix("/$defs/"),
                            read_json(linked.read_bytes())["$defs"],
                        )
        self.assertEqual(len(ids), len(set(ids)))
        cases = load("conformance/cases/core.json")
        self.assertTrue({case["rule"] for case in cases} <= set(ids))
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
