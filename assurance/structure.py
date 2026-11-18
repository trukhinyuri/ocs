"""Index normative declarations separately from evidence of their implementation."""

import hashlib
import json
import re

META = {"$comment", "title", "description", "examples", "default", "deprecated"}
MAP_OF_SCHEMAS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
LIST_OF_SCHEMAS = {"allOf", "anyOf", "oneOf", "prefixItems"}
ONE_SCHEMA = {
    "not",
    "if",
    "then",
    "else",
    "items",
    "contains",
    "propertyNames",
    "additionalProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contentSchema",
}
EXTRA = {
    ("spec/core.md", "Schema resources"): "core.schema-resources",
    ("spec/core.md", "Packaging and distribution"): "core.package-distribution",
    ("spec/composition.md", "Calling an import from inside an extension"): "composition.outbound",
    ("spec/composition.md", "Deployment choices"): "composition.deployment",
    ("spec/core.md", "Reading a requirement"): "core.interpretation",
    ("spec/core.md", "Roles"): "C-02",
    ("spec/profiles/interfaces.md", "Using the optional operation registry"): "interface.registry",
    ("spec/profiles/interfaces.md", "Intent equality"): "interface.intent",
    ("spec/profiles/interfaces.md", "Network streams"): "interface.http-stream",
    ("spec/profiles/interfaces.md", "Catalog pages"): "interface.pages",
}
INTRO = {
    "spec/core.md": "C-02",
    "spec/wire.md": "W-05",
    "spec/conformance.md": "T-01",
    "spec/composition.md": "B-01",
    "spec/profiles/README.md": "P-01",
    "spec/profiles/providers.md": "A-01",
}


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def schema_items(schema, path=""):
    # Keywords occur in schema positions only. Object member names inside a const
    # or sample are values, even when they resemble a validation keyword.
    if isinstance(schema, bool):
        yield path or "/", schema
        return
    if not schema:
        yield (path or "/") + "/@empty", {}
    for key, value in schema.items():
        where = path + "/" + pointer(key)
        if key in META:
            continue
        if key in MAP_OF_SCHEMAS:
            for name, sub in value.items():
                yield where + "/" + pointer(name) + "/@member", name
                yield from schema_items(sub, where + "/" + pointer(name))
        elif key in LIST_OF_SCHEMAS:
            yield where + "/@length", len(value)
            for i, sub in enumerate(value):
                yield from schema_items(sub, where + "/" + str(i))
        elif key in ONE_SCHEMA:
            yield from schema_items(value, where)
        elif key in ("required", "enum"):
            yield where + "/@length", len(value)
            for member in value:
                suffix = pointer(member) if key == "required" else fingerprint(member)
                yield where + "/" + suffix, member
        else:
            yield where, value


def inventory(root, catalog):
    edition = json.loads((root / "version.json").read_bytes())
    items = {}

    def emit(key, kind, locator, value, owner):
        if key in items:
            raise ValueError("repeated normative locator " + key)
        items[key] = {"kind": kind, "source": locator, "sha256": fingerprint(value), "owner": owner}

    for file in edition["normative"]:
        path = root / file
        if file.startswith("schemas/"):
            doc = json.loads(path.read_bytes())
            for pos, value in schema_items(doc):
                emit(
                    file + "#" + pos,
                    "schema-declaration",
                    file + "#" + pos,
                    value,
                    "edition-schema",
                )
        elif file.endswith("operations.json"):
            data = json.loads(path.read_bytes())
            for op in data["operations"]:
                for field, value in op.items():
                    name = op["method"] + "/" + field
                    emit(
                        "operation/" + name,
                        "registered-operation",
                        file + "#" + op["method"],
                        value,
                        op["profile"],
                    )
        elif file.endswith("index.json"):
            data = json.loads(path.read_bytes())
            for profile in data["profiles"]:
                for field, value in profile.items():
                    emit(
                        "profile/" + profile["id"] + "/" + field,
                        "profile-declaration",
                        file + "#" + profile["id"],
                        value,
                        profile["id"],
                    )
        elif file.endswith(".md"):
            group = INTRO.get(file)
            heading = ""
            fence = False
            serial = {}
            for line_no, raw in enumerate(path.read_text().splitlines(), 1):
                line = raw.strip()
                if line.startswith("\x60\x60\x60"):
                    fence = not fence
                    continue
                if fence or not line:
                    continue
                if line.startswith("#"):
                    heading = line.lstrip("# ")
                    group = EXTRA.get((file, heading), group)
                    continue
                if heading in ("Informative references", "Run the checks"):
                    continue
                if line.startswith("|") and (
                    "---" in line or "Code | Kind" in line or "Feature | Required" in line
                ):
                    continue
                match = re.match(r"(?:- )?\*\*([A-Z]-[0-9]{2})\b", line)
                if match:
                    group = match[1]
                if file == "spec/wire.md" and line.startswith("|"):
                    group = "wire.error-table"
                if line.startswith("This example uses"):
                    continue
                if group not in catalog["groups"]:
                    raise ValueError(f"unclassified normative paragraph {file}:{line_no}")
                serial[group] = serial.get(group, 0) + 1
                key = f"prose/{group}/{serial[group]}"
                emit(key, "normative-paragraph", file + ":" + str(line_no), line, group)
    return items


def compare(accepted, candidate):
    failures = []
    for key, old in accepted.items():
        now = candidate.get(key)
        if now is None:
            failures.append("removed normative item " + key)
        elif (old["kind"], old["sha256"], old["owner"]) != (
            now["kind"],
            now["sha256"],
            now["owner"],
        ):
            failures.append("changed supported normative item " + key)
    accepted_files = {x.split("#", 1)[0] for x in accepted if x.startswith("schemas/")}
    new = candidate.keys() - accepted.keys()
    for key in sorted(new):
        if not key.startswith("schemas/") or key.split("#", 1)[0] not in accepted_files:
            continue
        # An independently named definition has no effect until a consumer refers
        # to it. New URI identities/anchors may change existing resolution.
        name = re.match(r"^(.+?/\$defs/[^/]+)(?:/|$)", key)
        if name and name[1] + "/@member" in new:
            if not any(
                k.startswith(name[1] + "/") and k.endswith(("/$id", "/$anchor", "/$dynamicAnchor"))
                for k in new
            ):
                continue
        field = re.match(r"^(.+?)/properties/([^/]+)(?:/|$)", key)
        if field:
            parent = field[1]
            stem = parent + "/properties/" + field[2]
            if stem + "/@member" in new:
                contents = {
                    k[len(stem) :]: candidate[k]["sha256"]
                    for k in new
                    if k == stem or k.startswith(stem + "/")
                }
                contents.pop("/@member", None)
                old_extra = accepted.get(parent + "/additionalProperties")
                if (old_extra is None or old_extra["sha256"] == fingerprint(True)) and contents in (
                    {"/@empty": fingerprint({})},
                    {"": fingerprint(True)},
                ):
                    continue
        failures.append("additional constraint on a supported schema " + key)
    return failures
