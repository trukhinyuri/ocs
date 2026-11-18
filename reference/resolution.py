"""Materialize an admitted package and an assembly using bounded offline resources."""

import hashlib
import re
from copy import deepcopy
from pathlib import PurePosixPath
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

from admission import check_assembly, check_manifest, relative_name
from contracts import REGISTRY, SCHEMAS, read_json
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Resource
from referencing.jsonschema import DRAFT202012

PACKAGE_ROOT = "https://package.invalid/"
EDITION_IDS = {schema["$id"] for schema in SCHEMAS.values()}
MAX_RESOURCES = 1024
MAX_SCHEMA_BYTES = 8 * 1024 * 1024
MAX_SCHEMA_NODES = 65536


def absolute(base, ref):
    if not isinstance(ref, str) or "\\" in ref:
        raise ValueError("invalid schema reference")
    if ref.startswith("#"):
        return urldefrag(base)[0] + ref
    dest = urljoin(base, ref)
    bare, _ = urldefrag(dest)
    if bare in EDITION_IDS:
        return dest
    if not bare.startswith(PACKAGE_ROOT) or urlsplit(dest).query:
        raise ValueError("untrusted schema destination")
    parsed = urlsplit(ref)
    raw = unquote(parsed.path)
    if "\\" in raw or "\x00" in raw or re.search(r"%2[fF]|%5[cC]", parsed.path):
        raise ValueError("ambiguous schema path")
    depth = (
        0
        if parsed.scheme or raw.startswith("/")
        else len(PurePosixPath(urlsplit(base).path).parent.parts) - 1
    )
    for part in raw.split("/"):
        if part == "..":
            if depth <= 0:
                raise ValueError("schema path escapes package")
            depth -= 1
        elif part not in ("", "."):
            depth += 1
    return dest


def compiled_schema(schema, members):
    """Private registry for one embedded schema plus the exact edition resources."""
    registry = REGISTRY
    resources = {}
    uses = []
    queue = []
    visited = 0

    def insert(uri, resource):
        existing = resources.get(uri)
        if uri in EDITION_IDS or existing is not None and existing is not resource:
            raise ValueError("ambiguous schema identity")
        resources[uri] = resource

    def scan(resource, base):
        nonlocal visited
        visited += 1
        if visited > MAX_SCHEMA_NODES:
            raise ValueError("schema node budget exceeded")
        node = resource.contents
        if not isinstance(node, dict):
            return
        if (
            "$schema" in node
            and node["$schema"].rstrip("#") != "https://json-schema.org/draft/2020-12/schema"
        ):
            raise ValueError("unsupported mandatory schema dialect")
        supported_vocab = {
            "core",
            "applicator",
            "unevaluated",
            "validation",
            "meta-data",
            "format-annotation",
            "content",
        }
        for uri, mandatory in node.get("$vocabulary", {}).items():
            if mandatory and uri not in {
                "https://json-schema.org/draft/2020-12/vocab/" + v for v in supported_vocab
            }:
                raise ValueError("unsupported mandatory schema vocabulary")
        if "$id" in node:
            base = absolute(base, node["$id"])
            if "#" in base:
                raise ValueError("fragment in schema identity")
            insert(base, resource)
        for field in ("$ref", "$dynamicRef"):
            if field in node:
                uri = absolute(base, node[field])
                uses.append(uri)
                queue.append(urldefrag(uri)[0])
        for child in resource.subresources():
            scan(child, base)

    def register(value, uri):
        Draft202012Validator.check_schema(value)
        resource = Resource.from_contents(value, default_specification=DRAFT202012)
        insert(uri, resource)
        scan(resource, uri)
        return resource

    root = register(schema, PACKAGE_ROOT)
    total = 0
    while queue:
        uri = queue.pop()
        if uri in EDITION_IDS or uri in resources:
            continue
        name = unquote(uri[len(PACKAGE_ROOT) :])
        relative_name(name)
        raw = members.get(name)
        if not isinstance(raw, bytes) or len(resources) >= MAX_RESOURCES:
            raise ValueError("missing or unbounded package schema")
        total += len(raw)
        if len(raw) > MAX_SCHEMA_BYTES or total > 32 * 1024 * 1024:
            raise ValueError("schema resource bytes exceeded")
        register(read_json(raw), uri)
    registry = registry.with_resources(resources.items()).crawl()
    for uri in uses:
        registry.resolver().lookup(uri)
    target = absolute(PACKAGE_ROOT, root.id()) if root.id() is not None else PACKAGE_ROOT
    return Draft202012Validator({"$ref": target}, registry=registry, format_checker=FormatChecker())


def available_exports(packages, edges):
    """Resolve declared per-export dependencies to a least fixed point of usable exports.

    The opt-in reference extension declares an exact import version and scope
    for each dependent export. It can restrict behavior only within admitted
    assembly edges. It supplies neither a destination nor an additional grant.

    Each entry in manifest.extensions["org.example.operation-imports"] has
    the form {"operation": "example.enriched.read", "version": "1.0.0",
    "needs": [{"operation": "example.lookup.read", "version": "1.0.0",
    "scope": "resource:demo"}]}. The bind result omits unavailable targets
    from its directional bindings and identifies their missing scope in
    unavailableExports. The ready queue prevents optional cycles from
    supplying their own prerequisites.
    """
    lookup = {
        (e["caller"], e["operation"], e["version"], e["scope"]): (
            e["receiver"],
            e["operation"],
            e["version"],
        )
        for e in edges
    }
    prerequisites = {}
    for instance, descriptor in packages.items():
        imports = {(i["id"], i["version"]) for i in descriptor.get("imports", [])}
        exports = {(o["id"], o["version"]) for o in descriptor["exports"]}
        for operation, version in exports:
            prerequisites[instance, operation, version] = []
        rules = descriptor.get("extensions", {}).get("org.example.operation-imports", [])
        if not isinstance(rules, list):
            raise ValueError("invalid per-export dependency list")
        declared = set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {"operation", "version", "needs"}:
                raise ValueError("invalid dependent export")
            pair = (rule["operation"], rule["version"])
            if not all(isinstance(x, str) for x in pair) or pair not in exports or pair in declared:
                raise ValueError("missing or duplicate dependent export")
            declared.add(pair)
            needs = rule["needs"]
            if not isinstance(needs, list):
                raise ValueError("invalid per-export prerequisites")
            seen = set()
            for dep in needs:
                if not isinstance(dep, dict) or set(dep) != {"operation", "version", "scope"}:
                    raise ValueError("invalid per-export prerequisite")
                contract = (dep["operation"], dep["version"])
                scope = dep["scope"]
                if (
                    not all(isinstance(x, str) for x in contract)
                    or contract not in imports
                    or not isinstance(scope, str)
                    or not scope
                ):
                    raise ValueError("undeclared dependency or missing scope")
                key = (instance, *contract, scope)
                if key in seen:
                    raise ValueError("duplicate scoped prerequisite")
                seen.add(key)
                prerequisites[instance, *pair].append(key)
    remaining = {output: len(needed) for output, needed in prerequisites.items()}
    dependents = {output: [] for output in prerequisites}
    for output, needed in prerequisites.items():
        for key in needed:
            target = lookup.get(key)
            if target is not None:
                dependents[target].append(output)
    ready = [output for output, count in remaining.items() if count == 0]
    available = set()
    while ready:
        target = ready.pop()
        available.add(target)
        for dependent in dependents[target]:
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                ready.append(dependent)
    active_edges = [e for e in edges if (e["receiver"], e["operation"], e["version"]) in available]
    usable_imports = {(e["caller"], e["operation"], e["version"]) for e in active_edges}
    for instance, p in packages.items():
        if any(
            (instance, i["id"], i["version"]) not in usable_imports
            for i in p.get("imports", [])
            if not i.get("optional", False)
        ):
            raise ValueError("required import has no usable export")
    unavailable = [
        {
            "instance": ins,
            "operation": name,
            "version": ver,
            "missing": [
                {"operation": d[1], "version": d[2], "scope": d[3]}
                for d in needed
                if lookup.get(d) not in available
            ],
        }
        for (ins, name, ver), needed in sorted(prerequisites.items())
        if (ins, name, ver) not in available
    ]
    return active_edges, unavailable


def bind(assembly, manifests, authorities, available_features=(), package_members=None):
    """Return reviewed directional edges. Required activation cycles fail at admission."""
    check_assembly(assembly)
    packages = {}
    for instance in assembly["instances"]:
        key = instance["instance"]
        raw = manifests.get(key)
        if raw is None or hashlib.sha256(raw).hexdigest() != instance["manifestDigest"]:
            raise ValueError("missing descriptor or incorrect pin")
        manifest = read_json(raw)
        check_manifest(manifest)
        members = (package_members or {}).get(key, {})
        for operation in manifest["exports"]:
            for field in ("inputSchema", "outputSchema"):
                compiled_schema(operation[field], members)
        trust = authorities.get(key)
        if (
            not trust
            or not trust.get("issuer")
            or any(
                trust.get(field) != instance[field]
                for field in ("domain", "packageId", "packageVersion", "manifestDigest")
            )
        ):
            raise ValueError("untrusted issuer or domain binding")
        if set(manifest.get("needs", ())) - set(trust.get("capabilities", ())):
            raise ValueError("requested capability was not granted")
        if manifest["runtime"]["binding"] != "data" and (
            trust.get("executionPolicy") != "reviewed-local" or trust.get("requiresConfinement")
        ):
            raise ValueError("sealed host cannot provide requested executable confinement")
        for public in manifest["exports"]:
            if public["id"] == "quota.reset" and public["effect"] != "external-write":
                raise ValueError("declared reset effect contradicts the public contract")
        if (manifest["id"], manifest["version"]) != (
            instance["packageId"],
            instance["packageVersion"],
        ):
            raise ValueError("unbound package identity")
        if set(manifest.get("requiresFeatures", ())) - set(available_features):
            raise ValueError("unavailable mandatory feature")
        packages[key] = manifest
    graph = {instance: set() for instance in packages}
    satisfied = {instance: set() for instance in packages}
    for edge in assembly["edges"]:
        pair = (edge["operation"], edge["version"])
        src, dst = edge["caller"], edge["receiver"]
        imported = next(
            (i for i in packages[src].get("imports", []) if (i["id"], i["version"]) == pair), None
        )
        exported = next(
            (o for o in packages[dst]["exports"] if (o["id"], o["version"]) == pair), None
        )
        if imported is None or exported is None or exported["effect"] not in edge["grantedEffects"]:
            raise ValueError("missing export, declared import or effect grant")
        satisfied[src].add(pair)
        if not imported.get("optional", False):
            graph[src].add(dst)
    for src, manifest in packages.items():
        needed = {
            (i["id"], i["version"])
            for i in manifest.get("imports", [])
            if not i.get("optional", False)
        }
        if needed - satisfied[src]:
            raise ValueError("unresolved required import")
    # Kahn's algorithm avoids recursion even in a long dependency chain.
    parents = {k: set() for k in graph}
    for src, deps in graph.items():
        for dep in deps:
            parents[dep].add(src)
    counts = {k: len(v) for k, v in graph.items()}
    ready = [k for k, v in counts.items() if v == 0]
    order = []
    while ready:
        node = ready.pop()
        order.append(node)
        for parent in sorted(parents[node]):
            counts[parent] -= 1
            if counts[parent] == 0:
                ready.append(parent)
    if len(order) != len(packages):
        raise ValueError("unresolvable required activation cycle")
    rank = {node: number for number, node in enumerate(order)}
    if any(rank[dst] >= rank[src] for src, deps in graph.items() for dst in deps):
        raise ValueError("invalid activation rank witness")
    active_edges, unavailable = available_exports(packages, assembly["edges"])
    return {
        "activationOrder": order,
        "bindings": deepcopy(active_edges),
        "unavailableExports": unavailable,
        "issuers": {key: authorities[key]["issuer"] for key in packages},
        "descriptors": deepcopy(packages),
    }


def compatible_replacement(previous, candidate):
    """Preserve the sealed contract when replacing a reviewed component."""
    check_manifest(previous)
    check_manifest(candidate)
    if candidate["id"] != previous["id"] or set(candidate.get("needs", ())) - set(
        previous.get("needs", ())
    ):
        raise ValueError("replacement identity or permission requires review")
    if set(candidate.get("requiresFeatures", ())) - set(previous.get("requiresFeatures", ())):
        raise ValueError("replacement adds a required dependency")
    exports = {(op["id"], op["version"]): op for op in candidate["exports"]}
    for old in previous["exports"]:
        new = exports.get((old["id"], old["version"]))
        if new is None or any(
            old.get(field) != new.get(field)
            for field in ("effect", "flags", "inputSchema", "outputSchema")
        ):
            raise ValueError("public contract requires migration or reviewed refinement")
    return deepcopy(candidate)


def forward_operation_contract(source, receiver, negotiated_features):
    """Return an opaque-preserving snapshot after an exact, lossless contract check.

    This local adapter accepts matching wire representations. The receiving
    binding supplies the actually negotiated feature set. Opaque data is copied
    independently of the receiver's labels. Authentication of the package and
    any later dispatch remain separate host decisions.
    """
    if source.get("version") != receiver.get("version"):
        raise ValueError("the exact package revision cannot be represented")
    compatible_replacement(source, receiver)
    if set(source.get("needs", ())) != set(receiver.get("needs", ())):
        raise ValueError("the essential declared authority cannot be preserved")
    if (set(source.get("requiresFeatures", ())) | set(receiver.get("requiresFeatures", ()))) - set(
        negotiated_features
    ):
        raise ValueError("destination cannot interpret a required representation")
    return deepcopy(source)
