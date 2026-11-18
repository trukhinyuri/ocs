"""Materialize an admitted package and an assembly using bounded offline resources."""

import hashlib
from copy import deepcopy

from admission import check_assembly, check_manifest
from contracts import read_json
from schema_resources import compiled_schema as compiled_schema


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
        check_manifest(manifest, schema_resources=(package_members or {}).get(key, {}))
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
