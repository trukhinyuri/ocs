"""A bounded, private Draft 2020-12 resolver over admitted package bytes."""

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

from contracts import REGISTRY, SCHEMAS, read_json
from jsonschema import Draft202012Validator, FormatChecker
from package_paths import relative_name
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
