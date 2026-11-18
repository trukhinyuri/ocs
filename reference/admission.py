"""Offline checks shared by the development host and the package reader."""

import re
import unicodedata

from contracts import validate
from jsonschema import Draft202012Validator


def relative_name(name):
    parts = name.split("/")
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or any(part in ("", ".", "..") or part.endswith((" ", ".")) for part in parts)
        or any(ord(ch) < 32 or ch in ':<>|"?*' for ch in name)
        or any(
            re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])", part.split(".")[0], re.I)
            for part in parts
        )
    ):
        raise ValueError("invalid package-relative name")
    return parts


def check_names(names):
    spellings = {}
    paths = set()
    directories = set()
    for name in names:
        parts = relative_name(name)
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            key = unicodedata.normalize("NFC", prefix).casefold()
            if spellings.setdefault(key, prefix) != prefix:
                raise ValueError("case-colliding package paths")
            if length < len(parts):
                directories.add(prefix)
        if name in paths:
            raise ValueError("duplicate package entry")
        paths.add(name)
    if paths & directories:
        raise ValueError("regular file used as a package directory")


def check_manifest(descriptor, files=None):
    validate("manifest", descriptor)
    for field in ("exports", "imports"):
        declared = descriptor.get(field, [])
        keys = {(item["id"], item["version"]) for item in declared}
        if len(keys) != len(declared):
            raise ValueError("duplicate contract in " + field)
    for operation in descriptor["exports"]:
        for field in ("inputSchema", "outputSchema"):
            Draft202012Validator.check_schema(operation[field])
    entry = descriptor["runtime"].get("entry")
    if entry is not None:
        relative_name(entry)
        if files is not None and entry not in files:
            raise ValueError("entry absent from package")


def check_assembly(assembly):
    validate("assembly", assembly)
    ids = {instance["instance"] for instance in assembly["instances"]}
    if len(ids) != len(assembly["instances"]):
        raise ValueError("duplicate instance")
    selected = set()
    for edge in assembly["edges"]:
        if edge["caller"] not in ids or edge["receiver"] not in ids:
            raise ValueError("unknown binding endpoint")
        key = (edge["caller"], edge["operation"], edge["version"], edge["scope"])
        if key in selected:
            raise ValueError("ambiguous binding for this contract and scope")
        selected.add(key)
