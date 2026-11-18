"""Shared offline package and binding admission."""

from collections.abc import Mapping

from contracts import validate
from jsonschema.exceptions import SchemaError
from package_paths import check_names as check_names
from package_paths import relative_name
from referencing.exceptions import Unresolvable
from schema_resources import compiled_schema


def check_manifest(descriptor, files=None, *, schema_resources=None):
    validate("manifest", descriptor)
    for field in ("exports", "imports"):
        declared = descriptor.get(field, [])
        keys = {(item["id"], item["version"]) for item in declared}
        if len(keys) != len(declared):
            raise ValueError("duplicate contract in " + field)
    resources = (
        schema_resources
        if schema_resources is not None
        else files
        if isinstance(files, Mapping)
        else {}
    )
    for operation in descriptor["exports"]:
        if operation["id"] == "quota.reset" and operation["effect"] != "external-write":
            raise ValueError("declared reset effect contradicts the public contract")
        for field in ("inputSchema", "outputSchema"):
            try:
                compiled_schema(operation[field], resources)
            except (Unresolvable, SchemaError) as exc:
                raise ValueError("invalid or unresolved public schema") from exc
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
