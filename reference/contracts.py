"""Offline schema registry and strict JSON reader used by the development host."""

import datetime as dt
import json
import math
import time
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1_048_576


def unique(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate object member")
        data[key] = value
    return data


def read_json(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")
    value = json.loads(raw, object_pairs_hook=unique)

    def portable(v):
        if isinstance(v, str):
            v.encode("utf-8", errors="strict")
        elif type(v) is int and abs(v) > (1 << 53) - 1:
            raise ValueError("nonportable integer")
        elif isinstance(v, float) and (
            not math.isfinite(v) or (v.is_integer() and abs(v) > (1 << 53) - 1)
        ):
            raise ValueError("nonportable number")
        elif isinstance(v, dict):
            for k, item in v.items():
                portable(k)
                portable(item)
        elif isinstance(v, list):
            for item in v:
                portable(item)

    portable(value)
    return value


SCHEMAS = {}
REGISTRY = Registry()
for path in sorted((ROOT / "schemas").glob("*.schema.json")):
    schema = read_json(path.read_bytes())
    name = path.name.removesuffix(".schema.json")
    SCHEMAS[name] = schema
    REGISTRY = REGISTRY.with_resource(schema["$id"], Resource.from_contents(schema))


def validate_with(schema, instance):
    Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker()).validate(
        instance
    )


def validate(name, instance, definition=None):
    schema = SCHEMAS[name]
    if definition:
        schema = {"$ref": schema["$id"] + "#/$defs/" + definition}
    validate_with(schema, instance)


def utc_at(seconds):
    return (
        dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def now():
    return utc_at(time.time())


def pointer(error):
    return "".join("/" + str(k).replace("~", "~0").replace("/", "~1") for k in error.absolute_path)
