"""Portable package names under the reviewed archive and local schema policies."""

import re
import unicodedata


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
