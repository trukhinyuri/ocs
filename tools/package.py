#!/usr/bin/env python3
"""Build and inspect a portable development package without executing it."""

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from admission import check_manifest, check_names
from contracts import read_json

MAX_FILES = 1024
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 2 * 1024 * 1024
INDEX = "ocs.sum"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_contents(files):
    if "ocs.json" not in files:
        raise ValueError("missing root manifest")
    check_manifest(read_json(files["ocs.json"]), files)
    return {name: digest(files[name]) for name in sorted(files)}


def bounded_read(stream, remaining):
    limit = min(MAX_FILE, remaining)
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("package exceeds the file or total byte limit")
    return data


def source_files(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("expected a package directory")
    files = {}
    remaining = MAX_TOTAL
    for path in directory.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("package source contains a non-regular file")
        name = path.relative_to(directory).as_posix()
        if name == INDEX or len(files) + 2 > MAX_FILES:
            raise ValueError("reserved source path or file count exceeded")
        with path.open("rb") as stream:
            files[name] = bounded_read(stream, remaining)
        remaining -= len(files[name])
    checksums = checked_contents(files)
    files[INDEX] = (json.dumps(checksums, indent=2, sort_keys=True) + "\n").encode()
    if len(files[INDEX]) > min(MAX_FILE, remaining):
        raise ValueError("checksum index exceeds the byte limit")
    check_names(files)
    return files


def pack(directory, output):
    directory, output = Path(directory), Path(output)
    if output.resolve().is_relative_to(directory.resolve()):
        raise ValueError("choose an output outside the package source")
    files = source_files(directory)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
        staged = Path(handle.name)
    try:
        with ZipFile(staged, "w", compression=ZIP_STORED) as archive:
            for name, data in sorted(files.items()):
                info = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data)
        verify(staged)
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)


def verify(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive size or type outside the supported limits")
    with ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("too many package entries")
        names = [entry.orig_filename for entry in entries]
        check_names(names)
        if INDEX not in names or "ocs.json" not in names:
            raise ValueError("missing manifest or checksum index")
        files = {}
        remaining = MAX_TOTAL
        for entry in entries:
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (
                entry.is_dir()
                or mode not in (0, stat.S_IFREG)
                or entry.flag_bits & 1
                or entry.compress_type not in (ZIP_STORED, ZIP_DEFLATED)
            ):
                raise ValueError("unsupported archive entry")
            if entry.file_size > min(MAX_FILE, remaining) or entry.compress_size > MAX_ARCHIVE:
                raise ValueError("package size limit exceeded")
            with archive.open(entry) as stream:
                data = bounded_read(stream, remaining)
            if len(data) != entry.file_size:
                raise ValueError("archive size mismatch")
            files[entry.filename] = data
            remaining -= len(data)
        index = read_json(files.pop(INDEX))
        if index != checked_contents(files):
            raise ValueError("package membership or checksum mismatch")
        return read_json(files["ocs.json"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="inspect an existing package")
    parser.add_argument("path", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    if args.verify == (args.output is not None):
        parser.error("use SOURCE OUTPUT to build, or --verify ARCHIVE to inspect")
    try:
        if args.verify:
            manifest = verify(args.path)
            print(f"{manifest['id']}@{manifest['version']} verified")
        else:
            pack(args.path, args.output)
            print(args.output)
    except (OSError, ValueError, BadZipFile, SchemaError, ValidationError) as exc:
        parser.exit(1, f"invalid package: {exc}\n")


if __name__ == "__main__":
    main()
