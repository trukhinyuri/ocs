#!/usr/bin/env python3
"""Build and inspect a portable development package without executing it."""

import argparse
import hashlib
import hmac
import io
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
from resolution import compiled_schema

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
    manifest = read_json(files["ocs.json"])
    check_manifest(manifest, files)
    for op in manifest["exports"]:
        for field in ("inputSchema", "outputSchema"):
            compiled_schema(op[field], files)
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
    with path.open("rb") as stream:
        return read_json(inspect_archive(stream)["ocs.json"])


def inspect_archive(stream):
    with ZipFile(stream) as archive:
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
        return files


def install(archive, directory, expected_digest):
    """Atomically activate a verified archive in an owner-private package store."""
    archive, directory = Path(archive), Path(directory)
    with archive.open("rb") as stream:
        raw = stream.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE or not hmac.compare_digest(digest(raw), expected_digest):
        raise ValueError("whole-package pin mismatch")
    files = inspect_archive(io.BytesIO(raw))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        staged = Path(tmp) / "release"
        staged.mkdir(mode=0o700)
        for name, data in files.items():
            target = staged / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
        published = directory / expected_digest
        try:
            staged.rename(published)
        except OSError:
            if published.is_symlink() or not published.is_dir():
                raise
            members = source_files(published)
            members.pop(INDEX)
            if members != files:
                raise ValueError("immutable installed revision differs")
        pointer = Path(tmp) / "pointer"
        pointer.symlink_to(expected_digest)
        os.replace(pointer, directory / "current")
    return read_json(files["ocs.json"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install",
        metavar="WHOLE_PACKAGE_SHA256",
        help="install into private OUTPUT under the selected pin",
    )
    parser.add_argument("--verify", action="store_true", help="inspect an existing package")
    parser.add_argument("path", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    if (args.verify and args.install) or args.verify == (args.output is not None):
        parser.error("use SOURCE OUTPUT to build, or --verify ARCHIVE to inspect")
    try:
        if args.install:
            manifest = install(args.path, args.output, args.install)
            print(f"{manifest['id']}@{manifest['version']} installed")
        elif args.verify:
            manifest = verify(args.path)
            print(f"{manifest['id']}@{manifest['version']} verified")
        else:
            pack(args.path, args.output)
            print(args.output)
    except (OSError, ValueError, BadZipFile, SchemaError, ValidationError) as exc:
        parser.exit(1, f"invalid package: {exc}\n")


if __name__ == "__main__":
    main()
