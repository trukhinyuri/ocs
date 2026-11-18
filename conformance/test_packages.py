"""Inspect archives without loading their code or extracting their members."""

import shutil
import stat
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from admission import check_names
from package import pack, verify


class PackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.source = self.base / "source"
        shutil.copytree(
            ROOT / "examples/status", self.source, ignore=shutil.ignore_patterns("__pycache__")
        )
        self.output = self.base / "package.ocsx"

    def test_reproducible_round_trip(self):
        pack(self.source, self.output)
        other = self.base / "other.ocsx"
        pack(self.source, other)
        self.assertEqual(self.output.read_bytes(), other.read_bytes())
        self.assertEqual(verify(other)["id"], "org.example.status")
        with ZipFile(other) as archive:
            self.assertIn("LICENSE", archive.namelist())
            self.assertEqual(archive.namelist(), sorted(archive.namelist()))

    def test_tamper_missing_member_and_unlisted_file(self):
        pack(self.source, self.output)
        with ZipFile(self.output) as original:
            members = {n: original.read(n) for n in original.namelist()}
        for change in ("modified", "unlisted", "missing"):
            files = members.copy()
            if change == "modified":
                files["executor.py"] += b"\n# modified"
            elif change == "unlisted":
                files["extra"] = b"data"
            else:
                del files["README.md"]
            with ZipFile(self.output, "w") as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            with self.assertRaisesRegex(ValueError, "checksum"):
                verify(self.output)

    def test_archive_entry_names_and_types(self):
        for name, mode in [
            ("../outside", stat.S_IFREG),
            ("C:/outside", stat.S_IFREG),
            ("docs\\readme", stat.S_IFREG),
            ("README.MD", stat.S_IFREG),
            ("ocs.json", stat.S_IFREG),
            ("redirect", stat.S_IFLNK),
            ("pipe", stat.S_IFIFO),
        ]:
            with self.subTest(name=name):
                pack(self.source, self.output)
                entry = ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = (mode | 0o644) << 16
                with ZipFile(self.output, "a") as archive, warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(entry, "example")
                with self.assertRaises(ValueError):
                    verify(self.output)
        for names in (
            ["a", "a/b"],
            ["Docs/example", "docs/readme"],
            ["a/./b"],
            ["/asset"],
            ["a//b"],
            ["NUL.txt"],
            ["a:stream"],
            ["a."],
            ["caf\u00e9", "cafe\u0301"],
        ):
            with self.assertRaises(ValueError):
                check_names(names)

    def test_rejected_update_preserves_prior_output(self):
        pack(self.source, self.output)
        expected = self.output.read_bytes()
        (self.source / "executor.py").unlink()
        with self.assertRaisesRegex(ValueError, "entry absent"):
            pack(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), expected)
        (self.source / "executor.py").symlink_to(self.base)
        with self.assertRaisesRegex(ValueError, "non-regular"):
            pack(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), expected)
        with self.assertRaisesRegex(ValueError, "outside"):
            pack(self.source, self.source / "inside.ocsx")
