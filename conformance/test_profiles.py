"""Portable profile records with explicit state, precision and ownership."""

import base64
import hashlib
import sys
import unittest
from pathlib import Path

from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from contracts import read_json, validate, validate_with


class ProfileTests(unittest.TestCase):
    def test_artifact_byte_offsets_and_complete_digest(self):
        original = "one π".encode()
        handle = {
            "id": "public-example",
            "mediaType": "text/plain;charset=utf-8",
            "digest": hashlib.sha256(original).hexdigest(),
            "bytes": len(original),
            "scope": {"kind": "resource", "id": "sample"},
        }
        pieces = [original[:4], original[4:]]
        assembled = bytearray()
        for position, part in enumerate(pieces):
            query = {"artifact": handle, "offset": len(assembled), "maxBytes": 4}
            page = {
                "artifact": handle,
                "offset": query["offset"],
                "data": base64.b64encode(part).decode(),
                "eof": position == len(pieces) - 1,
            }
            validate("profile-wire", query, "artifactRead")
            validate("profile-wire", page, "artifactPage")
            raw = base64.b64decode(page["data"], validate=True)
            self.assertLessEqual(len(raw), query["maxBytes"])
            assembled.extend(raw)
        self.assertEqual(len(assembled), handle["bytes"])
        self.assertEqual(hashlib.sha256(assembled).hexdigest(), handle["digest"])
        for bad in (dict(page, data="", eof=False), dict(page, offset=-1), dict(page, data="a!")):
            with self.assertRaises(ValidationError):
                validate("profile-wire", bad, "artifactPage")

    def test_rendered_state_and_action_share_the_operation_contract(self):
        surface = read_json((ROOT / "examples/records/surface.json").read_bytes())
        validate("profile-data", surface, "surface")
        view = surface["view"]
        validate_with(view["dataSchema"], view["values"])
        manifest = read_json((ROOT / "examples/status/ocs.json").read_bytes())
        allowed = {(op["id"], op["version"]) for op in manifest["exports"]}
        for action in view["actions"]:
            self.assertIn(action["operation"], surface["operations"])
            self.assertIn((action["operation"], action["version"]), allowed)
        with self.assertRaises(ValidationError):
            validate("profile-wire", {"state": "needs-approval"}, "surfaceResult")

    def test_account_inventory_and_reset_eligibility(self):
        account = read_json((ROOT / "examples/records/account.json").read_bytes())
        full = {
            "accounts": [account],
            "complete": True,
            "revision": "inventory-1",
            "evidence": account["evidence"],
        }
        validate("profile-wire", full, "accountPage")
        partial = dict(full, complete=False, reason="more pages", nextPageToken="p2")
        validate("profile-wire", partial, "accountPage")
        with self.assertRaises(ValidationError):
            validate("profile-wire", dict(partial, complete=True), "accountPage")
        grant = read_json((ROOT / "examples/records/reset.json").read_bytes())
        with self.assertRaises(ValidationError):
            validate("profile-data", dict(grant, count=0, eligibility="eligible"), "resetGrant")
        validate("profile-data", dict(grant, count=0, eligibility="ineligible"), "resetGrant")
