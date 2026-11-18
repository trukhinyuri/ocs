"""Regression checks for the acceptance criteria of a supported scenario."""

import copy
import unittest

from compatibility import audit_index, case_changes


class CompatibilityTests(unittest.TestCase):
    def test_preserve_inputs_expectations_and_followup(self):
        error = {"method": "read", "params": {"id": False}, "expect": {"error": {"code": -33009}}}
        retry = {
            "method": "read",
            "params": {"id": "demo"},
            "expect": {"result": {"state": "ready"}},
        }
        case = {"id": "recovery", "rule": "W-06", "steps": [error, retry]}
        base = {"recovery": case}
        strengthened = copy.deepcopy(case)
        strengthened["steps"][0]["expect"]["error"]["data"] = {"kind": "input"}
        self.assertEqual(case_changes(base, {"recovery": strengthened}), [])
        self.assertIn("removed published case: recovery", case_changes(base, {}))
        for last in (
            [],
            [dict(retry, expect={"result": {}})],
            [dict(retry, params={"id": "other"})],
        ):
            with self.subTest(last=last):
                problems = case_changes(base, {"recovery": dict(case, steps=[error, *last])})
                self.assertTrue(any("recovery (step 2)" in p for p in problems))
        changed_type = dict(case, steps=[dict(error, params={"id": 0}), retry])
        self.assertTrue(case_changes(base, {"recovery": changed_type}))

    def test_trace_requires_evidence_or_explicit_qualification(self):
        record = {"scope": "Caller", "expect": "Complete the read", "checks": ["read"]}
        index = {
            "requirements": {"spec/wire.md": {"W-06": ["read-scenario"]}},
            "scenarios": {"read-scenario": record},
        }
        rules = {"spec/wire.md": {"W-06"}}
        report = {
            "checks": [
                {"id": "read", "rule": "W-06", "status": "pass"},
                {"id": "go-executor-read", "rule": "W-06", "status": "pass"},
            ]
        }
        self.assertEqual(audit_index(index, report, {"read"}, rules, set()), [])
        self.assertTrue(audit_index(index, {"checks": []}, set(), rules, set()))
        unchecked = dict(record, checks=[])
        index["scenarios"]["read-scenario"] = unchecked
        self.assertTrue(audit_index(index, {"checks": []}, set(), rules, set()))
        unchecked["qualification"] = "Observe the selected host."
        self.assertEqual(audit_index(index, {"checks": []}, set(), rules, set()), [])
        self.assertTrue(audit_index(index, report, {"read"}, rules, set()))
