"""Test exact preregistered comparisons and a real measured, waited subprocess."""

import copy
import json
import subprocess
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cost

PROTOCOL = "a" * 64
PLATFORM = {
    "os": "test-kernel",
    "method": "deterministic instrument used only in controls",
    "boundary": cost.BOUNDARY,
}
BASE = {key: 8 for key in cost.UNITS}
ACQUISITION = {
    "parent": "1" * 40,
    "candidate": "2" * 40,
    "verifiedReceiptSha256": "3" * 64,
}


def samples(values):
    a = {
        "counters": {key: 1 for key in cost.UNITS},
        "utcNs": 100,
        "pid": 6241,
        "sampleBracketNs": 1,
        "inFlightChildren": 0,
        "unavailable": None,
    }
    b = {
        **a,
        "utcNs": 116,
        "counters": {
            key: v if key in cost.PEAKS else 1 + v for key, v in values.items()
        },
    }
    return a, b


def instrument(values=BASE, platform=PLATFORM, sample_edit=None):
    pair = samples(values)
    if sample_edit:
        sample_edit(*pair)
    stack = ExitStack()
    stack.enter_context(
        patch.object(
            cost, "platform_conditions", side_effect=[platform, copy.deepcopy(platform)]
        )
    )
    stack.enter_context(patch.object(cost, "sample", side_effect=pair))
    return stack


def previous():
    with instrument():
        row = cost.baseline_cost(cost.start_cost(), PROTOCOL)
    row["acquisition"] = ACQUISITION
    return row


def registration(base):
    return {
        "format": cost.POLICY_FORMAT,
        "profile": "ocs-release/1",
        "platformSha256": cost.fingerprint(PLATFORM),
        "workloadSha256": PROTOCOL,
        "baselineEvidenceSha256": cost.fingerprint(base),
        "ceilings": {key: v + 4 for key, v in BASE.items()},
    }


class CostTests(unittest.TestCase):
    def refusal(self, outcome, criterion, callback):
        with self.assertRaises(cost.CostError) as error:
            callback()
        self.assertEqual(error.exception.outcome, outcome)
        self.assertEqual(error.exception.criterion, criterion)
        self.assertEqual(error.exception.observation["status"], outcome)
        json.dumps(error.exception.observation, allow_nan=False)
        return error.exception.observation

    def test_equal_and_lower_each_cell_is_accepted_with_exact_prior_and_ceilings(self):
        baseline = previous()
        reg = registration(baseline)
        with instrument():
            row = cost.finish_cost(cost.start_cost(), reg, baseline)
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["observed"], BASE)
        self.assertEqual(
            row["comparison"]["wallNs"],
            {
                "direction": "min",
                "unit": "nanoseconds",
                "value": 8,
                "ceiling": 12,
                "previous": 8,
            },
        )
        with instrument({key: v - 1 for key, v in BASE.items()}):
            better = cost.finish_cost(cost.start_cost(), reg, row)
        self.assertEqual(better["status"], "accepted")
        self.assertEqual(better["registrationSha256"], row["registrationSha256"])
        with instrument():
            failed = self.refusal(
                "rejected",
                "verification.cost.regression/inputBlocks",
                lambda: cost.finish_cost(cost.start_cost(), reg, better),
            )
        self.assertEqual(set(failed["adverse"]), set(cost.UNITS))

    def test_one_unit_regression_is_visible_below_ceiling_and_survives_repeat_as_evidence(
        self,
    ):
        baseline = previous()
        reg = registration(baseline)
        for key in cost.UNITS:
            with self.subTest(metric=key), instrument({**BASE, key: BASE[key] + 1}):
                failed = self.refusal(
                    "rejected",
                    "verification.cost.regression/" + key,
                    lambda: cost.finish_cost(cost.start_cost(), reg, baseline),
                )
                self.assertEqual(failed["adverse"], [key])
                self.assertLess(failed["observed"][key], reg["ceilings"][key])
        retained = cost.canonical(failed)
        with instrument():
            retried = cost.finish_cost(cost.start_cost(), reg, baseline)
        self.assertEqual(retried["adverse"], [])
        self.assertEqual(cost.canonical(failed), retained)
        self.assertEqual(json.loads(retained)["status"], "rejected")

    def test_missing_enrollment_baseline_and_foreign_conditions_hold(self):
        base = previous()
        reg = registration(base)
        for choice, expected in [
            (None, "registration"),
            ({**reg, "ceilings": {}}, "registration"),
            ({**reg, "platformSha256": "7" * 64}, "platform"),
            ({**reg, "workloadSha256": "7" * 64}, "baseline"),
            ({**reg, "baselineEvidenceSha256": "6" * 64}, "baseline"),
        ]:
            with self.subTest(criterion=expected), instrument():
                failure = self.refusal(
                    "undetermined",
                    "verification.cost." + expected,
                    lambda choice=choice: cost.finish_cost(
                        cost.start_cost(), choice, base
                    ),
                )
                self.assertEqual(failure["observed"]["wallNs"], 8)
        for p in [
            None,
            {k: v for k, v in base.items() if k != "acquisition"},
            {**base, "observed": {**BASE, "wallNs": "8"}},
        ]:
            with instrument():
                self.refusal(
                    "undetermined",
                    "verification.cost.baseline",
                    lambda p=p: cost.finish_cost(cost.start_cost(), reg, p),
                )
        with instrument({**BASE, "wallNs": 14}):
            held = self.refusal(
                "rejected",
                "verification.cost.regression/wallNs",
                lambda: cost.finish_cost(cost.start_cost(), reg, None),
            )
        self.assertEqual(held["comparison"]["wallNs"]["previous"], None)

    def test_observation_only_is_explicit_and_cannot_be_used_as_an_enrolled_baseline(
        self,
    ):
        with instrument():
            request = cost.finish_cost(cost.start_cost(), cost.EXPERIMENT, None)
        self.assertEqual(request["status"], "observation-only")
        self.assertIsNone(request["condition"])
        reg = registration(previous())
        with instrument():
            self.refusal(
                "undetermined",
                "verification.cost.baseline",
                lambda: cost.finish_cost(cost.start_cost(), reg, request),
            )
        with instrument():
            self.refusal(
                "undetermined",
                "verification.cost.registration",
                lambda: cost.finish_cost(
                    cost.start_cost(),
                    {"profile": "ocs-release/1", "mode": "observation-only"},
                    None,
                ),
            )

    def test_incomplete_cohort_and_missing_platform_counters_are_undetermined(self):
        base = previous()
        reg = registration(base)
        for edit in (
            lambda a, b: a.update(inFlightChildren=1),
            lambda a, b: b.update(inFlightChildren=1),
            lambda a, b: b["counters"].pop("waitedChildCpuUs"),
        ):
            with instrument(sample_edit=edit):
                self.refusal(
                    "undetermined",
                    "verification.cost.population",
                    lambda: cost.finish_cost(cost.start_cost(), reg, base),
                )
        a, b = samples(BASE)
        with (
            patch.object(cost, "sample", side_effect=[a, b]),
            patch.object(
                cost,
                "platform_conditions",
                side_effect=[PLATFORM, {**PLATFORM, "affinity": "different"}],
            ),
        ):
            self.refusal(
                "undetermined",
                "verification.cost.platform",
                lambda: cost.finish_cost(cost.start_cost(), reg, base),
            )
        with instrument(sample_edit=lambda a, b: b["counters"].update(wallNs=0)):
            self.refusal(
                "undetermined",
                "verification.cost.counter",
                lambda: cost.finish_cost(cost.start_cost(), reg, base),
            )

    @unittest.skipUnless(sys.platform == "linux", "Linux getrusage units required")
    def test_actual_clocks_and_resources_include_waited_child(self):
        start = cost.start_cost()
        subprocess.run(
            [sys.executable, "-I", "-c", "sum(n*n for n in range(400000))"],
            check=True,
            timeout=10,
        )
        row = cost.finish_cost(start, cost.EXPERIMENT, None)
        self.assertEqual(row["status"], "observation-only")
        for name in (
            "wallNs",
            "selfCpuNs",
            "waitedChildCpuUs",
            "selfPeakRssBytes",
            "largestWaitedChildPeakRssBytes",
        ):
            self.assertGreater(row["observed"][name], 0)
        self.assertEqual(row["provenance"]["first"]["inFlightChildren"], 0)
        self.assertEqual(row["provenance"]["last"]["inFlightChildren"], 0)
        self.assertEqual(
            row["platformSha256"], cost.fingerprint(row["provenance"]["platform"])
        )
        self.assertEqual(
            row["platformSha256"], row["provenance"]["finalPlatformSha256"]
        )

    def test_kernel_timeval_resolution(self):
        for seconds, microseconds in [(0, 1), (12, 548893), (152365, 20008), (0, 0)]:
            value = seconds + microseconds * 1e-6
            self.assertEqual(cost.micros(value), seconds * 1000000 + microseconds)
        with self.assertRaises(ValueError):
            cost.micros(float("inf"))


if __name__ == "__main__":
    unittest.main()
