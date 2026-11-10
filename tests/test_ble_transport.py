"""A skipped Android test must never qualify the BLE transport matrix."""

from pathlib import Path
import runpy
import unittest

CHECK = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/test-ble-transport.py"))["assert_instrumentation"]


class InstrumentationTests(unittest.TestCase):
    def test_assumption_skip_is_rejected_despite_junit_success_summary(self):
        with self.assertRaises(AssertionError):
            CHECK("INSTRUMENTATION_STATUS_CODE: 1\nINSTRUMENTATION_STATUS_CODE: -4\nOK (1 test)")

    def test_success_requires_a_completed_test(self):
        CHECK("INSTRUMENTATION_STATUS_CODE: 1\nINSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)")
        with self.assertRaises(AssertionError):
            CHECK("OK (1 test)")

    def test_ignored_and_failed_results_are_rejected(self):
        for status in ("-3", "-2"):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                CHECK(f"INSTRUMENTATION_STATUS_CODE: 1\nINSTRUMENTATION_STATUS_CODE: {status}\nOK (1 test)")
