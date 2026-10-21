"""Checks experiment accounting against failures and changed source files."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest


class AccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("wan_support.py")
        cls.helper_path = path
        if path.exists():
            spec = importlib.util.spec_from_file_location("wan_support", path)
            cls.helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.helper)

    def require_helper(self):
        self.assertTrue(self.helper_path.exists(), "experiment accounting helper is missing")
        return self.helper

    def test_timeout_preserves_output_and_is_not_a_success(self):
        helper = self.require_helper()
        with tempfile.TemporaryDirectory() as tmp:
            result = helper.run_process(
                [sys.executable, "-u", "-c", "import time; print('started',flush=True); time.sleep(5)"],
                Path(tmp), 0.2, time.monotonic() + 2,
            )
            self.assertEqual(result["outcome"], "timeout")
            self.assertIsNone(result["exitCode"])
            self.assertIn("started", (Path(tmp) / "stdout.log").read_text())

    def test_expired_campaign_does_not_start_a_process(self):
        helper = self.require_helper()
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "started"
            result = helper.run_process(
                [sys.executable, "-c", f"open({str(marker)!r},'w').write('bad')"],
                Path(tmp), 1, time.monotonic() - 1,
            )
            self.assertEqual(result["outcome"], "not-run")
            self.assertFalse(marker.exists())

    def test_missing_attempts_and_censored_durations_are_not_zero_or_success(self):
        helper = self.require_helper()
        summary = helper.summarize_runs([
            {"outcome": "success", "exitCode": 0, "processElapsedMs": 10,
             "report": {"attempts": 2, "mpcTlsMs": 8}},
            {"outcome": "timeout", "exitCode": None, "processElapsedMs": 100, "report": None},
            {"outcome": "not-run", "exitCode": None, "processElapsedMs": None, "report": None},
        ])
        self.assertEqual(summary["succeeded"], 1)
        self.assertEqual(summary["timedOut"], 1)
        self.assertEqual(summary["notRun"], 1)
        self.assertEqual(summary["successProcessElapsedMs"]["median"], 10)
        self.assertIsNone(summary["attemptsTotal"])
        self.assertEqual(summary["attemptsKnownSubtotal"], 2)
        self.assertEqual(summary["runsWithUnknownAttempts"], 1)

    def test_source_change_invalidates_snapshot(self):
        helper = self.require_helper()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runner.py"
            path.write_text("before")
            before = helper.hash_files(Path(tmp), ["runner.py"])
            path.write_text("after")
            after = helper.hash_files(Path(tmp), ["runner.py"])
            self.assertNotEqual(before, after)

    def test_calibration_budget_expiry_is_a_recorded_outcome(self):
        helper = self.require_helper()
        self.assertTrue(hasattr(helper, "calibrate"), "calibration failures need structured records")
        with tempfile.TemporaryDirectory() as tmp:
            result = helper.calibrate([sys.executable, "-c", "import time; time.sleep(5)"],
                                      Path(tmp), time.monotonic() + .1)
            self.assertEqual(result["outcome"], "timeout")
            self.assertEqual(result["reason"], "campaign-budget")
            self.assertIsNone(result["calibration"])
            self.assertTrue((Path(tmp) / "run.json").exists())

    def test_invalid_calibration_json_is_recorded_as_error(self):
        helper = self.require_helper()
        self.assertTrue(hasattr(helper, "calibrate"), "calibration failures need structured records")
        with tempfile.TemporaryDirectory() as tmp:
            result = helper.calibrate([sys.executable, "-c", "print('invalid')"],
                                      Path(tmp), time.monotonic() + 2)
            self.assertEqual(result["outcome"], "error")
            self.assertEqual(result["reason"], "invalid-calibration-output")


if __name__ == "__main__":
    unittest.main()
