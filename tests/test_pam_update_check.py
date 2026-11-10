"""Exercise the update checker against private files and mocked system commands.

Journey: specs/journeys/JOURNEY-S-013-pam-install-helper.md
"""

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "update_check", REPO / "scripts/check-pam-update.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class UpdateCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in checker.FILES:
            path = self.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                b"\x7fELFfixture"
                if name == checker.MODULE
                else b"auth include system-auth\n"
            )
        self.versions = {name: "1.0-1" for name in checker.PACKAGES}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(
            checker, "package_versions", side_effect=lambda: self.versions.copy()
        ).start()
        self.dependencies = mock.patch.object(
            checker, "check_dependencies", return_value=[]
        ).start()
        self.baseline = checker.snapshot(self.root)

    def path(self, name):
        return self.root / name.lstrip("/")

    def test_unchanged_setup_passes_without_writing_files(self):
        before = {
            path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()
        }
        self.assertEqual(checker.check(self.baseline, self.root), [])
        after = {
            path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()
        }
        self.assertEqual(before, after)

    def test_vendor_pam_change_requests_review_of_local_overrides(self):
        self.path("/usr/lib/pam.d/kde").write_text("auth required new_module.so\n")
        findings = checker.check(self.baseline, self.root)
        self.assertTrue(
            any("/usr/lib/pam.d/kde" in line and "merge" in line for line in findings)
        )

    def test_local_pam_change_requests_configuration_review(self):
        self.path("/etc/pam.d/kde").write_text("auth required different_module.so\n")
        self.assertTrue(
            any(
                "/etc/pam.d/kde" in line and "local PAM" in line
                for line in checker.check(self.baseline, self.root)
            )
        )

    def test_missing_module_reports_reinstallation_without_running_loader(self):
        self.path(checker.MODULE).unlink()
        self.assertTrue(
            any(
                checker.MODULE in line and "missing" in line
                for line in checker.check(self.baseline, self.root)
            )
        )
        self.dependencies.assert_not_called()

    def test_changed_module_is_not_executed_by_dependency_check(self):
        self.path(checker.MODULE).write_bytes(b"unknown new module")
        self.assertTrue(
            any(
                checker.MODULE in line
                for line in checker.check(self.baseline, self.root)
            )
        )
        self.dependencies.assert_not_called()

    def test_new_override_that_shadows_vendor_config_is_detected(self):
        path = self.path("/etc/pam.d/system-local-login")
        path.unlink()
        baseline = checker.snapshot(self.root)
        path.write_text("auth required replacement.so\n")
        self.assertTrue(
            any(
                str(path.relative_to(self.root)) in line
                for line in checker.check(baseline, self.root)
            )
        )

    def test_kde_package_update_requests_unlock_tests_even_without_pam_changes(self):
        self.versions["kscreenlocker"] = "2.0-1"
        findings = checker.check(self.baseline, self.root)
        self.assertTrue(
            any(
                "kscreenlocker: 1.0-1 -> 2.0-1" in line and "Retest" in line
                for line in findings
            )
        )

    def test_removed_package_is_detected(self):
        self.versions["pam"] = None
        self.assertTrue(
            any(
                "pam: 1.0-1 -> absent" in line
                for line in checker.check(self.baseline, self.root)
            )
        )

    def test_relevant_pacnew_is_reported_and_baseline_recording_refuses_it(self):
        self.path("/etc/pam.d/sudo.pacnew").write_text("auth include system-auth\n")
        self.assertTrue(
            any(
                "sudo.pacnew" in line
                for line in checker.check(self.baseline, self.root)
            )
        )
        with self.assertRaisesRegex(ValueError, "sudo.pacnew"):
            checker.record_baseline(self.root / "baseline.json", self.root)

    def test_check_does_not_advance_baseline_after_package_update(self):
        path = self.root / "baseline.json"
        path.write_text(json.dumps(self.baseline))
        before = path.read_bytes()
        self.versions["kscreenlocker"] = "2.0-1"
        with (
            mock.patch.object(
                checker, "snapshot", return_value=checker.snapshot(self.root)
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(checker.main(["--baseline", str(path)]), 1)
        self.assertEqual(path.read_bytes(), before)

    def test_explicit_recording_replaces_baseline_only_after_successful_checks(self):
        path = self.root / "baseline.json"
        path.write_text("old baseline")
        self.dependencies.return_value = ["Missing library"]
        with self.assertRaisesRegex(ValueError, "Missing library"):
            checker.record_baseline(path, self.root)
        self.assertEqual(path.read_text(), "old baseline")
        self.dependencies.return_value = []
        checker.record_baseline(path, self.root)
        self.assertEqual(checker.read_baseline(path), self.baseline)

    def test_missing_baseline_fails_with_actionable_output(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(
                checker.main(["--baseline", str(self.root / "missing.json")]), 2
            )
        self.assertIn("could not complete", output.getvalue())

    def test_corrupt_baseline_does_not_print_a_traceback(self):
        path = self.root / "baseline.json"
        for value in ("[]", "{", json.dumps({"files": [], "packages": {}})):
            path.write_text(value)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(checker.main(["--baseline", str(path)]), 2)


class CommandLineTests(unittest.TestCase):
    def test_missing_baseline_exits_without_writing_or_requiring_pacman(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                [sys.executable, str(REPO / "scripts/check-pam-update.py"),
                 "--baseline", str(root / "missing.json")],
                capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("could not complete", result.stderr)
            self.assertIn("--record-baseline", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(root.iterdir()), [])


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.module = Path(self.directory.name) / "pam_deunlock.so"
        self.module.write_bytes(b"\x7fELFfixture")
        # Fixture ownership stands in for the root-owned installed library.
        self.metadata = mock.patch.object(
            Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100644)
        )

    def test_ldd_relocations_include_unresolved_symbols(self):
        result = subprocess.CompletedProcess(
            [], 0, "undefined symbol: pam_get_authtok\n", ""
        )
        with (
            self.metadata,
            mock.patch.object(checker.subprocess, "run", return_value=result) as run,
        ):
            self.assertIn("pam_get_authtok", checker.check_dependencies(self.module)[0])
        self.assertEqual(
            run.call_args.args[0], ["/usr/bin/ldd", "-r", str(self.module)]
        )
        self.assertNotIn("LD_PRELOAD", run.call_args.kwargs["env"])

    def test_missing_library_is_reported_even_if_ldd_exits_zero(self):
        result = subprocess.CompletedProcess([], 0, "libpam.so.0 => not found\n", "")
        with (
            self.metadata,
            mock.patch.object(checker.subprocess, "run", return_value=result),
        ):
            self.assertIn("libpam.so.0", checker.check_dependencies(self.module)[0])

    def test_loader_failure_diagnostic_is_preserved(self):
        result = subprocess.CompletedProcess([], 1, "", "invalid ELF header\n")
        with (
            self.metadata,
            mock.patch.object(checker.subprocess, "run", return_value=result),
        ):
            self.assertIn(
                "invalid ELF header", checker.check_dependencies(self.module)[0]
            )

    def test_non_elf_module_does_not_run_loader(self):
        self.module.write_text("not a library")
        with self.metadata, mock.patch.object(checker.subprocess, "run") as run:
            self.assertIn("not an ELF", checker.check_dependencies(self.module)[0])
        run.assert_not_called()

    def test_writable_module_does_not_run_loader(self):
        with (
            mock.patch.object(
                Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100666)
            ),
            mock.patch.object(checker.subprocess, "run") as run,
        ):
            self.assertIn("permissions", checker.check_dependencies(self.module)[0])
        run.assert_not_called()


class HookTests(unittest.TestCase):
    def test_hook_runs_once_after_relevant_transactions_and_never_records_baseline(
        self,
    ):
        hook = (REPO / "deploy/arch/95-deunlock-check.hook").read_text()
        self.assertIn("When = PostTransaction", hook)
        self.assertNotIn("AbortOnFail", hook)
        self.assertNotIn("--record-baseline", hook)
        self.assertEqual(hook.count("Exec ="), 1)
        for package in checker.PACKAGES:
            self.assertIn(f"Target = {package}\n", hook)
        for operation in ("Install", "Upgrade", "Remove"):
            self.assertIn(f"Operation = {operation}\n", hook)


if __name__ == "__main__":
    unittest.main()
