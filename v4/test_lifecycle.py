"""Regression checks for the installation destination and state preservation."""
from pathlib import Path
import subprocess
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import lifecycle

HERE = Path(__file__).resolve().parent


class InstallationTest(unittest.TestCase):
    def invoke(self, command, *arguments, data=None, environment=None):
        return subprocess.run([sys.executable, str(HERE / "lifecycle.py"), command, *map(str, arguments)],
                              capture_output=True, text=True, input=data, timeout=30, env=environment)

    def test_prompt_accepts_custom_directory_with_spaces(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "My DoofusAI"
            result = self.invoke("install", data=str(directory) + "\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Installation directory [", result.stdout)
            self.assertTrue((directory / ".doofusai-spm-installation").exists())
            status = self.invoke("status", "--installdir", directory)
            self.assertEqual(status.returncode, 3)
            self.assertIn("Stopped", status.stdout)

    def test_explicit_directory_has_no_prompt_and_reinstall_preserves_state(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "application"
            first = self.invoke("install", "--installdir", directory)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertNotIn("Installation directory [", first.stdout)
            interpreter = directory / "venv" / "bin" / "python"
            details = subprocess.check_output(
                [str(interpreter), "-c", "import sys;print(sys.version_info[:2]);print(sys.prefix != sys.base_prefix)"],
                text=True,
            )
            self.assertIn("(3, 13)", details)
            self.assertIn("True", details)
            retained = directory / "venv" / "retained-package-marker"
            retained.write_text("Keep installed packages")
            data = directory / "data" / "preserved.txt"
            data.write_text("Retain this state")
            second = self.invoke("install", "--prefix", directory)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(data.read_text(), "Retain this state")
            self.assertEqual(retained.read_text(), "Keep installed packages")

    def test_enter_accepts_the_displayed_default(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "Default Install"
            environment = os.environ | {"DOOFUS_SPM_HOME": str(directory)}
            result = self.invoke("install", data="\n", environment=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"Installation directory [{directory}]", result.stdout)
            self.assertTrue((directory / ".doofusai-spm-installation").exists())

    def test_failed_environment_creation_can_be_retried(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "retry-install"
            with patch("lifecycle.venv.EnvBuilder.create", side_effect=OSError("fixture failure")):
                with self.assertRaisesRegex(ValueError, "Could not create"):
                    lifecycle.install(directory, None, None)
            self.assertTrue((directory / lifecycle.MARK).is_file())
            self.assertFalse((directory / "venv").exists())
            result = self.invoke("install", "--installdir", directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((directory / "venv" / "bin" / "python").exists())

    def test_nonempty_directory_is_rejected(self):
        with TemporaryDirectory() as root:
            directory = Path(root)
            (directory / "existing.txt").write_text("Unrelated")
            result = self.invoke("install", "--installdir", directory)
            self.assertEqual(result.returncode, 1)
            self.assertEqual((directory / "existing.txt").read_text(), "Unrelated")

    def test_unattended_install_requires_explicit_destination(self):
        result = self.invoke("install", data="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--installdir", result.stderr)


if __name__ == "__main__":
    unittest.main()
