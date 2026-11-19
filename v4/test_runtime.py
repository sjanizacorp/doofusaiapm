"""Regression checks for Python selection before bytecode loading."""
from pathlib import Path
import os
import py_compile
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parent


class RuntimeSelectionTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copy2(HERE / "runtime.sh", self.root / "runtime.sh")
        source = self.root / "fixture.py"
        source.write_text('import sys; print("Compatible Python", sys.version_info[:2])')
        py_compile.compile(str(source), cfile=str(self.root / "lifecycle.pyc"), doraise=True)
        source.unlink()

    def call(self, environment):
        return subprocess.run([str(self.root / "runtime.sh"), "install"], env=environment,
                              capture_output=True, text=True, timeout=15)

    def test_incompatible_override_gives_setup_message_without_loading_bytecode(self):
        candidate = Path("/usr/bin/python3")
        if not candidate.is_file():
            self.skipTest("Requires another Python interpreter")
        version = subprocess.check_output([str(candidate), "-c", "import sys;print(sys.version_info[:2])"], text=True)
        if "(3, 13)" in version:
            self.skipTest("System Python is already compatible")
        result = self.call(os.environ | {"DOOFUS_PYTHON": str(candidate)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("compatible CPython 3.13", result.stderr)
        self.assertNotIn("Bad magic", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_explicit_compatible_python_loads_compiled_runtime(self):
        result = self.call(os.environ | {"DOOFUS_PYTHON": sys.executable})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(3, 13)", result.stdout)

    def test_wrong_bytecode_is_rejected_before_loading(self):
        (self.root / "lifecycle.pyc").write_bytes(b"wrong bytecode")
        result = self.call(os.environ | {"DOOFUS_PYTHON": sys.executable})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_automatic_selection_works_with_incompatible_default_python(self):
        candidate = Path("/usr/bin/python3")
        if not candidate.is_file():
            self.skipTest("Requires system Python")
        tools = self.root / "bin"
        tools.mkdir()
        (tools / "python3").symlink_to(candidate)
        environment = os.environ | {"PATH": str(tools) + ":/usr/bin:/bin"}
        environment.pop("DOOFUS_PYTHON", None)
        result = self.call(environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(3, 13)", result.stdout)


if __name__ == "__main__":
    unittest.main()
