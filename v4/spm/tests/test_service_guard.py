from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import Product, Problem, issue, service_guard


class ServiceGuardTest(unittest.TestCase):
    def test_shared_database_allows_only_one_service_guard(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "state.sqlite"
            alias = Path(root) / "alias.sqlite"
            path.touch()
            alias.symlink_to(path)
            with service_guard(path):
                with self.assertRaisesRegex(Problem, "still owns"):
                    with service_guard(alias):
                        self.fail("A second writer entered")
            with service_guard(alias):
                self.assertTrue(path.with_suffix(".sqlite.service.lock").exists())

    def test_instance_metadata_tracks_process_separately_from_data(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "state.sqlite"
            with patch.dict("os.environ", {"SPM_NODE_NAME": "node-one"}):
                before = Product(path)
            admin = issue(path, "test", "pilot", "admin")
            viewer = issue(path, "test", "viewer", "viewer")
            with patch.dict("os.environ", {"SPM_NODE_NAME": "node-two"}):
                after = Product(path)
            first = before.request("GET", "/api/v1/instance", admin)[1]
            second = after.request("GET", "/api/v1/instance", admin)[1]
            self.assertEqual(first["stream_id"], second["stream_id"])
            self.assertNotEqual(first["boot_id"], second["boot_id"])
            self.assertEqual(second["node"], "node-two")
            with self.assertRaises(Problem) as restricted:
                after.request("GET", "/api/v1/instance", viewer)
            self.assertEqual(restricted.exception.status, 403)
