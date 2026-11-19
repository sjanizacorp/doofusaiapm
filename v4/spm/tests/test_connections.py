from concurrent.futures import Future
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app import Product, database, issue
from controls import Problem
from connections import command


class ConnectionsTest(unittest.TestCase):
    def test_configuration_permissions_scan_and_test_paths(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite"
            product = Product(path)
            admin = issue(path, "pilot", "owner", "admin")
            other = issue(path, "other", "owner", "admin")
            viewer = issue(path, "pilot", "reader", "viewer")
            route = "/api/v1/connections"
            def call(method, target=route, body=None, token=admin):
                return product.request(method, target, token, body)
            with self.assertRaises(Problem):
                call("POST", body={"name": "Storage", "provider": "gcs",
                                   "arguments": ["project-test"], "profile": "server"}, token=viewer)
            _, connection = call("POST", body={"name": "Storage", "provider": "gcs",
                                              "arguments": ["project-test"], "profile": "server"})
            key = connection["id"]
            self.assertEqual(call("GET", token=other)[1]["connections"], [])
            with self.assertRaises(Problem):
                call("POST", route + "/" + key + "/scan", {}, other)
            captured = []
            with patch.object(product.connections.executor, "submit", side_effect=lambda *args: captured.append(args)):
                self.assertEqual(call("POST", route + "/" + key + "/scan", {})[0], 202)
                with self.assertRaises(Problem):
                    call("POST", route + "/" + key + "/scan", {})
            with patch("connections.subprocess.run", return_value=SimpleNamespace(
                    returncode=0, stdout=b'{"status":"completed","assets":2}')) as process:
                function, *arguments = captured.pop()
                function(*arguments)
                self.assertIn("sync-gcs", process.call_args.args[0])
                self.assertIn("project-test", process.call_args.args[0])
            runs = call("GET", route + "/" + key + "/runs")[1]["runs"]
            self.assertEqual(runs[0]["status"], "completed")
            with patch.object(product.connections.executor, "submit", side_effect=lambda *args: captured.append(args)):
                call("POST", route + "/" + key + "/test", {})
            with patch("connections.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"secret")):
                function, *arguments = captured.pop()
                function(*arguments)
            failed = call("GET", route + "/" + key + "/runs")[1]["runs"][0]
            self.assertEqual(failed["status"], "failed")
            self.assertNotIn("secret", str(failed))
            product.connections.executor.shutdown()

    def test_command_translation_preserves_flags(self):
        import json
        for provider,args,expected in [
            ("aws", ["123456789012","us-east-1","arn"], "--analyzer"),
            ("salesforce", ["example.my.salesforce.com","00D000000000001","68.0"], "--agentforce"),
            ("vsphere", ["host.example.test","443"], "--port"),
        ]:
            with self.subTest(provider=provider):
                result = command({"provider":provider,"arguments":json.dumps(args),"project":"pilot","profile":"server"})
                self.assertIn(expected,result)
