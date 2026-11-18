from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from zipfile import ZipFile

from agent_protocol import deployment
from app import Handler, Product, database, issue, sync_gcs
from controls import Problem


class CollectionAgentTest(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "state.sqlite"
        self.product = Product(self.db)
        self.admin = issue(self.db, "main", "admin", "admin")
        self.other = issue(self.db, "other", "admin", "admin")
        self.viewer = issue(self.db, "main", "viewer", "viewer")

    def request(self, method, path, token, body=None):
        return self.product.request(method, "/api/v1/" + path, token, body)[1]

    def enroll(self, project="123"):
        return self.request("POST", "agents", self.admin,
                            {"name": "collector", "provider": "gcs", "arguments": [project], "ttl_hours": 12})

    def queued(self, agent):
        return self.request("POST", f"agents/{agent['id']}/jobs", self.admin, {})

    def claim(self, agent):
        return self.request("POST", "agent/poll", agent["token"], {})["job"]

    def test_round_trip_duplicate_delivery_and_failure_preserves_inventory(self):
        agent = self.enroll()
        self.assertEqual(self.request("GET", "agents", self.other)["agents"], [])
        with self.assertRaises(Problem):
            self.request("GET", "agents", self.viewer)
        with self.assertRaises(Problem):
            self.request("GET", "assets", agent["token"])
        job = self.queued(agent)
        self.assertEqual(self.queued(agent)["id"], job["id"])
        claimed = self.claim(agent)
        self.assertEqual(claimed["id"], job["id"])
        self.assertIsNone(self.claim(agent))
        report = {"job": claimed["id"], "claim": claimed["claim"], "status": "completed", "snapshot": [
            {"name": "pilot-store", "project_number": "123", "revision": "1", "facts": {}},
        ]}
        first = self.request("POST", "agent/report", agent["token"], report)
        self.assertEqual(self.request("POST", "agent/report", agent["token"], report), first)
        self.assertEqual(len(self.request("GET", "sync-runs", self.admin)["runs"]), 1)
        with self.assertRaises(Problem):
            self.request("POST", "agent/report", agent["token"], report | {"snapshot": []})
        with self.assertRaises(Problem):
            sync_gcs(self.db, "main", "123", collect=lambda *_: [])
        self.queued(agent)
        newer = self.claim(agent)
        wrong = report | {"job": newer["id"], "claim": newer["claim"],
                          "snapshot": [report["snapshot"][0] | {"project_number": "456"}]}
        with self.assertRaises(Problem):
            self.request("POST", "agent/report", agent["token"], wrong)
        failed = wrong | {"status": "failed", "snapshot": None}
        self.request("POST", "agent/report", agent["token"], failed)
        asset, = self.request("GET", "assets", self.admin)["assets"]
        self.assertTrue(asset["source"]["active"])
        self.assertEqual(self.request("GET", "sync-runs", self.admin)["runs"][0]["status"], "failed")

    def test_retry_reassigns_lease_and_rotation_invalidates_old_token(self):
        original = self.enroll()
        job = self.queued(original)
        old = self.claim(original)
        with database(self.db, write=True) as conn:
            conn.execute("UPDATE collection_jobs SET lease_until=? WHERE id=?",
                         ("2000-01-01T00:00:00+00:00", job["id"]))
        replacement = self.claim(original)
        self.assertNotEqual(old["claim"], replacement["claim"])
        with self.assertRaises(Problem):
            self.request("POST", "agent/report", original["token"],
                         {"job": old["id"], "claim": old["claim"], "status": "failed", "snapshot": None})
        rotated = self.request("POST", f"agents/{original['id']}/rotate", self.admin, {"ttl_hours": 12})
        with self.assertRaises(Problem):
            self.claim(original)
        self.assertEqual(self.claim(rotated)["id"], job["id"])
        self.request("DELETE", f"agents/{original['id']}", self.admin, {})
        with self.assertRaises(Problem):
            self.claim(rotated)

    def test_request_handler_accepts_large_snapshot_only_on_report_route(self):
        agent = self.enroll()
        self.queued(agent)
        job = self.claim(agent)
        report = {"job": job["id"], "claim": job["claim"], "status": "completed", "snapshot": [
            {"name": f"pilot-store-{index:03d}", "project_number": "123", "revision": "1", "facts": {}}
            for index in range(120)
        ]}
        body = json.dumps(report).encode()
        self.assertGreater(len(body), 8192)
        state = SimpleNamespace(product=self.product)

        def http(method, path, token, payload=b""):
            request = (f"{method} /api/v1/{path} HTTP/1.1\r\nHost: localhost\r\n"
                       f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
                       f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
            response = BytesIO()

            class InMemoryHandler(Handler):
                def setup(self):
                    self.rfile = BytesIO(request)
                    self.wfile = response

                def finish(self):
                    pass

            InMemoryHandler(None, ("127.0.0.1", 0), state)
            return response.getvalue()

        self.assertTrue(http("POST", "agent/poll", agent["token"], body).startswith(b"HTTP/1.0 400"))
        self.assertTrue(http("POST", "agent/report", agent["token"], body).startswith(b"HTTP/1.0 200"))
        headers, data = http("GET", "agents/package", self.admin).split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Type: application/zip", headers)
        self.assertTrue(data.startswith(b"PK"))

    def test_package_and_provider_configuration(self):
        bundle = self.request("GET", "agents/package", self.admin)
        with ZipFile(BytesIO(bundle)) as archive:
            self.assertIn("agent.py", archive.namelist())
            self.assertNotIn("agent.token", archive.namelist())
        targets = {
            "aws": ["123456789012", "us-east-1"],
            "vertex": ["project-test", "us-central1"],
            "gcs": ["project-test"],
            "azure": ["ce6e31db-5ce2-47d5-a143-a7b8d91f13c9", "test-group", "workspace"],
            "oci": ["ocid1.compartment.oc1..aaaa", "us-ashburn-1"],
            "ibm": ["ce6e31db-5ce2-47d5-a143-a7b8d91f13c9", "us-south"],
            "salesforce": ["example.my.salesforce.com", "00D000000000001", "68.0"],
            "vsphere": ["server.example.test", "443"],
        }
        for provider, args in targets.items():
            with self.subTest(provider=provider):
                scope, collect = deployment(provider, args)
                self.assertTrue(scope and callable(collect))
