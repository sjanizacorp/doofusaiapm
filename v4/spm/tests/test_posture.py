import concurrent.futures
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

from app import SCHEMA, SCHEMA_VERSION, Handler, Product, Problem, assess, database, digest, issue


class PostureTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "alpha", "owner", "admin")
        self.viewer = issue(self.path, "alpha", "observer", "viewer")
        self.operator = issue(self.path, "alpha", "analyst", "operator")
        self.other = issue(self.path, "beta", "owner", "admin")

    def save(self, facts):
        return self.product.request("POST", "/api/v1/assets", self.operator,
                                    {"id": "model-store", "kind": "storage", "facts": facts})

    def scan(self):
        return self.product.request("POST", "/api/v1/scans", self.operator, {"asset": "model-store"})

    def test_report_survives_restart_and_asset_edit(self):
        self.save({"encrypted": False, "public": False})
        status, scan = self.scan()
        self.assertEqual(status, 201)
        self.assertEqual(scan["result"]["score"], 70)
        self.save({"encrypted": True, "public": False})
        _, later = self.scan()
        self.assertEqual(later["result"]["score"], 100)
        _, report = Product(self.path).request("GET", "/api/v1/scans/" + scan["id"], self.viewer)
        self.assertEqual(report["snapshot"]["facts"]["encrypted"], False)
        self.assertEqual(report["result"], scan["result"])

    def test_incomplete_coverage_is_unscored(self):
        self.save({"encrypted": True})
        _, report = self.scan()
        result = report["result"]
        self.assertEqual(result["coverage"], "incomplete")
        self.assertIsNone(result["score"])
        self.assertEqual([item["status"] for item in result["outcomes"]], ["pass", "unknown"])

    def test_expired_credentials_and_admin_issue_assignment(self):
        expired = issue(self.path, "alpha", "former", "operator", "2020-01-01T00:00:00.000+00:00")
        self.save({"encrypted": False, "public": False})
        self.scan()
        _, issues = self.product.request("GET", "/api/v1/issues", self.viewer)
        item, = issues["issues"]
        route = "/api/v1/issues/" + item["id"] + "/assignment"
        for token, assignee, status in [
            (expired, "analyst", 401), (self.operator, "analyst", 403),
            (self.admin, "former", 400), (self.admin, "observer", 400),
            (self.other, "owner", 404),
        ]:
            with self.assertRaises(Problem) as problem:
                self.product.request("POST", route, token, {"assignee": assignee})
            self.assertEqual(problem.exception.status, status)
        _, result = self.product.request("POST", route, self.admin, {"assignee": "analyst"})
        self.assertEqual(result["assignee"], "analyst")
        self.save({"encrypted": True, "public": False})
        self.scan()
        _, results = self.product.request("GET", "/api/v1/issues?status=resolved", self.viewer)
        self.assertEqual(results["issues"][0]["assignee"], "analyst")
        _, result = self.product.request("POST", route, self.admin, {"assignee": None})
        self.assertIsNone(result["assignee"])
        _, audit = self.product.request("GET", "/api/v1/audit", self.admin)
        self.assertEqual([e["action"] for e in audit["events"] if e["action"] in ("issue.assigned", "issue.unassigned")],
                         ["issue.unassigned", "issue.assigned"])

    def test_auth_and_project_scope(self):
        self.save({})
        _, scan = self.scan()
        for method, route, token, code in [
            ("GET", "/api/v1/assets", "bogus", 401),
            ("POST", "/api/v1/scans", self.viewer, 403),
            ("GET", "/api/v1/audit", self.operator, 403),
            ("GET", "/api/v1/scans/" + scan["id"], self.other, 404),
        ]:
            with self.assertRaises(Problem) as problem:
                self.product.request(method, route, token)
            self.assertEqual(problem.exception.status, code)
        _, assets = self.product.request("GET", "/api/v1/assets", self.other)
        self.assertEqual(assets["assets"], [])

    def test_schema_rejects_unexpected_data(self):
        for facts in [{"secret": "fixture"}, {"encrypted": 1}, {"public": None}]:
            with self.assertRaises(Problem) as problem:
                self.save(facts)
            self.assertEqual(problem.exception.status, 400)
        with database(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)

    def test_parallel_writes_have_distinct_consistent_reports(self):
        self.save({"encrypted": False, "public": False})
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            reports = list(pool.map(lambda _: self.scan()[1], range(16)))
        self.assertEqual(len({item["id"] for item in reports}), 16)
        _, audit = self.product.request("GET", "/api/v1/audit", self.admin)
        self.assertEqual(sum(e["action"] == "scan.completed" for e in audit["events"]), 16)
        _, issues = self.product.request("GET", "/api/v1/issues", self.viewer)
        (item,) = issues["issues"]
        _, detail = self.product.request("GET", "/api/v1/issues/" + item["id"], self.viewer)
        self.assertEqual({event["scan"] for event in detail["events"]}, {r["id"] for r in reports})
        self.assertEqual(sum(event["action"] == "opened" for event in detail["events"]), 1)

    def test_issue_lifecycle_and_frozen_provenance(self):
        self.save({"encrypted": False, "public": False})
        _, initial = self.scan()
        _, response = self.product.request("GET", "/api/v1/issues", self.viewer)
        (item,) = response["issues"]
        route = "/api/v1/issues/" + item["id"]
        self.save({"public": False})
        _, unknown = self.scan()
        _, detail = self.product.request("GET", route, self.viewer)
        self.assertEqual(detail["issue"]["status"], "open")
        self.assertEqual(detail["issue"]["last_outcome"], "unknown")
        self.assertEqual(detail["issue"]["last_scan"], unknown["id"])
        self.product.request("POST", "/api/v1/assets", self.admin,
                             {"id": "model-store", "kind": "storage",
                              "facts": {"encrypted": True, "public": False}})
        _, fixed = self.scan()
        _, response = self.product.request("GET", "/api/v1/issues?status=resolved", self.viewer)
        self.assertEqual([i["id"] for i in response["issues"]], [item["id"]])
        self.assertEqual(fixed["snapshot"]["evidence"]["recorded_by"], "owner")
        self.save({"encrypted": False, "public": False})
        _, regressed = self.scan()
        _, detail = self.product.request("GET", route, self.viewer)
        self.assertEqual(detail["issue"]["status"], "open")
        self.assertEqual([entry["action"] for entry in detail["events"]],
                         ["reopened", "resolved", "unknown", "opened"])
        self.assertEqual([entry["outcome"] for entry in detail["events"]],
                         ["finding", "pass", "unknown", "finding"])
        self.assertEqual([entry["scan"] for entry in detail["events"]],
                         [regressed["id"], fixed["id"], unknown["id"], initial["id"]])
        _, old = self.product.request("GET", "/api/v1/scans/" + initial["id"], self.viewer)
        self.assertEqual(old["snapshot"], initial["snapshot"])
        self.assertEqual(old["snapshot"]["evidence"]["recorded_by"], "analyst")
        with self.assertRaises(Problem) as problem:
            self.product.request("GET", route, self.other)
        self.assertEqual(problem.exception.status, 404)

    def test_migrate_legacy_reports_without_rewriting_them(self):
        legacy = self.path.with_name("legacy.sqlite")
        snapshot = {"kind": "storage", "facts": {"encrypted": False}, "source": "operator-declared"}
        with database(legacy) as conn:
            conn.executescript(SCHEMA)
            conn.execute("INSERT INTO assets(project,id,kind,facts) VALUES(?,?,?,?)",
                         ("alpha", "old-asset", "storage", json.dumps(snapshot["facts"])))
            conn.execute("INSERT INTO scans(project,id,asset,snapshot,result) VALUES(?,?,?,?,?)",
                         ("alpha", "legacy-scan", "old-asset", json.dumps(snapshot),
                          json.dumps(assess("storage", snapshot["facts"]))))
            conn.execute("INSERT INTO credentials VALUES(?,?,?,?)",
                         (digest("legacy-token"), "reader", "alpha", "viewer"))
        token = "legacy-token"
        instance = Product(legacy)
        _, old = instance.request("GET", "/api/v1/scans/legacy-scan", token)
        self.assertEqual(old["snapshot"], snapshot)
        _, first = instance.request("GET", "/api/v1/issues", token)
        _, restarted = Product(legacy).request("GET", "/api/v1/issues", token)
        self.assertEqual(first, restarted)
        (item,) = restarted["issues"]
        self.assertEqual(item["first_scan"], "legacy-scan")
        with database(legacy) as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM issue_events").fetchone()[0], 1)

    def test_scan_and_issue_writes_roll_back_together(self):
        self.save({"encrypted": False, "public": False})
        with database(self.path) as conn:
            conn.executescript("""
                CREATE TRIGGER fail_issue BEFORE INSERT ON issue_events
                BEGIN SELECT RAISE(ABORT, 'test issue write failure'); END;
            """)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "test issue write failure"):
            self.scan()
        with database(self.path) as conn:
            for table in ("scans", "issues", "issue_events"):
                self.assertEqual(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM audit WHERE action='scan.completed'"
            ).fetchone()[0], 0)

    def test_http_issue_filter_reaches_product(self):
        self.save({"encrypted": False, "public": False})
        self.scan()
        self.save({"encrypted": True, "public": False})
        self.scan()
        product = self.product
        output = BytesIO()
        wire_request = (
            "GET /api/v1/issues?status=resolved HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {self.viewer}\r\n\r\n"
        ).encode()

        class InMemoryHandler(Handler):
            def setup(self):
                self.rfile = BytesIO(wire_request)
                self.wfile = output

            def finish(self):
                pass

        InMemoryHandler(None, ("127.0.0.1", 0), SimpleNamespace(product=product))
        headers, body = output.getvalue().split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.0 200"))
        (item,) = json.loads(body)["issues"]
        self.assertEqual(item["status"], "resolved")

    def test_backup_and_revocation(self):
        self.save({})
        self.scan()
        backup = self.path.with_name("backup.sqlite")
        cli = Path(__file__).parents[1] / "app.py"
        args = [sys.executable, str(cli), "--db", str(self.path)]
        subprocess.run(args + ["backup", str(backup)], check=True, capture_output=True)
        _, results = Product(backup).request("GET", "/api/v1/scans", self.viewer)
        self.assertEqual(len(results["scans"]), 1)
        subprocess.run(args + ["revoke", "alpha", "observer"], check=True, capture_output=True)
        with self.assertRaises(Problem) as problem:
            self.product.request("GET", "/api/v1/me", self.viewer)
        self.assertEqual(problem.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
