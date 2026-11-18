from unittest.mock import patch
from datetime import datetime, timedelta, timezone
import unittest

from tools import qualify


class QualificationTest(unittest.TestCase):
    @patch("tools.qualify.request")
    def test_load_requires_expected_response_shapes(self, request):
        request.side_effect = [
            {"status": "ok"},
            {"principal": "pilot", "project": "test", "role": "viewer"},
            {"unexpected": True},
        ]
        result = qualify.latency_run("http://127.0.0.1:1234", "fixture", 3, 1, 1000)
        self.assertFalse(result["passed"])
        self.assertEqual(result["failed"], 1)

    @patch("tools.qualify.request")
    def test_failover_requires_new_stream_and_known_report(self, request):
        scan = "2c9aecd6-f722-4b14-a099-096b8932109f"
        previous = "a" * 32
        found = "b" * 32
        request.side_effect = [
            {"status": "ok"}, {"stream_id": previous},
            {"status": "ok"}, {"stream_id": found}, {"id": scan},
        ]
        result = qualify.observe_failover("https://pilot.example.test", "fixture", previous, scan, 2)
        self.assertEqual(result["new_stream_id"], found)
        self.assertTrue(result["passed"])
        self.assertEqual(request.call_args.args[1], "/api/v1/scans/" + scan)

    @patch("tools.qualify.request")
    def test_live_pilot_requires_current_success_in_each_requested_scope(self, request):
        now = datetime.now(timezone.utc)
        request.side_effect = [
            {"project": "Pilot", "principal": "Jules"},
            {"runs": [
                {"source_project": "aws:123456789012:us-east-1", "provider": "aws",
                 "finished_at": now.isoformat(), "status": "completed"},
                {"source_project": "source-project:us-central1", "provider": "vertex",
                 "finished_at": (now - timedelta(hours=25)).isoformat(), "status": "completed"},
            ]},
        ]
        result = qualify.pilot("https://staging.example.test", "a.b.c", "Pilot", "Jules",
                               [("aws", "aws:123456789012:us-east-1"),
                                ("vertex", "source-project:us-central1")], None, 24)
        self.assertTrue(result["checks"][0]["passed"])
        self.assertFalse(result["checks"][1]["passed"])
        self.assertFalse(result["passed"])

    @patch("tools.qualify.request")
    def test_remediation_requires_expected_provider_and_recent_evidence(self, request):
        moment = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        baseline = {"id": "first-scan", "control": {"status": "finding"},
                    "sync": {"id": "first-sync", "provider": "azure", "source_project": "source"}}
        latest = {"id": "last-scan", "control": {"status": "pass"},
                  "sync": {"id": "last-sync", "provider": "azure", "source_project": "source",
                           "finished_at": moment}}
        request.return_value = {"verified": True, "issue": "fixture", "before": baseline, "after": latest}
        args = ("https://staging.example.test", "fixture-token", "fixture")
        self.assertTrue(qualify.remediation(*args, "azure", 3)["passed"])
        self.assertFalse(qualify.remediation(*args, "azure", 1)["passed"])
        self.assertFalse(qualify.remediation(*args, "aws", 3)["passed"])

    @patch("tools.qualify.request")
    def test_access_gate_requires_matching_transition_and_current_inventory(self, request):
        arguments = ("https://staging.example.test", "fixture", "latest", "baseline", "aws",
                     [("s3:GetObject", "access-removed")], 2)
        current = {"review": "latest", "baseline": "baseline", "provider": "aws",
                   "inventory_changed": False, "review_evaluated_at": datetime.now(timezone.utc).isoformat(),
                   "transitions": [{"action": "s3:GetObject", "change": "access-removed"}]}
        request.return_value = current
        self.assertTrue(qualify.access_change(*arguments)["passed"])
        request.return_value = current | {"inventory_changed": True}
        self.assertFalse(qualify.access_change(*arguments)["passed"])

    @patch("tools.qualify.request")
    def test_reschedule_watcher_requires_a_new_node_on_the_same_stream(self, request):
        scan = "2c9aecd6-f722-4b14-a099-096b8932109f"
        old_boot, new_boot, stream = "a" * 32, "b" * 32, "c" * 32
        request.side_effect = [
            {"status": "ok"}, {"boot_id": new_boot, "stream_id": "d" * 32, "node": "node-two"},
            {"status": "ok"}, {"boot_id": new_boot, "stream_id": stream, "node": "node-one"},
            {"status": "ok"}, {"boot_id": new_boot, "stream_id": stream, "node": "node-two"},
            {"id": scan},
        ]
        result = qualify.observe_reschedule("https://staging.example.test", "fixture", old_boot,
                                            "node-one", stream, scan, 2)
        self.assertTrue(result["passed"])
        self.assertEqual(result["new_node"], "node-two")
        self.assertEqual(request.call_count, 7)
