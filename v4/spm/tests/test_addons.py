from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
import json
from unittest.mock import patch

from app import Product, Problem, issue, sync_gcs, sync_vertex
from controls import utc
from gcs import CollectionError
from runtime_client import RuntimeClient, ScreeningError
from vertex import discover


class AddonTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "state.sqlite"
        self.product = Product(self.db)
        self.admin = issue(self.db, "pilot", "owner", "admin")
        self.other = issue(self.db, "other", "owner", "admin")

    def get(self, route, token=None):
        return self.product.request("GET", "/api/v1/" + route, token or self.admin)[1]

    def vertex(self, *, private=False, profiles=True, fail=False):
        root = "projects/1234567890/locations/us-central1"
        model = root + "/models/123"
        records = {
            "models": [{"name": model, "artifactUri": "gs://test-assets/artifacts/release"}],
            "endpoints": [{"name": root + "/endpoints/456", "displayName": "Test Endpoint",
                           "network": "net-a" if private else "",
                           "deployedModels": [{"model": model + "@1",
                                               "serviceAccount": "predict@pilot.iam.gserviceaccount.com"}]}],
            "reasoningEngines": [{"name": root + "/reasoningEngines/789",
                                  "spec": {"serviceAccount": "agent@pilot.iam.gserviceaccount.com"}}],
            "fileStoreDataProfiles": [{
                "fullResource": "//storage.googleapis.com/buckets/test-assets",
                "sensitivityScore": {"score": "SENSITIVITY_HIGH"},
                "profileLastGenerated": utc(),
            }],
        }

        def fetch(url, params, token, quota, label):
            self.assertEqual(token, "fixture")
            if fail and url.endswith("/endpoints"):
                raise CollectionError("Google inventory returned HTTP 403.")
            key = url.rsplit("/", 1)[-1]
            return {key: records[key]}

        return sync_vertex(self.db, "pilot", "pilot-src", "us-central1", profile_location="global" if profiles else None,
                           collect=lambda *args: discover(*args, get_token=lambda: "fixture", fetch=fetch))

    def test_cloud_relationships_and_profile_risk(self):
        sync_gcs(self.db, "pilot", "pilot-src", collect=lambda *_: [{
            "name": "test-assets", "project_number": "1234567890", "revision": "1",
            "facts": {"bucket_pap_enforced": False, "uniform_access_enabled": True, "default_cmek_configured": True},
        }])
        first = self.vertex()
        graph = self.get("cloud-graph")
        self.assertEqual(set(node["kind"] for node in graph["nodes"]),
                         {"agent", "model", "endpoint", "identity", "data"})
        self.assertEqual(first["relationships"], 4)
        self.assertEqual(self.get("cloud-graph", self.other)["nodes"], [])
        rows = {row["kind"]: row for row in self.get("issues")["issues"]}
        self.assertEqual(rows["gcs-bucket"]["risk"]["sensitivity_weight"], 20)
        self.assertEqual(rows["gcs-bucket"]["risk"]["score"], 75)
        self.assertEqual(rows["vertex-endpoint"]["risk"]["exposure_weight"], 20)
        bucket_issue = rows["gcs-bucket"]["id"]
        evidence, = self.get("issues/" + bucket_issue)["risk_evidence"]["cloud_paths"]
        self.assertEqual([node["kind"] for node in evidence["path"]], ["endpoint", "model", "data"])
        self.assertEqual([node["via"] for node in evidence["path"]], [None, "serves", "stores_artifacts"])
        self.assertEqual(evidence["freshness"], "recent")
        endpoint = next(node for node in graph["nodes"] if node["kind"] == "endpoint")
        status, _ = self.product.request("POST", "/api/v1/runtime-findings", self.admin, {
            "source": "TestGateway", "event_id": "evt-cloud", "node": endpoint["id"],
            "category": "guardrail_block", "severity": "high", "observed_at": utc(),
        })
        self.assertEqual(status, 201)
        self.assertEqual(self.get("runtime-findings")["findings"][0]["node_source"], "cloud")
        with self.assertRaises(CollectionError):
            self.vertex(fail=True)
        self.assertEqual(self.get("cloud-graph"), graph)
        self.assertEqual(self.get("sync-runs")["runs"][0]["status"], "failed")
        degraded, = self.get("issues/" + bucket_issue)["risk_evidence"]["cloud_paths"]
        self.assertEqual(degraded["freshness"], "degraded")
        self.vertex(private=True)
        resolved, = self.get("issues?status=resolved")["issues"]
        self.assertEqual(resolved["id"], rows["vertex-endpoint"]["id"])
        proof_path = "issues/" + resolved["id"] + "/remediation-proof"
        proof = self.get(proof_path)
        self.assertTrue(proof["verified"])
        self.assertNotEqual(proof["before"]["sync"]["id"], proof["after"]["sync"]["id"])
        self.assertEqual((proof["before"]["control"]["observed"], proof["after"]["control"]["observed"]),
                         (False, True))
        with self.assertRaises(Problem) as problem:
            self.get(proof_path, self.other)
        self.assertEqual(problem.exception.status, 404)
        open_issue, = self.get("issues")["issues"]
        self.assertEqual(open_issue["risk"]["score"], 55)
        with self.assertRaises(CollectionError):
            self.vertex(fail=True)
        self.assertEqual(self.get(proof_path)["reason"], "latest-source-sync-did-not-confirm-the-control")

    def test_runtime_inspection_redacts_without_persisting(self):
        before = self.get("security-events")
        body = {"text": "Contact person@example.test or share Bearer dummyplaceholder0000.", "action": "redact"}
        status, response = self.product.request("POST", "/api/v1/runtime/inspect", self.admin, body)
        self.assertEqual(status, 200)
        self.assertEqual(response["decision"], "redact")
        self.assertNotIn("person@example.test", response["text"])
        self.assertNotIn("dummyplaceholder0000", response["text"])
        _, blocked = self.product.request("POST", "/api/v1/runtime/inspect", self.admin,
                                          body | {"action": "block"})
        self.assertEqual(blocked["decision"], "block")
        self.assertNotIn("text", blocked)
        self.assertEqual(self.get("security-events"), before)
        self.assertEqual(self.get("runtime-findings")["findings"], [])
        with self.assertRaises(Problem):
            self.product.request("POST", "/api/v1/runtime/inspect", "invalid", body)

    def test_machine_credential_scope_and_source(self):
        token = issue(self.db, "pilot", "integration", "operator", runtime=("ApprovedGateway", 1, 1))
        status, _ = self.product.request("POST", "/api/v1/runtime/inspect", token,
                                         {"text": "hello", "action": "block"})
        self.assertEqual(status, 200)
        for method, path, data in [
            ("GET", "/api/v1/assets", None), ("GET", "/api/v1/runtime-findings", None),
            ("POST", "/api/v1/assets", {}),
            ("POST", "/api/v1/runtime-findings", {"source": "Spoofed"}),
        ]:
            with self.assertRaises(Problem) as problem:
                self.product.request(method, path, token, data)
            self.assertEqual(problem.exception.status, 403)
        self.product.request("POST", "/api/v1/graph/nodes", self.admin,
                             {"id": "target", "kind": "endpoint", "asset": None,
                              "criticality": "medium", "public": False})
        accepted, _ = self.product.request("POST", "/api/v1/runtime-findings", token, {
            "source": "ApprovedGateway", "event_id": "evt-1", "node": "target",
            "category": "guardrail_block", "severity": "high", "observed_at": utc(),
        })
        self.assertEqual(accepted, 201)

    @patch("runtime_client.build_opener")
    def test_inline_client_fails_closed(self, builder):
        raw = builder.return_value.open.return_value.__enter__.return_value.read
        client = RuntimeClient("https://spm.example.test", "synthetic-token")
        raw.return_value = json.dumps({"decision": "redact", "signals": {"email_address": 1},
                                       "text": "[REDACTED:email_address]"}).encode()
        self.assertEqual(client.screen("person@example.test"), "[REDACTED:email_address]")
        for response in [
            {"decision": "block", "signals": {"email_address": 1}},
            {"decision": "allow", "signals": {"email_address": 1}},
            {"decision": "redact", "signals": {"email_address": 1}},
        ]:
            raw.return_value = json.dumps(response).encode()
            with self.assertRaises(ScreeningError):
                client.screen("person@example.test")
        builder.return_value.open.side_effect = TimeoutError()
        with self.assertRaises(ScreeningError):
            client.screen("person@example.test")
