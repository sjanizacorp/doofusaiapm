from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import urlencode

from app import Product, issue, sync_cloud_graph
from controls import Problem


class InventorySetsTest(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "inventory.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "pilot", "owner", "admin")
        self.viewer = issue(self.path, "pilot", "reader", "viewer")
        self.other = issue(self.path, "other", "owner", "admin")
        self.product.request("POST", "/api/v1/connections", self.admin, {
            "name": "My AWS account", "provider": "aws",
            "arguments": ["123456789012", "us-east-1"], "profile": "server",
        })

    def get(self, route, token=None):
        return self.product.request("GET", "/api/v1/inventory/" + route, token or self.admin)[1]

    def test_named_sets_include_all_discovered_objects_and_details(self):
        scope = "aws:123456789012:us-east-1"
        nodes = {"model": {"kind": "model", "name": "Sales model"},
                 "role": {"kind": "identity", "name": "Inference role", "exposure": "analyzer_external_access"},
                 "bucket": {"kind": "data", "name": "Training data", "sensitivity": "high"}}
        sync_cloud_graph(self.path, "pilot", "aws", scope,
                         lambda: (nodes, [("model", "role", "uses_identity"), ("model", "bucket", "stores_artifacts")]))
        sets = self.get("sets", self.viewer)["sets"]
        selected = next(item for item in sets if item["name"] == "My AWS account")
        query = urlencode({"set": selected["id"]})
        objects = self.get("objects?" + query, self.viewer)["objects"]
        self.assertEqual({item["kind"] for item in objects}, {"model", "identity", "data"})
        model = next(item for item in objects if item["kind"] == "model")
        self.assertIsNone(model["assessment"])
        role = next(item for item in objects if item["kind"] == "identity")
        self.assertIsNotNone(role["assessment"])
        detail = self.get("objects?" + urlencode({"set": selected["id"], "object": model["id"]}), self.viewer)["object"]
        self.assertEqual(len(detail["relationships"]), 2)
        self.assertEqual(detail["resource"], "model")
        self.assertEqual(detail["latest_collection"]["status"], "completed")
        with self.assertRaises(Problem):
            self.get("objects?" + query, self.other)
        azure_scope = "azure:subscription:group:workspace"
        sync_cloud_graph(self.path, "pilot", "azure", azure_scope,
                         lambda: ({"azure-model": {"kind": "model", "name": "Azure model"}}, []))
        self.assertEqual(len(self.get("objects?" + query)["objects"]), 3)

    def test_manual_assets_and_pagination_are_preserved(self):
        self.product.request("POST", "/api/v1/assets", self.admin,
                             {"id": "manual-store", "kind": "storage", "facts": {"encrypted": True}})
        self.assertEqual(self.get("objects?set=manual")["objects"][0]["name"], "manual-store")
        nodes = {f"model-{n:03}": {"kind": "model", "name": f"Model {n}"} for n in range(101)}
        sync_cloud_graph(self.path, "pilot", "aws", "aws:123456789012:us-east-1", lambda: (nodes, []))
        selected = next(item for item in self.get("sets")["sets"] if item["name"] == "My AWS account")
        first = self.get("objects?" + urlencode({"set": selected["id"]}))
        self.assertEqual(len(first["objects"]), 100)
        second = self.get("objects?" + urlencode({"set": selected["id"], "after": first["next_after"]}))
        self.assertEqual(len(second["objects"]), 1)
        self.assertNotIn(second["objects"][0]["id"], {item["id"] for item in first["objects"]})

    def test_empty_configured_set_is_selectable(self):
        selected = next(item for item in self.get("sets")["sets"] if item["name"] == "My AWS account")
        self.assertEqual(self.get("objects?" + urlencode({"set": selected["id"]}))["objects"], [])
