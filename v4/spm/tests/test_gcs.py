import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from app import Product, Problem, issue, sync_gcs
import gcs


def raw_bucket(name="training-store", prevention="inherited", revision="1"):
    return {
        "name": name, "projectNumber": "1234567890", "metageneration": revision,
        "iamConfiguration": {
            "publicAccessPrevention": prevention,
            "uniformBucketLevelAccess": {"enabled": True},
        },
        "encryption": {"defaultKmsKeyName": "metadata-only-test-key"},
    }


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "state.sqlite"
        self.product = Product(self.db)
        self.token = issue(self.db, "alpha", "reader", "operator")
        self.other = issue(self.db, "beta", "reader", "viewer")

    def get(self, endpoint, token=None):
        return self.product.request("GET", "/api/v1/" + endpoint, token or self.token)[1]

    def sync(self, *items):
        def provider(source, quota):
            return gcs.discover(source, quota, get_token=lambda: "test-token",
                                get_page=lambda *_: {"items": items_as_list})
        items_as_list = list(items)
        return sync_gcs(self.db, "alpha", "model-sec", collect=provider)

    def test_paginated_inventory_and_bounded_retry(self):
        pages = [{"items": [raw_bucket()], "nextPageToken": "next"},
                 {"items": [raw_bucket("test-registry")]}]
        requests = []

        def page(params, token, quota):
            requests.append(dict(params))
            self.assertEqual((token, quota), ("test-token", "quota-sec"))
            return pages.pop(0)

        result = gcs.discover("model-sec", "quota-sec", get_token=lambda: "test-token", get_page=page)
        self.assertEqual([item["name"] for item in result], ["training-store", "test-registry"])
        self.assertEqual([req.get("pageToken") for req in requests], [None, "next"])
        with self.assertRaisesRegex(gcs.CollectionError, "invalid pagination"):
            gcs.discover("model-sec", get_token=lambda: "test-token",
                         get_page=lambda *_: {"nextPageToken": "same"})

    def test_http_transport_only_requests_inventory(self):
        packet = {"items": [raw_bucket()]}
        with patch("gcs.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = json.dumps(packet).encode()
            data = gcs.fetch_page({"project": "model-sec"}, "test-token", "quota-sec")
            self.assertEqual(data, packet)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(urlsplit(request.full_url).netloc, "storage.googleapis.com")
            self.assertEqual(parse_qs(urlsplit(request.full_url).query), {"project": ["model-sec"]})
            self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
            self.assertIsNone(gcs.NoRedirect().redirect_request(request, None, 302, "", {}, "https://example.com"))

    def test_reassess_and_close_existing_issue_with_source_provenance(self):
        first = self.sync(raw_bucket())
        asset, = self.get("assets")["assets"]
        self.assertEqual(asset["source"]["name"], "training-store")
        issue_row, = self.get("issues")["issues"]
        self.assertEqual(issue_row["check_id"], "PAP")
        original = self.get("scans/" + issue_row["first_scan"])
        self.assertEqual(original["snapshot"]["evidence"]["sync_id"], first["id"])
        self.assertEqual(original["snapshot"]["evidence"]["metageneration"], "1")
        self.assertNotIn("metadata-only-test-key", json.dumps(original))
        self.sync(raw_bucket(prevention="enforced", revision="2"))
        resolved, = self.get("issues?status=resolved")["issues"]
        self.assertEqual(resolved["id"], issue_row["id"])
        events = self.get("issues/" + resolved["id"])["events"]
        self.assertEqual([event["action"] for event in events], ["resolved", "opened"])
        self.assertEqual(self.get("scans/" + issue_row["first_scan"]), original)
        self.assertEqual(self.get("assets", self.other)["assets"], [])
        self.assertEqual(self.get("sync-runs", self.other)["runs"], [])
        for route, data in [
            ("assets", {"id": asset["id"], "kind": "storage", "facts": {}}),
            ("scans", {"asset": asset["id"]}),
        ]:
            with self.assertRaises(Problem) as problem:
                self.product.request("POST", "/api/v1/" + route, self.token, data)
            self.assertEqual(problem.exception.status, 409)

    def test_failure_keeps_prior_state_missing_buckets_are_marked_inactive(self):
        self.sync(raw_bucket())
        before = self.get("assets")
        count = len(self.get("scans")["scans"])

        def denied(*_):
            raise gcs.CollectionError("Cloud Storage inventory returned HTTP 403.")

        with self.assertRaisesRegex(gcs.CollectionError, "403"):
            sync_gcs(self.db, "alpha", "model-sec", collect=denied)
        self.assertEqual(self.get("assets"), before)
        self.assertEqual(len(self.get("scans")["scans"]), count)
        self.assertEqual(self.get("sync-runs")["runs"][0]["status"], "failed")
        self.sync()
        asset, = self.get("assets")["assets"]
        self.assertFalse(asset["source"]["active"])
        self.assertEqual(len(self.get("scans")["scans"]), count)
        current, = self.get("issues")["issues"]
        self.assertEqual(current["status"], "open")
        self.assertEqual(current["source_active"], 0)

    def test_missing_access_metadata_is_unscored(self):
        incomplete = raw_bucket()
        del incomplete["iamConfiguration"]
        self.sync(incomplete)
        assessment, = self.get("scans")["scans"]
        self.assertIsNone(assessment["result"]["score"])
        self.assertEqual([item["status"] for item in assessment["result"]["outcomes"]],
                         ["unknown", "unknown", "pass"])
