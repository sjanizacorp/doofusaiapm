from io import BytesIO
import json
from pathlib import Path
import pickle
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

import ai_bom
from app import Product, classify_cloud_batch, classify_cloud_object, issue, sync_aws
from content_scan import classify
from controls import Problem
from gcs import CollectionError
from gcs_access import troubleshoot
from model_threat import inspect_checkpoint
from npm_inventory import discover


class ContentAndDependenciesTest(unittest.TestCase):
    def test_npm_discovers_nested_dependencies_without_network(self):
        result = ai_bom.normalize(discover(json.dumps({
            "lockfileVersion": 3, "name": "app",
            "packages": {"": {"dependencies": {"alpha": "*", "beta": "*"}},
                         "node_modules/alpha": {"version": "1.0.0", "dependencies": {"beta": "2"}},
                         "node_modules/beta": {"version": "1.0.0"},
                         "node_modules/alpha/node_modules/beta": {"version": "2.0.0"}},
        }).encode()))
        self.assertEqual(len(result["components"]), 4)
        self.assertEqual(len(result["relationships"]), 3)

    def test_gcs_time_context_is_sent_and_retained(self):
        timestamp = "2026-11-17T12:00:00Z"

        def fetch(url, params, token, quota, operation, *, payload=None):
            if payload:
                access = payload["accessTuple"]
                self.assertEqual(access["conditionContext"]["request"]["receiveTime"], timestamp)
                return {"accessTuple": access, "overallAccessState": "UNKNOWN_INFO"}
            return {"name": "sample-bucket", "projectNumber": "123", "metageneration": "1"}

        _, results = troubleshoot("sample-bucket", "123", ["storage.objects.get"],
                                  principal="reader@example.test", receive_time=timestamp,
                                  credential=lambda: "fixture", fetch=fetch)
        self.assertEqual(results[0]["decision"], "indeterminate")
        self.assertEqual(results[0]["condition_receive_time"], timestamp)

    def test_s3_classification_carries_only_signal_counts_to_report(self):
        self.assertEqual(classify(b"unclassified")["sensitivity"], "unknown")
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            product = Product(path)
            admin = issue(path, "pilot", "owner", "admin")
            bucket = "arn:aws:s3:::sample-bucket"
            sync_aws(path, "pilot", "123456789012", "us-east-1", collect=lambda *_: (
                {bucket: {"kind": "data", "name": "sample-bucket"}}, [],
            ))
            route = "/api/v1/data-posture"
            node, = product.request("GET", route, admin)[1]["data"]

            def sample(*args):
                self.assertEqual(args, ("sample-bucket", "123456789012", "us-east-1", "fixture.txt"))
                return b"contact: customer@example.test"

            classify_cloud_object(path, "pilot", node["id"], "fixture.txt", sample_s3=sample)
            report = product.request("GET", route, admin)[1]
            evidence = report["data"][0]["latest_content_sample"]
            self.assertEqual(evidence["signals"], {"email_address": 1})
            self.assertNotIn("customer@example.test", json.dumps(report))
            self.assertNotIn("fixture.txt", json.dumps(report))

    def test_batch_is_atomic_and_replaces_existing_samples_by_object(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            product = Product(path)
            admin = issue(path, "pilot", "owner", "admin")
            bucket = "arn:aws:s3:::sample-bucket"
            sync_aws(path, "pilot", "123456789012", "us-east-1", collect=lambda *_: (
                {bucket: {"kind": "data", "name": "sample-bucket"}}, [],
            ))
            route = "/api/v1/data-posture"

            def report():
                return product.request("GET", route, admin)[1]["data"][0]

            node = report()["id"]

            def failed_sample(*target):
                return b"person@example.test" if target[-1] == "one.txt" else b"\0"

            with self.assertRaisesRegex(CollectionError, "Object 2 of 2"):
                classify_cloud_batch(path, "pilot", node, ["one.txt", "two.txt"], sample_s3=failed_sample)
            self.assertEqual(report()["content_sample_counts"], {})
            results = classify_cloud_batch(
                path, "pilot", node, ["one.txt", "two.txt"],
                sample_s3=lambda *target: b"person@example.test" if target[-1] == "one.txt" else b"notes",
            )
            self.assertEqual([item["sensitivity"] for item in results], ["moderate", "unknown"])
            self.assertEqual(report()["content_sample_counts"], {"moderate": 1, "unknown": 1})
            classify_cloud_batch(path, "pilot", node, ["one.txt"], sample_s3=lambda *_: b"notes")
            self.assertEqual(report()["content_sample_counts"], {"unknown": 2})

    def test_structured_screening_returns_status_without_original_value(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            product = Product(path)
            token = issue(path, "pilot", "gateway", "operator", runtime=("gateway", True, False))
            route = "/api/v1/runtime/inspect-document"
            status, result = product.request("POST", route, token,
                                             {"document": ["customer@", "example.test"]})
            self.assertEqual((status, result["decision"]), (403, "block"))
            self.assertNotIn("customer", str(result))
            self.assertEqual(product.request("POST", route, token, {"document": {"message": "ready"}})[0], 200)

    def test_checkpoint_scans_embedded_pickle_without_loading(self):
        def fixture(value):
            stream = BytesIO()
            with ZipFile(stream, "w") as archive:
                archive.writestr("checkpoint/version", "3")
                archive.writestr("checkpoint/data.pkl", pickle.dumps(value))
            return stream

        safe = fixture({"state": 1})
        self.assertEqual(inspect_checkpoint(safe, len(safe.getvalue()))["entries"], 2)
        unsafe = fixture(complex(1, 2))
        with self.assertRaisesRegex(Problem, "disallowed operations"):
            inspect_checkpoint(unsafe, len(unsafe.getvalue()))
