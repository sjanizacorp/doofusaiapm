from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from app import Product, classify_prefix, issue, sync_aws
from content_scan import classify, list_s3
from controls import Problem
from gcs import CollectionError
import onnx_policy


class EnforcementAddonsTest(unittest.TestCase):
    def test_provider_listing_and_prefix_classifier_preserve_bounds(self):
        response = {"Contents": [{"Key": "approved/contact.txt", "Size": 80},
                                 {"Key": "approved/weights.bin", "Size": 100}], "IsTruncated": True}
        invoke = Mock(return_value=response)

        def listing(*args):
            return list_s3(*args, invoke=invoke)

        self.assertEqual(listing("sample-bucket", "123456789012", "us-east-1", "approved/", 2),
                         (["approved/contact.txt"], 1, True))
        self.assertIn("--expected-bucket-owner", invoke.call_args.args)
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            product = Product(path)
            admin = issue(path, "pilot", "owner", "admin")
            sync_aws(path, "pilot", "123456789012", "us-east-1", collect=lambda *_: (
                {"arn:aws:s3:::sample-bucket": {"kind": "data", "name": "sample-bucket"}}, [],
            ))
            node = product.request("GET", "/api/v1/data-posture", admin)[1]["data"][0]["id"]
            sample = Mock(return_value=b"card: 4111 1111 1111 1111")
            result = classify_prefix(path, "pilot", node, "approved/", 2, list_s3=listing, sample_s3=sample)
            self.assertEqual(result, {"classified": 1, "levels": {"high": 1},
                                      "skipped_objects": 1, "listing_truncated": True})
            self.assertEqual(sample.call_args.args[-1], "approved/contact.txt")
            response["Contents"][0]["Key"] = "elsewhere/contact.txt"
            with self.assertRaises(CollectionError):
                classify_prefix(path, "pilot", node, "approved/", 2, list_s3=listing, sample_s3=sample)
            self.assertEqual(sample.call_count, 1)
        self.assertEqual(classify(b"card: 4111 1111 1111 1112")["sensitivity"], "unknown")

    def test_json_relay_screens_both_directions_and_binds_project(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            relay = Mock()
            product = Product(path, relay=("pilot", relay))
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            allowed = issue(path, "pilot", "caller", "operator", expiry, runtime=("relay", True, False))
            other = issue(path, "other", "caller", "operator", expiry, runtime=("relay", True, False))
            route = "/api/v1/runtime/relay"
            with self.assertRaises(Problem):
                product.request("POST", route, other, {"message": "ready"})
            with self.assertRaises(Problem):
                product.request("POST", route, allowed, ["person@", "example.test"])
            relay.forward.assert_not_called()
            relay.forward.return_value = {"status": "ok"}
            self.assertEqual(product.request("POST", route, allowed, {"message": "ready"}),
                             (200, {"status": "ok"}))
            relay.forward.return_value = ["person@", "example.test"]
            with self.assertRaisesRegex(Problem, "blocked"):
                product.request("POST", route, allowed, {"message": "ready"})

    @unittest.skipUnless(find_spec("onnx"), "Requires optional ONNX parser")
    def test_onnx_detects_external_tensor_and_custom_operator(self):
        import onnx
        from onnx import helper

        graph = helper.make_graph([helper.make_node("Identity", ["x"], ["y"])], "example", [], [])
        model = helper.make_model(graph)
        tensor = model.graph.initializer.add()
        tensor.name = "fixture"
        tensor.data_type = onnx.TensorProto.FLOAT
        tensor.dims.append(1)
        tensor.float_data.append(1)

        def inspect():
            raw = model.SerializeToString()
            return onnx_policy.inspect(BytesIO(raw), len(raw))

        self.assertEqual(inspect()["tensors_checked"], 1)
        tensor.data_location = onnx.TensorProto.EXTERNAL
        with self.assertRaisesRegex(Problem, "external tensor"):
            inspect()
        tensor.data_location = onnx.TensorProto.DEFAULT
        model.graph.node[0].domain = "vendor.custom"
        with self.assertRaisesRegex(Problem, "custom or invalid"):
            inspect()
