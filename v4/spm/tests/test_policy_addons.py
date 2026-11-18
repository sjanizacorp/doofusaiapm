from email.message import Message
from io import BytesIO
import json
from pathlib import Path
import pickle
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from agentforce import list_metadata
from app import Product, issue, review_aws_access, sync_aws
from controls import Problem
from model_behavior import buffered_stream
import model_threat
from runtime_client import GuardedTools, ScreeningError


class PolicyAddonsTest(unittest.TestCase):
    def test_stream_combines_split_content_and_rejects_incomplete_output(self):
        def event(delta, stop=None):
            return b"data: " + json.dumps({"choices": [
                {"index": 0, "delta": delta, "finish_reason": stop}
            ]}).encode() + b"\n\n"

        def response(data):
            stream = BytesIO(data)
            stream.headers = Message()
            stream.headers["Content-Type"] = "text/event-stream"
            return stream

        content = event({"content": "person@"}) + event({"content": "example.test"})
        complete = event({}, "stop") + b"data: [DONE]\n\n"
        self.assertEqual(buffered_stream(response(content + complete), 5), "person@example.test")
        for invalid in (content, content + event({"tool_calls": []}) + complete,
                        content + b"data: [DONE]\n\n"):
            with self.assertRaises(ValueError):
                buffered_stream(response(invalid), 5)

    def test_guarded_tool_cannot_run_before_policy_allows(self):
        authorizer, screening, handler = Mock(), Mock(), Mock(return_value="result")
        screening.screen.side_effect = lambda value, **_: value
        adapter = GuardedTools(agent="agent", authorizer=authorizer, screening=screening,
                               handlers={("lookup", "read", "catalog"): handler})
        args = {"tool": "lookup", "operation": "read", "target": "catalog", "text": "sample"}
        authorizer.authorize_tool.side_effect = ScreeningError()
        with self.assertRaises(ScreeningError):
            adapter.invoke(**args)
        handler.assert_not_called()
        authorizer.authorize_tool.side_effect = None
        self.assertEqual(adapter.invoke(**args), "result")
        handler.assert_called_once_with("sample")

    def test_raw_pickle_policy_accepts_data_and_rejects_object_loading(self):
        raw = pickle.dumps({"label": ["fixture"]})
        self.assertEqual(model_threat.inspect(BytesIO(raw), len(raw))["format"], "raw-pickle")
        obj = pickle.dumps(complex(1, 2), protocol=4)
        with self.assertRaisesRegex(Problem, "STACK_GLOBAL"):
            model_threat.inspect(BytesIO(obj), len(obj))
        with self.assertRaises(Problem):
            model_threat.inspect(BytesIO(raw + b"extra"), len(raw) + 5)

    def test_agentforce_metadata_transport_parses_names(self):
        body = b"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:m="http://soap.sforce.com/2006/04/metadata"><s:Body>
                    <m:listMetadataResponse><m:result><m:fullName>Support</m:fullName>
                    <m:type>AiAgentDefinition</m:type></m:result></m:listMetadataResponse>
                    </s:Body></s:Envelope>"""
        opener = Mock()
        opener.open.return_value = BytesIO(body)
        self.assertEqual(list_metadata("https://org.my.salesforce.com", "68.0", "fixture",
                                       "AiAgentDefinition", opener=opener), ["Support"])
        request = opener.open.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/services/Soap/m/68.0"))
        self.assertIn(b"listMetadata", request.data)

    def test_classification_is_project_scoped_and_correlates_exposure(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            product = Product(path)
            admin = issue(path, "pilot", "owner", "admin")
            other = issue(path, "other", "owner", "admin")
            account, region = "123456789012", "us-east-1"
            role = f"arn:aws:iam::{account}:role/Inference"
            bucket = "arn:aws:s3:::pilot-store"
            nodes = {
                role: {"kind": "identity", "name": "Inference", "exposure": "analyzer_external_access"},
                bucket: {"kind": "data", "name": "pilot-store", "sensitivity": "low"},
            }
            sync_aws(path, "pilot", account, region,
                     collect=lambda *_: (nodes, [(role, bucket, "can_access")]))
            asset, = product.request("GET", "/api/v1/assets", admin)[1]["assets"]
            review_aws_access(path, "pilot", asset["id"], bucket, ["s3:ListBucket"], evaluate=lambda *_: [
                {"action": "s3:ListBucket", "decision": "allowed"},
            ])
            route = "/api/v1/data-posture"
            entry, = product.request("GET", route, admin)[1]["data"]
            label = {"node": entry["id"], "sensitivity": "high"}
            with self.assertRaises(Problem):
                product.request("POST", route, other, label)
            product.request("POST", route, admin, label)
            entry, = product.request("GET", route, admin)[1]["data"]
            self.assertEqual((entry["provider_sensitivity"], entry["operator_sensitivity"]), ("low", "high"))
            self.assertTrue(entry["configuration_path"])
            evidence, = entry["access_evidence"]
            self.assertEqual(evidence["principal"], role)
            self.assertEqual(evidence["decisions"][0]["decision"], "allowed")
            self.assertEqual(entry["configuration_freshness"], "recent")
            self.assertEqual(evidence["freshness"], "recent")
            review_aws_access(path, "pilot", asset["id"], bucket, ["s3:listbucket"], evaluate=lambda *_: [
                {"action": "s3:listbucket", "decision": "indeterminate"},
            ])
            entry, = product.request("GET", route, admin)[1]["data"]
            evidence, = entry["access_evidence"]
            self.assertEqual(evidence["decisions"], [{"action": "s3:listbucket", "decision": "indeterminate"}])
            self.assertEqual(product.request("GET", route, other)[1]["data"], [])
