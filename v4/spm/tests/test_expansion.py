from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from app import Handler, Product, Problem, import_bom, issue, load_gateway, review_aws_workload_access, sync_aws
from aws_inventory import discover
from gcs import CollectionError
import github_bom
from telemetry import Telemetry
from verification import safe_model_package, safetensors_structure


def tensor(data):
    header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    return len(header).to_bytes(8, "little") + header + data


class ExpandedTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "database.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "pilot", "owner", "admin")
        self.other = issue(self.path, "other", "owner", "admin")

    def call(self, method, endpoint, body=None, token=None):
        return self.product.request(method, "/api/v1/" + endpoint, token or self.admin, body)[1]

    def node(self, name, kind):
        self.call("POST", "graph/nodes", {"id": name, "kind": kind, "asset": None,
                                         "criticality": "low", "public": False})

    def test_aws_inventory_assesses_only_analyzer_evidence(self):
        account, region = "123456789012", "us-east-1"
        prefix = f"arn:aws:sagemaker:{region}:{account}:"
        role = f"arn:aws:iam::{account}:role/predictor"
        analyzer = f"arn:aws:access-analyzer:{region}:{account}:analyzer/test-analyzer"
        state = ["ACTIVE"]

        def invoke(region_arg, service, action, *arguments):
            self.assertEqual(region_arg, region)
            responses = {
                ("sts", "get-caller-identity"): {"Account": account, "Arn": f"arn:aws:iam::{account}:user/test"},
                ("sagemaker", "list-models"): {"Models": [{"ModelName": "model-a"}]},
                ("sagemaker", "describe-model"): {"ModelArn": prefix + "model/model-a", "ExecutionRoleArn": role,
                                                 "VpcConfig": {"Subnets": ["subnet-00112233"], "SecurityGroupIds": ["sg-00112233"]},
                                                 "PrimaryContainer": {"ModelDataUrl": "s3://test-bucket/model.tar.gz",
                                                                      "Image": f"{account}.dkr.ecr.{region}.amazonaws.com/team/infer:latest"}},
                ("sagemaker", "list-endpoints"): {"Endpoints": [{"EndpointName": "predict"}]},
                ("sagemaker", "describe-endpoint"): {"EndpointArn": prefix + "endpoint/predict",
                                                    "EndpointConfigName": "endpoint-config"},
                ("sagemaker", "describe-endpoint-config"): {"EndpointConfigArn": prefix + "endpoint-config/endpoint-config",
                                                           "ProductionVariants": [{"ModelName": "model-a"}]},
                ("bedrock-agent", "list-agents"): {"agentSummaries": [{"agentId": "AGENT1"}]},
                ("bedrock-agent", "get-agent"): {"agent": {"agentArn": f"arn:aws:bedrock:{region}:{account}:agent/AGENT1",
                                                          "agentName": "agent-one", "agentResourceRoleArn": role,
                                                          "foundationModel": "provider.test-model"}},
                ("accessanalyzer", "list-findings-v2"): {
                    "findings": [{"resource": role, "resourceOwnerAccount": account,
                                  "findingType": "ExternalAccess", "status": status} for status in state],
                },
            }
            return responses[service, action]

        callback = lambda *args: discover(*args, invoke=invoke)
        result = sync_aws(self.path, "pilot", account, region, analyzer, collect=callback)
        self.assertGreaterEqual(result["relationships"], 8)
        graph = self.call("GET", "cloud-graph")
        self.assertTrue({"uses_subnet", "uses_security_group", "uses_image_repository"} <=
                        {edge["relation"] for edge in graph["edges"]})
        endpoint = next(node["id"] for node in graph["nodes"] if node["kind"] == "endpoint")
        role_asset = next(node["id"] for node in graph["nodes"] if node["resource"] == role)
        calls = []

        def review(path, project, asset, resource, actions):
            calls.append((project, asset, resource, actions))
            return {"id": "review"}

        result = review_aws_workload_access(self.path, "pilot", endpoint, review=review)
        self.assertEqual(calls, [("pilot", role_asset, "arn:aws:s3:::test-bucket", ["s3:ListBucket"])])
        self.assertEqual(len(result["reviews"]), 1)
        self.assertEqual(self.call("GET", "cloud-graph", token=self.other)["nodes"], [])
        first, = self.call("GET", "issues")["issues"]
        self.assertEqual(first["risk"]["score"], 65)
        self.assertEqual(self.call("GET", f"scans/{first['first_scan']}")["snapshot"]["evidence"]["analyzer"], analyzer)
        state.clear()
        sync_aws(self.path, "pilot", account, region, analyzer, collect=callback)
        unknown, = self.call("GET", "issues")["issues"]
        self.assertEqual(unknown["last_outcome"], "unknown")
        state.append("RESOLVED")
        sync_aws(self.path, "pilot", account, region, analyzer, collect=callback)
        resolved, = self.call("GET", "issues?status=resolved")["issues"]
        self.assertEqual(first["id"], resolved["id"])
        with self.assertRaises(CollectionError):
            sync_aws(self.path, "pilot", account, region, None, collect=callback)

    def test_github_spdx_intake_and_project_isolation(self):
        self.node("agent", "agent")
        repo = "aniza/example"
        report = "https://api.github.com/repos/aniza/example/dependency-graph/sbom/fetch-report/12345678-abcd-1234-abcd-123456789012"
        download = "https://assets.example.test/report"
        raw = json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                          "packages": [{"SPDXID": "root", "name": "app"},
                                       {"SPDXID": "lib", "name": "lib", "versionInfo": "1.2"}],
                          "relationships": [{"spdxElementId": "root", "relatedSpdxElement": "lib",
                                             "relationshipType": "DEPENDS_ON"}]}).encode()
        calls = iter([(201, json.dumps({"sbom_url": report}).encode()), (202, b""), (302, download)])
        client = github_bom.discover(repo, "read-token", "assets.example.test", fetch=lambda *_: next(calls),
                                    download=lambda url, host: raw if (url, host) == (download, "assets.example.test") else b"",
                                    wait=lambda _: None)
        result = import_bom(self.path, "pilot", "agent", client, {"provider": "github", "repository": repo})
        self.assertEqual(import_bom(self.path, "pilot", "agent", raw)["status"], "already-imported")
        document = self.call("GET", f"boms/{result['id']}")["document"]
        self.assertEqual(document["relationships"], [{"source": "root", "target": "lib", "relation": "depends_on"}])
        self.assertEqual(document["origin"]["repository"], repo)
        self.assertEqual(self.call("GET", "boms", token=self.other)["boms"], [])
        with self.assertRaises(Problem):
            github_bom.download_report("https://unsafe.example.test/report", "assets.example.test")
        with patch("github_bom.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = raw
            self.assertEqual(github_bom.download_report(download, "assets.example.test"), raw)
            outgoing = opener.return_value.open.call_args.args[0]
            self.assertIsNone(outgoing.get_header("Authorization"))
        with self.assertRaises(Problem):
            import_bom(self.path, "other", "agent", raw)

    def test_cyclonedx_and_numeric_policy(self):
        self.node("model", "model")
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                          "components": [{"type": "machine-learning-model", "bom-ref": "a", "name": "weights"},
                                         {"type": "library", "bom-ref": "b", "name": "library"}],
                          "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}).encode()
        result = import_bom(self.path, "pilot", "model", raw)
        self.assertEqual(result["components"], 2)
        good = tensor(b"\x00\x00\x80\x3f")
        self.assertEqual(safetensors_structure(BytesIO(good), len(good), numeric=True)["numeric_bytes_checked"], 4)
        bad = tensor(b"\x00\x00\x80\x7f")
        with self.assertRaisesRegex(Problem, "non-finite"):
            safetensors_structure(BytesIO(bad), len(bad), numeric=True)

    def test_native_package_gate(self):
        good = tensor(b"\x00\x00\x80\x3f")
        for extra, valid in [(None, True), ("loader.py", False), ("artifact.bin", False), ("../settings.json", False)]:
            archive = BytesIO()
            with ZipFile(archive, "w") as zipped:
                zipped.writestr("model.safetensors", good)
                zipped.writestr("config.json", "{}")
                if extra:
                    zipped.writestr(extra, "inert data")
            size = len(archive.getvalue())
            if valid:
                self.assertEqual(safe_model_package(archive, size, numeric=True)["weight_files"], 1)
            else:
                with self.assertRaises(Problem):
                    safe_model_package(archive, size, numeric=True)

    def test_agent_scope_and_admin_minimum_policy(self):
        self.node("agent-a", "agent")
        self.node("agent-b", "agent")
        agent_token = issue(self.path, "pilot", "integration", "operator",
                            runtime=("gateway", False, False), tool_agent="agent-a")
        labels = {"agent": "agent-a", "tool": "knowledge-base", "operation": "read", "target": "approved"}
        self.assertEqual(self.call("POST", "runtime/authorize-tool", labels, agent_token)["decision"], "deny")
        self.call("POST", "agent-tool-rules", labels)
        self.assertEqual(self.call("POST", "runtime/authorize-tool", labels, agent_token)["decision"], "allow")
        for amended in ({"operation": "write"}, {"target": "unapproved"}):
            self.assertEqual(self.call("POST", "runtime/authorize-tool", labels | amended,
                                       agent_token)["decision"], "deny")
        with self.assertRaises(Problem) as problem:
            self.call("POST", "runtime/authorize-tool", labels | {"agent": "agent-b"}, agent_token)
        self.assertEqual(problem.exception.status, 403)
        self.call("DELETE", "agent-tool-rules", labels)
        self.assertEqual(self.call("POST", "runtime/authorize-tool", labels, agent_token)["decision"], "deny")
        self.call("POST", "runtime-policy", {"minimum_action": "block"})
        decision = self.call("POST", "runtime/inspect", {"text": "person@example.test", "action": "redact"})
        self.assertEqual(decision["decision"], "block")
        self.assertNotIn("text", decision)

    def test_agent_model_permissions_are_separate_and_fail_closed(self):
        self.node("agent", "agent")
        self.node("different-agent", "agent")
        self.node("approved-model", "model")
        self.node("other-model", "model")
        models = issue(self.path, "pilot", "model-router", "operator", runtime=("gateway", 0, 0),
                       tool_agent="agent", allow_tools=False, allow_models=True)
        tool = issue(self.path, "pilot", "tool-router", "operator", runtime=("gateway", 0, 0),
                     tool_agent="agent")
        request = {"agent": "agent", "model": "approved-model"}
        self.assertEqual(self.call("POST", "runtime/authorize-model", request, models)["decision"], "deny")
        self.call("POST", "agent-model-rules", request)
        self.assertEqual(self.call("POST", "runtime/authorize-model", request, models)["decision"], "allow")
        self.assertEqual(self.call("POST", "runtime/authorize-model", request | {"model": "other-model"},
                                   models)["decision"], "deny")
        for request_token, endpoint, body in [
            (tool, "runtime/authorize-model", request),
            (models, "runtime/authorize-model", request | {"agent": "different-agent"}),
            (models, "runtime/authorize-tool", {"agent": "agent", "tool": "search",
                                                "operation": "read", "target": "approved"}),
            (models, "agent-model-rules", request),
        ]:
            with self.assertRaises(Problem) as problem:
                self.call("POST", endpoint, body, request_token)
            self.assertEqual(problem.exception.status, 403)
        self.call("DELETE", "agent-model-rules", request)
        self.assertEqual(self.call("POST", "runtime/authorize-model", request, models)["decision"], "deny")

    def test_chat_gateway_requires_current_authorization_for_input_and_output(self):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import Mock

        self.node("agent", "agent")
        self.node("model", "model")
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        token = issue(self.path, "pilot", "caller", "operator", expires, runtime=("gateway", 0, 0),
                      tool_agent="agent", allow_tools=False, allow_models=True)
        model = Mock()
        self.product.chat_gateway = {None: ("pilot", "agent", "model", model)}
        route = "runtime/chat"
        prompt = {"text": "Return a status."}
        rule = {"agent": "agent", "model": "model"}
        with self.assertRaises(Problem):
            self.call("POST", route, prompt, token)
        model.answer.assert_not_called()
        self.call("POST", "agent-model-rules", rule)
        with self.assertRaises(Problem):
            self.call("POST", route, {"text": "person@example.test"}, token)
        model.answer.assert_not_called()
        model.answer.return_value = "Ready."
        self.assertEqual(self.call("POST", route, prompt, token), {"text": "Ready."})
        model.answer.return_value = "person@example.test"
        with self.assertRaises(Problem):
            self.call("POST", route, prompt, token)

        def revoked(_):
            self.call("DELETE", "agent-model-rules", rule)
            return "Ready."

        model.answer.side_effect = revoked
        with self.assertRaises(Problem):
            self.call("POST", route, prompt, token)

    def test_gateway_routes_isolate_projects_and_upstream_credentials(self):
        from datetime import datetime, timedelta, timezone

        for owner in (self.admin, self.other):
            for name, kind in (("agent", "agent"), ("model", "model")):
                self.call("POST", "graph/nodes", {"id": name, "kind": kind, "asset": None,
                                                 "criticality": "low", "public": False}, owner)
            self.call("POST", "agent-model-rules", {"agent": "agent", "model": "model"}, owner)
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        tokens = {
            project: issue(self.path, project, "caller", "operator", expires, runtime=("gateway", 0, 0),
                           tool_agent="agent", allow_tools=False, allow_models=True)
            for project in ("pilot", "other")
        }
        routes = [{"id": project, "project": project, "agent": "agent", "model_node": "model",
                   "origin": f"https://{project}.example.test", "model": f"{project}-v1",
                   "token_env": f"DOOFUS_GATEWAY_TOKEN_{project.upper()}"}
                  for project in tokens]
        config = self.path.with_name("gateway.json")
        config.write_text(json.dumps({"routes": routes}))
        with patch.dict(os.environ, {"DOOFUS_GATEWAY_TOKEN_PILOT": "pilot-fixture",
                                     "DOOFUS_GATEWAY_TOKEN_OTHER": "other-fixture"}, clear=True):
            self.product.chat_gateway = load_gateway(config)
            calls = []
            for key, (_, _, _, deployment) in self.product.chat_gateway.items():
                self.assertEqual(deployment.endpoint, f"https://{key}.example.test/v1/chat/completions")
                self.assertEqual(deployment.token, f"{key}-fixture")

                def answer(text, selected=key):
                    calls.append((selected, text))
                    return f"{selected} response"

                deployment.answer = answer
            prompt = {"text": "Return a status."}
            for key, token in tokens.items():
                self.assertEqual(self.call("POST", "runtime/chat", prompt | {"route": key}, token),
                                 {"text": f"{key} response"})
            with self.assertRaises(Problem) as wrong_project:
                self.call("POST", "runtime/chat", prompt | {"route": "other"}, tokens["pilot"])
            self.assertEqual(wrong_project.exception.status, 403)
            with self.assertRaises(Problem) as missing_route:
                self.call("POST", "runtime/chat", prompt, tokens["pilot"])
            self.assertEqual(missing_route.exception.status, 400)
            self.assertEqual(calls, [("pilot", prompt["text"]), ("other", prompt["text"])])
            config.write_text(json.dumps({"routes": [routes[0], routes[0]]}))
            with self.assertRaises(Problem):
                load_gateway(config)
            config.write_text(json.dumps({"routes": [routes[0] | {"token_env": "UNRELATED_TOKEN"}]}))
            with self.assertRaises(Problem):
                load_gateway(config)

    def test_protected_metrics(self):
        state = SimpleNamespace(product=self.product, telemetry=Telemetry(), metrics_token="fixture-secret")
        state.telemetry.record("api", 200, 0.01)

        def http(token):
            authorization = f"Authorization: Bearer {token}\r\n" if token else ""
            request = (f"GET /metrics HTTP/1.1\r\nHost: localhost\r\n{authorization}\r\n").encode()
            result = BytesIO()

            class InMemoryHandler(Handler):
                def setup(self):
                    self.rfile = BytesIO(request)
                    self.wfile = result

                def finish(self):
                    pass

            InMemoryHandler(None, ("127.0.0.1", 0), state)
            return result.getvalue()

        self.assertTrue(http(None).startswith(b"HTTP/1.0 401"))
        report = http("fixture-secret")
        self.assertTrue(report.startswith(b"HTTP/1.0 200"))
        self.assertIn(b'doofusai_http_requests_total{route="api",status_class="2xx"} 1', report)
        self.assertNotIn(b"fixture-secret", report)
