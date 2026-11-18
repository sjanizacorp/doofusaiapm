from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as Object
import unittest
from unittest.mock import patch

from app import (
    Product, Problem, issue, review_aws_access, review_gcs_access, review_vsphere_access,
    sync_aws, sync_gcs, sync_vsphere,
)
from gcs import CollectionError
from gcs_access import evaluate as evaluate_gcs, troubleshoot
from iam_review import evaluate
from vsphere_inventory import evaluate_privileges

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/InferenceRole"
BUCKET = "arn:aws:s3:::pilot-model-store"
OBJECT = BUCKET + "/weights.bin"
AWS_NODES = {
    ROLE: {"kind": "identity", "name": "InferenceRole"},
    BUCKET: {"kind": "data", "name": "pilot-model-store"},
}


class AccessReviewTest(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "pilot", "owner", "admin")
        self.viewer = issue(self.path, "pilot", "reader", "viewer")
        self.other = issue(self.path, "other", "owner", "admin")

    def get(self, route, credential=None):
        return self.product.request("GET", "/api/v1/" + route, credential or self.admin)[1]

    def setup_aws(self):
        sync_aws(self.path, "pilot", ACCOUNT, REGION, collect=lambda *_: (AWS_NODES, []))
        return self.get("assets")["assets"][0]["id"]

    def test_aws_review_preserves_context_and_restricts_results(self):
        asset = self.setup_aws()
        actions = ["s3:GetObject", "s3:PutObject"]

        def provider(region, service, operation, *args):
            self.assertEqual(region, REGION)
            if service == "sts":
                self.assertEqual(operation, "get-caller-identity")
                return {"Account": ACCOUNT}
            self.assertEqual(operation, "simulate-principal-policy")
            self.assertEqual(args, ("--no-paginate", "--policy-source-arn", ROLE, "--resource-arns",
                                    OBJECT, "--action-names", *actions))
            return {"EvaluationResults": [
                {"EvalActionName": "s3:getobject", "ResourceSpecificResults": [{
                    "EvalResourceName": OBJECT, "EvalResourceDecision": "allowed",
                    "MissingContextValues": ["aws:SourceVpce"],
                }]},
                {"EvalActionName": "s3:PutObject", "EvalResourceName": OBJECT, "EvalDecision": "explicitDeny",
                 "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": False}},
            ]}

        saved = review_aws_access(self.path, "pilot", asset, OBJECT, actions,
                                  evaluate=lambda *args: evaluate(*args, invoke=provider))
        route = "access-reviews/" + saved["id"]
        review = self.get(route)
        self.assertEqual(review["mode"], "aws-iam-policy-simulation")
        self.assertFalse(review["inventory_changed"])
        self.assertEqual(review["decisions"][0]["decision"], "indeterminate")
        self.assertEqual(review["decisions"][0]["reported_decision"], "allowed")
        self.assertEqual(review["decisions"][1]["decision"], "explicitDeny")
        self.assertEqual(review["decisions"][1]["permissions_boundary_allows"], False)
        self.assertEqual(len(self.get("access-reviews?asset=" + asset)["reviews"]), 1)
        for credential, status in [(self.viewer, 403), (self.other, 404)]:
            with self.assertRaises(Problem) as problem:
                self.get(route, credential)
            self.assertEqual(problem.exception.status, status)
        with patch("app.timestamp", return_value="2030-01-01T00:00:00.000+00:00"):
            sync_aws(self.path, "pilot", ACCOUNT, REGION, collect=lambda *_: (AWS_NODES, []))
        self.assertTrue(self.get(route)["inventory_changed"])
        self.assertEqual(self.get("issues")["issues"], [])

    def test_aws_review_rejects_untracked_or_cross_account_resources(self):
        asset = self.setup_aws()

        def never(*_):
            self.fail("The simulator must not run for out-of-scope requests.")

        with self.assertRaises(Problem):
            review_aws_access(self.path, "pilot", asset, "arn:aws:s3:::untracked-store/item",
                              ["s3:GetObject"], evaluate=never)
        with self.assertRaises(CollectionError):
            review_aws_access(self.path, "pilot", asset,
                              "arn:aws:lambda:us-east-1:000000000000:function:test",
                              ["lambda:InvokeFunction"], evaluate=never)
        with self.assertRaises(CollectionError):
            review_aws_access(self.path, "pilot", asset, OBJECT, ["s3:*"], evaluate=never)
        self.assertEqual(self.get("access-reviews")["reviews"], [])

    def test_aws_review_rejects_partial_provider_response(self):
        def provider(_, service, action, *args):
            if service == "sts":
                return {"Account": ACCOUNT}
            return {"IsTruncated": True, "EvaluationResults": []}
        with self.assertRaisesRegex(CollectionError, "incomplete"):
            evaluate(REGION, ROLE, OBJECT, ["s3:GetObject"], invoke=provider)

    def test_comparison_requires_same_scope_and_marks_unknowns_inconclusive(self):
        asset = self.setup_aws()
        first = review_aws_access(self.path, "pilot", asset, OBJECT, ["s3:GetObject", "s3:PutObject"],
                                  evaluate=lambda *_: [{"action": "s3:GetObject", "decision": "allowed"},
                                                        {"action": "s3:PutObject", "decision": "implicitDeny"}])
        last = review_aws_access(self.path, "pilot", asset, OBJECT, ["s3:putobject", "s3:getobject"],
                                 evaluate=lambda *_: [{"action": "s3:putobject", "decision": "indeterminate"},
                                                       {"action": "s3:getobject", "decision": "explicitDeny"}])
        route = "access-reviews/" + last["id"]
        self.assertEqual(self.get(route)["prior_reviews"][0]["id"], first["id"])
        changes = self.get(route + "/compare?baseline=" + first["id"])["transitions"]
        self.assertEqual([item["change"] for item in changes], ["inconclusive", "access-removed"])
        incompatible = review_aws_access(self.path, "pilot", asset, OBJECT, ["s3:GetObject"],
                                          evaluate=lambda *_: [{"action": "s3:GetObject", "decision": "allowed"}])
        with self.assertRaises(Problem) as problem:
            self.get("access-reviews/" + incompatible["id"] + "/compare?baseline=" + last["id"])
        self.assertEqual(problem.exception.status, 409)

    def test_vcenter_named_privilege_check_for_discovered_vm(self):
        resource = "VirtualMachine:vm-10"
        sync_vsphere(self.path, "pilot", "vc.example.test", collect=lambda *_: ({
            resource: {"kind": "virtual_machine", "name": "VM", "facts": {}},
        }, []))
        asset = self.get("assets")["assets"][0]["id"]
        privileges = ["System.View", "VirtualMachine.Interact.PowerOn", "VirtualMachine.Config.Settings"]

        def fake_vm(identifier, stub):
            self.assertEqual(identifier, "vm-10")
            self.assertEqual(stub, "fixture-stub")
            return Object(_GetMoId=lambda: identifier)

        def check(entities, userName, privId):
            self.assertEqual(userName, "reader@example.test")
            self.assertEqual(privId, privileges)
            return [Object(entity=entities[0], privAvailability=[
                Object(privId=privileges[0], isGranted=True), Object(privId=privileges[1], isGranted=False),
            ])]

        @contextmanager
        def provider(host, port, ca_file):
            self.assertEqual((host, port, ca_file), ("vc.example.test", 443, None))
            yield (Object(_stub="fixture-stub"), Object(about=Object(apiType="VirtualCenter"),
                   authorizationManager=Object(HasUserPrivilegeOnEntities=check)),
                   Object(VirtualMachine=fake_vm), None)

        with patch("vsphere_inventory.session", provider):
            saved = review_vsphere_access(self.path, "pilot", asset, "reader@example.test", privileges)
        review = self.get("access-reviews/" + saved["id"])
        self.assertEqual(review["mode"], "vcenter-privilege-check")
        self.assertEqual([item["decision"] for item in review["decisions"]],
                         ["allowed", "denied", "indeterminate"])

        @contextmanager
        def esxi(*_):
            yield None, Object(about=Object(apiType="HostAgent")), None, None
        with patch("vsphere_inventory.session", esxi):
            with self.assertRaisesRegex(CollectionError, "require vCenter"):
                evaluate_privileges("esx.example.test", 443, resource, "reader@example.test", privileges)

    def test_gcs_named_principal_preserves_provider_uncertainty(self):
        states = iter(("CAN_ACCESS", "CANNOT_ACCESS", "UNKNOWN_CONDITIONAL"))
        calls = []

        def fetch(url, params, token, quota, operation, *, payload=None):
            if payload is None:
                return {"name": "pilot-bucket", "projectNumber": "123", "metageneration": "1"}
            access_tuple = payload["accessTuple"]
            calls.append(access_tuple)
            self.assertEqual(url, "https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot")
            return {"accessTuple": access_tuple, "overallAccessState": next(states)}

        permissions = ["storage.objects.get", "storage.objects.create", "storage.objects.delete"]
        principal, decisions = troubleshoot("pilot-bucket", "123", permissions, principal="user@example.test",
                                            credential=lambda: "fixture", fetch=fetch)
        self.assertEqual(principal, "google-account:user@example.test")
        self.assertEqual([entry["decision"] for entry in decisions], ["allowed", "denied", "indeterminate"])
        self.assertEqual(calls, [
            {"principal": "user@example.test", "fullResourceName": "//storage.googleapis.com/projects/_/buckets/pilot-bucket",
             "permission": permission} for permission in permissions
        ])

    def test_gcs_checks_current_caller_with_provider_verified_bucket_identity(self):
        sync_gcs(self.path, "pilot", "source-ai", collect=lambda *_: [{
            "name": "pilot-artifacts", "project_number": "1234567890", "revision": "1", "facts": {},
        }])
        asset = self.get("assets")["assets"][0]["id"]
        permissions = ["storage.objects.get", "storage.objects.delete"]
        account = ["1234567890"]
        calls = []

        def transport(url, params, token, quota, operation):
            self.assertEqual(token, "fixture")
            calls.append(url)
            if url.endswith("/userinfo"):
                self.assertIsNone(quota)
                return {"sub": "5544332211"}
            if url.endswith("/iam/testPermissions"):
                self.assertEqual(params, [("permissions", item) for item in permissions])
                return {"kind": "storage#testIamPermissionsResponse", "permissions": [permissions[0]]}
            return {"name": "pilot-artifacts", "projectNumber": account[0], "metageneration": "1"}

        adapter = lambda *args: evaluate_gcs(*args, credential=lambda: "fixture", fetch=transport)
        saved = review_gcs_access(self.path, "pilot", asset, permissions, evaluate=adapter)
        detail = self.get("access-reviews/" + saved["id"])
        self.assertEqual(detail["mode"], "google-storage-caller-permissions")
        self.assertEqual(detail["principal"], "google-sub:5544332211")
        self.assertFalse(detail["inventory_changed"])
        self.assertEqual([row["decision"] for row in detail["decisions"]], ["allowed", "denied"])
        self.assertEqual(len(calls), 4)
        calls.clear()
        account[0] = "9999999"
        with self.assertRaisesRegex(CollectionError, "did not match"):
            review_gcs_access(self.path, "pilot", asset, permissions, evaluate=adapter)
        self.assertFalse(any(url.endswith("/iam/testPermissions") for url in calls))
        self.assertEqual(len(self.get("access-reviews")["reviews"]), 1)
