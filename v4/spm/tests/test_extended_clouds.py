from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app import Product, issue, sync_cloud_graph
from gcs import CollectionError
import ibm_inventory
import oci_inventory
import salesforce_inventory

COMPARTMENT = "ocid1.compartment.oc1..aaaa"
OCI_PROJECT = "ocid1.datascienceproject.oc1.iad.bbbb"
OCI_MODEL = "ocid1.datasciencemodel.oc1.iad.cccc"
OCI_DEPLOYMENT = "ocid1.datasciencemodeldeployment.oc1.iad.dddd"
SPACE = "4e1458f9-6efc-42b2-8c51-affe37a0ed73"
MODEL = "39a2f86a-04b1-4b1e-aa9b-d2c9af977c30"
DEPLOYMENT = "312bdaa8-b584-40a6-aafe-ccdc186ff40e"
ORG = "00D000000000001"
HOST = "company--uat.sandbox.my.salesforce.com"
FLOW = "300000000000001"
FLOW_VERSION = "301000000000001"


class ExtendedCloudTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "pilot", "admin", "admin")
        self.other = issue(self.path, "other", "admin", "admin")

    def get(self, endpoint, token=None):
        return self.product.request("GET", "/api/v1/" + endpoint, token or self.admin)[1]

    def test_oci_health_and_failed_refresh_preserves_inventory(self):
        state = "NEEDS_ATTENTION"
        compartment = COMPARTMENT
        scope = oci_inventory.scope_key(COMPARTMENT, "us-ashburn-1")

        def call(region, kind, action, flag, requested, pagination):
            self.assertEqual((region, action, flag, requested, pagination),
                             ("us-ashburn-1", "list", "--compartment-id", COMPARTMENT, "--all"))
            resource = {"project": OCI_PROJECT, "model": OCI_MODEL, "model-deployment": OCI_DEPLOYMENT}[kind]
            return {"data": [{"id": resource, "compartment-id": compartment, "display-name": kind,
                              "project-id": OCI_PROJECT, "lifecycle-state": state}]}

        def sync():
            return sync_cloud_graph(self.path, "pilot", "oci", scope,
                                    lambda: oci_inventory.discover(COMPARTMENT, "us-ashburn-1", call=call))

        self.assertEqual(sync()["relationships"], 2)
        self.assertEqual(self.get("issues")["issues"][0]["kind"], "oci-endpoint")
        compartment = "ocid1.compartment.oc1..another"
        with self.assertRaises(CollectionError):
            sync()
        self.assertEqual(len(self.get("cloud-graph")["nodes"]), 3)
        self.assertEqual(self.get("sync-runs")["runs"][0]["status"], "failed")
        self.assertEqual(self.get("cloud-graph", self.other)["nodes"], [])
        compartment, state = COMPARTMENT, "ACTIVE"
        sync()
        self.assertEqual(self.get("issues")["issues"], [])

    def test_oci_deployment_detail_adds_verified_model_and_logging_evidence(self):
        actual = COMPARTMENT
        logging = {"access": None}
        resources = {
            "project": OCI_PROJECT, "model": OCI_MODEL, "model-deployment": OCI_DEPLOYMENT,
        }
        scope = oci_inventory.scope_key(COMPARTMENT, "us-ashburn-1")

        def call(region, resource, operation, *arguments):
            key = resources[resource]
            common = {"id": key, "project-id": OCI_PROJECT, "display-name": resource,
                      "compartment-id": COMPARTMENT, "lifecycle-state": "ACTIVE"}
            if operation == "list":
                return {"data": [common]}
            self.assertEqual(arguments, ("--model-deployment-id", OCI_DEPLOYMENT))
            return {"data": common | {
                "compartment-id": actual,
                "category-log-details": logging,
                "model-deployment-configuration-details": {
                    "deployment-type": "SINGLE_MODEL",
                    "model-configuration-details": {"model-id": OCI_MODEL},
                },
            }}

        def sync():
            return sync_cloud_graph(self.path, "pilot", "oci", scope, lambda: oci_inventory.discover(
                COMPARTMENT, "us-ashburn-1", call=call, include_deployment_details=True,
            ))

        self.assertEqual(sync()["relationships"], 3)
        self.assertIn("serves", {edge["relation"] for edge in self.get("cloud-graph")["edges"]})
        self.assertEqual(len(self.get("issues")["issues"]), 1)
        actual = "ocid1.compartment.oc1..other"
        with self.assertRaises(CollectionError):
            sync()
        self.assertEqual(len(self.get("cloud-graph")["edges"]), 3)
        actual = COMPARTMENT
        logging = {"access": {"log-id": "ocid1.log.oc1.iad.aaaa", "log-group-id": "ocid1.loggroup.oc1.iad.bbbb"}}
        sync()
        self.assertEqual(self.get("issues")["issues"], [])

    def test_ibm_paginates_with_space_bound_to_the_request(self):
        def fetch(url, params, token, quota, operation):
            self.assertEqual(params["space_id"], SPACE)
            self.assertEqual(token, "fixture")
            if url.endswith("/models"):
                if "start" not in params:
                    return {"resources": [], "next": {"href": "/ml/v4/models?start=next&space_id=other"}}
                self.assertEqual(params["start"], "next")
                return {"resources": [{"metadata": {"id": MODEL, "name": "Model", "space_id": SPACE},
                                       "entity": {}}]}
            return {"resources": [{"metadata": {"id": DEPLOYMENT, "name": "Deployment", "space_id": SPACE},
                                   "entity": {"asset": {"id": MODEL}, "status": {"state": "failed"}}}]}

        scope = ibm_inventory.scope_key(SPACE, "us-south")
        result = sync_cloud_graph(self.path, "pilot", "ibm", scope,
                                  lambda: ibm_inventory.discover(SPACE, "us-south", fetch=fetch, token="fixture"))
        self.assertEqual(result["relationships"], 1)
        self.assertEqual(self.get("cloud-graph")["edges"][0]["relation"], "serves")
        self.assertEqual(self.get("issues")["issues"][0]["kind"], "ibm-endpoint")
        with self.assertRaises(CollectionError):
            ibm_inventory.discover(SPACE, "us-south", token="fixture", fetch=lambda *_: {
                "resources": [], "next": {"href": "https://untrusted.example/ml/v4/models?start=bad"},
            })

    def test_salesforce_requires_expected_org_and_scoped_continuation(self):
        actual, continuation = ORG, "/services/data/v63.0/tooling/query/01g-next"
        calls = []

        def fetch(url, params, token, quota, operation):
            calls.append(url)
            self.assertTrue(url.startswith(f"https://{HOST}/services/"))
            if "/tooling/" not in url:
                return {"records": [{"Id": actual, "IsSandbox": True}], "done": True}
            if params is not None:
                self.assertIn("FROM FlowDefinition", params["q"])
                return {"records": [], "done": False, "nextRecordsUrl": continuation}
            return {"records": [{"Id": FLOW, "DeveloperName": "Follow_Up",
                                 "NamespacePrefix": "example", "ActiveVersionId": FLOW_VERSION}], "done": True}

        scope = salesforce_inventory.scope_key(HOST, ORG)
        sync_cloud_graph(self.path, "pilot", "salesforce", scope,
                         lambda: salesforce_inventory.discover(HOST, ORG, fetch=fetch, token="fixture"))
        self.assertEqual(self.get("cloud-graph")["nodes"][1]["name"], "example__Follow_Up")
        self.assertEqual(self.get("cloud-graph")["edges"][0]["relation"], "contains")
        actual, calls[:] = "00D000000000002", []
        with self.assertRaises(CollectionError):
            salesforce_inventory.discover(HOST, ORG, fetch=fetch, token="fixture")
        self.assertEqual(len(calls), 1)
        actual, continuation, calls[:] = ORG, "/services/data/v63.0/query/replaced", []
        with self.assertRaises(CollectionError):
            salesforce_inventory.discover(HOST, ORG, fetch=fetch, token="fixture")
        self.assertEqual(len(calls), 2)
