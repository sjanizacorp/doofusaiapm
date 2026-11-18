from pathlib import Path
import json
from types import SimpleNamespace
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from app import Product, Problem, import_bom, issue, sync_azure, sync_vsphere
from azure_inventory import discover as azure_discover, list_arm
from gcs import CollectionError
from vsphere_inventory import collect_properties, discover as vmware_discover


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state.sqlite"
        self.product = Product(self.path)
        self.token = issue(self.path, "pilot", "owner", "admin")
        self.other = issue(self.path, "other", "owner", "viewer")

    def call(self, method, endpoint, body=None, token=None):
        return self.product.request(method, "/api/v1/" + endpoint, token or self.token, body)[1]

    def test_azure_inventory_assessment_identity_and_foundry(self):
        subscription = "12345678-abcd-1234-abcd-123456789012"
        group, workspace = "Pilot-RG", "pilot-ml"
        root = (f"/subscriptions/{subscription}/resourceGroups/{group}"
                f"/providers/Microsoft.MachineLearningServices/workspaces/{workspace}")
        model = root + "/models/test-model"
        endpoint = root + "/onlineEndpoints/predict"
        owner = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        state = {"public": "Enabled", "role": True}
        audiences = []

        def credential(subject, audience):
            self.assertEqual(subject, subscription)
            audiences.append(audience)
            return "azure-token" if audience == "https://management.azure.com" else "foundry-token"

        def fetch(url, token):
            parts = urlsplit(url)
            if parts.hostname == "account.services.ai.azure.com":
                self.assertEqual(token, "foundry-token")
                self.assertEqual(parse_qs(parts.query)["api-version"], ["v1"])
                return {"data": [{"name": "support-agent", "versions": {
                    "latest": {"definition": {"model": "foundation-deployment"}},
                }}], "has_more": False}
            self.assertEqual(parts.hostname, "management.azure.com")
            self.assertEqual(token, "azure-token")
            suffix = parts.path.removeprefix(root)
            results = {
                "": {"id": root, "properties": {
                    "storageAccount": f"/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Storage/storageAccounts/pilot",
                }},
                "/models": {"value": [{"id": model}]},
                "/onlineEndpoints": {"value": [{"id": endpoint, "properties": {
                    "publicNetworkAccess": state["public"],
                }, "identity": {"principalId": owner}}]},
                "/onlineEndpoints/predict/deployments": {"value": [{"properties": {"model": "azureml:test-model:1"}}]},
                "/providers/Microsoft.Authorization/roleAssignments": {
                    "value": [{"properties": {"principalId": owner, "scope": root,
                                              "roleDefinitionId": "/roles/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}]
                    if state["role"] else [],
                },
            }
            return results[suffix]

        collect = lambda *args: azure_discover(*args, credential=credential, fetch=fetch)
        first = sync_azure(self.path, "pilot", subscription, group, workspace, True,
                           ("account", "project"), collect=collect)
        graph = self.call("GET", "cloud-graph")
        self.assertGreaterEqual(first["nodes"], 6)
        self.assertEqual(self.call("GET", "cloud-graph", token=self.other)["nodes"], [])
        self.assertIn("https://ai.azure.com", audiences)
        self.assertTrue(any(node["kind"] == "agent" for node in graph["nodes"]))
        self.assertTrue(any(edge["relation"] == "serves" for edge in graph["edges"]))
        agent = next(node["id"] for node in graph["nodes"] if node["kind"] == "agent")
        labels = {"agent": agent, "tool": "search", "operation": "read", "target": "approved"}
        self.call("POST", "agent-tool-rules", labels)
        token = issue(self.path, "pilot", "foundry-gateway", "operator",
                      runtime=("gateway", False, False), tool_agent=agent)
        self.assertEqual(self.call("POST", "runtime/authorize-tool", labels, token)["decision"], "allow")
        initial = {row["kind"]: row for row in self.call("GET", "issues")["issues"]}
        self.assertEqual(set(initial), {"azure-endpoint", "azure-identity"})
        state.update(public="Disabled", role=False)
        sync_azure(self.path, "pilot", subscription, group, workspace, True, ("account", "project"), collect=collect)
        resolved = {row["kind"]: row["id"] for row in self.call("GET", "issues?status=resolved")["issues"]}
        self.assertEqual(resolved, {kind: row["id"] for kind, row in initial.items()})
        with self.assertRaises(CollectionError):
            sync_azure(self.path, "pilot", subscription, group, workspace,
                       collect=lambda *_: (_ for _ in ()).throw(CollectionError("provider denied")))
        self.assertEqual(self.call("GET", "sync-runs")["runs"][0]["status"], "failed")
        self.assertEqual(self.call("GET", "issues?status=resolved")["issues"][0]["status"], "resolved")

    def test_azure_does_not_send_token_to_foreign_continuation(self):
        from_calls = []

        def fetch(url, _):
            from_calls.append(url)
            return {"value": [], "nextLink": "https://untrusted.example.test/inventory"}

        with self.assertRaisesRegex(CollectionError, "cannot leave"):
            list_arm("/scope/inventory", "fixture", fetch)
        self.assertEqual(len(from_calls), 1)

    def test_esxi_topology_answers_from_known_facts_only(self):
        def ref(identifier):
            return SimpleNamespace(_GetMoId=lambda: identifier)

        host, vm, store, network = map(ref, ("host-1", "vm-2", "ds-3", "network-4"))
        records = {
            "HostSystem": [(host, {"name": "production-test", "config.lockdownMode": "lockdownDisabled"})],
            "VirtualMachine": [(vm, {"name": "model-vm", "runtime.host": host, "datastore": [store], "network": [network],
                                     "config.flags.enableLogging": False, "config.firmware": "bios"})],
            "Datastore": [(store, {"name": "model-store"})],
            "Network": [(network, {"name": "service-portgroup"})],
        }
        collector = lambda *args: vmware_discover(*args, extract=lambda *_: records)
        first = sync_vsphere(self.path, "pilot", "esx.example.test", collect=collector)
        self.assertEqual(first["relationships"], 3)
        assets = self.call("GET", "assets")["assets"]
        vm_asset = next(item for item in assets if item["kind"] == "vsphere-vm")
        self.assertNotIn("efi_secure_boot_enabled", vm_asset["facts"])
        bom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                          "components": [{"type": "library", "name": "vm-runtime"}]}).encode()
        self.assertEqual(import_bom(self.path, "pilot", vm_asset["id"], bom)["status"], "imported")
        with self.assertRaises(Problem) as problem:
            self.call("POST", "scans", {"asset": vm_asset["id"]})
        self.assertEqual(problem.exception.status, 409)
        initial = {row["kind"]: row["id"] for row in self.call("GET", "issues")["issues"]}
        records["HostSystem"][0][1]["config.lockdownMode"] = "lockdownNormal"
        records["VirtualMachine"][0][1].update({"config.flags.enableLogging": True,
                                                "config.firmware": "efi",
                                                "config.bootOptions.efiSecureBootEnabled": True})
        sync_vsphere(self.path, "pilot", "esx.example.test", collect=collector)
        resolved = {row["kind"]: row["id"] for row in self.call("GET", "issues?status=resolved")["issues"]}
        self.assertEqual(resolved, initial)

    def test_vsphere_sdk_property_collector_paginates_and_cleans_up(self):
        def typed(**kwargs):
            return SimpleNamespace(**kwargs)

        spec_type = SimpleNamespace(TraversalSpec=typed, ObjectSpec=typed, PropertySpec=typed,
                                    FilterSpec=typed, RetrieveOptions=typed)
        vim = SimpleNamespace(view=SimpleNamespace(ContainerView=object))
        vmodl = SimpleNamespace(query=SimpleNamespace(PropertyCollector=spec_type))
        trace = []
        item = lambda value: SimpleNamespace(obj=value, propSet=[SimpleNamespace(name="name", val=value)])
        collector = SimpleNamespace(
            RetrievePropertiesEx=lambda specs, options: (
                trace.append(options.maxObjects) or SimpleNamespace(objects=[item("host-1")], token="next")),
            ContinueRetrievePropertiesEx=lambda token: (
                trace.append(token) or SimpleNamespace(objects=[item("host-2")], token=None)),
        )
        view = SimpleNamespace(Destroy=lambda: trace.append("destroyed"))
        content = SimpleNamespace(propertyCollector=collector, rootFolder=object(),
                                  viewManager=SimpleNamespace(CreateContainerView=lambda *args: view))
        result = collect_properties(content, vim, vmodl, object, ("name",))
        self.assertEqual(result, [("host-1", {"name": "host-1"}), ("host-2", {"name": "host-2"})])
        self.assertEqual(trace, [100, "next", "destroyed"])
