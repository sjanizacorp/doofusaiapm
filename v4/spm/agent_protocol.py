"""Configuration and snapshot contract for platform collection agents."""
import re
from pathlib import Path

import aws_inventory
import azure_inventory
import gcs
import ibm_inventory
import oci_inventory
import salesforce_inventory
import vertex
import vsphere_inventory
from controls import Problem, parse_time

MAX_REPORT = 2 * 1024 * 1024
PROVIDERS = {"gcs", "vertex", "aws", "azure", "oci", "ibm", "salesforce", "vsphere"}
KINDS = {"agent", "automation", "data", "endpoint", "host", "identity", "model", "network", "repository",
         "service", "virtual_machine", "workspace"}
EXPOSURES = {"unknown", "private_configuration", "public_network_configuration", "analyzer_external_access",
             "analyzer_resolved", "azure_no_matching_role", "azure_privileged_role", "active_flow_version"}
RELATION = re.compile(r"[a-z][a-z0-9_]{0,39}")


def text(value, size):
    return isinstance(value, str) and 0 < len(value) <= size and value.isprintable()


def deployment(provider, arguments):
    if not isinstance(provider, str) or provider not in PROVIDERS or not isinstance(arguments, list):
        raise Problem(400, "Use a supported agent provider and argument array.")
    if any(not text(item, 300) or item.startswith("-") for item in arguments):
        raise Problem(400, "Invalid collection arguments.")
    counts = {"gcs": (1,), "vertex": (2,), "aws": (2, 3), "azure": (3,), "oci": (2,),
              "ibm": (2,), "salesforce": (2, 3), "vsphere": (1, 2)}
    if len(arguments) not in counts[provider]:
        raise Problem(400, "Wrong number of collection arguments for this provider.")
    try:
        if provider == "gcs":
            (project,) = arguments
            return gcs.project_id(project), lambda: gcs.discover(project)
        if provider == "vertex":
            project, region = arguments
            gcs.project_id(project)
            vertex.checked_location(region)
            return f"{project}:{region}", lambda: vertex.discover(project, region)
        if provider == "aws":
            account, region, *optional = arguments
            aws_inventory.parameters(account, region)
            analyzer = optional[0] if optional else None
            if analyzer and not re.fullmatch(rf"arn:aws(?:-[a-z0-9-]+)?:access-analyzer:{region}:{account}:analyzer/[A-Za-z0-9_-]+", analyzer):
                raise gcs.CollectionError("Use an Access Analyzer ARN in the selected account and region.")
            return f"aws:{account}:{region}", lambda: aws_inventory.discover(account, region, analyzer)
        if provider == "azure":
            return azure_inventory.scope_key(*arguments), lambda: azure_inventory.discover(*arguments)
        if provider == "oci":
            return oci_inventory.scope_key(*arguments), lambda: oci_inventory.discover(*arguments)
        if provider == "ibm":
            return ibm_inventory.scope_key(*arguments), lambda: ibm_inventory.discover(*arguments)
        if provider == "salesforce":
            host, org, *version = arguments
            release = version[0] if version else "63.0"
            if not salesforce_inventory.VERSION.fullmatch(release):
                raise gcs.CollectionError("Use a Salesforce REST API version such as 68.0.")
            return (salesforce_inventory.scope_key(host, org),
                    lambda: salesforce_inventory.discover(host, org, release,
                                                         include_agentforce=int(release.split(".")[0]) >= 68))
        host, *options = arguments
        port = int(options[0]) if options else 443
        scope = vsphere_inventory.scope_key(host, port)
        def collect_vsphere():
            import os
            ca = os.environ.get("DOOFUS_AGENT_VSPHERE_CA")
            return vsphere_inventory.discover(host, port, Path(ca) if ca else None)
        return scope, collect_vsphere
    except (ValueError, gcs.CollectionError) as error:
        raise Problem(400, str(error)) from None


def validate_snapshot(provider, payload, assessment, checks):
    def bad():
        raise Problem(400, "Invalid or oversized agent snapshot.")
    def facts(value, allowed):
        if not isinstance(value, dict) or any(key not in allowed or type(val) is not bool
                                              for key, val in value.items()):
            bad()

    if provider == "gcs":
        if not isinstance(payload, list) or len(payload) > 2000:
            bad()
        names, projects = set(), set()
        for bucket in payload:
            if (not isinstance(bucket, dict) or set(bucket) != {"name", "project_number", "revision", "facts"}
                    or not isinstance(bucket["name"], str) or not gcs.BUCKET.fullmatch(bucket["name"])
                    or bucket["name"] in names):
                bad()
            names.add(bucket["name"])
            for key in ("project_number", "revision"):
                if not isinstance(bucket[key], str) or not re.fullmatch(r"[0-9]{1,20}", bucket[key]):
                    bad()
            projects.add(bucket["project_number"])
            facts(bucket["facts"], {check[1] for check in checks["gcs-bucket"]})
        if len(projects) > 1:
            bad()
        return payload
    if not isinstance(payload, dict) or set(payload) != {"nodes", "edges"}:
        bad()
    nodes, edges = payload["nodes"], payload["edges"]
    if not isinstance(nodes, dict) or len(nodes) > 2400 or not isinstance(edges, list) or len(edges) > 10000:
        bad()
    for key, node in nodes.items():
        if (not text(key, 1024) or not isinstance(node, dict)
                or node.keys() - {"kind", "name", "facts", "exposure", "sensitivity", "profile_observed"}
                or not text(node.get("kind"), 40) or node["kind"] not in KINDS or not text(node.get("name"), 320)):
            bad()
        exposure = node.get("exposure")
        if exposure is not None and (not isinstance(exposure, str) or exposure not in EXPOSURES):
            bad()
        if provider == "vertex" and node["kind"] == "endpoint" and exposure not in (
                "unknown", "private_configuration", "public_network_configuration"):
            bad()
        if node.get("sensitivity") not in (None, "unknown", "low", "moderate", "high"):
            bad()
        if node.get("profile_observed") is not None:
            parse_time(node["profile_observed"])
        candidate = assessment(provider, {"facts": {}, **node})
        if candidate:
            facts(candidate[2], {check[1] for check in checks[candidate[0]]})
        if "facts" in node:
            facts(node["facts"], {check[1] for check in checks[candidate[0]]} if candidate else set())
        if candidate and provider in ("vsphere", "oci", "ibm"):
            node.setdefault("facts", {})
    edge_set = set()
    for edge in edges:
        if (not isinstance(edge, list) or len(edge) != 3 or not all(isinstance(item, str) for item in edge)
                or edge[0] not in nodes or edge[1] not in nodes or not RELATION.fullmatch(edge[2])
                or tuple(edge) in edge_set):
            bad()
        edge_set.add(tuple(edge))
    return nodes, edges
