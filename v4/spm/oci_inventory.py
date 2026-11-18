"""Compartment-scoped OCI Data Science inventory."""
from concurrent.futures import ThreadPoolExecutor
import json
import re
import subprocess
import tempfile

from gcs import CollectionError

REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+")
OCID = re.compile(r"ocid1\.[a-z]+\.oc[a-z0-9]*\.[a-z0-9-]*\.[a-z0-9]{1,180}")


def valid_id(value, *kinds):
    return (isinstance(value, str) and OCID.fullmatch(value) is not None
            and value.split(".")[1] in kinds)


def scope_key(compartment, region):
    if not valid_id(compartment, "compartment", "tenancy") or REGION.fullmatch(region) is None:
        raise CollectionError("Use an OCI compartment or tenancy OCID and region.")
    return f"oci:{region}:{compartment}"


def cli(region, resource, *arguments):
    command = ["oci", "data-science", resource, *arguments, "--region", region, "--output", "json"]
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                           timeout=45, check=True)
        except (OSError, subprocess.SubprocessError):
            raise CollectionError(f"OCI Data Science {resource} request failed.") from None
        output.seek(0)
        response = output.read(2 * 1024 * 1024 + 1)
    if len(response) > 2 * 1024 * 1024:
        raise CollectionError("OCI inventory exceeded the response limit.")
    try:
        return json.loads(response)
    except (ValueError, RecursionError):
        raise CollectionError("OCI returned invalid JSON.") from None


def deployment_detail(call, region, compartment, key, project):
    reply = call(region, "model-deployment", "get", "--model-deployment-id", key)
    item = reply.get("data") if isinstance(reply, dict) else None
    if (not isinstance(item, dict) or item.get("id") != key or item.get("compartment-id") != compartment
            or item.get("project-id") != project or item.get("lifecycle-state") in ("DELETED", "DELETING")):
        raise CollectionError("OCI deployment detail did not match the listed asset.")
    configuration = item.get("model-deployment-configuration-details")
    if not isinstance(configuration, dict) or not isinstance(configuration.get("deployment-type"), str):
        raise CollectionError("OCI returned missing model deployment configuration.")
    model = None
    if configuration["deployment-type"] in ("SINGLE_MODEL", "SINGLE_MODEL_FLEX"):
        details = configuration.get("model-configuration-details")
        model = details.get("model-id") if isinstance(details, dict) else None
        if not valid_id(model, "datasciencemodel"):
            raise CollectionError("OCI returned an invalid deployed model reference.")
    facts = {}
    if "category-log-details" in item:
        logs = item["category-log-details"]
        if logs is not None and not isinstance(logs, dict):
            raise CollectionError("OCI returned malformed deployment logging configuration.")
        access = (logs or {}).get("access")
        if access is not None and not isinstance(access, dict):
            raise CollectionError("OCI returned malformed access logging configuration.")
        if access is None:
            facts["access_logging_configured"] = False
        elif valid_id(access.get("log-id"), "log") and valid_id(access.get("log-group-id"), "loggroup"):
            facts["access_logging_configured"] = True
        else:
            raise CollectionError("OCI returned incomplete access logging configuration.")
    return key, model, facts


def discover(compartment, region, *, call=cli, include_deployment_details=False):
    scope_key(compartment, region)
    nodes, edges, deployments = {}, [], []
    for resource, kind, id_kind in (("project", "service", "datascienceproject"),
                                    ("model", "model", "datasciencemodel"),
                                    ("model-deployment", "endpoint", "datasciencemodeldeployment")):
        reply = call(region, resource, "list", "--compartment-id", compartment, "--all")
        items = reply.get("data") if isinstance(reply, dict) else None
        if not isinstance(items, list) or len(items) + len(nodes) > 500:
            raise CollectionError("OCI returned invalid inventory or exceeded the 500 asset limit.")
        for item in items:
            key = item.get("id") if isinstance(item, dict) else None
            if not valid_id(key, id_kind) or key in nodes or item.get("compartment-id") != compartment:
                raise CollectionError("OCI returned an invalid or out-of-scope Data Science asset.")
            state = item.get("lifecycle-state")
            if not isinstance(state, str):
                raise CollectionError("OCI returned an invalid lifecycle state.")
            if state in ("DELETED", "DELETING"):
                continue
            name = item.get("display-name")
            if not isinstance(name, str) or not name or len(name) > 255 or not name.isprintable():
                raise CollectionError("OCI returned an invalid Data Science asset name.")
            node = {"kind": kind, "name": name}
            nodes[key] = node
            if kind != "service":
                project = item.get("project-id")
                if not valid_id(project, "datascienceproject"):
                    raise CollectionError("OCI returned an invalid project relationship.")
                if project in nodes:
                    edges.append((project, key, "contains"))
            if kind == "endpoint":
                deployments.append((key, project))
                states = {"ACTIVE": True, "FAILED": False, "NEEDS_ATTENTION": False}
                node["facts"] = {"operational": states[state]} if state in states else {}
    if include_deployment_details:
        if len(deployments) > 100:
            raise CollectionError("OCI detailed collection is limited to 100 deployments per compartment.")
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(deployment_detail, call, region, compartment, key, project)
                       for key, project in deployments]
            for future in futures:
                key, model, facts = future.result()
                nodes[key]["facts"].update(facts)
                if model in nodes and nodes[model]["kind"] == "model":
                    edges.append((key, model, "serves"))
    return nodes, edges
