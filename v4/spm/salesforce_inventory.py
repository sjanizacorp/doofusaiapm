"""Salesforce org and Flow metadata via read-only REST and Tooling queries."""
import os
import re

import agentforce
from gcs import CollectionError, fetch_google

HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})*\.my\.salesforce\.com")
ORG = re.compile(r"00D[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?")
RECORD = re.compile(r"[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?")
VERSION = re.compile(r"[0-9]{2}\.0")
TOKEN = re.compile(r"[A-Za-z0-9!._~+/=-]{1,8192}")


def scope_key(host, org):
    if not HOST.fullmatch(host) or not ORG.fullmatch(org):
        raise CollectionError("Use a Salesforce My Domain hostname and a Salesforce org ID.")
    return f"salesforce:{org[:15]}"


def discover(host, org, version="63.0", *, fetch=fetch_google, token=None, include_agentforce=False, listing=agentforce.list_metadata):
    scope_key(host, org)
    if not VERSION.fullmatch(version):
        raise CollectionError("Use a Salesforce REST API version such as 63.0.")
    if include_agentforce and int(version.split(".")[0]) < 68:
        raise CollectionError("Agentforce discovery requires Salesforce API version 68.0 or later.")
    token = token if token is not None else os.environ.get("DOOFUS_SALESFORCE_TOKEN", "")
    if not TOKEN.fullmatch(token):
        raise CollectionError("Supply a short-lived Salesforce OAuth token in DOOFUS_SALESFORCE_TOKEN.")
    base = f"/services/data/v{version}"
    origin = f"https://{host}"
    identity = fetch(origin + base + "/query", {"q": "SELECT Id, IsSandbox FROM Organization"},
                     token, None, "Salesforce organization inventory")
    records = identity.get("records") if isinstance(identity, dict) else None
    if (not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict)
            or identity.get("done") is not True):
        raise CollectionError("Salesforce did not return exactly one organization.")
    actual = records[0].get("Id")
    sandbox = records[0].get("IsSandbox")
    if not isinstance(actual, str) or not ORG.fullmatch(actual) or actual[:15] != org[:15] or type(sandbox) is not bool:
        raise CollectionError("Salesforce returned a different organization or invalid environment metadata.")
    org_key = org[:15]
    nodes = {org_key: {"kind": "service", "name": "Salesforce sandbox" if sandbox else "Salesforce organization"}}
    edges, seen = [], set()
    path = base + "/tooling/query"
    params = {"q": "SELECT Id, DeveloperName, NamespacePrefix, ActiveVersionId FROM FlowDefinition"}
    for _ in range(20):
        page = fetch(origin + path, params, token, None, "Salesforce Flow inventory")
        records = page.get("records") if isinstance(page, dict) else None
        if not isinstance(records, list) or len(nodes) + len(records) > 500 or type(page.get("done")) is not bool:
            raise CollectionError("Salesforce returned invalid Flow inventory or exceeded the 499 Flow limit.")
        for flow in records:
            key = flow.get("Id") if isinstance(flow, dict) else None
            if not isinstance(key, str) or not RECORD.fullmatch(key) or key[:15] in nodes:
                raise CollectionError("Salesforce returned an invalid or duplicate Flow ID.")
            key = key[:15]
            name = flow.get("DeveloperName")
            namespace = flow.get("NamespacePrefix")
            active = flow.get("ActiveVersionId")
            if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_]{1,255}", name) is None
                    or (namespace is not None and (not isinstance(namespace, str)
                        or re.fullmatch(r"[A-Za-z0-9_]{1,40}", namespace) is None))
                    or (active is not None and (not isinstance(active, str) or not RECORD.fullmatch(active)))
                    or "ActiveVersionId" not in flow):
                raise CollectionError("Salesforce returned invalid Flow metadata.")
            nodes[key] = {"kind": "automation", "name": f"{namespace}__{name}" if namespace else name,
                          "exposure": "active_flow_version" if active else None}
            edges.append((org_key, key, "contains"))
        if page["done"]:
            if include_agentforce:
                agentforce.collect(origin, version, token, org_key, nodes, edges, listing=listing)
            return nodes, edges
        path = page.get("nextRecordsUrl")
        if (not isinstance(path, str) or re.fullmatch(re.escape(base) + r"/tooling/query/[A-Za-z0-9_-]{1,160}",
                                                     path) is None or path in seen):
            raise CollectionError("Salesforce returned an invalid or repeated Flow continuation.")
        seen.add(path)
        params = None
    raise CollectionError("Salesforce Flow inventory exceeded the pagination limit.")
