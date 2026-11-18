"""Read Azure ML, optional Foundry agent inventory, and explicitly scoped ARM RBAC metadata."""
import re
import subprocess
from urllib.parse import urlencode, urlsplit

from gcs import CollectionError, fetch_google

GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,89}")
HOST_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}")
ARM = "https://management.azure.com"
API_VERSION = "2025-12-01"
PRIVILEGED = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "b24988ac-6180-42a0-ab88-20f7382dd24c",
              "18d7d88d-d35e-4626-b4bd-58b5ac8b705e"}


def scope_key(subscription, group, workspace):
    if GUID.fullmatch(subscription) is None or any(NAME.fullmatch(item) is None for item in (group, workspace)):
        raise CollectionError("Use a subscription UUID and valid Azure resource group and workspace names.")
    return ":".join(("azure", subscription.lower(), group.lower(), workspace.lower()))


def access_token(subscription, audience):
    try:
        output = subprocess.run(
            ["az", "account", "get-access-token", "--subscription", subscription, "--resource", audience,
             "--query", "accessToken", "--output", "tsv", "--only-show-errors"],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, text=True, timeout=25,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise CollectionError("Could not obtain the required Azure CLI access token.") from None
    token = output.stdout.strip()
    if not 1 <= len(token) <= 8192 or not token.isascii() or any(char.isspace() for char in token):
        raise CollectionError("Azure CLI returned an invalid access token.")
    return token


def default_fetch(url, token):
    parts = urlsplit(url)
    # Keep provider-supplied opaque query strings intact.
    return fetch_google(url, None, token, None, f"Azure inventory ({parts.hostname})")


def records(document, key):
    rows = document.get(key) if isinstance(document, dict) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CollectionError("Azure returned a malformed inventory page.")
    return rows


def list_arm(path, token, fetch, *, api_version=API_VERSION, **query):
    params = urlencode({"api-version": api_version, **query})
    url = f"{ARM}{path}?{params}"
    seen, rows = set(), []
    for _ in range(20):
        if url in seen:
            raise CollectionError("Azure pagination did not advance.")
        seen.add(url)
        document = fetch(url, token)
        rows.extend(records(document, "value"))
        if len(rows) > 2000:
            raise CollectionError("Azure inventory exceeded the supported 2,000 item collection limit.")
        url = document.get("nextLink")
        if url is None or url == "":
            return rows
        if not isinstance(url, str) or len(url) > 8192:
            raise CollectionError("Azure returned a malformed pagination link.")
        try:
            location = urlsplit(url)
        except ValueError:
            raise CollectionError("Azure returned a malformed pagination link.") from None
        if location.scheme != "https" or location.netloc != "management.azure.com" or (
            location.path.lower() != path.lower() or location.fragment
        ):
            raise CollectionError("Azure pagination cannot leave the selected ARM collection.")
    raise CollectionError("Azure inventory exceeded the page limit.")


def resource(row, prefix):
    full_id = row.get("id")
    if not isinstance(full_id, str) or not full_id.lower().startswith(prefix.lower() + "/"):
        raise CollectionError("Azure returned a resource outside the requested scope.")
    remainder = full_id[len(prefix) + 1:]
    if NAME.fullmatch(remainder) is None:
        raise CollectionError("Azure returned an invalid resource name.")
    return full_id.lower(), remainder


def foundry_agents(subscription, account, project, *, fetch, credential):
    if HOST_NAME.fullmatch(account) is None or NAME.fullmatch(project) is None:
        raise CollectionError("Use valid Foundry account and project names.")
    root = f"https://{account.lower()}.services.ai.azure.com/api/projects/{project}/agents"
    token = credential(subscription, "https://ai.azure.com")
    seen, cursor = set(), None
    for _ in range(20):
        params = {"api-version": "v1", "limit": "100"}
        if cursor:
            params["after"] = cursor
        page = fetch(root + "?" + urlencode(params), token)
        yield from records(page, "data")
        more = page.get("has_more", False)
        if type(more) is not bool:
            raise CollectionError("Foundry returned invalid pagination metadata.")
        if not more:
            return
        cursor = page.get("last_id")
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 250 or cursor in seen:
            raise CollectionError("Foundry agent pagination did not advance.")
        seen.add(cursor)
    raise CollectionError("Foundry agents exceeded the page limit.")


def discover(subscription, group, workspace, rbac=False, foundry=None, *,
             credential=access_token, fetch=default_fetch):
    scope_key(subscription, group, workspace)
    token = credential(subscription, ARM)
    sub = "/subscriptions/" + subscription
    rg = sub + "/resourceGroups/" + group
    root = rg + "/providers/Microsoft.MachineLearningServices/workspaces/" + workspace
    workspace_data = fetch(f"{ARM}{root}?api-version={API_VERSION}", token)
    if not isinstance(workspace_data, dict) or str(workspace_data.get("id", "")).lower() != root.lower():
        raise CollectionError("Azure returned an unexpected workspace.")
    nodes, edges, identity_by_guid = {}, set(), {}

    def node(key, kind, name, **fields):
        if key not in nodes and len(nodes) >= 4000:
            raise CollectionError("Azure topology exceeds 4,000 nodes.")
        nodes.setdefault(key, {"kind": kind, "name": name, **fields})

    def identity(origin, record):
        if not isinstance(record, dict):
            return
        entries = [(origin + ":identity", record)]
        assigned = record.get("userAssignedIdentities", {})
        if isinstance(assigned, dict):
            entries.extend((identifier.lower(), data) for identifier, data in assigned.items()
                           if isinstance(identifier, str) and "/providers/microsoft.managedidentity/userassignedidentities/" in identifier.lower()
                           and len(identifier) <= 500 and identifier.isprintable() and isinstance(data, dict))
        for ref, value in entries:
            principal = value.get("principalId")
            if isinstance(principal, str) and GUID.fullmatch(principal):
                key = "azure-principal:" + principal.lower()
                identity_by_guid[principal.lower()] = key
                node(key, "identity", ref)
                edges.add((origin, key, "uses_identity"))

    ws = root.lower()
    node(ws, "workspace", workspace)
    identity(ws, workspace_data.get("identity"))
    properties = workspace_data.get("properties") or {}
    if isinstance(properties, dict):
        storage = properties.get("storageAccount")
        if isinstance(storage, str) and len(storage) <= 500 and "/providers/microsoft.storage/storageaccounts/" in storage.lower():
            name = storage.rsplit("/", 1)[-1]
            if NAME.fullmatch(name):
                node(storage.lower(), "data", name)
                edges.add((ws, storage.lower(), "workspace_storage"))

    model_root = root + "/models"
    endpoints_root = root + "/onlineEndpoints"
    models = list_arm(model_root, token, fetch)
    endpoints = list_arm(endpoints_root, token, fetch)
    if len(endpoints) > 200:
        raise CollectionError("Azure ML endpoint listing exceeds 200 endpoints per workspace.")
    for row in models:
        key, name = resource(row, model_root)
        node(key, "model", name)
        edges.add((ws, key, "contains"))
    for item in endpoints:
        key, name = resource(item, endpoints_root)
        properties = item.get("properties")
        access = properties.get("publicNetworkAccess") if isinstance(properties, dict) else None
        exposure = {"Enabled": "public_network_configuration", "Disabled": "private_configuration"}.get(
            access if isinstance(access, str) else "")
        node(key, "endpoint", name, exposure=exposure)
        identity(key, item.get("identity"))
        edges.add((ws, key, "contains"))
        if len(edges) > 12000:
            raise CollectionError("Azure topology exceeds 12,000 relationships.")
        for deployment in list_arm(endpoints_root + "/" + name + "/deployments", token, fetch):
            config = deployment.get("properties")
            model = config.get("model") if isinstance(config, dict) else None
            if isinstance(model, str):
                canonical = model.lower().removeprefix("azureml:")
                if ":" in canonical and "/" not in canonical:
                    name, _, version = canonical.partition(":")
                    if NAME.fullmatch(name) and NAME.fullmatch(version):
                        canonical = model_root.lower() + "/" + name
                base = canonical.split("/versions/", 1)[0]
                if base in nodes and nodes[base]["kind"] == "model":
                    edges.add((key, base, "serves"))

    if rbac:
        scopes = {part.lower() for part in (sub, rg, root)}
        assignments = list_arm(root + "/providers/Microsoft.Authorization/roleAssignments", token, fetch,
                               api_version="2022-04-01", **{"$filter": "atScope()"})
        for ref in identity_by_guid.values():
            nodes[ref]["exposure"] = "azure_no_matching_role"
        for entry in assignments:
            fields = entry.get("properties")
            if not isinstance(fields, dict):
                continue
            principal, definition, scope = [fields.get(key) for key in ("principalId", "roleDefinitionId", "scope")]
            if all(isinstance(value, str) for value in (principal, definition, scope)) and (
                principal.lower() in identity_by_guid and scope.lower() in scopes
                and definition.rsplit("/", 1)[-1].lower() in PRIVILEGED
            ):
                nodes[identity_by_guid[principal.lower()]]["exposure"] = "azure_privileged_role"

    if foundry:
        account, project = foundry
        for number, entry in enumerate(foundry_agents(subscription, account, project, fetch=fetch, credential=credential)):
            if number >= 2000:
                raise CollectionError("Foundry agent inventory exceeded 2,000 agents.")
            name = entry.get("name")
            if not isinstance(name, str) or NAME.fullmatch(name) is None:
                raise CollectionError("Foundry returned an invalid agent name.")
            key = "foundry:" + account.lower() + "/" + project + "/" + name
            node(key, "agent", name)
            version = entry.get("versions")
            latest = version.get("latest") if isinstance(version, dict) else None
            definition = latest.get("definition") if isinstance(latest, dict) else None
            model = definition.get("model") if isinstance(definition, dict) else None
            if isinstance(model, str) and NAME.fullmatch(model):
                model_key = f"foundry:{account.lower()}/{project}/model/{model}"
                node(model_key, "model", model)
                edges.add((key, model_key, "uses_model"))
    if len(edges) > 12000:
        raise CollectionError("Azure topology exceeds 12,000 relationships.")
    return nodes, sorted(edges)
