"""Read-only property inventory for ESXi and vCenter via the vSphere Web Services API."""
from contextlib import contextmanager, suppress
import os
import re
import ssl

from gcs import CollectionError

HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
MOID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
PRIVILEGE = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+){1,8}")
OBJECT_LIMIT = 2000
PROPERTIES = {
    "HostSystem": ("name", "config.lockdownMode"),
    "VirtualMachine": ("name", "config.flags.enableLogging", "config.firmware",
                       "config.bootOptions.efiSecureBootEnabled", "runtime.host", "datastore", "network"),
    "Datastore": ("name",),
    "Network": ("name",),
}
KINDS = {"HostSystem": "host", "VirtualMachine": "virtual_machine", "Datastore": "data", "Network": "network"}


def scope_key(host, port):
    if HOST.fullmatch(host) is None or ".." in host or not 1 <= port <= 65535:
        raise CollectionError("Use an ESXi or vCenter DNS name or IPv4 address and valid port.")
    return f"vsphere:{host.lower()}:{port}"


@contextmanager
def session(host, port, ca_file=None):
    scope_key(host, port)
    user, password = os.environ.get("SPM_VSPHERE_USER"), os.environ.get("SPM_VSPHERE_PASSWORD")
    if not user or not password:
        raise CollectionError("Set SPM_VSPHERE_USER and SPM_VSPHERE_PASSWORD for a read-only vSphere account.")
    try:
        from pyVim.connect import Disconnect, SmartConnect
        from pyVmomi import vim, vmodl
    except ImportError:
        raise CollectionError("Install pyVmomi from requirements-vsphere.txt for ESXi or vCenter discovery.") from None
    service = None
    try:
        context = ssl.create_default_context(cafile=ca_file)
        service = SmartConnect(host=host, port=port, user=user, pwd=password,
                               sslContext=context, httpConnectionTimeout=15)
        yield service, service.RetrieveContent(), vim, vmodl
    except CollectionError:
        raise
    except Exception:
        # Do not surface SDK errors that may embed authentication or session data.
        raise CollectionError("vSphere request failed. Check connectivity, TLS trust and read permissions.") from None
    finally:
        if service is not None:
            with suppress(Exception):
                Disconnect(service)


def retrieve(host, port, ca_file=None):
    with session(host, port, ca_file) as (_, content, vim, vmodl):
        return {kind: collect_properties(content, vim, vmodl, getattr(vim, kind), paths)
                for kind, paths in PROPERTIES.items()}


def validate_review_inputs(principal, privileges):
    if (not isinstance(principal, str) or not 1 <= len(principal) <= 200 or not principal.isprintable()
            or not (re.fullmatch(r"[^@\\\s]+@[^@\\\s]+", principal)
                    or re.fullmatch(r"[^@\\\s]+\\[^@\\]+", principal))):
        raise CollectionError("Use a vCenter user principal such as user@example.com or DOMAIN\\user.")
    if (not 1 <= len(privileges) <= 30 or len(set(privileges)) != len(privileges)
            or any(len(item) > 128 or PRIVILEGE.fullmatch(item) is None for item in privileges)):
        raise CollectionError("Supply one to 30 distinct vCenter privilege IDs.")


def privilege_results(response, target, privileges):
    if (not isinstance(response, (list, tuple)) or len(response) != 1
            or object_id(getattr(response[0], "entity", None)) != target):
        raise CollectionError("vCenter did not identify the requested inventory object.")
    results = {}
    entries = getattr(response[0], "privAvailability", None) or []
    if not isinstance(entries, (list, tuple)) or len(entries) > len(privileges):
        raise CollectionError("vCenter returned malformed privilege evidence.")
    for entry in entries:
        name, granted = getattr(entry, "privId", None), getattr(entry, "isGranted", None)
        if name not in privileges or name in results or type(granted) is not bool:
            raise CollectionError("vCenter returned malformed privilege evidence.")
        results[name] = granted
    return [{"action": item, "decision": ("allowed" if results[item] else "denied")
             if item in results else "indeterminate"} for item in privileges]


def evaluate_privileges(host, port, resource, principal, privileges, ca_file=None):
    validate_review_inputs(principal, privileges)
    kind, _, moid = resource.partition(":")
    if kind not in ("HostSystem", "VirtualMachine") or MOID.fullmatch(moid) is None:
        raise CollectionError("Only an inventoried vSphere host or VM can be reviewed.")
    with session(host, port, ca_file) as (service, content, vim, _):
        if content.about.apiType != "VirtualCenter":
            raise CollectionError("Named-user privilege checks require vCenter. Sync this host through vCenter first.")
        target = getattr(vim, kind)(moid, service._stub)
        review = content.authorizationManager.HasUserPrivilegeOnEntities(
            entities=[target], userName=principal, privId=list(privileges),
        )
        return privilege_results(review, moid, privileges)


def collect_properties(content, vim, vmodl, managed_type, paths):
    pc = vmodl.query.PropertyCollector
    collector = content.propertyCollector
    view = content.viewManager.CreateContainerView(content.rootFolder, [managed_type], True)
    token = None
    try:
        traversal = pc.TraversalSpec(name="inventory", type=vim.view.ContainerView, path="view", skip=False)
        objects = pc.ObjectSpec(obj=view, skip=True, selectSet=[traversal])
        properties = pc.PropertySpec(type=managed_type, all=False, pathSet=list(paths))
        spec = pc.FilterSpec(objectSet=[objects], propSet=[properties])
        page = collector.RetrievePropertiesEx([spec], pc.RetrieveOptions(maxObjects=100))
        seen = set()
        records = []
        for _ in range(40):
            if page is None:
                return records
            for item in page.objects or []:
                records.append((item.obj, {prop.name: prop.val for prop in item.propSet or []}))
                if len(records) > OBJECT_LIMIT:
                    raise CollectionError("A vSphere object type exceeds the 2,000 object limit.")
            token = page.token
            if not token:
                return records
            if token in seen:
                raise CollectionError("vSphere property pagination did not advance.")
            seen.add(token)
            page = collector.ContinueRetrievePropertiesEx(token)
        raise CollectionError("vSphere property collection exceeded the page limit.")
    finally:
        if token:
            with suppress(Exception):
                collector.CancelRetrievePropertiesEx(token)
        with suppress(Exception):
            view.Destroy()


def object_id(reference):
    if reference is None:
        return None
    method = getattr(reference, "_GetMoId", None)
    value = method() if callable(method) else None
    return value if isinstance(value, str) and MOID.fullmatch(value) else None


def discover(host, port=443, ca_file=None, *, extract=retrieve):
    scope_key(host, port)
    inventory = extract(host, port, ca_file)
    if not isinstance(inventory, dict):
        raise CollectionError("vSphere returned an incomplete inventory.")
    nodes, edges = {}, set()
    for kind, asset_kind in KINDS.items():
        records = inventory.get(kind)
        if not isinstance(records, list) or len(records) > OBJECT_LIMIT:
            raise CollectionError("vSphere returned an incomplete inventory.")
        for reference, properties in records:
            identifier = object_id(reference)
            if identifier is None or not isinstance(properties, dict):
                raise CollectionError("vSphere returned malformed object properties.")
            key = f"{kind}:{identifier}"
            if key in nodes:
                raise CollectionError("vSphere returned duplicate inventory objects.")
            name = properties.get("name")
            label = name if isinstance(name, str) and name.isprintable() and 1 <= len(name) <= 200 else identifier
            entry = {"kind": asset_kind, "name": label}
            facts = {}
            if kind == "HostSystem":
                lockdown = properties.get("config.lockdownMode")
                if lockdown in ("lockdownDisabled", "lockdownNormal", "lockdownStrict"):
                    facts["lockdown_enabled"] = lockdown != "lockdownDisabled"
            if kind == "VirtualMachine":
                logging = properties.get("config.flags.enableLogging")
                if type(logging) is bool:
                    facts["vm_logging_enabled"] = logging
                secure_boot = properties.get("config.bootOptions.efiSecureBootEnabled")
                if properties.get("config.firmware") == "efi" and type(secure_boot) is bool:
                    facts["efi_secure_boot_enabled"] = secure_boot
            entry["facts"] = facts
            nodes[key] = entry
    for reference, properties in inventory["VirtualMachine"]:
        vm = "VirtualMachine:" + object_id(reference)
        host_ref = object_id(properties.get("runtime.host"))
        if host_ref and f"HostSystem:{host_ref}" in nodes:
            edges.add((f"HostSystem:{host_ref}", vm, "hosts"))
        for property_name, kind, relation in (("datastore", "Datastore", "uses_datastore"),
                                               ("network", "Network", "attached_network")):
            references = properties.get(property_name) or []
            if not isinstance(references, (list, tuple)):
                raise CollectionError("vSphere returned malformed referenced inventory.")
            for target in references:
                ref = object_id(target)
                if ref and f"{kind}:{ref}" in nodes:
                    edges.add((vm, f"{kind}:{ref}", relation))
                if len(edges) > 12000:
                    raise CollectionError("vSphere topology exceeds 12,000 relationships.")
    return nodes, sorted(edges)
