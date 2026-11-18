"""Normalize a bounded CycloneDX dependency inventory without resolving external references."""
import hashlib

from controls import Problem
from verification import parse_json

MAX_BOM_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 2000
MAX_DEPENDENCIES = 10000
SCHEMA = """
CREATE TABLE bills_of_materials (
  project TEXT NOT NULL, id TEXT NOT NULL, workload TEXT NOT NULL, digest TEXT NOT NULL,
  spec_version TEXT NOT NULL, document TEXT NOT NULL, total_components INTEGER NOT NULL,
  total_dependencies INTEGER NOT NULL, imported_by TEXT NOT NULL, imported_at TEXT NOT NULL,
  PRIMARY KEY(project,id), UNIQUE(project,workload,digest)
);
CREATE INDEX bills_of_materials_workload ON bills_of_materials(project,workload,imported_at);
"""
TYPES = {
    "application", "framework", "library", "container", "platform", "operating-system",
    "device", "device-driver", "firmware", "file", "machine-learning-model", "data",
    "cryptographic-asset",
}


def label(value, field, limit=250):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or not value.strip() or not value.isprintable():
        raise Problem(400, f"Invalid CycloneDX {field}.")
    return value


def items(owner, field):
    value = owner.get(field, [])
    if not isinstance(value, list):
        raise Problem(400, f"CycloneDX {field} must be a list.")
    return value


def normalize(raw):
    document = parse_json(raw)
    if isinstance(document, dict) and "sbom" in document:
        return normalize_spdx(document["sbom"])
    if isinstance(document, dict) and document.get("spdxVersion"):
        return normalize_spdx(document)
    if (not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") not in ("1.5", "1.6", "1.7")):
        raise Problem(400, "Supply CycloneDX 1.5, 1.6 or 1.7 JSON.")
    version = document["specVersion"]
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise Problem(400, "CycloneDX metadata must be an object.")
    root = metadata.get("component")
    components = {}
    edges = set()
    root_ref = None

    def edge(origin, target, relation):
        edges.add((origin, target, relation))
        if len(edges) > MAX_DEPENDENCIES:
            raise Problem(400, "CycloneDX inventory exceeds the relationship limit.")

    def visit(component, parent=None, depth=0, is_service=False):
        if not isinstance(component, dict) or depth > 16 or len(components) >= MAX_COMPONENTS:
            raise Problem(400, "Invalid or oversized CycloneDX component inventory.")
        type_value = "service" if is_service else component.get("type")
        if not isinstance(type_value, str) or (not is_service and type_value not in TYPES):
            raise Problem(400, "Unsupported CycloneDX component type.")
        ref = component.get("bom-ref")
        if ref is None:
            fingerprint = hashlib.sha256(f"{parent}:{len(components)}".encode()).hexdigest()[:24]
            ref = "spm-generated-" + fingerprint
        else:
            label(ref, "component reference")
        if ref in components:
            raise Problem(400, "CycloneDX contains a duplicate component reference.")
        row = {"ref": ref, "type": type_value, "name": label(component.get("name"), "component name")}
        for key in ("group", "version", "purl"):
            if key in component:
                row[key] = label(component[key], key, 500)
        components[ref] = row
        if parent is not None:
            edge(parent, ref, "contains")
        for child in items(component, "services" if is_service else "components"):
            visit(child, ref, depth + 1, is_service)
        return ref

    if root is not None:
        root_ref = visit(root)
    for component in items(document, "components"):
        visit(component)
    for service in items(document, "services"):
        visit(service, is_service=True)
    if not components:
        raise Problem(400, "CycloneDX document has no supported components or services.")
    dependencies = items(document, "dependencies")
    if len(dependencies) > MAX_COMPONENTS:
        raise Problem(400, "CycloneDX contains too many dependency entries.")
    dependency_sources = set()
    for entry in dependencies:
        if not isinstance(entry, dict):
            raise Problem(400, "Invalid CycloneDX dependency.")
        source = label(entry.get("ref"), "dependency reference")
        if source not in components or source in dependency_sources:
            raise Problem(400, "CycloneDX dependency references must be unique and local to this document.")
        dependency_sources.add(source)
        for key, relation in (("dependsOn", "depends_on"), ("provides", "provides")):
            targets = items(entry, key)
            if len(targets) > MAX_COMPONENTS:
                raise Problem(400, "CycloneDX dependency entry exceeds the component limit.")
            for raw_target in targets:
                target = label(raw_target, "dependency target")
                if target not in components or target == source:
                    raise Problem(400, "CycloneDX dependency target is unresolved or self-referencing.")
                edge(source, target, relation)
    return {"source_format": "CycloneDX", "spec_version": version, "root_ref": root_ref,
            "components": list(components.values()),
            "relationships": [{"source": origin, "target": target, "relation": relation}
                              for origin, target, relation in sorted(edges)]}


def normalize_spdx(document):
    if not isinstance(document, dict) or document.get("spdxVersion") not in ("SPDX-2.2", "SPDX-2.3"):
        raise Problem(400, "Supply a supported SPDX 2.2 or 2.3 package report.")
    packages = items(document, "packages")
    relations = items(document, "relationships")
    if not 1 <= len(packages) <= MAX_COMPONENTS or len(relations) > MAX_DEPENDENCIES:
        raise Problem(400, "SPDX package or relationship count outside supported limits.")
    components = {}
    edges = set()
    root_ref = None
    for package in packages:
        if not isinstance(package, dict):
            raise Problem(400, "Invalid SPDX package record.")
        ref = label(package.get("SPDXID"), "SPDX package identifier")
        if ref in components:
            raise Problem(400, "SPDX contains a duplicate package identifier.")
        row = {"ref": ref, "type": "library", "name": label(package.get("name"), "SPDX package name")}
        if "versionInfo" in package:
            row["version"] = label(package["versionInfo"], "SPDX package version")
        for identifier in items(package, "externalRefs"):
            if isinstance(identifier, dict) and identifier.get("referenceType") == "purl":
                row["purl"] = label(identifier.get("referenceLocator"), "SPDX package URL", 500)
                break
        components[ref] = row
    ignored = 0
    for edge in relations:
        if not isinstance(edge, dict):
            raise Problem(400, "Invalid SPDX relationship record.")
        source = label(edge.get("spdxElementId"), "SPDX relationship origin")
        target = label(edge.get("relatedSpdxElement"), "SPDX relationship target")
        relation = edge.get("relationshipType")
        if relation == "DESCRIBES" and target in components and source == document.get("SPDXID"):
            root_ref = root_ref or target
        elif source in components and target in components and source != target:
            if relation in ("DEPENDS_ON", "CONTAINS"):
                edges.add((source, target, relation.lower()))
            elif relation == "DEPENDENCY_OF":
                edges.add((target, source, "depends_on"))
            else:
                ignored += 1
        else:
            ignored += 1
    return {"source_format": "SPDX", "spec_version": document["spdxVersion"], "root_ref": root_ref,
            "ignored_relationships": ignored, "components": list(components.values()),
            "relationships": [{"source": origin, "target": target, "relation": relation}
                              for origin, target, relation in sorted(edges)]}
