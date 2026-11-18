"""Offline dependency discovery from npm package-lock v2/v3."""
import hashlib
import json
import re

import ai_bom
from controls import Problem
from verification import parse_json

NAME = re.compile(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+")


def discover(raw):
    lock = parse_json(raw)
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3):
        raise Problem(400, "Supply a package-lock.json version 2 or 3.")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages or len(packages) > ai_bom.MAX_COMPONENTS:
        raise Problem(400, "Invalid or oversized npm package inventory.")
    components, refs, links = [], {}, {}
    for path, item in packages.items():
        segments = path.split("/") if path else []
        if (not isinstance(item, dict) or len(path) > 4096
                or any(not re.fullmatch(r"@?[a-zA-Z0-9_.-]+", part) or part in (".", "..") for part in segments)):
            raise Problem(400, "Invalid npm lockfile package path.")
        if item.get("link") is True:
            target = item.get("resolved")
            if not isinstance(target, str) or not target or target not in packages:
                raise Problem(400, "npm workspace link must resolve within the lockfile.")
            links[path] = target
            continue
        inferred = path.rsplit("node_modules/", 1)[-1] if "node_modules/" in path else path.rsplit("/", 1)[-1]
        name = item.get("name", inferred or lock.get("name"))
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise Problem(400, "Invalid npm package name.")
        ref = "npm-" + hashlib.sha256(path.encode()).hexdigest()
        refs[path] = ref
        component = {"type": "library" if path else "application", "name": name, "bom-ref": ref}
        version = item.get("version")
        if version is not None:
            component["version"] = ai_bom.label(version, "npm package version")
        components.append(component)
    if "" not in refs or any(target not in refs for target in links.values()):
        raise Problem(400, "Invalid npm workspace link chain.")

    def resolve(path, name):
        base = path
        while True:
            if base.rsplit("/", 1)[-1] != "node_modules":
                candidate = (base + "/" if base else "") + "node_modules/" + name
                actual = links.get(candidate, candidate)
                if actual in refs:
                    return refs[actual]
            if not base:
                return None
            base = base.rpartition("/")[0]

    dependencies = []
    relationship_count = 0
    for path, ref in refs.items():
        targets = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            entries = packages[path].get(key, {})
            if not isinstance(entries, dict) or any(not NAME.fullmatch(name) for name in entries):
                raise Problem(400, "Invalid npm lockfile dependency declaration.")
            for name in entries:
                target = resolve(path, name)
                if target and target != ref:
                    targets.add(target)
        relationship_count += len(targets)
        if relationship_count > ai_bom.MAX_DEPENDENCIES:
            raise Problem(400, "npm inventory exceeds the relationship limit.")
        dependencies.append({"ref": ref, "dependsOn": sorted(targets)})
    root, *rest = sorted(components, key=lambda item: item["type"] != "application")
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": root},
                       "components": rest, "dependencies": dependencies}).encode()
