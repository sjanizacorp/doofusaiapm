"""Read-only Google AI inventory and profile metadata discovery."""
import re
from datetime import datetime, timedelta, timezone

from controls import Problem, parse_time, utc
from gcs import BUCKET, CollectionError, access_token, fetch_google, project_id

SCHEMA = """
CREATE TABLE cloud_graph_nodes (
  project TEXT NOT NULL, scope TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL,
  name TEXT NOT NULL, resource TEXT NOT NULL, exposure TEXT, sensitivity TEXT,
  profile_observed TEXT, observed_at TEXT NOT NULL,
  PRIMARY KEY(project,scope,id)
);
CREATE TABLE cloud_graph_edges (
  project TEXT NOT NULL, scope TEXT NOT NULL, origin TEXT NOT NULL, target TEXT NOT NULL,
  relation TEXT NOT NULL, PRIMARY KEY(project,scope,origin,target,relation),
  FOREIGN KEY(project,scope,origin) REFERENCES cloud_graph_nodes(project,scope,id),
  FOREIGN KEY(project,scope,target) REFERENCES cloud_graph_nodes(project,scope,id)
);
"""

LOCATION = re.compile(r"[a-z][a-z0-9-]{0,30}")
RESOURCE = re.compile(r"projects/([a-z0-9-]+)/locations/([a-z0-9-]+)/(models|endpoints|reasoningEngines)/([a-zA-Z0-9_-]+)(?:@[0-9]+)?")
ACCOUNT = re.compile(r"[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.gserviceaccount\.com")
LEVELS = {"SENSITIVITY_HIGH": "high", "SENSITIVITY_MODERATE": "moderate",
          "SENSITIVITY_LOW": "low", "SENSITIVITY_UNKNOWN": "unknown",
          "SENSITIVITY_SCORE_UNSPECIFIED": "unknown"}


def checked_location(value):
    if LOCATION.fullmatch(value) is None:
        raise CollectionError("Use a valid Google Cloud location.")
    return value


def paginated(url, key, token, quota, fetch):
    params = {"pageSize": 100}
    seen = set()
    results = []
    for _ in range(20):
        page = fetch(url, params.copy(), token, quota, f"Google AI inventory ({key})")
        if not isinstance(page, dict) or not isinstance(page.get(key, []), list):
            raise CollectionError(f"Google returned malformed {key} inventory.")
        entries = page.get(key, [])
        if any(not isinstance(item, dict) for item in entries):
            raise CollectionError(f"Google returned malformed {key} entries.")
        results.extend(entries)
        if len(results) > 2000:
            raise CollectionError(f"Google {key} inventory exceeds 2,000 records.")
        next_page = page.get("nextPageToken")
        if next_page is None:
            return results
        if (not isinstance(next_page, str) or not next_page or len(next_page) > 4096
                or next_page in seen):
            raise CollectionError(f"Invalid pagination in {key} inventory.")
        seen.add(next_page)
        params["pageToken"] = next_page
    raise CollectionError(f"Google {key} inventory exceeds 20 pages.")


def private_endpoint(item):
    psc = item.get("privateServiceConnectConfig", {})
    network, legacy = item.get("network", ""), item.get("enablePrivateServiceConnect", False)
    if not isinstance(network, str) or type(legacy) is not bool or not isinstance(psc, dict):
        return None
    enabled = psc.get("enablePrivateServiceConnect", False)
    if type(enabled) is not bool:
        return None
    return bool(network or legacy or enabled)


def discover(project, region, quota=None, profile_location=None, *, get_token=access_token, fetch=fetch_google):
    project_id(project)
    checked_location(region)
    if quota:
        project_id(quota)
    if profile_location:
        checked_location(profile_location)
    token = get_token()
    root = f"https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}"
    collections = {key: paginated(f"{root}/{key}", key, token, quota, fetch)
                   for key in ("models", "endpoints", "reasoningEngines")}
    nodes, edges, model_names, owner_refs = {}, set(), {}, set()

    def node(key, kind, name, **evidence):
        nodes.setdefault(key, {"key": key, "kind": kind, "name": name, **evidence})

    def attach_account(origin, value):
        if isinstance(value, str) and len(value) <= 254 and ACCOUNT.fullmatch(value):
            key = "account:" + value
            node(key, "identity", value)
            edges.add((origin, key, "uses_identity"))

    for kind, collection in (("model", "models"), ("endpoint", "endpoints"), ("agent", "reasoningEngines")):
        resource_ids = set()
        for item in collections[collection]:
            name = item.get("name", "")
            match = RESOURCE.fullmatch(name) if isinstance(name, str) and len(name) <= 400 else None
            if not match or match[2] != region or match[3] != collection or "@" in name:
                raise CollectionError(f"Google returned an unexpected {collection} resource name.")
            if name in resource_ids:
                raise CollectionError(f"Google returned a duplicate {collection} resource.")
            resource_ids.add(name)
            owner_refs.add(match[1])
            if (len(owner_refs - {project}) > 1
                    or (match[1] != project and (project.isdecimal() or not match[1].isdecimal()))):
                raise CollectionError("Google returned inventory with inconsistent project identifiers.")
            title = item.get("displayName")
            if not isinstance(title, str) or not title.strip() or not title.isprintable() or len(title) > 160:
                title = name
            if kind == "model":
                model_names[match[4]] = name
                node(name, kind, title)
                uri = item.get("artifactUri")
                if isinstance(uri, str) and uri.startswith("gs://"):
                    bucket = uri[5:].split("/", 1)[0]
                    if BUCKET.fullmatch(bucket):
                        key = "bucket:" + bucket
                        node(key, "data", bucket)
                        edges.add((name, key, "stores_artifacts"))
            elif kind == "endpoint":
                private = private_endpoint(item)
                node(name, kind, title, exposure="unknown" if private is None else
                     ("private_configuration" if private else "public_network_configuration"))
                deployments = item.get("deployedModels", [])
                if not isinstance(deployments, list) or any(not isinstance(d, dict) for d in deployments):
                    raise CollectionError("Google returned malformed endpoint deployments.")
                for deployment in deployments:
                    model = deployment.get("model", "")
                    target = RESOURCE.fullmatch(model) if isinstance(model, str) else None
                    if (target and target[1] in owner_refs | {project} and target[2] == region
                            and target[3] == "models" and target[4] in model_names):
                        edges.add((name, model_names[target[4]], "serves"))
                    attach_account(name, deployment.get("serviceAccount"))
            else:
                node(name, kind, title)
                spec = item.get("spec", {})
                if isinstance(spec, dict):
                    identity = spec.get("identity", {})
                    explicit = identity.get("serviceAccount") if isinstance(identity, dict) else None
                    attach_account(name, explicit or spec.get("serviceAccount"))

    if profile_location:
        uri = f"https://dlp.googleapis.com/v2/projects/{project}/locations/{profile_location}/fileStoreDataProfiles"
        for item in paginated(uri, "fileStoreDataProfiles", token, quota, fetch):
            resource = item.get("fullResource", "")
            prefix = "//storage.googleapis.com/buckets/"
            if not isinstance(resource, str) or not resource.startswith(prefix):
                continue
            bucket = resource[len(prefix):]
            if not BUCKET.fullmatch(bucket):
                continue
            score = item.get("sensitivityScore", {})
            status = item.get("profileStatus") or {}
            outcome = status.get("status", {}) if isinstance(status, dict) else None
            if not isinstance(outcome, dict) or outcome.get("code", 0):
                continue
            level = score.get("score") if isinstance(score, dict) else None
            if not isinstance(level, str) or level not in LEVELS:
                continue
            try:
                generated = parse_time(item.get("profileLastGenerated"))
            except Problem:
                continue
            if generated > datetime.now(timezone.utc) + timedelta(minutes=5):
                continue
            observed = utc(generated)
            key = "bucket:" + bucket
            node(key, "data", bucket)
            data = nodes[key]
            if observed > data.get("profile_observed", ""):
                data.update(sensitivity=LEVELS[level], profile_observed=observed)

    if len(nodes) > 4000 or len(edges) > 12000:
        raise CollectionError("Google AI topology exceeds the supported size.")
    return nodes, sorted(edges)
