"""Read-only IBM watsonx.ai deployment space inventory."""
import os
import re
from urllib.parse import parse_qs, urlsplit

from gcs import CollectionError, fetch_google

REGION = {
    "us-south", "us-east", "eu-gb", "eu-de", "eu-es", "jp-tok", "au-syd", "ca-tor",
    "br-sao", "jp-osa", "ca-mon", "in-che",
}
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,8192}")


def scope_key(space, region):
    if UUID.fullmatch(space) is None or region not in REGION:
        raise CollectionError("Use a watsonx.ai deployment space UUID and supported IBM Cloud region.")
    return f"ibm:{region}:{space}"


def collection(origin, kind, space, token, fetch):
    path = f"/ml/v4/{kind}"
    results, seen = [], set()
    params = {"version": "2024-01-01", "space_id": space, "limit": 100}
    for _ in range(20):
        reply = fetch(origin + path, params.copy(), token, None, "IBM watsonx.ai inventory")
        records = reply.get("resources") if isinstance(reply, dict) else None
        if not isinstance(records, list) or len(results) + len(records) > 250:
            raise CollectionError("IBM returned invalid inventory or exceeded the 250 asset collection limit.")
        results.extend(records)
        link = reply.get("next")
        if link is None:
            return results
        href = link.get("href") if isinstance(link, dict) else None
        if not isinstance(href, str) or len(href) > 4096:
            raise CollectionError("IBM returned invalid pagination metadata.")
        try:
            url = urlsplit(href)
            query = parse_qs(url.query)
        except ValueError:
            raise CollectionError("IBM returned invalid pagination metadata.") from None
        starts = query.get("start", [])
        if (url.path != path or url.fragment or (url.scheme or url.netloc)
                and f"{url.scheme}://{url.netloc}" != origin or len(starts) != 1
                or not TOKEN.fullmatch(starts[0]) or starts[0] in seen):
            raise CollectionError("IBM pagination changed origin, resource, or repeated a cursor.")
        seen.add(starts[0])
        params["start"] = starts[0]
    raise CollectionError("IBM inventory exceeded the pagination limit.")


def discover(space, region, *, fetch=fetch_google, token=None):
    scope_key(space, region)
    token = token if token is not None else os.environ.get("DOOFUS_IBM_IAM_TOKEN", "")
    if not TOKEN.fullmatch(token):
        raise CollectionError("Supply a short-lived IBM IAM bearer in DOOFUS_IBM_IAM_TOKEN.")
    origin = f"https://{region}.ml.cloud.ibm.com"
    nodes, edges = {}, []
    for collection_name, kind in (("models", "model"), ("deployments", "endpoint")):
        for record in collection(origin, collection_name, space, token, fetch):
            metadata = record.get("metadata") if isinstance(record, dict) else None
            entity = record.get("entity") if isinstance(record, dict) else None
            if not isinstance(metadata, dict) or not isinstance(entity, dict):
                raise CollectionError("IBM returned malformed watsonx.ai asset metadata.")
            key, name = metadata.get("id"), metadata.get("name")
            if (not isinstance(key, str) or not UUID.fullmatch(key) or key in nodes
                    or metadata.get("space_id") != space or not isinstance(name, str)
                    or not name or len(name) > 255 or not name.isprintable()):
                raise CollectionError("IBM returned an invalid or out-of-scope watsonx.ai asset.")
            nodes[key] = node = {"kind": kind, "name": name}
            if kind == "endpoint":
                asset = entity.get("asset")
                model = asset.get("id") if isinstance(asset, dict) else None
                if isinstance(model, str) and model in nodes and nodes[model]["kind"] == "model":
                    edges.append((key, model, "serves"))
                status = entity.get("status")
                state = status.get("state") if isinstance(status, dict) else None
                node["facts"] = {"operational": state == "ready"} if state in ("ready", "failed") else {}
    return nodes, edges
