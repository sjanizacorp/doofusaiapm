"""Read-only Google Cloud Storage bucket metadata connector."""
import json
import re
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20}")
BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
BUCKET_LIST_URL = "https://storage.googleapis.com/storage/v1/b"
FIELDS = (
    "nextPageToken,items(name,projectNumber,metageneration,"
    "encryption(defaultKmsKeyName),iamConfiguration(publicAccessPrevention,"
    "uniformBucketLevelAccess(enabled)))"
)
MAX_RESPONSE = 2 * 1024 * 1024


class CollectionError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a provider credential to a different URL.
        return None


def project_id(value):
    if PROJECT.fullmatch(value) is None:
        raise CollectionError("Use a Google Cloud project ID or project number.")
    return value


def access_token():
    try:
        result = subprocess.run(
            ["gcloud", "auth", "application-default", "print-access-token", "--quiet"],
            check=True, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise CollectionError("Could not obtain Google Application Default Credentials.") from None
    token = result.stdout.strip()
    if not token or any(char.isspace() for char in token):
        raise CollectionError("Google CLI returned an invalid credential.")
    return token


def fetch_page(params, token, quota_project):
    return fetch_google(BUCKET_LIST_URL, params, token, quota_project, "Cloud Storage inventory")


def fetch_google(url, params, token, quota_project, operation, *, payload=None):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"{url}?{urlencode(params)}" if params is not None else url, headers=headers,
                      data=json.dumps(payload).encode("utf-8") if payload is not None else None)
    try:
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except HTTPError as error:
        error.close()
        raise CollectionError(f"{operation} returned HTTP {error.code}.") from None
    except (URLError, OSError):
        raise CollectionError(f"{operation} request failed or timed out.") from None
    if len(raw) > MAX_RESPONSE:
        raise CollectionError(f"{operation} response exceeded the size limit.")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise CollectionError(f"{operation} returned invalid JSON.") from None


def observation(item):
    if not isinstance(item, dict):
        raise CollectionError("Cloud Storage returned malformed bucket metadata.")
    name = item.get("name")
    number = item.get("projectNumber")
    generation = item.get("metageneration")
    if (not isinstance(name, str) or BUCKET.fullmatch(name) is None
            or not isinstance(number, str) or not number.isascii() or not number.isdecimal()
            or not isinstance(generation, str) or not generation.isascii() or not generation.isdecimal()):
        raise CollectionError("Cloud Storage returned invalid bucket identity or metadata revision.")
    iam = item.get("iamConfiguration", {})
    encryption = item.get("encryption", {})
    if not isinstance(iam, dict) or not isinstance(encryption, dict):
        raise CollectionError("Cloud Storage returned invalid bucket configuration.")
    uniform = iam.get("uniformBucketLevelAccess", {})
    prevention = iam.get("publicAccessPrevention")
    if not isinstance(uniform, dict):
        raise CollectionError("Cloud Storage returned invalid bucket access settings.")
    facts = {}
    if prevention in ("enforced", "inherited"):
        facts["bucket_pap_enforced"] = prevention == "enforced"
    if type(uniform.get("enabled")) is bool:
        facts["uniform_access_enabled"] = uniform["enabled"]
    key_name = encryption.get("defaultKmsKeyName")
    if key_name is not None and (not isinstance(key_name, str) or not key_name):
        raise CollectionError("Cloud Storage returned an invalid encryption setting.")
    facts["default_cmek_configured"] = key_name is not None
    return {"name": name, "project_number": number, "revision": generation, "facts": facts}


def discover(cloud_project, quota_project=None, *, get_token=access_token, get_page=fetch_page):
    project_id(cloud_project)
    if quota_project is not None:
        project_id(quota_project)
    token = get_token()
    params = {"project": cloud_project, "projection": "noAcl",
              "maxResults": 500, "fields": FIELDS}
    page_tokens = set()
    buckets = {}
    project_number = None
    # Bound collection time and memory even when upstream pagination misbehaves.
    for _ in range(40):
        payload = get_page(params, token, quota_project)
        if not isinstance(payload, dict) or not isinstance(payload.get("items", []), list):
            raise CollectionError("Cloud Storage returned a malformed inventory page.")
        for item in payload.get("items", []):
            bucket = observation(item)
            if project_number and bucket["project_number"] != project_number:
                raise CollectionError("Cloud Storage returned buckets from different projects.")
            project_number = bucket["project_number"]
            if cloud_project.isdecimal() and cloud_project != project_number:
                raise CollectionError("Cloud Storage returned an unexpected project number.")
            if bucket["name"] in buckets:
                raise CollectionError("Cloud Storage returned a duplicate bucket; retry reconciliation.")
            buckets[bucket["name"]] = bucket
        if len(buckets) > 5000:
            raise CollectionError("Cloud Storage inventory exceeds the supported 5,000 buckets.")
        next_page = payload.get("nextPageToken")
        if next_page is None:
            return list(buckets.values())
        if not isinstance(next_page, str) or not next_page or len(next_page) > 4096 or next_page in page_tokens:
            raise CollectionError("Cloud Storage returned invalid pagination.")
        page_tokens.add(next_page)
        params["pageToken"] = next_page
    raise CollectionError("Cloud Storage inventory exceeded the page limit.")
