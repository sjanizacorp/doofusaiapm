"""Fetch the GitHub dependency graph SBOM through its asynchronous read API."""
import json
import re
from time import sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from ai_bom import MAX_BOM_BYTES
from controls import Problem
from gcs import NoRedirect

REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")
REPORT = re.compile(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")
BASE = "https://api.github.com"


def read_report(url, token):
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                    "Authorization": f"Bearer {token}",
                                    "X-GitHub-Api-Version": "2026-03-10",
                                    "User-Agent": "DoofusAI-SPM"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=12) as response:
            status, raw = response.status, response.read(MAX_BOM_BYTES + 1)
    except HTTPError as error:
        if error.code == 302:
            location = error.headers.get("Location", "")
            error.close()
            return 302, location
        error.close()
        raise Problem(502, f"GitHub dependency graph returned HTTP {error.code}.") from None
    except (OSError, URLError):
        raise Problem(503, "GitHub dependency graph is temporarily unavailable.") from None
    if len(raw) > MAX_BOM_BYTES:
        raise Problem(400, "GitHub dependency report exceeds the 2 MiB import limit.")
    return status, raw


def download_report(location, host):
    try:
        url = urlsplit(location)
        valid = (url.scheme == "https" and url.hostname == host and url.port in (None, 443)
                 and not url.username and not url.password and not url.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise Problem(502, "GitHub SBOM download host does not match the configured host.")
    try:
        # Do not send the GitHub bearer token to the temporary download host.
        with build_opener(NoRedirect()).open(Request(location), timeout=12) as response:
            raw = response.read(MAX_BOM_BYTES + 1)
    except (OSError, URLError):
        raise Problem(502, "Could not download the generated GitHub SBOM.") from None
    if len(raw) > MAX_BOM_BYTES:
        raise Problem(400, "GitHub dependency report exceeds the 2 MiB import limit.")
    return raw


def discover(repo, token, download_host, *, fetch=read_report, download=download_report, wait=sleep):
    if REPO.fullmatch(repo) is None or repo.split("/")[1] in (".", ".."):
        raise Problem(400, "Use a GitHub repository in owner/name format.")
    if not isinstance(token, str) or not token or len(token) > 512 or not token.isascii() or any(
        char.isspace() for char in token
    ):
        raise Problem(400, "Provide a GitHub read credential.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}\.[a-z]{2,}", download_host):
        raise Problem(400, "Configure the trusted GitHub report download hostname.")
    path = f"/repos/{repo}/dependency-graph/sbom"
    status, raw = fetch(BASE + path + "/generate-report", token)
    try:
        payload = json.loads(raw)
        location = payload["sbom_url"]
        report_id = location.rsplit("/", 1)[-1]
        valid = (status == 201 and REPORT.fullmatch(report_id) is not None and
                 location.lower() == (BASE + path + "/fetch-report/" + report_id).lower())
    except (TypeError, KeyError, AttributeError, ValueError, RecursionError):
        valid = False
    if not valid:
        raise Problem(502, "GitHub returned an unexpected SBOM report location.")
    for number in range(8):
        if number:
            wait(2)
        status, report = fetch(BASE + path + "/fetch-report/" + report_id, token)
        if status == 200:
            return report
        if status == 302:
            return download(report, download_host)
        if status != 202:
            raise Problem(502, f"Unexpected GitHub SBOM report status {status}.")
    raise Problem(503, "GitHub did not finish generating the dependency report in time.")
