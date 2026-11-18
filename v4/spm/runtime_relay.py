"""Fixed-destination JSON relay for an ingress enforcement boundary."""
import json
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from controls import Problem
from gcs import NoRedirect
from verification import parse_json

LIMIT = 8192


class Relay:
    def __init__(self, target, token=None, *, opener=None):
        if not isinstance(target, str) or not target.isascii() or any(char.isspace() for char in target):
            raise Problem(400, "Use a valid relay destination URL.")
        parts = urlsplit(target)
        if (not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
                or not parts.path.startswith("/") or parts.path == "/" or "%" in parts.path
                or parts.path.startswith("//") or any(part in (".", "..") for part in parts.path.split("/"))
                or not (parts.scheme == "https" or
                        parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost"))):
            raise Problem(400, "Use a fixed HTTPS destination path or a loopback HTTP destination.")
        if token is not None and (not 1 <= len(token) <= 8192 or not token.isascii()
                                  or any(char.isspace() for char in token)):
            raise Problem(400, "Invalid relay upstream credential.")
        self.target = target
        self.token = token
        self.opener = opener or build_opener(NoRedirect())

    def forward(self, payload):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            request = Request(self.target, data=encoded, headers=headers, method="POST")
            with self.opener.open(request, timeout=3) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise ValueError()
                body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError()
            result = parse_json(body)
            json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
            return result
        except (OSError, Problem, ValueError, RecursionError) as error:
            if hasattr(error, "close"):
                error.close()
            raise Problem(502, "Relay upstream did not return eligible JSON.") from None
