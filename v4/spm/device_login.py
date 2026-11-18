"""Bounded, single-process browser sign-in via OAuth 2.0 device authorization."""
from collections import deque
from dataclasses import dataclass
import json
import re
import secrets
from threading import Lock
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener

from controls import Problem
from federation import https_issuer
from gcs import NoRedirect

CODE = re.compile(r"[A-Za-z0-9 -]{1,48}")
SESSION = re.compile(r"[A-Za-z0-9_-]{43}")
MAX_PENDING = 32


class ProviderUnavailable(Exception):
    pass


def provider_post(url, params):
    request = Request(url, data=urlencode(params).encode("ascii"), headers={
        "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        try:
            response = build_opener(NoRedirect()).open(request, timeout=8)
        except HTTPError as error:
            if error.code in (400, 401, 403):
                response = error
            else:
                error.close()
                raise ProviderUnavailable() from None
        with response:
            raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError()
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError()
        return document
    except (URLError, OSError, ValueError, RecursionError):
        raise ProviderUnavailable() from None


@dataclass
class Attempt:
    device_code: str
    expires: float
    interval: int
    next_poll: float
    polling: bool = False


class DeviceLogin:
    def __init__(self, issuer, *, post=provider_post, clock=monotonic):
        config = issuer.device_config
        keys = {"client_id", "device_endpoint", "token_endpoint", "verification_uri", "origin"}
        if not isinstance(config, dict) or config.keys() != keys:
            raise Problem(400, "Device sign-in configuration has missing or unexpected fields.")
        if not isinstance(config["client_id"], str) or config["client_id"] not in issuer.clients:
            raise Problem(400, "Device client must be in the federation client allowlist.")
        for key in ("device_endpoint", "token_endpoint", "verification_uri", "origin"):
            https_issuer(config[key])
        origin = urlsplit(config["origin"])
        if origin.path or origin.netloc != origin.netloc.lower() or config["origin"] != f"https://{origin.netloc}":
            raise Problem(400, "Device sign-in origin must be an exact HTTPS origin with no path.")
        self.config = config
        self.post = post
        self.clock = clock
        self.lock = Lock()
        self.attempts = {}
        self.starts = deque()
        self.starting = 0

    def start(self):
        with self.lock:
            now = self.clock()
            self.attempts = {key: item for key, item in self.attempts.items() if item.expires > now}
            while self.starts and self.starts[0] <= now - 60:
                self.starts.popleft()
            if len(self.starts) >= 12 or len(self.attempts) + self.starting >= MAX_PENDING:
                raise Problem(429, "Too many sign-in attempts. Try again shortly.")
            self.starts.append(now)
            self.starting += 1
        try:
            try:
                response = self.post(self.config["device_endpoint"],
                                     {"client_id": self.config["client_id"], "scope": "spm:access"})
            except ProviderUnavailable:
                raise Problem(503, "Identity provider is temporarily unavailable.") from None
            device_code, code = response.get("device_code"), response.get("user_code")
            expiry, interval = response.get("expires_in"), response.get("interval", 5)
            if (not isinstance(device_code, str) or not 1 <= len(device_code) <= 4096
                    or not isinstance(code, str) or CODE.fullmatch(code) is None
                    or response.get("verification_uri") != self.config["verification_uri"]
                    or type(expiry) is not int or not 1 <= expiry <= 3600
                    or type(interval) is not int or not 1 <= interval <= 90):
                raise Problem(502, "Identity provider returned an unsupported sign-in challenge.")
            duration = min(expiry, 600)
            session = secrets.token_urlsafe(32)
            with self.lock:
                self.attempts[session] = Attempt(device_code, self.clock() + duration,
                                                 interval, self.clock() + interval)
            return {"session": session, "user_code": code, "verification_uri": self.config["verification_uri"],
                    "expires_in": duration, "retry_in": interval}
        finally:
            with self.lock:
                self.starting -= 1

    def cancel(self, session):
        with self.lock:
            self.attempts.pop(session, None)
        return {"status": "cancelled"}

    def poll(self, session):
        with self.lock:
            now = self.clock()
            item = self.attempts.get(session)
            if item is None or item.expires <= now:
                self.attempts.pop(session, None)
                raise Problem(410, "Sign-in expired. Start a new attempt.")
            if item.polling or item.next_poll > now:
                return {"status": "pending", "retry_in": item.interval}
            item.polling = True
        try:
            response = self.post(self.config["token_endpoint"], {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": self.config["client_id"], "device_code": item.device_code,
            })
        except ProviderUnavailable:
            response = {"error": "transient"}
        except Exception:
            with self.lock:
                item.polling = False
                item.next_poll = self.clock() + item.interval
            raise
        with self.lock:
            item.polling = False
            if self.attempts.get(session) is not item or item.expires <= self.clock():
                self.attempts.pop(session, None)
                raise Problem(410, "Sign-in expired or was cancelled.")
            error = response.get("error")
            if error in ("authorization_pending", "slow_down", "transient"):
                if error == "slow_down":
                    item.interval += 5
                if error == "transient":
                    item.interval *= 2
                item.next_poll = self.clock() + item.interval
                return {"status": "pending", "retry_in": min(item.interval, 600)}
            del self.attempts[session]
        token = response.get("access_token")
        token_type = response.get("token_type")
        if error == "expired_token":
            raise Problem(410, "Sign-in expired. Start a new attempt.")
        if error == "access_denied":
            raise Problem(403, "Sign-in was denied.")
        if error is not None or not isinstance(token, str) or not 1 <= len(token) <= 8185 or (
            not isinstance(token_type, str) or token_type.lower() != "bearer"
        ):
            raise Problem(502, "Identity provider did not return a usable access token.")
        return {"status": "approved", "access_token": token}
