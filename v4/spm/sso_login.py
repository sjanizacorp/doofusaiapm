"""OIDC authorization-code sign-in for Entra ID and AD FS with PKCE and nonce."""
import base64
import hashlib
import json
import os
import secrets
from threading import Lock
from time import monotonic
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener

from controls import Problem
from gcs import NoRedirect


def https(value):
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise Problem(400, "SSO endpoints must use HTTPS.")
    return value


def fetch(url, form=None):
    request = Request(url, data=urlencode(form).encode() if form else None,
                      headers={"Accept": "application/json",
                               **({"Content-Type": "application/x-www-form-urlencoded"} if form else {})})
    try:
        with build_opener(NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError()
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (OSError, ValueError) as error:
        if hasattr(error, "close"):
            error.close()
        raise Problem(503, "Organization sign-in is temporarily unavailable.") from None


class SSO:
    def __init__(self, settings, request=fetch):
        import jwt
        self.jwt = jwt
        if not isinstance(settings, dict) or set(settings) != {"issuer", "discovery_url", "client_id", "redirect_uri"}:
            raise Problem(400, "SSO requires issuer, discovery_url, client_id and redirect_uri.")
        self.config = settings
        for key in ("issuer", "discovery_url", "redirect_uri"):
            https(settings[key])
        if not isinstance(settings["client_id"], str) or not settings["client_id"]:
            raise Problem(400, "SSO requires a client ID.")
        redirect = urlsplit(settings["redirect_uri"])
        if redirect.path != "/" or redirect.query:
            raise Problem(400, "Register the HTTPS application root as the SSO redirect URI.")
        self.request = request
        self.pending = {}
        self.lock = Lock()
        self.metadata = None
        self.metadata_until = 0

    def discovery(self):
        if self.metadata and monotonic() < self.metadata_until:
            return self.metadata
        metadata = self.request(self.config["discovery_url"])
        if metadata.get("issuer") != self.config["issuer"]:
            raise Problem(503, "Organization sign-in issuer does not match configuration.")
        try:
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                https(metadata[key])
        except (KeyError, Problem):
            raise Problem(503, "Organization sign-in metadata is incomplete.") from None
        self.metadata, self.metadata_until = metadata, monotonic() + 300
        return metadata

    def start(self):
        metadata = self.discovery()
        with self.lock:
            now = monotonic()
            self.pending = {k:v for k,v in self.pending.items() if v[0] > now}
            if len(self.pending) >= 32:
                raise Problem(429, "Too many organization sign-in attempts. Try again shortly.")
            state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            self.pending[state] = (now + 300, nonce, verifier)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return {"url": metadata["authorization_endpoint"] + "?" + urlencode({
            "client_id": self.config["client_id"], "redirect_uri": self.config["redirect_uri"],
            "response_type": "code", "response_mode": "query", "scope": "openid profile",
            "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
        }), "state": state}

    def complete(self, state, code):
        if not isinstance(state, str) or not isinstance(code, str) or len(code) > 8192:
            raise Problem(401, "Organization sign-in attempt is invalid.")
        with self.lock:
            attempt = self.pending.pop(state, None)
        if attempt is None or attempt[0] < monotonic():
            raise Problem(401, "Organization sign-in attempt has expired.")
        _, nonce, verifier = attempt
        metadata = self.discovery()
        form = {"grant_type": "authorization_code", "client_id": self.config["client_id"],
                "redirect_uri": self.config["redirect_uri"], "code": code, "code_verifier": verifier}
        secret = os.environ.get("DOOFUS_SSO_CLIENT_SECRET")
        if secret:
            form["client_secret"] = secret
        token = self.request(metadata["token_endpoint"], form).get("id_token")
        try:
            if not isinstance(token, str) or len(token) > 32768:
                raise ValueError()
            header = self.jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise ValueError()
            keys = self.request(metadata["jwks_uri"]).get("keys")
            if not isinstance(keys, list) or len(keys) > 100:
                raise ValueError()
            matching = [k for k in keys if k.get("kid") == header["kid"] and k.get("kty") == "RSA"
                        and k.get("use", "sig") == "sig"]
            if len(matching) != 1:
                raise ValueError()
            key = self.jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(matching[0]))
            claims = self.jwt.decode(token, key, algorithms=["RS256"], audience=self.config["client_id"],
                                     issuer=self.config["issuer"], leeway=30,
                                     options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]})
            if claims["nonce"] != nonce or not isinstance(claims["sub"], str) or len(claims["sub"]) > 255:
                raise ValueError()
            return self.config["issuer"], claims["sub"]
        except (self.jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError):
            raise Problem(401, "Organization sign-in could not be verified.") from None
