"""Direct validation of RFC 9068 access tokens from a configured issuer."""
import base64
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from controls import Problem
from verification import parse_json, read_limited, verify_signature

SCHEMA = """
CREATE TABLE federated_users (
  issuer TEXT NOT NULL, subject TEXT NOT NULL, project TEXT NOT NULL, principal TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), PRIMARY KEY(issuer,subject)
);
"""
SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


def https_issuer(issuer):
    if not isinstance(issuer, str):
        raise Problem(400, "Supply an HTTPS issuer URL.")
    url = urlsplit(issuer)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise Problem(400, "Supply an HTTPS issuer URL.")
    return issuer


def subject(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 255 or not value.isprintable():
        raise Problem(400, "Invalid federated subject.")
    return value


def segment(value):
    if SEGMENT.fullmatch(value) is None:
        raise ValueError()
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(data).decode().rstrip("=") != value:
        raise ValueError()
    return data


class Issuer:
    def __init__(self, config):
        data = parse_json(read_limited(config, 8192))
        required = {"issuer", "audience", "clients", "keys"}
        if not isinstance(data, dict) or not required <= data.keys() <= required | {"device"}:
            raise Problem(400, "Federation config requires issuer, audience, clients and keys.")
        self.issuer = https_issuer(data["issuer"])
        self.device_config = data.get("device")
        self.audience = data["audience"]
        clients, keys = data["clients"], data["keys"]
        if (not isinstance(self.audience, str) or not self.audience
                or not isinstance(clients, list) or not clients or any(
                    not isinstance(client, str) or not client for client in clients)
                or not isinstance(keys, dict) or not keys or any(
                    not isinstance(path, str) or not path for path in keys.values())):
            raise Problem(400, "Invalid federation audience, clients or signing keys.")
        self.clients = set(clients)
        self.keys = {}
        for kid, file in keys.items():
            path = (config.parent / Path(file)).resolve()
            try:
                subprocess.run(["openssl", "rsa", "-pubin", "-in", str(path), "-noout"],
                               check=True, capture_output=True, timeout=5)
            except (OSError, subprocess.SubprocessError):
                raise Problem(400, "Federation verification keys must be RSA public keys.") from None
            self.keys[kid] = path

    def verify(self, token, *, now=None):
        try:
            encoded_header, encoded_claims, encoded_signature = token.split(".")
            header = parse_json(segment(encoded_header))
            claims = parse_json(segment(encoded_claims))
            signature = segment(encoded_signature)
            if not isinstance(header, dict) or not isinstance(claims, dict):
                raise ValueError()
            if (header.get("alg") != "RS256" or header.get("typ") not in ("at+jwt", "application/at+jwt")
                    or set(header) - {"alg", "typ", "kid"}):
                raise ValueError()
            key = self.keys[header["kid"]]
            verify_signature((encoded_header + "." + encoded_claims).encode("ascii"), signature, key)
            aud = claims["aud"]
            if isinstance(aud, str):
                aud = [aud]
            if (claims["iss"] != self.issuer or not isinstance(aud, list)
                    or any(not isinstance(value, str) for value in aud) or self.audience not in aud
                    or claims["client_id"] not in self.clients or not isinstance(claims["jti"], str)
                    or not claims["jti"]):
                raise ValueError()
            scopes = claims["scope"]
            if not isinstance(scopes, str) or "spm:access" not in scopes.split():
                raise ValueError()
            issued, expires = claims["iat"], claims["exp"]
            clock = datetime.now(timezone.utc).timestamp() if now is None else now
            not_before = claims.get("nbf", issued)
            if (any(type(value) is not int for value in (issued, expires, not_before))
                    or not issued <= clock + 30 or not_before > clock
                    or not clock < expires or not 0 < expires - issued <= 900):
                raise ValueError()
            return subject(claims["sub"])
        except (ValueError, KeyError, TypeError, Problem, OSError):
            raise Problem(401, "Supply a valid bearer token.") from None
