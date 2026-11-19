from datetime import datetime, timezone
from importlib.util import find_spec
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import parse_qs, urlsplit

from app import Product, database, issue, timestamp
from controls import Problem
from local_login import set_user
from sso_login import SSO


class BrowserLoginTest(unittest.TestCase):
    def test_password_sign_in_lockout_reset_and_session_revocation(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.sqlite"
            product = Product(path)
            with database(path, write=True) as conn:
                set_user(conn, "ModelOps", "alex.smith", "long demo passphrase", "admin")
            def login(password):
                return product.browser_login("/auth/local", "POST",
                                             {"username": "Alex.Smith", "password": password})[1]
            session = login("long demo passphrase")
            self.assertEqual(product.request("GET", "/api/v1/me", session["access_token"])[1]["principal"],
                             "alex.smith")
            for _ in range(5):
                with self.assertRaises(Problem):
                    login("wrong")
            with self.assertRaises(Problem):
                login("long demo passphrase")
            with database(path, write=True) as conn:
                set_user(conn, "ModelOps", "alex.smith", "new demo passphrase", "viewer")
                saved = conn.execute("SELECT password_hash FROM local_users").fetchone()[0]
                self.assertNotIn("passphrase", saved)
            with self.assertRaises(Problem):
                product.request("GET", "/api/v1/me", session["access_token"])
            replacement = login("new demo passphrase")
            self.assertEqual(product.request("GET", "/api/v1/me", replacement["access_token"])[1]["role"],
                             "viewer")

    def test_sso_session_requires_mapping_and_logout_revokes_session(self):
        from types import SimpleNamespace
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.sqlite"
            sso = SimpleNamespace(complete=lambda *_: ("https://identity.example.test", "stable-subject"))
            product = Product(path, sso=sso)
            body = {"state": "state", "code": "code"}
            with self.assertRaises(Problem):
                product.browser_login("/auth/sso/complete", "POST", body)
            with database(path, write=True) as conn:
                conn.execute("INSERT INTO federated_users VALUES(?,?,?,?,?)",
                             ("https://identity.example.test", "stable-subject", "ModelOps", "alex.smith", "viewer"))
            result = product.browser_login("/auth/sso/complete", "POST", body)[1]
            token = result["access_token"]
            self.assertEqual(product.request("GET", "/api/v1/me", token)[1]["principal"], "alex.smith")
            product.request("POST", "/api/v1/session/logout", token, {})
            with self.assertRaises(Problem):
                product.request("GET", "/api/v1/me", token)

    @unittest.skipUnless(find_spec("jwt"), "Requires optional SSO dependencies")
    def test_oidc_signed_token_nonce_and_single_use_state(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "test", "use": "sig"}
        issuer = "https://id.example.test/tenant/v2.0"
        metadata = {"issuer": issuer, "authorization_endpoint": "https://id.example.test/authorize",
                    "token_endpoint": "https://id.example.test/token", "jwks_uri": "https://id.example.test/keys"}
        values = {}
        def request(url, data=None):
            if url.endswith("openid-configuration"):
                return metadata
            if url.endswith("/keys"):
                return {"keys": [public]}
            self.assertTrue(data["code_verifier"])
            now = int(datetime.now(timezone.utc).timestamp())
            return {"id_token": jwt.encode({"iss": issuer, "aud": "client", "sub": "employee-subject",
                                           "iat": now, "exp": now + 300, "nonce": values["nonce"]},
                                          key, algorithm="RS256", headers={"kid": "test"})}
        sso = SSO({"issuer": issuer, "discovery_url": "https://id.example.test/.well-known/openid-configuration",
                   "client_id": "client", "redirect_uri": "https://spm.example.test/"}, request=request)
        started = sso.start()
        query = parse_qs(urlsplit(started["url"]).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        values["nonce"] = query["nonce"][0]
        self.assertEqual(sso.complete(started["state"], "code"), (issuer, "employee-subject"))
        with self.assertRaises(Problem):
            sso.complete(started["state"], "code")
        wrong_nonce = sso.start()
        values["nonce"] = "different-nonce"
        with self.assertRaises(Problem):
            sso.complete(wrong_nonce["state"], "code")
        second = sso.start()
        values["nonce"] = "wrong"
        with self.assertRaises(Problem):
            sso.complete(second["state"], "code")
