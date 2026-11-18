import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
from struct import pack
import subprocess
import sys
import tempfile
import unittest

from app import Product, Problem, SCHEMA_VERSION, issue
from federation import Issuer
from device_login import DeviceLogin, ProviderUnavailable


class EnterpriseTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.db = self.directory / "primary.sqlite"
        self.product = Product(self.db)
        self.admin = issue(self.db, "model-sec", "owner", "admin")
        self.viewer = issue(self.db, "model-sec", "reader", "viewer")
        self.other = issue(self.db, "other", "observer", "admin")
        self.post("assets", {"id": "training-store", "kind": "storage",
                             "facts": {"encrypted": False, "public": False}})
        self.report = self.post("scans", {"asset": "training-store"})[1]

    def get(self, route, token=None):
        return self.product.request("GET", "/api/v1/" + route, token or self.admin)[1]

    def post(self, route, body, token=None):
        return self.product.request("POST", "/api/v1/" + route, token or self.admin, body)

    def cli(self, *arguments, check=True):
        return subprocess.run(
            [sys.executable, str(Path(__file__).parents[1] / "app.py"), "--db", str(self.db),
             *map(str, arguments)], check=check, capture_output=True, text=True,
        )

    def graph(self):
        for name, kind, asset, level, exposed in [
            ("public-service", "endpoint", None, "medium", True),
            ("pipeline-model", "model", None, "high", False),
            ("pipeline-role", "identity", None, "medium", False),
            ("training-data", "data", "training-store", "critical", False),
        ]:
            self.post("graph/nodes", {"id": name, "kind": kind, "asset": asset,
                                      "criticality": level, "public": exposed})
        for origin, target, relation in [
            ("public-service", "pipeline-model", "serves"),
            ("public-service", "pipeline-role", "uses_identity"),
            ("pipeline-model", "training-data", "reads_data"),
        ]:
            self.post("graph/edges", {"origin": origin, "target": target, "relation": relation})

    def test_graph_prioritization_and_exceptions(self):
        original, = self.get("issues")["issues"]
        self.assertEqual(original["risk"]["score"], 30)
        self.graph()
        item, = self.get("issues")["issues"]
        self.assertEqual(item["risk"]["score"], 90)
        self.assertEqual(item["risk"]["exposure_weight"], 20)
        self.assertEqual(self.get("graph/nodes", self.other), {"nodes": []})
        with self.assertRaises(Problem) as problem:
            self.post("graph/edges", {"origin": "training-data", "target": "pipeline-model", "relation": "serves"})
        self.assertEqual(problem.exception.status, 400)
        self.product.request("DELETE", "/api/v1/graph/edges", self.admin,
                             {"origin": "pipeline-model", "target": "training-data", "relation": "reads_data"})
        item, = self.get("issues")["issues"]
        self.assertEqual(item["risk"]["score"], 70)
        route = "issues/" + item["id"] + "/exceptions"
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with self.assertRaises(Problem) as problem:
            self.post(route, {"reason": "Approved maintenance window", "expires_at": future}, self.viewer)
        self.assertEqual(problem.exception.status, 403)
        status, record = self.post(route, {"reason": "Approved maintenance window", "expires_at": future})
        self.assertEqual(status, 201)
        self.assertEqual(self.get("issues")["issues"][0]["active_exception"]["id"], record["id"])
        self.assertEqual(self.get("issues")["issues"][0]["status"], "open")
        self.product.request("DELETE", "/api/v1/" + route, self.admin, {"id": record["id"]})
        self.assertIsNone(self.get("issues")["issues"][0]["active_exception"])
        self.assertIsNotNone(self.get(route)["exceptions"][0]["revoked_at"])

    def test_runtime_deduplication_and_scoped_security_feed(self):
        self.graph()
        event = {"source": "ApprovedGateway", "event_id": "event-1", "node": "public-service",
                 "category": "guardrail_block", "severity": "high", "observed_at": "2025-01-01T12:00:00Z"}
        status, created = self.post("runtime-findings", event)
        self.assertEqual(status, 201)
        self.assertEqual(self.post("runtime-findings", event), (200, created))
        with self.assertRaises(Problem) as problem:
            self.post("runtime-findings", event | {"severity": "low"})
        self.assertEqual(problem.exception.status, 409)
        with self.assertRaises(Problem) as problem:
            self.post("runtime-findings", event | {"raw_prompt": "forbidden"})
        self.assertEqual(problem.exception.status, 400)
        events = self.get("security-events")
        runtime, = [item for item in events["events"] if item["action"] == "runtime.received"]
        self.assertEqual(runtime["details"], event)
        self.assertEqual(self.get("security-events?after=" + str(events["next_after"]))["events"], [])
        self.assertFalse(any(r["action"] == "runtime.received" for r in self.get("security-events", self.other)["events"]))
        with self.assertRaises(Problem) as problem:
            self.get("security-events", self.viewer)
        self.assertEqual(problem.exception.status, 403)
        self.assertEqual(self.get("operations")["counts"]["runtime_findings"], 1)

    def test_cold_restore_read_and_write(self):
        backup = self.directory / "backup.sqlite"
        recovery = self.directory / "recovery.sqlite"
        self.cli("backup", backup)
        validation = json.loads(self.cli("verify-backup", backup).stdout)
        self.assertEqual(validation["schema_version"], SCHEMA_VERSION)
        self.assertEqual(validation["counts"]["scans"], 1)
        shutil.copyfile(backup, recovery)
        original_stream = self.get("security-events")["stream_id"]
        cli = Path(__file__).parents[1] / "app.py"
        promote = subprocess.run(
            [sys.executable, str(cli), "--db", str(recovery), "promote-recovery"],
            check=True, capture_output=True, text=True,
        )
        self.assertNotEqual(json.loads(promote.stdout)["stream_id"], original_stream)
        self.db.rename(self.directory / "offline.sqlite")
        recovered = Product(recovery)
        self.assertEqual(
            recovered.request("GET", "/api/v1/security-events", self.admin)[1]["stream_id"],
            json.loads(promote.stdout)["stream_id"],
        )
        self.assertEqual(recovered.request("GET", "/api/v1/scans/" + self.report["id"], self.viewer)[0], 200)
        recovered.request("POST", "/api/v1/assets", self.admin,
                          {"id": "training-store", "kind": "storage", "facts": {"encrypted": True}})
        status, result = recovered.request("POST", "/api/v1/scans", self.admin, {"asset": "training-store"})
        self.assertEqual(status, 201)
        self.assertNotEqual(result["id"], self.report["id"])
        self.assertFalse(self.db.exists())

    def keys(self, name="test"):
        private = self.directory / (name + "-private.pem")
        public = self.directory / (name + "-public.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", private], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", private, "-pubout", "-out", public],
                       check=True, capture_output=True)
        return private, public

    def sign(self, private, payload):
        return subprocess.run(["openssl", "dgst", "-sha256", "-sign", private], input=payload,
                              capture_output=True, check=True).stdout

    @unittest.skipUnless(shutil.which("openssl"), "Requires OpenSSL")
    def test_ci_artifact_gate_and_protected_export(self):
        private, public = self.keys()
        artifact = self.directory / "model.bin"
        manifest = self.directory / "model.json"
        signature = self.directory / "model.sig"
        original = b"non-executable fixture"
        artifact.write_bytes(original)
        payload = {"schema": 1, "artifact_id": "training-model-1", "size": len(original),
                   "sha256": hashlib.sha256(original).hexdigest()}
        manifest.write_text(json.dumps(payload))
        signature.write_bytes(self.sign(private, manifest.read_bytes()))
        arguments = ("verify-artifact", artifact, manifest, signature, public, "--artifact-id", "training-model-1")
        self.assertEqual(json.loads(self.cli(*arguments).stdout), payload)
        self.assertEqual(self.cli(*arguments[:-1], "other-model", check=False).returncode, 1)
        artifact.write_bytes(b"changed")
        self.assertEqual(self.cli(*arguments, check=False).returncode, 1)
        export = self.directory / "audit.signed"
        self.cli("export-audit", "model-sec", export, private)
        verified = json.loads(self.cli("verify-audit", export, public).stdout)
        self.assertEqual(verified["project"], "model-sec")
        self.assertTrue(all(event["project"] == "model-sec" for event in verified["events"]))
        envelope = json.loads(export.read_text())
        envelope["payload"] = base64.b64encode(b"tampered").decode()
        export.write_text(json.dumps(envelope))
        self.assertEqual(self.cli("verify-audit", export, public, check=False).returncode, 1)

    @unittest.skipUnless(shutil.which("openssl"), "Requires OpenSSL")
    def test_federated_access_token_validation_and_revoke(self):
        private, public = self.keys()
        path = self.directory / "issuer.json"
        issuer = "https://issuer.example.test"
        origin = "https://spm.example.test"
        verify_url = issuer + "/verify"
        path.write_text(json.dumps({"issuer": issuer, "audience": "spm-api",
                                    "clients": ["portal"], "keys": {"key-one": public.name},
                                    "device": {"origin": origin, "client_id": "portal",
                                               "device_endpoint": issuer + "/device",
                                               "token_endpoint": issuer + "/token",
                                               "verification_uri": verify_url}}))
        self.cli("map-identity", issuer, "opaque-IdP-subject", "model-sec", "Jules", "viewer")
        service = Product(self.db, Issuer(path))
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {"iss": issuer, "sub": "opaque-IdP-subject", "aud": "spm-api", "client_id": "portal",
                  "scope": "spm:access", "jti": "event-a", "iat": now, "exp": now + 300}

        def token(statement, typ="at+jwt"):
            def encode(data):
                return base64.urlsafe_b64encode(data).rstrip(b"=")
            header = {"typ": typ, "alg": "RS256", "kid": "key-one"}
            wire = b".".join(encode(json.dumps(item).encode()) for item in (header, statement))
            return (wire + b"." + encode(self.sign(private, wire))).decode()

        valid = token(claims)
        self.assertEqual(service.request("GET", "/api/v1/me", valid)[1]["principal"], "Jules")
        now_device = [100]
        replies = iter([{"error": "authorization_pending"}, {"error": "slow_down"}, ProviderUnavailable(),
                        {"access_token": valid, "token_type": "Bearer"}])
        provider_calls = []

        def provider(url, fields):
            provider_calls.append((url, fields))
            if url.endswith("/device"):
                return {"device_code": "provider-secret", "user_code": "ABC-123", "expires_in": 90,
                        "interval": 5, "verification_uri": verify_url}
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        service.device = DeviceLogin(service.issuer, post=provider, clock=lambda: now_device[0])
        self.assertEqual(service.device_request("/auth/device", "GET", None)[1], {"enabled": True})
        with self.assertRaises(Problem) as problem:
            service.device_request("/auth/device/start", "POST", "https://wrong.example.test", {})
        self.assertEqual(problem.exception.status, 403)
        self.assertEqual(provider_calls, [])
        challenge = service.device_request("/auth/device/start", "POST", origin, {})[1]
        self.assertNotIn("provider-secret", json.dumps(challenge))
        payload = {"session": challenge["session"]}
        self.assertEqual(service.device_request("/auth/device/poll", "POST", origin, payload)[1]["status"], "pending")
        self.assertEqual(len(provider_calls), 1)
        now_device[0] += 5
        self.assertEqual(service.device_request("/auth/device/poll", "POST", origin, payload)[1]["retry_in"], 5)
        now_device[0] += 5
        self.assertEqual(service.device_request("/auth/device/poll", "POST", origin, payload)[1]["retry_in"], 10)
        now_device[0] += 10
        self.assertEqual(service.device_request("/auth/device/poll", "POST", origin, payload)[1]["retry_in"], 20)
        now_device[0] += 20
        self.assertEqual(service.device_request("/auth/device/poll", "POST", origin, payload)[1]["access_token"], valid)
        with self.assertRaises(Problem) as problem:
            service.device_request("/auth/device/poll", "POST", origin, payload)
        self.assertEqual(problem.exception.status, 410)
        cancelled = service.device_request("/auth/device/start", "POST", origin, {})[1]
        service.device_request("/auth/device/cancel", "POST", origin, {"session": cancelled["session"]})
        with self.assertRaises(Problem) as problem:
            service.device_request("/auth/device/poll", "POST", origin, {"session": cancelled["session"]})
        self.assertEqual(problem.exception.status, 410)
        for rejected in (token(claims | {"aud": "other"}), token(claims | {"exp": now - 1}),
                         token(claims | {"exp": now + 901}), token(claims, typ="JWT")):
            with self.assertRaises(Problem) as problem:
                service.request("GET", "/api/v1/me", rejected)
            self.assertEqual(problem.exception.status, 401)
        self.cli("unmap-identity", issuer, "opaque-IdP-subject")
        with self.assertRaises(Problem):
            service.request("GET", "/api/v1/me", valid)

    @unittest.skipUnless(shutil.which("openssl"), "Requires OpenSSL")
    def test_gguf_gate_checks_signed_tensor_layout_and_metadata(self):
        private, public = self.keys()
        artifact = self.directory / "model.gguf"
        manifest = self.directory / "manifest.json"
        signature = self.directory / "manifest.sig"
        arguments = ("verify-artifact", artifact, manifest, signature, public,
                     "--artifact-id", "gguf-fixture", "--format-policy", "gguf")

        def string(value):
            return pack("<Q", len(value)) + value

        def fixture(second_offset=32, second_axis=32, metadata=None):
            entries = metadata if metadata is not None else [
                string(b"general.alignment") + pack("<II", 4, 32),
                string(b"tokenizer.ggml.tokens") + pack("<IIQ", 9, 8, 2) + string(b"a") + string(b"b"),
            ]
            header = b"GGUF" + pack("<IQQ", 3, 2, len(entries)) + b"".join(entries)
            header += string(b"float.weight") + pack("<IQIQ", 1, 4, 0, 0)
            header += string(b"quant.weight") + pack("<IQIQ", 1, second_axis, 2, second_offset)
            return header + bytes((-len(header)) % 32) + bytes(32 + 18)

        def check(raw, *extra):
            artifact.write_bytes(raw)
            manifest.write_text(json.dumps({"schema": 1, "artifact_id": "gguf-fixture",
                                            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}))
            signature.write_bytes(self.sign(private, manifest.read_bytes()))
            return self.cli(*arguments, *extra, check=False)

        result = check(fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["structure"]["tensors"], 2)
        self.assertEqual(check(fixture(), "--numeric-policy", "finite").returncode, 1)
        duplicate = string(b"general.alignment") + pack("<II", 4, 32)
        invalid = (fixture(second_offset=0), fixture(second_axis=31), fixture()[:-1],
                   fixture() + b"trailing", fixture(metadata=[duplicate, duplicate]))
        for raw in invalid:
            with self.subTest(size=len(raw)):
                self.assertEqual(check(raw).returncode, 1)

    @unittest.skipUnless(shutil.which("openssl"), "Requires OpenSSL")
    def test_safetensors_gate_rejects_signed_malformed_artifacts(self):
        private, public = self.keys()
        artifact = self.directory / "test.safetensors"
        manifest = self.directory / "manifest.json"
        signature = self.directory / "manifest.sig"
        arguments = ("verify-artifact", artifact, manifest, signature, public,
                     "--artifact-id", "safe-model", "--format-policy", "safetensors")

        def check(header, tensors, expect_success):
            raw = len(header).to_bytes(8, "little") + header + tensors
            artifact.write_bytes(raw)
            manifest.write_text(json.dumps({"schema": 1, "artifact_id": "safe-model",
                                            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}))
            signature.write_bytes(self.sign(private, manifest.read_bytes()))
            result = self.cli(*arguments, check=expect_success)
            if expect_success:
                self.assertEqual(json.loads(result.stdout)["structure"],
                                 {"format": "safetensors", "tensors": 1, "data_bytes": 8})
            else:
                self.assertEqual(result.returncode, 1)

        header = b'{"weights":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}'
        check(header, bytes(8), True)
        check(header, bytes(9), False)
        check(header.replace(b'"shape":[2]', b'"shape":[3]'), bytes(8), False)
        check(header.replace(b'"dtype":"F32"', b'"dtype":"F32","dtype":"F16"'), bytes(8), False)
        check(header.replace(b'"dtype":"F32"', b'"dtype":"unknown"'), bytes(8), False)

    @unittest.skipUnless(shutil.which("openssl"), "Requires OpenSSL")
    def test_external_scanner_verdict_is_bound_to_digest_and_freshness(self):
        signing_private, signing_public = self.keys("release")
        scanner_private, scanner_public = self.keys("scanner")
        artifact = self.directory / "model.bin"
        manifest = self.directory / "manifest.json"
        signature = self.directory / "manifest.sig"
        report = self.directory / "verdict.json"
        report_signature = self.directory / "verdict.sig"
        data = b"inert test model"
        checksum = hashlib.sha256(data).hexdigest()
        artifact.write_bytes(data)
        manifest.write_text(json.dumps({"schema": 1, "artifact_id": "fixture",
                                        "sha256": checksum, "size": len(data)}))
        signature.write_bytes(self.sign(signing_private, manifest.read_bytes()))
        base = ("verify-artifact", artifact, manifest, signature, signing_public, "--artifact-id", "fixture")
        full = (*base, "--threat-report", report, "--threat-signature", report_signature,
                "--threat-public-key", scanner_public, "--trusted-scanner", "approval-service")
        verdict = {"schema": "doofusai.threat-verdict.v1", "artifact_id": "fixture", "sha256": checksum,
                   "scanner": "approval-service", "scanned_at": datetime.now(timezone.utc).isoformat(),
                   "verdict": "allow"}
        for updates, expected in [
            ({}, 0), ({"verdict": "deny"}, 1), ({"sha256": "a" * 64}, 1),
            ({"scanned_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()}, 1),
        ]:
            report.write_text(json.dumps(verdict | updates))
            report_signature.write_bytes(self.sign(scanner_private, report.read_bytes()))
            self.assertEqual(self.cli(*full, check=False).returncode, expected)
        self.assertEqual(self.cli(*base, "--threat-report", report, check=False).returncode, 1)
