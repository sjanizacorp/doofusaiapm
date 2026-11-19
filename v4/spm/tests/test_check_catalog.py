"""Rule lifecycle, isolation, immutable evidence and signed feed regression tests."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from app import CHECKS, Product, audit, database, issue
from controls import Problem
import check_catalog as rules
import verification


def example(version=1):
    return {"schema": "doofusai.rules.v1", "id": "organization", "version": version, "rules": [{
        "id": "retention", "title": "Storage retention", "description": "Require an approved retention period.",
        "kind": "storage", "field": "retention_days", "operator": "ge", "expected": 90,
        "severity": "high", "remediation": "Configure at least 90 days retention.", "source_url": "",
        "tests": [{"facts": {"retention_days": 90}, "status": "pass"},
                  {"facts": {"retention_days": 30}, "status": "finding"}, {"facts": {}, "status": "unknown"}]}]}


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite"
        self.product = Product(self.path)
        self.admin = issue(self.path, "alpha", "owner", "admin")
        self.viewer = issue(self.path, "alpha", "reader", "viewer")
        self.operator = issue(self.path, "alpha", "runner", "operator")
        self.other = issue(self.path, "beta", "owner", "admin")

    def call(self, method, route, body=None, token=None):
        return self.product.request(method, "/api/v1/" + route, token or self.admin, body)[1]

    def stage(self, pack=None):
        return self.call("POST", "rule-packs/stage", pack or example())

    def activate(self, version=1):
        return self.call("POST", "rule-packs/activate", {"id": "organization", "version": version})

    def save(self, extra=None):
        self.call("POST", "assets", {"id": "store", "kind": "storage", "facts": dict(encrypted=True, public=False, **(extra or {}))})

    def scan(self):
        return self.call("POST", "scans", {"asset": "store"})

    def test_catalogue_plan_permissions_and_historical_execution(self):
        self.assertEqual(len(self.call("GET", "checks", token=self.viewer)["checks"]), 19)
        self.stage(); self.activate(); self.save({"retention_days": 30})
        plan = self.call("POST", "checks/plan", {"asset": "store"}, self.viewer)
        self.assertEqual(sum(r["status"] == "planned" for r in plan["plan"]), 3)
        scan = self.scan()
        self.assertEqual(scan["result"]["counts"], {"pass": 2, "finding": 1, "unknown": 0, "skipped": 17, "disabled": 0, "unsupported": 0, "error": 0})
        self.assertEqual(len(scan["result"]["policy_version"]), 64)
        record, = self.call("GET", "issues")["issues"]
        self.assertEqual(record["risk"]["policy_weight"], 35)
        self.assertEqual(record["check_id"], "organization:retention")
        self.activate(0)
        self.assertEqual(self.call("GET", "scans/" + scan["id"], token=self.viewer)["result"], scan["result"])
        self.assertEqual(self.call("GET", "rule-packs", token=self.other)["packs"], [])
        for token in (self.operator, self.viewer):
            with self.assertRaises(Problem): self.call("POST", "rule-packs/stage", example(), token)
        with self.assertRaises(Problem): self.call("POST", "rule-packs/activate", {"id": "organization", "version": 1}, self.other)

    def test_revisions_preview_unknown_disable_and_rollback(self):
        self.stage(); self.activate(); self.save()
        first = self.scan()
        self.assertEqual(first["result"]["counts"]["unknown"], 1)
        self.assertIsNone(first["result"]["score"])
        pack = example(2); pack["rules"][0]["severity"] = "critical"
        preview = self.call("POST", "rule-packs/preview", {"pack": pack, "asset": "store"})
        self.assertTrue(preview["preview"])
        self.assertEqual(len(self.call("GET", "rule-packs")["packs"]), 1)
        self.stage(pack); self.activate(2); self.save({"retention_days": 30})
        self.assertNotEqual(first["result"]["policy_version"], self.scan()["result"]["policy_version"])
        self.call("POST", "checks/setting", {"id": "organization:retention", "enabled": False, "reason": "Approved exception"})
        self.assertEqual(self.scan()["result"]["counts"]["disabled"], 1)
        self.assertEqual(self.call("GET", "issues")["issues"][0]["status"], "open")
        self.activate(1)
        self.call("POST", "checks/setting", {"id": "organization:retention", "enabled": True, "reason": "Exception expired"})
        self.assertEqual(self.scan()["result"]["outcomes"][-1]["revision"], 1)
        altered = example(); altered["rules"][0]["title"] = "Replacement"
        with self.assertRaisesRegex(Problem, "immutable"): self.stage(altered)

    def test_rejects_invalid_and_executable_rules(self):
        for field, value in [("operator", "eval"), ("severity", []), ("kind", {}), ("field", "__class__.x"), ("expected", True), ("source_url", "javascript:alert(1)")]:
            pack = example(); pack["rules"][0][field] = value
            with self.subTest(field=field), self.assertRaises(Problem): self.stage(pack)
        pack = example(); pack["rules"][0]["tests"][0]["status"] = "finding"
        with self.assertRaisesRegex(Problem, "fixture failed"): self.stage(pack)
        pack = example(); pack["version"] = True
        with self.assertRaises(Problem): self.stage(pack)
        pack = example(); pack["id"] = "builtin"
        with self.assertRaisesRegex(Problem, "Built-in rule IDs"): self.stage(pack)

    def test_typed_operators_and_shipped_pack_upgrade(self):
        for op, expected, yes, no in [("eq", True, True, False), ("ne", "deny", "allow", "deny"), ("gt", 5, 6, 5), ("ge", 5, 5, 4), ("lt", 5, 4, 5), ("le", 5, 5, 6), ("in", ["a", "b"], "a", "c"), ("not_in", ["a"], "b", "a")]:
            rule = dict(example()["rules"][0], operator=op, expected=expected)
            self.assertEqual(rules.evaluate(rule, {"retention_days": yes})[0], "pass")
            self.assertEqual(rules.evaluate(rule, {"retention_days": no})[0], "finding")
            self.assertEqual(rules.evaluate(rule, {})[0], "unknown")
        rule = dict(example()["rules"][0], operator="eq", expected=True)
        self.assertEqual(rules.evaluate(rule, {"retention_days": 1})[0], "unknown")
        rule.update(operator="exists", expected=True)
        self.assertEqual(rules.evaluate(rule, {})[0], "finding")
        pack = rules.baseline(CHECKS); pack["version"] = 2; self.stage(pack)
        self.call("POST", "rule-packs/activate", {"id": "builtin", "version": 2}); self.save()
        self.assertTrue(all(e["version"] == 2 for e in self.scan()["result"]["execution"]))
        self.call("POST", "rule-packs/activate", {"id": "builtin", "version": 0})
        self.assertTrue(all(c["version"] == 1 for c in self.call("GET", "checks")["checks"]))

    def test_paged_metadata_and_direct_document_export(self):
        for version in range(1, 53):
            self.stage(example(version))
        newest = self.call("GET", "rule-packs")
        self.assertEqual(len(newest["packs"]), 50)
        self.assertNotIn("document", newest["packs"][0])
        older = self.call("GET", "rule-packs?before=" + str(newest["next_before"]))
        self.assertEqual([p["version"] for p in older["packs"]], [2, 1])
        self.assertEqual(self.call("GET", "rule-packs/organization/1"), example())
        with self.assertRaises(Problem): self.call("GET", "rule-packs/organization/1", token=self.other)
        with self.assertRaises(Problem): self.call("GET", "rule-packs?before=-1")

    def test_invalid_inputs_disabled_preview_and_preserved_builtin_weights(self):
        self.stage(); self.activate(); self.save()
        self.call("POST", "checks/setting", {"id": "organization:retention", "enabled": False, "reason": "Approved change"})
        preview = self.call("POST", "rule-packs/preview", {"pack": example(2), "asset": "store"})
        self.assertEqual(preview["result"]["counts"]["disabled"], 1)
        for route, payload in [("checks/plan", {"asset": []}), ("checks/setting", {"id": [], "enabled": True, "reason": "test"}), ("rule-sources/check", {"id": {}})]:
            with self.subTest(route=route), self.assertRaises(Problem): self.call("POST", route, payload)
        pack = rules.baseline(CHECKS); weights = [r["weight"] for r in pack["rules"]]
        pack["version"] = 2; self.stage(pack)
        self.call("POST", "rule-packs/activate", {"id": "builtin", "version": 2})
        self.assertEqual([r["weight"] for r in self.call("GET", "checks")["checks"] if r["pack"] == "builtin"], weights)


class SignedFeeds(unittest.TestCase):
    setUp = RuleTests.setUp
    call = RuleTests.call
    activate = RuleTests.activate
    save = RuleTests.save

    def prepare_key(self):
        self.private = Path(self.temp.name) / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private)], check=True, capture_output=True)
        self.public = subprocess.check_output(["openssl", "pkey", "-in", str(self.private), "-pubout"], text=True)

    def source(self, mode="stage"):
        return self.call("POST", "rule-sources", {"id": "organization", "url": "https://updates.example.org/rules.json", "public_key": self.public, "mode": mode, "interval_minutes": 5})

    def signed(self, pack):
        sig = verification.signed_command(["-sign", str(self.private)], rules.canonical(pack))
        return rules.canonical({"payload": pack, "signature": base64.b64encode(sig).decode()})

    def update(self, raw):
        return rules.update_source(self.path, "alpha", "organization", CHECKS, database, audit, lambda _: raw)

    def test_signed_updates_tampering_and_rollback_stickiness(self):
        self.prepare_key(); self.source("auto")
        self.assertEqual(self.update(self.signed(example()))["status"], "activated")
        self.assertEqual(self.update(self.signed(example(2)))["status"], "activated")
        self.activate(1)
        self.assertEqual(self.update(self.signed(example(2)))["status"], "unchanged")
        active, = [p for p in self.call("GET", "rule-packs")["packs"] if p["active"]]
        self.assertEqual(active["version"], 1)
        self.assertEqual(self.update(self.signed(example()))["status"], "error")
        envelope = json.loads(self.signed(example(3))); envelope["payload"]["version"] = 4
        self.assertEqual(self.update(json.dumps(envelope).encode())["status"], "error")
        self.assertEqual(len(self.call("GET", "rule-packs")["packs"]), 2)

    def test_notify_stage_isolation_and_mutation_during_fetch(self):
        self.prepare_key(); self.source("notify")
        self.assertEqual(self.update(self.signed(example()))["status"], "available")
        self.assertEqual(self.call("GET", "rule-packs")["packs"], [])
        changed = example(); changed["rules"][0]["title"] = "Changed"
        self.assertEqual(self.update(self.signed(changed))["status"], "error")
        self.source("stage")
        self.assertEqual(self.update(self.signed(example()))["status"], "staged")
        self.assertFalse(self.call("GET", "rule-packs")["packs"][0]["active"])
        self.assertEqual(self.call("GET", "rule-sources", token=self.other)["sources"], [])
        with self.assertRaises(Problem): self.call("GET", "rule-sources", token=self.viewer)
        def download(_):
            self.source("disabled")
            return self.signed(example(2))
        result = rules.update_source(self.path, "alpha", "organization", CHECKS, database, audit, download)
        self.assertEqual(result["status"], "superseded")
        self.assertEqual(len(self.call("GET", "rule-packs")["packs"]), 1)

    def test_https_private_addresses_and_scheduler(self):
        for url in ("http://example.org/rules", "https://user:pass@example.org/rules", "https://example.org:8443/rules", "https://example.org/rules?token=secret"):
            with self.subTest(url=url), self.assertRaises(Problem): rules.safe_url(url)
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"):
            with patch("check_catalog.socket.getaddrinfo", return_value=[(2, 1, 6, "", (address, 443))]):
                with self.assertRaisesRegex(Problem, "public IP"): rules.fetch_feed("https://updates.example.org/rules")
        self.prepare_key(); self.source("stage")
        worker = rules.Updater(self.path, CHECKS, database, audit)
        with patch("check_catalog.update_source") as update:
            worker.tick(); update.assert_called_once()
        self.source("disabled")
        with patch("check_catalog.update_source") as update:
            worker.tick(); update.assert_not_called()

    def test_cli_sign_stage_preview_and_export(self):
        self.prepare_key()
        script = Path(__file__).resolve().parents[1] / "app.py"
        packfile = Path(self.temp.name) / "pack.json"; packfile.write_bytes(rules.canonical(example()))
        signed = Path(self.temp.name) / "signed.json"
        def cli(*arguments):
            return json.loads(subprocess.check_output([sys.executable, str(script), "--db", str(self.path), "rules", "alpha", *arguments], text=True))
        self.assertTrue(cli("validate", "--file", str(packfile))["passed"])
        self.assertEqual(cli("stage", "--file", str(packfile))["version"], 1)
        self.assertEqual(cli("export", "--id", "organization", "--version", "1"), example())
        self.assertTrue(cli("sign", "--file", str(packfile), "--private-key", str(self.private), "--output", str(signed))["signed"])
        self.source(); self.assertEqual(self.update(signed.read_bytes())["status"], "staged")
        self.save(); self.assertTrue(cli("preview", "--file", str(packfile), "--asset", "store")["preview"])
