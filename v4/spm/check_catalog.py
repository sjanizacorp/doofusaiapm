"""Versioned, declarative posture checks. Authored by Aniza Inc.

Rules compare collected facts; they never execute downloaded Python or expressions.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic
from urllib.parse import parse_qs, urlsplit

from controls import Problem, protect_admin
import verification

MAX_PACK = 1024 * 1024
MAX_RULES = 250
SCHEMA = """
CREATE TABLE rule_packs (
 project TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL, document TEXT NOT NULL,
 digest TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL, verified_source TEXT,
 PRIMARY KEY(project,id,version)
);
CREATE TABLE active_rule_packs (
 project TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
 PRIMARY KEY(project,id), FOREIGN KEY(project,id,version) REFERENCES rule_packs(project,id,version)
);
CREATE TABLE rule_settings (
 project TEXT NOT NULL, id TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 reason TEXT NOT NULL, PRIMARY KEY(project,id)
);
CREATE TABLE rule_sources (
 project TEXT NOT NULL, id TEXT NOT NULL, url TEXT NOT NULL, public_key TEXT NOT NULL,
 mode TEXT NOT NULL, interval_minutes INTEGER NOT NULL, next_check TEXT NOT NULL,
 checked_at TEXT, last_status TEXT NOT NULL, last_version INTEGER, last_digest TEXT,
 PRIMARY KEY(project,id)
);
"""
ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}")
FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}")
OPERATORS = ("eq", "ne", "gt", "ge", "lt", "le", "in", "not_in", "exists")
WEIGHTS = {"low": 10, "medium": 20, "high": 35, "critical": 45}
SOURCES = {
 "storage": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
 "registry": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/security.html",
 "agent": "https://genai.owasp.org/",
 "gcs-bucket": "https://cloud.google.com/storage/docs/best-practices",
 "aws-role": "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
 "azure-endpoint": "https://learn.microsoft.com/azure/machine-learning/how-to-secure-online-endpoint",
 "azure-identity": "https://learn.microsoft.com/azure/role-based-access-control/best-practices",
 "vsphere-host": "https://www.vmware.com/resources/audit-security/vsphere.html",
 "vsphere-vm": "https://www.vmware.com/resources/audit-security/vsphere.html",
 "oci-endpoint": "https://docs.oracle.com/en-us/iaas/data-science/using/model-dep-logging.htm",
 "ibm-endpoint": "https://cloud.ibm.com/docs/watson-machine-learning",
 "vertex-endpoint": "https://cloud.google.com/vertex-ai/docs/general/deployment",
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def text(value, name, limit=1000):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or "\0" in value:
        raise Problem(400, f"Supply {name} as text of 1–{limit} characters.")
    return value


def rule_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Problem(400, "Use a rule/pack ID beginning with a letter, followed by up to 79 letters, digits, periods, underscores or hyphens.")
    return value


def scalar(value):
    return (value is None or type(value) in (str, bool, int, float)) and not (
        isinstance(value, str) and len(value) > 1000 or type(value) is int and abs(value) > 10**15
        or type(value) is float and not math.isfinite(value))


def evaluate(rule, facts):
    field, operator, expected = rule["field"], rule["operator"], rule["expected"]
    actual = facts.get(field)
    if operator == "exists":
        passed = (field in facts and actual is not None) == expected
    elif actual is None:
        return "unknown", "Required evidence is missing."
    elif not scalar(actual):
        return "unknown", "Collected evidence has an unsupported type."
    elif operator in ("eq", "ne"):
        if type(actual) is not type(expected):
            return "unknown", "Collected evidence type does not match the rule."
        passed = actual == expected if operator == "eq" else actual != expected
    elif operator in ("in", "not_in"):
        if not any(type(actual) is type(item) for item in expected):
            return "unknown", "Collected evidence type does not match the rule."
        matched = any(type(actual) is type(item) and actual == item for item in expected)
        passed = matched if operator == "in" else not matched
    else:
        if type(actual) not in (int, float):
            return "unknown", "The rule requires numeric evidence."
        passed = {"gt": lambda: actual > expected, "ge": lambda: actual >= expected,
                  "lt": lambda: actual < expected, "le": lambda: actual <= expected}[operator]()
    return ("pass", "Condition satisfied.") if passed else ("finding", "Condition not satisfied.")


def validate_pack(document, kinds):
    if not isinstance(document, dict) or document.keys() != {"schema", "id", "version", "rules"}:
        raise Problem(400, "A pack requires schema, id, version and rules.")
    if document["schema"] != "doofusai.rules.v1":
        raise Problem(400, "Unsupported rule pack schema.")
    rule_id(document["id"])
    if type(document["version"]) is not int or not 1 <= document["version"] <= 10**9:
        raise Problem(400, "Pack version must be an integer from 1 to 1000000000.")
    rules = document["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise Problem(400, f"Use 1–{MAX_RULES} rules per pack.")
    seen, assertions = set(), 0
    for rule in rules:
        required = {"id", "title", "description", "kind", "field", "operator", "expected", "severity", "remediation", "source_url", "tests"}
        if not isinstance(rule, dict) or not required <= rule.keys() or rule.keys() - required - {"weight"}:
            raise Problem(400, "Each rule requires " + ", ".join(sorted(required)) + ".")
        if "weight" in rule and (type(rule["weight"]) is not int or not 1 <= rule["weight"] <= 100):
            raise Problem(400, "Optional policy weight must be an integer from 1 to 100.")
        key = rule_id(rule["id"])
        if key in seen:
            raise Problem(400, "Duplicate rule ID within pack.")
        seen.add(key)
        for field, limit in (("title", 160), ("description", 1000), ("remediation", 1000)):
            text(rule[field], field, limit)
        if not isinstance(rule["kind"], str) or rule["kind"] not in kinds or not isinstance(rule["field"], str) or not FIELD.fullmatch(rule["field"]):
            raise Problem(400, "Use a supported asset kind and one top-level fact field.")
        if document["id"] == "builtin" and not key.startswith(rule["kind"] + "."):
            raise Problem(400, "Built-in rule IDs must start with the asset kind followed by a period.")
        if not isinstance(rule["operator"], str) or rule["operator"] not in OPERATORS or not isinstance(rule["severity"], str) or rule["severity"] not in WEIGHTS:
            raise Problem(400, "Unsupported comparison operator or severity.")
        op, expected = rule["operator"], rule["expected"]
        if op in ("in", "not_in"):
            valid = isinstance(expected, list) and 1 <= len(expected) <= 50 and all(scalar(v) and v is not None for v in expected)
        elif op == "exists":
            valid = type(expected) is bool
        elif op in ("gt", "ge", "lt", "le"):
            valid = type(expected) in (int, float) and scalar(expected)
        else:
            valid = scalar(expected) and expected is not None
        if not valid:
            raise Problem(400, "Expected value is incompatible with the comparison operator.")
        if not isinstance(rule["source_url"], str):
            raise Problem(400, "Source references must be a URL string or an empty string.")
        if rule["source_url"]:
            parsed = urlsplit(text(rule["source_url"], "source URL", 2000))
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise Problem(400, "Source references must use HTTPS URLs.")
        tests = rule["tests"]
        if not isinstance(tests, list) or not 2 <= len(tests) <= 20:
            raise Problem(400, "Each rule requires 2–20 regression fixtures, including pass and finding cases.")
        statuses = set()
        for test in tests:
            if (not isinstance(test, dict) or test.keys() != {"facts", "status"}
                    or test["status"] not in ("pass", "finding", "unknown") or not isinstance(test["facts"], dict)
                    or len(test["facts"]) > 50 or any(not isinstance(k, str) or not FIELD.fullmatch(k) or not scalar(v)
                                                     for k, v in test["facts"].items())):
                raise Problem(400, "Invalid rule regression fixture.")
            status, _ = evaluate(rule, test["facts"])
            if status != test["status"]:
                raise Problem(400, f"Regression fixture failed for {key}: expected {test['status']}, got {status}.")
            statuses.add(status)
            assertions += 1
        if not {"pass", "finding"} <= statuses:
            raise Problem(400, "Regression fixtures must cover both pass and finding outcomes.")
    if len(canonical(document)) > MAX_PACK:
        raise Problem(400, "Rule pack exceeds the one MiB limit.")
    return {"rules": len(rules), "assertions": assertions, "passed": True}


def baseline(checks):
    rules = []
    for kind, entries in checks.items():
        for key, field, expected, remediation, penalty in entries:
            rules.append({"id": kind + "." + key, "title": remediation, "description": f"Compare collected {field} evidence against the configured requirement.",
                          "kind": kind, "field": field, "operator": "eq", "expected": expected,
                          "severity": "critical" if penalty >= 40 else "high" if penalty >= 30 else "medium",
                          "weight": penalty,
                          "remediation": remediation, "source_url": SOURCES[kind],
                          "tests": [{"facts": {field: expected}, "status": "pass"},
                                    {"facts": {field: not expected}, "status": "finding"}, {"facts": {}, "status": "unknown"}]})
    return {"schema": "doofusai.rules.v1", "id": "builtin", "version": 1, "rules": rules}


def catalogue(conn, project, checks):
    packs = {"builtin": baseline(checks)}
    for row in conn.execute("SELECT p.document FROM rule_packs p JOIN active_rule_packs a USING(project,id,version) WHERE p.project=?", (project,)):
        pack = json.loads(row["document"])
        packs[pack["id"]] = pack
    settings = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM rule_settings WHERE project=?", (project,))}
    rows = []
    for pack_id, pack in sorted(packs.items()):
        for rule in pack["rules"]:
            identifier = pack_id + ":" + rule["id"]
            setting = settings.get(identifier, {})
            weight = rule.get("weight", WEIGHTS[rule["severity"]])
            rows.append(dict(rule, catalogue_id=identifier, pack=pack_id, version=pack["version"],
                             enabled=bool(setting.get("enabled", True)), disabled_reason=setting.get("reason", ""), weight=weight))
    return rows


def assessment(conn, project, kind, facts, checks, rules=None):
    rules = catalogue(conn, project, checks) if rules is None else rules
    revision = hashlib.sha256(canonical(rules)).hexdigest()
    outcomes, manifest = [], []
    for rule in rules:
        check = rule["id"].split(".", 1)[1] if rule["pack"] == "builtin" else rule["catalogue_id"]
        if not rule["enabled"]:
            status, reason = "disabled", rule["disabled_reason"]
        elif rule["kind"] != kind:
            status, reason = "skipped", "Not applicable to this asset kind."
        else:
            status, reason = evaluate(rule, facts)
        manifest.append({"id": rule["catalogue_id"], "title": rule["title"], "pack": rule["pack"], "version": rule["version"],
                         "status": status, "reason": reason, "source_url": rule["source_url"],
                         "field": rule["field"], "operator": rule["operator"], "expected": rule["expected"],
                         "severity": rule["severity"], "remediation": rule["remediation"]})
        if status in ("pass", "finding", "unknown"):
            outcomes.append({"check": check, "field": rule["field"], "expected": rule["expected"], "observed": facts.get(rule["field"]),
                             "status": status, "remediation": rule["remediation"], "penalty": rule["weight"] if status == "finding" else 0,
                             "catalogue_id": rule["catalogue_id"], "revision": rule["version"], "severity": rule["severity"],
                             "source_url": rule["source_url"], "policy_weight": rule["weight"]})
    complete = bool(outcomes) and all(o["status"] != "unknown" for o in outcomes)
    return {"policy_version": revision, "coverage": "complete" if complete else "incomplete",
            "score": max(0, 100 - sum(o["penalty"] for o in outcomes)) if complete else None,
            "outcomes": outcomes, "execution": manifest, "counts": {s: sum(r["status"] == s for r in manifest)
            for s in ("pass", "finding", "unknown", "skipped", "disabled", "unsupported", "error")}}


def stage(conn, user, document, checks, audit, verified_source=None):
    validation = validate_pack(document, checks)
    project, key, version = user["project"], document["id"], document["version"]
    raw = canonical(document)
    digest = hashlib.sha256(raw).hexdigest()
    old = conn.execute("SELECT digest FROM rule_packs WHERE project=? AND id=? AND version=?", (project, key, version)).fetchone()
    if old:
        if old["digest"] != digest:
            raise Problem(409, "A published revision is immutable. Increase the pack version.")
        return {"id": key, "version": version, "digest": digest, "validation": validation, "unchanged": True}
    maximum = conn.execute("SELECT MAX(version) FROM rule_packs WHERE project=? AND id=?", (project, key)).fetchone()[0] or 0
    if version <= maximum or (key == "builtin" and version <= 1):
        raise Problem(409, "New pack revisions must increase the version. Roll back by activating an existing revision.")
    total = conn.execute("SELECT count(*) FROM rule_packs WHERE project=?", (project,)).fetchone()[0]
    if total >= 1000:
        raise Problem(409, "Project rule revision storage limit reached (1000).")
    conn.execute("INSERT INTO rule_packs VALUES(?,?,?,?,?,?,?,?)",
                 (project, key, version, raw.decode(), digest, now(), user["principal"], verified_source))
    audit(conn, user, "rules.staged", key, {"version": version, "digest": digest, "verified_source": verified_source})
    return {"id": key, "version": version, "digest": digest, "validation": validation}


def activate(conn, user, key, version, checks, audit):
    rule_id(key)
    if type(version) is not int or version < 0:
        raise Problem(400, "Use an integer version, or zero to remove the active override.")
    if version:
        row = conn.execute("SELECT document FROM rule_packs WHERE project=? AND id=? AND version=?", (user["project"], key, version)).fetchone()
        if row is None:
            raise Problem(404, "Rule revision not found.")
        validate_pack(json.loads(row["document"]), checks)
        count = conn.execute("SELECT count(*) FROM active_rule_packs WHERE project=? AND id<>?", (user["project"], key)).fetchone()[0]
        if count >= 20:
            raise Problem(409, "At most 20 rule packs may be active per project.")
        conn.execute("INSERT INTO active_rule_packs VALUES(?,?,?) ON CONFLICT(project,id) DO UPDATE SET version=excluded.version",
                     (user["project"], key, version))
    else:
        conn.execute("DELETE FROM active_rule_packs WHERE project=? AND id=?", (user["project"], key))
    audit(conn, user, "rules.activated", key, {"version": version})
    return {"id": key, "active_version": version}


def safe_url(url):
    try:
        parsed = urlsplit(text(url, "feed URL", 2000))
        port = parsed.port
    except ValueError:
        raise Problem(400, "Invalid HTTPS feed URL or port.") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or port not in (None, 443)):
        raise Problem(400, "Feeds require an HTTPS URL on port 443, without credentials, query or fragment.")
    if any(ord(c) <= 32 or ord(c) >= 127 for c in url):
        raise Problem(400, "Feed URLs must use printable ASCII without spaces.")
    return parsed


def fetch_feed(url):
    parsed = safe_url(url)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise Problem(400, "Rule feeds must resolve exclusively to public IP addresses.")
        # Pin the validated address for this connection; preserve hostname verification and SNI.
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=10, context=context)
        raw = socket.create_connection((addresses[0][4][0], 443), timeout=10)
        try:
            tls = context.wrap_socket(raw, server_hostname=parsed.hostname)
            connection.sock = tls
            connection.request("GET", parsed.path or "/", headers={"Accept": "application/json", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise Problem(400, "Rule feed must return HTTP 200 and uncompressed JSON. Redirects are not followed.")
            deadline = monotonic() + 10
            payload = bytearray()
            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise Problem(400, "Rule feed exceeded the download time limit.")
                tls.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_PACK + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > MAX_PACK:
                    raise Problem(400, "Rule feed exceeds one MiB.")
            return bytes(payload)
        finally:
            connection.close()
            raw.close()
    except ssl.SSLCertVerificationError:
        raise Problem(400, "TLS certificate verification failed. Install Python's CA certificates or configure SSL_CERT_FILE with an approved CA bundle.") from None
    except (OSError, ValueError, http.client.HTTPException):
        raise Problem(400, "Could not retrieve the rule feed over verified HTTPS.") from None


def verify_feed(raw, source):
    envelope = verification.parse_json(raw)
    if not isinstance(envelope, dict) or envelope.keys() != {"payload", "signature"}:
        raise Problem(400, "Feed requires a payload and base64 SHA-256 signature.")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        data = canonical(envelope["payload"])
    except (ValueError, TypeError):
        raise Problem(400, "Invalid rule feed signature or payload.") from None
    with TemporaryDirectory() as temporary:
        key = Path(temporary) / "publisher.pem"
        key.write_text(source["public_key"])
        verification.verify_signature(data, signature, key)
    pack = envelope["payload"]
    if not isinstance(pack, dict) or pack.get("id") != source["id"]:
        raise Problem(400, "Signed feed pack does not match the configured source ID.")
    return pack


def save_source(conn, user, body, audit):
    if not isinstance(body, dict) or body.keys() != {"id", "url", "public_key", "mode", "interval_minutes"}:
        raise Problem(400, "Source requires id, url, public_key, mode and interval_minutes.")
    key = rule_id(body["id"])
    if (conn.execute("SELECT count(*) FROM rule_sources WHERE project=?", (user["project"],)).fetchone()[0] >= 20
            and conn.execute("SELECT 1 FROM rule_sources WHERE project=? AND id=?", (user["project"], key)).fetchone() is None):
        raise Problem(409, "At most 20 trusted rule sources may be configured per project.")
    safe_url(body["url"])
    public = text(body["public_key"], "publisher public key", 8192)
    if not public.startswith("-----BEGIN PUBLIC KEY-----") or "PRIVATE" in public:
        raise Problem(400, "Supply only the publisher PEM public key, never a private key.")
    # Reject malformed or unsupported keys at configuration time.
    with TemporaryDirectory() as temporary:
        keyfile = Path(temporary) / "key.pem"
        keyfile.write_text(public)
        import subprocess
        try:
            subprocess.run(["openssl", "pkey", "-pubin", "-in", str(keyfile), "-noout"],
                           capture_output=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            raise Problem(400, "Invalid publisher public key.") from None
    if body["mode"] not in ("notify", "stage", "auto", "disabled"):
        raise Problem(400, "Source mode must be notify, stage, auto or disabled.")
    interval = body["interval_minutes"]
    if type(interval) is not int or not 5 <= interval <= 10080:
        raise Problem(400, "Use a source interval of 5–10080 minutes.")
    conn.execute("""INSERT INTO rule_sources VALUES(?,?,?,?,?,?,?,NULL,'pending',NULL,NULL)
     ON CONFLICT(project,id) DO UPDATE SET url=excluded.url,public_key=excluded.public_key,
     mode=excluded.mode,interval_minutes=excluded.interval_minutes,next_check=excluded.next_check,
     checked_at=NULL,last_status='pending',last_version=NULL,last_digest=NULL""",
                 (user["project"], body["id"], body["url"], public, body["mode"], interval, now()))
    audit(conn, user, "rules.source.configured", body["id"], {"mode": body["mode"], "url": body["url"]})
    return {"id": body["id"], "mode": body["mode"]}


def update_source(path, project, key, checks, database, audit, fetch=fetch_feed):
    with database(path) as conn:
        row = conn.execute("SELECT * FROM rule_sources WHERE project=? AND id=?", (project, key)).fetchone()
        if row is None:
            raise Problem(404, "Rule source not found.")
        source = dict(row)
    if source["mode"] == "disabled":
        return {"id": key, "status": "disabled"}
    pack, failure = None, None
    try:
        pack = verify_feed(fetch(source["url"]), source)
        validate_pack(pack, checks)
    except (Problem, OSError, ValueError) as error:
        failure = str(error)[:500]
    user = {"project": project, "principal": "rule-feed:" + key, "role": "admin"}
    with database(path, write=True) as conn:
        current = conn.execute("SELECT * FROM rule_sources WHERE project=? AND id=?", (project, key)).fetchone()
        if current is None or dict(current) != source:
            return {"id": key, "status": "superseded", "reason": "Source configuration or update state changed during fetch."}
        result = {"id": key, "status": "error", "reason": failure}
        if failure is None:
            try:
                known = conn.execute("SELECT MAX(version) FROM rule_packs WHERE project=? AND id=?", (project, key)).fetchone()[0] or 0
                minimum = max(known, source["last_version"] or 0, 1 if key == "builtin" else 0)
                if pack["version"] < minimum:
                    raise Problem(409, "Feed rollback detected; select a retained revision explicitly to roll back.")
                if (pack["version"] == source["last_version"] and source["last_digest"]
                        and source["last_digest"] != hashlib.sha256(canonical(pack)).hexdigest()):
                    raise Problem(409, "Feed changed the contents of an immutable revision.")
                # Stage verifies immutable version/digest even if a version is already known.
                if source["mode"] == "notify":
                    old = conn.execute("SELECT digest FROM rule_packs WHERE project=? AND id=? AND version=?", (project, key, pack["version"])).fetchone()
                    if old and old["digest"] != hashlib.sha256(canonical(pack)).hexdigest():
                        raise Problem(409, "Feed changed the contents of an immutable revision.")
                    result = {"id": key, "status": "available", "version": pack["version"]}
                else:
                    result = stage(conn, user, pack, checks, audit, source["url"])
                    result["status"] = "staged"
                    if source["mode"] == "auto":
                        # Never reactivate the same revision after an operator rollback.
                        if pack["version"] > (source["last_version"] or 0):
                            activate(conn, user, key, pack["version"], checks, audit)
                            result["status"] = "activated"
                        else:
                            result["status"] = "unchanged"
            except Problem as error:
                result = {"id": key, "status": "error", "reason": str(error)[:500]}
        next_check = (datetime.now(timezone.utc) + timedelta(minutes=source["interval_minutes"])).isoformat(timespec="seconds")
        succeeded = pack is not None and result["status"] != "error"
        conn.execute("UPDATE rule_sources SET next_check=?,checked_at=?,last_status=?,last_version=?,last_digest=? WHERE project=? AND id=?",
                     (next_check, now(), json.dumps(result), max(source["last_version"] or 0, pack["version"]) if succeeded else source["last_version"],
                      hashlib.sha256(canonical(pack)).hexdigest() if succeeded else source["last_digest"], project, key))
        audit(conn, user, "rules.source.checked", key, result)
        return result


def manage(conn, user, method, route, body, checks, audit, query=""):
    project = user["project"]
    if route == "/api/v1/checks" and method == "GET":
        return 200, {"checks": catalogue(conn, project, checks), "operators": OPERATORS, "kinds": list(checks)}
    if route == "/api/v1/checks/plan" and method == "POST":
        if not isinstance(body, dict) or body.keys() != {"asset"}:
            raise Problem(400, "Supply the asset ID.")
        asset = text(body["asset"], "asset ID", 80)
        row = conn.execute("SELECT kind,facts FROM assets WHERE project=? AND id=?", (project, asset)).fetchone()
        if row is None:
            raise Problem(404, "Asset not found.")
        result = assessment(conn, project, row["kind"], json.loads(row["facts"]), checks)
        for item in result["execution"]:
            if item["status"] in ("pass", "finding", "unknown"):
                item["status"], item["reason"] = "planned", "Applicable; scan will evaluate collected evidence."
        return 200, {"asset": body["asset"], "policy_version": result["policy_version"], "plan": result["execution"]}
    if route == "/api/v1/rule-packs" and method == "GET":
        params = parse_qs(query, keep_blank_values=True)
        before = params.get("before", ["9223372036854775807"])
        if len(before) != 1 or not before[0].isascii() or not before[0].isdigit() or not 1 <= int(before[0]) <= 9223372036854775807:
            raise Problem(400, "Invalid rule history cursor.")
        rows = list(conn.execute("""SELECT p.rowid AS sequence,p.project,p.id,p.version,p.digest,p.created_at,p.created_by,
          p.verified_source,a.version IS NOT NULL AS active FROM rule_packs p LEFT JOIN active_rule_packs a USING(project,id,version)
          WHERE p.project=? AND p.rowid<? ORDER BY p.rowid DESC LIMIT 51""", (project, int(before[0]))))
        return 200, {"packs": [dict(r) | {"active": bool(r["active"])} for r in rows[:50]],
                     "next_before": rows[49]["sequence"] if len(rows) > 50 else None}
    if route == "/api/v1/rule-packs/builtin" and method == "GET":
        return 200, baseline(checks)
    if route.startswith("/api/v1/rule-packs/") and method == "GET":
        parts = route.removeprefix("/api/v1/rule-packs/").split("/")
        if len(parts) != 2 or not parts[1].isascii() or not parts[1].isdigit() or len(parts[1]) > 10:
            raise Problem(400, "Use /rule-packs/PACK/VERSION to export a retained revision.")
        row = conn.execute("SELECT document FROM rule_packs WHERE project=? AND id=? AND version=?", (project, rule_id(parts[0]), int(parts[1]))).fetchone()
        if row is None:
            raise Problem(404, "Rule revision not found.")
        return 200, json.loads(row["document"])
    if route == "/api/v1/rule-sources" and method == "GET":
        protect_admin(user)
        return 200, {"sources": [dict(r) for r in conn.execute("SELECT * FROM rule_sources WHERE project=? ORDER BY id", (project,))]}
    protect_admin(user)
    if route == "/api/v1/rule-packs/preview" and method == "POST":
        if not isinstance(body, dict) or body.keys() != {"pack", "asset"}:
            raise Problem(400, "Supply a pack document and asset ID.")
        pack = body["pack"]
        validate_pack(pack, checks)
        asset = text(body["asset"], "asset ID", 80)
        row = conn.execute("SELECT kind,facts FROM assets WHERE project=? AND id=?", (project, asset)).fetchone()
        if row is None:
            raise Problem(404, "Asset not found.")
        current = catalogue(conn, project, checks)
        settings = {r["catalogue_id"]: r for r in current}
        rules = [r for r in current if r["pack"] != pack["id"]]
        rules.extend(dict(r, catalogue_id=pack["id"] + ":" + r["id"], pack=pack["id"], version=pack["version"],
                          enabled=settings.get(pack["id"] + ":" + r["id"], {}).get("enabled", True),
                          disabled_reason=settings.get(pack["id"] + ":" + r["id"], {}).get("disabled_reason", ""),
                          weight=r.get("weight", WEIGHTS[r["severity"]])) for r in pack["rules"])
        return 200, {"asset": body["asset"], "preview": True,
                     "result": assessment(conn, project, row["kind"], json.loads(row["facts"]), checks, rules)}
    if route in ("/api/v1/rule-packs/validate", "/api/v1/rule-packs/stage") and method == "POST":
        return 200, validate_pack(body, checks) if route.endswith("validate") else stage(conn, user, body, checks, audit)
    if route == "/api/v1/rule-packs/activate" and method == "POST":
        if not isinstance(body, dict) or body.keys() != {"id", "version"}:
            raise Problem(400, "Supply id and version.")
        return 200, activate(conn, user, body["id"], body["version"], checks, audit)
    if route == "/api/v1/checks/setting" and method == "POST":
        if (not isinstance(body, dict) or body.keys() != {"id", "enabled", "reason"} or not isinstance(body["id"], str) or type(body["enabled"]) is not bool
                or body["id"] not in {r["catalogue_id"] for r in catalogue(conn, project, checks)}):
            raise Problem(400, "Supply a known catalogue id, boolean enabled and reason.")
        reason = text(body["reason"], "change reason", 500)
        conn.execute("INSERT INTO rule_settings VALUES(?,?,?,?) ON CONFLICT(project,id) DO UPDATE SET enabled=excluded.enabled,reason=excluded.reason",
                     (project, body["id"], int(body["enabled"]), reason))
        audit(conn, user, "rules.setting.updated", body["id"], body)
        return 200, body
    if route == "/api/v1/rule-sources" and method == "POST":
        return 200, save_source(conn, user, body, audit)
    if route == "/api/v1/rule-sources/check" and method == "POST":
        if not isinstance(body, dict) or body.keys() != {"id"}:
            raise Problem(400, "Supply the source ID.")
        rule_id(body["id"])
        changed = conn.execute("UPDATE rule_sources SET next_check=?,last_status='queued' WHERE project=? AND id=? AND mode<>'disabled'",
                               (now(), project, body["id"])).rowcount
        if not changed:
            raise Problem(404, "Enabled rule source not found.")
        audit(conn, user, "rules.source.queued", body["id"])
        return 202, {"id": body["id"], "status": "queued", "message": "The running service checks due sources every 30 seconds."}
    raise Problem(404, "Rule operation not found.")


class Updater:
    def __init__(self, path, checks, database, audit):
        self.path, self.checks, self.database, self.audit = path, checks, database, audit
        self.stop_event = Event()
        self.thread = Thread(target=self.run, daemon=True, name="rule-feed-updater")

    def tick(self):
        with self.database(self.path) as conn:
            sources = [(r["project"], r["id"]) for r in conn.execute(
                "SELECT project,id FROM rule_sources WHERE mode<>'disabled' AND next_check<=? ORDER BY next_check LIMIT 10", (now(),))]
        for project, key in sources:
            if self.stop_event.is_set():
                return
            try:
                update_source(self.path, project, key, self.checks, self.database, self.audit)
            except (Problem, OSError):
                # Source-level fetch and validation failures are persisted by update_source.
                continue

    def run(self):
        import logging
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                logging.getLogger(__name__).exception("Rule update worker failed")
            self.stop_event.wait(30)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=15)
