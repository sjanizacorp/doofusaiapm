"""DoofusAI SPM, authored by Aniza Inc."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
from threading import BoundedSemaphore, Thread
from time import perf_counter
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import gcs
import agent_protocol
import agent_registry
import controls
from controls import Problem
import verification
import federation
import device_login
import vertex
import runtime_policy
import runtime_relay
import ai_bom
import aws_inventory
import azure_inventory
import vsphere_inventory
import github_bom
import telemetry
import risk_evidence
import iam_review
import access_reviews
import model_behavior
import gcs_access
import content_scan
import data_posture
import npm_inventory
import ibm_inventory
import oci_inventory
import salesforce_inventory

WEB = Path(__file__).with_name("web")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}")
CHECKS = {
    "storage": [("ENC", "encrypted", True, "Enable encryption at rest", 30),
                ("ACCESS", "public", False, "Remove public access", 45)],
    "registry": [("SIGNED", "signatures_required", True, "Require trusted signatures", 35),
                 ("ACCESS", "public", False, "Remove public access", 45)],
    "agent": [("REVIEW", "approval_required", True, "Require approval for sensitive actions", 30),
              ("DATA", "redaction_enabled", True, "Enable sensitive-data redaction", 25)],
    "gcs-bucket": [
        ("PAP", "bucket_pap_enforced", True, "Enforce public access prevention explicitly on the bucket", 35),
        ("UNIFORM", "uniform_access_enabled", True, "Review and enable uniform bucket-level access", 25),
        ("CMEK", "default_cmek_configured", True, "Configure a customer-managed default key if required", 20),
    ],
    "aws-role": [
        ("EXTERNAL", "external_access_reported", False, "Review the active external access finding in AWS IAM Access Analyzer", 45),
    ],
    "azure-endpoint": [
        ("PRIVATE", "public_network_disabled", True, "Review whether this Azure ML endpoint should disable public network access", 30),
    ],
    "azure-identity": [
        ("PRIVILEGED", "privileged_role_reported", False, "Review direct privileged Azure RBAC assignments for this managed identity", 35),
    ],
    "vsphere-host": [
        ("LOCKDOWN", "lockdown_enabled", True, "Review vSphere lockdown mode and emergency access policy", 35),
    ],
    "vsphere-vm": [
        ("LOGGING", "vm_logging_enabled", True, "Enable virtual machine logging where required by policy", 20),
        ("SECURE_BOOT", "efi_secure_boot_enabled", True, "Review and enable Secure Boot for supported EFI workloads", 25),
    ],
    "oci-endpoint": [
        ("DEPLOYMENT_HEALTH", "operational", True, "Investigate the OCI Data Science deployment lifecycle state", 20),
        ("ACCESS_LOGGING", "access_logging_configured", True, "Configure OCI access logging for inference requests", 25),
    ],
    "ibm-endpoint": [
        ("DEPLOYMENT_HEALTH", "operational", True, "Investigate the failed watsonx.ai deployment", 20),
    ],
    "vertex-endpoint": [
        ("PRIVATE", "private_network_configured", True, "Review whether the prediction endpoint requires private networking", 30),
    ],
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
  digest TEXT PRIMARY KEY, principal TEXT NOT NULL, project TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer'))
);
CREATE TABLE IF NOT EXISTS assets (
  project TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, facts TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(project,id)
);
CREATE TABLE IF NOT EXISTS scans (
  project TEXT NOT NULL, id TEXT NOT NULL, asset TEXT NOT NULL, snapshot TEXT NOT NULL,
  result TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(project,id)
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, project TEXT NOT NULL, principal TEXT NOT NULL,
  action TEXT NOT NULL, resource TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""
ISSUE_SCHEMA = """
ALTER TABLE assets ADD COLUMN evidence TEXT;
CREATE TABLE issues (
  project TEXT NOT NULL, id TEXT NOT NULL, asset TEXT NOT NULL, kind TEXT NOT NULL,
  check_id TEXT NOT NULL, field TEXT NOT NULL, status TEXT NOT NULL
    CHECK(status IN ('open','resolved')),
  first_scan TEXT NOT NULL, last_scan TEXT NOT NULL, last_outcome TEXT NOT NULL,
  updated_at TEXT NOT NULL, PRIMARY KEY(project,id), UNIQUE(project,asset,kind,check_id)
);
CREATE INDEX issues_by_project_status ON issues(project,status,updated_at DESC,id);
CREATE TABLE issue_events (
  seq INTEGER PRIMARY KEY, project TEXT NOT NULL, issue TEXT NOT NULL, scan TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('opened','observed','resolved','reopened','unknown')),
  outcome TEXT NOT NULL CHECK(outcome IN ('finding','pass','unknown')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(project,issue) REFERENCES issues(project,id),
  FOREIGN KEY(project,scan) REFERENCES scans(project,id)
);
CREATE INDEX issue_events_by_issue ON issue_events(project,issue,seq DESC);
"""
SOURCE_SCHEMA = """
CREATE TABLE cloud_assets (
  project TEXT NOT NULL, asset TEXT NOT NULL, provider TEXT NOT NULL,
  source_project TEXT NOT NULL, name TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
  last_seen TEXT NOT NULL, PRIMARY KEY(project,asset),
  FOREIGN KEY(project,asset) REFERENCES assets(project,id)
);
CREATE INDEX cloud_assets_by_source ON cloud_assets(project,provider,source_project);
CREATE TABLE sync_runs (
  id TEXT NOT NULL PRIMARY KEY, project TEXT NOT NULL, provider TEXT NOT NULL,
  source_project TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('completed','failed')),
  assets INTEGER, error TEXT
);
CREATE INDEX sync_runs_by_project ON sync_runs(project,finished_at DESC,id);
"""
OPERATIONS_SCHEMA = """
ALTER TABLE issues ADD COLUMN assignee TEXT;
ALTER TABLE credentials ADD COLUMN expires_at TEXT;
"""
STREAM_SCHEMA = """
CREATE TABLE event_stream (singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL);
INSERT INTO event_stream VALUES(1,lower(hex(randomblob(16))));
"""
RUNTIME_CREDENTIAL_SCHEMA = """
CREATE TABLE runtime_credentials (
  digest TEXT PRIMARY KEY, source TEXT NOT NULL,
  allow_inspect INTEGER NOT NULL CHECK(allow_inspect IN (0,1)),
  allow_findings INTEGER NOT NULL CHECK(allow_findings IN (0,1)),
  FOREIGN KEY(digest) REFERENCES credentials(digest) ON DELETE CASCADE
);
"""
MIGRATIONS = (
    SCHEMA, ISSUE_SCHEMA, SOURCE_SCHEMA, OPERATIONS_SCHEMA,
    controls.SCHEMA, federation.SCHEMA, STREAM_SCHEMA, vertex.SCHEMA, RUNTIME_CREDENTIAL_SCHEMA,
    controls.RUNTIME_TARGET_SCHEMA, ai_bom.SCHEMA, runtime_policy.SCHEMA, runtime_policy.TOOL_SCHEMA,
    aws_inventory.SCHEMA, runtime_policy.MODEL_SCHEMA, access_reviews.SCHEMA, data_posture.SCHEMA,
    data_posture.CONTENT_SCHEMA, agent_registry.SCHEMA,
)
SCHEMA_VERSION = len(MIGRATIONS)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def database(path, write=False):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        if write:
            conn.execute("BEGIN IMMEDIATE")
        with conn:
            yield conn
    finally:
        conn.close()


@contextmanager
def service_guard(path):
    path = path.resolve()
    with path.with_suffix(path.suffix + ".service.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Problem(409, "Another DoofusAI service still owns this database.") from None
        yield


def initialize(path):
    with database(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    with database(path, write=True) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema {version} requires a newer DoofusAI SPM release.")
        for number, script in enumerate(MIGRATIONS, start=1):
            if number <= version:
                continue
            # executescript commits implicitly. Keep all schema and replay writes
            # under the same lock and rollback boundary instead.
            for statement in script.strip().rstrip(";").split(";"):
                conn.execute(statement)
            if number == 2:
                for scan in conn.execute("SELECT * FROM scans ORDER BY rowid"):
                    snapshot = json.loads(scan["snapshot"])
                    result = json.loads(scan["result"])
                    record_issues(conn, scan["project"], scan["asset"], snapshot["kind"], scan["id"],
                                  scan["created_at"], result["outcomes"], emit_audit=False)
            conn.execute(f"PRAGMA user_version={number}")


def identifier(value):
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise Problem(400, "Use 1–80 letters, numbers, spaces, periods, underscores, colons or hyphens.")
    return value


def object_fields(data, required):
    if not isinstance(data, dict) or data.keys() != set(required):
        raise Problem(400, "Expected fields: " + ", ".join(required))


GATEWAY_ROUTE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
GATEWAY_TOKEN_ENV = re.compile(r"DOOFUS_GATEWAY_TOKEN_[A-Z0-9_]{1,48}")


def load_gateway(path):
    settings = verification.parse_json(verification.read_limited(path, 32768))
    if not isinstance(settings, dict):
        raise Problem(400, "Use a JSON object for the chat gateway configuration.")

    required = ("project", "agent", "model_node", "origin", "model")

    def deployment(entry, token):
        if not isinstance(entry["origin"], str):
            raise Problem(400, "Invalid chat gateway origin.")
        return (identifier(entry["project"]), identifier(entry["agent"]), identifier(entry["model_node"]),
                model_behavior.ChatDeployment(entry["origin"], entry["model"], token))

    if "routes" not in settings:
        object_fields(settings, required)
        return {None: deployment(settings, os.environ.get("SPM_MODEL_TOKEN"))}
    object_fields(settings, ("routes",))
    entries = settings["routes"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise Problem(400, "Configure between one and 32 chat gateway routes.")
    routes = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise Problem(400, "Each chat gateway route must be an object.")
        optional = ("token_env",) if "token_env" in entry else ()
        object_fields(entry, (*required, "id", *optional))
        route = entry["id"]
        if not isinstance(route, str) or GATEWAY_ROUTE.fullmatch(route) is None or route in routes:
            raise Problem(400, "Use distinct lowercase chat gateway route IDs.")
        token = None
        if optional:
            env = entry["token_env"]
            if not isinstance(env, str) or GATEWAY_TOKEN_ENV.fullmatch(env) is None or not os.environ.get(env):
                raise Problem(400, "Supply the configured DOOFUS_GATEWAY_TOKEN_ credential.")
            token = os.environ[env]
        routes[route] = deployment(entry, token)
    return routes


def audit(conn, identity, action, resource, details=None):
    conn.execute(
        "INSERT INTO audit(project,principal,action,resource,details) VALUES(?,?,?,?,?)",
        (identity["project"], identity["principal"], action, resource,
         json.dumps(details) if details is not None else None),
    )


def issue(path, project, principal, role, expires_at=None, *, runtime=None, tool_agent=None,
          allow_tools=True, allow_models=False):
    identifier(project)
    identifier(principal)
    token = secrets.token_urlsafe(32)
    if expires_at is None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="milliseconds")
    with database(path, write=True) as conn:
        fingerprint = digest(token)
        conn.execute("INSERT INTO credentials(digest,principal,project,role,expires_at) VALUES(?,?,?,?,?)",
                     (fingerprint, principal, project, role, expires_at))
        if runtime is not None:
            if tool_agent and not runtime_policy.is_agent(conn, project, tool_agent):
                raise Problem(404, "Runtime credential must reference a known agent in this project.")
            conn.execute(
                """INSERT INTO runtime_credentials
                   (digest,source,allow_inspect,allow_findings,agent_node,allow_tools,allow_models)
                   VALUES(?,?,?,?,?,?,?)""",
                (fingerprint, *runtime, tool_agent, bool(tool_agent and allow_tools), bool(tool_agent and allow_models)),
            )
        audit(conn, {"project": project, "principal": "local-cli"},
              "credential.issued" if runtime is None else "credential.runtime.issued", principal)
    return token


def assess(kind, facts):
    outcomes = []
    for check, field, expected, remediation, penalty in CHECKS[kind]:
        actual = facts.get(field)
        if actual is None:
            status = "unknown"
        else:
            status = "pass" if actual == expected else "finding"
        outcomes.append({"check": check, "field": field, "expected": expected,
                         "observed": actual, "status": status, "remediation": remediation,
                         "penalty": penalty if status == "finding" else 0})
    complete = all(row["status"] != "unknown" for row in outcomes)
    return {"policy_version": 1, "coverage": "complete" if complete else "incomplete",
            "score": 100 - sum(row["penalty"] for row in outcomes) if complete else None,
            "outcomes": outcomes}


def record_issues(conn, project, asset, kind, scan, created_at, outcomes, *, emit_audit=True):
    """Project a persisted scan into issue state and append its observations."""
    for outcome in outcomes:
        check_id = outcome["check"]
        observation = outcome["status"]
        existing = conn.execute(
            "SELECT id,status FROM issues WHERE project=? AND asset=? AND kind=? AND check_id=?",
            (project, asset, kind, check_id),
        ).fetchone()
        if existing is None:
            if observation != "finding":
                continue
            issue_id = str(uuid4())
            conn.execute(
                """INSERT INTO issues(project,id,asset,kind,check_id,field,status,
                   first_scan,last_scan,last_outcome,updated_at)
                   VALUES(?,?,?,?,?,?,'open',?,?,?,?)""",
                (project, issue_id, asset, kind, check_id, outcome["field"],
                 scan, scan, observation, created_at),
            )
            action = "opened"
        else:
            issue_id, status = existing["id"], existing["status"]
            action = "unknown"
            if observation == "finding":
                action = "reopened" if status == "resolved" else "observed"
                status = "open"
            elif observation == "pass":
                action = "resolved" if status == "open" else "observed"
                status = "resolved"
            conn.execute(
                """UPDATE issues SET status=?,last_scan=?,last_outcome=?,updated_at=?
                   WHERE project=? AND id=?""",
                (status, scan, observation, created_at, project, issue_id),
            )
        conn.execute(
            "INSERT INTO issue_events(project,issue,scan,action,outcome,created_at) VALUES(?,?,?,?,?,?)",
            (project, issue_id, scan, action, observation, created_at),
        )
        if emit_audit and action in ("opened", "resolved", "reopened"):
            audit(conn, {"project": project, "principal": "assessment"}, "issue." + action,
                  issue_id, {"asset": asset, "scan": scan, "check": check_id})


def save_asset(conn, project, asset, kind, facts, evidence):
    conn.execute(
        """INSERT INTO assets(project,id,kind,facts,evidence) VALUES(?,?,?,?,?)
        ON CONFLICT(project,id) DO UPDATE SET kind=excluded.kind,
        facts=excluded.facts,evidence=excluded.evidence,updated_at=CURRENT_TIMESTAMP""",
        (project, asset, kind, json.dumps(facts), json.dumps(evidence)),
    )


def save_scan(conn, user, asset, snapshot):
    result = assess(snapshot["kind"], snapshot["facts"])
    scan = str(uuid4())
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO scans(project,id,asset,snapshot,result,created_at) VALUES(?,?,?,?,?,?)",
        (user["project"], scan, asset, json.dumps(snapshot), json.dumps(result), created_at),
    )
    record_issues(conn, user["project"], asset, snapshot["kind"], scan, created_at, result["outcomes"])
    audit(conn, user, "scan.completed", scan)
    return {"id": scan, "asset": asset, "snapshot": snapshot, "result": result}


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def import_bom(path, project, workload, raw, source=None):
    identifier(project)
    identifier(workload)
    if len(raw) > ai_bom.MAX_BOM_BYTES:
        raise Problem(400, "CycloneDX document exceeds the 2 MiB import limit.")
    document = ai_bom.normalize(raw)
    if source is not None:
        document["origin"] = source
    fingerprint = hashlib.sha256(raw).hexdigest()
    with database(path, write=True) as conn:
        previous = conn.execute(
            "SELECT id FROM bills_of_materials WHERE project=? AND workload=? AND digest=?",
            (project, workload, fingerprint),
        ).fetchone()
        if previous is not None:
            return {"id": previous["id"], "status": "already-imported"}
        target = conn.execute(
            """SELECT kind FROM graph_nodes WHERE project=? AND id=?
               UNION ALL SELECT kind FROM cloud_graph_nodes WHERE project=? AND id=? LIMIT 1""",
            (project, workload, project, workload),
        ).fetchone()
        if target is None or target["kind"] not in ("model", "endpoint", "agent", "virtual_machine"):
            raise Problem(404, "BOM target must be a model, endpoint, agent or VM in this project.")
        record = str(uuid4())
        components, relationships = len(document["components"]), len(document["relationships"])
        conn.execute(
            "INSERT INTO bills_of_materials VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, record, workload, fingerprint, document["spec_version"], json.dumps(document),
             components, relationships, "local-cli", timestamp()),
        )
        audit(conn, {"project": project, "principal": "local-cli"}, "bom.imported", record,
              {"workload": workload, "sha256": fingerprint, "components": components,
               "relationships": relationships})
        return {"id": record, "status": "imported", "components": components,
                "relationships": relationships}


def ensure_local_collector(conn, project, provider, scope):
    if conn.execute("""SELECT 1 FROM collection_agents WHERE project=? AND scope=?
                       AND provider=? AND revoked_at IS NULL""", (project, scope, provider)).fetchone():
        raise Problem(409, "Use the enrolled collection agent for this scope.")


def persist_gcs(conn, project, source_project, buckets, identity, run_id, started, finished):
    conn.execute(
        "UPDATE cloud_assets SET active=0 WHERE project=? AND provider='gcs' AND source_project=?",
        (project, source_project),
    )
    for bucket in buckets:
        # Full bucket name and canonical project number form the source identity.
        key = json.dumps([bucket["project_number"], bucket["name"]])
        asset = "gcs:" + digest(key)
        existing = conn.execute(
            """SELECT c.source_project FROM assets a LEFT JOIN cloud_assets c
               ON c.project=a.project AND c.asset=a.id WHERE a.project=? AND a.id=?""",
            (project, asset),
        ).fetchone()
        if existing is not None and existing["source_project"] != source_project:
            raise gcs.CollectionError("Bucket is already tracked under a different source project identifier.")
        evidence = {"recorded_at": finished, "recorded_by": identity["principal"],
                    "cloud_project_number": bucket["project_number"], "bucket": bucket["name"],
                    "metageneration": bucket["revision"], "sync_id": run_id}
        save_asset(conn, project, asset, "gcs-bucket", bucket["facts"], evidence)
        conn.execute(
            """INSERT INTO cloud_assets(project,asset,provider,source_project,name,active,last_seen)
               VALUES(?,?,'gcs',?,?,1,?) ON CONFLICT(project,asset)
               DO UPDATE SET active=1,last_seen=excluded.last_seen""",
            (project, asset, source_project, bucket["name"], finished),
        )
        save_scan(conn, identity, asset, {
            "kind": "gcs-bucket", "facts": bucket["facts"],
            "source": "google-cloud-storage", "evidence": evidence,
        })
    conn.execute(
        """INSERT INTO sync_runs VALUES(?,?,'gcs',?,?,?,'completed',?,NULL)""",
        (run_id, project, source_project, started, finished, len(buckets)),
    )
    audit(conn, identity, "connector.completed", run_id)
    return {"id": run_id, "assets": len(buckets), "status": "completed"}


def sync_gcs(path, project, source_project, quota_project=None, *, collect=gcs.discover):
    """Collect before taking the write lock, then reconcile a full inventory atomically."""
    identifier(project)
    gcs.project_id(source_project)
    identity = {"project": project, "principal": "gcs-connector"}
    run_id, started = str(uuid4()), timestamp()
    lock_path = path.resolve().with_suffix(path.suffix + ".gcs.lock")
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise gcs.CollectionError("Another Google Cloud sync is active for this database.") from None
        try:
            buckets = collect(source_project, quota_project)
            finished = timestamp()
            with database(path, write=True) as conn:
                ensure_local_collector(conn, project, "gcs", source_project)
                return persist_gcs(conn, project, source_project, buckets, identity, run_id, started, finished)
        except gcs.CollectionError as error:
            with database(path, write=True) as conn:
                ensure_local_collector(conn, project, "gcs", source_project)
                conn.execute(
                    """INSERT INTO sync_runs VALUES(?,?,'gcs',?,?,?,'failed',NULL,?)""",
                    (run_id, project, source_project, started, timestamp(), str(error)),
                )
                audit(conn, identity, "connector.failed", run_id)
            raise


def classify_cloud_object(path, project, node, key, **samplers):
    return classify_cloud_batch(path, project, node, [key], **samplers)[0]


def classify_cloud_batch(path, project, node, keys, *, sample_s3=content_scan.s3, sample_gcs=content_scan.gcs):
    if not isinstance(keys, list) or not keys:
        raise Problem(400, "Supply 1–32 distinct object keys.")
    return classify_cloud_selection(path, project, node, lambda *_: (keys, 0, False),
                                    sample_s3=sample_s3, sample_gcs=sample_gcs)["samples"]


def classify_cloud_selection(path, project, node, select, *, sample_s3=content_scan.s3, sample_gcs=content_scan.gcs):
    identifier(project)
    identifier(node)
    def lookup(conn):
        return conn.execute(
            """SELECT n.scope,n.resource,n.name,n.observed_at,
                      (SELECT provider FROM sync_runs s WHERE s.project=n.project AND s.source_project=n.scope
                       AND s.status='completed' ORDER BY rowid DESC LIMIT 1) AS owner_provider,
                      (SELECT json_extract(a.evidence,'$.cloud_project_number')
                       FROM assets a JOIN cloud_assets c ON c.project=a.project AND c.asset=a.id
                       WHERE c.project=n.project AND c.provider='gcs' AND c.active=1 AND c.name=n.name
                       AND c.source_project=substr(n.scope,1,instr(n.scope,':')-1)) AS gcs_project_number
               FROM cloud_graph_nodes n WHERE n.project=? AND n.id=? AND n.kind='data'""", (project, node),
        ).fetchone()

    with database(path) as conn:
        current = lookup(conn)
        if current is None:
            raise Problem(404, "Use an inventoried data node in this project.")
        match = content_scan.AWS_BUCKET.fullmatch(current["resource"])
        if current["owner_provider"] == "aws" and match:
            _, account, region = current["scope"].split(":")
            provider = "aws"
            target = (match[2], account, region)
        elif current["owner_provider"] == "vertex" and current["resource"] == "bucket:" + current["name"]:
            bucket = current["name"]
            number = current["gcs_project_number"]
            if not isinstance(number, str):
                raise Problem(409, "Sync the same Google Cloud project with sync-gcs to verify bucket ownership.")
            provider = "gcs"
            target = (bucket, number)
        else:
            raise Problem(400, "Object sampling supports discovered AWS S3 and Google Cloud Storage buckets.")
    keys, skipped, truncated = select(provider, target)
    if (not isinstance(keys, list) or len(keys) > 32
            or any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys)):
        raise Problem(400, "Supply 1–32 distinct object keys.")
    for key in keys:
        content_scan.object_key(key)

    sampler = sample_s3 if provider == "aws" else sample_gcs
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(sampler, *target, key) for key in keys]
        for index, future in enumerate(futures, 1):
            try:
                result = content_scan.classify(future.result())
            except gcs.CollectionError as error:
                raise gcs.CollectionError(f"Object {index} of {len(keys)}: {error}") from None
            results.append(result | {"provider": provider})
    with database(path, write=True) as conn:
        latest = lookup(conn)
        if latest is None or tuple(latest) != tuple(current):
            raise Problem(409, "Inventory changed during sampling. Retry against current inventory.")
        sampled_at = timestamp()
        conn.executemany(
            """INSERT INTO data_content_samples VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(project,scope,node,object_digest) DO UPDATE SET inventory_at=excluded.inventory_at,
               sampled_at=excluded.sampled_at,result=excluded.result""",
            [(project, current["scope"], node, digest(key), current["observed_at"], sampled_at, json.dumps(result))
             for key, result in zip(keys, results)],
        )
        audit(conn, {"project": project, "principal": "local-cli"}, "data.sampled", node,
              {"provider": provider, "samples": len(results), "skipped_objects": skipped,
               "listing_truncated": truncated, "levels": dict(Counter(result["sensitivity"] for result in results))})
    return {"samples": results, "skipped_objects": skipped, "listing_truncated": truncated}


def classify_prefix(path, project, node, prefix, limit=32, *, list_s3=content_scan.list_s3,
                    list_gcs=content_scan.list_gcs, **samplers):
    content_scan.object_key(prefix.removesuffix("/"))
    if not prefix.endswith("/") or not 1 <= limit <= 32:
        raise Problem(400, "Use a nonempty folder prefix ending in / and a limit from 1 to 32.")

    def select(provider, target):
        listing = list_s3 if provider == "aws" else list_gcs
        return listing(*target, prefix, limit)

    result = classify_cloud_selection(path, project, node, select, **samplers)
    samples = result.pop("samples")
    return result | {"classified": len(samples), "levels": dict(Counter(item["sensitivity"] for item in samples))}


def review_gcs_access(path, project, asset, permissions, quota_project=None, *, evaluate=gcs_access.evaluate):
    identifier(project)
    identifier(asset)

    def bucket(conn):
        return conn.execute(
            """SELECT c.name,c.source_project,c.last_seen,a.evidence FROM cloud_assets c
               JOIN assets a ON a.project=c.project AND a.id=c.asset
               WHERE c.project=? AND c.asset=? AND c.provider='gcs' AND c.active=1""",
            (project, asset),
        ).fetchone()

    with database(path) as conn:
        current = bucket(conn)
        if current is None:
            raise Problem(404, "Use an active Cloud Storage bucket in this project.")
    provenance = json.loads(current["evidence"] or "{}")
    principal, decisions = evaluate(current["name"], provenance.get("cloud_project_number"),
                                    permissions, quota_project)
    review_id = str(uuid4())
    with database(path, write=True) as conn:
        latest = bucket(conn)
        if latest is None or tuple(latest) != tuple(current):
            raise Problem(409, "Bucket inventory changed during review. Run it again.")
        conn.execute(
            "INSERT INTO access_reviews VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, review_id, asset, current["source_project"], "gcs", principal,
             "gs://" + current["name"], current["last_seen"], timestamp(), json.dumps(decisions)),
        )
        audit(conn, {"project": project, "principal": "local-cli"}, "gcs.access.reviewed", asset,
              {"review": review_id, "decisions": len(decisions)})
    return {"id": review_id, "asset": asset, "decisions": len(decisions)}


def sync_vertex(path, project, cloud_project, region, quota=None, profile_location=None,
                *, collect=vertex.discover):
    gcs.project_id(cloud_project)
    vertex.checked_location(region)
    return sync_cloud_graph(path, project, "vertex", f"{cloud_project}:{region}",
                            lambda: collect(cloud_project, region, quota, profile_location))


def sync_aws(path, project, account, region, analyzer=None, *, collect=aws_inventory.discover):
    aws_inventory.parameters(account, region)
    return sync_cloud_graph(path, project, "aws", f"aws:{account}:{region}",
                            lambda: collect(account, region, analyzer), analyzer=analyzer)


def review_aws_access(path, project, asset, resource, actions, *, evaluate=iam_review.evaluate):
    identifier(project)
    identifier(asset)

    def subject(conn):
        return conn.execute(
            """SELECT n.scope,n.resource,n.observed_at FROM cloud_graph_nodes n
               JOIN cloud_assets a ON a.project=n.project AND a.asset=n.id AND a.source_project=n.scope
               WHERE n.project=? AND n.id=? AND n.kind='identity' AND a.provider='aws' AND a.active=1""",
            (project, asset),
        ).fetchone()

    def validate_bucket(conn, scope, bucket):
        if bucket and conn.execute(
            "SELECT 1 FROM cloud_graph_nodes WHERE project=? AND scope=? AND kind='data' AND resource=?",
            (project, scope, bucket),
        ).fetchone() is None:
            raise Problem(400, "The S3 target bucket must be inventoried in this AWS scope.")

    with database(path) as conn:
        conn.execute("BEGIN")
        current = subject(conn)
        if current is None:
            raise Problem(404, "Use an active AWS role asset in this project.")
        principal, scope = current["resource"], current["scope"]
        account, bucket = iam_review.request_scope(principal, resource, actions)
        provider, expected_account, region = scope.split(":")
        if provider != "aws" or account != expected_account:
            raise Problem(409, "AWS role scope is inconsistent. Rerun inventory.")
        validate_bucket(conn, scope, bucket)
    decisions = evaluate(region, principal, resource, actions)
    review_id = str(uuid4())
    with database(path, write=True) as conn:
        latest = subject(conn)
        if latest is None or tuple(latest) != tuple(current):
            raise Problem(409, "AWS role inventory changed during review. Run it again.")
        validate_bucket(conn, scope, bucket)
        conn.execute(
            "INSERT INTO access_reviews VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, review_id, asset, scope, "aws", principal, resource, current["observed_at"],
             timestamp(), json.dumps(decisions)),
        )
        audit(conn, {"project": project, "principal": "local-cli"}, "aws.access.reviewed", asset,
              {"review": review_id, "decisions": len(decisions)})
    return {"id": review_id, "asset": asset, "decisions": len(decisions)}


def review_aws_workload_access(path, project, workload, *, review=review_aws_access):
    identifier(project)
    identifier(workload)
    with database(path) as conn:
        source = conn.execute(
            """SELECT scope,kind FROM cloud_graph_nodes WHERE project=? AND id=?
               AND kind IN ('model','endpoint') AND scope LIKE 'aws:%'""", (project, workload),
        ).fetchone()
        if source is None:
            raise Problem(404, "Use a discovered AWS model or endpoint in this project.")
        scope = source["scope"]
        pairings = conn.execute(
            """WITH models(id) AS (
                SELECT ? WHERE ?='model'
                UNION
                SELECT target FROM cloud_graph_edges WHERE project=? AND scope=? AND origin=?
                  AND relation='serves'
            )
            SELECT DISTINCT r.target AS role,d.resource AS bucket
            FROM models m JOIN cloud_graph_edges r ON r.origin=m.id AND r.project=? AND r.scope=?
              AND r.relation='uses_identity'
            JOIN cloud_graph_edges b ON b.origin=m.id AND b.project=r.project AND b.scope=r.scope
              AND b.relation='stores_artifacts'
            JOIN cloud_graph_nodes d ON d.project=b.project AND d.scope=b.scope AND d.id=b.target AND d.kind='data'
            JOIN cloud_assets a ON a.project=r.project AND a.asset=r.target
              AND a.provider='aws' AND a.source_project=r.scope AND a.active=1
            ORDER BY r.target,d.resource LIMIT 13""",
            (workload, source["kind"], project, scope, workload, project, scope),
        ).fetchall()
    if len(pairings) > 12:
        raise Problem(400, "Workload has more than 12 discovered role and bucket pairs. Review each model separately.")
    return {"workload": workload, "reviews": [
        review(path, project, row["role"], row["bucket"], ["s3:ListBucket"]) for row in pairings
    ]}


def sync_azure(path, project, subscription, group, workspace, rbac=False, foundry=None,
               *, collect=azure_inventory.discover):
    scope = azure_inventory.scope_key(subscription, group, workspace)
    return sync_cloud_graph(path, project, "azure", scope,
                            lambda: collect(subscription, group, workspace, rbac, foundry))


def sync_vsphere(path, project, host, port=443, ca_file=None, *, collect=vsphere_inventory.discover):
    scope = vsphere_inventory.scope_key(host, port)
    return sync_cloud_graph(path, project, "vsphere", scope, lambda: collect(host, port, ca_file))


def review_vsphere_access(path, project, asset, principal, privileges, ca_file=None,
                          *, evaluate=vsphere_inventory.evaluate_privileges):
    identifier(project)
    identifier(asset)
    vsphere_inventory.validate_review_inputs(principal, privileges)

    def subject(conn):
        return conn.execute(
            """SELECT n.scope,n.resource,n.observed_at FROM cloud_graph_nodes n
               JOIN cloud_assets a ON a.project=n.project AND a.asset=n.id AND a.source_project=n.scope
               WHERE n.project=? AND n.id=? AND n.kind IN ('host','virtual_machine')
               AND a.provider='vsphere' AND a.active=1""", (project, asset),
        ).fetchone()

    with database(path) as conn:
        current = subject(conn)
        if current is None:
            raise Problem(404, "Use an active vSphere host or VM asset in this project.")
        scope, resource = current["scope"], current["resource"]
    provider, host, port = scope.split(":")
    if provider != "vsphere":
        raise Problem(409, "vSphere inventory scope is inconsistent. Rerun inventory.")
    decisions = evaluate(host, int(port), resource, principal, privileges, ca_file)
    review_id = str(uuid4())
    with database(path, write=True) as conn:
        latest = subject(conn)
        if latest is None or tuple(latest) != tuple(current):
            raise Problem(409, "vSphere inventory changed during review. Run it again.")
        conn.execute(
            "INSERT INTO access_reviews VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, review_id, asset, scope, "vsphere", principal, resource, current["observed_at"],
             timestamp(), json.dumps(decisions)),
        )
        audit(conn, {"project": project, "principal": "local-cli"}, "vsphere.access.reviewed", asset,
              {"review": review_id, "decisions": len(decisions)})
    return {"id": review_id, "asset": asset, "decisions": len(decisions)}


def graph_assessment(provider, node):
    exposure = node.get("exposure")
    if provider == "vertex" and node["kind"] == "endpoint":
        facts = {} if exposure == "unknown" else {
            "private_network_configured": exposure == "private_configuration",
        }
        return "vertex-endpoint", "google-vertex-ai", facts
    if provider == "aws" and node["kind"] == "identity":
        facts = {}
        if exposure in ("analyzer_external_access", "analyzer_resolved"):
            facts["external_access_reported"] = exposure == "analyzer_external_access"
        return "aws-role", "aws-access-analyzer", facts
    if provider == "azure" and node["kind"] == "endpoint":
        facts = {} if exposure is None else {"public_network_disabled": exposure == "private_configuration"}
        return "azure-endpoint", "azure-arm", facts
    if provider == "azure" and node["kind"] == "identity":
        facts = {} if exposure is None else {"privileged_role_reported": exposure == "azure_privileged_role"}
        return "azure-identity", "azure-rbac", facts
    if provider in ("oci", "ibm") and node["kind"] == "endpoint":
        source = {"oci": "oci-data-science", "ibm": "ibm-watsonx"}[provider]
        return provider + "-endpoint", source, node["facts"]
    if provider == "vsphere" and node["kind"] in ("host", "virtual_machine"):
        kind = "vsphere-host" if node["kind"] == "host" else "vsphere-vm"
        return kind, "vsphere-property-collector", node["facts"]
    return None


def persist_cloud_graph(conn, project, provider, scope, nodes, edges, identity, run_id, started, finished, analyzer=None):
    node_ids = {key: provider + ":" + digest(scope + "/" + key) for key in nodes}
    if provider == "aws":
        pinned = conn.execute("SELECT arn FROM aws_scope_analyzers WHERE project=? AND scope=?",
                              (project, scope)).fetchone()
        if pinned and analyzer != pinned["arn"]:
            raise gcs.CollectionError("Use the Access Analyzer already pinned to this scope.")
        if analyzer and not pinned:
            conn.execute("INSERT INTO aws_scope_analyzers VALUES(?,?,?)", (project, scope, analyzer))
    conn.execute("DELETE FROM cloud_graph_edges WHERE project=? AND scope=?", (project, scope))
    conn.execute("DELETE FROM cloud_graph_nodes WHERE project=? AND scope=?", (project, scope))
    conn.execute("UPDATE cloud_assets SET active=0 WHERE project=? AND provider=? AND source_project=?",
                 (project, provider, scope))
    for key, node in nodes.items():
        asset = node_ids[key]
        conn.execute(
            "INSERT INTO cloud_graph_nodes VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, scope, asset, node["kind"], node["name"], key, node.get("exposure"),
             node.get("sensitivity"), node.get("profile_observed"), finished),
        )
        assessment = graph_assessment(provider, node)
        if assessment is None:
            continue
        kind, source, facts = assessment
        existing = conn.execute(
            """SELECT c.provider FROM assets a LEFT JOIN cloud_assets c
               ON c.project=a.project AND c.asset=a.id WHERE a.project=? AND a.id=?""",
            (project, asset),
        ).fetchone()
        if existing is not None and existing["provider"] != provider:
            raise gcs.CollectionError("Discovered resource conflicts with an existing asset.")
        evidence = {"recorded_at": finished, "recorded_by": identity["principal"],
                    "cloud_resource": key, "name": node["name"], "sync_id": run_id}
        if analyzer:
            evidence["analyzer"] = analyzer
        save_asset(conn, project, asset, kind, facts, evidence)
        conn.execute(
            """INSERT INTO cloud_assets VALUES(?,?,?,?,?,1,?)
               ON CONFLICT(project,asset) DO UPDATE SET active=1,last_seen=excluded.last_seen,
               name=excluded.name""", (project, asset, provider, scope, node["name"], finished),
        )
        save_scan(conn, identity, asset, {"kind": kind, "facts": facts,
                                         "source": source, "evidence": evidence})
    conn.executemany(
        "INSERT INTO cloud_graph_edges VALUES(?,?,?,?,?)",
        [(project, scope, node_ids[a], node_ids[b], relation) for a, b, relation in edges],
    )
    conn.execute(
        "INSERT INTO sync_runs VALUES(?,?,?,?,?,?,'completed',?,NULL)",
        (run_id, project, provider, scope, started, finished, len(nodes)),
    )
    audit(conn, identity, "connector.completed", run_id)
    return {"id": run_id, "nodes": len(nodes), "relationships": len(edges), "status": "completed"}


def sync_cloud_graph(path, project, provider, scope, collect, *, analyzer=None):
    identifier(project)
    identity = {"project": project, "principal": provider + "-connector"}
    run_id, started = str(uuid4()), timestamp()
    lock_path = path.resolve().with_suffix(path.suffix + ".gcs.lock")
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise gcs.CollectionError("Another cloud sync is active for this database.") from None
        try:
            nodes, edges = collect()
            finished = timestamp()
            with database(path, write=True) as conn:
                ensure_local_collector(conn, project, provider, scope)
                return persist_cloud_graph(conn, project, provider, scope, nodes, edges, identity, run_id, started, finished, analyzer)
        except gcs.CollectionError as error:
            with database(path, write=True) as conn:
                conn.execute(
                    "INSERT INTO sync_runs VALUES(?,?,?,?,?,?,'failed',NULL,?)",
                    (run_id, project, provider, scope, started, timestamp(), str(error)),
                )
                audit(conn, identity, "connector.failed", run_id)
            raise


def reconcile_agent_report(conn, agent, job, status, snapshot, finished):
    project, provider, scope = (agent[key] for key in ("project", "provider", "scope"))
    identity = {"project": project, "principal": "agent:" + agent["id"]}
    run_id, started = job["id"], job["created_at"]
    if status == "failed":
        message = "Remote collector could not complete the snapshot."
        conn.execute("INSERT INTO sync_runs VALUES(?,?,?,?,?,?,'failed',NULL,?)",
                     (run_id, project, provider, scope, started, finished, message))
        audit(conn, identity, "connector.failed", run_id)
        return {"id": run_id, "status": "failed"}
    data = agent_protocol.validate_snapshot(provider, snapshot, graph_assessment, CHECKS)
    if provider == "gcs":
        if scope.isdecimal() and any(bucket["project_number"] != scope for bucket in data):
            raise Problem(400, "The reported GCS project did not match the enrolled scope.")
        try:
            return persist_gcs(conn, project, scope, data, identity, run_id, started, finished)
        except gcs.CollectionError as error:
            raise Problem(409, str(error)) from None
    arguments = json.loads(agent["arguments"])
    analyzer = arguments[2] if provider == "aws" and len(arguments) == 3 else None
    try:
        return persist_cloud_graph(conn, project, provider, scope, *data, identity, run_id, started,
                                   finished, analyzer)
    except gcs.CollectionError as error:
        raise Problem(409, str(error)) from None


class Product:
    def __init__(self, path, issuer=None, chat_gateway=None, relay=None):
        self.path = path
        self.boot_id = uuid4().hex
        node = os.environ.get("SPM_NODE_NAME", "")
        self.node = node if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", node) else None
        self.chat_gateway = chat_gateway
        self.relay = relay
        self.issuer = issuer
        self.device = device_login.DeviceLogin(issuer) if issuer and issuer.device_config is not None else None
        initialize(path)

    def device_request(self, route, method, origin, body=None):
        if route == "/auth/device" and method == "GET":
            return 200, {"enabled": self.device is not None}
        if self.device is None or method != "POST":
            raise Problem(404, "Sign-in route unavailable.")
        if origin != self.device.config["origin"]:
            raise Problem(403, "Sign in from the configured application origin.")
        if route == "/auth/device/start":
            object_fields(body, ())
            return 200, self.device.start()
        if route in ("/auth/device/poll", "/auth/device/cancel"):
            object_fields(body, ("session",))
            session = body["session"]
            if not isinstance(session, str) or device_login.SESSION.fullmatch(session) is None:
                raise Problem(400, "Invalid sign-in attempt.")
            if route.endswith("/cancel"):
                return 200, self.device.cancel(session)
            result = self.device.poll(session)
            if result["status"] == "approved":
                token = result["access_token"]
                if token.count(".") != 2:
                    raise Problem(401, "Identity provider did not issue a federated access token.")
                self.request("GET", "/api/v1/me", token)
            return 200, result
        raise Problem(404, "Sign-in route unavailable.")

    def gateway_chat(self, token, body):
        if self.chat_gateway is None:
            raise Problem(404, "Chat gateway unavailable.")
        explicit = isinstance(body, dict) and "route" in body
        streamed = isinstance(body, dict) and "upstream_stream" in body
        fields = ("route", "text") if explicit else ("text",)
        object_fields(body, (*fields, "upstream_stream") if streamed else fields)
        stream = body.get("upstream_stream", False)
        if type(stream) is not bool:
            raise Problem(400, "upstream_stream must be a Boolean.")
        selected = body.get("route")
        if explicit and (not isinstance(selected, str) or GATEWAY_ROUTE.fullmatch(selected) is None):
            raise Problem(400, "Supply a valid chat gateway route ID.")
        if not explicit and None not in self.chat_gateway:
            raise Problem(400, "A chat gateway route ID is required.")
        gateway = self.chat_gateway.get(selected)
        rejected = "Use an active model credential for the configured route."
        if gateway is None:
            raise Problem(403, rejected)
        project, agent, model, deployment = gateway
        text = body["text"]
        if not isinstance(text, str) or not text.strip() or len(text) > 6000:
            raise Problem(400, "Supply chat text of 1–6000 characters.")

        def authorize_and_screen(content):
            with database(self.path) as conn:
                conn.execute("BEGIN")
                credential = conn.execute(
                    """SELECT 1 FROM credentials c JOIN runtime_credentials r USING(digest)
                       WHERE c.digest=? AND c.project=? AND c.role='operator' AND c.expires_at>? AND r.agent_node=? AND r.allow_models=1""",
                    (digest(token), project, timestamp(), agent),
                ).fetchone()
                if credential is None:
                    raise Problem(403, rejected)
                if runtime_policy.authorize_model(conn, project, agent, model) != {"decision": "allow"}:
                    raise Problem(403, "Agent model invocation was not authorized.")
                result = runtime_policy.inspect({"text": content, "action": "block"}, object_fields, "block")
                if result["decision"] != "allow":
                    raise Problem(403, "Content blocked by gateway policy.")

        authorize_and_screen(text)
        try:
            reply = deployment.answer(text, stream=True) if stream else deployment.answer(text)
        except model_behavior.ChatError:
            raise Problem(502, "The configured model did not return an eligible response.") from None
        authorize_and_screen(reply)
        return 200, {"text": reply}

    def relay_json(self, token, body):
        if self.relay is None:
            raise Problem(404, "JSON relay unavailable.")
        project, relay = self.relay

        def check(payload):
            with database(self.path) as conn:
                allowed = conn.execute(
                    """SELECT 1 FROM runtime_credentials r JOIN credentials c USING(digest)
                       WHERE c.digest=? AND c.project=? AND c.role='operator' AND c.expires_at>?
                       AND r.allow_inspect=1""", (digest(token), project, timestamp()),
                ).fetchone()
            if allowed is None:
                raise Problem(403, "Use an active inspection credential for the relay project.")
            if runtime_policy.inspect_document(payload)["decision"] != "allow":
                raise Problem(403, "Relay content blocked by policy.")

        check(body)
        response = relay.forward(body)
        if not isinstance(response, (dict, list)):
            raise Problem(502, "Relay upstream did not return a JSON object or array.")
        check(response)
        return 200, response

    def request(self, method, route, token, body=None):
        url = urlsplit(route)
        route = url.path
        if route == "/api/v1/runtime/relay" and method == "POST":
            if url.query:
                raise Problem(400, "The JSON relay does not accept a query string.")
            return self.relay_json(token, body)
        if route == "/api/v1/runtime/chat" and method == "POST":
            return self.gateway_chat(token, body)
        if route in ("/api/v1/agent/poll", "/api/v1/agent/report") and method == "POST":
            with database(self.path, write=True) as conn:
                agent = agent_registry.authenticate(conn, token, timestamp)
                if route.endswith("/poll"):
                    object_fields(body, ())
                    return 200, agent_registry.poll(conn, agent, timestamp, reconcile_agent_report)
                return 200, agent_registry.report(conn, agent, body, object_fields, timestamp,
                                                  reconcile_agent_report)
        subject = None
        if self.issuer is not None and "." in token:
            subject = self.issuer.verify(token)
        read_only = method == "GET" or (method == "POST" and route in (
            "/api/v1/runtime/inspect", "/api/v1/runtime/inspect-document", "/api/v1/runtime/authorize-tool", "/api/v1/runtime/authorize-model",
        ))
        with database(self.path, write=not read_only) as conn:
            if read_only:
                conn.execute("BEGIN")
            if subject is None:
                user = conn.execute(
                    """SELECT c.*,r.source AS runtime_source,r.allow_inspect,r.allow_findings,r.agent_node,
                       r.allow_tools,r.allow_models
                       FROM credentials c LEFT JOIN runtime_credentials r USING(digest)
                       WHERE c.digest=? AND (c.expires_at IS NULL OR c.expires_at>?)""",
                    (digest(token), timestamp()),
                ).fetchone()
            else:
                user = conn.execute(
                    """SELECT principal,project,role,NULL AS expires_at,NULL AS runtime_source
                       FROM federated_users
                       WHERE issuer=? AND subject=?""", (self.issuer.issuer, subject)
                ).fetchone()
            if user is None:
                raise Problem(401, "Supply a valid bearer token.")
            project = user["project"]
            if user["runtime_source"] is not None:
                inspect = route in ("/api/v1/runtime/inspect", "/api/v1/runtime/inspect-document") and user["allow_inspect"]
                findings = route == "/api/v1/runtime-findings" and user["allow_findings"]
                tool_check = route == "/api/v1/runtime/authorize-tool" and user["allow_tools"]
                model_check = route == "/api/v1/runtime/authorize-model" and user["allow_models"]
                if method != "POST" or not (inspect or findings or tool_check or model_check):
                    raise Problem(403, "Credential is restricted to runtime operations.")
                if findings and isinstance(body, dict) and body.get("source") != user["runtime_source"]:
                    raise Problem(403, "Credential is bound to another runtime event source.")
                if (tool_check or model_check) and isinstance(body, dict) and body.get("agent") != user["agent_node"]:
                    raise Problem(403, "Credential is bound to another agent.")
            if method != "GET" and user["role"] == "viewer":
                raise Problem(403, "This credential is read-only.")
            if route == "/api/v1/agents" or route.startswith("/api/v1/agents/"):
                controls.protect_admin(user)
                if route == "/api/v1/agents/package" and method == "GET":
                    return 200, agent_registry.package()
                return agent_registry.manage(conn, user, method, route, body, object_fields, timestamp, audit)
            if route == "/api/v1/me" and method == "GET":
                result = {k: user[k] for k in ("principal", "project", "role")}
                if user["expires_at"] is not None:
                    result["expires_at"] = user["expires_at"]
                return 200, result
            if route == "/api/v1/assets" and method in ("GET", "POST"):
                if method == "GET":
                    after = parse_qs(url.query, keep_blank_values=True).get("after", [""])
                    if len(after) != 1 or (after[0] and NAME.fullmatch(after[0]) is None):
                        raise Problem(400, "Invalid inventory cursor.")
                    rows = conn.execute(
                        """SELECT a.project,a.id,a.kind,a.facts,a.updated_at,
                           c.provider,c.name,c.active,c.last_seen,c.source_project
                           FROM assets a LEFT JOIN cloud_assets c ON c.project=a.project AND c.asset=a.id
                           WHERE a.project=? AND a.id>? ORDER BY a.id LIMIT 501""",
                        (project, after[0]),
                    )
                    assets = []
                    for row in rows:
                        asset = {key: row[key] for key in ("project", "id", "kind", "updated_at")}
                        asset["facts"] = json.loads(row["facts"])
                        if row["provider"] is not None:
                            asset["source"] = {key: row[key] for key in
                                               ("provider", "name", "last_seen", "source_project")}
                            asset["source"]["active"] = bool(row["active"])
                        assets.append(asset)
                    response = {"assets": assets[:500]}
                    if len(assets) == 501:
                        response["next_after"] = assets[499]["id"]
                    return 200, response
                object_fields(body, ("id", "kind", "facts"))
                asset = identifier(body["id"])
                kind, facts = body["kind"], body["facts"]
                if not isinstance(kind, str) or kind not in ("storage", "registry", "agent"):
                    raise Problem(400, "Unsupported asset kind.")
                if asset.startswith(("gcs:", "vertex:", "aws:", "azure:", "vsphere:", "oci:", "ibm:", "salesforce:")):
                    tracked = conn.execute(
                        """SELECT a.id FROM assets a LEFT JOIN cloud_assets c
                           ON c.project=a.project AND c.asset=a.id
                           WHERE a.project=? AND a.id=? AND c.asset IS NULL""",
                        (project, asset),
                    ).fetchone()
                    if tracked is None:
                        raise Problem(409, "This asset identifier is reserved for the cloud connector.")
                if not isinstance(facts, dict) or any(
                    key not in {check[1] for check in CHECKS[kind]} or type(value) is not bool
                    for key, value in facts.items()
                ):
                    raise Problem(400, "Facts must be supported boolean fields for the asset kind.")
                evidence = {"recorded_by": user["principal"], "recorded_at": timestamp()}
                save_asset(conn, project, asset, kind, facts, evidence)
                audit(conn, user, "asset.saved", asset)
                return 200, {"id": asset, "kind": kind, "facts": facts}
            if route == "/api/v1/scans" and method in ("GET", "POST"):
                if method == "GET":
                    rows = conn.execute(
                        """SELECT s.id,s.asset,s.created_at,s.result,c.name AS bucket_name
                           FROM scans s LEFT JOIN cloud_assets c ON c.project=s.project AND c.asset=s.asset
                           WHERE s.project=? ORDER BY s.rowid DESC LIMIT 100""",
                        (project,))
                    return 200, {"scans": [dict(row) | {"result": json.loads(row["result"])} for row in rows]}
                object_fields(body, ("asset",))
                asset = identifier(body["asset"])
                row = conn.execute("SELECT kind,facts,evidence FROM assets WHERE project=? AND id=?",
                                   (project, asset)).fetchone()
                if row is None:
                    raise Problem(404, "Asset not found.")
                if row["kind"] not in ("storage", "registry", "agent"):
                    raise Problem(409, "Run the owning cloud connector to reassess this asset with fresh facts.")
                snapshot = {"kind": row["kind"], "facts": json.loads(row["facts"]),
                            "source": "operator-declared"}
                if row["evidence"] is not None:
                    snapshot["evidence"] = json.loads(row["evidence"])
                return 201, save_scan(conn, user, asset, snapshot)
            if route == "/api/v1/sync-runs" and method == "GET":
                rows = conn.execute(
                    "SELECT * FROM sync_runs WHERE project=? ORDER BY rowid DESC LIMIT 100", (project,)
                )
                return 200, {"runs": [dict(row) for row in rows]}
            if route == "/api/v1/cloud-graph" and method == "GET":
                scopes = [row["scope"] for row in conn.execute(
                    "SELECT DISTINCT scope FROM cloud_graph_nodes WHERE project=? ORDER BY scope", (project,)
                )]
                selected = parse_qs(url.query).get("scope", scopes[:1])
                if not selected:
                    return 200, {"scopes": [], "scope": None, "nodes": [], "edges": []}
                if len(selected) != 1 or selected[0] not in scopes:
                    raise Problem(404, "Discovered inventory scope not found.")
                return 200, {"scopes": scopes, "scope": selected[0], **{
                    key: [dict(row) for row in conn.execute(
                        f"SELECT * FROM cloud_graph_{key} WHERE project=? AND scope=? ORDER BY rowid",
                        (project, selected[0]),
                    )] for key in ("nodes", "edges")
                }}
            if route == "/api/v1/boms" and method == "GET":
                filters = parse_qs(url.query, keep_blank_values=True).get("workload", [])
                if len(filters) > 1:
                    raise Problem(400, "Supply at most one workload filter.")
                workload = identifier(filters[0]) if filters else None
                columns = "id,workload,digest,spec_version,total_components,total_dependencies,imported_by,imported_at"
                where = " AND workload=?" if workload is not None else ""
                values = (project, workload) if workload is not None else (project,)
                rows = conn.execute(
                    f"SELECT {columns} FROM bills_of_materials WHERE project=?{where} ORDER BY rowid DESC LIMIT 100",
                    values,
                )
                return 200, {"boms": [dict(row) for row in rows]}
            if route.startswith("/api/v1/boms/") and method == "GET":
                row = conn.execute("SELECT * FROM bills_of_materials WHERE project=? AND id=?",
                                   (project, route.removeprefix("/api/v1/boms/"))).fetchone()
                if row is None:
                    raise Problem(404, "Bill of materials not found.")
                return 200, dict(row) | {"document": json.loads(row["document"])}
            if route == "/api/v1/data-posture" and method in ("GET", "POST"):
                controls.protect_admin(user)
                if method == "GET":
                    cursor = parse_qs(url.query, keep_blank_values=True).get("after", [""])
                    if len(cursor) != 1:
                        raise Problem(400, "Supply one data posture cursor.")
                    return 200, data_posture.report(conn, project, identifier(cursor[0]) if cursor[0] else "")
                result = data_posture.record(conn, user, body, object_fields, identifier, timestamp)
                audit(conn, user, "data.classified", result["node"], {"sensitivity": result["sensitivity"]})
                return 200, result
            if route == "/api/v1/access-reviews" and method == "GET":
                controls.protect_admin(user)
                filters = parse_qs(url.query, keep_blank_values=True).get("asset", [])
                if len(filters) > 1:
                    raise Problem(400, "Supply at most one asset filter.")
                fields = "id,asset,scope,provider,principal,resource,inventory_observed_at,evaluated_at"
                where = " AND asset=?" if filters else ""
                values = (project, identifier(filters[0])) if filters else (project,)
                rows = conn.execute(
                    f"SELECT {fields} FROM access_reviews WHERE project=?{where} ORDER BY rowid DESC LIMIT 100",
                    values,
                )
                return 200, {"reviews": [dict(row) for row in rows]}
            if route.startswith("/api/v1/access-reviews/") and method == "GET":
                controls.protect_admin(user)
                review_id = route.removeprefix("/api/v1/access-reviews/")
                if review_id.endswith("/compare"):
                    baselines = parse_qs(url.query, keep_blank_values=True).get("baseline", [])
                    if len(baselines) != 1:
                        raise Problem(400, "Supply one baseline review ID.")
                    review = access_reviews.load(conn, project, review_id.removesuffix("/compare"))
                    return 200, access_reviews.compare(conn, review, identifier(baselines[0]))
                return 200, access_reviews.detail(conn, access_reviews.load(conn, project, review_id))
            if route.startswith("/api/v1/scans/") and method == "GET":
                scan = route.removeprefix("/api/v1/scans/")
                row = conn.execute("SELECT * FROM scans WHERE project=? AND id=?",
                                   (project, scan)).fetchone()
                if row is None:
                    raise Problem(404, "Scan not found.")
                return 200, dict(row) | {key: json.loads(row[key]) for key in ("snapshot", "result")}
            if route == "/api/v1/issues" and method == "GET":
                status = parse_qs(url.query, keep_blank_values=True).get("status", ["open"])
                if status not in (["open"], ["resolved"]):
                    raise Problem(400, "Issue status must be open or resolved.")
                rows = conn.execute(
                    """SELECT i.*,c.name AS bucket_name,c.active AS source_active
                       FROM issues i LEFT JOIN cloud_assets c ON c.project=i.project AND c.asset=i.asset
                       WHERE i.project=? AND i.status=?""",
                    (project, status[0]),
                )
                return 200, {"issues": controls.prioritize(conn, project, rows, CHECKS)[:100]}
            if route in ("/api/v1/graph/nodes", "/api/v1/graph/edges") and (
                method in ("GET", "POST") or (method == "DELETE" and route.endswith("/edges"))
            ):
                status, result = controls.graph_route(conn, project, route, method, body,
                                                      object_fields, identifier)
                if method != "GET":
                    audit(conn, user, "graph.removed" if method == "DELETE" else "graph.saved",
                          result.get("id", result.get("origin")), result)
                return status, result
            if route == "/api/v1/runtime-findings" and method in ("GET", "POST"):
                status, result = controls.runtime_route(conn, user, method, body, object_fields, identifier)
                if status == 201:
                    audit(conn, user, "runtime.received", str(result["sequence"]), body)
                return status, result
            if route == "/api/v1/runtime/inspect-document" and method == "POST":
                object_fields(body, ("document",))
                result = runtime_policy.inspect_document(body["document"])
                return (403 if result["decision"] == "block" else 200), result
            if route == "/api/v1/runtime/inspect" and method == "POST":
                current = conn.execute("SELECT minimum_action FROM project_runtime_policies WHERE project=?",
                                       (project,)).fetchone()
                floor = current["minimum_action"] if current else "redact"
                return 200, runtime_policy.inspect(body, object_fields, floor)
            if route == "/api/v1/runtime/authorize-tool" and method == "POST":
                coordinates = runtime_policy.tool_coordinates(body, object_fields, identifier)
                decision = runtime_policy.authorize_tool(conn, project, coordinates)
                return 200, decision
            if route == "/api/v1/runtime/authorize-model" and method == "POST":
                object_fields(body, ("agent", "model"))
                return 200, runtime_policy.authorize_model(conn, project, identifier(body["agent"]),
                                                           identifier(body["model"]))
            if route == "/api/v1/agent-model-rules" and method in ("GET", "POST", "DELETE"):
                controls.protect_admin(user)
                if method == "GET":
                    rows = conn.execute(
                        "SELECT * FROM agent_model_rules WHERE project=? ORDER BY agent,model LIMIT 500", (project,)
                    )
                    return 200, {"rules": [dict(row) for row in rows]}
                object_fields(body, ("agent", "model"))
                agent, model = identifier(body["agent"]), identifier(body["model"])
                if method == "POST":
                    if not runtime_policy.is_agent(conn, project, agent) or not runtime_policy.known_node(
                        conn, project, model, "model"
                    ):
                        raise Problem(404, "Use a model and agent present in this project.")
                    conn.execute(
                        """INSERT INTO agent_model_rules VALUES(?,?,?,?,?)
                           ON CONFLICT(project,agent,model)
                           DO UPDATE SET updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                        (project, agent, model, user["principal"], timestamp()),
                    )
                    action = "agent.model.allowed"
                else:
                    conn.execute("DELETE FROM agent_model_rules WHERE project=? AND agent=? AND model=?",
                                 (project, agent, model))
                    action = "agent.model.revoked"
                audit(conn, user, action, agent, {"model": model})
                return 200, body
            if route == "/api/v1/agent-tool-rules" and method in ("GET", "POST", "DELETE"):
                controls.protect_admin(user)
                if method == "GET":
                    rows = conn.execute(
                        "SELECT * FROM agent_tool_rules WHERE project=? ORDER BY agent,tool,operation,target LIMIT 500",
                        (project,),
                    )
                    return 200, {"rules": [dict(row) for row in rows]}
                coordinates = runtime_policy.tool_coordinates(body, object_fields, identifier)
                if method == "POST":
                    if not runtime_policy.is_agent(conn, project, coordinates[0]):
                        raise Problem(404, "Agent not found in this project.")
                    conn.execute(
                        """INSERT INTO agent_tool_rules VALUES(?,?,?,?,?,?,?)
                           ON CONFLICT(project,agent,tool,operation,target)
                           DO UPDATE SET updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
                        (project, *coordinates, user["principal"], timestamp()),
                    )
                    action = "agent.tool.allowed"
                else:
                    conn.execute(
                        "DELETE FROM agent_tool_rules WHERE project=? AND agent=? AND tool=? AND operation=? AND target=?",
                        (project, *coordinates),
                    )
                    action = "agent.tool.revoked"
                audit(conn, user, action, coordinates[0], body)
                return 200, body
            if route == "/api/v1/runtime-policy" and method in ("GET", "POST"):
                controls.protect_admin(user)
                if method == "GET":
                    row = conn.execute("SELECT * FROM project_runtime_policies WHERE project=?",
                                       (project,)).fetchone()
                    return 200, dict(row) if row else {"project": project, "minimum_action": "redact"}
                object_fields(body, ("minimum_action",))
                floor = body["minimum_action"]
                if floor not in ("redact", "block"):
                    raise Problem(400, "Minimum action must be redact or block.")
                updated = timestamp()
                conn.execute(
                    """INSERT INTO project_runtime_policies VALUES(?,?,?,?)
                       ON CONFLICT(project) DO UPDATE SET minimum_action=excluded.minimum_action,
                       updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                    (project, floor, user["principal"], updated),
                )
                audit(conn, user, "runtime.policy.updated", project, {"minimum_action": floor})
                return 200, {"project": project, "minimum_action": floor, "updated_at": updated}
            if route == "/api/v1/security-events" and method == "GET":
                return controls.event_feed(conn, user, url.query)
            if route == "/api/v1/operations" and method == "GET":
                controls.protect_admin(user)
                counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE project=?",
                                              (project,)).fetchone()[0]
                          for table in ("assets", "scans", "issues", "runtime_findings")}
                last_sync = conn.execute(
                    """SELECT status,finished_at FROM sync_runs WHERE project=? ORDER BY rowid DESC LIMIT 1""",
                    (project,),
                ).fetchone()
                return 200, {"schema_version": SCHEMA_VERSION, "counts": counts,
                             "last_sync": dict(last_sync) if last_sync else None}
            if route == "/api/v1/instance" and method == "GET":
                controls.protect_admin(user)
                stream = conn.execute("SELECT id FROM event_stream WHERE singleton=1").fetchone()["id"]
                return 200, {"boot_id": self.boot_id, "stream_id": stream, "node": self.node}
            if route.startswith("/api/v1/issues/") and route.endswith("/exceptions"):
                issue_id = route.removeprefix("/api/v1/issues/").removesuffix("/exceptions")
                status, result = controls.exception_route(conn, user, issue_id, method, body, object_fields)
                if method != "GET":
                    action = "issue.exception.approved" if method == "POST" else "issue.exception.revoked"
                    audit(conn, user, action, issue_id,
                          {key: value for key, value in result.items() if key != "reason"})
                return status, result
            if route.startswith("/api/v1/issues/") and route.endswith("/assignment") and method == "POST":
                issue_id = route.removeprefix("/api/v1/issues/").removesuffix("/assignment")
                if user["role"] != "admin":
                    raise Problem(403, "Project administrator access required.")
                object_fields(body, ("assignee",))
                assignee = body["assignee"]
                if assignee is not None:
                    identifier(assignee)
                    eligible = conn.execute(
                        """SELECT 1 FROM credentials c WHERE project=? AND principal=?
                           AND role IN ('admin','operator') AND (expires_at IS NULL OR expires_at>?)
                           AND NOT EXISTS(SELECT 1 FROM runtime_credentials r WHERE r.digest=c.digest)
                           UNION ALL SELECT 1 FROM federated_users
                           WHERE project=? AND principal=? AND role IN ('admin','operator')""",
                        (project, assignee, timestamp(), project, assignee),
                    ).fetchone()
                    if eligible is None:
                        raise Problem(400, "Assign the issue to an active administrator or operator in this project.")
                changed = conn.execute("UPDATE issues SET assignee=? WHERE project=? AND id=?",
                                       (assignee, project, issue_id)).rowcount
                if changed == 0:
                    raise Problem(404, "Issue not found.")
                action = "issue.assigned" if assignee is not None else "issue.unassigned"
                audit(conn, user, action, issue_id, {"assignee": assignee})
                return 200, {"id": issue_id, "assignee": assignee}
            if route.startswith("/api/v1/issues/") and route.endswith("/remediation-proof") and method == "GET":
                issue_id = route.removeprefix("/api/v1/issues/").removesuffix("/remediation-proof")
                return 200, risk_evidence.remediation_proof(conn, project, issue_id)
            if route.startswith("/api/v1/issues/") and method == "GET":
                issue_id = route.removeprefix("/api/v1/issues/")
                row = conn.execute("SELECT * FROM issues WHERE project=? AND id=?",
                                   (project, issue_id)).fetchone()
                if row is None:
                    raise Problem(404, "Issue not found.")
                events = conn.execute(
                    """SELECT scan,action,outcome,created_at FROM issue_events WHERE project=? AND issue=?
                       ORDER BY seq DESC LIMIT 100""",
                    (project, issue_id),
                )
                issue = controls.prioritize(conn, project, (row,), CHECKS)[0]
                return 200, {"issue": issue, "events": [dict(event) for event in events],
                             "risk_evidence": risk_evidence.explain(conn, project, row["asset"])}
            if route == "/api/v1/audit" and method == "GET":
                if user["role"] != "admin":
                    raise Problem(403, "Project administrator access required.")
                records = conn.execute(
                    """SELECT seq,project,principal,action,resource,created_at
                       FROM audit WHERE project=? ORDER BY seq DESC LIMIT 100""", (project,)
                )
                return 200, {"events": [dict(row) for row in records]}
            raise Problem(404, "Route not found.")


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def send(self, status, data, content_type="application/json"):
        if content_type == "application/json":
            data = json.dumps(data, ensure_ascii=False).encode()
        registry = getattr(self.server, "telemetry", None)
        if registry is not None:
            registry.record(self.metric_group, status, perf_counter() - self.metric_started)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self):
        route = urlsplit(self.path).path
        self.metric_started = perf_counter()
        self.metric_group = telemetry.route_group(route)
        static = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8")}
        try:
            if self.command == "GET" and route == "/metrics":
                token = getattr(self.server, "metrics_token", None)
                supplied = self.headers.get("Authorization", "")
                if token is None:
                    raise Problem(404, "Metrics endpoint unavailable.")
                if not supplied.isascii() or not secrets.compare_digest(supplied, "Bearer " + token):
                    raise Problem(401, "Supply a valid monitoring credential.")
                return self.send(200, self.server.telemetry.render(),
                                 "text/plain; version=0.0.4; charset=utf-8")
            if self.command == "GET" and route in static:
                file, content_type = static[route]
                return self.send(200, (WEB / file).read_bytes(), content_type)
            if self.command == "GET" and route == "/health":
                with database(self.server.product.path) as conn:
                    conn.execute("SELECT 1 FROM assets LIMIT 1").fetchone()
                    if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                        raise Problem(503, "Storage schema is not ready.")
                return self.send(200, {"status": "ok"})
            device = route == "/auth/device" or route.startswith("/auth/device/")
            auth = self.headers.get("Authorization", "")
            if not device and (not auth.startswith("Bearer ") or len(auth) > 8192):
                raise Problem(401, "Supply a valid bearer token.")
            body = None
            if self.command in ("POST", "DELETE"):
                if self.headers.get_content_type() != "application/json":
                    raise Problem(415, "Use application/json.")
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    size_limit = agent_protocol.MAX_REPORT if route == "/api/v1/agent/report" else 8192
                    if not 0 < size <= size_limit:
                        raise Problem(400, f"Supply a JSON body of 1–{size_limit} bytes.")
                    raw = self.rfile.read(size)
                    if route in ("/api/v1/runtime/inspect-document", "/api/v1/runtime/relay", "/api/v1/agent/report"):
                        body = verification.parse_json(raw)
                    else:
                        body = json.loads(raw)
                except (ValueError, RecursionError):
                    raise Problem(400, "Invalid JSON body.") from None
            if device:
                status, result = self.server.product.device_request(route, self.command, self.headers.get("Origin"), body)
            else:
                status, result = self.server.product.request(self.command, self.path, auth[7:], body)
            if route == "/api/v1/agents/package" and self.command == "GET":
                return self.send(status, result, "application/zip")
            self.send(status, result)
        except Problem as exc:
            self.send(exc.status, {"error": str(exc)})
        except sqlite3.Error:
            self.send(503, {"error": "Storage unavailable."})

    do_GET = dispatch
    do_POST = dispatch
    do_DELETE = dispatch

    def log_message(self, format, *args):
        # Access logs omit input paths, bearer tokens and request bodies.
        return


class PostureHTTPServer(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = False

    def __init__(self, address, handler):
        self.capacity = BoundedSemaphore(32)
        self.telemetry = telemetry.Telemetry()
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.telemetry.reject()
            self.shutdown_request(request)
            return
        self.telemetry.connection(1)
        try:
            super().process_request(request, address)
        except BaseException:
            self.capacity.release()
            self.telemetry.connection(-1)
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.capacity.release()
            self.telemetry.connection(-1)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("data/posture.sqlite"))
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--listen-address", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1")
    serve.add_argument("--relay-config", type=Path, help="Enable a fixed-destination JSON enforcement relay")
    serve.add_argument("--chat-gateway-config", type=Path, help="Enable project and agent bound text gateway routes")
    serve.add_argument("--issuer-config", type=Path, help="Trusted RFC 9068 issuer configuration")
    serve.add_argument("--metrics-token-file", type=Path, help="Enable the protected Prometheus endpoint")
    mapping = commands.add_parser("map-identity")
    mapping.add_argument("issuer")
    mapping.add_argument("subject")
    mapping.add_argument("project")
    mapping.add_argument("principal")
    mapping.add_argument("role", choices=("admin", "operator", "viewer"))
    unmap = commands.add_parser("unmap-identity")
    unmap.add_argument("issuer")
    unmap.add_argument("subject")
    provision = commands.add_parser("issue")
    provision.add_argument("project")
    provision.add_argument("principal")
    provision.add_argument("role", choices=("admin", "operator", "viewer"))
    lifetime = provision.add_mutually_exclusive_group()
    lifetime.add_argument("--ttl-hours", type=int, choices=range(1, 721),
                          metavar="HOURS", help="Credential lifetime, 1–720 hours (default: 720)")
    lifetime.add_argument("--ttl-minutes", type=int, choices=range(1, 61),
                          metavar="MINUTES", help="Short-lived credential, 1–60 minutes")
    runtime_issue = commands.add_parser("issue-runtime", help="Issue a narrowly scoped runtime credential")
    runtime_issue.add_argument("project")
    runtime_issue.add_argument("principal")
    runtime_issue.add_argument("source")
    runtime_issue.add_argument("--scope", required=True,
                               choices=("inspect", "findings", "both", "tools", "models", "agent"))
    runtime_issue.add_argument("--agent", help="Required for tools, models and agent scopes")
    runtime_issue.add_argument("--ttl-minutes", type=int, choices=range(1, 61), default=15, metavar="MINUTES")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("project")
    revoke.add_argument("principal")
    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    sync = commands.add_parser("sync-gcs", help="Discover and assess Cloud Storage buckets through read-only ADC")
    sync.add_argument("project", help="DoofusAI project")
    sync.add_argument("cloud_project", help="Google Cloud project ID or number")
    sync.add_argument("--quota-project", help="Optional Google Cloud API quota project")
    gcs_review = commands.add_parser("review-gcs-access", help="Check the active Google caller's permissions on a bucket")
    gcs_review.add_argument("project")
    gcs_review.add_argument("asset", help="DoofusAI Cloud Storage asset ID")
    gcs_review.add_argument("--permission", action="append", required=True)
    gcs_review.add_argument("--quota-project")
    gcs_review.add_argument("--receive-time", help="RFC 3339 request time for named-principal conditional evaluation")
    gcs_review.add_argument("--principal", help="Assess a named Google user or service account via IAM Policy Troubleshooter")
    ai_sync = commands.add_parser("sync-vertex", help="Discover read-only Google AI inventory and class labels")
    ai_sync.add_argument("project")
    ai_sync.add_argument("cloud_project")
    ai_sync.add_argument("region")
    ai_sync.add_argument("--quota-project")
    ai_sync.add_argument("--profile-location", help="Location of existing Sensitive Data Protection profiles")
    aws = commands.add_parser("sync-aws", help="Discover AWS AI inventory and access analysis metadata")
    aws.add_argument("project")
    aws.add_argument("account")
    aws.add_argument("region")
    aws.add_argument("--analyzer")
    access = commands.add_parser("review-aws-access", help="Record read-only IAM policy simulation evidence")
    access.add_argument("project")
    access.add_argument("asset", help="DoofusAI AWS role asset ID")
    access.add_argument("--resource", required=True, help="One exact resource ARN")
    access.add_argument("--action", required=True, action="append", help="AWS action; repeat for up to 30 actions")
    workload_access = commands.add_parser("review-aws-workload-access", help="Review discovered model role and artifact bucket pairs")
    workload_access.add_argument("project")
    workload_access.add_argument("workload")
    azure = commands.add_parser("sync-azure", help="Discover Azure ML and optional Microsoft Foundry inventory")
    azure.add_argument("project")
    azure.add_argument("subscription")
    azure.add_argument("resource_group")
    azure.add_argument("workspace")
    azure.add_argument("--rbac", action="store_true", help="Collect selected ARM role-assignment metadata")
    azure.add_argument("--foundry-account")
    azure.add_argument("--foundry-project")
    oci = commands.add_parser("sync-oci", help="Discover OCI Data Science projects, models and deployments")
    oci.add_argument("project")
    oci.add_argument("compartment")
    oci.add_argument("region")
    oci.add_argument("--deployment-details", action="store_true",
                     help="Collect deployment-to-model and access logging evidence")
    ibm = commands.add_parser("sync-ibm", help="Discover models and deployments in a watsonx.ai space")
    ibm.add_argument("project")
    ibm.add_argument("space")
    ibm.add_argument("region")
    salesforce = commands.add_parser("sync-salesforce", help="Discover Salesforce organization and Flow metadata")
    salesforce.add_argument("project")
    salesforce.add_argument("host", help="Salesforce My Domain hostname")
    salesforce.add_argument("org", help="Expected Salesforce organization ID")
    salesforce.add_argument("--api-version", default="63.0")
    salesforce.add_argument("--agentforce", action="store_true", help="Collect Agentforce definitions and versions")
    vsphere = commands.add_parser("sync-vsphere", aliases=["sync-esxi"], help="Discover ESXi or vCenter inventory")
    vsphere.add_argument("project")
    vsphere.add_argument("host")
    vsphere.add_argument("--port", type=int, default=443)
    vsphere.add_argument("--ca-file", type=Path)
    vsphere_access = commands.add_parser("review-vsphere-access", help="Record a read-only vCenter privilege check")
    vsphere_access.add_argument("project")
    vsphere_access.add_argument("asset")
    vsphere_access.add_argument("--principal", required=True, help="vCenter user whose privilege is checked")
    vsphere_access.add_argument("--privilege", action="append", required=True, help="vCenter privilege ID")
    vsphere_access.add_argument("--ca-file", type=Path)
    sample = commands.add_parser("classify-object", help="Classify a text sample from one inventoried cloud object")
    sample.add_argument("project")
    sample.add_argument("node")
    sample.add_argument("object_key")
    discover_sample = commands.add_parser("classify-prefix", help="Discover and classify one bounded page under a cloud prefix")
    discover_sample.add_argument("project")
    discover_sample.add_argument("node")
    discover_sample.add_argument("prefix")
    discover_sample.add_argument("--limit", type=int, default=32)
    batch = commands.add_parser("classify-batch", help="Classify up to 32 selected objects from one inventoried bucket")
    batch.add_argument("project")
    batch.add_argument("node")
    batch.add_argument("manifest", type=Path, help="JSON array of exact object keys")
    npm = commands.add_parser("sync-npm-lock", help="Discover dependencies from package-lock.json without executing npm")
    npm.add_argument("project")
    npm.add_argument("workload")
    npm.add_argument("lockfile", type=Path)
    bom = commands.add_parser("import-bom", help="Import CycloneDX packages and dependencies for a workload")
    bom.add_argument("project")
    bom.add_argument("workload")
    bom.add_argument("document", type=Path)
    github_sbom = commands.add_parser("sync-github-bom", help="Collect a GitHub dependency graph report")
    github_sbom.add_argument("project")
    github_sbom.add_argument("workload")
    github_sbom.add_argument("repository")
    github_sbom.add_argument("--download-host", required=True)
    verify = commands.add_parser("verify-artifact", help="Fail CI if a model differs from its signed manifest")
    verify.add_argument("artifact", type=Path)
    verify.add_argument("manifest", type=Path)
    verify.add_argument("signature", type=Path)
    verify.add_argument("public_key", type=Path)
    verify.add_argument("--artifact-id", required=True)
    verify.add_argument("--format-policy", choices=("safetensors", "safe-model-package", "gguf", "pickle-data", "checkpoint-data", "onnx-inline"),
                        help="Require the selected signed artifact format policy")
    verify.add_argument("--numeric-policy", choices=("finite",),
                        help="Reject non-finite floating-point weights and invalid Boolean bytes in Safetensors")
    verify.add_argument("--threat-report", type=Path)
    verify.add_argument("--threat-signature", type=Path)
    verify.add_argument("--threat-public-key", type=Path)
    verify.add_argument("--trusted-scanner")
    verify.add_argument("--threat-max-age-hours", type=int, choices=range(1, 169),
                        metavar="HOURS", help="Freshness limit (default: 24 hours)")
    check_backup = commands.add_parser("verify-backup")
    check_backup.add_argument("backup", type=Path)
    export = commands.add_parser("export-audit")
    export.add_argument("project")
    export.add_argument("destination", type=Path)
    export.add_argument("private_key", type=Path)
    export.add_argument("--after", type=int, default=0)
    verify_export = commands.add_parser("verify-audit")
    verify_export.add_argument("export", type=Path)
    verify_export.add_argument("public_key", type=Path)
    behavior = commands.add_parser("evaluate-model", help="Run a fixed behavior contract against a trusted deployment")
    behavior.add_argument("suite", type=Path)
    behavior.add_argument("--origin", required=True)
    behavior.add_argument("--model", required=True)
    behavior.add_argument("--timeout", type=float, default=10)
    commands.add_parser("promote-recovery", help="Give a validated restored database a new event stream ID")
    args = parser.parse_args()
    if args.command == "evaluate-model":
        try:
            deployment = model_behavior.ChatDeployment(args.origin, args.model, os.environ.get("SPM_MODEL_TOKEN"),
                                                       timeout=args.timeout)
            raw = verification.read_limited(args.suite, model_behavior.MAX_SUITE)
            result = model_behavior.evaluate(raw, deployment)
            print(json.dumps(result))
            if not result["passed"]:
                parser.exit(1)
        except (OSError, ValueError, Problem) as error:
            parser.exit(1, f"Behavior evaluation failed: {error}\n")
        return
    if args.command in ("verify-artifact", "verify-backup", "verify-audit"):
        try:
            if args.command == "verify-artifact":
                result = verification.verify_artifact(args.artifact, args.manifest, args.signature,
                                                      args.public_key, identifier(args.artifact_id),
                                                      args.format_policy, args.numeric_policy == "finite")
                threat = (args.threat_report, args.threat_signature, args.threat_public_key, args.trusted_scanner)
                if any(item is not None for item in threat) or args.threat_max_age_hours is not None:
                    if any(item is None for item in threat):
                        raise Problem(400, "Threat report, signature, trusted public key and scanner are all required.")
                    result["threat_verdict"] = verification.verify_threat_report(
                        result, *threat, args.threat_max_age_hours or 24,
                    )
            elif args.command == "verify-backup":
                result = verification.verify_backup(args.backup, SCHEMA_VERSION)
            else:
                result = verification.verify_signed_export(args.export, args.public_key)
            print(json.dumps(result))
        except (OSError, sqlite3.Error, Problem) as error:
            parser.exit(1, f"Verification failed: {error}\n")
        return
    args.db.parent.mkdir(parents=True, exist_ok=True)
    if args.command == "promote-recovery":
        try:
            with service_guard(args.db):
                verification.verify_backup(args.db, SCHEMA_VERSION)
                stream = uuid4().hex
                with database(args.db, write=True) as conn:
                    conn.execute("UPDATE event_stream SET id=? WHERE singleton=1", (stream,))
            print(json.dumps({"stream_id": stream}))
        except (OSError, sqlite3.Error, Problem) as error:
            parser.exit(1, f"Recovery promotion failed: {error}\n")
        return
    try:
        issuer = federation.Issuer(args.issuer_config) if getattr(args, "issuer_config", None) else None
    except (OSError, ValueError, Problem) as error:
        parser.exit(1, f"Federation configuration invalid: {error}\n")
    if args.command != "serve":
        initialize(args.db)
    if args.command == "issue":
        delta = timedelta(minutes=args.ttl_minutes) if args.ttl_minutes else timedelta(hours=args.ttl_hours or 720)
        expires = datetime.now(timezone.utc) + delta
        print(issue(args.db, args.project, args.principal, args.role,
                    expires.isoformat(timespec="milliseconds")))
    elif args.command == "issue-runtime":
        expires = datetime.now(timezone.utc) + timedelta(minutes=args.ttl_minutes)
        scope = (identifier(args.source), args.scope in ("inspect", "both"),
                 args.scope in ("findings", "both"))
        if (args.scope in ("tools", "models", "agent")) != (args.agent is not None):
            parser.error("--agent is required for tools, models and agent scopes and applies only to those scopes.")
        try:
            agent = identifier(args.agent) if args.agent else None
            print(issue(args.db, args.project, args.principal, "operator",
                        expires.isoformat(timespec="milliseconds"), runtime=scope, tool_agent=agent,
                        allow_tools=args.scope in ("tools", "agent"),
                        allow_models=args.scope in ("models", "agent")))
        except Problem as error:
            parser.exit(1, f"Runtime credential failed: {error}\n")
    elif args.command == "revoke":
        identifier(args.project)
        identifier(args.principal)
        with database(args.db, write=True) as conn:
            changed = conn.execute("DELETE FROM credentials WHERE project=? AND principal=?",
                                   (args.project, args.principal)).rowcount
            audit(conn, {"project": args.project, "principal": "local-cli"},
                  "credential.revoked", args.principal)
        print(f"Revoked {changed} credential(s).")
    elif args.command in ("map-identity", "unmap-identity"):
        issuer_url = federation.https_issuer(args.issuer)
        subject = federation.subject(args.subject)
        with database(args.db, write=True) as conn:
            previous = conn.execute(
                "SELECT project,principal FROM federated_users WHERE issuer=? AND subject=?",
                (issuer_url, subject),
            ).fetchone()
            if args.command == "unmap-identity":
                if previous:
                    conn.execute("DELETE FROM federated_users WHERE issuer=? AND subject=?", (issuer_url, subject))
                    audit(conn, {"project": previous["project"], "principal": "local-cli"},
                          "identity.unmapped", previous["principal"])
            else:
                project, principal = identifier(args.project), identifier(args.principal)
                if previous and (previous["project"], previous["principal"]) != (project, principal):
                    parser.exit(1, "Unmap the previous identity before changing its project or principal.\n")
                conn.execute(
                    """INSERT INTO federated_users VALUES(?,?,?,?,?)
                       ON CONFLICT(issuer,subject) DO UPDATE SET role=excluded.role""",
                    (issuer_url, subject, project, principal, args.role),
                )
                audit(conn, {"project": project, "principal": "local-cli"}, "identity.mapped", principal)
        print("Federated identity mapping updated.")
    elif args.command == "backup":
        fd = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with database(args.db) as original, database(args.destination) as copy:
                original.backup(copy)
                if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("Backup failed integrity check")
        except Exception:
            args.destination.unlink()
            raise
        print(f"Verified backup written to {args.destination}")
    elif args.command == "sync-gcs":
        try:
            print(json.dumps(sync_gcs(args.db, args.project, args.cloud_project, args.quota_project)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Google Cloud sync failed: {error}\n")
    elif args.command == "review-gcs-access":
        try:
            evaluate = gcs_access.evaluate
            if args.receive_time and not args.principal:
                raise Problem(400, "Conditional time requires --principal.")
            if args.principal is not None:
                from functools import partial
                receive_time = (controls.parse_time(args.receive_time).isoformat().replace("+00:00", "Z")
                                if args.receive_time else None)
                evaluate = partial(gcs_access.troubleshoot, principal=args.principal, receive_time=receive_time)
            print(json.dumps(review_gcs_access(args.db, args.project, args.asset,
                                               args.permission, args.quota_project, evaluate=evaluate)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Google Cloud access review failed: {error}\n")
    elif args.command == "sync-vertex":
        try:
            print(json.dumps(sync_vertex(args.db, args.project, args.cloud_project, args.region,
                                         args.quota_project, args.profile_location)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Google AI sync failed: {error}\n")
    elif args.command == "sync-aws":
        try:
            print(json.dumps(sync_aws(args.db, args.project, args.account, args.region, args.analyzer)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"AWS AI sync failed: {error}\n")
    elif args.command == "review-aws-access":
        try:
            print(json.dumps(review_aws_access(args.db, args.project, args.asset, args.resource, args.action)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"AWS access review failed: {error}\n")
    elif args.command == "review-aws-workload-access":
        try:
            print(json.dumps(review_aws_workload_access(args.db, args.project, args.workload)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"AWS workload access review failed: {error}\n")
    elif args.command == "sync-azure":
        if bool(args.foundry_account) != bool(args.foundry_project):
            parser.error("Use --foundry-account and --foundry-project together.")
        foundry = (args.foundry_account, args.foundry_project) if args.foundry_account else None
        try:
            print(json.dumps(sync_azure(args.db, args.project, args.subscription, args.resource_group,
                                        args.workspace, args.rbac, foundry)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Azure AI sync failed: {error}\n")
    elif args.command in ("sync-oci", "sync-ibm", "sync-salesforce"):
        provider = args.command.removeprefix("sync-")
        detail_options = {}
        try:
            if provider == "oci":
                connector = oci_inventory
                scope_args = (args.compartment, args.region)
                options = ()
                detail_options = {"include_deployment_details": args.deployment_details}
            elif provider == "ibm":
                connector = ibm_inventory
                scope_args = (args.space, args.region)
                options = ()
            else:
                connector = salesforce_inventory
                scope_args = (args.host, args.org)
                options = (args.api_version,)
                detail_options = {"include_agentforce": args.agentforce}
            result = sync_cloud_graph(args.db, args.project, provider, connector.scope_key(*scope_args),
                                      lambda: connector.discover(*scope_args, *options, **detail_options))
            print(json.dumps(result))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"{provider} inventory failed: {error}\n")
    elif args.command in ("sync-vsphere", "sync-esxi"):
        try:
            print(json.dumps(sync_vsphere(args.db, args.project, args.host, args.port, args.ca_file)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"vSphere sync failed: {error}\n")
    elif args.command == "review-vsphere-access":
        try:
            print(json.dumps(review_vsphere_access(args.db, args.project, args.asset, args.principal,
                                                    args.privilege, args.ca_file)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"vCenter access review failed: {error}\n")
    elif args.command == "classify-object":
        try:
            print(json.dumps(classify_cloud_object(args.db, args.project, args.node, args.object_key)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Content classification failed: {error}\n")
    elif args.command == "classify-prefix":
        try:
            print(json.dumps(classify_prefix(args.db, args.project, args.node, args.prefix, args.limit)))
        except (Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Prefix classification failed: {error}\n")
    elif args.command == "classify-batch":
        try:
            keys = verification.parse_json(verification.read_limited(args.manifest, 32768))
            samples = classify_cloud_batch(args.db, args.project, args.node, keys)
            print(json.dumps({"classified": len(samples),
                              "levels": dict(Counter(item["sensitivity"] for item in samples))}))
        except (OSError, Problem, gcs.CollectionError) as error:
            parser.exit(1, f"Batch classification failed: {error}\n")
    elif args.command == "sync-npm-lock":
        try:
            raw = verification.read_limited(args.lockfile, ai_bom.MAX_BOM_BYTES)
            result = import_bom(args.db, args.project, args.workload, npm_inventory.discover(raw),
                                {"provider": "npm-lock", "input_sha256": hashlib.sha256(raw).hexdigest()})
            print(json.dumps(result))
        except (OSError, Problem) as error:
            parser.exit(1, f"npm dependency discovery failed: {error}\n")
    elif args.command == "import-bom":
        try:
            raw = verification.read_limited(args.document, ai_bom.MAX_BOM_BYTES)
            print(json.dumps(import_bom(args.db, args.project, args.workload, raw)))
        except (OSError, Problem) as error:
            parser.exit(1, f"BOM import failed: {error}\n")
    elif args.command == "sync-github-bom":
        try:
            raw = github_bom.discover(args.repository, os.environ.get("SPM_GITHUB_TOKEN"), args.download_host)
            print(json.dumps(import_bom(args.db, args.project, args.workload, raw,
                                        {"provider": "github", "repository": args.repository})))
        except Problem as error:
            parser.exit(1, f"GitHub dependency sync failed: {error}\n")
    elif args.command == "export-audit":
        try:
            project = identifier(args.project)
            with database(args.db) as conn:
                conn.execute("BEGIN")
                _, result = controls.event_feed(conn, {"project": project, "role": "admin"},
                                                f"after={args.after}")
            package = {"schema": "doofusai.audit.v1", "project": project,
                       "exported_at": timestamp(), "after": args.after, **result}
            verification.write_signed_export(args.destination, package, args.private_key)
            print(json.dumps({key: result[key] for key in ("next_after", "has_more")}))
        except (OSError, Problem) as error:
            parser.exit(1, f"Audit export failed: {error}\n")
    else:
        metrics_token = None
        if args.metrics_token_file is not None:
            try:
                metrics_token = verification.read_limited(args.metrics_token_file, 260).decode("ascii").strip()
                if re.fullmatch(r"[A-Za-z0-9_-]{32,256}", metrics_token) is None:
                    raise Problem(400, "Monitoring credential must contain at least 32 URL-safe characters.")
            except (OSError, UnicodeError, Problem) as error:
                parser.exit(1, f"Metrics configuration invalid: {error}\n")
        try:
            with service_guard(args.db):
                gateway = load_gateway(args.chat_gateway_config) if args.chat_gateway_config else None
                relay = None
                if args.relay_config:
                    settings = verification.parse_json(verification.read_limited(args.relay_config, 4096))
                    object_fields(settings, ("project", "target"))
                    relay = (identifier(settings["project"]), runtime_relay.Relay(
                        settings["target"], os.environ.get("DOOFUS_RELAY_UPSTREAM_TOKEN")
                    ))
                product = Product(args.db, issuer, gateway, relay)
                with PostureHTTPServer((args.listen_address, args.port), Handler) as server:
                    server.product = product
                    server.metrics_token = metrics_token
                    signal.signal(signal.SIGTERM, lambda *_: Thread(target=server.shutdown, daemon=True).start())
                    print(f"DoofusAI SPM · http://{args.listen_address}:{server.server_port}", flush=True)
                    server.serve_forever()
        except (OSError, ValueError, Problem) as error:
            parser.exit(1, f"Service start failed: {error}\n")


if __name__ == "__main__":
    main()
