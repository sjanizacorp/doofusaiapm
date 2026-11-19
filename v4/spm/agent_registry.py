"""Project-bound enrollment and leased jobs for read-only collection agents."""
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
from pathlib import Path
import secrets
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from agent_protocol import deployment, text
from controls import Problem

SCHEMA = """
CREATE TABLE collection_agents (
 id TEXT PRIMARY KEY, project TEXT NOT NULL, name TEXT NOT NULL, provider TEXT NOT NULL,
 scope TEXT NOT NULL, arguments TEXT NOT NULL, token_digest TEXT NOT NULL UNIQUE,
 expires_at TEXT NOT NULL, revoked_at TEXT, last_seen TEXT, created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX active_collection_agent_scope ON collection_agents(project,scope) WHERE revoked_at IS NULL;
CREATE TABLE collection_jobs (
 id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES collection_agents(id),
 status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
 created_at TEXT NOT NULL, finished_at TEXT, claim TEXT, lease_until TEXT,
 attempts INTEGER NOT NULL DEFAULT 0, report_digest TEXT, result TEXT
);
CREATE UNIQUE INDEX collection_job_active ON collection_jobs(agent) WHERE status IN ('queued','running');
CREATE INDEX collection_job_history ON collection_jobs(agent,created_at DESC);
"""
BASELINE_SCHEMA = """
ALTER TABLE collection_jobs ADD COLUMN baseline_sync TEXT;
"""
SCHEDULE_SCHEMA = """
ALTER TABLE collection_agents ADD COLUMN interval_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE collection_agents ADD COLUMN next_run TEXT;
"""
PACKAGE = ("agent.py", "agent_protocol.py", "agentforce.py", "gcs.py", "controls.py",
           "vertex.py", "aws_inventory.py", "azure_inventory.py", "oci_inventory.py",
           "ibm_inventory.py", "salesforce_inventory.py", "vsphere_inventory.py", "requirements-vsphere.txt")


def package():
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name in PACKAGE:
            source = Path(__file__).with_name(name)
            if source.suffix == ".py" and not source.is_file():
                source = source.with_suffix(".pyc")
            archive.writestr(source.name, source.read_bytes())
    return output.getvalue()


def secret():
    token = "agent_" + secrets.token_urlsafe(32)
    return token, digest(token)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def manage(conn, user, method, path, body, fields, stamp, audit):
    project = user["project"]
    if path == "/api/v1/agents" and method == "GET":
        rows = conn.execute("""
            SELECT id,name,provider,scope,expires_at,revoked_at,last_seen,created_at,interval_minutes,next_run
            FROM collection_agents WHERE project=? ORDER BY created_at DESC,id LIMIT 100
        """, (project,))
        return 200, {"agents": [dict(row) for row in rows]}
    if path == "/api/v1/agents" and method == "POST":
        fields(body, ("name", "provider", "arguments", "ttl_hours"))
        name, provider, arguments, ttl = (body[key] for key in ("name", "provider", "arguments", "ttl_hours"))
        if not text(name, 80) or type(ttl) is not int or not 1 <= ttl <= 720:
            raise Problem(400, "Use an agent name and a lifetime of 1–720 hours.")
        scope, _ = deployment(provider, arguments)
        if conn.execute("SELECT 1 FROM collection_agents WHERE project=? AND scope=? AND revoked_at IS NULL",
                        (project, scope)).fetchone():
            raise Problem(409, "This scope already has an agent. Rotate or revoke it first.")
        key, now = str(uuid4()), stamp()
        token, hashed = secret()
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl)).isoformat(timespec="milliseconds")
        conn.execute("INSERT INTO collection_agents(id,project,name,provider,scope,arguments,token_digest,expires_at,revoked_at,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?)",
                     (key, project, name, provider, scope, json.dumps(arguments), hashed, expires, now))
        audit(conn, user, "agent.enrolled", key, {"provider": provider, "scope": scope})
        return 201, {"id": key, "scope": scope, "token": token, "expires_at": expires}

    elements = path.removeprefix("/api/v1/agents/").split("/")
    if not elements[0] or len(elements) > 2:
        raise Problem(404, "Collection agent route unavailable.")
    agent = conn.execute("SELECT * FROM collection_agents WHERE project=? AND id=?",
                         (project, elements[0])).fetchone()
    if agent is None:
        raise Problem(404, "Collection agent not found.")
    key = agent["id"]
    if len(elements) == 1 and method == "DELETE":
        fields(body, ())
        now = stamp()
        conn.execute("UPDATE collection_agents SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, key))
        conn.execute("""UPDATE collection_jobs SET status='cancelled',finished_at=?
                      WHERE agent=? AND status IN ('queued','running')""", (now, key))
        audit(conn, user, "agent.revoked", key)
        return 200, {"id": key, "revoked": True}
    if elements[1:] == ["schedule"] and method == "POST":
        fields(body, ("interval_minutes",))
        interval = body["interval_minutes"]
        if type(interval) is not int or interval not in (0, 5, 15, 30, 60, 360, 1440) or agent["revoked_at"]:
            raise Problem(400, "Choose a supported collection interval.")
        conn.execute("UPDATE collection_agents SET interval_minutes=?,next_run=? WHERE id=?",
                     (interval, stamp() if interval else None, key))
        audit(conn, user, "agent.schedule.updated", key, {"interval_minutes": interval})
        return 200, {"interval_minutes": interval}
    if elements[1:] == ["rotate"] and method == "POST":
        fields(body, ("ttl_hours",))
        ttl = body["ttl_hours"]
        if type(ttl) is not int or not 1 <= ttl <= 720 or agent["revoked_at"]:
            raise Problem(400, "Use an active agent and a lifetime of 1–720 hours.")
        token, hashed = secret()
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl)).isoformat(timespec="milliseconds")
        conn.execute("UPDATE collection_agents SET token_digest=?,expires_at=? WHERE id=?",
                     (hashed, expires, key))
        conn.execute("""UPDATE collection_jobs SET status='queued',claim=NULL,lease_until=NULL,attempts=0
                        WHERE agent=? AND status='running'""", (key,))
        audit(conn, user, "agent.credential.rotated", key)
        return 200, {"id": key, "token": token, "expires_at": expires}
    if elements[1:] != ["jobs"]:
        raise Problem(404, "Collection agent route unavailable.")
    if method == "GET":
        jobs = conn.execute("""SELECT id,status,created_at,finished_at,attempts,result
                              FROM collection_jobs WHERE agent=? ORDER BY rowid DESC LIMIT 30""", (key,))
        return 200, {"jobs": [dict(job) | {"result": json.loads(job["result"]) if job["result"] else None}
                              for job in jobs]}
    if method != "POST":
        raise Problem(404, "Collection agent route unavailable.")
    fields(body, ())
    now = stamp()
    if agent["revoked_at"] or agent["expires_at"] <= now:
        raise Problem(409, "Collection agent credential is inactive.")
    active = conn.execute("SELECT id,status FROM collection_jobs WHERE agent=? AND status IN ('queued','running')",
                          (key,)).fetchone()
    if active:
        return 200, dict(active)
    job = str(uuid4())
    conn.execute("INSERT INTO collection_jobs(id,agent,status,created_at) VALUES(?,?,'queued',?)", (job, key, now))
    audit(conn, user, "agent.collection.queued", key, {"job": job})
    return 201, {"id": job, "status": "queued"}


def authenticate(conn, token, stamp):
    if not isinstance(token, str) or not token.startswith("agent_") or len(token) != 49:
        raise Problem(401, "Supply a current collection agent credential.")
    agent = conn.execute("""SELECT * FROM collection_agents WHERE token_digest=? AND expires_at>?
                         AND revoked_at IS NULL""", (digest(token), stamp())).fetchone()
    if agent is None:
        raise Problem(401, "Supply a current collection agent credential.")
    return agent


def latest_completed_sync(conn, agent):
    latest = conn.execute(
        """SELECT id FROM sync_runs WHERE project=? AND provider=? AND source_project=?
           AND status='completed' ORDER BY rowid DESC LIMIT 1""",
        (agent["project"], agent["provider"], agent["scope"]),
    ).fetchone()
    return latest["id"] if latest else None


def poll(conn, agent, stamp, reconcile):
    now, key = stamp(), agent["id"]
    conn.execute("UPDATE collection_agents SET last_seen=? WHERE id=?", (now, key))
    job = conn.execute("SELECT * FROM collection_jobs WHERE agent=? AND status IN ('queued','running')",
                       (key,)).fetchone()
    if job is None and agent["interval_minutes"] and (not agent["next_run"] or agent["next_run"] <= now):
        job_id = str(uuid4())
        conn.execute("INSERT INTO collection_jobs(id,agent,status,created_at) VALUES(?,?,'queued',?)",
                     (job_id, key, now))
        job = conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone()
    if job is None or (job["status"] == "running" and job["lease_until"] > now):
        return {"job": None}
    baseline = latest_completed_sync(conn, agent)
    if job["attempts"] >= 3:
        if baseline == job["baseline_sync"]:
            reconcile(conn, agent, job, "failed", None, now)
        conn.execute("""UPDATE collection_jobs SET status='failed',finished_at=?,result=? WHERE id=?""",
                     (now, '{"error":"Agent lease expired after three attempts."}', job["id"]))
        return {"job": None}
    if agent["interval_minutes"]:
        next_run = (datetime.now(timezone.utc) + timedelta(minutes=agent["interval_minutes"])).isoformat(timespec="milliseconds")
        conn.execute("UPDATE collection_agents SET next_run=? WHERE id=?", (next_run, key))
    claim = secrets.token_urlsafe(32)
    lease = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(timespec="milliseconds")
    conn.execute("""UPDATE collection_jobs SET status='running',claim=?,lease_until=?,baseline_sync=?,
                    attempts=attempts+1 WHERE id=?""", (claim, lease, baseline, job["id"]))
    return {"job": {"id": job["id"], "claim": claim, "provider": agent["provider"],
                    "arguments": json.loads(agent["arguments"])}}


def report(conn, agent, body, fields, stamp, reconcile):
    fields(body, ("job", "claim", "status", "snapshot"))
    key, claim, status = body["job"], body["claim"], body["status"]
    if not text(key, 36) or not text(claim, 43) or status not in ("completed", "failed"):
        raise Problem(400, "Invalid collection report.")
    job = conn.execute("SELECT * FROM collection_jobs WHERE id=? AND agent=?", (key, agent["id"])).fetchone()
    if job is None or job["claim"] != claim:
        raise Problem(409, "Collection lease is no longer active.")
    fingerprint = digest(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    if job["report_digest"] == fingerprint:
        return json.loads(job["result"])
    now = stamp()
    if job["status"] != "running" or job["lease_until"] <= now:
        raise Problem(409, "Collection lease is no longer active.")
    if status == "failed" and body["snapshot"] is not None:
        raise Problem(400, "Failed reports must omit snapshot content.")
    if latest_completed_sync(conn, agent) != job["baseline_sync"]:
        result = {"id": key, "status": "cancelled", "reason": "superseded-by-newer-inventory"}
    else:
        result = reconcile(conn, agent, job, status, body["snapshot"], now)
    conn.execute("""UPDATE collection_jobs SET status=?,finished_at=?,result=?,report_digest=? WHERE id=?""",
                 (result["status"], now, json.dumps(result), fingerprint, key))
    conn.execute("UPDATE collection_agents SET last_seen=? WHERE id=?", (now, agent["id"]))
    return result
