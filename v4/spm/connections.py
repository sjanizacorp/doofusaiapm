"""Console-managed platform connections and server-side collection runs."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from agent_protocol import deployment, text
from controls import Problem

SCHEMA = """
CREATE TABLE platform_connections (
 id TEXT PRIMARY KEY, project TEXT NOT NULL, name TEXT NOT NULL, provider TEXT NOT NULL,
 scope TEXT NOT NULL, arguments TEXT NOT NULL, profile TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX platform_connection_scope ON platform_connections(project,provider,scope);
CREATE TABLE platform_connection_runs (
 id TEXT PRIMARY KEY, connection TEXT NOT NULL REFERENCES platform_connections(id),
 mode TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT, result TEXT
);
CREATE UNIQUE INDEX platform_connection_running ON platform_connection_runs(connection) WHERE status='running';
"""
PROFILE_KEYS = {
    "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR",
    "OCI_CLI_PROFILE", "OCI_CLI_CONFIG_FILE", "OCI_CLI_AUTH",
    "DOOFUS_IBM_IAM_TOKEN", "DOOFUS_SALESFORCE_TOKEN",
    "SPM_VSPHERE_USER", "SPM_VSPHERE_PASSWORD", "DOOFUS_AGENT_VSPHERE_CA",
}
HELP = {
    "aws": "AWS CLI with a read-only account identity. Configure an AWS profile on the server.",
    "gcs": "Google CLI with Application Default Credentials permitted to list buckets in this project.",
    "vertex": "Google CLI with Application Default Credentials permitted to read Vertex AI inventory.",
    "azure": "Azure CLI signed in with read-only access to the selected workspace.",
    "oci": "OCI CLI with a read-only profile for the selected compartment and region.",
    "ibm": "Short-lived IBM IAM token in the server credential profile.",
    "salesforce": "Salesforce OAuth token in the server credential profile.",
    "vsphere": "Read-only VMware username and password in the server credential profile; pyVmomi installed.",
}


def profiles():
    result = {"server": {}}
    path = os.environ.get("DOOFUS_CONNECTION_PROFILES")
    if not path:
        return result
    try:
        file = Path(path)
        if file.stat().st_mode & 0o077 or file.stat().st_size > 65536:
            raise ValueError()
        data = json.loads(file.read_text())
        if not isinstance(data, dict) or len(data) > 50:
            raise ValueError()
        for name, values in data.items():
            if (not text(name, 80) or name == "server" or not isinstance(values, dict)
                    or values.keys() - PROFILE_KEYS or any(not isinstance(v, str) or len(v) > 8192
                                                         or "\0" in v for v in values.values())):
                raise ValueError()
        result.update(data)
    except (OSError, ValueError):
        raise Problem(503, "The server connection profile file is invalid. Check its ownership, permissions and JSON format.") from None
    return result


def command(connection):
    arguments = json.loads(connection["arguments"])
    provider = connection["provider"]
    entry = Path(__file__).with_name("app.py")
    if not entry.exists():
        entry = entry.with_suffix(".pyc")
    action = {"vertex": "sync-vertex", "vsphere": "sync-vsphere"}.get(provider, "sync-" + provider)
    options = arguments
    if provider == "salesforce":
        options = arguments[:2] + (["--api-version", arguments[2]] if len(arguments) == 3 else [])
        if len(arguments) == 3 and int(arguments[2].split(".")[0]) >= 68:
            options += ["--agentforce"]
    elif provider == "vsphere":
        options = arguments[:1] + (["--port", arguments[1]] if len(arguments) == 2 else [])
        ca = profiles()[connection["profile"]].get("DOOFUS_AGENT_VSPHERE_CA") or os.environ.get("DOOFUS_AGENT_VSPHERE_CA")
        if ca:
            options += ["--ca-file", ca]
    elif provider == "aws" and len(arguments) == 3:
        options = arguments[:2] + ["--analyzer", arguments[2]]
    return [sys.executable, "-B", str(entry), "--db", None, action, connection["project"], *options]


class Connections:
    def __init__(self, path, database, audit, stamp):
        self.path, self.database, self.audit, self.stamp = path, database, audit, stamp
        with database(path, write=True) as conn:
            conn.execute("""UPDATE platform_connection_runs SET status='failed',finished_at=?,result=?
                            WHERE status='running'""",
                         (stamp(), '{"error":"Service restarted during this operation. Run the connection again."}'))
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="connection")

    def request(self, method, route, user, body, fields):
        if user["role"] != "admin":
            raise Problem(403, "Project administrator access required.")
        project = user["project"]
        with self.database(self.path, write=method != "GET") as conn:
            if route == "/api/v1/connections" and method == "GET":
                rows = conn.execute("""SELECT * FROM platform_connections WHERE project=? ORDER BY created_at,id""",
                                    (project,)).fetchall()
                return 200, {"connections": [dict(row) | {"arguments": json.loads(row["arguments"])} for row in rows],
                             "profiles": list(profiles()), "requirements": HELP}
            if route == "/api/v1/connections" and method == "POST":
                fields(body, ("name", "provider", "arguments", "profile"))
                if not text(body["name"], 80) or not isinstance(body["profile"], str) or body["profile"] not in profiles():
                    raise Problem(400, "Choose a connection name and configured credential profile.")
                scope, _ = deployment(body["provider"], body["arguments"])
                if conn.execute("""SELECT 1 FROM platform_connections WHERE project=? AND provider=? AND scope=?""",
                                (project, body["provider"], scope)).fetchone():
                    raise Problem(409, "A connection already exists for this provider scope.")
                if conn.execute("SELECT count(*) FROM platform_connections WHERE project=?", (project,)).fetchone()[0] >= 50:
                    raise Problem(409, "This project has reached the 50 connection limit.")
                key = str(uuid4())
                conn.execute("INSERT INTO platform_connections VALUES(?,?,?,?,?,?,?,?)",
                             (key, project, body["name"], body["provider"], scope, json.dumps(body["arguments"]),
                              body["profile"], self.stamp()))
                self.audit(conn, user, "connection.created", key)
                return 201, {"id": key}
            parts = route.removeprefix("/api/v1/connections/").split("/")
            row = conn.execute("SELECT * FROM platform_connections WHERE project=? AND id=?",
                               (project, parts[0])).fetchone()
            if row is None:
                raise Problem(404, "Connection not found.")
            if parts[1:] == ["runs"] and method == "GET":
                rows = conn.execute("""SELECT * FROM platform_connection_runs WHERE connection=?
                                       ORDER BY rowid DESC LIMIT 30""", (row["id"],))
                return 200, {"runs": [dict(run) | {"result": json.loads(run["result"]) if run["result"] else None}
                                     for run in rows]}
            if len(parts) == 1 and method == "DELETE":
                fields(body, ())
                if conn.execute("SELECT 1 FROM platform_connection_runs WHERE connection=? AND status='running'",
                                (row["id"],)).fetchone():
                    raise Problem(409, "Wait for the active scan to finish before removing the connection.")
                conn.execute("DELETE FROM platform_connection_runs WHERE connection=?", (row["id"],))
                conn.execute("DELETE FROM platform_connections WHERE id=?", (row["id"],))
                self.audit(conn, user, "connection.deleted", row["id"])
                return 200, {"deleted": True}
            if parts[1:] not in (["test"], ["scan"]) or method != "POST":
                raise Problem(404, "Connection operation unavailable.")
            fields(body, ())
            if conn.execute("SELECT 1 FROM platform_connection_runs WHERE connection=? AND status='running'",
                            (row["id"],)).fetchone():
                raise Problem(409, "A connection operation is already running.")
            if conn.execute("SELECT count(*) FROM platform_connection_runs WHERE status='running'").fetchone()[0] >= 16:
                raise Problem(429, "The server scan queue is full. Try again after a scan finishes.")
            if row["profile"] not in profiles():
                raise Problem(409, "The configured server credential profile is unavailable.")
            job = str(uuid4())
            conn.execute("INSERT INTO platform_connection_runs VALUES(?,?,?,'running',?,NULL,NULL)",
                         (job, row["id"], parts[1], self.stamp()))
            self.audit(conn, user, "connection." + parts[1] + ".started", row["id"], {"run": job})
        self.executor.submit(self.run, dict(row), job, parts[1], dict(user))
        return 202, {"id": job, "status": "running"}

    def run(self, connection, job, mode, user):
        try:
            environment = os.environ.copy()
            environment.update(profiles()[connection["profile"]])
            argv = command(connection)
            if mode == "test":
                script = ("import json,sys;from agent_protocol import deployment;"
                          "_,collect=deployment(sys.argv[1],json.loads(sys.argv[2]));"
                          "data=collect();print(json.dumps({'reachable':True}))")
                argv = [sys.executable, "-B", "-c", script, connection["provider"], connection["arguments"]]
            else:
                argv[argv.index("--db") + 1] = str(self.path.resolve())
            output = subprocess.run(argv, cwd=Path(__file__).parent, env=environment,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=900, check=False)
            if output.returncode != 0:
                raise ValueError()
            result = json.loads(output.stdout)
            if not isinstance(result, dict):
                raise ValueError()
            status = "completed"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, Problem):
            status = "failed"
            result = {"error": "Connection could not complete. Check provider tools, read permissions, target values and the server credential profile."}
        with self.database(self.path, write=True) as conn:
            conn.execute("UPDATE platform_connection_runs SET status=?,finished_at=?,result=? WHERE id=?",
                         (status, self.stamp(), json.dumps(result), job))
            self.audit(conn, user, "connection." + mode + "." + status, connection["id"], {"run": job})
