"""Project-scoped risk, remediation and defensive telemetry."""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs
from uuid import uuid4

SCHEMA = """
CREATE TABLE graph_nodes (
  project TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, asset TEXT,
  criticality TEXT NOT NULL, public INTEGER NOT NULL,
  PRIMARY KEY(project,id), UNIQUE(project,asset),
  FOREIGN KEY(project,asset) REFERENCES assets(project,id)
);
CREATE TABLE graph_edges (
  project TEXT NOT NULL, origin TEXT NOT NULL, target TEXT NOT NULL, relation TEXT NOT NULL,
  PRIMARY KEY(project,origin,target,relation),
  FOREIGN KEY(project,origin) REFERENCES graph_nodes(project,id),
  FOREIGN KEY(project,target) REFERENCES graph_nodes(project,id)
);
CREATE INDEX graph_target ON graph_edges(project,target);
CREATE TABLE issue_exceptions (
  project TEXT NOT NULL, issue TEXT NOT NULL, id TEXT NOT NULL, reason TEXT NOT NULL,
  approved_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY(project,id), FOREIGN KEY(project,issue) REFERENCES issues(project,id)
);
CREATE INDEX exceptions_issue ON issue_exceptions(project,issue,expires_at);
CREATE TABLE runtime_findings (
  seq INTEGER PRIMARY KEY, project TEXT NOT NULL, source TEXT NOT NULL, event_id TEXT NOT NULL,
  node TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
  observed_at TEXT NOT NULL, received_at TEXT NOT NULL, received_by TEXT NOT NULL,
  UNIQUE(project,source,event_id), FOREIGN KEY(project,node) REFERENCES graph_nodes(project,id)
);
CREATE INDEX runtime_findings_project ON runtime_findings(project,seq DESC);
ALTER TABLE audit ADD COLUMN details TEXT;
CREATE INDEX audit_project_cursor ON audit(project,seq);
"""
RUNTIME_TARGET_SCHEMA = """
CREATE TABLE runtime_findings_next (
  seq INTEGER PRIMARY KEY, project TEXT NOT NULL, source TEXT NOT NULL, event_id TEXT NOT NULL,
  node TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
  observed_at TEXT NOT NULL, received_at TEXT NOT NULL, received_by TEXT NOT NULL,
  node_source TEXT NOT NULL CHECK(node_source IN ('declared','cloud')),
  UNIQUE(project,source,event_id)
);
INSERT INTO runtime_findings_next SELECT runtime_findings.*,'declared' FROM runtime_findings;
DROP TABLE runtime_findings;
ALTER TABLE runtime_findings_next RENAME TO runtime_findings;
CREATE INDEX runtime_findings_project ON runtime_findings(project,seq DESC);
"""

KINDS = {"model", "identity", "endpoint", "data", "agent"}
RELATIONS = {
    "serves": ("endpoint", "model"),
    "uses_identity": ("endpoint", "identity"),
    "reads_data": ("model", "data"),
    "can_access": ("identity", "data"),
}
CRITICALITY = {"low": 0, "medium": 10, "high": 25, "critical": 40}
CATEGORIES = {"guardrail_block", "sensitive_data_detection", "policy_violation", "identity_alert"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}

PUBLIC_NODES = """
WITH RECURSIVE reach(id) AS (
  SELECT id FROM graph_nodes WHERE project=? AND kind='endpoint' AND public=1
  UNION
  SELECT e.target FROM graph_edges e JOIN reach r ON e.origin=r.id WHERE e.project=?
)
SELECT id FROM reach
"""
CLOUD_CONTEXT = """
WITH RECURSIVE reach(scope,id) AS (
  SELECT scope,id FROM cloud_graph_nodes
  WHERE project=? AND (exposure='public_network_configuration' OR exposure='analyzer_external_access')
  UNION
  SELECT e.scope,e.target FROM cloud_graph_edges e
  JOIN reach r ON e.scope=r.scope AND e.origin=r.id WHERE e.project=?
)
SELECT n.id,n.kind,n.name,n.scope,n.sensitivity,n.profile_observed,
       r.id IS NOT NULL AS exposed FROM cloud_graph_nodes n
LEFT JOIN reach r ON r.scope=n.scope AND r.id=n.id WHERE n.project=?
"""


class Problem(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def utc(value=None):
    return (value or datetime.now(timezone.utc)).isoformat(timespec="milliseconds")


def parse_time(value):
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.utcoffset() is None:
            raise ValueError()
        return value.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise Problem(400, "Use an ISO 8601 timestamp with a time zone.") from None


def protect_admin(user):
    if user["role"] != "admin":
        raise Problem(403, "Project administrator access required.")


def graph_route(conn, project, route, method, body, fields, identifier):
    table = "graph_nodes" if route.endswith("/nodes") else "graph_edges"
    if method == "GET":
        order = "id" if table == "graph_nodes" else "origin,target,relation"
        records = conn.execute(
            f"SELECT * FROM {table} WHERE project=? ORDER BY {order}", (project,)
        )
        key = "nodes" if table == "graph_nodes" else "edges"
        return 200, {key: [dict(record) for record in records]}
    if table == "graph_nodes":
        fields(body, ("id", "kind", "asset", "criticality", "public"))
        node, kind, asset = identifier(body["id"]), body["kind"], body["asset"]
        criticality, public = body["criticality"], body["public"]
        if not isinstance(kind, str) or kind not in KINDS:
            raise Problem(400, "Unsupported relationship node kind.")
        if not isinstance(criticality, str) or criticality not in CRITICALITY:
            raise Problem(400, "Unsupported criticality.")
        if type(public) is not bool or (public and kind != "endpoint"):
            raise Problem(400, "Public must be Boolean and can only be true for endpoints.")
        existing = conn.execute(
            "SELECT kind FROM graph_nodes WHERE project=? AND id=?", (project, node)
        ).fetchone()
        if node.startswith(("vertex:", "aws:", "azure:", "vsphere:", "oci:", "ibm:", "salesforce:")) and existing is None:
            raise Problem(409, "This node identifier is reserved for discovered cloud assets.")
        if existing is not None and existing["kind"] != kind:
            raise Problem(409, "An existing relationship node cannot change kind.")
        if existing is None and conn.execute(
            "SELECT COUNT(*) FROM graph_nodes WHERE project=?", (project,)
        ).fetchone()[0] >= 500:
            raise Problem(409, "Project relationship inventory is full (500 nodes).")
        if asset is not None:
            identifier(asset)
            if conn.execute("SELECT 1 FROM assets WHERE project=? AND id=?",
                            (project, asset)).fetchone() is None:
                raise Problem(404, "Linked asset not found.")
            if conn.execute("SELECT 1 FROM graph_nodes WHERE project=? AND asset=? AND id<>?",
                            (project, asset, node)).fetchone():
                raise Problem(409, "Asset is already linked to another relationship node.")
        conn.execute(
            """INSERT INTO graph_nodes VALUES(?,?,?,?,?,?) ON CONFLICT(project,id)
               DO UPDATE SET asset=excluded.asset,criticality=excluded.criticality,public=excluded.public""",
            (project, node, kind, asset, criticality, public),
        )
        return 200, body
    fields(body, ("origin", "target", "relation"))
    origin, target, relation = identifier(body["origin"]), identifier(body["target"]), body["relation"]
    if not isinstance(relation, str) or relation not in RELATIONS:
        raise Problem(400, "Unsupported relationship.")
    kinds = {row["id"]: row["kind"] for row in conn.execute(
        "SELECT id,kind FROM graph_nodes WHERE project=? AND id IN (?,?)", (project, origin, target)
    )}
    if origin not in kinds or target not in kinds:
        raise Problem(404, "Relationship node not found.")
    if (kinds[origin], kinds[target]) != RELATIONS[relation]:
        raise Problem(400, "Relationship does not support the specified node kinds.")
    if method == "DELETE":
        conn.execute("DELETE FROM graph_edges WHERE project=? AND origin=? AND target=? AND relation=?",
                     (project, origin, target, relation))
    else:
        if conn.execute("SELECT COUNT(*) FROM graph_edges WHERE project=?", (project,)).fetchone()[0] >= 5000:
            if conn.execute(
                "SELECT 1 FROM graph_edges WHERE project=? AND origin=? AND target=? AND relation=?",
                (project, origin, target, relation),
            ).fetchone() is None:
                raise Problem(409, "Project relationship inventory is full (5,000 edges).")
        conn.execute("INSERT OR IGNORE INTO graph_edges VALUES(?,?,?,?)",
                     (project, origin, target, relation))
    return 200, body


def prioritize(conn, project, rows, checks):
    exposed = {row["id"] for row in conn.execute(PUBLIC_NODES, (project, project))}
    assets = {row["asset"]: row for row in conn.execute(
        "SELECT * FROM graph_nodes WHERE project=? AND asset IS NOT NULL", (project,)
    )}
    storage = {(row["source_project"], row["name"]): row["asset"] for row in conn.execute(
        """SELECT asset,source_project,name FROM cloud_assets
           WHERE project=? AND provider='gcs' AND active=1""", (project,)
    )}
    cloud = {}
    cutoff = utc(datetime.now(timezone.utc) - timedelta(days=30))
    for observed in conn.execute(CLOUD_CONTEXT, (project, project, project)):
        asset = observed["id"] if observed["kind"] in ("endpoint", "identity", "host", "virtual_machine") else None
        if observed["kind"] == "data" and observed["scope"].count(":") == 1:
            asset = storage.get((observed["scope"].split(":", 1)[0], observed["name"]))
        if asset is None:
            continue
        context = cloud.setdefault(asset, {"exposure": 0, "sensitivity": 0})
        context["exposure"] = max(context["exposure"], 20 if observed["exposed"] else 0)
        if observed["profile_observed"] and observed["profile_observed"] >= cutoff:
            context["sensitivity"] = max(context["sensitivity"],
                                         {"high": 20, "moderate": 10}.get(observed["sensitivity"], 0))
    active = {}
    for row in conn.execute(
        """SELECT issue,id,expires_at FROM issue_exceptions
           WHERE project=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at,id""",
        (project, utc()),
    ):
        active[row["issue"]] = {"id": row["id"], "expires_at": row["expires_at"]}
    issues = []
    for row in rows:
        issue = dict(row)
        node = assets.get(row["asset"])
        context = cloud.get(row["asset"])
        base = next((check[4] for check in checks.get(row["kind"], ()) if check[0] == row["check_id"]), 0)
        scan = conn.execute("SELECT result FROM scans WHERE project=? AND id=?", (project, row["last_scan"])).fetchone()
        if scan:
            outcome = next((o for o in json.loads(scan["result"])["outcomes"] if o["check"] == row["check_id"]), None)
            if outcome and "policy_weight" in outcome:
                base = outcome["policy_weight"]
        criticality = CRITICALITY[node["criticality"]] if node else 0
        exposure = 20 if node and node["id"] in exposed else 0
        if context:
            exposure = max(exposure, context["exposure"])
        sensitivity = context["sensitivity"] if context else 0
        issue["risk"] = {
            "score": min(100, base + criticality + exposure + sensitivity),
            "policy_weight": base, "criticality_weight": criticality, "exposure_weight": exposure,
            "sensitivity_weight": sensitivity,
            "evidence": ("cloud-metadata" if context else
                         "declared-relationships" if node else "policy-only"),
        }
        issue["active_exception"] = active.get(row["id"])
        issues.append(issue)
    return sorted(issues, key=lambda item: (item["active_exception"] is not None,
                                          -item["risk"]["score"], item["id"]))


def exception_route(conn, user, issue, method, body, fields):
    project = user["project"]
    if conn.execute("SELECT 1 FROM issues WHERE project=? AND id=?",
                    (project, issue)).fetchone() is None:
        raise Problem(404, "Issue not found.")
    if method == "GET":
        rows = conn.execute(
            "SELECT * FROM issue_exceptions WHERE project=? AND issue=? ORDER BY rowid DESC LIMIT 100",
            (project, issue),
        )
        return 200, {"exceptions": [dict(row) for row in rows]}
    protect_admin(user)
    if method == "DELETE":
        fields(body, ("id",))
        changed = conn.execute(
            "UPDATE issue_exceptions SET revoked_at=? WHERE project=? AND issue=? AND id=? AND revoked_at IS NULL",
            (utc(), project, issue, body["id"] if isinstance(body["id"], str) else ""),
        ).rowcount
        if not changed:
            raise Problem(404, "Active exception record not found.")
        return 200, {"id": body["id"], "status": "revoked"}
    fields(body, ("reason", "expires_at"))
    reason = body["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500 or not reason.isprintable():
        raise Problem(400, "Enter a printable reason of 1–500 characters.")
    now, expires = datetime.now(timezone.utc), parse_time(body["expires_at"])
    if not now < expires <= now + timedelta(days=90):
        raise Problem(400, "Exception expiration must be in the next 90 days.")
    if conn.execute(
        """SELECT 1 FROM issue_exceptions WHERE project=? AND issue=?
           AND revoked_at IS NULL AND expires_at>?""", (project, issue, utc(now))
    ).fetchone():
        raise Problem(409, "Revoke the current exception before adding another.")
    record = {"id": str(uuid4()), "reason": reason, "expires_at": utc(expires)}
    conn.execute(
        "INSERT INTO issue_exceptions VALUES(?,?,?,?,?,?,?,NULL)",
        (project, issue, record["id"], reason, user["principal"], utc(now), record["expires_at"]),
    )
    return 201, record


def runtime_route(conn, user, method, body, fields, identifier):
    project = user["project"]
    if method == "GET":
        rows = conn.execute("SELECT * FROM runtime_findings WHERE project=? ORDER BY seq DESC LIMIT 100",
                            (project,))
        return 200, {"findings": [dict(row) for row in rows]}
    fields(body, ("source", "event_id", "node", "category", "severity", "observed_at"))
    source, event, node = (identifier(body[key]) for key in ("source", "event_id", "node"))
    category, severity = body["category"], body["severity"]
    if (not isinstance(category, str) or category not in CATEGORIES or
            not isinstance(severity, str) or severity not in SEVERITIES):
        raise Problem(400, "Unsupported runtime finding category or severity.")
    observed_at = parse_time(body["observed_at"])
    if observed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise Problem(400, "Observation timestamp is in the future.")
    fields_from_sender = (node, category, severity, utc(observed_at))
    existing = conn.execute("SELECT * FROM runtime_findings WHERE project=? AND source=? AND event_id=?",
                            (project, source, event)).fetchone()
    if existing is not None:
        if tuple(existing[field] for field in ("node", "category", "severity", "observed_at")) != fields_from_sender:
            raise Problem(409, "Event ID already exists with different evidence.")
        return 200, {"sequence": existing["seq"]}
    target = conn.execute(
        """SELECT 'declared' AS source FROM graph_nodes WHERE project=? AND id=?
           UNION ALL SELECT 'cloud' FROM cloud_graph_nodes WHERE project=? AND id=? LIMIT 1""",
        (project, node, project, node),
    ).fetchone()
    if target is None:
        raise Problem(404, "Runtime finding node not found.")
    result = conn.execute(
        """INSERT INTO runtime_findings(project,source,event_id,node,category,severity,
           observed_at,received_at,received_by,node_source) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (project, source, event, *fields_from_sender, utc(), user["principal"], target["source"]),
    )
    return 201, {"sequence": result.lastrowid}


def event_feed(conn, user, query):
    protect_admin(user)
    after = parse_qs(query, keep_blank_values=True).get("after", ["0"])
    if (len(after) != 1 or not after[0].isascii() or not after[0].isdecimal()
            or len(after[0]) > 19 or int(after[0]) > 2**63 - 1):
        raise Problem(400, "Use a valid nonnegative event cursor.")
    rows = conn.execute(
        "SELECT * FROM audit WHERE project=? AND seq>? ORDER BY seq LIMIT 501",
        (user["project"], int(after[0])),
    ).fetchall()
    events = [dict(row) | {"details": json.loads(row["details"]) if row["details"] else None}
              for row in rows[:500]]
    stream = conn.execute("SELECT id FROM event_stream WHERE singleton=1").fetchone()["id"]
    return 200, {"stream_id": stream, "events": events, "next_after": events[-1]["seq"] if events else int(after[0]),
                 "has_more": len(rows) > 500}
