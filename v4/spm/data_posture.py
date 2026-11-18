"""Project-scoped classification and evidence correlation."""
import json
from datetime import datetime, timedelta, timezone

from controls import Problem, parse_time

SCHEMA = """
CREATE TABLE data_labels (
    project TEXT NOT NULL, scope TEXT NOT NULL, node TEXT NOT NULL,
    sensitivity TEXT NOT NULL, observed_at TEXT NOT NULL, recorded_by TEXT NOT NULL,
    PRIMARY KEY(project,scope,node)
);
"""

CONTENT_SCHEMA = """
CREATE TABLE data_content_samples (
    project TEXT NOT NULL, scope TEXT NOT NULL, node TEXT NOT NULL, object_digest TEXT NOT NULL,
    inventory_at TEXT NOT NULL, sampled_at TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY(project,scope,node,object_digest)
);
CREATE INDEX data_content_samples_time
ON data_content_samples(project,scope,node,inventory_at,sampled_at DESC);
"""


def record(conn, user, body, fields, identifier, timestamp):
    fields(body, ("node", "sensitivity"))
    node, level = identifier(body["node"]), body["sensitivity"]
    if level not in ("low", "moderate", "high", "unknown"):
        raise Problem(400, "Use a supported sensitivity level.")
    rows = conn.execute("SELECT scope FROM cloud_graph_nodes WHERE project=? AND id=? AND kind='data'",
                        (user["project"], node)).fetchall()
    if len(rows) != 1:
        raise Problem(404, "Use a discovered data node in this project.")
    scope, observed = rows[0]["scope"], timestamp()
    conn.execute("""INSERT INTO data_labels VALUES(?,?,?,?,?,?)
                 ON CONFLICT(project,scope,node) DO UPDATE SET sensitivity=excluded.sensitivity,
                 observed_at=excluded.observed_at,recorded_by=excluded.recorded_by""",
                 (user["project"], scope, node, level, observed, user["principal"]))
    return {"node": node, "scope": scope, "sensitivity": level, "observed_at": observed}


REPORT = """
WITH RECURSIVE exposure(scope,node) AS (
    SELECT scope,id FROM cloud_graph_nodes WHERE project=?
      AND exposure IN ('public_network_configuration','analyzer_external_access')
    UNION
    SELECT e.scope,e.target FROM cloud_graph_edges e JOIN exposure p
      ON e.scope=p.scope AND e.origin=p.node WHERE e.project=?
)
SELECT n.id,n.scope,n.name,n.resource,n.observed_at,l.sensitivity AS operator_sensitivity,
       l.observed_at AS operator_observed_at,n.sensitivity AS provider_sensitivity,n.profile_observed,
       (e.node IS NOT NULL) AS configuration_path,
       (SELECT status FROM sync_runs s WHERE s.project=n.project AND s.source_project=n.scope
        ORDER BY rowid DESC LIMIT 1) AS latest_sync_status
FROM cloud_graph_nodes n LEFT JOIN exposure e ON e.scope=n.scope AND e.node=n.id
LEFT JOIN data_labels l ON l.project=n.project AND l.scope=n.scope AND l.node=n.id
WHERE n.project=? AND n.kind='data' AND n.id>? ORDER BY n.id LIMIT 101
"""


def report(conn, project, after):
    data = [dict(row) for row in conn.execute(REPORT, (project, project, project, after))]
    cutoff = datetime.now(timezone.utc) - timedelta(hours=72)
    for item in data[:100]:
        candidates = conn.execute(
            """WITH reviews AS (
                SELECT r.id,r.provider,r.principal,r.evaluated_at,
                       json_extract(d.value,'$.action') AS action,
                       json_extract(d.value,'$.decision') AS decision,
                       row_number() OVER (PARTITION BY r.provider,r.principal,r.resource,
                         CASE WHEN r.provider='aws' THEN lower(json_extract(d.value,'$.action'))
                              ELSE json_extract(d.value,'$.action') END
                         ORDER BY r.rowid DESC) AS rank
                FROM access_reviews r JOIN cloud_assets a ON a.project=r.project AND a.asset=r.asset
                AND a.provider=r.provider AND a.source_project=r.scope AND a.active=1
                AND a.last_seen=r.inventory_observed_at
                JOIN json_each(r.decisions) d
                WHERE r.project=? AND json_type(d.value,'$.condition_receive_time') IS NULL
                  AND ((r.scope=? AND r.resource=?)
                  OR (r.provider='gcs' AND r.resource=?
                      AND a.source_project=substr(?,1,instr(?,':')-1)
                      AND EXISTS (SELECT 1 FROM sync_runs s WHERE s.project=r.project
                          AND s.provider='vertex' AND s.source_project=? AND s.status='completed')))
            )
            SELECT id,provider,principal,evaluated_at,action,decision FROM reviews
            WHERE rank=1 ORDER BY evaluated_at DESC,id,action LIMIT 101""",
            (project, item["scope"], item["resource"],
             "gs://" + item["name"] if item["resource"] == "bucket:" + item["name"] else "",
             item["scope"], item["scope"], item["scope"]),
        ).fetchall()
        matches = {}
        for row in candidates[:100]:
            evidence = matches.setdefault(row["id"], {
                **{key: row[key] for key in ("id", "provider", "principal", "evaluated_at")},
                "freshness": "stale" if parse_time(row["evaluated_at"]) < cutoff else "recent",
                "decisions": [],
            })
            evidence["decisions"].append({"action": row["action"], "decision": row["decision"]})
        item["access_evidence"] = list(matches.values())
        item["access_evidence_truncated"] = len(candidates) > 100
        sample = conn.execute(
            """SELECT sampled_at,result FROM data_content_samples WHERE project=? AND scope=? AND node=?
               AND inventory_at=? ORDER BY sampled_at DESC,object_digest LIMIT 1""",
            (project, item["scope"], item["id"], item["observed_at"]),
        ).fetchone()
        item["latest_content_sample"] = (json.loads(sample["result"]) | {"sampled_at": sample["sampled_at"]}
                                         if sample else None)
        distribution = conn.execute(
            """SELECT json_extract(result,'$.sensitivity') AS sensitivity, count(*) AS samples
               FROM data_content_samples WHERE project=? AND scope=? AND node=? AND inventory_at=?
               GROUP BY sensitivity""",
            (project, item["scope"], item["id"], item["observed_at"]),
        )
        item["content_sample_counts"] = {row["sensitivity"]: row["samples"] for row in distribution}
        item["configuration_path"] = bool(item["configuration_path"])
        if item["latest_sync_status"] == "failed":
            item["configuration_freshness"] = "degraded"
        else:
            item["configuration_freshness"] = (
                "stale" if parse_time(item["observed_at"]) < cutoff else "recent"
            )
    return {"data": data[:100]} | ({"next_after": data[99]["id"]} if len(data) > 100 else {})
