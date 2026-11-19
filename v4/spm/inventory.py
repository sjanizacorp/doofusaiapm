"""Project-scoped object sets with complete collected graph inventory and evidence."""
import hashlib
import json
from urllib.parse import parse_qs

from controls import Problem

PAGE = 100


def set_id(provider, scope):
    return "scope:" + hashlib.sha256((provider + "\0" + scope).encode()).hexdigest()


def sets(conn, project):
    sources = conn.execute("""
        SELECT provider,scope,name,0 AS priority FROM platform_connections WHERE project=?
        UNION ALL SELECT provider,scope,name,1 FROM collection_agents WHERE project=? AND revoked_at IS NULL
        UNION ALL SELECT provider,source_project,NULL,2 FROM sync_runs WHERE project=?
        UNION ALL SELECT provider,source_project,NULL,3 FROM cloud_assets WHERE project=?
        ORDER BY priority,name
    """, (project,) * 4)
    indexed = {}
    for source in sources:
        key = set_id(source["provider"], source["scope"])
        if key not in indexed:
            indexed[key] = {"id": key, "name": source["name"] or source["provider"].upper() + " · " + source["scope"],
                            "provider": source["provider"], "scope": source["scope"]}
    return [{"id": "all", "name": "All inventoried objects", "provider": None, "scope": None},
            {"id": "manual", "name": "Manually entered assets", "provider": None, "scope": None},
            *sorted(indexed.values(), key=lambda item: (item["name"].lower(), item["id"]))]


OBJECTS = """
SELECT n.id,n.kind,n.name,n.resource,n.scope,n.observed_at,
       a.facts,a.evidence,n.exposure,n.sensitivity,n.profile_observed,1 AS active
FROM cloud_graph_nodes n LEFT JOIN assets a ON a.project=n.project AND a.id=n.id
WHERE n.project=? AND (? IS NULL OR n.scope=?)
UNION ALL
SELECT a.id,a.kind,coalesce(c.name,a.id),coalesce(json_extract(a.evidence,'$.cloud_resource'),c.name,a.id),
       c.source_project,coalesce(c.last_seen,a.updated_at),a.facts,a.evidence,NULL,NULL,NULL,
       coalesce(c.active,1)
FROM assets a LEFT JOIN cloud_assets c ON c.project=a.project AND c.asset=a.id
WHERE a.project=? AND (? IS NULL OR c.source_project=?)
  AND NOT EXISTS (SELECT 1 FROM cloud_graph_nodes n WHERE n.project=a.project AND n.id=a.id)
"""


def objects(conn, project, query):
    params = parse_qs(query, keep_blank_values=True)
    if set(params) - {"set", "after", "object"} or any(len(value) != 1 for value in params.values()):
        raise Problem(400, "Supply one set and an optional cursor or object ID.")
    selected = params.get("set", ["all"])[0]
    choices = sets(conn, project)
    group = next((item for item in choices if item["id"] == selected), None)
    if group is None:
        raise Problem(404, "Inventory object set not found.")
    scope = group["scope"]
    manual = selected == "manual"
    after = params.get("after", [""])[0]
    object_id = params.get("object", [None])[0]
    if len(after) > 300 or object_id is not None and len(object_id) > 300:
        raise Problem(400, "Inventory identifier exceeds supported limits.")
    condition = "scope IS NULL" if manual else "1=1"
    if object_id:
        condition += " AND id=?"
        tail = (object_id,)
    else:
        condition += " AND id>?"
        tail = (after,)
    rows = conn.execute(f"SELECT * FROM ({OBJECTS}) WHERE {condition} ORDER BY id LIMIT ?",
                        (project, scope, scope, project, scope, scope, *tail, PAGE + 1)).fetchall()
    result = []
    for row in rows[:PAGE]:
        item = dict(row)
        item["facts"] = json.loads(item["facts"]) if item["facts"] else {}
        item["evidence"] = json.loads(item["evidence"]) if item["evidence"] else {}
        item["active"] = bool(item["active"])
        item["provider"] = group["provider"]
        if selected == "all" and item["scope"] is not None:
            source = conn.execute("""SELECT provider FROM sync_runs WHERE project=? AND source_project=?
                                     ORDER BY rowid DESC LIMIT 1""", (project, item["scope"])).fetchone()
            item["provider"] = source["provider"] if source else None
        scan = conn.execute("""SELECT id,created_at,result FROM scans WHERE project=? AND asset=?
                               ORDER BY rowid DESC LIMIT 1""", (project, item["id"])).fetchone()
        item["assessment"] = ({"id": scan["id"], "created_at": scan["created_at"],
                               "result": json.loads(scan["result"])} if scan else None)
        result.append(item)
    if object_id:
        if not result:
            raise Problem(404, "Object not found in the selected inventory set.")
        item = result[0]
        edges = conn.execute("""
            SELECT e.origin,e.target,e.relation,o.name AS origin_name,t.name AS target_name
            FROM cloud_graph_edges e
            JOIN cloud_graph_nodes o ON o.project=e.project AND o.scope=e.scope AND o.id=e.origin
            JOIN cloud_graph_nodes t ON t.project=e.project AND t.scope=e.scope AND t.id=e.target
            WHERE e.project=? AND e.scope=? AND (e.origin=? OR e.target=?)
            ORDER BY e.relation,e.origin,e.target LIMIT 501
        """, (project, item["scope"], object_id, object_id)).fetchall()
        item["relationships"] = [dict(edge) for edge in edges[:500]]
        item["relationships_truncated"] = len(edges) > 500
        latest = conn.execute("""SELECT provider,status,finished_at,error FROM sync_runs
                                 WHERE project=? AND source_project=? ORDER BY rowid DESC LIMIT 1""",
                              (project, item["scope"])).fetchone()
        item["latest_collection"] = dict(latest) if latest else None
        return {"object": item, "set": group}
    total = conn.execute(f"SELECT count(*) FROM ({OBJECTS}) WHERE " + ("scope IS NULL" if manual else "1=1"),
                         (project, scope, scope, project, scope, scope)).fetchone()[0]
    return {"objects": result, "set": group, "total": total,
            **({"next_after": result[-1]["id"]} if len(rows) > PAGE else {})}
