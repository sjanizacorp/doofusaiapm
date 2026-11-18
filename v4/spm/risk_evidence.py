"""Explain the observed or declared topology behind an issue's risk score."""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import json

from controls import Problem, parse_time


def shortest_path(nodes, edges, roots, target):
    if target not in nodes:
        return None
    parents = {origin: (None, None) for origin in sorted(roots)}
    queue = deque(parents)
    while queue:
        current = queue.popleft()
        if current == target:
            break
        for child, relation in edges.get(current, ()):
            if child in nodes and child not in parents:
                parents[child] = (current, relation)
                queue.append(child)
    if target not in parents:
        return None
    path = []
    current = target
    while current is not None:
        parent, relation = parents[current]
        path.append(dict(nodes[current]) | {"via": relation})
        current = parent
    return list(reversed(path))


def cloud_targets(conn, project, asset):
    source = conn.execute(
        "SELECT provider,source_project,name,active FROM cloud_assets WHERE project=? AND asset=?",
        (project, asset),
    ).fetchone()
    if source is None or not source["active"]:
        return []
    if source["provider"] != "gcs":
        return [(source["source_project"], asset)]
    rows = conn.execute(
        """SELECT scope,id FROM cloud_graph_nodes WHERE project=? AND kind='data' AND name=?
           AND substr(scope,1,instr(scope,':')-1)=? ORDER BY scope,id""",
        (project, source["name"], source["source_project"]),
    )
    # Only the Vertex collector links GCS storage by bucket name within its source project.
    return [(row["scope"], row["id"]) for row in rows if row["scope"].count(":") == 1]


def explain(conn, project, asset, *, now=None):
    now = now or datetime.now(timezone.utc)
    result = {"declared_path": None, "cloud_paths": [], "interpretation": "configuration-relationships"}
    target = conn.execute("SELECT id FROM graph_nodes WHERE project=? AND asset=?", (project, asset)).fetchone()
    if target:
        declared = {row["id"]: row for row in conn.execute(
            "SELECT id,kind,public FROM graph_nodes WHERE project=? ORDER BY id", (project,)
        )}
        edges = defaultdict(list)
        for row in conn.execute(
            "SELECT origin,target,relation FROM graph_edges WHERE project=? ORDER BY origin,target,relation", (project,),
        ):
            edges[row["origin"]].append((row["target"], row["relation"]))
        roots = [key for key, row in declared.items() if row["kind"] == "endpoint" and row["public"]]
        result["declared_path"] = shortest_path(declared, edges, roots, target["id"])

    for scope, node_id in cloud_targets(conn, project, asset)[:25]:
        nodes = {row["id"]: row for row in conn.execute(
            """SELECT id,kind,name,exposure,sensitivity,profile_observed,observed_at
               FROM cloud_graph_nodes WHERE project=? AND scope=? ORDER BY id""", (project, scope),
        )}
        if node_id not in nodes:
            continue
        edges = defaultdict(list)
        for edge in conn.execute(
            """SELECT origin,target,relation FROM cloud_graph_edges WHERE project=? AND scope=?
               ORDER BY origin,target,relation""", (project, scope),
        ):
            edges[edge["origin"]].append((edge["target"], edge["relation"]))
        roots = [key for key, item in nodes.items()
                 if item["exposure"] in ("public_network_configuration", "analyzer_external_access")]
        path = shortest_path(nodes, edges, roots, node_id)
        latest = conn.execute(
            """SELECT id,provider,status,finished_at FROM sync_runs WHERE project=? AND source_project=?
               ORDER BY rowid DESC LIMIT 1""", (project, scope),
        ).fetchone()
        item = nodes[node_id]
        stale = now - parse_time(item["observed_at"]) > timedelta(hours=72)
        result["cloud_paths"].append({
            "scope": scope, "path": path,
            "target_sensitivity": item["sensitivity"], "profile_observed": item["profile_observed"],
            "observed_at": item["observed_at"],
            "freshness": "stale" if stale else "degraded" if latest and latest["status"] == "failed" else "recent",
            "latest_sync": dict(latest) if latest else None,
        })
    return result


def remediation_proof(conn, project, issue):
    record = conn.execute("SELECT * FROM issues WHERE project=? AND id=?", (project, issue)).fetchone()
    if record is None:
        raise Problem(404, "Issue not found.")
    if record["status"] != "resolved" or record["last_outcome"] != "pass":
        return {"verified": False, "reason": "latest-assessment-does-not-confirm-remediation"}
    active = conn.execute(
        "SELECT provider,source_project,active FROM cloud_assets WHERE project=? AND asset=?",
        (project, record["asset"]),
    ).fetchone()
    if active is None or not active["active"]:
        return {"verified": False, "reason": "source-asset-not-active"}
    before = conn.execute(
        """SELECT scan FROM issue_events WHERE project=? AND issue=? AND outcome='finding'
           ORDER BY seq DESC LIMIT 1""", (project, issue),
    ).fetchone()
    if before is None:
        return {"verified": False, "reason": "baseline-finding-missing"}
    assessments = []
    for scan_id in (before["scan"], record["last_scan"]):
        scan = conn.execute(
            "SELECT snapshot,result FROM scans WHERE project=? AND asset=? AND id=?",
            (project, record["asset"], scan_id),
        ).fetchone()
        if scan is None:
            return {"verified": False, "reason": "assessment-evidence-missing"}
        snapshot, result = json.loads(scan["snapshot"]), json.loads(scan["result"])
        sync_id = snapshot.get("evidence", {}).get("sync_id")
        run = conn.execute(
            """SELECT id,provider,source_project,status,finished_at FROM sync_runs
               WHERE project=? AND id=?""", (project, sync_id),
        ).fetchone()
        outcome = next((outcome for outcome in result["outcomes"] if outcome["check"] == record["check_id"]), None)
        if (run is None or run["status"] != "completed" or outcome is None
                or run["provider"] != active["provider"] or run["source_project"] != active["source_project"]):
            return {"verified": False, "reason": "completed-source-evidence-missing"}
        assessments.append({"id": scan_id, "sync": dict(run), "control": outcome,
                            "policy_version": result["policy_version"]})
    first, last = assessments
    baseline, verified = first["control"], last["control"]
    if (first["sync"]["id"] == last["sync"]["id"] or first["policy_version"] != last["policy_version"]
            or first["sync"]["finished_at"] > last["sync"]["finished_at"]
            or baseline["field"] != verified["field"] or baseline["expected"] != verified["expected"]
            or baseline["status"] != "finding" or verified["status"] != "pass"):
        return {"verified": False, "reason": "assessments-not-comparable"}
    latest = conn.execute(
        """SELECT id,status FROM sync_runs WHERE project=? AND provider=? AND source_project=?
           ORDER BY rowid DESC LIMIT 1""", (project, active["provider"], active["source_project"]),
    ).fetchone()
    if latest is None or latest["status"] != "completed" or latest["id"] != last["sync"]["id"]:
        return {"verified": False, "reason": "latest-source-sync-did-not-confirm-the-control"}
    return {"verified": True, "issue": issue, "asset": record["asset"], "check": record["check_id"],
            "before": first, "after": last}
