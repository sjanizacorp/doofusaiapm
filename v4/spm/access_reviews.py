"""Project-scoped access review history and comparisons."""
import json

from controls import Problem

SCHEMA = """
CREATE TABLE access_reviews (
  project TEXT NOT NULL, id TEXT NOT NULL, asset TEXT NOT NULL, scope TEXT NOT NULL, provider TEXT NOT NULL,
  principal TEXT NOT NULL, resource TEXT NOT NULL,
  inventory_observed_at TEXT NOT NULL, evaluated_at TEXT NOT NULL, decisions TEXT NOT NULL,
  PRIMARY KEY(project,id)
);
CREATE INDEX access_reviews_asset ON access_reviews(project,asset,evaluated_at DESC,id);
"""

def load(conn, project, review_id):
    row = conn.execute("SELECT rowid AS sequence,* FROM access_reviews WHERE project=? AND id=?",
                       (project, review_id)).fetchone()
    if row is None:
        raise Problem(404, "Access review not found.")
    return row


def inventory_changed(conn, review):
    inventory = conn.execute(
        """SELECT last_seen FROM cloud_assets WHERE project=? AND provider=? AND source_project=?
           AND asset=? AND active=1""",
        (review["project"], review["provider"], review["scope"], review["asset"]),
    ).fetchone()
    return inventory is None or inventory["last_seen"] != review["inventory_observed_at"]


def detail(conn, review):
    previous = conn.execute(
        """SELECT id,evaluated_at FROM access_reviews WHERE project=? AND asset=? AND scope=?
           AND provider=? AND principal=? AND resource=? AND rowid<? ORDER BY rowid DESC LIMIT 20""",
        tuple(review[key] for key in ("project", "asset", "scope", "provider", "principal", "resource", "sequence")),
    )
    return ({key: review[key] for key in review.keys() if key != "sequence"} | {
        "decisions": json.loads(review["decisions"]),
        "mode": {"aws": "aws-iam-policy-simulation", "vsphere": "vcenter-privilege-check",
                 "gcs": ("google-iam-policy-troubleshooter" if review["principal"].startswith("google-account:")
                         else "google-storage-caller-permissions")}[review["provider"]],
        "inventory_changed": inventory_changed(conn, review),
        "prior_reviews": [dict(row) for row in previous],
    })


def compare(conn, review, baseline_id):
    baseline = load(conn, review["project"], baseline_id)
    fields = ("asset", "scope", "provider", "principal", "resource")
    if (baseline["sequence"] >= review["sequence"]
            or any(baseline[key] != review[key] for key in fields)):
        raise Problem(409, "Choose an earlier review for the same provider, principal and resource.")

    def indexed(record):
        operations = json.loads(record["decisions"])
        return {(entry["action"].lower() if review["provider"] == "aws" else entry["action"]): entry
                for entry in operations}

    before, after = indexed(baseline), indexed(review)
    if before.keys() != after.keys():
        raise Problem(409, "Reviews must use the same set of actions or privileges.")
    transitions = []
    for key, current in after.items():
        if before[key].get("condition_receive_time") != current.get("condition_receive_time"):
            raise Problem(409, "Compare reviews recorded with the same request time context.")
        old, new = before[key]["decision"], current["decision"]
        if "indeterminate" in (old, new):
            category = "inconclusive"
        elif old == new:
            category = "unchanged"
        elif old == "allowed":
            category = "access-removed"
        elif new == "allowed":
            category = "access-added"
        else:
            category = "denial-changed"
        transitions.append({"action": current["action"], "before": old, "after": new,
                            "change": category})
    return {"baseline": baseline_id, "review": review["id"], "provider": review["provider"],
            "review_evaluated_at": review["evaluated_at"],
            "inventory_changed": inventory_changed(conn, review), "transitions": transitions}
