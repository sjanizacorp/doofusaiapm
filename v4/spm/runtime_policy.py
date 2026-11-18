"""Bounded defensive screening of application content, without persistence."""
import re

from controls import Problem

SCHEMA = """
CREATE TABLE project_runtime_policies (
  project TEXT PRIMARY KEY, minimum_action TEXT NOT NULL CHECK(minimum_action IN ('redact','block')),
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL
);
"""
TOOL_SCHEMA = """
ALTER TABLE runtime_credentials ADD COLUMN agent_node TEXT;
CREATE TABLE agent_tool_rules (
  project TEXT NOT NULL, agent TEXT NOT NULL, tool TEXT NOT NULL, operation TEXT NOT NULL,
  target TEXT NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(project,agent,tool,operation,target)
);
"""
MODEL_SCHEMA = """
ALTER TABLE runtime_credentials ADD COLUMN allow_tools INTEGER NOT NULL DEFAULT 0 CHECK(allow_tools IN (0,1));
UPDATE runtime_credentials SET allow_tools=1 WHERE agent_node IS NOT NULL;
ALTER TABLE runtime_credentials ADD COLUMN allow_models INTEGER NOT NULL DEFAULT 0 CHECK(allow_models IN (0,1));
CREATE TABLE agent_model_rules (
  project TEXT NOT NULL, agent TEXT NOT NULL, model TEXT NOT NULL,
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(project,agent,model)
);
"""

PATTERNS = (
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----"
    )),
    ("private_key_marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer[ \t]+[A-Za-z0-9_.~+/-]{16,}={0,2}", re.IGNORECASE)),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("email_address", re.compile(
        r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
        r"(?:\.[A-Za-z0-9-]{1,63}){1,5}(?![A-Za-z0-9-])"
    )),
)


def inspect(body, fields, minimum_action="redact"):
    fields(body, ("text", "action"))
    text, action = body["text"], body["action"]
    if not isinstance(text, str) or len(text) > 6000:
        raise Problem(400, "Supply text of at most 6,000 characters.")
    try:
        text.encode("utf-8")
    except UnicodeError:
        raise Problem(400, "Screening input must contain valid Unicode text.") from None
    if action not in ("redact", "block"):
        raise Problem(400, "Action must be redact or block.")
    if minimum_action == "block":
        action = "block"
    findings = {}
    screened = text
    for label, pattern in PATTERNS:
        screened, total = pattern.subn(f"[REDACTED:{label}]", screened)
        if total:
            findings[label] = total
    # Unmatched private-key headers are unsafe to redact partially.
    if "private_key_marker" in findings or (findings and action == "block"):
        return {"decision": "block", "signals": findings}
    if findings:
        return {"decision": "redact", "signals": findings, "text": screened}
    return {"decision": "allow", "signals": {}}


def tool_coordinates(body, fields, identifier):
    fields(body, ("agent", "tool", "operation", "target"))
    agent, tool, target = (identifier(body[key]) for key in ("agent", "tool", "target"))
    operation = body["operation"]
    if operation not in ("read", "write", "invoke"):
        raise Problem(400, "Tool operation must be read, write or invoke.")
    return agent, tool, operation, target


def known_node(conn, project, identifier, kind):
    return conn.execute(
        """SELECT 1 FROM graph_nodes WHERE project=? AND id=? AND kind=?
           UNION ALL SELECT 1 FROM cloud_graph_nodes WHERE project=? AND id=? AND kind=? LIMIT 1""",
        (project, identifier, kind, project, identifier, kind),
    ).fetchone() is not None


def is_agent(conn, project, identifier):
    return known_node(conn, project, identifier, "agent")


def authorize_tool(conn, project, coordinates):
    agent, *_ = coordinates
    if is_agent(conn, project, agent) and conn.execute(
        "SELECT 1 FROM agent_tool_rules WHERE project=? AND agent=? AND tool=? AND operation=? AND target=?",
        (project, *coordinates),
    ).fetchone():
        return {"decision": "allow"}
    return {"decision": "deny"}


def authorize_model(conn, project, agent, model):
    if (is_agent(conn, project, agent) and known_node(conn, project, model, "model")
            and conn.execute(
                "SELECT 1 FROM agent_model_rules WHERE project=? AND agent=? AND model=?",
                (project, agent, model),
            ).fetchone()):
        return {"decision": "allow"}
    return {"decision": "deny"}


def inspect_document(document):
    """Return an allow/block decision for a structured JSON payload."""
    if not isinstance(document, (dict, list)):
        raise Problem(400, "Supply a JSON object or array.")
    pending = [(document, 0)]
    strings, count, length = [], 0, 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count + len(pending) > 1000 or depth > 16:
            raise Problem(400, "Structured screening document exceeds nesting or item limits.")
        if isinstance(value, dict):
            for key, child in reversed(tuple(value.items())):
                pending.extend(((child, depth + 1), (key, depth + 1)))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in reversed(value))
        elif isinstance(value, str):
            length += len(value)
            if length > 6000:
                raise Problem(400, "Structured screening text exceeds the size limit.")
            strings.append(value)

    def fields(body, expected):
        # Calls below construct the exact internal text screening payload.
        assert body.keys() == set(expected)

    signals = {}
    for text in (*strings, "".join(strings)):
        decision = inspect({"text": text, "action": "block"}, fields, "block")
        for category, occurrences in decision["signals"].items():
            signals[category] = max(signals.get(category, 0), occurrences)
    return {"decision": "block" if signals else "allow", "signals": signals}
