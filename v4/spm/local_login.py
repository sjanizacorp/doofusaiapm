"""Username/password sign-in and expiring local browser sessions."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets

from controls import Problem

SCHEMA = """
CREATE TABLE local_users (
 username TEXT PRIMARY KEY, project TEXT NOT NULL, principal TEXT NOT NULL, role TEXT NOT NULL,
 salt TEXT NOT NULL, password_hash TEXT NOT NULL, failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT
);
CREATE TABLE browser_sessions (
 digest TEXT PRIMARY KEY REFERENCES credentials(digest) ON DELETE CASCADE,
 username TEXT NOT NULL
);
"""
USER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,79}")
ITERATIONS = 600000


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS).hex()


def set_user(conn, project, username, password, role):
    if not isinstance(username, str) or not USER.fullmatch(username):
        raise Problem(400, "Use a username of 1–80 letters, numbers, dots, @, hyphens or underscores.")
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise Problem(400, "Use a password or passphrase of 12–128 characters.")
    username = username.lower()
    salt = secrets.token_hex(16)
    conn.execute("DELETE FROM credentials WHERE digest IN (SELECT digest FROM browser_sessions WHERE username=?)",
                 (username,))
    conn.execute("""INSERT INTO local_users(username,project,principal,role,salt,password_hash)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET project=excluded.project,
                    principal=excluded.principal,role=excluded.role,salt=excluded.salt,
                    password_hash=excluded.password_hash,failed=0,locked_until=NULL""",
                 (username, project, username, role, salt, password_hash(password, salt)))


def session(conn, project, principal, role, owner):
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(timespec="milliseconds")
    conn.execute("INSERT INTO credentials(digest,principal,project,role,expires_at) VALUES(?,?,?,?,?)",
                 (digest, principal, project, role, expires))
    conn.execute("INSERT INTO browser_sessions VALUES(?,?)", (digest, owner))
    return {"access_token": token, "expires_at": expires}


def authenticate(conn, username, password, stamp):
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 128 or len(username) > 80:
        raise Problem(401, "Username or password is incorrect.")
    username = username.lower()
    user = conn.execute("SELECT * FROM local_users WHERE username=?", (username,)).fetchone()
    expected = user["password_hash"] if user else "0" * 64
    actual = password_hash(password, user["salt"] if user else "0" * 32)
    now = stamp()
    if user is None:
        return None
    if user["locked_until"] and user["locked_until"] > now:
        return None
    if not hmac.compare_digest(actual, expected):
        failed = user["failed"] + 1
        locked = ((datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(timespec="milliseconds")
                  if failed >= 5 else None)
        conn.execute("UPDATE local_users SET failed=?,locked_until=? WHERE username=?",
                     (failed, locked, username))
        return None
    conn.execute("UPDATE local_users SET failed=0,locked_until=NULL WHERE username=?", (username,))
    return session(conn, user["project"], user["principal"], user["role"], username)
