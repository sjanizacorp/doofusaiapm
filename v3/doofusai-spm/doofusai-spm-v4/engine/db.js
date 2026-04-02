/**
 * Persistence Layer — sql.js (pure-JS SQLite, zero native compilation).
 *
 * sql.js init is async (loads a WASM binary). We resolve it once at startup
 * via initDb(), which must be awaited before any other DB call.
 * All query helpers remain synchronous after that.
 */

const path = require('path');
const fs   = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'doofusai.db');

let _db = null;   // sql.js Database instance

/** Flush in-memory DB to disk. Called after every write. */
function flush() {
  if (!_db) return;
  fs.writeFileSync(DB_PATH, Buffer.from(_db.export()));
}

function getDb() {
  if (!_db) throw new Error('[DB] Database not initialised — await initDb() first');
  return _db;
}

/**
 * Async init — call once at server startup: await initDb()
 * Loads the sql.js WASM, opens (or creates) the DB file, runs schema migrations.
 */
async function initDb() {
  if (_db) return _db;

  const initSqlJs = require('sql.js');
  // initSqlJs() returns a Promise<SqlJsStatic>
  const SQL = await initSqlJs();

  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  _db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  _db.run(`CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    profile       TEXT,
    target_type   TEXT NOT NULL,
    target_meta   TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    started_at    TEXT,
    finished_at   TEXT,
    posture_score REAL,
    tier          TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  )`);

  _db.run(`CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    policy_id      TEXT NOT NULL,
    policy_name    TEXT NOT NULL,
    target_type    TEXT NOT NULL,
    resource       TEXT,
    severity       TEXT NOT NULL,
    confidence     TEXT NOT NULL DEFAULT 'probable',
    score          REAL NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'open',
    title          TEXT NOT NULL,
    description    TEXT,
    evidence       TEXT,
    remediation    TEXT,
    framework_refs TEXT,
    tags           TEXT,
    first_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at    TEXT
  )`);

  _db.run(`CREATE TABLE IF NOT EXISTS scan_profiles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    target_type TEXT NOT NULL,
    config      TEXT,
    policies    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  )`);

  _db.run(`CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id)`);
  _db.run(`CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status)`);
  _db.run(`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`);
  _db.run(`CREATE INDEX IF NOT EXISTS idx_scans_status      ON scans(status)`);

  flush();
  console.info(`[DB] Initialised — ${DB_PATH}`);
  return _db;
}

// ── Query helpers ─────────────────────────────────────────────────────────────

function namedToPositional(sql, params = {}) {
  const values = [];
  const matches = sql.match(/@\w+/g) || [];
  for (const m of matches) values.push(params[m.slice(1)] ?? null);
  return { sql: sql.replace(/@\w+/g, '?'), values };
}

function run(db, sql, params = {}) {
  const { sql: s, values } = namedToPositional(sql, params);
  db.run(s, values);
  flush();
}

function get(db, sql, ...args) {
  const stmt = db.prepare(sql);
  stmt.bind(args);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free();
  return null;
}

function all(db, sql, params = {}) {
  const { sql: s, values } = namedToPositional(sql, params);
  const res = db.exec(s, values);
  if (!res.length) return [];
  const { columns, values: rows } = res[0];
  return rows.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
}

// ── Scan operations ───────────────────────────────────────────────────────────

function createScan(db, scan) {
  run(db, `INSERT INTO scans (id, profile, target_type, target_meta, status, started_at)
           VALUES (@id, @profile, @target_type, @target_meta, @status, @started_at)`, {
    ...scan,
    target_meta: JSON.stringify(scan.target_meta || {}),
    started_at:  new Date().toISOString(),
  });
  return scan.id;
}

function updateScan(db, id, updates) {
  const fields = Object.keys(updates).map(k => `${k} = @${k}`).join(', ');
  run(db, `UPDATE scans SET ${fields} WHERE id = @id`, { ...updates, id });
}

function getScan(db, id) {
  const row = get(db, 'SELECT * FROM scans WHERE id = ?', id);
  if (!row) return null;
  return { ...row, target_meta: JSON.parse(row.target_meta || '{}') };
}

function listScans(db, limit = 20) {
  return all(db, 'SELECT * FROM scans ORDER BY created_at DESC LIMIT @limit', { limit });
}

// ── Finding operations ────────────────────────────────────────────────────────

function upsertFinding(db, finding) {
  const existing = get(db,
    'SELECT id FROM findings WHERE scan_id = ? AND policy_id = ? AND resource = ?',
    finding.scan_id, finding.policy_id, finding.resource || ''
  );
  if (existing) {
    run(db, `UPDATE findings SET last_seen = datetime('now'), status = @status WHERE id = @id`,
      { id: existing.id, status: finding.status || 'open' });
    return existing.id;
  }
  run(db, `INSERT INTO findings
      (id, scan_id, policy_id, policy_name, target_type, resource, severity,
       confidence, score, status, title, description, evidence, remediation,
       framework_refs, tags)
    VALUES
      (@id, @scan_id, @policy_id, @policy_name, @target_type, @resource,
       @severity, @confidence, @score, @status, @title, @description,
       @evidence, @remediation, @framework_refs, @tags)`, {
    ...finding,
    framework_refs: JSON.stringify(finding.framework_refs || []),
    tags:           JSON.stringify(finding.tags || []),
    evidence:       finding.evidence ? redact(finding.evidence) : null,
    resource:       finding.resource ? redact(finding.resource) : null,
  });
  return finding.id;
}

function getFindings(db, { scanId, status, severity, targetType, limit = 200 } = {}) {
  let sql = 'SELECT * FROM findings WHERE 1=1';
  const params = {};
  if (scanId)     { sql += ' AND scan_id = @scanId';         params.scanId = scanId; }
  if (status)     { sql += ' AND status = @status';          params.status = status; }
  if (severity)   { sql += ' AND severity = @severity';      params.severity = severity; }
  if (targetType) { sql += ' AND target_type = @targetType'; params.targetType = targetType; }
  sql += ' ORDER BY score DESC, first_seen DESC LIMIT @limit';
  params.limit = limit;
  return all(db, sql, params).map(r => ({
    ...r,
    framework_refs: JSON.parse(r.framework_refs || '[]'),
    tags:           JSON.parse(r.tags || '[]'),
  }));
}

function updateFindingStatus(db, id, status) {
  const resolved_at = status === 'resolved' ? new Date().toISOString() : null;
  run(db, 'UPDATE findings SET status = @status, resolved_at = @resolved_at WHERE id = @id',
    { status, resolved_at, id });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function redact(str) {
  if (!str) return str;
  return String(str)
    .replace(/sk-[A-Za-z0-9]{20,}/g,                             'sk-[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,                'Bearer [REDACTED]')
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]')
    .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,                  '[PHONE]');
}

module.exports = {
  initDb, getDb,
  createScan, updateScan, getScan, listScans,
  upsertFinding, getFindings, updateFindingStatus,
};
