/**
 * Scanner — top-level orchestrator.
 * loadPolicies → runAllChecks → scoreFindings → persist → return ScanResult
 */

const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { loadAllPolicies } = require('./policyLoader');
const { runAllChecks } = require('./runner');
const { scoreFinding, computePostureScore, scoreTier } = require('./scoring');
const { initDb, createScan, updateScan, upsertFinding, getFindings } = require('./db');

const ENGINE_ROOT = __dirname;

let _db = null;
let _policies = null;

/** Called once from server.js after await initDb() resolves. */
function setDb(db) { _db = db; }

function getDb() {
  if (!_db) throw new Error('[Scanner] DB not ready — call setDb() after initDb()');
  return _db;
}

function getPolicies() {
  if (!_policies) _policies = loadAllPolicies(ENGINE_ROOT);
  return _policies;
}

/** Force policy reload (useful after hot-dropping a new YAML file). */
function reloadPolicies() {
  _policies = loadAllPolicies(ENGINE_ROOT);
  return _policies;
}

/**
 * Run a full scan against a target.
 *
 * @param {object} target  { type: 'llm_api'|'ai_infra'|'model_registry'|'ai_app', name, ...params }
 * @param {object} opts    { profile?, policyIds? (override subset) }
 * @returns {Promise<ScanResult>}
 */
async function runScan(target, opts = {}) {
  const db = getDb();
  let policies = getPolicies();

  if (opts.policyIds?.length) {
    policies = policies.filter(p => opts.policyIds.includes(p.id));
  }

  const scanId = uuidv4();

  // Persist scan record
  createScan(db, {
    id: scanId,
    profile: opts.profile || null,
    target_type: target.type,
    target_meta: { name: target.name, type: target.type },
    status: 'running',
  });

  console.info(`[Scanner] Scan ${scanId} started — target: ${target.type}/${target.name}`);

  let findings = [];
  try {
    const rawFindings = await runAllChecks(policies, target, ENGINE_ROOT);

    // Score each finding and persist
    for (const rf of rawFindings) {
      const scored = { ...rf, score: scoreFinding(rf), scan_id: scanId };
      upsertFinding(db, scored);
      findings.push(scored);
    }

    const postureScore = computePostureScore(findings);
    const tier = scoreTier(postureScore);

    updateScan(db, scanId, {
      status: 'completed',
      finished_at: new Date().toISOString(),
      posture_score: postureScore,
      tier: tier.code,
    });

    console.info(`[Scanner] Scan ${scanId} completed — score: ${postureScore} (${tier.tier}), findings: ${findings.length}`);

    return {
      scanId,
      status: 'completed',
      postureScore,
      tier,
      findingCount: findings.length,
      findings,
    };
  } catch (err) {
    updateScan(db, scanId, { status: 'failed', finished_at: new Date().toISOString() });
    console.error(`[Scanner] Scan ${scanId} failed:`, err);
    throw err;
  }
}

/**
 * Get scan results by ID.
 */
function getScanResult(scanId) {
  const db = getDb();
  const { getScan } = require('./db');
  const scan = getScan(db, scanId);
  if (!scan) return null;
  const findings = getFindings(db, { scanId });
  return { scan, findings };
}

module.exports = { runScan, getScanResult, reloadPolicies, getPolicies, setDb };
