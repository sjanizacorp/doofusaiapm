/**
 * Check Runner — executes check modules in isolated worker threads.
 * Each check gets a 30s timeout. A crashing check cannot take down the engine.
 */

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const CHECK_TIMEOUT_MS = 30_000;

// ── Worker bootstrap (runs inside each Worker thread) ────────────────────────

if (!isMainThread) {
  const { checkModulePath, target, config, policyId } = workerData;
  (async () => {
    try {
      const mod = require(checkModulePath);
      const findings = await mod.run(target, config);
      parentPort.postMessage({ ok: true, findings: findings || [] });
    } catch (err) {
      parentPort.postMessage({ ok: false, error: err.message, findings: [] });
    }
  })();
}

// ── Runner (called from main thread / scanner) ────────────────────────────────

/**
 * Run a single check module in a worker thread with timeout.
 * @param {string} checkModulePath  Absolute path to the check module file.
 * @param {object} target           Target descriptor (no raw secrets — pass only what the check needs).
 * @param {object} config           Policy-level config merged with global env bindings.
 * @param {string} policyId         Used for logging.
 * @returns {Promise<Finding[]>}
 */
function runCheck(checkModulePath, target, config, policyId) {
  return new Promise((resolve) => {
    const worker = new Worker(__filename, {
      workerData: { checkModulePath, target, config, policyId },
    });

    const timer = setTimeout(() => {
      worker.terminate();
      console.warn(`[Runner] Check ${policyId} timed out after ${CHECK_TIMEOUT_MS}ms`);
      resolve([]);
    }, CHECK_TIMEOUT_MS);

    worker.on('message', ({ ok, findings, error }) => {
      clearTimeout(timer);
      if (!ok) {
        console.warn(`[Runner] Check ${policyId} failed: ${error}`);
      }
      resolve(findings || []);
    });

    worker.on('error', (err) => {
      clearTimeout(timer);
      console.error(`[Runner] Worker error in ${policyId}:`, err.message);
      resolve([]);
    });

    worker.on('exit', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        console.warn(`[Runner] Worker for ${policyId} exited with code ${code}`);
      }
    });
  });
}

/**
 * Run all applicable policies against a target concurrently (max 5 parallel).
 * @param {Policy[]} policies       All loaded policies.
 * @param {object}   target         { type, ...config } — type must match policy.target_types.
 * @param {string}   engineRoot     Absolute path to the engine directory.
 * @returns {Promise<RawFinding[]>}
 */
async function runAllChecks(policies, target, engineRoot) {
  const applicable = policies.filter(p =>
    p.enabled !== false && p.target_types.includes(target.type)
  );

  if (applicable.length === 0) {
    console.info(`[Runner] No applicable policies for target type: ${target.type}`);
    return [];
  }

  console.info(`[Runner] Running ${applicable.length} checks for ${target.type}`);

  // Concurrency pool of 5
  const allFindings = [];
  const pool = [];

  for (const policy of applicable) {
    const checkModulePath = path.resolve(engineRoot, policy.check_module + '.js');
    const task = runCheck(checkModulePath, target, {}, policy.id)
      .then(findings => {
        const stamped = findings.map(f => ({
          id: f.id || uuidv4(),
          policy_id: policy.id,
          policy_name: policy.name,
          target_type: target.type,
          severity: f.severity || policy.severity,
          confidence: f.confidence || 'probable',
          title: f.title || policy.name,
          description: f.description || policy.description,
          evidence: f.evidence || null,
          remediation: f.remediation || policy.remediation,
          resource: f.resource || target.name || target.type,
          framework_refs: policy.framework_refs,
          tags: policy.tags || [],
          status: 'open',
        }));
        allFindings.push(...stamped);
      });

    pool.push(task);
    if (pool.length >= 5) {
      await Promise.all(pool.splice(0, 5));
    }
  }

  await Promise.all(pool);
  return allFindings;
}

module.exports = { runAllChecks, runCheck };
