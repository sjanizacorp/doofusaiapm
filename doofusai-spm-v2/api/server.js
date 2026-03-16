/**
 * DoofusAI SPM REST API — Express + OpenAPI 3.1
 * All routes documented inline; swagger-jsdoc generates the spec at /api/docs
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const path = require('path');

const { runScan, getScanResult, reloadPolicies, getPolicies, setDb } = require('../engine/scanner');
const { initDb, getDb, listScans, getScan, getFindings, updateFindingStatus } = require('../engine/db');
const { computePostureScore, scoreTier } = require('../engine/scoring');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.1.0',
    info: {
      title: 'DoofusAI SPM API',
      version: '1.0.0',
      description: 'DoofusAI Security Posture Management — scan engine REST interface',
    },
    servers: [{ url: '/api/v1' }],
    components: {
      schemas: {
        Scan: {
          type: 'object',
          properties: {
            id:            { type: 'string' },
            target_type:   { type: 'string', enum: ['llm_api', 'ai_infra', 'model_registry', 'ai_app'] },
            status:        { type: 'string', enum: ['pending', 'running', 'completed', 'failed'] },
            posture_score: { type: 'number', nullable: true },
            tier:          { type: 'string', nullable: true },
            created_at:    { type: 'string', format: 'date-time' },
            finished_at:   { type: 'string', format: 'date-time', nullable: true },
          },
        },
        Finding: {
          type: 'object',
          properties: {
            id:             { type: 'string' },
            scan_id:        { type: 'string' },
            policy_id:      { type: 'string' },
            severity:       { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            confidence:     { type: 'string', enum: ['confirmed', 'probable', 'possible'] },
            score:          { type: 'number' },
            status:         { type: 'string', enum: ['open', 'acknowledged', 'resolved'] },
            title:          { type: 'string' },
            description:    { type: 'string' },
            remediation:    { type: 'string' },
            framework_refs: { type: 'array', items: { type: 'object' } },
          },
        },
        PostureReport: {
          type: 'object',
          properties: {
            posture_score: { type: 'number' },
            tier:          { type: 'object' },
            open_count:    { type: 'integer' },
            by_severity:   { type: 'object' },
            by_target:     { type: 'object' },
            by_framework:  { type: 'object' },
            generated_at:  { type: 'string', format: 'date-time' },
          },
        },
      },
    },
  },
  apis: [__filename],
});

app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get('/api/openapi.json', (req, res) => res.json(swaggerSpec));

// ── Middleware ────────────────────────────────────────────────────────────────

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function validateTargetType(type) {
  return ['llm_api', 'ai_infra', 'model_registry', 'ai_app'].includes(type);
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * @openapi
 * /api/v1/health:
 *   get:
 *     summary: Health check
 *     responses:
 *       200:
 *         description: Service healthy
 */
app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() });
});

/**
 * @openapi
 * /api/v1/scans:
 *   post:
 *     summary: Start a new scan
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [target]
 *             properties:
 *               target:
 *                 type: object
 *                 required: [type, name]
 *                 properties:
 *                   type: { type: string, enum: [llm_api, ai_infra, model_registry, ai_app] }
 *                   name: { type: string }
 *               policy_ids:
 *                 type: array
 *                 items: { type: string }
 *               profile:
 *                 type: string
 *     responses:
 *       202:
 *         description: Scan accepted
 */
app.post('/api/v1/scans', asyncHandler(async (req, res) => {
  const { target, policy_ids, profile } = req.body;

  if (!target?.type || !validateTargetType(target.type)) {
    return res.status(400).json({ error: 'Invalid or missing target.type' });
  }
  if (!target?.name) {
    return res.status(400).json({ error: 'Missing target.name' });
  }

  // Strip any raw secrets that might have been included — only accept redacted config
  const safeTarget = sanitiseTarget(target);

  // Run async — return scan ID immediately
  const scanId = uuidv4();
  res.status(202).json({ scan_id: scanId, status: 'pending', message: 'Scan queued' });

  // Fire and forget with status updates
  runScan(safeTarget, { profile, policyIds: policy_ids, scanId }).catch(err => {
    console.error('[API] Scan failed:', err);
  });
}));

/**
 * @openapi
 * /api/v1/scans:
 *   get:
 *     summary: List recent scans
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 20 }
 *     responses:
 *       200:
 *         description: Array of scans
 */
app.get('/api/v1/scans', asyncHandler(async (req, res) => {
  const db = getDb();
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const scans = listScans(db, limit);
  res.json({ scans, count: scans.length });
}));

/**
 * @openapi
 * /api/v1/scans/{id}:
 *   get:
 *     summary: Get scan status and results
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Scan with findings
 *       404:
 *         description: Scan not found
 */
app.get('/api/v1/scans/:id', asyncHandler(async (req, res) => {
  const result = getScanResult(req.params.id);
  if (!result) return res.status(404).json({ error: 'Scan not found' });
  res.json(result);
}));

/**
 * @openapi
 * /api/v1/findings:
 *   get:
 *     summary: List findings with optional filters
 *     parameters:
 *       - in: query
 *         name: scan_id
 *         schema: { type: string }
 *       - in: query
 *         name: severity
 *         schema: { type: string, enum: [critical, high, medium, low, info] }
 *       - in: query
 *         name: status
 *         schema: { type: string, enum: [open, acknowledged, resolved] }
 *       - in: query
 *         name: target_type
 *         schema: { type: string }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 200 }
 *     responses:
 *       200:
 *         description: Array of findings
 */
app.get('/api/v1/findings', asyncHandler(async (req, res) => {
  const db = getDb();
  const { scan_id, severity, status, target_type, limit } = req.query;
  const findings = getFindings(db, {
    scanId: scan_id,
    severity,
    status,
    targetType: target_type,
    limit: Math.min(parseInt(limit) || 200, 500),
  });
  res.json({ findings, count: findings.length });
}));

/**
 * @openapi
 * /api/v1/findings/{id}/status:
 *   patch:
 *     summary: Update finding status
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [status]
 *             properties:
 *               status: { type: string, enum: [open, acknowledged, resolved] }
 *     responses:
 *       200:
 *         description: Status updated
 */
app.patch('/api/v1/findings/:id/status', asyncHandler(async (req, res) => {
  const { status } = req.body;
  const valid = ['open', 'acknowledged', 'resolved'];
  if (!valid.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${valid.join(', ')}` });
  }
  const db = getDb();
  updateFindingStatus(db, req.params.id, status);
  res.json({ id: req.params.id, status });
}));

/**
 * @openapi
 * /api/v1/reports/{scan_id}:
 *   get:
 *     summary: Get a posture report for a scan
 *     parameters:
 *       - in: path
 *         name: scan_id
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: format
 *         schema: { type: string, enum: [json, summary], default: json }
 *       - in: query
 *         name: severity
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Report data
 */
app.get('/api/v1/reports/:scan_id', asyncHandler(async (req, res) => {
  const db = getDb();
  const scan = getScan(db, req.params.scan_id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const findings = getFindings(db, {
    scanId: req.params.scan_id,
    severity: req.query.severity,
  });

  const open = findings.filter(f => f.status !== 'resolved');
  const postureScore = computePostureScore(open);
  const tier = scoreTier(postureScore);

  const bySeverity = ['critical', 'high', 'medium', 'low', 'info'].reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length;
    return acc;
  }, {});

  const byTarget = {};
  for (const f of findings) {
    byTarget[f.target_type] = (byTarget[f.target_type] || 0) + 1;
  }

  const byFramework = {};
  for (const f of findings) {
    for (const ref of (f.framework_refs || [])) {
      byFramework[ref.framework] = (byFramework[ref.framework] || 0) + 1;
    }
  }

  const report = {
    scan,
    posture_score: postureScore,
    tier,
    open_count: open.length,
    total_count: findings.length,
    by_severity: bySeverity,
    by_target: byTarget,
    by_framework: byFramework,
    findings,
    generated_at: new Date().toISOString(),
  };

  if (req.query.format === 'summary') {
    return res.json({
      scan_id: scan.id,
      posture_score: postureScore,
      tier: tier.tier,
      open_count: open.length,
      by_severity: bySeverity,
      generated_at: report.generated_at,
    });
  }

  res.json(report);
}));

/**
 * @openapi
 * /api/v1/policies:
 *   get:
 *     summary: List loaded policies
 *     responses:
 *       200:
 *         description: Array of policies
 */
app.get('/api/v1/policies', (req, res) => {
  const policies = getPolicies();
  res.json({ policies, count: policies.length });
});

/**
 * @openapi
 * /api/v1/policies/reload:
 *   post:
 *     summary: Hot-reload policies from disk
 *     responses:
 *       200:
 *         description: Policies reloaded
 */
app.post('/api/v1/policies/reload', (req, res) => {
  const policies = reloadPolicies();
  res.json({ reloaded: policies.length, timestamp: new Date().toISOString() });
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[API Error]', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Remove any raw secrets from an incoming target config. */
function sanitiseTarget(target) {
  const safe = { ...target };
  // Reject raw keys — expect them via env
  delete safe.api_key_raw;
  delete safe.password;
  delete safe.secret;
  delete safe.token;

  // Bind env-sourced keys by reference name
  if (safe.api_key_env) {
    safe.api_key = process.env[safe.api_key_env] || null;
  }

  return safe;
}

// ── Server ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;

if (require.main === module) {
  initDb()
    .then(db => {
      setDb(db);
      app.listen(PORT, () => {
        console.info(`[API] DoofusAI SPM server running on http://localhost:${PORT}`);
        console.info(`[API] OpenAPI docs: http://localhost:${PORT}/api/docs`);
      });
    })
    .catch(err => {
      console.error('[API] Failed to initialise database:', err);
      process.exit(1);
    });
}

module.exports = app;
