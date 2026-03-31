/**
 * Check: INFRA-001 — Unauthenticated MLflow / Jupyter endpoints
 * Target type: ai_infra
 *
 * Attempts a HEAD/GET to well-known MLflow and Jupyter paths.
 * Any 200 response without an auth challenge is a finding.
 */

const { v4: uuidv4 } = require('uuid');
const http = require('http');
const https = require('https');

const PROBE_PATHS = [
  { path: '/api/2.0/mlflow/experiments/list', label: 'MLflow REST API', port: 5000 },
  { path: '/',                                label: 'Jupyter root',    port: 8888 },
  { path: '/api/kernels',                     label: 'Jupyter kernels', port: 8888 },
  { path: '/api/2.0/mlflow/registered-models/list', label: 'MLflow model registry', port: 5000 },
];

function probe(host, port, urlPath, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const mod = port === 443 ? https : http;
    const req = mod.request({ host, port, path: urlPath, method: 'GET', timeout: timeoutMs }, (res) => {
      resolve({ status: res.statusCode, auth: res.headers['www-authenticate'] || null });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

async function run(target, config) {
  const findings = [];
  const host = target.host || 'localhost';

  for (const { path: urlPath, label, port } of PROBE_PATHS) {
    const result = await probe(host, target.port || port, urlPath);
    if (!result) continue; // unreachable — not a finding

    if (result.status === 200 && !result.auth) {
      findings.push({
        id: uuidv4(),
        title: `Unauthenticated ${label} endpoint accessible`,
        description: `The ${label} endpoint at ${host}:${target.port || port}${urlPath} returned HTTP 200 without requiring authentication. This exposes model metadata, experiment data, and potentially allows arbitrary code execution.`,
        severity: 'critical',
        confidence: 'confirmed',
        resource: `${host}:${target.port || port}`,
        evidence: `GET ${urlPath} → HTTP ${result.status}, no WWW-Authenticate header`,
      });
    }
  }

  // Check for missing audit logging config
  if (!target.audit_log_enabled) {
    findings.push({
      id: uuidv4(),
      title: 'Audit logging not enabled on AI infrastructure',
      description: 'Audit logging is disabled or not configured. Without it, there is no record of model access, experiment modifications, or data pipeline executions.',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: 'audit_log_enabled: false',
    });
  }

  return findings;
}

module.exports = { id: 'INFRA-001', name: 'Unauthenticated ML Endpoints', run };
