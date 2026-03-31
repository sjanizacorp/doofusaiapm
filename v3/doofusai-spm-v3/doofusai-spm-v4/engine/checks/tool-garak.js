/**
 * Check wrapper: garak
 * https://github.com/NVIDIA/garak
 *
 * Probes an LLM endpoint for vulnerabilities: prompt injection, jailbreaks,
 * hallucination, toxicity, data extraction.
 *
 * Requires: pip install garak
 *
 * Target config expected:
 *   target.model_type    — 'openai', 'huggingface', 'rest', etc.
 *   target.model_name    — model identifier (e.g. 'gpt-4o', 'mistral-7b')
 *   target.api_key_env   — env var name holding the API key (not the key itself)
 *   target.garak_probes  — array of probe IDs to run (optional, defaults to fast set)
 */

const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Fast probe set for CI/quick scans — full list takes 30+ minutes
const DEFAULT_PROBES = [
  'promptinject',
  'dan',
  'atkgen',
  'knownbadsignatures',
];

const PROBE_SEVERITY = {
  promptinject:        'critical',
  dan:                 'high',
  atkgen:              'high',
  knownbadsignatures:  'critical',
  encoding:            'medium',
  continuation:        'medium',
  realtoxicityprompts: 'high',
  grandma:             'medium',
};

function runGarak(modelType, modelName, probes, apiKeyEnv, timeoutMs = 25_000) {
  return new Promise((resolve, reject) => {
    const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'garak-'));
    const probeArgs = probes.flatMap(p => ['--probes', p]);

    const env = { ...process.env };
    if (apiKeyEnv && process.env[apiKeyEnv]) {
      env[apiKeyEnv] = process.env[apiKeyEnv];
    }

    const proc = spawn('python', [
      '-m', 'garak',
      '--model_type', modelType,
      '--model_name', modelName,
      '--report_prefix', path.join(reportDir, 'report'),
      '--format', 'json',
      ...probeArgs,
    ], { env, timeout: timeoutMs });

    let stderr = '';
    proc.stderr.on('data', d => { stderr += d.toString(); });

    proc.on('close', (code) => {
      const reportPath = path.join(reportDir, 'report.json');
      if (!fs.existsSync(reportPath)) {
        if (code !== 0) return reject(new Error(`garak exited ${code}: ${stderr.slice(0, 300)}`));
        return resolve([]);
      }
      try {
        const raw = fs.readFileSync(reportPath, 'utf8');
        const results = JSON.parse(raw);
        resolve(results);
      } catch {
        resolve([]);
      } finally {
        fs.rmSync(reportDir, { recursive: true, force: true });
      }
    });

    proc.on('error', reject);
  });
}

async function run(target, config) {
  const findings = [];
  const modelType = target.model_type || 'openai';
  const modelName = target.model_name;

  if (!modelName) {
    return [{
      id: uuidv4(),
      title: 'garak: model_name not configured',
      description: 'Set target.model_name (e.g. "gpt-4o") to enable garak probing.',
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  const probes = target.garak_probes || DEFAULT_PROBES;

  let results;
  try {
    results = await runGarak(modelType, modelName, probes, target.api_key_env);
  } catch (err) {
    return [{
      id: uuidv4(),
      title: 'garak not installed or probe failed',
      description: `Could not run garak: ${err.message}. Install with: pip install garak`,
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  // Parse garak JSON report — results is array of probe result objects
  for (const probe of (Array.isArray(results) ? results : [])) {
    if (!probe.passed) {
      findings.push({
        id: uuidv4(),
        title: `garak: ${probe.probe} — vulnerability detected`,
        description: `The model ${modelName} failed the garak "${probe.probe}" probe. This indicates susceptibility to the attack type this probe tests.`,
        severity: PROBE_SEVERITY[probe.probe] || 'high',
        confidence: 'confirmed',
        resource: `${modelType}/${modelName}`,
        evidence: `Probe: ${probe.probe}, Failures: ${probe.failures || 'unknown'}, Pass rate: ${probe.pass_rate ?? 'N/A'}`,
      });
    }
  }

  return findings;
}

module.exports = { id: 'TOOL-GARAK', name: 'garak LLM vulnerability probe', run };
