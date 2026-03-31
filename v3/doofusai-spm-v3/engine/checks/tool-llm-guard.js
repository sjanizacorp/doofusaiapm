/**
 * Check wrapper: llm-guard
 * https://github.com/protectai/llm-guard
 *
 * Runs a set of input/output scanners against sample prompts and responses
 * to detect PII leakage, prompt injection, toxicity, and banned topics.
 *
 * Requires: pip install llm-guard
 *
 * Target config expected:
 *   target.sample_prompts  — array of test input strings to scan
 *   target.sample_outputs  — array of test output strings to scan (optional)
 *   target.scanners        — array of scanner IDs (optional, defaults to all)
 */

const { execFile } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_SCANNERS = [
  'PromptInjection',
  'Anonymize',
  'BanTopics',
  'Toxicity',
  'TokenLimit',
];

const SCANNER_SEVERITY = {
  PromptInjection: 'critical',
  Anonymize:       'high',
  BanTopics:       'high',
  Toxicity:        'medium',
  TokenLimit:      'medium',
  Secrets:         'critical',
  NoRefusal:       'high',
  LanguageSame:    'low',
};

/** Write a temporary Python runner script and execute it. */
function buildRunnerScript(scanners, prompts, outputs) {
  return `
import json, sys
from llm_guard.input_scanners import PromptInjection, Anonymize, BanTopics, Toxicity, TokenLimit, Secrets
from llm_guard.output_scanners import NoRefusal

SCANNER_CLASSES = {
  "PromptInjection": PromptInjection,
  "Anonymize": Anonymize,
  "BanTopics": BanTopics,
  "Toxicity": Toxicity,
  "TokenLimit": TokenLimit,
  "Secrets": Secrets,
  "NoRefusal": NoRefusal,
}

results = []
prompts = ${JSON.stringify(prompts)}
outputs = ${JSON.stringify(outputs || [])}
scanners = ${JSON.stringify(scanners)}

for scanner_name in scanners:
  cls = SCANNER_CLASSES.get(scanner_name)
  if not cls:
    continue
  try:
    scanner = cls()
    for i, prompt in enumerate(prompts):
      try:
        sanitised, is_valid, risk_score = scanner.scan(prompt)
        if not is_valid:
          results.append({
            "scanner": scanner_name,
            "input": "prompt",
            "index": i,
            "risk_score": risk_score,
            "sanitised": sanitised[:200] if sanitised else None,
          })
      except Exception as e:
        results.append({"scanner": scanner_name, "error": str(e)})
  except Exception as e:
    results.append({"scanner": scanner_name, "init_error": str(e)})

print(json.dumps(results))
`;
}

function runLlmGuard(scanners, prompts, outputs, timeoutMs = 25_000) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(os.tmpdir(), `llmguard_${Date.now()}.py`);
    fs.writeFileSync(scriptPath, buildRunnerScript(scanners, prompts, outputs));

    execFile('python', [scriptPath], { timeout: timeoutMs, maxBuffer: 2_097_152 }, (err, stdout, stderr) => {
      fs.unlink(scriptPath, () => {});
      if (err && !stdout) {
        return reject(new Error(`llm-guard runner failed: ${stderr?.slice(0, 300) || err.message}`));
      }
      try {
        resolve(JSON.parse(stdout || '[]'));
      } catch {
        reject(new Error('Failed to parse llm-guard output'));
      }
    });
  });
}

async function run(target, config) {
  const findings = [];

  const prompts = target.sample_prompts;
  if (!prompts?.length) {
    return [{
      id: uuidv4(),
      title: 'llm-guard: no sample_prompts configured',
      description: 'Provide target.sample_prompts (array of strings) to enable llm-guard input scanning.',
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  const scanners = target.scanners || DEFAULT_SCANNERS;

  let results;
  try {
    results = await runLlmGuard(scanners, prompts, target.sample_outputs || []);
  } catch (err) {
    return [{
      id: uuidv4(),
      title: 'llm-guard not installed or scan failed',
      description: `Could not run llm-guard: ${err.message}. Install with: pip install llm-guard`,
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  for (const r of results) {
    if (r.init_error || r.error) continue;
    findings.push({
      id: uuidv4(),
      title: `llm-guard: ${r.scanner} triggered on ${r.input} #${r.index}`,
      description: `llm-guard scanner "${r.scanner}" flagged prompt #${r.index} with risk score ${r.risk_score?.toFixed(3)}. This indicates the application may pass dangerous content to or from the LLM without proper filtering.`,
      severity: SCANNER_SEVERITY[r.scanner] || 'medium',
      confidence: r.risk_score > 0.9 ? 'confirmed' : r.risk_score > 0.6 ? 'probable' : 'possible',
      resource: target.name,
      evidence: `Scanner: ${r.scanner}, Risk score: ${r.risk_score?.toFixed(3)}, Input index: ${r.index}`,
    });
  }

  return findings;
}

module.exports = { id: 'TOOL-LLM-GUARD', name: 'llm-guard input/output scanner', run };
