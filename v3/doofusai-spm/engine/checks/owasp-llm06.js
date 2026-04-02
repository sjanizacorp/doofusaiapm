/**
 * Check: OWASP-LLM06 — Sensitive Information Disclosure / Exposed API Keys
 * Target type: llm_api
 *
 * Checks for API keys leaked in environment variables, config objects,
 * or passed directly instead of via secrets manager.
 */

const { v4: uuidv4 } = require('uuid');

const SECRET_PATTERNS = [
  { re: /^sk-[A-Za-z0-9]{20,}$/, label: 'OpenAI API key', severity: 'critical' },
  { re: /^sk-ant-[A-Za-z0-9\-]{30,}$/, label: 'Anthropic API key', severity: 'critical' },
  { re: /^AKIA[0-9A-Z]{16}$/, label: 'AWS access key', severity: 'critical' },
  { re: /^AIza[0-9A-Za-z\-_]{35}$/, label: 'Google API key', severity: 'critical' },
  { re: /^[0-9a-f]{32}$/, label: 'Possible API token (32-char hex)', severity: 'medium' },
];

async function run(target, config) {
  const findings = [];

  // Check if API key was passed directly in target config (not via env)
  if (target.api_key_raw) {
    findings.push({
      id: uuidv4(),
      title: 'API key passed directly — not via environment variable',
      description: 'The API key was provided as a raw string in the target configuration rather than being injected from an environment variable or secrets manager. This risks the key appearing in logs, scan results, or config files.',
      severity: 'high',
      confidence: 'confirmed',
      resource: target.name,
      evidence: 'api_key_raw field present in target config',
    });
  }

  // Check the key format for known provider patterns
  const keyToTest = target.api_key_raw || target.api_key || '';
  for (const { re, label, severity } of SECRET_PATTERNS) {
    if (re.test(keyToTest)) {
      findings.push({
        id: uuidv4(),
        title: `${label} detected in scan config`,
        description: `A ${label} was found in the scan configuration. Rotate this key immediately if it has been committed to version control or appeared in any log output.`,
        severity,
        confidence: 'confirmed',
        resource: target.name,
        evidence: `Key matches pattern for: ${label}`,
      });
      break;
    }
  }

  // Check for missing rate-limit config
  if (!target.rate_limit_rpm && !target.rate_limit_tpm) {
    findings.push({
      id: uuidv4(),
      title: 'No rate-limit guardrails configured',
      description: 'The LLM API endpoint has no rate-limit configuration. An attacker or runaway agent could exhaust quota, cause denial-of-service, or trigger unexpected billing.',
      severity: 'medium',
      confidence: 'probable',
      resource: target.name,
      evidence: 'rate_limit_rpm and rate_limit_tpm both absent',
    });
  }

  return findings;
}

module.exports = { id: 'OWASP-LLM06', name: 'Sensitive Information Disclosure', run };
