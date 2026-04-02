/**
 * OWASP LLM10:2025 — Unbounded Consumption (formerly Model DoS)
 * Denial of wallet, resource exhaustion, runaway agents
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (!target.rate_limit_rpm && !target.rate_limit_tpm) {
    findings.push({ id: uuidv4(), title: 'No rate limiting configured — Denial of Wallet risk', description: 'No per-user or per-application rate limits are configured. An attacker or runaway process can exhaust API quota, causing service disruption and unexpected billing (Denial of Wallet attack).', severity: 'high', confidence: 'confirmed', resource: target.name, evidence: 'rate_limit_rpm: null, rate_limit_tpm: null' });
  }

  if (!target.max_tokens_per_request) {
    findings.push({ id: uuidv4(), title: 'No maximum token limit per request', description: 'No max_tokens limit is set per request. Adversarially crafted inputs can trigger very long completions, exhausting compute and quota at disproportionate cost.', severity: 'medium', confidence: 'probable', resource: target.name, evidence: 'max_tokens_per_request: null' });
  }

  if (!target.budget_alert && !target.spend_cap) {
    findings.push({ id: uuidv4(), title: 'No spend cap or budget alert configured', description: 'No budget alert or hard spend cap is configured on the LLM provider account. A billing exploit could go undetected until the monthly invoice arrives.', severity: 'medium', confidence: 'probable', resource: target.name, evidence: 'budget_alert: false, spend_cap: false' });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM10', name: 'Unbounded Consumption', run };
