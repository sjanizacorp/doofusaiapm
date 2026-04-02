/**
 * OWASP LLM07:2025 — System Prompt Leakage
 * System prompt exposure, secrets in prompts, prompt confidentiality
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];
  const sp = target.system_prompt || '';

  if (sp && !target.prompt_confidentiality_instruction) {
    findings.push({ id: uuidv4(), title: 'System prompt lacks confidentiality instructions', description: 'The system prompt does not instruct the model to keep it confidential. Users can extract system prompt contents via crafted queries, exposing business logic, API endpoints, and security controls embedded in the prompt.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'prompt_confidentiality_instruction: false' });
  }

  // Look for operational details that should not be in system prompt
  const sensitivePatterns = [/https?:\/\/[^\s]+/gi, /\bdb\b.*\bpassword\b/i, /\bsecret\b/i, /internal only/i];
  const matches = sensitivePatterns.filter(p => p.test(sp));
  if (matches.length > 0) {
    findings.push({ id: uuidv4(), title: 'Sensitive operational details found in system prompt', description: 'The system prompt contains internal URLs, credentials references, or sensitive operational details. These are extractable by users via prompt injection or direct questioning.', severity: 'high', confidence: 'confirmed', resource: target.name, evidence: `${matches.length} sensitive pattern(s) detected in system prompt` });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM07', name: 'System Prompt Leakage', run };
