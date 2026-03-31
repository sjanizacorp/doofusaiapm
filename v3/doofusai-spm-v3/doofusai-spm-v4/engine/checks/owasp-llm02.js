/**
 * OWASP LLM02:2025 — Sensitive Information Disclosure
 * Checks for training data leakage, system prompt exposure, PII in outputs
 */
const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  const findings = [];
  const systemPrompt = target.system_prompt || '';

  // Check for secrets/credentials embedded in system prompt
  const secretPatterns = [/sk-[A-Za-z0-9]{20,}/, /password\s*[:=]/i, /api[_-]?key\s*[:=]/i, /Bearer\s+[A-Za-z0-9]/i];
  for (const pat of secretPatterns) {
    if (pat.test(systemPrompt)) {
      findings.push({ id: uuidv4(), title: 'Credentials embedded in system prompt', description: 'The system prompt contains what appears to be a secret, API key, or credential. System prompts can be extracted via prompt injection and these credentials would then be exposed.', severity: 'critical', confidence: 'confirmed', resource: target.name, evidence: 'Secret pattern found in system_prompt' });
    }
  }

  // No output PII filtering
  if (!target.output_pii_filter && !target.output_scanner) {
    findings.push({ id: uuidv4(), title: 'No output PII filtering configured', description: 'The model has no output scanner to detect and redact PII before responses reach users. Models can memorise and reproduce training data including personal information.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'output_pii_filter: false, output_scanner: null' });
  }

  // Check for training data leakage protection
  if (!target.training_data_controls) {
    findings.push({ id: uuidv4(), title: 'No training data leakage controls documented', description: 'No controls are documented to prevent the model from reproducing memorised training data. This is particularly important for models fine-tuned on proprietary or sensitive datasets.', severity: 'medium', confidence: 'possible', resource: target.name, evidence: 'training_data_controls: null' });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM02', name: 'Sensitive Information Disclosure', run };
