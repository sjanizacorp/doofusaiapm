/**
 * OWASP LLM04:2025 — Data and Model Poisoning
 * Training data integrity, fine-tuning pipeline controls
 */
const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  const findings = [];

  if (!target.training_data_validation) {
    findings.push({ id: uuidv4(), title: 'No training data validation or sanitisation controls', description: 'Training and fine-tuning pipelines lack input validation to detect poisoned or adversarially crafted data. An attacker who can influence training data can embed backdoors that trigger on specific inputs in production.', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'training_data_validation: false' });
  }

  if (!target.fine_tune_access_control) {
    findings.push({ id: uuidv4(), title: 'Fine-tuning pipeline has no access control', description: 'The model fine-tuning or continuous training pipeline is not access-controlled. Any user with pipeline access can introduce poisoned examples into the training dataset.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'fine_tune_access_control: false' });
  }

  if (!target.dataset_integrity_checks) {
    findings.push({ id: uuidv4(), title: 'No dataset integrity checks (checksums / lineage)', description: 'Training datasets do not have checksums or lineage tracking. Dataset substitution attacks are undetectable without integrity verification.', severity: 'high', confidence: 'possible', resource: target.name, evidence: 'dataset_integrity_checks: false' });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM04', name: 'Data and Model Poisoning', run };
