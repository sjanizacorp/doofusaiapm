/**
 * ATLAS-002 — Adversarial Evasion Attacks (AML.T0015)
 * Input perturbation defences, adversarial robustness
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (!target.adversarial_input_detection) {
    findings.push({ id: uuidv4(), title: 'No adversarial input detection (AML.T0015)', description: 'The model endpoint has no adversarial example detection. Imperceptible perturbations to inputs can cause misclassification or unexpected model behaviour, particularly dangerous in computer vision and audio models.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'adversarial_input_detection: false' });
  }

  if (!target.input_preprocessing_defence) {
    findings.push({ id: uuidv4(), title: 'No input preprocessing defence against perturbations', description: 'Defensive preprocessing (input smoothing, feature squeezing, randomised smoothing) is not applied. These defences reduce the effectiveness of adversarial perturbation attacks.', severity: 'medium', confidence: 'possible', resource: target.name, evidence: 'input_preprocessing_defence: false' });
  }

  return findings;
}
module.exports = { id: 'ATLAS-002', name: 'Adversarial Evasion Attacks', run };
