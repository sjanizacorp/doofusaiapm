/**
 * Check: REGISTRY-001 — Pickle Deserialisation & Unsigned Artefacts
 * Target type: model_registry
 *
 * OWASP LLM05 (Supply Chain) — unsigned/unverified model checksums,
 * pickle-file deserialisation risks.
 */

const { v4: uuidv4 } = require('uuid');

const RISKY_FORMATS = ['pkl', 'pickle', 'pt', 'pth', 'bin'];

async function run(target, config) {
  const findings = [];

  // Check for unsigned / unverified models in registry
  if (!target.signature_verification && !target.checksum_policy) {
    findings.push({
      id: uuidv4(),
      title: 'No model signature verification policy',
      description: 'The model registry does not enforce signature verification or checksum validation on artefacts. A supply-chain attacker could replace a model with a malicious one containing embedded payloads.',
      severity: 'critical',
      confidence: 'probable',
      resource: target.name,
      evidence: 'signature_verification: false, checksum_policy: null',
    });
  }

  // Check for pickle-format models (arbitrary code execution risk)
  const formats = target.artefact_formats || [];
  const riskyFormats = formats.filter(f => RISKY_FORMATS.includes(f.toLowerCase()));

  if (riskyFormats.length > 0) {
    findings.push({
      id: uuidv4(),
      title: `Pickle-format models in registry (${riskyFormats.join(', ')})`,
      description: 'One or more models are stored in pickle format (.pkl, .pt, .bin). Python pickle deserialisation executes arbitrary code. A malicious model file can achieve full RCE on the loading host.',
      severity: 'high',
      confidence: 'confirmed',
      resource: target.name,
      evidence: `Artefact formats found: ${riskyFormats.join(', ')}`,
    });
  }

  // Check for model versioning policy
  if (!target.versioning_policy) {
    findings.push({
      id: uuidv4(),
      title: 'No model versioning policy configured',
      description: 'The model registry has no versioning policy. Without version control, it is impossible to roll back to a known-good model after a supply-chain compromise or silent accuracy regression.',
      severity: 'medium',
      confidence: 'probable',
      resource: target.name,
      evidence: 'versioning_policy: null',
    });
  }

  return findings;
}

module.exports = { id: 'REGISTRY-001', name: 'Unsigned Artefacts & Pickle Risk', run };
