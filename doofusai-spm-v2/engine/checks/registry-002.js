/**
 * Check: REGISTRY-002 — Missing SBOM & Public Model Cards Without Licence Clarity
 * Target type: model_registry
 *
 * OWASP LLM05 (Supply Chain), NIST AI RMF GOVERN.
 */

const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  const findings = [];

  if (!target.sbom_present && !target.dependency_manifest) {
    findings.push({
      id: uuidv4(),
      title: 'No Software Bill of Materials (SBOM) for model dependencies',
      description: 'There is no SBOM or dependency manifest for this model. Without it, it is impossible to audit training data sources, base model lineage, or library vulnerabilities that may affect model behaviour.',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: 'sbom_present: false, dependency_manifest: null',
    });
  }

  if (target.public === true && !target.licence) {
    findings.push({
      id: uuidv4(),
      title: 'Public model card has no licence declaration',
      description: 'The model is publicly accessible but has no licence specified in its model card. This creates legal risk for users and may indicate the model card was not reviewed before publication.',
      severity: 'medium',
      confidence: 'confirmed',
      resource: target.name,
      evidence: 'public: true, licence: null',
    });
  }

  if (target.public === true && !target.data_provenance) {
    findings.push({
      id: uuidv4(),
      title: 'Public model has no training data provenance declaration',
      description: 'The model is publicly accessible but its training data sources are undocumented. This is a supply-chain risk indicator and may violate data governance obligations (GDPR, CCPA).',
      severity: 'medium',
      confidence: 'probable',
      resource: target.name,
      evidence: 'public: true, data_provenance: null',
    });
  }

  return findings;
}

module.exports = { id: 'REGISTRY-002', name: 'Missing SBOM & Model Card Issues', run };
