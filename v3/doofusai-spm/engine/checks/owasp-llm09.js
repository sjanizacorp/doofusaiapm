/**
 * OWASP LLM09:2025 — Misinformation
 * Hallucination controls, fact-checking, output verification
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (!target.hallucination_mitigation && !target.grounding_mechanism) {
    findings.push({ id: uuidv4(), title: 'No hallucination mitigation or output grounding', description: 'The application has no grounding mechanism (RAG, structured prompting, output verification) to reduce hallucination risk. In high-stakes domains this can lead to materially false information being presented as fact.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'hallucination_mitigation: false, grounding_mechanism: null' });
  }

  if (target.high_stakes_domain && !target.human_review_before_delivery) {
    findings.push({ id: uuidv4(), title: 'High-stakes domain with no human review gate', description: 'The application operates in a high-stakes domain (medical, legal, financial) but model outputs are delivered to end users without human review. Confident-sounding misinformation in these domains can cause direct harm.', severity: 'critical', confidence: 'probable', resource: target.name, evidence: `high_stakes_domain: ${target.high_stakes_domain}, human_review_before_delivery: false` });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM09', name: 'Misinformation', run };
