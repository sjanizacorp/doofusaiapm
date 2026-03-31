/**
 * ATLAS-001 — Model Reconnaissance & Extraction (MITRE ATLAS AML.T0024, AML.T0040)
 * Checks for controls against model API probing and model theft
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (!target.query_logging) {
    findings.push({ id: uuidv4(), title: 'Model API queries not logged (AML.T0040)', description: 'API queries to the model are not logged. Model extraction attacks work by querying the API thousands of times with crafted inputs to replicate model behaviour. Without logs, these attacks are undetectable.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'query_logging: false' });
  }

  if (!target.anomalous_query_detection) {
    findings.push({ id: uuidv4(), title: 'No anomalous query pattern detection (AML.T0024)', description: 'The API does not detect systematic probing patterns indicative of model extraction or reconnaissance. Adversaries probe model APIs to map decision boundaries before launching targeted attacks.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'anomalous_query_detection: false' });
  }

  if (!target.model_watermarking) {
    findings.push({ id: uuidv4(), title: 'Model not watermarked — theft undetectable (AML.T0040)', description: 'The model has no watermark. If the model is extracted or stolen, there is no way to prove ownership or detect that the theft occurred.', severity: 'medium', confidence: 'possible', resource: target.name, evidence: 'model_watermarking: false' });
  }

  return findings;
}
module.exports = { id: 'ATLAS-001', name: 'Model Reconnaissance & Extraction', run };
