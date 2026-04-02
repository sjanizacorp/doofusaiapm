/**
 * Check: APP-002 — Insecure RAG Retrieval & PII Leakage in Context
 * Target type: ai_app
 *
 * OWASP LLM06 (Sensitive Info), OWASP LLM01 (indirect injection via retrieval).
 */

const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  const findings = [];

  // Vector DB access control
  if (target.vector_db && !target.vector_db_auth && !target.retrieval_acl) {
    findings.push({
      id: uuidv4(),
      title: 'Vector database has no access control on retrieval',
      description: 'The RAG pipeline retrieves from a vector database without row-level or user-level access controls. Any user can retrieve documents they should not have access to, enabling both data leakage and indirect prompt injection via poisoned documents.',
      severity: 'critical',
      confidence: 'confirmed',
      resource: target.name,
      evidence: 'vector_db_auth: false, retrieval_acl: null',
    });
  }

  // PII scanning on retrieved context
  if (!target.pii_filter_enabled && !target.output_scanner) {
    findings.push({
      id: uuidv4(),
      title: 'No PII filtering on retrieved context or model output',
      description: 'The RAG application does not scan retrieved documents or model responses for PII before returning them to the user. Customer data (names, emails, account numbers) in the vector store may leak into responses.',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: 'pii_filter_enabled: false, output_scanner: null',
    });
  }

  // Input validation
  if (!target.input_validation && !target.input_scanner) {
    findings.push({
      id: uuidv4(),
      title: 'No input validation or injection scanning on user queries',
      description: 'User queries are passed directly to the retrieval and LLM pipeline without validation. This enables direct prompt injection and allows adversarial inputs to manipulate retrieval results.',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: 'input_validation: false, input_scanner: null',
    });
  }

  // Indirect injection via document store
  if (target.web_browsing || target.url_fetching) {
    findings.push({
      id: uuidv4(),
      title: 'Agent fetches external URLs — indirect prompt injection risk',
      description: 'The application fetches external web content and injects it into the LLM context. Malicious web pages can embed instructions that manipulate agent behaviour (indirect prompt injection via retrieval).',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: 'web_browsing or url_fetching enabled without content sanitisation',
    });
  }

  return findings;
}

module.exports = { id: 'APP-002', name: 'Insecure RAG Retrieval & PII Leakage', run };
