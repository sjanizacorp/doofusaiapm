/**
 * OWASP LLM08:2025 — Vector and Embedding Weaknesses
 * RAG poisoning, embedding inversion, vector DB access control
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (target.vector_db && !target.embedding_input_validation) {
    findings.push({ id: uuidv4(), title: 'Embedding inputs not validated before indexing', description: 'Content is indexed into the vector database without validation. An attacker who can influence indexed content can inject adversarial embeddings that manipulate retrieval results or embed prompt injection payloads in retrieved chunks.', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'vector_db: true, embedding_input_validation: false' });
  }

  if (target.vector_db && !target.multi_tenant_isolation) {
    findings.push({ id: uuidv4(), title: 'No multi-tenant isolation in vector database', description: 'The vector database does not enforce tenant or user-level isolation on retrieval. A user can retrieve documents belonging to another user or tenant, enabling cross-tenant data leakage.', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'multi_tenant_isolation: false' });
  }

  if (target.vector_db && !target.embedding_model_provenance) {
    findings.push({ id: uuidv4(), title: 'Embedding model provenance undocumented', description: 'The embedding model used to generate vectors has no documented provenance. A compromised embedding model can produce misleading similarity results, degrading RAG accuracy and enabling retrieval manipulation attacks.', severity: 'medium', confidence: 'possible', resource: target.name, evidence: 'embedding_model_provenance: null' });
  }

  return findings;
}
module.exports = { id: 'OWASP-LLM08', name: 'Vector and Embedding Weaknesses', run };
