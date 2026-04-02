/**
 * ATLAS-003 — AI Agent Attack Surface (Oct 2025 ATLAS additions: AML.T0051.xxx)
 * Context poisoning, memory manipulation, agent hijacking
 */
const { v4: uuidv4 } = require('uuid');
async function run(target, config) {
  const findings = [];

  if (!target.agent_memory_isolation) {
    findings.push({ id: uuidv4(), title: 'Agent memory/context not isolated between sessions', description: 'The AI agent shares memory or context state across user sessions. An attacker in one session can poison the agent\'s memory to influence behaviour in subsequent sessions (context poisoning — AML.T0051.003).', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'agent_memory_isolation: false' });
  }

  if (!target.tool_call_validation) {
    findings.push({ id: uuidv4(), title: 'Agent tool calls not validated before execution', description: 'Tool call parameters from the LLM are passed directly to tool execution without validation. A prompt injection can craft malicious tool call arguments (e.g. path traversal, SQL injection) that execute through the tool.', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'tool_call_validation: false' });
  }

  if (!target.agent_action_logging) {
    findings.push({ id: uuidv4(), title: 'Agent actions not logged for audit', description: 'Agent tool calls, retrieved context, and decisions are not logged. Post-incident investigation of agent misbehaviour is impossible without an action log.', severity: 'high', confidence: 'confirmed', resource: target.name, evidence: 'agent_action_logging: false' });
  }

  if (target.persistent_agent_memory && !target.memory_content_validation) {
    findings.push({ id: uuidv4(), title: 'Persistent agent memory written without content validation', description: 'The agent writes to persistent memory without validating content for injection payloads. Malicious content written to memory can influence all future sessions (persistent context poisoning).', severity: 'critical', confidence: 'probable', resource: target.name, evidence: 'persistent_agent_memory: true, memory_content_validation: false' });
  }

  return findings;
}
module.exports = { id: 'ATLAS-003', name: 'AI Agent Attack Surface', run };
