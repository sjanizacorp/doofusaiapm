/**
 * Check: APP-001 — Excessive Agency (OWASP LLM08)
 * Target type: ai_app
 *
 * LLM agents with overly broad tool scopes, missing human-in-the-loop
 * for high-risk actions, and unbounded recursion depth.
 */

const { v4: uuidv4 } = require('uuid');

const HIGH_RISK_TOOLS = [
  'execute_code', 'run_shell', 'delete_file', 'send_email', 'make_payment',
  'database_write', 'api_post', 'deploy', 'create_user', 'modify_permissions',
];

async function run(target, config) {
  const findings = [];

  const tools = target.tools || target.available_tools || [];
  const hitl = target.human_in_the_loop || false;
  const maxDepth = target.max_recursion_depth || target.max_iterations;

  // High-risk tools without HITL
  const riskyTools = tools.filter(t =>
    HIGH_RISK_TOOLS.some(r => String(t).toLowerCase().includes(r))
  );

  if (riskyTools.length > 0 && !hitl) {
    findings.push({
      id: uuidv4(),
      title: `Agent has high-risk tool access without human-in-the-loop (${riskyTools.length} tools)`,
      description: `The agent has access to ${riskyTools.length} high-risk tools (${riskyTools.slice(0,3).join(', ')}${riskyTools.length > 3 ? '…' : ''}) with no human approval gate. A prompt injection or hallucination could trigger irreversible actions.`,
      severity: 'critical',
      confidence: 'confirmed',
      resource: target.name,
      evidence: `High-risk tools: ${riskyTools.join(', ')}`,
    });
  }

  // Unbounded recursion / iteration
  if (!maxDepth || maxDepth > 20) {
    findings.push({
      id: uuidv4(),
      title: 'No recursion depth limit — agent loop DoS risk',
      description: 'The agent has no maximum iteration or recursion depth configured. A prompt injection or adversarial input could cause the agent to loop indefinitely, exhausting compute resources and LLM quota.',
      severity: 'high',
      confidence: 'probable',
      resource: target.name,
      evidence: `max_recursion_depth: ${maxDepth || 'not set'}`,
    });
  }

  // Tool scope too broad
  if (tools.length > 15) {
    findings.push({
      id: uuidv4(),
      title: `Overly broad tool scope (${tools.length} tools)`,
      description: `The agent has access to ${tools.length} tools. Principle of least privilege requires agents to only have access to tools strictly necessary for their defined task. Broad access amplifies the blast radius of prompt injection.`,
      severity: 'medium',
      confidence: 'probable',
      resource: target.name,
      evidence: `Tool count: ${tools.length}`,
    });
  }

  return findings;
}

module.exports = { id: 'APP-001', name: 'Excessive Agency', run };
