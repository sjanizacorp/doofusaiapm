/**
 * Policy Loader — reads YAML/JSON policy files, validates schema, returns array of Policy objects.
 * Supports both built-in /policy and user /custom-policies directories.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { z } = require('zod');

// ── Schema ────────────────────────────────────────────────────────────────────

const FrameworkRefSchema = z.object({
  framework: z.enum(['OWASP_LLM', 'MITRE_ATLAS', 'NIST_AI_RMF', 'CUSTOM']),
  id: z.string().optional(),
  url: z.string().url().optional(),
  function: z.enum(['GOVERN', 'MAP', 'MEASURE', 'MANAGE']).optional(),
  category: z.string().optional(),
});

const PolicySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().min(1),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  target_types: z.array(z.enum(['llm_api', 'ai_infra', 'model_registry', 'ai_app'])),
  check_module: z.string().min(1),
  remediation: z.string().min(1),
  enabled: z.boolean().default(true),
  framework_refs: z.array(FrameworkRefSchema).min(1),
  tags: z.array(z.string()).default([]),
});

// ── Loader ────────────────────────────────────────────────────────────────────

function loadPoliciesFromDir(dirPath) {
  if (!fs.existsSync(dirPath)) return [];

  const policies = [];
  const files = fs.readdirSync(dirPath).filter(f => f.match(/\.(yaml|yml|json)$/));

  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    try {
      const raw = fs.readFileSync(fullPath, 'utf8');
      const parsed = file.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw);
      const result = PolicySchema.safeParse(parsed);

      if (!result.success) {
        console.warn(`[PolicyLoader] Invalid policy ${file}:`, result.error.flatten());
        continue;
      }
      policies.push({ ...result.data, _source: fullPath });
    } catch (err) {
      console.warn(`[PolicyLoader] Failed to parse ${file}:`, err.message);
    }
  }

  return policies;
}

function loadAllPolicies(engineRoot) {
  const builtIn = loadPoliciesFromDir(path.join(engineRoot, 'policy'));
  const custom = loadPoliciesFromDir(path.join(engineRoot, 'custom-policies'));

  const all = [...builtIn, ...custom];

  // Deduplicate by id — custom overrides built-in
  const map = new Map();
  for (const p of all) {
    if (map.has(p.id)) {
      console.info(`[PolicyLoader] Custom policy overrides built-in: ${p.id}`);
    }
    map.set(p.id, p);
  }

  const enabled = [...map.values()].filter(p => p.enabled !== false);
  console.info(`[PolicyLoader] Loaded ${enabled.length} policies (${builtIn.length} built-in, ${custom.length} custom)`);
  return enabled;
}

module.exports = { loadAllPolicies, PolicySchema };
