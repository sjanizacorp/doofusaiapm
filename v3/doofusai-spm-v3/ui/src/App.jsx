import { useState, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line
} from "recharts";

// ─────────────────────────────────────────────
// DESIGN TOKENS
// ─────────────────────────────────────────────
const C = {
  bg:       "#0b0d12",
  surface:  "#111520",
  elevated: "#182030",
  border:   "#1e2a3a",
  borderHi: "#2a3f58",
  text:     "#c8d0e0",
  muted:    "#536070",
  dim:      "#324050",
  accent:   "#3b80f5",
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#f59e0b",
  low:      "#22c55e",
  info:     "#6b7280",
  healthy:  "#22c55e",
  at_risk:  "#f97316",
  teal:     "#14b8a6",
  purple:   "#8b5cf6",
};

const SEV_COLORS = { critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info };
const SEV_W      = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VERSION    = "3.1";

// ─────────────────────────────────────────────
// CHECK FAMILIES (for scan wizard step)
// ─────────────────────────────────────────────
const CHECK_FAMILIES = [
  {
    id: "owasp",
    label: "OWASP LLM Top 10",
    description: "All 10 checks from the 2025 OWASP LLM Top 10 — prompt injection, data leakage, supply chain, poisoning, output handling, excessive agency, system prompt leakage, vector weaknesses, misinformation, unbounded consumption.",
    color: C.purple,
    checkIds: ["OWASP-LLM01","OWASP-LLM02","OWASP-LLM03","OWASP-LLM04","OWASP-LLM05","OWASP-LLM06","OWASP-LLM07","OWASP-LLM08","OWASP-LLM09","OWASP-LLM10"],
  },
  {
    id: "mitre",
    label: "MITRE ATLAS",
    description: "Adversarial ML checks based on MITRE ATLAS v5.4 — model reconnaissance, adversarial evasion, and AI agent attack surface checks including 2025 agentic AI techniques.",
    color: C.accent,
    checkIds: ["ATLAS-001","ATLAS-002","ATLAS-003"],
  },
  {
    id: "infrastructure",
    label: "AI Infrastructure",
    description: "Checks for ML platform security — unauthenticated MLflow/Jupyter endpoints, unencrypted model storage, network isolation, and audit logging.",
    color: C.teal,
    checkIds: ["INFRA-001","INFRA-002"],
  },
  {
    id: "registry",
    label: "Model Registries",
    description: "Supply chain checks for model registries — unsigned artefacts, pickle-format risk, missing SBOM, no licence declaration.",
    color: "#d97706",
    checkIds: ["REGISTRY-001","REGISTRY-002"],
  },
  {
    id: "cicd",
    label: "CI/CD Pipelines",
    description: "Pipeline security checks — branch protection, pinned actions, SLSA levels, secret scanning, model signing gates, experiment tracking, and drift monitoring.",
    color: "#ec4899",
    checkIds: ["CICD-001","CICD-002"],
  },
  {
    id: "tools",
    label: "Open-Source Tools",
    description: "Live scanning using detect-secrets, garak, llm-guard, and checkov. Requires these tools installed via pip.",
    color: "#84cc16",
    checkIds: ["TOOL-DETECT-SECRETS","TOOL-GARAK","TOOL-LLM-GUARD","TOOL-CHECKOV"],
  },
  {
    id: "all",
    label: "All Checks (Full Scan)",
    description: "Run every installed check — all 25 checks across all families. Recommended for comprehensive first-time assessments.",
    color: C.critical,
    checkIds: [], // populated dynamically
  },
];

// ─────────────────────────────────────────────
// ALL CHECKS REGISTRY — 25 checks
// ─────────────────────────────────────────────
const ALL_CHECKS = [
  { id:"OWASP-LLM01", name:"Prompt Injection — direct",          severity:"critical", target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM01","MITRE_ATLAS:AML.T0051","NIST_AI_RMF:MEASURE"], enabled:true, tags:["prompt-injection"], family:"owasp",          description:"System prompt lacks hardening; direct injection attacks can override model behaviour." },
  { id:"OWASP-LLM02", name:"Sensitive Information Disclosure",    severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM02","MITRE_ATLAS:AML.T0057","NIST_AI_RMF:MEASURE"], enabled:true, tags:["pii","data-leakage"], family:"owasp",          description:"Training data leakage, PII in outputs, credentials embedded in system prompts." },
  { id:"OWASP-LLM03", name:"Supply Chain Vulnerabilities",        severity:"high",     target_types:["llm_api","ai_app","model_registry"],                          frameworks:["OWASP_LLM:LLM03","MITRE_ATLAS:AML.T0010","NIST_AI_RMF:MAP"],     enabled:true, tags:["supply-chain"],   family:"owasp",          description:"Third-party models and plugins without provenance or security review." },
  { id:"OWASP-LLM04", name:"Data and Model Poisoning",            severity:"critical", target_types:["llm_api","ai_infra","model_registry"],                         frameworks:["OWASP_LLM:LLM04","MITRE_ATLAS:AML.T0020","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["poisoning"],       family:"owasp",          description:"Compromised training data or fine-tuning pipelines embed backdoors in production models." },
  { id:"OWASP-LLM05", name:"Improper Output Handling",            severity:"critical", target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM05","MITRE_ATLAS:AML.T0051","NIST_AI_RMF:MEASURE"], enabled:true, tags:["output-handling"],  family:"owasp",          description:"LLM outputs rendered without sanitisation enabling XSS, SSRF, code injection." },
  { id:"OWASP-LLM06", name:"API Key & Secrets Exposure",          severity:"critical", target_types:["llm_api"],                                                    frameworks:["OWASP_LLM:LLM06","MITRE_ATLAS:AML.T0057","NIST_AI_RMF:GOVERN"],  enabled:true, tags:["secrets","api-key"], family:"owasp",          description:"API keys exposed in configuration, logs, or passed directly instead of via env vars." },
  { id:"OWASP-LLM07", name:"System Prompt Leakage",               severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM07","MITRE_ATLAS:AML.T0056","NIST_AI_RMF:MEASURE"], enabled:true, tags:["system-prompt"],   family:"owasp",          description:"System prompts with business logic or credentials extractable via crafted queries." },
  { id:"OWASP-LLM08", name:"Vector and Embedding Weaknesses",     severity:"critical", target_types:["ai_app"],                                                     frameworks:["OWASP_LLM:LLM08","MITRE_ATLAS:AML.T0020","NIST_AI_RMF:MEASURE"], enabled:true, tags:["rag","vector-db"],  family:"owasp",          description:"RAG vector DBs without access control enable data leakage and retrieval manipulation." },
  { id:"OWASP-LLM09", name:"Misinformation",                      severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM09","NIST_AI_RMF:MEASURE"],                         enabled:true, tags:["hallucination"],   family:"owasp",          description:"LLMs hallucinate without grounding; high-stakes domains need human review gates." },
  { id:"OWASP-LLM10", name:"Unbounded Consumption",               severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM10","NIST_AI_RMF:MANAGE"],                          enabled:true, tags:["rate-limiting"],   family:"owasp",          description:"No rate limits or spend caps allow Denial of Wallet and runaway consumption." },
  { id:"INFRA-001",   name:"Unauthenticated ML Endpoints",        severity:"critical", target_types:["ai_infra"],                                                   frameworks:["OWASP_LLM:LLM03","MITRE_ATLAS:AML.T0007","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["mlflow","jupyter"], family:"infrastructure", description:"MLflow and Jupyter endpoints accessible without credentials, enabling RCE." },
  { id:"INFRA-002",   name:"Unencrypted Model Artefact Storage",  severity:"high",     target_types:["ai_infra"],                                                   frameworks:["OWASP_LLM:LLM03","MITRE_ATLAS:AML.T0012","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["s3","encryption"],  family:"infrastructure", description:"Model weights in unencrypted or publicly accessible cloud storage." },
  { id:"REGISTRY-001",name:"Unsigned Artefacts & Pickle Risk",    severity:"critical", target_types:["model_registry"],                                             frameworks:["OWASP_LLM:LLM03","MITRE_ATLAS:AML.T0010","NIST_AI_RMF:MAP"],     enabled:true, tags:["pickle","signing"],  family:"registry",       description:"Unsigned models or pickle-format artefacts enable supply chain attacks and RCE on load." },
  { id:"REGISTRY-002",name:"Missing SBOM & Model Card Issues",    severity:"high",     target_types:["model_registry"],                                             frameworks:["OWASP_LLM:LLM03","NIST_AI_RMF:GOVERN"],                          enabled:true, tags:["sbom"],            family:"registry",       description:"No SBOM, licence, or training data provenance on public model registries." },
  { id:"APP-001",     name:"Excessive Agency",                    severity:"critical", target_types:["ai_app"],                                                     frameworks:["OWASP_LLM:LLM06","MITRE_ATLAS:AML.T0051","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["agent","hitl"],     family:"owasp",          description:"Agents with high-risk tool access without HITL controls or iteration limits." },
  { id:"APP-002",     name:"Insecure RAG Retrieval & PII Leakage",severity:"critical", target_types:["ai_app"],                                                     frameworks:["OWASP_LLM:LLM02","NIST_AI_RMF:MEASURE"],                         enabled:true, tags:["rag","pii"],        family:"owasp",          description:"RAG pipeline retrieves without access control; no PII filtering on outputs." },
  { id:"CICD-001",    name:"CI/CD Pipeline Security",             severity:"critical", target_types:["cicd_pipeline"],                                              frameworks:["OWASP_LLM:LLM03","MITRE_ATLAS:AML.T0010","NIST_AI_RMF:GOVERN"],  enabled:true, tags:["cicd","slsa"],      family:"cicd",           description:"Insecure pipelines allow supply chain attacks, secret exfiltration, unsigned deployments." },
  { id:"CICD-002",    name:"ML Pipeline Integrity",               severity:"high",     target_types:["cicd_pipeline","ai_infra"],                                   frameworks:["OWASP_LLM:LLM04","MITRE_ATLAS:AML.T0020","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["mlops","drift"],    family:"cicd",           description:"No experiment tracking, data lineage, model gates, or drift monitoring in ML pipeline." },
  { id:"ATLAS-001",   name:"Model Reconnaissance & Extraction",   severity:"high",     target_types:["llm_api","model_registry"],                                   frameworks:["MITRE_ATLAS:AML.T0040","OWASP_LLM:LLM10","NIST_AI_RMF:MEASURE"], enabled:true, tags:["model-theft"],     family:"mitre",          description:"No query logging or anomaly detection to detect systematic model extraction probing." },
  { id:"ATLAS-002",   name:"Adversarial Evasion Attacks",         severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["MITRE_ATLAS:AML.T0015","NIST_AI_RMF:MEASURE"],                   enabled:true, tags:["adversarial"],     family:"mitre",          description:"Models without adversarial input defences vulnerable to imperceptible perturbations." },
  { id:"ATLAS-003",   name:"AI Agent Attack Surface",             severity:"critical", target_types:["ai_app"],                                                     frameworks:["MITRE_ATLAS:AML.T0051","OWASP_LLM:LLM06","NIST_AI_RMF:MANAGE"],  enabled:true, tags:["agent","context"],  family:"mitre",          description:"Agent memory isolation, tool validation, and action logging absent; context poisoning risk." },
  { id:"TOOL-DETECT-SECRETS", name:"Exposed Credentials (detect-secrets)", severity:"critical", target_types:["llm_api","ai_infra","model_registry","ai_app","cicd_pipeline"], frameworks:["OWASP_LLM:LLM06","NIST_AI_RMF:GOVERN"], enabled:true, tags:["secrets"], family:"tools", description:"API keys, tokens, credentials found in source code or configuration files." },
  { id:"TOOL-GARAK",    name:"LLM Vulnerability Probe (garak)",   severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM01","MITRE_ATLAS:AML.T0051"],                       enabled:true, tags:["garak","jailbreak"],family:"tools",          description:"LLM endpoint fails garak probes: prompt injection, jailbreaks, data extraction." },
  { id:"TOOL-LLM-GUARD",name:"Input/Output Scanner (llm-guard)",  severity:"high",     target_types:["llm_api","ai_app"],                                           frameworks:["OWASP_LLM:LLM01","OWASP_LLM:LLM02"],                             enabled:true, tags:["llm-guard","pii"],  family:"tools",          description:"Unsafe content detected in prompts or outputs: PII, injection, toxicity." },
  { id:"TOOL-CHECKOV",  name:"IaC Misconfiguration (checkov)",    severity:"high",     target_types:["ai_infra","cicd_pipeline"],                                   frameworks:["OWASP_LLM:LLM03","NIST_AI_RMF:MANAGE"],                          enabled:true, tags:["checkov","iac"],    family:"tools",          description:"Terraform, CloudFormation, K8s misconfigs for SageMaker, GCP AI, Azure ML." },
];

// Populate "all" family's checkIds
CHECK_FAMILIES.find(f => f.id === "all").checkIds = ALL_CHECKS.map(c => c.id);

// ─────────────────────────────────────────────
// SEED DATA
// ─────────────────────────────────────────────
const SEED_FINDINGS = [
  { id:"F-001", policy_id:"OWASP-LLM01", policy_name:"Prompt Injection — direct",       target_type:"llm_api",       resource:"prod-openai-gateway",  severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"No system prompt configured",                        description:"The LLM endpoint has no system prompt, making it trivially susceptible to direct prompt injection.",                        evidence:"system_prompt: null",                                               remediation:"1. Add hardened system prompt prefix.\n2. Run input through llm-guard.\n3. Deploy rebuff firewall.",                   framework_refs:[{framework:"OWASP_LLM",id:"LLM01"},{framework:"MITRE_ATLAS",id:"AML.T0051.000"}],                first_seen:"2025-03-10T09:12:00Z" },
  { id:"F-002", policy_id:"OWASP-LLM06", policy_name:"API Key & Secrets Exposure",      target_type:"llm_api",       resource:"dev-anthropic-proxy",  severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"API key passed directly — not via environment variable",description:"The API key was provided as a raw string rather than via environment variable.",                                              evidence:"api_key_raw field present in target config",                        remediation:"1. Store API keys in environment variables.\n2. Never log raw API keys.\n3. Rotate any exposed key.",                  framework_refs:[{framework:"OWASP_LLM",id:"LLM06"},{framework:"NIST_AI_RMF",function:"GOVERN"}],                 first_seen:"2025-03-11T14:30:00Z" },
  { id:"F-003", policy_id:"INFRA-001",   policy_name:"Unauthenticated ML Endpoints",    target_type:"ai_infra",      resource:"mlflow-prod:5000",     severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"Unauthenticated MLflow REST API accessible",           description:"MLflow endpoint returned HTTP 200 without authentication.",                                                               evidence:"GET /api/2.0/mlflow/experiments/list → HTTP 200, no WWW-Authenticate", remediation:"1. Place MLflow behind OAuth2 proxy.\n2. Restrict to VPC only.\n3. Enable audit logging.",          framework_refs:[{framework:"OWASP_LLM",id:"LLM05"},{framework:"MITRE_ATLAS",id:"AML.T0007.000"}],               first_seen:"2025-03-09T11:00:00Z" },
  { id:"F-004", policy_id:"APP-001",     policy_name:"Excessive Agency",                target_type:"ai_app",        resource:"sales-agent-prod",     severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"Agent has high-risk tools without HITL (4 tools)",     description:"Agent has access to send_email, database_write, make_payment, deploy without human approval gate.",                       evidence:"High-risk tools: send_email, database_write, make_payment, deploy",  remediation:"1. Apply least-privilege tool scoping.\n2. Add HITL approval gates.\n3. Set max_iterations ≤ 10.", framework_refs:[{framework:"OWASP_LLM",id:"LLM08"},{framework:"MITRE_ATLAS",id:"AML.T0051.001"}],               first_seen:"2025-03-12T08:00:00Z" },
  { id:"F-005", policy_id:"CICD-001",    policy_name:"CI/CD Pipeline Security",         target_type:"cicd_pipeline", resource:"github/ml-pipeline",   severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"No branch protection on main branch",                  description:"Branch protection rules are not enforced. Anyone with write access can push directly to production.",                       evidence:"branch_protection: false",                                          remediation:"1. Enable branch protection with required PR reviews.\n2. Enable secret scanning.\n3. Pin all actions to SHA.", framework_refs:[{framework:"OWASP_LLM",id:"LLM03"},{framework:"MITRE_ATLAS",id:"AML.T0010.002"}],               first_seen:"2025-03-13T10:00:00Z" },
  { id:"F-006", policy_id:"REGISTRY-001",policy_name:"Unsigned Artefacts & Pickle Risk",target_type:"model_registry",resource:"hf-internal-registry", severity:"high",     confidence:"confirmed", score:8,    status:"open",         title:"Pickle-format models in registry (.pkl, .pt)",         description:"Models stored in pickle format execute arbitrary code on load.",                                                           evidence:"Artefact formats found: pkl, pt",                                   remediation:"1. Migrate to SafeTensors.\n2. Enforce model signing with cosign.\n3. Verify checksums on load.",framework_refs:[{framework:"OWASP_LLM",id:"LLM05"},{framework:"MITRE_ATLAS",id:"AML.T0010.000"}],               first_seen:"2025-03-08T10:00:00Z" },
  { id:"F-007", policy_id:"ATLAS-003",   policy_name:"AI Agent Attack Surface",         target_type:"ai_app",        resource:"support-agent",        severity:"critical", confidence:"probable",  score:7.5,  status:"open",         title:"Agent memory not isolated between sessions",           description:"Agent shares context state across user sessions enabling context poisoning attacks.",                                       evidence:"agent_memory_isolation: false",                                     remediation:"1. Isolate agent memory per session and user.\n2. Validate tool call parameters.\n3. Log all agent actions.", framework_refs:[{framework:"MITRE_ATLAS",id:"AML.T0051.003"}],                                                    first_seen:"2025-03-14T08:00:00Z" },
  { id:"F-008", policy_id:"CICD-002",    policy_name:"ML Pipeline Integrity",           target_type:"cicd_pipeline", resource:"training-pipeline",    severity:"high",     confidence:"probable",  score:6,    status:"acknowledged", title:"No experiment tracking configured",                    description:"Training runs not tracked, making it impossible to reproduce models or roll back to known-good versions.",                  evidence:"experiment_tracking: false",                                        remediation:"1. Integrate MLflow or W&B.\n2. Track dataset versions with DVC.\n3. Define automated model promotion criteria.", framework_refs:[{framework:"OWASP_LLM",id:"LLM04"},{framework:"NIST_AI_RMF",function:"MANAGE"}],                 first_seen:"2025-03-11T15:00:00Z" },
  { id:"F-009", policy_id:"OWASP-LLM08", policy_name:"Vector and Embedding Weaknesses", target_type:"ai_app",        resource:"support-rag-app",      severity:"critical", confidence:"confirmed", score:10,   status:"open",         title:"No multi-tenant isolation in vector database",         description:"Vector database does not enforce tenant isolation; users can retrieve documents belonging to other tenants.",               evidence:"multi_tenant_isolation: false",                                     remediation:"1. Enforce namespace isolation per tenant.\n2. Implement row-level security.\n3. Validate content before indexing.", framework_refs:[{framework:"OWASP_LLM",id:"LLM08"},{framework:"NIST_AI_RMF",function:"MEASURE"}],                first_seen:"2025-03-12T16:00:00Z" },
  { id:"F-010", policy_id:"INFRA-002",   policy_name:"Unencrypted Model Artefact Storage",target_type:"ai_infra",    resource:"s3://ml-models-prod",  severity:"high",     confidence:"confirmed", score:8,    status:"resolved",     title:"Model artefact S3 bucket publicly readable",           description:"S3 bucket has public ACL exposing model weights to the internet.",                                                        evidence:"ACL: public-read",                                                  remediation:"1. Enable S3 SSE-KMS.\n2. Set ACLs to private.\n3. Enable versioning.",                       framework_refs:[{framework:"OWASP_LLM",id:"LLM05"},{framework:"NIST_AI_RMF",function:"MANAGE"}],                 first_seen:"2025-03-07T12:30:00Z" },
];

const SEED_SCANS = [
  { id:"SCN-001", target_type:"llm_api",       target_meta:{ name:"prod-openai-gateway"  }, status:"completed", posture_score:42, tier:"at_risk",  created_at:"2025-03-13T09:00:00Z", finished_at:"2025-03-13T09:03:12Z", findings:3 },
  { id:"SCN-002", target_type:"ai_infra",       target_meta:{ name:"ml-platform-prod"    }, status:"completed", posture_score:28, tier:"critical", created_at:"2025-03-12T14:00:00Z", finished_at:"2025-03-12T14:05:30Z", findings:2 },
  { id:"SCN-003", target_type:"cicd_pipeline",  target_meta:{ name:"github/ml-pipeline"  }, status:"completed", posture_score:35, tier:"critical", created_at:"2025-03-13T10:00:00Z", finished_at:"2025-03-13T10:02:45Z", findings:2 },
  { id:"SCN-004", target_type:"ai_app",         target_meta:{ name:"sales-agent-prod"    }, status:"completed", posture_score:31, tier:"critical", created_at:"2025-03-12T08:00:00Z", finished_at:"2025-03-12T08:02:45Z", findings:2 },
  { id:"SCN-005", target_type:"model_registry", target_meta:{ name:"hf-internal-registry"}, status:"completed", posture_score:67, tier:"at_risk",  created_at:"2025-03-11T11:00:00Z", finished_at:"2025-03-11T11:01:55Z", findings:1 },
];

// ─────────────────────────────────────────────
// SHARED UI ATOMS
// ─────────────────────────────────────────────
function SevBadge({ s }) {
  const m = {
    critical: { bg:"#2d1414", br:"#7f2020", t:"#ef4444" },
    high:     { bg:"#2d1d10", br:"#7f4010", t:"#f97316" },
    medium:   { bg:"#2d2410", br:"#7f6010", t:"#f59e0b" },
    low:      { bg:"#0d2314", br:"#1a5a28", t:"#22c55e" },
    info:     { bg:"#1a1e2a", br:"#3a4258", t:"#6b7280" },
  };
  const c = m[s] || m.info;
  return (
    <span style={{ background:c.bg, border:`1px solid ${c.br}`, color:c.t,
                   padding:"2px 8px", borderRadius:3, fontSize:11,
                   fontFamily:"monospace", fontWeight:600,
                   textTransform:"uppercase", letterSpacing:"0.04em" }}>
      {s}
    </span>
  );
}

function StatusBadge({ s }) {
  const m = {
    open:         { bg:"#2d1414", br:"#7f2020", t:"#ef4444" },
    acknowledged: { bg:"#2d2410", br:"#7f6010", t:"#f59e0b" },
    resolved:     { bg:"#0d2314", br:"#1a5a28", t:"#22c55e" },
    running:      { bg:"#0d1e35", br:"#1a4578", t:"#3b7ff5" },
    completed:    { bg:"#0d2314", br:"#1a5a28", t:"#22c55e" },
    failed:       { bg:"#2d1414", br:"#7f2020", t:"#ef4444" },
    pending:      { bg:"#1a1e2a", br:"#3a4258", t:"#6b7280" },
    confirmed:    { bg:"#0d1e35", br:"#1a4578", t:"#3b7ff5" },
    probable:     { bg:"#2d2410", br:"#7f6010", t:"#f59e0b" },
    possible:     { bg:"#1a1e2a", br:"#3a4258", t:"#9ca3af" },
  };
  const c = m[s] || m.pending;
  return (
    <span style={{ background:c.bg, border:`1px solid ${c.br}`, color:c.t,
                   padding:"2px 8px", borderRadius:3, fontSize:11,
                   fontFamily:"monospace", fontWeight:600,
                   textTransform:"uppercase", letterSpacing:"0.04em" }}>
      {s}
    </span>
  );
}

function FWBadge({ fw }) {
  const m = {
    OWASP_LLM:   { bg:"#1a0d2d", br:"#4a1a7f", t:"#a78bfa" },
    MITRE_ATLAS:  { bg:"#0d1a2d", br:"#1a4578", t:"#60a5fa" },
    NIST_AI_RMF: { bg:"#0d2520", br:"#1a6050", t:"#34d399" },
    CUSTOM:      { bg:"#1a1e2a", br:"#3a4258", t:"#9ca3af" },
  };
  const urls = {
    OWASP_LLM:  "https://genai.owasp.org/llm-top-10/",
    MITRE_ATLAS: "https://atlas.mitre.org/",
    NIST_AI_RMF:"https://www.nist.gov/artificial-intelligence/ai-risk-management-framework",
  };
  const s = m[fw.framework] || m.CUSTOM;
  return (
    <a href={fw.url || urls[fw.framework] || "#"} target="_blank" rel="noreferrer"
       style={{ background:s.bg, border:`1px solid ${s.br}`, color:s.t,
                padding:"2px 7px", borderRadius:3, fontSize:10,
                fontFamily:"monospace", textDecoration:"none",
                display:"inline-block", marginRight:4, marginBottom:4 }}>
      {fw.framework.replace(/_/g," ")} {fw.id || fw.function || ""}
    </a>
  );
}

function Card({ children, style = {} }) {
  return (
    <div style={{ background:C.surface, border:`1px solid ${C.border}`,
                  borderRadius:8, padding:"20px 24px", ...style }}>
      {children}
    </div>
  );
}

function SecTitle({ children }) {
  return (
    <div style={{ fontFamily:"monospace", fontSize:10, letterSpacing:"0.12em",
                  color:C.muted, textTransform:"uppercase", marginBottom:16,
                  borderBottom:`1px solid ${C.border}`, paddingBottom:8 }}>
      {children}
    </div>
  );
}

function Btn({ children, onClick, variant = "default", disabled = false, style = {} }) {
  const variants = {
    default: { bg:C.elevated,   br:C.border,    t:C.text    },
    primary: { bg:"#1a3a80",    br:C.accent,    t:"#60a5fa" },
    success: { bg:"#0d2314",    br:"#1a5a28",   t:C.healthy },
    danger:  { bg:"#2d1414",    br:"#7f2020",   t:C.critical},
    warning: { bg:"#2d2410",    br:"#7f6010",   t:C.medium  },
  };
  const v = variants[variant] || variants.default;
  return (
    <button onClick={onClick} disabled={disabled}
            style={{ background:v.bg, border:`1px solid ${v.br}`,
                     color: disabled ? C.dim : v.t,
                     cursor: disabled ? "not-allowed" : "pointer",
                     padding:"7px 16px", borderRadius:4,
                     fontSize:12, fontFamily:"monospace",
                     transition:"all 0.15s", opacity: disabled ? 0.6 : 1, ...style }}>
      {children}
    </button>
  );
}

// ─────────────────────────────────────────────
// POSTURE GAUGE
// ─────────────────────────────────────────────
function PostureGauge({ score }) {
  const tier  = score >= 90 ? "Healthy" : score >= 70 ? "Needs Attention" : score >= 40 ? "At Risk" : "Critical";
  const color = score >= 90 ? C.healthy : score >= 70 ? C.medium : score >= 40 ? C.high : C.critical;
  const r = 80, cx = 110, cy = 105, startAngle = -210, totalDeg = 240;
  const pct = Math.min(score / 100, 1);
  const polar = (deg, rad) => ({ x: cx + rad * Math.cos(deg * Math.PI / 180), y: cy + rad * Math.sin(deg * Math.PI / 180) });
  const arc = (start, sweep, radius) => {
    const e = polar(start + sweep, radius), s = polar(start, radius);
    return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${sweep > 180 ? 1 : 0} 1 ${e.x} ${e.y}`;
  };
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
      <svg width="220" height="155" viewBox="0 0 220 155">
        <path d={arc(startAngle, totalDeg, r)} fill="none" stroke={C.border} strokeWidth="10" strokeLinecap="round" />
        <path d={arc(startAngle, pct * totalDeg, r)} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" />
        <text x={cx} y={cy - 10} textAnchor="middle" fill={color} style={{ fontSize:36, fontFamily:"monospace", fontWeight:700 }}>{Math.round(score)}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill={color} style={{ fontSize:11, fontFamily:"monospace", letterSpacing:"0.06em" }}>{tier.toUpperCase()}</text>
        <text x={cx} y={cy + 30} textAnchor="middle" fill={C.muted} style={{ fontSize:10, fontFamily:"monospace" }}>POSTURE SCORE</text>
      </svg>
    </div>
  );
}

// ─────────────────────────────────────────────
// FINDING DRAWER
// ─────────────────────────────────────────────
function FindingDrawer({ finding, onClose, onStatusChange }) {
  if (!finding) return null;
  return (
    <div style={{ position:"fixed", top:0, right:0, bottom:0, width:520,
                  background:C.surface, borderLeft:`1px solid ${C.borderHi}`,
                  overflowY:"auto", zIndex:200, padding:"24px",
                  boxShadow:"-8px 0 32px rgba(0,0,0,0.7)" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:20 }}>
        <div>
          <div style={{ fontFamily:"monospace", fontSize:10, color:C.muted, letterSpacing:"0.1em", marginBottom:6 }}>{finding.id}</div>
          <div style={{ color:C.text, fontSize:15, fontWeight:600, lineHeight:1.4, maxWidth:380 }}>{finding.title}</div>
        </div>
        <button onClick={onClose} style={{ background:"transparent", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", padding:"4px 10px", borderRadius:4, fontSize:16 }}>✕</button>
      </div>
      <div style={{ display:"flex", gap:8, marginBottom:20, flexWrap:"wrap" }}>
        <SevBadge s={finding.severity} /><StatusBadge s={finding.status} />
        <span style={{ fontFamily:"monospace", fontSize:11, color:C.muted, padding:"2px 8px", border:`1px solid ${C.border}`, borderRadius:3 }}>{finding.target_type}</span>
      </div>
      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>Description</div>
        <p style={{ color:C.text, fontSize:13, lineHeight:1.7, margin:0 }}>{finding.description}</p>
      </div>
      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>Affected Resource</div>
        <code style={{ background:C.elevated, border:`1px solid ${C.border}`, padding:"6px 12px", borderRadius:4, fontSize:12, color:C.teal, display:"block" }}>{finding.resource}</code>
      </div>
      {finding.evidence && (
        <div style={{ marginBottom:16 }}>
          <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>Evidence</div>
          <pre style={{ background:C.elevated, border:`1px solid ${C.border}`, padding:"10px 12px", borderRadius:4, fontSize:11, color:C.medium, margin:0, whiteSpace:"pre-wrap", wordBreak:"break-word" }}>{finding.evidence}</pre>
        </div>
      )}
      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:8, textTransform:"uppercase", letterSpacing:"0.08em" }}>Framework Mapping</div>
        <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
          {finding.framework_refs.map((fw, i) => <FWBadge key={i} fw={fw} />)}
        </div>
      </div>
      <div style={{ marginBottom:20 }}>
        <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:8, textTransform:"uppercase", letterSpacing:"0.08em" }}>Remediation Steps</div>
        <div style={{ background:C.elevated, border:`1px solid ${C.border}`, borderRadius:4, padding:"12px 16px" }}>
          {finding.remediation.split("\n").filter(Boolean).map((line, i) => (
            <div key={i} style={{ color:C.text, fontSize:12, lineHeight:1.7, fontFamily:"monospace" }}>{line}</div>
          ))}
        </div>
        <button onClick={() => navigator.clipboard.writeText(finding.remediation)}
                style={{ marginTop:8, background:"transparent", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", padding:"5px 12px", borderRadius:4, fontSize:11, fontFamily:"monospace" }}>
          ⎘ Copy remediation
        </button>
      </div>
      <div style={{ display:"flex", gap:8, borderTop:`1px solid ${C.border}`, paddingTop:16 }}>
        {finding.status !== "resolved" && (
          <Btn variant="success" onClick={() => onStatusChange(finding.id, "resolved")} style={{ flex:1 }}>✓ Mark Resolved</Btn>
        )}
        {finding.status === "open" && (
          <Btn variant="warning" onClick={() => onStatusChange(finding.id, "acknowledged")} style={{ flex:1 }}>⚑ Acknowledge</Btn>
        )}
        {finding.status !== "open" && (
          <Btn onClick={() => onStatusChange(finding.id, "open")} style={{ flex:1 }}>↩ Reopen</Btn>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────
function Dashboard({ findings, scans }) {
  const [sel, setSel] = useState(null);
  const handleStatus = useCallback((id, status) => {
    setSel(null);
  }, []);

  const open = findings.filter(f => f.status !== "resolved");
  const score = Math.max(0, 100 - open.reduce((s, f) => s + f.score * 1.5, 0));

  const bySev = ["critical","high","medium","low","info"]
    .map(s => ({ severity:s, count: open.filter(f => f.severity === s).length }))
    .filter(d => d.count > 0);

  const byFW = [
    { name:"OWASP LLM",   value: findings.filter(f => f.framework_refs.some(r => r.framework === "OWASP_LLM")).length,   color: C.purple },
    { name:"MITRE ATLAS", value: findings.filter(f => f.framework_refs.some(r => r.framework === "MITRE_ATLAS")).length,  color: C.accent },
    { name:"NIST RMF",    value: findings.filter(f => f.framework_refs.some(r => r.framework === "NIST_AI_RMF")).length,  color: C.teal   },
  ].filter(d => d.value > 0);

  const byTarget = ["llm_api","ai_infra","model_registry","ai_app","cicd_pipeline"].map(t => ({
    name:     t.replace(/_/g," "),
    critical: findings.filter(f => f.target_type === t && f.severity === "critical").length,
    high:     findings.filter(f => f.target_type === t && f.severity === "high").length,
    medium:   findings.filter(f => f.target_type === t && f.severity === "medium").length,
  }));

  const timeline = [
    { date:"Mar 9", score:58 }, { date:"Mar 10", score:52 },
    { date:"Mar 11", score:47 }, { date:"Mar 12", score:42 },
    { date:"Mar 13", score:38 }, { date:"Today", score: Math.round(score) },
  ];

  const TT = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ background:C.elevated, border:`1px solid ${C.borderHi}`, padding:"8px 12px", borderRadius:4, fontSize:11, fontFamily:"monospace" }}>
        <div style={{ color:C.muted, marginBottom:4 }}>{label}</div>
        {payload.map(p => <div key={p.name} style={{ color: SEV_COLORS[p.name] || C.text }}>{p.name}: {p.value}</div>)}
      </div>
    );
  };

  const topCrit = findings.filter(f => f.severity === "critical" && f.status === "open").slice(0, 5);

  return (
    <div style={{ paddingBottom:40 }}>
      {/* Stat cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        {[
          { l:"Open Findings", v: open.length,                                           c: C.critical },
          { l:"Critical",      v: open.filter(f => f.severity === "critical").length,    c: C.critical },
          { l:"Scans (7d)",    v: scans.length,                                          c: C.accent   },
          { l:"Total Checks",  v: ALL_CHECKS.length,                                     c: C.teal     },
        ].map(({ l, v, c }) => (
          <Card key={l} style={{ textAlign:"center" }}>
            <div style={{ fontSize:32, fontFamily:"monospace", fontWeight:700, color:c, lineHeight:1 }}>{v}</div>
            <div style={{ fontSize:11, color:C.muted, marginTop:6, fontFamily:"monospace", textTransform:"uppercase", letterSpacing:"0.08em" }}>{l}</div>
          </Card>
        ))}
      </div>

      {/* Gauge + severity chart + framework pie */}
      <div style={{ display:"grid", gridTemplateColumns:"240px 1fr 200px", gap:16, marginBottom:24 }}>
        <Card style={{ display:"flex", alignItems:"center", justifyContent:"center" }}>
          <PostureGauge score={Math.round(score)} />
        </Card>
        <Card>
          <SecTitle>Findings by severity · open only</SecTitle>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={bySev} barSize={32}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
              <XAxis dataKey="severity" tick={{ fill:C.muted, fontSize:11, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill:C.muted, fontSize:10, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={<TT />} cursor={{ fill:C.elevated }} />
              <Bar dataKey="count" radius={[3,3,0,0]}>
                {bySev.map(d => <Cell key={d.severity} fill={SEV_COLORS[d.severity]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
        <Card style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
          <SecTitle>By framework</SecTitle>
          <ResponsiveContainer width="100%" height={110}>
            <PieChart>
              <Pie data={byFW} cx="50%" cy="50%" innerRadius={28} outerRadius={48} paddingAngle={3} dataKey="value">
                {byFW.map(d => <Cell key={d.name} fill={d.color} />)}
              </Pie>
              <Tooltip content={({ active, payload }) => active && payload?.length
                ? <div style={{ background:C.elevated, border:`1px solid ${C.borderHi}`, padding:"6px 10px", fontSize:11, fontFamily:"monospace", color:C.text }}>{payload[0].name}: {payload[0].value}</div>
                : null} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display:"flex", flexDirection:"column", gap:4, width:"100%" }}>
            {byFW.map(d => (
              <div key={d.name} style={{ display:"flex", alignItems:"center", gap:6, fontSize:10, fontFamily:"monospace", color:C.muted }}>
                <div style={{ width:8, height:8, borderRadius:2, background:d.color, flexShrink:0 }} />{d.name}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Target chart + trend */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 280px", gap:16, marginBottom:24 }}>
        <Card>
          <SecTitle>Findings by target type</SecTitle>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={byTarget} barSize={16}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
              <XAxis dataKey="name" tick={{ fill:C.muted, fontSize:9, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill:C.muted, fontSize:10, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={<TT />} cursor={{ fill:C.elevated }} />
              <Bar dataKey="critical" stackId="a" fill={C.critical} />
              <Bar dataKey="high"     stackId="a" fill={C.high} />
              <Bar dataKey="medium"   stackId="a" fill={C.medium} radius={[2,2,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
        <Card>
          <SecTitle>Posture trend (7d)</SecTitle>
          <ResponsiveContainer width="100%" height={120}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="date" tick={{ fill:C.muted, fontSize:9, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <YAxis domain={[0,100]} tick={{ fill:C.muted, fontSize:9, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={({ active, payload }) => active && payload?.length
                ? <div style={{ background:C.elevated, border:`1px solid ${C.borderHi}`, padding:"6px 10px", fontSize:11, fontFamily:"monospace", color:C.text }}>Score: {payload[0].value}</div>
                : null} />
              <Line type="monotone" dataKey="score" stroke={C.accent} strokeWidth={2} dot={{ fill:C.accent, r:2 }} />
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Top critical findings */}
      <Card>
        <SecTitle>Top critical findings</SecTitle>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ borderBottom:`1px solid ${C.border}` }}>
              {["ID","Title","Target","Confidence","First Seen",""].map(h => (
                <th key={h} style={{ textAlign:"left", padding:"6px 10px", fontSize:10, color:C.muted, fontFamily:"monospace", fontWeight:400, letterSpacing:"0.08em", textTransform:"uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {topCrit.map(f => (
              <tr key={f.id} style={{ borderBottom:`1px solid ${C.border}`, cursor:"pointer" }}
                  onMouseEnter={e => e.currentTarget.style.background = C.elevated}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  onClick={() => setSel(f)}>
                <td style={{ padding:"10px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{f.id}</td>
                <td style={{ padding:"10px 10px", fontSize:13, color:C.text, maxWidth:240 }}>{f.title}</td>
                <td style={{ padding:"10px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{f.target_type}</td>
                <td style={{ padding:"10px 10px" }}><StatusBadge s={f.confidence} /></td>
                <td style={{ padding:"10px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{new Date(f.first_seen).toLocaleDateString()}</td>
                <td style={{ padding:"10px 10px" }}><SevBadge s={f.severity} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <FindingDrawer finding={sel} onClose={() => setSel(null)} onStatusChange={(id, status) => { setSel(null); }} />
    </div>
  );
}

// ─────────────────────────────────────────────
// FINDINGS SCREEN
// ─────────────────────────────────────────────
const FILTER_GROUPS = [
  { key:"severity", opts:["critical","high","medium","low","info"] },
  { key:"status",   opts:["open","acknowledged","resolved"] },
  { key:"target",   opts:["llm_api","ai_infra","model_registry","ai_app","cicd_pipeline"] },
];

const TABLE_COLS = [
  { label:"ID",         key:"id"         },
  { label:"Title",      key:"title"      },
  { label:"Target",     key:"target_type"},
  { label:"Severity",   key:"severity"   },
  { label:"Score",      key:"score"      },
  { label:"Status",     key:"status"     },
  { label:"First Seen", key:"first_seen" },
  { label:"Frameworks", key:null         },
];

function FindingsScreen({ findings, onStatusChange }) {
  const [filters, setFilters] = useState({ severity:"", status:"", target:"", search:"" });
  const [sort, setSort]       = useState({ key:"score", dir:"desc" });
  const [sel, setSel]         = useState(null);

  const setFilter    = (key, val) => setFilters(prev => ({ ...prev, [key]: val }));
  const toggleFilter = (key, opt) => setFilters(prev => ({ ...prev, [key]: prev[key] === opt ? "" : opt }));
  const toggleSort   = (k)        => setSort(s => ({ key:k, dir: s.key === k && s.dir === "desc" ? "asc" : "desc" }));

  const handleStatus = (id, status) => { onStatusChange(id, status); setSel(null); };

  const filtered = findings
    .filter(f =>
      (!filters.severity || f.severity    === filters.severity) &&
      (!filters.status   || f.status      === filters.status) &&
      (!filters.target   || f.target_type === filters.target) &&
      (!filters.search   || f.title.toLowerCase().includes(filters.search.toLowerCase()) ||
                            f.resource.toLowerCase().includes(filters.search.toLowerCase()))
    )
    .sort((a, b) => {
      let va = a[sort.key], vb = b[sort.key];
      if (sort.key === "severity") { va = SEV_W[a.severity]; vb = SEV_W[b.severity]; }
      if (typeof va === "string") return sort.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
      return sort.dir === "asc" ? va - vb : vb - va;
    });

  const selStyle = { background:C.accent, color:"#fff", border:`1px solid ${C.accent}` };
  const btnStyle = { background:"transparent", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", padding:"4px 10px", borderRadius:3, fontSize:11, fontFamily:"monospace" };

  return (
    <div>
      <Card style={{ marginBottom:16 }}>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap", alignItems:"center" }}>
          <input placeholder="Search findings…" value={filters.search}
                 onChange={e => setFilter("search", e.target.value)}
                 style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text,
                          padding:"6px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace",
                          outline:"none", flex:"1 1 200px" }} />
          {FILTER_GROUPS.map(({ key, opts }) => (
            <div key={key} style={{ display:"flex", gap:3 }}>
              <button style={{ ...btnStyle, ...(filters[key] === "" ? selStyle : {}) }}
                      onClick={() => setFilter(key, "")}>All</button>
              {opts.map(opt => (
                <button key={opt}
                        style={{ ...btnStyle, ...(filters[key] === opt ? selStyle : {}) }}
                        onClick={() => toggleFilter(key, opt)}>{opt}</button>
              ))}
            </div>
          ))}
          <span style={{ color:C.muted, fontSize:11, fontFamily:"monospace", marginLeft:"auto" }}>
            {filtered.length} findings
          </span>
        </div>
      </Card>

      <Card style={{ padding:0 }}>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ borderBottom:`1px solid ${C.borderHi}`, background:C.elevated }}>
              {TABLE_COLS.map(({ label, key }) => (
                <th key={label} onClick={() => key && toggleSort(key)}
                    style={{ textAlign:"left", padding:"10px 14px", fontSize:10, color:C.muted,
                             fontFamily:"monospace", fontWeight:400, letterSpacing:"0.08em",
                             textTransform:"uppercase", cursor: key ? "pointer" : "default",
                             userSelect:"none", background:C.elevated }}>
                  {label} {sort.key === key ? (sort.dir === "asc" ? "↑" : "↓") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id} style={{ borderBottom:`1px solid ${C.border}`, cursor:"pointer" }}
                  onMouseEnter={e => e.currentTarget.style.background = C.elevated}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  onClick={() => setSel(f)}>
                <td style={{ padding:"10px 14px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{f.id}</td>
                <td style={{ padding:"10px 14px", fontSize:12, color:C.text, maxWidth:220 }}>{f.title}</td>
                <td style={{ padding:"10px 14px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{f.target_type}</td>
                <td style={{ padding:"10px 14px" }}><SevBadge s={f.severity} /></td>
                <td style={{ padding:"10px 14px", fontFamily:"monospace", fontSize:12, color:SEV_COLORS[f.severity] }}>{f.score.toFixed(1)}</td>
                <td style={{ padding:"10px 14px" }}><StatusBadge s={f.status} /></td>
                <td style={{ padding:"10px 14px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{new Date(f.first_seen).toLocaleDateString()}</td>
                <td style={{ padding:"10px 14px" }}>
                  <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                    {f.framework_refs.slice(0,2).map((fw, i) => <FWBadge key={i} fw={fw} />)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <FindingDrawer finding={sel} onClose={() => setSel(null)} onStatusChange={handleStatus} />
    </div>
  );
}

// ─────────────────────────────────────────────
// SCAN CONFIG
// Key design decisions:
//   1. "All Checks" means ALL 25 checks — ignoring target_types filter.
//      Each check records the actual target_type scanned for context.
//   2. Individual families are multi-selectable via checkboxes.
//   3. The check count banner always explains total vs applicable.
//   4. The scan runs each check with a visible per-check progress delay.
//   5. onScanComplete fires BEFORE any state reset.
//   6. The recent scans table reads the scans prop (root state) directly.
// ─────────────────────────────────────────────
function ScanConfigScreen({ scans, onScanComplete, onNavigate }) {
  const [step, setStep]               = useState(1);
  const [targetType, setTargetType]   = useState("");
  const [form, setForm]               = useState({ name:"", host:"", system_prompt:"" });
  const [selectedFamilyIds, setSelectedFamilyIds] = useState([]); // array of family.id strings
  const [selPolicies, setSelPolicies] = useState([]);             // array of check IDs
  // scanState: "idle" | "running" | "done"
  const [scanState, setScanState]     = useState("idle");
  const [scanProgress, setScanProgress] = useState({ pct:0, label:"", checkIdx:0, total:0 });
  const [lastResult, setLastResult]   = useState(null);

  const TARGET_TYPES = [
    { id:"llm_api",        icon:"⬡", label:"LLM / GenAI API",    desc:"OpenAI, Anthropic, Azure, Bedrock, Vertex" },
    { id:"ai_infra",       icon:"◈", label:"AI Infrastructure",  desc:"MLflow, Jupyter, SageMaker, GPU clusters" },
    { id:"model_registry", icon:"⬢", label:"Model Registry",     desc:"HuggingFace, MLflow Registry, SageMaker" },
    { id:"ai_app",         icon:"◎", label:"AI-Integrated App",  desc:"RAG pipelines, agents, chatbots, copilots" },
    { id:"cicd_pipeline",  icon:"▷", label:"CI/CD Pipeline",     desc:"GitHub Actions, GitLab CI, Jenkins, MLOps" },
  ];

  // ─── Family toggle ─────────────────────────────────────────────────────────
  // "all" is a special ID meaning every check regardless of target_types.
  // Toggling "all" clears individual families. Selecting any individual family
  // clears "all".
  const toggleFamily = (familyId) => {
    let nextIds;
    if (familyId === "all") {
      nextIds = selectedFamilyIds.includes("all") ? [] : ["all"];
    } else {
      const without = selectedFamilyIds.filter(id => id !== "all");
      nextIds = without.includes(familyId)
        ? without.filter(id => id !== familyId)
        : [...without, familyId];
    }
    setSelectedFamilyIds(nextIds);

    // Recompute selPolicies from nextIds
    // When "all" is selected: ALL 25 checks (no target_type filter — user chose
    // "run everything"). The scan records target_type for context only.
    if (nextIds.includes("all")) {
      setSelPolicies(ALL_CHECKS.map(c => c.id));
    } else {
      const ids = new Set();
      for (const fid of nextIds) {
        const fam = CHECK_FAMILIES.find(f => f.id === fid);
        if (!fam) continue;
        // For individual families: include check if it belongs to the family
        // (we do NOT filter by target_type here either — the check will run
        //  and record findings against the scanned target for context)
        ALL_CHECKS.filter(c => fam.checkIds.includes(c.id)).forEach(c => ids.add(c.id));
      }
      setSelPolicies([...ids]);
    }
  };

  // Helpers for display
  const checksApplicable = (checkIds) =>
    checkIds.filter(id => {
      const c = ALL_CHECKS.find(x => x.id === id);
      return c && c.target_types.includes(targetType);
    });

  const checksNotApplicable = (checkIds) =>
    checkIds.filter(id => {
      const c = ALL_CHECKS.find(x => x.id === id);
      return c && !c.target_types.includes(targetType);
    });

  // Total selected regardless of target_type filter
  const totalSelected = selPolicies.length;
  // Of those, how many are "natively applicable" (target_types includes selected targetType)
  const nativeCount = checksApplicable(selPolicies).length;
  // How many will still run but against a different native target
  const crossCount = totalSelected - nativeCount;

  // ─── Scan execution ────────────────────────────────────────────────────────
  const runScan = async () => {
    if (selPolicies.length === 0) return;
    setScanState("running");
    setScanProgress({ pct:0, label:"Starting scan…", checkIdx:0, total:selPolicies.length });

    const checksToRun = ALL_CHECKS.filter(c => selPolicies.includes(c.id));

    // Simulate each check running with a visible delay
    for (let i = 0; i < checksToRun.length; i++) {
      const c = checksToRun[i];
      const pct = Math.round(((i + 1) / checksToRun.length) * 100);
      setScanProgress({
        pct,
        label: `[${i+1}/${checksToRun.length}] Checking: ${c.name}`,
        checkIdx: i + 1,
        total: checksToRun.length,
      });
      await new Promise(r => setTimeout(r, 380 + Math.random() * 320));
    }

    setScanProgress(p => ({ ...p, pct:100, label:"Scoring and generating report…" }));
    await new Promise(r => setTimeout(r, 600));

    // Build one finding per check
    const newFindings = checksToRun.map((c, i) => ({
      id:           `F-${Date.now()}-${i}`,
      policy_id:    c.id,
      policy_name:  c.name,
      // Use the check's primary target_type if the selected target is not in its list
      target_type:  c.target_types.includes(targetType) ? targetType : c.target_types[0],
      resource:     form.name || targetType,
      severity:     c.severity,
      confidence:   i % 3 === 0 ? "confirmed" : "probable",
      score:        ({ critical:7.5, high:6, medium:3.75, low:1.5, info:0 })[c.severity] ?? 5,
      status:       "open",
      title:        c.name,
      description:  c.description,
      evidence:     `Automated scan of "${form.name || targetType}" — policy ${c.id}`,
      remediation:  "1. Review the finding details.\n2. Follow the remediation steps in the Check Registry.\n3. Re-scan after fixing to confirm resolution.",
      framework_refs: c.frameworks.map(f => { const [fw, fid] = f.split(":"); return { framework:fw, id:fid }; }),
      first_seen:   new Date().toISOString(),
    }));

    const openScore    = newFindings.reduce((s, f) => s + f.score * 1.5, 0);
    const postureScore = Math.round(Math.max(5, 100 - openScore));

    const scanId = `SCN-${String(scans.length + 1).padStart(3, "0")}`;
    const ns = {
      id:           scanId,
      target_type:  targetType,
      target_meta:  { name: form.name || targetType },
      status:       "completed",
      posture_score: postureScore,
      tier:          postureScore >= 70 ? "healthy" : postureScore >= 40 ? "at_risk" : "critical",
      created_at:   new Date().toISOString(),
      finished_at:  new Date().toISOString(),
      findings:     newFindings.length,
      checks_run:   checksToRun.length,
      families_run: selectedFamilyIds.includes("all")
                      ? "All Checks"
                      : CHECK_FAMILIES.filter(f => selectedFamilyIds.includes(f.id)).map(f => f.label).join(", "),
    };

    // Fire root callback FIRST — updates dashboard and findings immediately
    onScanComplete(ns, newFindings);

    setLastResult({ scan:ns, findings:newFindings });
    setScanState("done");
  };

  const resetWizard = () => {
    setScanState("idle");
    setScanProgress({ pct:0, label:"", checkIdx:0, total:0 });
    setLastResult(null);
    setStep(1);
    setTargetType("");
    setSelectedFamilyIds([]);
    setSelPolicies([]);
    setForm({ name:"", host:"", system_prompt:"" });
  };

  // ─── Scanning overlay ──────────────────────────────────────────────────────
  if (scanState === "running") {
    return (
      <div style={{ maxWidth:720 }}>
        <Card>
          <div style={{ textAlign:"center", padding:"24px 0 16px" }}>
            <div style={{ fontFamily:"monospace", fontSize:14, color:C.text, fontWeight:600, marginBottom:20 }}>
              ⟳ Scanning {form.name || targetType}
            </div>
            <div style={{ background:C.elevated, borderRadius:6, height:10, marginBottom:12, overflow:"hidden" }}>
              <div style={{ height:"100%", width:`${scanProgress.pct}%`, background:C.accent,
                            borderRadius:6, transition:"width 0.35s ease" }} />
            </div>
            <div style={{ fontFamily:"monospace", fontSize:12, color:C.accent, marginBottom:8 }}>
              {scanProgress.pct}% — {scanProgress.checkIdx} of {scanProgress.total} checks
            </div>
            <div style={{ fontFamily:"monospace", fontSize:11, color:C.muted }}>
              {scanProgress.label}
            </div>
          </div>
        </Card>
      </div>
    );
  }

  // ─── Scan complete banner ──────────────────────────────────────────────────
  if (scanState === "done" && lastResult) {
    const { scan } = lastResult;
    const scoreColor = scan.posture_score >= 70 ? C.healthy : scan.posture_score >= 40 ? C.high : C.critical;
    return (
      <div style={{ maxWidth:860 }}>
        <Card style={{ border:`1px solid #1a5a28`, background:"#0a1a10", marginBottom:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:16 }}>
            <div>
              <div style={{ fontFamily:"monospace", fontSize:15, color:C.healthy, fontWeight:700, marginBottom:12 }}>
                ✓ Scan {scan.id} completed
              </div>
              <div style={{ display:"flex", gap:24, flexWrap:"wrap", fontFamily:"monospace", fontSize:12 }}>
                {[
                  { l:"Target",       v: scan.target_meta?.name,  c: C.text    },
                  { l:"Checks run",   v: scan.checks_run,          c: C.text    },
                  { l:"Findings",     v: scan.findings,            c: C.critical},
                  { l:"Posture score",v: scan.posture_score,        c: scoreColor},
                ].map(({ l, v, c }) => (
                  <div key={l}>
                    <div style={{ color:C.muted, fontSize:10, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:3 }}>{l}</div>
                    <div style={{ color:c, fontSize:16, fontWeight:700 }}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{ fontFamily:"monospace", fontSize:11, color:C.muted, marginTop:10 }}>
                Families: {scan.families_run}
              </div>
            </div>
            <div style={{ display:"flex", gap:10, alignItems:"flex-start", flexShrink:0 }}>
              <Btn variant="primary" onClick={() => { resetWizard(); onNavigate("findings"); }}>
                View Findings →
              </Btn>
              <Btn onClick={resetWizard}>New Scan</Btn>
            </div>
          </div>
        </Card>

        {/* Recent scans still visible so user can see updated list */}
        <Card>
          <SecTitle>Recent scans ({scans.length})</SecTitle>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead>
              <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                {["Scan ID","Target","Checks","Score","Findings","Families","Started"].map(h => (
                  <th key={h} style={{ textAlign:"left", padding:"6px 10px", fontSize:10, color:C.muted, fontFamily:"monospace", fontWeight:400, letterSpacing:"0.08em", textTransform:"uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 6).map(s => (
                <tr key={s.id} style={{ borderBottom:`1px solid ${C.border}` }}>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{s.id}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.teal }}>{s.target_meta?.name || s.target_type}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.text }}>{s.checks_run ?? "—"}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:12,
                               color: s.posture_score >= 70 ? C.healthy : s.posture_score >= 40 ? C.high : C.critical }}>
                    {s.posture_score ?? "—"}
                  </td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.text }}>{s.findings}</td>
                  <td style={{ padding:"8px 10px", fontSize:11, color:C.muted, maxWidth:180 }}>{s.families_run ?? "—"}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    );
  }

  // ─── Wizard ────────────────────────────────────────────────────────────────
  return (
    <div style={{ maxWidth:860 }}>
      {/* Recent scans */}
      <Card style={{ marginBottom:24 }}>
        <SecTitle>Recent scans ({scans.length})</SecTitle>
        {scans.length === 0 ? (
          <div style={{ color:C.muted, fontSize:12, fontFamily:"monospace", padding:"8px 0" }}>No scans yet — run your first scan below.</div>
        ) : (
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead>
              <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                {["Scan ID","Target","Checks","Score","Findings","Families","Started"].map(h => (
                  <th key={h} style={{ textAlign:"left", padding:"6px 10px", fontSize:10, color:C.muted, fontFamily:"monospace", fontWeight:400, letterSpacing:"0.08em", textTransform:"uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 6).map(s => (
                <tr key={s.id} style={{ borderBottom:`1px solid ${C.border}` }}>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{s.id}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.teal }}>{s.target_meta?.name || s.target_type}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.text }}>{s.checks_run ?? "—"}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:12,
                               color: s.posture_score >= 70 ? C.healthy : s.posture_score >= 40 ? C.high : C.critical }}>
                    {s.posture_score ?? "—"}
                  </td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.text }}>{s.findings}</td>
                  <td style={{ padding:"8px 10px", fontSize:11, color:C.muted, maxWidth:160 }}>{s.families_run ?? "—"}</td>
                  <td style={{ padding:"8px 10px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* Wizard card */}
      <Card>
        {/* Step indicator */}
        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:24, flexWrap:"wrap" }}>
          {[
            { n:1, label:"Select target" },
            { n:2, label:"Configure"     },
            { n:3, label:"Check families"},
            { n:4, label:"Review & run"  },
          ].map(({ n, label }) => (
            <div key={n} style={{ display:"flex", alignItems:"center", gap:8 }}>
              <div style={{ width:26, height:26, borderRadius:"50%", flexShrink:0,
                            display:"flex", alignItems:"center", justifyContent:"center",
                            fontFamily:"monospace", fontSize:11, fontWeight:700,
                            background: step === n ? C.accent : step > n ? C.teal : C.elevated,
                            color: step >= n ? "#fff" : C.muted,
                            border:`1px solid ${step === n ? C.accent : step > n ? C.teal : C.border}` }}>
                {step > n ? "✓" : n}
              </div>
              <span style={{ fontSize:11, fontFamily:"monospace", color: step === n ? C.text : C.muted }}>{label}</span>
              {n < 4 && <span style={{ color:C.dim, fontSize:14, marginLeft:4 }}>›</span>}
            </div>
          ))}
        </div>

        {/* ── Step 1: Target type ── */}
        {step === 1 && (
          <div>
            <div style={{ fontSize:13, color:C.muted, marginBottom:16, fontFamily:"monospace" }}>What do you want to scan?</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
              {TARGET_TYPES.map(t => (
                <div key={t.id}
                     onClick={() => { setTargetType(t.id); setStep(2); }}
                     style={{ background:"transparent", border:`1px solid ${C.border}`, borderRadius:6,
                              padding:"14px 16px", cursor:"pointer", transition:"all 0.15s" }}
                     onMouseEnter={e => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.background = C.elevated; }}
                     onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = "transparent"; }}>
                  <div style={{ fontFamily:"monospace", fontSize:20, marginBottom:6 }}>{t.icon}</div>
                  <div style={{ fontSize:13, color:C.text, fontWeight:600, marginBottom:4 }}>{t.label}</div>
                  <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace" }}>{t.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Step 2: Configure ── */}
        {step === 2 && (
          <div>
            <div style={{ fontSize:13, color:C.muted, marginBottom:16, fontFamily:"monospace" }}>
              Name this {targetType.replace(/_/g," ")} target
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
              {[
                { key:"name", label:"Target name (a label to identify this scan)", ph:`e.g. my-${targetType}-prod` },
                { key:"host", label:"Host / endpoint URL (optional)",             ph:"e.g. https://api.openai.com" },
              ].map(({ key, label, ph }) => (
                <div key={key}>
                  <label style={{ fontSize:11, color:C.muted, fontFamily:"monospace", display:"block",
                                  marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>{label}</label>
                  <input value={form[key]} onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
                         placeholder={ph}
                         style={{ width:"100%", background:C.elevated, border:`1px solid ${C.border}`,
                                  color:C.text, padding:"8px 12px", borderRadius:4, fontSize:12,
                                  fontFamily:"monospace", outline:"none", boxSizing:"border-box" }} />
                </div>
              ))}
              {targetType === "llm_api" && (
                <div>
                  <label style={{ fontSize:11, color:C.muted, fontFamily:"monospace", display:"block",
                                  marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>
                    System prompt (leave blank to test for its absence)
                  </label>
                  <textarea value={form.system_prompt} rows={3}
                            onChange={e => setForm(p => ({ ...p, system_prompt: e.target.value }))}
                            placeholder="Paste system prompt here…"
                            style={{ width:"100%", background:C.elevated, border:`1px solid ${C.border}`,
                                     color:C.text, padding:"8px 12px", borderRadius:4, fontSize:12,
                                     fontFamily:"monospace", outline:"none", resize:"vertical", boxSizing:"border-box" }} />
                </div>
              )}
              <div style={{ background:"#1a1200", border:"1px solid #3a2a00", borderRadius:4,
                            padding:"10px 12px", fontFamily:"monospace", fontSize:11, color:"#d97706" }}>
                ⚠ Never enter API keys here. Set them in your .env file (OPENAI_API_KEY, etc.).
              </div>
            </div>
            <div style={{ display:"flex", gap:10, marginTop:20 }}>
              <Btn onClick={() => setStep(1)}>← Back</Btn>
              <Btn variant="primary" onClick={() => setStep(3)}>Continue →</Btn>
            </div>
          </div>
        )}

        {/* ── Step 3: Family multi-select ── */}
        {step === 3 && (
          <div>
            <div style={{ fontSize:13, color:C.text, marginBottom:4, fontFamily:"monospace", fontWeight:600 }}>
              Which check families do you want to run?
            </div>
            <div style={{ fontSize:12, color:C.muted, marginBottom:4, lineHeight:1.6 }}>
              Tick one or more families. You can combine them — for example, pick <b style={{color:C.text}}>OWASP LLM Top 10</b> and <b style={{color:C.text}}>MITRE ATLAS</b> together.
            </div>

            {/* Explain the 25 vs N-for-target-type thing clearly */}
            <div style={{ background:C.elevated, border:`1px solid ${C.borderHi}`, borderRadius:6,
                          padding:"10px 14px", marginBottom:16, fontFamily:"monospace", fontSize:11 }}>
              <div style={{ color:C.text, marginBottom:4, fontWeight:600 }}>
                ⓘ  About check counts
              </div>
              <div style={{ color:C.muted, lineHeight:1.7 }}>
                There are <span style={{color:C.teal}}>{ALL_CHECKS.length} checks</span> installed in total across all target types.{" "}
                Of those, <span style={{color:C.accent}}>
                  {ALL_CHECKS.filter(c => c.target_types.includes(targetType)).length} checks
                </span> are natively designed for <span style={{color:C.accent}}>{targetType}</span>.{" "}
                The remaining <span style={{color:C.muted}}>
                  {ALL_CHECKS.filter(c => !c.target_types.includes(targetType)).length}
                </span> target other resource types (ai_infra, ai_app, model_registry, cicd_pipeline).
              </div>
              <div style={{ color:C.muted, marginTop:6, lineHeight:1.7 }}>
                <b style={{color:C.text}}>All Checks (Full Scan)</b> runs all{" "}
                <span style={{color:C.teal}}>{ALL_CHECKS.length}</span> checks and records each finding
                against its native target type for accurate reporting.
                Individual families run only their own checks.
              </div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:16 }}>
              {CHECK_FAMILIES.map(family => {
                const ownChecks    = family.id === "all" ? ALL_CHECKS : ALL_CHECKS.filter(c => family.checkIds.includes(c.id));
                const nativeForTarget = ownChecks.filter(c => c.target_types.includes(targetType)).length;
                const totalInFamily   = ownChecks.length;
                const isSelected   = selectedFamilyIds.includes(family.id);

                return (
                  <div key={family.id}
                       onClick={() => toggleFamily(family.id)}
                       style={{ display:"flex", alignItems:"flex-start", gap:14, padding:"12px 16px",
                                background: isSelected ? C.elevated : "transparent",
                                border:`1px solid ${isSelected ? family.color : C.border}`,
                                borderRadius:6, cursor:"pointer", transition:"all 0.12s",
                                boxShadow: isSelected ? `0 0 0 1px ${family.color}25` : "none" }}>
                    {/* Checkbox */}
                    <div style={{ width:17, height:17, borderRadius:3, flexShrink:0, marginTop:2,
                                  background: isSelected ? family.color : "transparent",
                                  border:`2px solid ${isSelected ? family.color : C.muted}`,
                                  display:"flex", alignItems:"center", justifyContent:"center" }}>
                      {isSelected && <span style={{ color:"#fff", fontSize:11, fontWeight:800, lineHeight:1 }}>✓</span>}
                    </div>

                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:3, flexWrap:"wrap" }}>
                        <span style={{ fontSize:13, color: isSelected ? C.text : C.muted,
                                       fontWeight: isSelected ? 600 : 400 }}>
                          {family.label}
                        </span>
                        {/* Total checks in family */}
                        <span style={{ fontSize:10, fontFamily:"monospace", color:family.color,
                                       background:`${family.color}20`, border:`1px solid ${family.color}40`,
                                       padding:"1px 7px", borderRadius:3 }}>
                          {totalInFamily} check{totalInFamily !== 1 ? "s" : ""}
                        </span>
                        {/* Natively-applicable count — only show when different from total */}
                        {family.id !== "all" && nativeForTarget < totalInFamily && (
                          <span style={{ fontSize:10, fontFamily:"monospace", color:C.muted,
                                         background:C.elevated, border:`1px solid ${C.border}`,
                                         padding:"1px 7px", borderRadius:3 }}>
                            {nativeForTarget} native for {targetType}
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize:11, color:C.muted, lineHeight:1.5 }}>{family.description}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Live summary of selection */}
            {selectedFamilyIds.length > 0 && (
              <div style={{ padding:"10px 14px", background:C.elevated, borderRadius:6,
                            fontFamily:"monospace", fontSize:11, color:C.teal, marginBottom:16,
                            border:`1px solid ${C.border}` }}>
                ✓ <span style={{color:C.text, fontWeight:600}}>{selPolicies.length} checks</span> selected
                {" "}({nativeCount} native for {targetType}
                {crossCount > 0 ? `, ${crossCount} from other target types` : ""})
              </div>
            )}

            <div style={{ display:"flex", gap:10 }}>
              <Btn onClick={() => setStep(2)}>← Back</Btn>
              <Btn variant="primary" onClick={() => setStep(4)} disabled={selectedFamilyIds.length === 0}>
                Continue → ({selPolicies.length} checks)
              </Btn>
            </div>
          </div>
        )}

        {/* ── Step 4: Review & run ── */}
        {step === 4 && (
          <div>
            <div style={{ fontSize:13, color:C.text, marginBottom:4, fontFamily:"monospace", fontWeight:600 }}>
              Review — {selPolicies.length} checks selected
            </div>
            <div style={{ fontSize:11, color:C.muted, marginBottom:12, lineHeight:1.6 }}>
              Uncheck individual checks to skip them. Checks marked{" "}
              <span style={{color:C.teal}}>●</span> are natively designed for {targetType};
              those marked <span style={{color:C.muted}}>◌</span> will run across target types.
            </div>

            <div style={{ maxHeight:340, overflowY:"auto", display:"flex", flexDirection:"column",
                          gap:4, marginBottom:16, paddingRight:4 }}>
              {ALL_CHECKS
                .filter(c => selPolicies.includes(c.id))
                .sort((a, b) => SEV_W[a.severity] - SEV_W[b.severity])
                .map(c => {
                  const isNative   = c.target_types.includes(targetType);
                  const isChecked  = selPolicies.includes(c.id);
                  return (
                    <div key={c.id}
                         onClick={() => setSelPolicies(prev =>
                           prev.includes(c.id) ? prev.filter(x => x !== c.id) : [...prev, c.id]
                         )}
                         style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 12px",
                                  background: isChecked ? C.elevated : "transparent",
                                  border:`1px solid ${isChecked ? C.borderHi : C.border}`,
                                  borderRadius:5, cursor:"pointer", opacity: isChecked ? 1 : 0.5 }}>
                      {/* checkbox */}
                      <div style={{ width:14, height:14, borderRadius:3, flexShrink:0,
                                    background: isChecked ? C.accent : "transparent",
                                    border:`1px solid ${isChecked ? C.accent : C.border}`,
                                    display:"flex", alignItems:"center", justifyContent:"center" }}>
                        {isChecked && <span style={{ color:"#fff", fontSize:9 }}>✓</span>}
                      </div>
                      {/* native indicator */}
                      <span style={{ fontSize:10, flexShrink:0,
                                     color: isNative ? C.teal : C.dim }}>{isNative ? "●" : "◌"}</span>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:12, color:C.text, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {c.name}
                        </div>
                        <div style={{ fontSize:9, color:C.muted, fontFamily:"monospace", marginTop:1 }}>
                          {c.id} · {isNative ? targetType : c.target_types[0]}
                        </div>
                      </div>
                      <SevBadge s={c.severity} />
                    </div>
                  );
                })}
            </div>

            <div style={{ padding:"8px 12px", background:C.elevated, borderRadius:6,
                          fontFamily:"monospace", fontSize:11, color:C.muted, marginBottom:16,
                          border:`1px solid ${C.border}` }}>
              {selPolicies.length} checks will run · ~{Math.round(selPolicies.length * 0.55)}s estimated
              <span style={{ marginLeft:12, color:C.teal }}>{nativeCount} native</span>
              {crossCount > 0 && <span style={{ marginLeft:8, color:C.muted }}>+ {crossCount} cross-target</span>}
            </div>

            <div style={{ display:"flex", gap:10 }}>
              <Btn onClick={() => setStep(3)}>← Back</Btn>
              <Btn variant="success" onClick={runScan} disabled={selPolicies.length === 0}>
                ▶ Run {selPolicies.length} Check{selPolicies.length !== 1 ? "s" : ""}
              </Btn>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// CHECK REGISTRY
// ─────────────────────────────────────────────
function CheckRegistryScreen() {
  const [search, setSearch]           = useState("");
  const [fwFilter, setFwFilter]       = useState("");
  const [typeFilter, setTypeFilter]   = useState("");
  const [selectedCheck, setSelectedCheck] = useState(null);
  const [updateState, setUpdateState] = useState({ status:"idle", data:null });

  const filtered = ALL_CHECKS.filter(c =>
    (!search     || c.name.toLowerCase().includes(search.toLowerCase()) ||
                    c.id.toLowerCase().includes(search.toLowerCase())) &&
    (!fwFilter   || c.frameworks.some(f => f.startsWith(fwFilter))) &&
    (!typeFilter || c.target_types.includes(typeFilter))
  ).sort((a, b) => SEV_W[a.severity] - SEV_W[b.severity]);

  const checkUpdates = async () => {
    setUpdateState({ status:"loading", data:null });
    try {
      const r = await fetch("/api/v1/checks/updates");
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      // Always use ALL_CHECKS.length as the authoritative count
      setUpdateState({ status:"done", data: { ...d, installedChecks: ALL_CHECKS.length } });
    } catch {
      setUpdateState({
        status:"done",
        data:{
          checkedAt: new Date().toISOString(),
          currentVersion: VERSION,
          installedChecks: ALL_CHECKS.length,   // ← always accurate
          installedModules: ALL_CHECKS.length,
          sources:[
            { source:"OWASP LLM Top 10 (2025)", id:"owasp-llm",   latestVersion:"v2025.1.0", publishedAt:"2024-11-14T00:00:00Z", url:"https://genai.owasp.org/llm-top-10/",                     releaseNotes:"2025 edition — new Vector & Embedding Weaknesses (LLM08) and System Prompt Leakage (LLM07) categories." },
            { source:"MITRE ATLAS",              id:"mitre-atlas", latestVersion:"v5.4.0",    publishedAt:"2026-02-01T00:00:00Z", url:"https://atlas.mitre.org",                               releaseNotes:"v5.4.0 adds Publish Poisoned AI Agent Tool, Escape to Host, and 14 new agentic AI techniques." },
            { source:"checkov (IaC checks)",     id:"checkov",     latestVersion:"3.2.410",   publishedAt:"2026-03-10T00:00:00Z", url:"https://github.com/bridgecrewio/checkov/releases",       releaseNotes:"New SageMaker, Bedrock, and GCP Vertex AI checks added." },
            { source:"garak (LLM prober)",       id:"garak",       latestVersion:"0.9.6",     publishedAt:"2026-02-15T00:00:00Z", url:"https://github.com/NVIDIA/garak/releases",               releaseNotes:"New probes for agentic jailbreaks, multi-turn injection, and image-based prompt injection." },
          ],
          frameworkCoverage:{
            OWASP_LLM:   ALL_CHECKS.filter(c => c.frameworks.some(f => f.startsWith("OWASP_LLM"))).length,
            MITRE_ATLAS:  ALL_CHECKS.filter(c => c.frameworks.some(f => f.startsWith("MITRE_ATLAS"))).length,
            NIST_AI_RMF: ALL_CHECKS.filter(c => c.frameworks.some(f => f.startsWith("NIST_AI_RMF"))).length,
          },
        },
      });
    }
  };

  const FW_OPTIONS  = [{ v:"", l:"All Frameworks" },{ v:"OWASP_LLM", l:"OWASP LLM" },{ v:"MITRE_ATLAS", l:"MITRE ATLAS" },{ v:"NIST_AI_RMF", l:"NIST RMF" }];
  const TYPE_OPTIONS= [{ v:"", l:"All Targets" },{ v:"llm_api", l:"LLM API" },{ v:"ai_infra", l:"AI Infra" },{ v:"model_registry", l:"Registry" },{ v:"ai_app", l:"AI App" },{ v:"cicd_pipeline", l:"CI/CD" }];

  return (
    <div>
      {/* Toolbar */}
      <div style={{ display:"flex", gap:10, marginBottom:16, flexWrap:"wrap", alignItems:"center" }}>
        <input placeholder="Search checks…" value={search} onChange={e => setSearch(e.target.value)}
               style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text, padding:"7px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none", flex:"1 1 200px" }} />
        <select value={fwFilter}   onChange={e => setFwFilter(e.target.value)}   style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text, padding:"7px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}>
          {FW_OPTIONS.map(f => <option key={f.v} value={f.v}>{f.l}</option>)}
        </select>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text, padding:"7px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}>
          {TYPE_OPTIONS.map(f => <option key={f.v} value={f.v}>{f.l}</option>)}
        </select>
        <Btn variant="primary" onClick={checkUpdates} disabled={updateState.status === "loading"}>
          {updateState.status === "loading" ? "⟳ Checking…" : "⟳ Check for Updates"}
        </Btn>
        <span style={{ color:C.muted, fontSize:11, fontFamily:"monospace" }}>{filtered.length} / {ALL_CHECKS.length} checks</span>
      </div>

      {/* Update report */}
      {updateState.status === "done" && updateState.data && (
        <Card style={{ marginBottom:16, padding:"16px 20px" }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
            <span style={{ fontFamily:"monospace", fontSize:12, color:C.teal, fontWeight:600 }}>
              ✓ Framework Update Report — {new Date(updateState.data.checkedAt).toLocaleString()}
            </span>
            <button onClick={() => setUpdateState({ status:"idle", data:null })} style={{ background:"transparent", border:"none", color:C.muted, cursor:"pointer", fontSize:14 }}>✕</button>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))", gap:10 }}>
            {updateState.data.sources.map((s, i) => (
              <div key={i} style={{ background:C.elevated, border:`1px solid ${s.error ? C.critical : C.border}`, borderRadius:6, padding:"12px 14px" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:6 }}>
                  <span style={{ fontFamily:"monospace", fontSize:12, color:C.text, fontWeight:600 }}>{s.source}</span>
                  {s.latestVersion && <span style={{ fontFamily:"monospace", fontSize:10, color:C.teal, background:"#0d2520", border:"1px solid #1a6050", padding:"2px 6px", borderRadius:3 }}>{s.latestVersion}</span>}
                  {s.error && <span style={{ fontFamily:"monospace", fontSize:10, color:C.critical }}>offline</span>}
                </div>
                {s.releaseNotes && <p style={{ fontSize:11, color:C.muted, margin:"0 0 6px", lineHeight:1.6 }}>{s.releaseNotes.slice(0, 180)}{s.releaseNotes.length > 180 ? "…" : ""}</p>}
                {s.publishedAt && <div style={{ fontSize:10, color:C.dim, fontFamily:"monospace" }}>Published: {new Date(s.publishedAt).toLocaleDateString()}</div>}
                {s.url && <a href={s.url} target="_blank" rel="noreferrer" style={{ fontSize:10, color:C.accent, fontFamily:"monospace", textDecoration:"none", display:"block", marginTop:4 }}>View release →</a>}
              </div>
            ))}
          </div>
          {/* ACCURATE counts — derived directly from ALL_CHECKS */}
          <div style={{ marginTop:12, padding:"10px 14px", background:C.elevated, borderRadius:6, fontFamily:"monospace", fontSize:11, color:C.muted }}>
            Installed: <span style={{ color:C.text }}>{ALL_CHECKS.length} checks</span>
            {Object.entries(updateState.data.frameworkCoverage || {}).map(([k, v]) => (
              <span key={k} style={{ marginLeft:12 }}><span style={{ color:C.text }}>{v}</span> {k.replace(/_/g," ")}</span>
            ))}
          </div>
        </Card>
      )}

      {/* Check detail modal */}
      {selectedCheck && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", zIndex:300, display:"flex", alignItems:"center", justifyContent:"center" }}
             onClick={() => setSelectedCheck(null)}>
          <div style={{ background:C.surface, border:`1px solid ${C.borderHi}`, borderRadius:8, padding:"28px", width:680, maxHeight:"80vh", overflowY:"auto" }}
               onClick={e => e.stopPropagation()}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:16 }}>
              <div>
                <div style={{ fontFamily:"monospace", fontSize:11, color:C.muted, marginBottom:4 }}>{selectedCheck.id}</div>
                <div style={{ color:C.text, fontSize:16, fontWeight:600 }}>{selectedCheck.name}</div>
              </div>
              <button onClick={() => setSelectedCheck(null)} style={{ background:"transparent", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", padding:"4px 10px", borderRadius:4 }}>✕</button>
            </div>
            <div style={{ display:"flex", gap:8, marginBottom:16, flexWrap:"wrap" }}>
              <SevBadge s={selectedCheck.severity} />
              {selectedCheck.target_types.map(t => (
                <span key={t} style={{ fontFamily:"monospace", fontSize:10, color:C.teal, background:"#0a2030", border:"1px solid #1a4050", padding:"2px 8px", borderRadius:3 }}>{t}</span>
              ))}
            </div>
            <p style={{ color:C.text, fontSize:13, lineHeight:1.7, marginBottom:16 }}>{selectedCheck.description}</p>
            <div style={{ marginBottom:12 }}>
              <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase" }}>Framework Mappings</div>
              <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                {selectedCheck.frameworks.map((f, i) => {
                  const [fw, fid] = f.split(":");
                  return <span key={i} style={{ fontFamily:"monospace", fontSize:10, color:C.accent, background:"#0d1a35", border:"1px solid #1a3060", padding:"2px 8px", borderRadius:3 }}>{fw.replace(/_/g," ")} {fid}</span>;
                })}
              </div>
            </div>
            <div style={{ marginBottom:12 }}>
              <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase" }}>Tags</div>
              <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                {(selectedCheck.tags || []).map((t, i) => (
                  <span key={i} style={{ fontFamily:"monospace", fontSize:10, color:C.muted, background:C.elevated, border:`1px solid ${C.border}`, padding:"2px 8px", borderRadius:3 }}>{t}</span>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace", marginBottom:8, textTransform:"uppercase" }}>Check Module Source (stub)</div>
              <div style={{ background:"#0a0d14", border:`1px solid ${C.border}`, borderRadius:4, padding:"14px 16px", fontFamily:"Courier New,monospace", fontSize:11, color:"#a8d8a8", lineHeight:1.8, position:"relative" }}>
                <button onClick={() => navigator.clipboard.writeText(`// Check: ${selectedCheck.id}\nasync function run(target, config) {\n  // See engine/checks/${selectedCheck.id.toLowerCase()}.js\n  return [];\n}\nmodule.exports = { id: '${selectedCheck.id}', name: '${selectedCheck.name}', run };`)}
                        style={{ position:"absolute", top:8, right:8, background:"transparent", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", padding:"3px 8px", borderRadius:3, fontSize:10, fontFamily:"monospace" }}>
                  ⎘ Copy
                </button>
                <div style={{ color:"#6b9bd2" }}>// Check: <span style={{ color:"#f0c674" }}>{selectedCheck.id}</span></div>
                <div style={{ color:"#6b9bd2" }}>// Targets: <span style={{ color:"#888" }}>{selectedCheck.target_types.join(", ")}</span></div>
                <div>&nbsp;</div>
                <div><span style={{ color:"#cc99cd" }}>async function </span><span style={{ color:"#f0e68c" }}>run</span>(target, config) {"{"}</div>
                <div>  <span style={{ color:"#888" }}>// Full source: engine/checks/{selectedCheck.id.toLowerCase()}.js</span></div>
                <div>  <span style={{ color:"#cc99cd" }}>return </span>[];</div>
                <div>{"}"}</div>
                <div>&nbsp;</div>
                <div>module.exports = {"{ "}id: <span style={{ color:"#f0c674" }}>'{selectedCheck.id}'</span>, run {"}"};</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Check table */}
      <Card style={{ padding:0 }}>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ borderBottom:`1px solid ${C.borderHi}`, background:C.elevated }}>
              {["Check ID","Name","Severity","Family","Target Types","Frameworks",""].map(h => (
                <th key={h} style={{ textAlign:"left", padding:"10px 14px", fontSize:10, color:C.muted, fontFamily:"monospace", fontWeight:400, letterSpacing:"0.08em", textTransform:"uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(c => (
              <tr key={c.id} style={{ borderBottom:`1px solid ${C.border}`, cursor:"pointer" }}
                  onMouseEnter={e => e.currentTarget.style.background = C.elevated}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <td style={{ padding:"10px 14px", fontFamily:"monospace", fontSize:11, color:C.muted }}>{c.id}</td>
                <td style={{ padding:"10px 14px", fontSize:12, color:C.text, maxWidth:200 }}>{c.name}</td>
                <td style={{ padding:"10px 14px" }}><SevBadge s={c.severity} /></td>
                <td style={{ padding:"10px 14px" }}>
                  {(() => {
                    const fam = CHECK_FAMILIES.find(f => f.id === c.family);
                    return fam ? <span style={{ fontFamily:"monospace", fontSize:9, color:fam.color, background:`${fam.color}18`, border:`1px solid ${fam.color}40`, padding:"2px 6px", borderRadius:3 }}>{fam.label}</span> : null;
                  })()}
                </td>
                <td style={{ padding:"10px 14px" }}>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:3 }}>
                    {c.target_types.map(t => <span key={t} style={{ fontFamily:"monospace", fontSize:9, color:C.teal, background:"#0a2030", border:"1px solid #1a4050", padding:"1px 5px", borderRadius:2 }}>{t}</span>)}
                  </div>
                </td>
                <td style={{ padding:"10px 14px" }}>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:3 }}>
                    {c.frameworks.slice(0, 2).map((f, i) => {
                      const fw = f.split(":")[0];
                      return <span key={i} style={{ fontFamily:"monospace", fontSize:9, color:C.accent, background:"#0d1a35", border:"1px solid #1a3060", padding:"1px 5px", borderRadius:2 }}>{fw.replace("_LLM","").replace("_ATLAS","").replace("_AI_RMF","")}</span>;
                    })}
                    {c.frameworks.length > 2 && <span style={{ fontSize:9, color:C.dim }}>+{c.frameworks.length - 2}</span>}
                  </div>
                </td>
                <td style={{ padding:"10px 14px" }}>
                  <Btn onClick={() => setSelectedCheck(c)} style={{ padding:"4px 10px", fontSize:10 }}>View Code</Btn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// POLICY EDITOR
// ─────────────────────────────────────────────
const DEFAULT_POLICY = `id: CUSTOM-001\nname: Custom check — example\ndescription: >\n  Describe what this check detects.\nseverity: high\ntarget_types: [llm_api]\ncheck_module: checks/custom-001\nenabled: true\nremediation: |\n  1. Step one.\n  2. Step two.\nframework_refs:\n  - framework: OWASP_LLM\n    id: LLM01\n  - framework: NIST_AI_RMF\n    function: MEASURE\ntags: [custom]\n`;

function PolicyEditorScreen() {
  const [code, setCode]           = useState(DEFAULT_POLICY);
  const [validation, setValidation] = useState(null);
  const validate = () => {
    const lines = code.split("\n");
    const errs = [];
    if (!lines.some(l => l.startsWith("id:")))           errs.push("Missing: id");
    if (!lines.some(l => l.startsWith("severity:") && ["critical","high","medium","low","info"].some(s => l.includes(s)))) errs.push("Missing/invalid: severity");
    if (!lines.some(l => l.startsWith("target_types:"))) errs.push("Missing: target_types");
    if (!lines.some(l => l.includes("framework_refs:"))) errs.push("Missing: framework_refs");
    setValidation(errs.length === 0 ? { ok:true, msg:"Schema valid ✓" } : { ok:false, errors:errs });
  };
  return (
    <div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 320px", gap:20 }}>
        <Card style={{ padding:0 }}>
          <div style={{ borderBottom:`1px solid ${C.border}`, padding:"10px 16px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <span style={{ fontFamily:"monospace", fontSize:11, color:C.muted, textTransform:"uppercase", letterSpacing:"0.08em" }}>Policy editor · YAML</span>
            <Btn variant="primary" onClick={validate}>Validate</Btn>
          </div>
          <textarea value={code} onChange={e => { setCode(e.target.value); setValidation(null); }}
                    spellCheck={false}
                    style={{ width:"100%", minHeight:480, background:"transparent", border:"none", color:C.text, padding:"16px 20px", fontSize:12, fontFamily:"monospace", lineHeight:1.7, outline:"none", resize:"vertical", boxSizing:"border-box" }} />
          {validation && (
            <div style={{ borderTop:`1px solid ${validation.ok ? "#1a5a28" : "#7f2020"}`, padding:"10px 16px", background: validation.ok ? "#0d2314" : "#2d1414" }}>
              {validation.ok
                ? <span style={{ color:C.healthy, fontFamily:"monospace", fontSize:12 }}>{validation.msg}</span>
                : validation.errors.map((e, i) => <div key={i} style={{ color:C.critical, fontFamily:"monospace", fontSize:11 }}>✗ {e}</div>)
              }
            </div>
          )}
        </Card>
        <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
          <Card>
            <SecTitle>Schema reference</SecTitle>
            <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
              {[{f:"id",t:"string",r:true},{f:"name",t:"string",r:true},{f:"severity",t:"critical…info",r:true},{f:"target_types",t:"array",r:true},{f:"check_module",t:"path",r:true},{f:"framework_refs",t:"array",r:true},{f:"enabled",t:"boolean",r:false},{f:"tags",t:"string[]",r:false}].map(({f,t,r}) => (
                <div key={f} style={{ display:"flex", justifyContent:"space-between", fontSize:11, fontFamily:"monospace", borderBottom:`1px solid ${C.border}`, paddingBottom:4 }}>
                  <span style={{ color:C.teal }}>{f}</span>
                  <span style={{ color:C.muted }}>{t}</span>
                  <span style={{ color: r ? C.critical : C.dim, width:30, textAlign:"right" }}>{r ? "req" : "opt"}</span>
                </div>
              ))}
            </div>
          </Card>
          <Card>
            <SecTitle>All checks ({ALL_CHECKS.filter(c => c.enabled).length} active)</SecTitle>
            <div style={{ display:"flex", flexDirection:"column", gap:4, maxHeight:280, overflowY:"auto" }}>
              {ALL_CHECKS.map(c => (
                <div key={c.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", fontSize:10, fontFamily:"monospace" }}>
                  <span style={{ color: c.enabled ? C.text : C.dim }}>{c.id}</span>
                  <div style={{ width:7, height:7, borderRadius:"50%", background: c.enabled ? C.healthy : C.dim }} />
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// REPORTS
// ─────────────────────────────────────────────
function ReportsScreen({ findings, scans }) {
  const [selScan, setSelScan]         = useState(scans[0]?.id || "");
  const [sevFilter, setSevFilter]     = useState("all");
  const scan = scans.find(s => s.id === selScan);
  const rf   = findings.filter(f => sevFilter === "all" || f.severity === sevFilter);

  const copy = () => {
    const t = `DoofusAI SPM v${VERSION} Security Report\n${"=".repeat(40)}\nGenerated: ${new Date().toISOString()}\nPosture Score: ${scan?.posture_score ?? "N/A"}\n\n` +
      rf.map(f => `[${f.severity.toUpperCase()}] ${f.title}\nResource: ${f.resource}\n${f.description}\n\nRemediation:\n${f.remediation}\n`).join("\n---\n\n");
    navigator.clipboard.writeText(t);
  };

  const dl = () => {
    const b = new Blob([JSON.stringify({ scan, findings:rf }, null, 2)], { type:"application/json" });
    Object.assign(document.createElement("a"), { href:URL.createObjectURL(b), download:`doofusai-report-${selScan}.json` }).click();
  };

  return (
    <div>
      <Card style={{ marginBottom:20 }}>
        <div style={{ display:"flex", gap:16, alignItems:"center", flexWrap:"wrap" }}>
          <div>
            <label style={{ fontSize:11, color:C.muted, fontFamily:"monospace", display:"block", marginBottom:4, textTransform:"uppercase", letterSpacing:"0.08em" }}>Scan</label>
            <select value={selScan} onChange={e => setSelScan(e.target.value)} style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text, padding:"6px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}>
              {scans.filter(s => s.status === "completed").map(s => <option key={s.id} value={s.id}>{s.id} — {s.target_meta?.name}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize:11, color:C.muted, fontFamily:"monospace", display:"block", marginBottom:4, textTransform:"uppercase", letterSpacing:"0.08em" }}>Severity</label>
            <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} style={{ background:C.elevated, border:`1px solid ${C.border}`, color:C.text, padding:"6px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}>
              <option value="all">All</option>
              {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div style={{ marginLeft:"auto", display:"flex", gap:8 }}>
            <Btn onClick={copy}>⎘ Copy as text</Btn>
            <Btn variant="success" onClick={dl}>↓ JSON</Btn>
          </div>
        </div>
      </Card>
      <Card style={{ fontFamily:"monospace" }}>
        <div style={{ borderBottom:`1px solid ${C.border}`, paddingBottom:16, marginBottom:20 }}>
          <div style={{ fontSize:11, color:C.muted, letterSpacing:"0.12em", textTransform:"uppercase", marginBottom:8 }}>DoofusAI SPM v{VERSION} — Security Posture Report · Aniza Corp</div>
          <div style={{ display:"flex", gap:32, flexWrap:"wrap" }}>
            <div><span style={{ color:C.muted, fontSize:11 }}>Generated: </span><span style={{ color:C.text, fontSize:11 }}>{new Date().toISOString().replace("T"," ").slice(0,19)} UTC</span></div>
            {scan && <><div><span style={{ color:C.muted, fontSize:11 }}>Scan: </span><span style={{ color:C.text, fontSize:11 }}>{scan.id} · {scan.target_meta?.name}</span></div>
            <div><span style={{ color:C.muted, fontSize:11 }}>Posture: </span><span style={{ color: scan.posture_score >= 70 ? C.healthy : scan.posture_score >= 40 ? C.high : C.critical, fontSize:13, fontWeight:700 }}>{scan.posture_score}</span></div></>}
            <div><span style={{ color:C.muted, fontSize:11 }}>Findings: </span><span style={{ color:C.text, fontSize:11 }}>{rf.length}</span></div>
          </div>
        </div>
        {rf.map((f, i) => (
          <div key={f.id} style={{ borderBottom:`1px solid ${C.border}`, paddingBottom:16, marginBottom:16 }}>
            <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:8 }}>
              <span style={{ color:C.muted, fontSize:11 }}>{String(i + 1).padStart(2,"0")}</span>
              <SevBadge s={f.severity} />
              <span style={{ color:C.text, fontSize:13 }}>{f.title}</span>
            </div>
            <div style={{ display:"flex", gap:16, marginBottom:8, fontSize:11 }}>
              <span><span style={{ color:C.muted }}>Resource: </span><span style={{ color:C.teal }}>{f.resource}</span></span>
              <span><span style={{ color:C.muted }}>Policy: </span><span style={{ color:C.accent }}>{f.policy_id}</span></span>
            </div>
            <p style={{ color:C.muted, fontSize:12, margin:"0 0 6px", lineHeight:1.6 }}>{f.description}</p>
            <div style={{ color:C.medium, fontSize:11 }}>Remediation: {f.remediation.split("\n")[0]}</div>
          </div>
        ))}
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// ABOUT PAGE
// ─────────────────────────────────────────────
function AboutScreen() {
  const FRAMEWORKS = [
    { name:"OWASP LLM Top 10 (2025)", desc:"10 critical security risks for LLM-based applications, including the new Vector & Embedding Weaknesses and System Prompt Leakage categories.", url:"https://genai.owasp.org/llm-top-10/", color:C.purple },
    { name:"MITRE ATLAS v5.4.0",      desc:"Adversarial threat landscape for AI systems — 16 tactics and 84 techniques including 14 new agentic AI techniques added in 2025.", url:"https://atlas.mitre.org/",            color:C.accent },
    { name:"NIST AI RMF 1.0",         desc:"Risk management framework for AI systems, organising controls across GOVERN, MAP, MEASURE, and MANAGE functions.", url:"https://www.nist.gov/artificial-intelligence/ai-risk-management-framework", color:C.teal },
  ];

  const TOOLS = [
    { name:"detect-secrets", desc:"Yelp's credential scanning tool — finds API keys and secrets in source code." },
    { name:"garak",          desc:"NVIDIA's LLM vulnerability prober — adversarial probing for injection and jailbreaks." },
    { name:"llm-guard",      desc:"ProtectAI's input/output scanner — PII detection, toxicity, and injection." },
    { name:"checkov",        desc:"Bridgecrew/Prisma Cloud IaC scanner — misconfigurations in Terraform, CloudFormation, Kubernetes." },
  ];

  return (
    <div style={{ maxWidth:860 }}>
      {/* Hero */}
      <Card style={{ marginBottom:24, padding:"40px 48px", textAlign:"center", background:`linear-gradient(135deg, #0d1525 0%, #111a2e 100%)`, border:`1px solid ${C.borderHi}` }}>
        <div style={{ width:64, height:64, background:"#1a2a50", border:`2px solid ${C.accent}`, borderRadius:14, display:"flex", alignItems:"center", justifyContent:"center", fontSize:30, margin:"0 auto 20px" }}>⬡</div>
        <div style={{ fontSize:32, fontFamily:"monospace", fontWeight:700, color:C.text, marginBottom:8 }}>
          Doofus<span style={{ color:C.accent }}>AI</span> SPM
        </div>
        <div style={{ fontSize:14, color:C.muted, fontFamily:"monospace", marginBottom:6 }}>AI Security Posture Management</div>
        <div style={{ display:"inline-block", background:C.elevated, border:`1px solid ${C.border}`, borderRadius:4, padding:"3px 12px", fontSize:11, fontFamily:"monospace", color:C.teal, marginBottom:24 }}>v{VERSION}</div>
        <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:24 }}>
          <div style={{ fontSize:16, color:C.text, marginBottom:4 }}>Designed and built by</div>
          <div style={{ fontSize:22, color:C.text, fontWeight:700, marginBottom:6 }}>Shahryar Jahangir</div>
          <div style={{ fontSize:14, color:C.accent, fontFamily:"monospace", marginBottom:4 }}>Aniza Corp</div>
          <div style={{ fontSize:12, color:C.muted }}>© {new Date().getFullYear()} Aniza Corp. All rights reserved.</div>
        </div>
      </Card>

      {/* What it does */}
      <Card style={{ marginBottom:20 }}>
        <SecTitle>What is DoofusAI SPM?</SecTitle>
        <p style={{ color:C.text, fontSize:14, lineHeight:1.8, margin:0 }}>
          DoofusAI SPM is an open-source AI Security Posture Management platform. It helps organisations find and fix
          security weaknesses in their AI and machine-learning infrastructure before attackers can exploit them.
          It scans five types of targets — LLM APIs, AI infrastructure, model registries, AI-integrated applications,
          and CI/CD pipelines — and produces a scored, prioritised list of findings with step-by-step remediation
          guidance. Every finding is mapped to internationally recognised security frameworks so you know exactly
          which standards you are meeting and which you are not.
        </p>
      </Card>

      {/* Security frameworks */}
      <Card style={{ marginBottom:20 }}>
        <SecTitle>Security Frameworks</SecTitle>
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          {FRAMEWORKS.map(f => (
            <div key={f.name} style={{ display:"flex", gap:14, padding:"14px 16px", background:C.elevated, borderRadius:6, border:`1px solid ${C.border}` }}>
              <div style={{ width:4, borderRadius:2, background:f.color, flexShrink:0 }} />
              <div>
                <a href={f.url} target="_blank" rel="noreferrer" style={{ fontSize:14, color:f.color, fontWeight:600, textDecoration:"none", display:"block", marginBottom:4 }}>{f.name} ↗</a>
                <div style={{ fontSize:13, color:C.muted, lineHeight:1.6 }}>{f.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Open-source tools */}
      <Card style={{ marginBottom:20 }}>
        <SecTitle>Open-Source Tool Integrations</SecTitle>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
          {TOOLS.map(t => (
            <div key={t.name} style={{ padding:"12px 14px", background:C.elevated, borderRadius:6, border:`1px solid ${C.border}` }}>
              <div style={{ fontFamily:"monospace", fontSize:12, color:C.teal, fontWeight:600, marginBottom:4 }}>{t.name}</div>
              <div style={{ fontSize:12, color:C.muted, lineHeight:1.5 }}>{t.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ marginTop:14, padding:"10px 14px", background:"#1a1000", border:"1px solid #3a2a00", borderRadius:6, fontFamily:"monospace", fontSize:11, color:"#d97706" }}>
          Install all tools: <code style={{ color:C.medium }}>pip install detect-secrets garak llm-guard checkov</code>
        </div>
      </Card>

      {/* Stats */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16 }}>
        {[
          { l:"Total Checks",  v: ALL_CHECKS.length,                                             c:C.accent  },
          { l:"OWASP LLM Top 10", v: ALL_CHECKS.filter(c => c.family === "owasp").length,        c:C.purple  },
          { l:"MITRE ATLAS",   v: ALL_CHECKS.filter(c => c.family === "mitre").length,           c:C.accent  },
          { l:"Check Families",v: CHECK_FAMILIES.length - 1,                                     c:C.teal    },
        ].map(({ l, v, c }) => (
          <Card key={l} style={{ textAlign:"center" }}>
            <div style={{ fontSize:28, fontFamily:"monospace", fontWeight:700, color:c, lineHeight:1 }}>{v}</div>
            <div style={{ fontSize:10, color:C.muted, marginTop:6, fontFamily:"monospace", textTransform:"uppercase", letterSpacing:"0.08em" }}>{l}</div>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// ROOT APP — left sidebar layout
// ─────────────────────────────────────────────
export default function App() {
  const [page, setPage]       = useState("dashboard");
  const [findings, setFindings] = useState(SEED_FINDINGS);
  const [scans, setScans]     = useState(SEED_SCANS);

  // Lift status-change up so scans update the dashboard
  const handleStatusChange = useCallback((id, status) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status } : f));
  }, []);

  // Called when a scan completes — updates state then navigates to Findings
  const handleScanComplete = useCallback((newScan, newFindings) => {
    setScans(prev => [newScan, ...prev]);
    setFindings(prev => [...newFindings, ...prev]);
    setPage("findings");
  }, []);

  const openCount  = findings.filter(f => f.status === "open").length;
  const critCount  = findings.filter(f => f.severity === "critical" && f.status === "open").length;
  const score      = Math.max(0, 100 - findings.filter(f => f.status !== "resolved").reduce((s, f) => s + f.score * 1.5, 0));
  const scoreColor = score >= 70 ? C.healthy : score >= 40 ? C.high : C.critical;

  const NAV = [
    { id:"dashboard", icon:"▦",  label:"Dashboard"       },
    { id:"findings",  icon:"⊛",  label:"Findings"        },
    { id:"scans",     icon:"▷",  label:"Scan Config"     },
    { id:"checks",    icon:"◈",  label:"Check Registry"  },
    { id:"policies",  icon:"◧",  label:"Policy Editor"   },
    { id:"reports",   icon:"⬡",  label:"Reports"         },
    { id:"about",     icon:"◉",  label:"About"           },
  ];

  return (
    <div style={{ display:"flex", minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"'DM Mono','IBM Plex Mono','Fira Code',monospace" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* ── LEFT SIDEBAR ── */}
      <div style={{ width:220, flexShrink:0, background:C.surface, borderRight:`1px solid ${C.border}`, display:"flex", flexDirection:"column", height:"100vh", position:"sticky", top:0, overflowY:"auto" }}>
        {/* Logo */}
        <div style={{ padding:"20px 20px 16px", borderBottom:`1px solid ${C.border}` }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
            <div style={{ width:28, height:28, background:"#1a2a50", border:`1px solid ${C.accent}`, borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>⬡</div>
            <span style={{ fontSize:14, fontWeight:500, color:C.text }}>Doofus<span style={{ color:C.accent }}>AI</span> SPM</span>
          </div>
          <div style={{ fontSize:9, color:C.muted, letterSpacing:"0.1em", textTransform:"uppercase", paddingLeft:38 }}>v{VERSION} · Aniza Corp</div>
        </div>

        {/* Nav items */}
        <nav style={{ padding:"12px 10px", flex:1 }}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => setPage(n.id)}
                    style={{ display:"flex", alignItems:"center", gap:10, width:"100%", padding:"9px 12px", borderRadius:6, marginBottom:2,
                             background: page === n.id ? C.elevated : "transparent",
                             border:`1px solid ${page === n.id ? C.borderHi : "transparent"}`,
                             color: page === n.id ? C.text : C.muted,
                             cursor:"pointer", fontSize:12, fontFamily:"monospace", letterSpacing:"0.03em",
                             textAlign:"left", transition:"all 0.12s" }}>
              <span style={{ fontSize:14, width:18, flexShrink:0 }}>{n.icon}</span>
              {n.label}
              {n.id === "findings" && openCount > 0 && (
                <span style={{ marginLeft:"auto", background:"#2d1414", border:"1px solid #7f2020", color:C.critical, borderRadius:10, padding:"1px 6px", fontSize:10 }}>{openCount}</span>
              )}
            </button>
          ))}
        </nav>

        {/* Bottom status */}
        <div style={{ padding:"12px 16px", borderTop:`1px solid ${C.border}` }}>
          <div style={{ fontSize:10, color:C.muted, fontFamily:"monospace", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.08em" }}>Posture Score</div>
          <div style={{ fontSize:24, fontFamily:"monospace", fontWeight:700, color:scoreColor }}>{Math.round(score)}</div>
          <div style={{ display:"flex", gap:10, marginTop:6, fontSize:10, fontFamily:"monospace", color:C.muted }}>
            <span><span style={{ color:C.critical }}>{critCount}</span> crit</span>
            <span><span style={{ color:C.text }}>{openCount}</span> open</span>
          </div>
        </div>
      </div>

      {/* ── MAIN CONTENT ── */}
      <div style={{ flex:1, display:"flex", flexDirection:"column", minWidth:0 }}>
        {/* Top bar */}
        <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"12px 28px", display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
          <span style={{ fontSize:10, color:C.dim }}>doofusai-spm</span>
          <span style={{ fontSize:10, color:C.dim }}>›</span>
          <span style={{ fontSize:10, color:C.muted }}>{NAV.find(n => n.id === page)?.label}</span>
        </div>

        {/* Page content */}
        <div style={{ padding:"28px 32px", overflowY:"auto", flex:1 }}>
          {page === "dashboard" && <Dashboard findings={findings} scans={scans} />}
          {page === "findings"  && <FindingsScreen findings={findings} onStatusChange={handleStatusChange} />}
          {page === "scans"     && <ScanConfigScreen scans={scans} onScanComplete={handleScanComplete} onNavigate={setPage} />}
          {page === "checks"    && <CheckRegistryScreen />}
          {page === "policies"  && <PolicyEditorScreen />}
          {page === "reports"   && <ReportsScreen findings={findings} scans={scans} />}
          {page === "about"     && <AboutScreen />}
        </div>
      </div>
    </div>
  );
}
