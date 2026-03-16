import { useState, useEffect, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend
} from "recharts";

// ── Mock data engine ───────────────────────────────────────────────────────────

const MOCK_FINDINGS = [
  { id: "F-001", policy_id: "OWASP-LLM01", policy_name: "Prompt Injection — direct", target_type: "llm_api", resource: "prod-openai-gateway", severity: "critical", confidence: "confirmed", score: 10, status: "open", title: "No system prompt configured", description: "The LLM endpoint has no system prompt. Without one, the model has no guardrails and is trivially susceptible to direct prompt injection.", evidence: "system_prompt: null", remediation: "1. Add a hardened system prompt prefix.\n2. Run input through llm-guard PromptInjectionScanner.\n3. Deploy rebuff firewall at API gateway.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM01" }, { framework: "MITRE_ATLAS", id: "AML.T0051.000" }, { framework: "NIST_AI_RMF", function: "MEASURE" }], first_seen: "2025-03-10T09:12:00Z" },
  { id: "F-002", policy_id: "OWASP-LLM06", policy_name: "Sensitive Information Disclosure", target_type: "llm_api", resource: "dev-anthropic-proxy", severity: "critical", confidence: "confirmed", score: 10, status: "open", title: "API key passed directly — not via environment variable", description: "The API key was provided as a raw string in the target configuration rather than being injected from an environment variable or secrets manager.", evidence: "api_key_raw field present in target config", remediation: "1. Store API keys exclusively in environment variables.\n2. Never log raw API keys.\n3. Rotate any key that has been observed in plaintext.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM06" }, { framework: "NIST_AI_RMF", function: "GOVERN" }], first_seen: "2025-03-11T14:30:00Z" },
  { id: "F-003", policy_id: "INFRA-001", policy_name: "Unauthenticated ML Endpoints", target_type: "ai_infra", resource: "mlflow-prod:5000", severity: "critical", confidence: "confirmed", score: 10, status: "open", title: "Unauthenticated MLflow REST API endpoint accessible", description: "The MLflow endpoint at mlflow-prod:5000/api/2.0/mlflow/experiments/list returned HTTP 200 without requiring authentication.", evidence: "GET /api/2.0/mlflow/experiments/list → HTTP 200, no WWW-Authenticate header", remediation: "1. Place MLflow behind OAuth2/LDAP proxy.\n2. Restrict to VPC only.\n3. Enable audit logging.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM05" }, { framework: "MITRE_ATLAS", id: "AML.T0007.000" }], first_seen: "2025-03-09T11:00:00Z" },
  { id: "F-004", policy_id: "APP-001", policy_name: "Excessive Agency", target_type: "ai_app", resource: "sales-agent-prod", severity: "critical", confidence: "confirmed", score: 10, status: "open", title: "Agent has high-risk tool access without HITL (4 tools)", description: "The agent has access to 4 high-risk tools (send_email, database_write, make_payment, deploy) with no human approval gate.", evidence: "High-risk tools: send_email, database_write, make_payment, deploy", remediation: "1. Apply least-privilege tool scoping.\n2. Add HITL approval gates before irreversible actions.\n3. Set max_iterations ≤ 10.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM08" }, { framework: "MITRE_ATLAS", id: "AML.T0051.001" }], first_seen: "2025-03-12T08:00:00Z" },
  { id: "F-005", policy_id: "APP-002", policy_name: "Insecure RAG Retrieval & PII Leakage", target_type: "ai_app", resource: "support-rag-app", severity: "critical", confidence: "confirmed", score: 10, status: "open", title: "Vector database has no access control on retrieval", description: "The RAG pipeline retrieves from a vector database without row-level access controls. Any user can retrieve documents they should not have access to.", evidence: "vector_db_auth: false, retrieval_acl: null", remediation: "1. Implement row-level security on vector DB.\n2. Scan output with llm-guard PII scanner.\n3. Validate all queries before retrieval.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM06" }, { framework: "NIST_AI_RMF", function: "MEASURE" }], first_seen: "2025-03-10T16:45:00Z" },
  { id: "F-006", policy_id: "REGISTRY-001", policy_name: "Unsigned Artefacts & Pickle Risk", target_type: "model_registry", resource: "hf-internal-registry", severity: "high", confidence: "confirmed", score: 8, status: "open", title: "Pickle-format models in registry (.pkl, .pt)", description: "One or more models are stored in pickle format. Python pickle deserialisation executes arbitrary code.", evidence: "Artefact formats found: pkl, pt", remediation: "1. Migrate from pickle to SafeTensors format.\n2. Enforce model signing with sigstore/cosign.\n3. Verify SHA-256 checksums on load.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM05" }, { framework: "MITRE_ATLAS", id: "AML.T0010.000" }], first_seen: "2025-03-08T10:00:00Z" },
  { id: "F-007", policy_id: "INFRA-002", policy_name: "Unencrypted Model Artefact Storage", target_type: "ai_infra", resource: "s3://ml-models-prod", severity: "high", confidence: "confirmed", score: 8, status: "acknowledged", title: "Model artefact S3 bucket is publicly readable", description: "The S3 bucket has a public ACL. Training data, model weights, and hyperparameters are exposed to the internet.", evidence: "ACL: public-read", remediation: "1. Enable S3 SSE-KMS encryption.\n2. Set ACLs to private, block public access.\n3. Enable bucket versioning.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM05" }, { framework: "NIST_AI_RMF", function: "MANAGE" }], first_seen: "2025-03-07T12:30:00Z" },
  { id: "F-008", policy_id: "OWASP-LLM01", policy_name: "Prompt Injection — direct", target_type: "llm_api", resource: "staging-gpt4-endpoint", severity: "medium", confidence: "probable", score: 3.75, status: "open", title: "System prompt lacks explicit injection hardening", description: "The system prompt exists but does not include explicit instructions to resist prompt injection.", evidence: "No hardening phrases found in system prompt", remediation: "Add explicit injection-resistance instructions to the system prompt.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM01" }, { framework: "MITRE_ATLAS", id: "AML.T0051.000" }], first_seen: "2025-03-13T09:00:00Z" },
  { id: "F-009", policy_id: "REGISTRY-002", policy_name: "Missing SBOM and Model Card Issues", target_type: "model_registry", resource: "hf-internal-registry", severity: "medium", confidence: "probable", score: 3.75, status: "open", title: "No SBOM for model dependencies", description: "There is no SBOM or dependency manifest for this model.", evidence: "sbom_present: false, dependency_manifest: null", remediation: "1. Generate CycloneDX/SPDX SBOM for every model.\n2. Add licence and data_provenance to model cards.", framework_refs: [{ framework: "OWASP_LLM", id: "LLM05" }, { framework: "NIST_AI_RMF", function: "GOVERN" }], first_seen: "2025-03-11T15:00:00Z" },
  { id: "F-010", policy_id: "INFRA-002", policy_name: "Unencrypted Model Artefact Storage", target_type: "ai_infra", resource: "gcs://ml-experiments-dev", severity: "low", confidence: "probable", score: 1.5, status: "resolved", title: "Audit logging not enabled on AI infrastructure", description: "Audit logging is disabled. Without it, there is no record of model access or pipeline executions.", evidence: "audit_log_enabled: false", remediation: "Enable CloudTrail/Cloud Audit Logs on all ML infrastructure.", framework_refs: [{ framework: "NIST_AI_RMF", function: "MANAGE" }], first_seen: "2025-03-06T08:00:00Z" },
];

const MOCK_SCANS = [
  { id: "SCN-001", target_type: "llm_api",        target_meta: { name: "prod-openai-gateway" },    status: "completed", posture_score: 42, tier: "at_risk",   created_at: "2025-03-13T09:00:00Z", finished_at: "2025-03-13T09:03:12Z", findings: 3 },
  { id: "SCN-002", target_type: "ai_infra",        target_meta: { name: "ml-platform-prod" },       status: "completed", posture_score: 28, tier: "critical",  created_at: "2025-03-12T14:00:00Z", finished_at: "2025-03-12T14:05:30Z", findings: 2 },
  { id: "SCN-003", target_type: "ai_app",          target_meta: { name: "sales-agent-prod" },       status: "completed", posture_score: 35, tier: "critical",  created_at: "2025-03-12T08:00:00Z", finished_at: "2025-03-12T08:02:45Z", findings: 2 },
  { id: "SCN-004", target_type: "model_registry",  target_meta: { name: "hf-internal-registry" },   status: "completed", posture_score: 67, tier: "at_risk",   created_at: "2025-03-11T11:00:00Z", finished_at: "2025-03-11T11:01:55Z", findings: 2 },
  { id: "SCN-005", target_type: "llm_api",         target_meta: { name: "staging-gpt4-endpoint" },  status: "running",   posture_score: null, tier: null,      created_at: "2025-03-13T10:00:00Z", finished_at: null, findings: 0 },
];

const POLICIES = [
  { id: "OWASP-LLM01", name: "Prompt Injection — direct", severity: "critical", target_types: ["llm_api", "ai_app"], framework: "OWASP LLM Top 10", enabled: true },
  { id: "OWASP-LLM06", name: "Sensitive Information Disclosure", severity: "critical", target_types: ["llm_api"], framework: "OWASP LLM Top 10", enabled: true },
  { id: "INFRA-001",   name: "Unauthenticated ML Endpoints", severity: "critical", target_types: ["ai_infra"], framework: "Custom", enabled: true },
  { id: "INFRA-002",   name: "Unencrypted Model Artefact Storage", severity: "high", target_types: ["ai_infra"], framework: "NIST AI RMF", enabled: true },
  { id: "REGISTRY-001", name: "Unsigned Artefacts & Pickle Risk", severity: "critical", target_types: ["model_registry"], framework: "OWASP LLM Top 10", enabled: true },
  { id: "REGISTRY-002", name: "Missing SBOM and Model Card Issues", severity: "high", target_types: ["model_registry"], framework: "NIST AI RMF", enabled: false },
  { id: "APP-001",     name: "Excessive Agency", severity: "critical", target_types: ["ai_app"], framework: "OWASP LLM Top 10", enabled: true },
  { id: "APP-002",     name: "Insecure RAG Retrieval & PII Leakage", severity: "critical", target_types: ["ai_app"], framework: "OWASP LLM Top 10", enabled: true },
];

// ── Design tokens ──────────────────────────────────────────────────────────────

const C = {
  bg:       "#0d0f14",
  surface:  "#131720",
  elevated: "#1a2030",
  border:   "#1e2535",
  borderHi: "#2a3550",
  text:     "#c9d1e0",
  muted:    "#5a6478",
  dim:      "#3a4258",
  accent:   "#3b7ff5",
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#f59e0b",
  low:      "#22c55e",
  info:     "#6b7280",
  healthy:  "#22c55e",
  at_risk:  "#f97316",
  attention:"#f59e0b",
  teal:     "#14b8a6",
  purple:   "#8b5cf6",
};

const SEVERITY_COLORS = { critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info };
const SEVERITY_WEIGHTS = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Utility components ─────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const colors = {
    critical: { bg: "#2d1414", border: "#7f2020", text: "#ef4444" },
    high:     { bg: "#2d1d10", border: "#7f4010", text: "#f97316" },
    medium:   { bg: "#2d2410", border: "#7f6010", text: "#f59e0b" },
    low:      { bg: "#0d2314", border: "#1a5a28", text: "#22c55e" },
    info:     { bg: "#1a1e2a", border: "#3a4258", text: "#6b7280" },
  };
  const s = colors[severity] || colors.info;
  return (
    <span style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      padding: "2px 8px", borderRadius: 3, fontSize: 11, fontFamily: "monospace",
      fontWeight: 600, letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{severity}</span>
  );
}

function StatusBadge({ status }) {
  const map = {
    open:         { bg: "#2d1414", border: "#7f2020", text: "#ef4444" },
    acknowledged: { bg: "#2d2410", border: "#7f6010", text: "#f59e0b" },
    resolved:     { bg: "#0d2314", border: "#1a5a28", text: "#22c55e" },
    running:      { bg: "#0d1e35", border: "#1a4578", text: "#3b7ff5" },
    completed:    { bg: "#0d2314", border: "#1a5a28", text: "#22c55e" },
    failed:       { bg: "#2d1414", border: "#7f2020", text: "#ef4444" },
    pending:      { bg: "#1a1e2a", border: "#3a4258", text: "#6b7280" },
  };
  const s = map[status] || map.pending;
  return (
    <span style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      padding: "2px 8px", borderRadius: 3, fontSize: 11, fontFamily: "monospace",
      fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em",
    }}>{status}</span>
  );
}

function FrameworkBadge({ fw }) {
  const map = {
    OWASP_LLM:  { bg: "#1a0d2d", border: "#4a1a7f", text: "#a78bfa" },
    MITRE_ATLAS: { bg: "#0d1a2d", border: "#1a4578", text: "#60a5fa" },
    NIST_AI_RMF: { bg: "#0d2520", border: "#1a6050", text: "#34d399" },
    CUSTOM:      { bg: "#1a1e2a", border: "#3a4258", text: "#9ca3af" },
  };
  const urls = {
    OWASP_LLM: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    MITRE_ATLAS: "https://atlas.mitre.org/",
    NIST_AI_RMF: "https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf",
  };
  const s = map[fw.framework] || map.CUSTOM;
  return (
    <a href={fw.url || urls[fw.framework] || "#"} target="_blank" rel="noreferrer" style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      padding: "2px 7px", borderRadius: 3, fontSize: 10, fontFamily: "monospace",
      textDecoration: "none", letterSpacing: "0.02em", display: "inline-block",
    }}>
      {fw.framework.replace("_", " ")} {fw.id || fw.function || ""}
    </a>
  );
}

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 8, padding: "20px 24px", ...style,
    }}>{children}</div>
  );
}

function SectionTitle({ children }) {
  return (
    <div style={{
      fontFamily: "monospace", fontSize: 10, letterSpacing: "0.12em",
      color: C.muted, textTransform: "uppercase", marginBottom: 16,
      borderBottom: `1px solid ${C.border}`, paddingBottom: 8,
    }}>{children}</div>
  );
}

function PostureGauge({ score }) {
  const tier = score >= 90 ? "Healthy" : score >= 70 ? "Needs Attention" : score >= 40 ? "At Risk" : "Critical";
  const color = score >= 90 ? C.healthy : score >= 70 ? C.attention : score >= 40 ? C.at_risk : C.critical;

  const r = 80, cx = 110, cy = 100;
  const startAngle = -210, totalDeg = 240;
  const pct = Math.min(score / 100, 1);
  const sweepDeg = pct * totalDeg;

  function polarToXY(deg, radius) {
    const rad = (deg * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  }

  function arcPath(start, sweep, radius) {
    const end = start + sweep;
    const s = polarToXY(start, radius);
    const e = polarToXY(end, radius);
    const large = sweep > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${large} 1 ${e.x} ${e.y}`;
  }

  const trackPath  = arcPath(startAngle, totalDeg, r);
  const filledPath = arcPath(startAngle, sweepDeg, r);

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <svg width="220" height="150" viewBox="0 0 220 150">
        <path d={trackPath} fill="none" stroke={C.border} strokeWidth="10" strokeLinecap="round" />
        <path d={filledPath} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${color}66)` }} />
        <text x={cx} y={cy - 8} textAnchor="middle" fill={color}
          style={{ fontSize: 36, fontFamily: "monospace", fontWeight: 700 }}>
          {Math.round(score)}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill={color}
          style={{ fontSize: 12, fontFamily: "monospace", letterSpacing: "0.06em" }}>
          {tier.toUpperCase()}
        </text>
        <text x={cx} y={cy + 32} textAnchor="middle" fill={C.muted}
          style={{ fontSize: 10, fontFamily: "monospace" }}>
          POSTURE SCORE
        </text>
      </svg>
    </div>
  );
}

// ── Finding Drawer ──────────────────────────────────────────────────────────────

function FindingDrawer({ finding, onClose, onStatusChange }) {
  if (!finding) return null;
  return (
    <div style={{
      position: "fixed", top: 0, right: 0, bottom: 0, width: 520,
      background: C.surface, borderLeft: `1px solid ${C.borderHi}`,
      overflowY: "auto", zIndex: 100, padding: "24px",
      boxShadow: "-8px 0 32px rgba(0,0,0,0.6)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ fontFamily: "monospace", fontSize: 10, color: C.muted, letterSpacing: "0.1em", marginBottom: 6 }}>{finding.id}</div>
          <div style={{ color: C.text, fontSize: 15, fontWeight: 600, lineHeight: 1.4, maxWidth: 380 }}>{finding.title}</div>
        </div>
        <button onClick={onClose} style={{
          background: "transparent", border: `1px solid ${C.border}`, color: C.muted,
          cursor: "pointer", padding: "4px 10px", borderRadius: 4, fontSize: 16,
        }}>✕</button>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        <SeverityBadge severity={finding.severity} />
        <StatusBadge status={finding.status} />
        <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted, padding: "2px 8px", border: `1px solid ${C.border}`, borderRadius: 3 }}>
          {finding.target_type.replace("_", " ")}
        </span>
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Description</div>
        <p style={{ color: C.text, fontSize: 13, lineHeight: 1.7, margin: 0 }}>{finding.description}</p>
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Affected Resource</div>
        <code style={{ background: C.elevated, border: `1px solid ${C.border}`, padding: "6px 12px", borderRadius: 4, fontSize: 12, color: C.teal, display: "block" }}>{finding.resource}</code>
      </div>

      {finding.evidence && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Evidence</div>
          <pre style={{ background: C.elevated, border: `1px solid ${C.border}`, padding: "10px 12px", borderRadius: 4, fontSize: 11, color: C.medium, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{finding.evidence}</pre>
        </div>
      )}

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>Framework Mapping</div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {finding.framework_refs.map((fw, i) => <FrameworkBadge key={i} fw={fw} />)}
        </div>
      </div>

      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>Remediation Steps</div>
        <div style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 4, padding: "12px 16px" }}>
          {finding.remediation.split("\n").filter(Boolean).map((line, i) => (
            <div key={i} style={{ color: C.text, fontSize: 12, lineHeight: 1.7, fontFamily: "monospace" }}>
              <span style={{ color: C.accent }}>{line.match(/^\d+\./) ? "" : "→ "}</span>{line}
            </div>
          ))}
        </div>
        <button onClick={() => navigator.clipboard.writeText(finding.remediation)} style={{
          marginTop: 8, background: "transparent", border: `1px solid ${C.border}`,
          color: C.muted, cursor: "pointer", padding: "5px 12px", borderRadius: 4,
          fontSize: 11, fontFamily: "monospace",
        }}>⎘ Copy remediation</button>
      </div>

      <div style={{ display: "flex", gap: 8, borderTop: `1px solid ${C.border}`, paddingTop: 16 }}>
        {finding.status !== "resolved" && (
          <button onClick={() => onStatusChange(finding.id, "resolved")} style={{
            flex: 1, padding: "8px 0", background: "#0d2314", border: `1px solid #1a5a28`,
            color: C.healthy, cursor: "pointer", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
          }}>✓ Mark Resolved</button>
        )}
        {finding.status === "open" && (
          <button onClick={() => onStatusChange(finding.id, "acknowledged")} style={{
            flex: 1, padding: "8px 0", background: "#2d2410", border: `1px solid #7f6010`,
            color: C.medium, cursor: "pointer", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
          }}>⚑ Acknowledge</button>
        )}
        {finding.status !== "open" && (
          <button onClick={() => onStatusChange(finding.id, "open")} style={{
            flex: 1, padding: "8px 0", background: C.elevated, border: `1px solid ${C.border}`,
            color: C.muted, cursor: "pointer", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
          }}>↩ Reopen</button>
        )}
      </div>
    </div>
  );
}

// ── Dashboard screen ────────────────────────────────────────────────────────────

function Dashboard({ findings, scans }) {
  const [selectedFinding, setSelectedFinding] = useState(null);

  const open = findings.filter(f => f.status !== "resolved");
  const postureScore = Math.max(0, 100 - open.reduce((s, f) => s + f.score * 1.5, 0));

  const bySeverity = ["critical","high","medium","low","info"].map(s => ({
    severity: s, count: open.filter(f => f.severity === s).length,
  })).filter(d => d.count > 0);

  const byFramework = [
    { name: "OWASP LLM",  value: findings.filter(f => f.framework_refs.some(r => r.framework === "OWASP_LLM")).length,  color: C.purple },
    { name: "MITRE ATLAS",value: findings.filter(f => f.framework_refs.some(r => r.framework === "MITRE_ATLAS")).length, color: C.accent },
    { name: "NIST RMF",   value: findings.filter(f => f.framework_refs.some(r => r.framework === "NIST_AI_RMF")).length,  color: C.teal },
  ].filter(d => d.value > 0);

  const byTarget = [
    { name: "LLM API",     critical: findings.filter(f => f.target_type==="llm_api"       && f.severity==="critical").length, high: findings.filter(f => f.target_type==="llm_api"       && f.severity==="high").length, medium: findings.filter(f => f.target_type==="llm_api"       && f.severity==="medium").length },
    { name: "AI Infra",    critical: findings.filter(f => f.target_type==="ai_infra"       && f.severity==="critical").length, high: findings.filter(f => f.target_type==="ai_infra"       && f.severity==="high").length, medium: findings.filter(f => f.target_type==="ai_infra"       && f.severity==="medium").length },
    { name: "Registry",    critical: findings.filter(f => f.target_type==="model_registry" && f.severity==="critical").length, high: findings.filter(f => f.target_type==="model_registry" && f.severity==="high").length, medium: findings.filter(f => f.target_type==="model_registry" && f.severity==="medium").length },
    { name: "AI App",      critical: findings.filter(f => f.target_type==="ai_app"         && f.severity==="critical").length, high: findings.filter(f => f.target_type==="ai_app"         && f.severity==="high").length, medium: findings.filter(f => f.target_type==="ai_app"         && f.severity==="medium").length },
  ];

  const timeline = [
    { date: "Mar 7", score: 55 }, { date: "Mar 8", score: 51 }, { date: "Mar 9", score: 44 },
    { date: "Mar 10", score: 40 }, { date: "Mar 11", score: 38 }, { date: "Mar 12", score: 36 },
    { date: "Mar 13", score: Math.round(postureScore) },
  ];

  const topCritical = findings.filter(f => f.severity === "critical" && f.status === "open").slice(0, 5);

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ background: C.elevated, border: `1px solid ${C.borderHi}`, padding: "8px 12px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>
        <div style={{ color: C.muted, marginBottom: 4 }}>{label}</div>
        {payload.map(p => <div key={p.name} style={{ color: SEVERITY_COLORS[p.name] || C.text }}>{p.name}: {p.value}</div>)}
      </div>
    );
  };

  return (
    <div style={{ padding: "0 0 40px" }}>
      {/* Stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        {[
          { label: "Open Findings", value: open.length, color: C.critical },
          { label: "Critical", value: open.filter(f=>f.severity==="critical").length, color: C.critical },
          { label: "Scans (7d)", value: scans.length, color: C.accent },
          { label: "Policies Active", value: POLICIES.filter(p=>p.enabled).length, color: C.teal },
        ].map(({ label, value, color }) => (
          <Card key={label} style={{ textAlign: "center" }}>
            <div style={{ fontSize: 32, fontFamily: "monospace", fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 6, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</div>
          </Card>
        ))}
      </div>

      {/* Gauge + Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "240px 1fr 200px", gap: 16, marginBottom: 24 }}>
        <Card style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
          <PostureGauge score={Math.round(postureScore)} />
        </Card>

        <Card>
          <SectionTitle>Findings by severity · open only</SectionTitle>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={bySeverity} barSize={32}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
              <XAxis dataKey="severity" tick={{ fill: C.muted, fontSize: 11, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: C.elevated }} />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {bySeverity.map(d => <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
          <SectionTitle>By framework</SectionTitle>
          <ResponsiveContainer width="100%" height={130}>
            <PieChart>
              <Pie data={byFramework} cx="50%" cy="50%" innerRadius={32} outerRadius={52} paddingAngle={3} dataKey="value">
                {byFramework.map(d => <Cell key={d.name} fill={d.color} />)}
              </Pie>
              <Tooltip content={({ active, payload }) => active && payload?.length
                ? <div style={{ background: C.elevated, border: `1px solid ${C.borderHi}`, padding: "6px 10px", fontSize: 11, fontFamily: "monospace", color: C.text }}>{payload[0].name}: {payload[0].value}</div>
                : null} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, width: "100%" }}>
            {byFramework.map(d => (
              <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, fontFamily: "monospace", color: C.muted }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                {d.name}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Target breakdown + Timeline */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, marginBottom: 24 }}>
        <Card>
          <SectionTitle>Findings by target type</SectionTitle>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={byTarget} barSize={18}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
              <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: C.elevated }} />
              <Bar dataKey="critical" stackId="a" fill={C.critical} radius={[0, 0, 0, 0]} />
              <Bar dataKey="high"     stackId="a" fill={C.high} />
              <Bar dataKey="medium"   stackId="a" fill={C.medium} radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <SectionTitle>Posture score trend (7d)</SectionTitle>
          <ResponsiveContainer width="100%" height={120}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="date" tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
              <Tooltip content={({ active, payload }) => active && payload?.length
                ? <div style={{ background: C.elevated, border: `1px solid ${C.borderHi}`, padding: "6px 10px", fontSize: 11, fontFamily: "monospace", color: C.text }}>Score: {payload[0].value}</div>
                : null} />
              <Line type="monotone" dataKey="score" stroke={C.accent} strokeWidth={2} dot={{ fill: C.accent, r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Critical findings table */}
      <Card>
        <SectionTitle>Top critical findings</SectionTitle>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["ID", "Title", "Target", "Confidence", "First Seen", ""].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", fontSize: 10, color: C.muted, fontFamily: "monospace", fontWeight: 400, letterSpacing: "0.08em", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {topCritical.map(f => (
              <tr key={f.id} style={{ borderBottom: `1px solid ${C.border}`, cursor: "pointer", transition: "background 0.15s" }}
                onMouseEnter={e => e.currentTarget.style.background = C.elevated}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                onClick={() => setSelectedFinding(f)}>
                <td style={{ padding: "10px 10px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{f.id}</td>
                <td style={{ padding: "10px 10px", fontSize: 13, color: C.text, maxWidth: 240 }}>{f.title}</td>
                <td style={{ padding: "10px 10px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{f.target_type}</td>
                <td style={{ padding: "10px 10px" }}><StatusBadge status={f.confidence} /></td>
                <td style={{ padding: "10px 10px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{new Date(f.first_seen).toLocaleDateString()}</td>
                <td style={{ padding: "10px 10px" }}>
                  <SeverityBadge severity={f.severity} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusChange={() => setSelectedFinding(null)}
      />
    </div>
  );
}

// ── Findings screen ────────────────────────────────────────────────────────────

function FindingsScreen({ findings, setFindings }) {
  const [filters, setFilters] = useState({ severity: "", status: "", target: "", search: "" });
  const [sort, setSort] = useState({ key: "score", dir: "desc" });
  const [selected, setSelected] = useState(null);

  const filtered = findings
    .filter(f =>
      (!filters.severity || f.severity === filters.severity) &&
      (!filters.status   || f.status === filters.status) &&
      (!filters.target   || f.target_type === filters.target) &&
      (!filters.search   || f.title.toLowerCase().includes(filters.search.toLowerCase()) || f.resource.toLowerCase().includes(filters.search.toLowerCase()))
    )
    .sort((a, b) => {
      let va = a[sort.key], vb = b[sort.key];
      if (sort.key === "severity") { va = SEVERITY_WEIGHTS[a.severity]; vb = SEVERITY_WEIGHTS[b.severity]; }
      if (typeof va === "string") return sort.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
      return sort.dir === "asc" ? va - vb : vb - va;
    });

  const toggleSort = (key) => setSort(s => ({ key, dir: s.key === key && s.dir === "desc" ? "asc" : "desc" }));

  const handleStatusChange = (id, status) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status } : f));
    setSelected(null);
  };

  const selStyle = { background: C.accent, color: "#fff", border: `1px solid ${C.accent}` };
  const btnStyle = { background: "transparent", border: `1px solid ${C.border}`, color: C.muted, cursor: "pointer", padding: "4px 12px", borderRadius: 3, fontSize: 11, fontFamily: "monospace" };

  return (
    <div>
      {/* Filters */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <input
            placeholder="Search findings…"
            value={filters.search}
            onChange={e => setFilters(p => ({ ...p, search: e.target.value }))}
            style={{ background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: "6px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace", outline: "none", flex: "1 1 200px" }}
          />
          {[
            { key: "severity", opts: ["critical","high","medium","low","info"], label: "Severity" },
            { key: "status",   opts: ["open","acknowledged","resolved"],        label: "Status" },
            { key: "target",   opts: ["llm_api","ai_infra","model_registry","ai_app"], label: "Target" },
          ].map(({ key, opts, label }) => (
            <div key={key} style={{ display: "flex", gap: 4 }}>
              <button style={{ ...btnStyle, ...(filters[key] === "" ? selStyle : {}) }} onClick={() => setFilters(p => ({ ...p, [key]: "" }))}>All</button>
              {opts.map(o => (
                <button key={o} style={{ ...btnStyle, ...(filters[key] === o ? selStyle : {}) }}
                  onClick={() => setFilters(p => ({ ...p, [key]: p[key] === o ? "" : o }))}>
                  {o}
                </button>
              ))}
            </div>
          ))}
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace", marginLeft: "auto" }}>{filtered.length} findings</span>
        </div>
      </Card>

      <Card style={{ padding: 0 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.borderHi}` }}>
              {[
                { label: "ID",        key: "id" },
                { label: "Title",     key: "title" },
                { label: "Target",    key: "target_type" },
                { label: "Severity",  key: "severity" },
                { label: "Score",     key: "score" },
                { label: "Status",    key: "status" },
                { label: "First Seen",key: "first_seen" },
                { label: "Frameworks",key: null },
              ].map(({ label, key }) => (
                <th key={label} onClick={() => key && toggleSort(key)}
                  style={{ textAlign: "left", padding: "10px 14px", fontSize: 10, color: C.muted, fontFamily: "monospace", fontWeight: 400, letterSpacing: "0.08em", textTransform: "uppercase", cursor: key ? "pointer" : "default", userSelect: "none", background: C.elevated }}>
                  {label} {sort.key === key ? (sort.dir === "asc" ? "↑" : "↓") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id}
                style={{ borderBottom: `1px solid ${C.border}`, cursor: "pointer", transition: "background 0.12s" }}
                onMouseEnter={e => e.currentTarget.style.background = C.elevated}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                onClick={() => setSelected(f)}>
                <td style={{ padding: "10px 14px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{f.id}</td>
                <td style={{ padding: "10px 14px", fontSize: 12, color: C.text, maxWidth: 220 }}>{f.title}</td>
                <td style={{ padding: "10px 14px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{f.target_type}</td>
                <td style={{ padding: "10px 14px" }}><SeverityBadge severity={f.severity} /></td>
                <td style={{ padding: "10px 14px", fontFamily: "monospace", fontSize: 12, color: SEVERITY_COLORS[f.severity] }}>{f.score.toFixed(1)}</td>
                <td style={{ padding: "10px 14px" }}><StatusBadge status={f.status} /></td>
                <td style={{ padding: "10px 14px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{new Date(f.first_seen).toLocaleDateString()}</td>
                <td style={{ padding: "10px 14px" }}>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {f.framework_refs.slice(0, 2).map((fw, i) => <FrameworkBadge key={i} fw={fw} />)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} onStatusChange={handleStatusChange} />
    </div>
  );
}

// ── Scan Config screen ─────────────────────────────────────────────────────────

function ScanConfigScreen({ scans, setScans }) {
  const [step, setStep] = useState(1);
  const [targetType, setTargetType] = useState("");
  const [form, setForm] = useState({ name: "", host: "", system_prompt: "" });
  const [selectedPolicies, setSelectedPolicies] = useState(POLICIES.filter(p=>p.enabled).map(p=>p.id));
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState(null);

  const TARGET_TYPES = [
    { id: "llm_api",        icon: "⬡", label: "LLM / GenAI API",      desc: "OpenAI, Anthropic, Azure, Bedrock, Vertex" },
    { id: "ai_infra",       icon: "◈", label: "AI Infrastructure",     desc: "MLflow, Jupyter, SageMaker, GPU clusters" },
    { id: "model_registry", icon: "⬢", label: "Model Registry",        desc: "HuggingFace, MLflow Registry, SageMaker" },
    { id: "ai_app",         icon: "◎", label: "AI-Integrated App",     desc: "RAG pipelines, agents, chatbots, copilots" },
  ];

  const runScan = async () => {
    setScanning(true);
    await new Promise(r => setTimeout(r, 2200));
    const id = `SCN-${String(scans.length + 1).padStart(3, "0")}`;
    const applicable = POLICIES.filter(p => selectedPolicies.includes(p.id) && p.target_types.includes(targetType));
    const newScan = {
      id, target_type: targetType,
      target_meta: { name: form.name || targetType },
      status: "completed", posture_score: Math.floor(40 + Math.random() * 40),
      tier: "at_risk", created_at: new Date().toISOString(),
      finished_at: new Date().toISOString(), findings: applicable.length,
    };
    setScans(prev => [newScan, ...prev]);
    setLastScan(newScan);
    setScanning(false);
    setStep(1); setTargetType(""); setForm({ name: "", host: "", system_prompt: "" });
  };

  return (
    <div style={{ maxWidth: 780 }}>
      {/* Recent scans */}
      <Card style={{ marginBottom: 24 }}>
        <SectionTitle>Recent scans</SectionTitle>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Scan ID", "Target", "Name", "Score", "Status", "Findings", "Started"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", fontSize: 10, color: C.muted, fontFamily: "monospace", fontWeight: 400, letterSpacing: "0.08em", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 7).map(s => (
              <tr key={s.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{s.id}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: C.teal }}>{s.target_type}</td>
                <td style={{ padding: "8px 10px", fontSize: 12, color: C.text }}>{s.target_meta?.name}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 12, color: s.posture_score ? (s.posture_score >= 70 ? C.healthy : s.posture_score >= 40 ? C.at_risk : C.critical) : C.muted }}>{s.posture_score ?? "—"}</td>
                <td style={{ padding: "8px 10px" }}><StatusBadge status={s.status} /></td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: C.text }}>{s.findings}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: C.muted }}>{new Date(s.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {lastScan && (
        <div style={{ background: "#0d2314", border: `1px solid #1a5a28`, borderRadius: 6, padding: "12px 16px", marginBottom: 20, fontFamily: "monospace", fontSize: 12, color: C.healthy }}>
          ✓ Scan {lastScan.id} completed — posture score: {lastScan.posture_score} · {lastScan.findings} checks run
        </div>
      )}

      {/* Wizard */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
          {[1, 2, 3].map(n => (
            <div key={n} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{
                width: 26, height: 26, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                fontFamily: "monospace", fontSize: 11, fontWeight: 700,
                background: step === n ? C.accent : step > n ? C.teal : C.elevated,
                color: step >= n ? "#fff" : C.muted,
                border: `1px solid ${step === n ? C.accent : step > n ? C.teal : C.border}`,
              }}>{step > n ? "✓" : n}</div>
              <span style={{ fontSize: 12, fontFamily: "monospace", color: step === n ? C.text : C.muted }}>
                {["Select target", "Configure", "Select policies"][n - 1]}
              </span>
              {n < 3 && <span style={{ color: C.dim, fontSize: 14 }}>›</span>}
            </div>
          ))}
        </div>

        {step === 1 && (
          <div>
            <div style={{ fontSize: 13, color: C.muted, marginBottom: 16, fontFamily: "monospace" }}>Select target type to scan</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {TARGET_TYPES.map(t => (
                <div key={t.id} onClick={() => { setTargetType(t.id); setStep(2); }}
                  style={{
                    background: targetType === t.id ? C.elevated : "transparent",
                    border: `1px solid ${targetType === t.id ? C.accent : C.border}`,
                    borderRadius: 6, padding: "14px 16px", cursor: "pointer", transition: "all 0.15s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = C.borderHi}
                  onMouseLeave={e => e.currentTarget.style.borderColor = targetType === t.id ? C.accent : C.border}>
                  <div style={{ fontFamily: "monospace", fontSize: 20, marginBottom: 6 }}>{t.icon}</div>
                  <div style={{ fontSize: 13, color: C.text, fontWeight: 600, marginBottom: 4 }}>{t.label}</div>
                  <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>{t.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <div style={{ fontSize: 13, color: C.muted, marginBottom: 16, fontFamily: "monospace" }}>Configure {targetType} target</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {[
                { key: "name", label: "Target name", placeholder: "e.g. prod-openai-gateway" },
                { key: "host", label: "Host / endpoint URL", placeholder: "e.g. https://api.openai.com" },
              ].map(({ key, label, placeholder }) => (
                <div key={key}>
                  <label style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</label>
                  <input value={form[key]} onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
                    placeholder={placeholder}
                    style={{ width: "100%", background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace", outline: "none", boxSizing: "border-box" }} />
                </div>
              ))}
              {targetType === "llm_api" && (
                <div>
                  <label style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>System prompt (leave blank to test for absence)</label>
                  <textarea value={form.system_prompt} onChange={e => setForm(p => ({ ...p, system_prompt: e.target.value }))}
                    rows={4} placeholder="Paste system prompt here…"
                    style={{ width: "100%", background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace", outline: "none", resize: "vertical", boxSizing: "border-box" }} />
                </div>
              )}
              <div style={{ background: "#1a1000", border: `1px solid #3a2a00`, borderRadius: 4, padding: "10px 12px", fontFamily: "monospace", fontSize: 11, color: "#d97706" }}>
                ⚠ API keys and secrets must be set as environment variables — never entered here.
                Use <code style={{ color: C.medium }}>OPENAI_API_KEY</code>, <code style={{ color: C.medium }}>ANTHROPIC_API_KEY</code>, etc.
              </div>
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
              <button onClick={() => setStep(1)} style={{ background: "transparent", border: `1px solid ${C.border}`, color: C.muted, cursor: "pointer", padding: "8px 20px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>← Back</button>
              <button onClick={() => setStep(3)} style={{ background: C.accent, border: "none", color: "#fff", cursor: "pointer", padding: "8px 20px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>Continue →</button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div>
            <div style={{ fontSize: 13, color: C.muted, marginBottom: 16, fontFamily: "monospace" }}>Select policies to run ({selectedPolicies.length} selected)</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
              {POLICIES.filter(p => p.target_types.includes(targetType)).map(p => (
                <div key={p.id} onClick={() => setSelectedPolicies(prev => prev.includes(p.id) ? prev.filter(x => x !== p.id) : [...prev, p.id])}
                  style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", background: selectedPolicies.includes(p.id) ? C.elevated : "transparent", border: `1px solid ${selectedPolicies.includes(p.id) ? C.borderHi : C.border}`, borderRadius: 6, cursor: "pointer", transition: "all 0.12s" }}>
                  <div style={{ width: 16, height: 16, borderRadius: 3, background: selectedPolicies.includes(p.id) ? C.accent : "transparent", border: `1px solid ${selectedPolicies.includes(p.id) ? C.accent : C.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    {selectedPolicies.includes(p.id) && <span style={{ color: "#fff", fontSize: 10 }}>✓</span>}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, color: C.text }}>{p.name}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace", marginTop: 2 }}>{p.id} · {p.framework}</div>
                  </div>
                  <SeverityBadge severity={p.severity} />
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={() => setStep(2)} style={{ background: "transparent", border: `1px solid ${C.border}`, color: C.muted, cursor: "pointer", padding: "8px 20px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>← Back</button>
              <button onClick={runScan} disabled={scanning || selectedPolicies.length === 0}
                style={{ background: scanning ? C.elevated : "#0d2314", border: `1px solid ${scanning ? C.border : "#1a5a28"}`, color: scanning ? C.muted : C.healthy, cursor: scanning ? "not-allowed" : "pointer", padding: "8px 28px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>
                {scanning ? "⟳ Scanning…" : "▶ Run Scan Now"}
              </button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Policy Editor screen ────────────────────────────────────────────────────────

const DEFAULT_POLICY = `id: CUSTOM-001
name: Custom check — example
description: >
  Describe what this check detects and why it matters.
severity: high
target_types: [llm_api]
check_module: checks/custom-001
enabled: true
remediation: |
  1. Step one of the remediation.
  2. Step two.
framework_refs:
  - framework: OWASP_LLM
    id: LLM01
  - framework: NIST_AI_RMF
    function: MEASURE
    category: MS-2.5
tags: [custom, example]
`;

function PolicyEditorScreen({ policies }) {
  const [code, setCode] = useState(DEFAULT_POLICY);
  const [validation, setValidation] = useState(null);

  const validate = () => {
    try {
      const lines = code.split("\n");
      const hasId       = lines.some(l => l.startsWith("id:"));
      const hasSeverity = lines.some(l => l.startsWith("severity:") && ["critical","high","medium","low","info"].some(s => l.includes(s)));
      const hasTargets  = lines.some(l => l.startsWith("target_types:"));
      const hasRefs     = lines.some(l => l.includes("framework_refs:"));
      const errors = [];
      if (!hasId)       errors.push("Missing required field: id");
      if (!hasSeverity) errors.push("Missing or invalid severity (must be critical/high/medium/low/info)");
      if (!hasTargets)  errors.push("Missing required field: target_types");
      if (!hasRefs)     errors.push("Missing required field: framework_refs");
      setValidation(errors.length === 0 ? { ok: true, msg: "Schema valid ✓" } : { ok: false, errors });
    } catch (e) {
      setValidation({ ok: false, errors: [e.message] });
    }
  };

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}>
        <Card style={{ padding: 0 }}>
          <div style={{ borderBottom: `1px solid ${C.border}`, padding: "10px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted, textTransform: "uppercase", letterSpacing: "0.08em" }}>Policy editor · YAML</span>
            <button onClick={validate} style={{ background: C.accent, border: "none", color: "#fff", cursor: "pointer", padding: "5px 14px", borderRadius: 3, fontSize: 11, fontFamily: "monospace" }}>Validate</button>
          </div>
          <textarea value={code} onChange={e => { setCode(e.target.value); setValidation(null); }}
            spellCheck={false}
            style={{ width: "100%", minHeight: 480, background: "transparent", border: "none", color: C.text, padding: "16px 20px", fontSize: 12, fontFamily: "monospace", lineHeight: 1.7, outline: "none", resize: "vertical", boxSizing: "border-box", tabSize: 2 }} />
          {validation && (
            <div style={{ borderTop: `1px solid ${validation.ok ? "#1a5a28" : "#7f2020"}`, padding: "10px 16px", background: validation.ok ? "#0d2314" : "#2d1414" }}>
              {validation.ok
                ? <span style={{ color: C.healthy, fontFamily: "monospace", fontSize: 12 }}>{validation.msg}</span>
                : validation.errors.map((e, i) => <div key={i} style={{ color: C.critical, fontFamily: "monospace", fontSize: 11 }}>✗ {e}</div>)
              }
            </div>
          )}
        </Card>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Card>
            <SectionTitle>Schema reference</SectionTitle>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {[
                { field: "id", type: "string", req: true },
                { field: "name", type: "string", req: true },
                { field: "description", type: "string", req: true },
                { field: "severity", type: "critical|high|medium|low|info", req: true },
                { field: "target_types", type: "array", req: true },
                { field: "check_module", type: "string (path)", req: true },
                { field: "remediation", type: "string (markdown)", req: true },
                { field: "framework_refs", type: "array", req: true },
                { field: "enabled", type: "boolean", req: false },
                { field: "tags", type: "string[]", req: false },
              ].map(({ field, type, req }) => (
                <div key={field} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "monospace", borderBottom: `1px solid ${C.border}`, paddingBottom: 5 }}>
                  <span style={{ color: C.teal }}>{field}</span>
                  <span style={{ color: C.muted, maxWidth: 140, textAlign: "right" }}>{type}</span>
                  <span style={{ color: req ? C.critical : C.dim, width: 40, textAlign: "right" }}>{req ? "req" : "opt"}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <SectionTitle>Active policies ({policies.filter(p=>p.enabled).length})</SectionTitle>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {policies.map(p => (
                <div key={p.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, fontFamily: "monospace" }}>
                  <span style={{ color: p.enabled ? C.text : C.dim }}>{p.id}</span>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: p.enabled ? C.healthy : C.dim }} />
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ── Reports screen ──────────────────────────────────────────────────────────────

function ReportsScreen({ findings, scans }) {
  const [selectedScan, setSelectedScan] = useState(scans[0]?.id || "");
  const [severityFilter, setSeverityFilter] = useState("all");

  const scan = scans.find(s => s.id === selectedScan);
  const reportFindings = findings.filter(f =>
    (!selectedScan || true) &&
    (severityFilter === "all" || f.severity === severityFilter)
  );

  const copy = () => {
    const text = `DoofusAI SPM Security Report\n${"=".repeat(40)}\nGenerated: ${new Date().toISOString()}\nPosture Score: ${scan?.posture_score ?? "N/A"}\n\n${reportFindings.map(f => `[${f.severity.toUpperCase()}] ${f.title}\nResource: ${f.resource}\nID: ${f.policy_id}\n${f.description}\n\nRemediation:\n${f.remediation}\n`).join("\n---\n\n")}`;
    navigator.clipboard.writeText(text);
  };

  return (
    <div>
      <Card style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
          <div>
            <label style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.08em" }}>Scan</label>
            <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
              style={{ background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: "6px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace", outline: "none" }}>
              {scans.filter(s=>s.status==="completed").map(s => <option key={s.id} value={s.id}>{s.id} — {s.target_meta?.name}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.08em" }}>Severity filter</label>
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
              style={{ background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: "6px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace", outline: "none" }}>
              <option value="all">All severities</option>
              {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button onClick={copy} style={{ background: "transparent", border: `1px solid ${C.border}`, color: C.muted, cursor: "pointer", padding: "6px 16px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>⎘ Copy as text</button>
            <button onClick={() => { const d = { scan, findings: reportFindings }; const b = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }); const u = URL.createObjectURL(b); Object.assign(document.createElement("a"), { href: u, download: `doofusai-report-${selectedScan}.json` }).click(); }}
              style={{ background: "#0d2314", border: `1px solid #1a5a28`, color: C.healthy, cursor: "pointer", padding: "6px 16px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>↓ JSON</button>
          </div>
        </div>
      </Card>

      {/* Report preview */}
      <Card style={{ fontFamily: "monospace" }}>
        <div style={{ borderBottom: `1px solid ${C.border}`, paddingBottom: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>DoofusAI Security Posture Management Report</div>
          <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
            <div><span style={{ color: C.muted, fontSize: 11 }}>Generated: </span><span style={{ color: C.text, fontSize: 11 }}>{new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</span></div>
            {scan && <div><span style={{ color: C.muted, fontSize: 11 }}>Scan: </span><span style={{ color: C.text, fontSize: 11 }}>{scan.id} · {scan.target_meta?.name}</span></div>}
            {scan && <div><span style={{ color: C.muted, fontSize: 11 }}>Posture: </span><span style={{ color: scan.posture_score >= 70 ? C.healthy : scan.posture_score >= 40 ? C.at_risk : C.critical, fontSize: 13, fontWeight: 700 }}>{scan.posture_score}</span></div>}
            <div><span style={{ color: C.muted, fontSize: 11 }}>Findings: </span><span style={{ color: C.text, fontSize: 11 }}>{reportFindings.length}</span></div>
          </div>
        </div>

        {reportFindings.map((f, i) => (
          <div key={f.id} style={{ borderBottom: `1px solid ${C.border}`, paddingBottom: 18, marginBottom: 18 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8 }}>
              <span style={{ color: C.muted, fontSize: 11 }}>{String(i + 1).padStart(2, "0")}</span>
              <SeverityBadge severity={f.severity} />
              <span style={{ color: C.text, fontSize: 13 }}>{f.title}</span>
            </div>
            <div style={{ display: "flex", gap: 16, marginBottom: 8, fontSize: 11 }}>
              <span><span style={{ color: C.muted }}>Resource: </span><span style={{ color: C.teal }}>{f.resource}</span></span>
              <span><span style={{ color: C.muted }}>Policy: </span><span style={{ color: C.accent }}>{f.policy_id}</span></span>
              <span><span style={{ color: C.muted }}>Confidence: </span><span style={{ color: C.text }}>{f.confidence}</span></span>
            </div>
            <p style={{ color: C.muted, fontSize: 12, margin: "0 0 8px", lineHeight: 1.6 }}>{f.description}</p>
            <div style={{ color: C.medium, fontSize: 11 }}>
              Remediation: {f.remediation.split("\n")[0]}
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
}

// ── Root App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [findings, setFindings] = useState(MOCK_FINDINGS);
  const [scans, setScans] = useState(MOCK_SCANS);

  const NAV = [
    { id: "dashboard", icon: "▦", label: "Dashboard" },
    { id: "findings",  icon: "⊛", label: "Findings" },
    { id: "scans",     icon: "▷", label: "Scan Config" },
    { id: "policies",  icon: "◧", label: "Policy Editor" },
    { id: "reports",   icon: "⬡", label: "Reports" },
  ];

  const openCount = findings.filter(f => f.status === "open").length;
  const critCount = findings.filter(f => f.severity === "critical" && f.status === "open").length;
  const postureScore = Math.max(0, 100 - findings.filter(f=>f.status!=="resolved").reduce((s,f) => s + f.score * 1.5, 0));

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'DM Mono', 'IBM Plex Mono', 'Fira Code', monospace" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* Top bar */}
      <div style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, padding: "0 24px", display: "flex", alignItems: "center", height: 52, position: "sticky", top: 0, zIndex: 50 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 40 }}>
          <div style={{ width: 28, height: 28, background: "#1a2a50", border: `1px solid ${C.accent}`, borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>⬡</div>
          <span style={{ fontSize: 13, fontWeight: 500, letterSpacing: "0.02em", color: C.text }}>Doofus<span style={{ color: C.accent }}>AI</span> SPM</span>
          <span style={{ fontSize: 9, color: C.muted, letterSpacing: "0.1em", textTransform: "uppercase", borderLeft: `1px solid ${C.border}`, paddingLeft: 10 }}>Security Posture</span>
        </div>

        <nav style={{ display: "flex", gap: 2, flex: 1 }}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => setPage(n.id)}
              style={{ background: page === n.id ? C.elevated : "transparent", border: page === n.id ? `1px solid ${C.border}` : "1px solid transparent", color: page === n.id ? C.text : C.muted, cursor: "pointer", padding: "6px 14px", borderRadius: 4, fontSize: 11, fontFamily: "monospace", letterSpacing: "0.04em", transition: "all 0.12s", display: "flex", alignItems: "center", gap: 6 }}>
              <span>{n.icon}</span>{n.label}
            </button>
          ))}
        </nav>

        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.muted }}><span style={{ color: C.critical, fontWeight: 700 }}>{critCount}</span> critical</div>
          <div style={{ fontSize: 11, color: C.muted }}><span style={{ color: C.text }}>{openCount}</span> open</div>
          <div style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 4, padding: "3px 10px", fontSize: 11, color: postureScore >= 70 ? C.healthy : postureScore >= 40 ? C.at_risk : C.critical }}>
            Score: {Math.round(postureScore)}
          </div>
        </div>
      </div>

      {/* Page header */}
      <div style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, padding: "14px 28px", display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 10, color: C.dim }}>doofusai</span>
        <span style={{ fontSize: 10, color: C.dim }}>›</span>
        <span style={{ fontSize: 10, color: C.muted }}>{NAV.find(n=>n.id===page)?.label}</span>
      </div>

      {/* Content */}
      <div style={{ padding: "24px 28px" }}>
        {page === "dashboard" && <Dashboard findings={findings} scans={scans} />}
        {page === "findings"  && <FindingsScreen findings={findings} setFindings={setFindings} />}
        {page === "scans"     && <ScanConfigScreen scans={scans} setScans={setScans} />}
        {page === "policies"  && <PolicyEditorScreen policies={POLICIES} />}
        {page === "reports"   && <ReportsScreen findings={findings} scans={scans} />}
      </div>
    </div>
  );
}
