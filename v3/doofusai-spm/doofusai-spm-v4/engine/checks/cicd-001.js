/**
 * CICD-001 — CI/CD Pipeline Security for AI/ML
 * Covers: secrets in CI config, pinned actions, SLSA, model signing gates,
 * branch protection, artifact signing, privileged runners
 *
 * Target type: cicd_pipeline
 * Config expected:
 *   target.repo_path         — local path to .github/workflows or CI config
 *   target.ci_platform       — 'github_actions' | 'gitlab_ci' | 'jenkins' | 'circleci'
 *   target.branch_protection — bool
 *   target.pinned_actions    — bool
 *   target.slsa_level        — 0..3 (0 = none)
 *   target.secret_scanning   — bool
 *   target.privileged_runner — bool
 *   target.model_signing_gate— bool
 *   target.dependency_review — bool
 *   target.code_review_required — bool
 */
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const ACTION_VERSION_RE = /uses:\s+[A-Za-z0-9_\-./]+@(?![\da-f]{40})[^\s#]+/g;

async function run(target, config) {
  const findings = [];

  // ── Static metadata checks ──────────────────────────────────────────────

  if (!target.branch_protection) {
    findings.push({ id: uuidv4(), title: 'No branch protection on main/production branch', description: 'Branch protection rules are not enforced. Anyone with write access can push directly to the production branch, bypassing CI security gates and potentially deploying untested or malicious model code.', severity: 'critical', confidence: 'confirmed', resource: target.name, evidence: 'branch_protection: false' });
  }

  if (!target.code_review_required) {
    findings.push({ id: uuidv4(), title: 'Code review not required before merge', description: 'Pull request approvals are not required. Training code, model configs, and pipeline definitions can be merged without peer review, enabling insider threats and accidental misconfigurations.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'code_review_required: false' });
  }

  if (!target.secret_scanning) {
    findings.push({ id: uuidv4(), title: 'Secret scanning not enabled on repository', description: 'Automated secret scanning is not enabled. API keys, credentials, and tokens committed to the repository will not be detected and revoked automatically.', severity: 'critical', confidence: 'confirmed', resource: target.name, evidence: 'secret_scanning: false' });
  }

  if (target.privileged_runner) {
    findings.push({ id: uuidv4(), title: 'CI runner executes with elevated privileges', description: 'The CI/CD runner has privileged access (root, docker socket, AWS admin credentials). A compromised pipeline job — e.g. via a malicious dependency — could exfiltrate secrets, modify production models, or pivot to cloud infrastructure.', severity: 'critical', confidence: 'confirmed', resource: target.name, evidence: 'privileged_runner: true' });
  }

  if (!target.pinned_actions && target.ci_platform === 'github_actions') {
    findings.push({ id: uuidv4(), title: 'GitHub Actions not pinned to full commit SHA', description: 'Actions reference mutable tags (e.g. @v3) rather than immutable commit SHAs. A compromised action maintainer can push malicious code under an existing tag, which will execute in your CI pipeline on next run.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'pinned_actions: false, ci_platform: github_actions' });
  }

  if (!target.dependency_review) {
    findings.push({ id: uuidv4(), title: 'No dependency review / SBOM check in pipeline', description: 'The CI pipeline does not run dependency review or generate an SBOM. Vulnerable or malicious ML library versions can be introduced without detection.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'dependency_review: false' });
  }

  if (!target.model_signing_gate) {
    findings.push({ id: uuidv4(), title: 'No model signing gate in deployment pipeline', description: 'The CD pipeline does not require model artefacts to be signed before deployment. An unsigned model could have been modified after training without any audit trail.', severity: 'high', confidence: 'probable', resource: target.name, evidence: 'model_signing_gate: false' });
  }

  const slsaLevel = target.slsa_level || 0;
  if (slsaLevel < 2) {
    findings.push({ id: uuidv4(), title: `SLSA supply chain integrity level too low (level ${slsaLevel})`, description: `The pipeline achieves SLSA level ${slsaLevel}. SLSA level 2 is the minimum recommended for production AI pipelines — it requires a hosted build service and provenance generation. Current level cannot guarantee the model deployed matches the code reviewed.`, severity: slsaLevel === 0 ? 'high' : 'medium', confidence: 'probable', resource: target.name, evidence: `slsa_level: ${slsaLevel}` });
  }

  // ── File-based checks (if repo_path provided) ───────────────────────────
  const repoPath = target.repo_path;
  if (repoPath && fs.existsSync(repoPath)) {
    const workflowDir = path.join(repoPath, '.github', 'workflows');
    if (fs.existsSync(workflowDir)) {
      const files = fs.readdirSync(workflowDir).filter(f => f.match(/\.(yml|yaml)$/));
      for (const file of files) {
        const content = fs.readFileSync(path.join(workflowDir, file), 'utf8');

        // Detect unpinned actions
        const unpinned = content.match(ACTION_VERSION_RE) || [];
        if (unpinned.length > 0) {
          findings.push({ id: uuidv4(), title: `Unpinned GitHub Actions in ${file}`, description: `${unpinned.length} action(s) use mutable version tags rather than commit SHAs in ${file}. Each is a potential supply chain attack vector.`, severity: 'high', confidence: 'confirmed', resource: `${target.name}/${file}`, evidence: unpinned.slice(0, 3).join(', ') });
        }

        // Detect hardcoded secrets patterns
        if (/password\s*[:=]\s*['"][^'"]{6,}['"]/i.test(content) || /api[_-]?key\s*[:=]\s*['"][^'"]{10,}['"]/i.test(content)) {
          findings.push({ id: uuidv4(), title: `Possible hardcoded secret in ${file}`, description: `The workflow file ${file} contains what appears to be a hardcoded password or API key. CI files are version-controlled and widely accessible — secrets must use encrypted secrets ({{ secrets.MY_SECRET }}).`, severity: 'critical', confidence: 'probable', resource: `${target.name}/${file}`, evidence: 'Credential pattern matched in workflow YAML' });
        }

        // Detect pull_request_target without explicit checkout ref guard
        if (content.includes('pull_request_target') && !content.includes('github.event.pull_request.head.sha')) {
          findings.push({ id: uuidv4(), title: `Dangerous pull_request_target trigger in ${file}`, description: `${file} uses pull_request_target which has write access to secrets and can be triggered by fork PRs. Without pinning the checkout to the base branch, this enables a malicious fork to exfiltrate secrets.`, severity: 'critical', confidence: 'confirmed', resource: `${target.name}/${file}`, evidence: 'pull_request_target trigger without sha-pinned checkout' });
        }
      }
    }
  }

  return findings;
}
module.exports = { id: 'CICD-001', name: 'CI/CD Pipeline Security', run };
