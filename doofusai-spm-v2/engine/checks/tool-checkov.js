/**
 * Check wrapper: checkov
 * https://github.com/bridgecrewio/checkov
 *
 * Scans IaC files (Terraform, CloudFormation, Kubernetes) for AI/ML
 * infrastructure misconfigurations covering SageMaker, GCP AI, Azure ML.
 *
 * Requires: pip install checkov
 *
 * Target config expected:
 *   target.iac_path      — path to IaC directory or file
 *   target.framework     — 'terraform', 'cloudformation', 'kubernetes', 'all'
 *   target.check_ids     — array of specific check IDs (optional)
 */

const { execFile } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

// AI/ML-relevant checkov check IDs
const ML_RELEVANT_CHECKS = [
  'CKV_AWS_80',   // SageMaker notebook not internet-accessible
  'CKV_AWS_122',  // SageMaker endpoint encryption
  'CKV_AWS_123',  // SageMaker training job VPC
  'CKV_GCP_43',   // GCP AI Platform notebook not public
  'CKV_AZURE_33', // Azure ML workspace encryption
  'CKV_AWS_21',   // S3 versioning enabled (model artefacts)
  'CKV_AWS_19',   // S3 SSE enabled
  'CKV2_AWS_6',   // S3 public access blocked
  'CKV_AWS_53',   // S3 bucket has logging
];

const SEVERITY_MAP = {
  HIGH:   'critical',
  MEDIUM: 'high',
  LOW:    'medium',
};

function runCheckov(iacPath, framework, checkIds) {
  return new Promise((resolve, reject) => {
    const args = [
      '--directory', iacPath,
      '--framework', framework || 'all',
      '--output', 'json',
      '--quiet',
    ];

    if (checkIds?.length) {
      args.push('--check', checkIds.join(','));
    } else {
      args.push('--check', ML_RELEVANT_CHECKS.join(','));
    }

    execFile('checkov', args, { timeout: 25_000, maxBuffer: 10_485_760 }, (err, stdout, stderr) => {
      // checkov exits 1 when checks fail — that's expected
      if (err && !stdout) {
        return reject(new Error(`checkov failed: ${stderr?.slice(0, 300) || err.message}`));
      }
      try {
        const raw = stdout.trim();
        // checkov may output multiple JSON objects — take the last valid one
        const jsonStart = raw.lastIndexOf('{');
        resolve(JSON.parse(jsonStart >= 0 ? raw.slice(jsonStart) : raw || '{}'));
      } catch {
        resolve({});
      }
    });
  });
}

async function run(target, config) {
  const findings = [];
  const iacPath = target.iac_path;

  if (!iacPath || !fs.existsSync(iacPath)) {
    return [{
      id: uuidv4(),
      title: 'checkov: iac_path not configured or does not exist',
      description: 'Set target.iac_path to the directory containing your IaC files (Terraform/CF/K8s).',
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  let result;
  try {
    result = await runCheckov(iacPath, target.framework || 'all', target.check_ids);
  } catch (err) {
    return [{
      id: uuidv4(),
      title: 'checkov not installed or scan failed',
      description: `Could not run checkov: ${err.message}. Install with: pip install checkov`,
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  // Handle both single-framework and multi-framework output shapes
  const results = result.results || result;
  const failedChecks = results?.failed_checks || [];

  for (const check of failedChecks) {
    const severity = SEVERITY_MAP[check.check?.severity] || 'medium';
    findings.push({
      id: uuidv4(),
      title: `IaC misconfiguration: ${check.check?.name || check.check_id}`,
      description: `Checkov check ${check.check_id} failed on ${path.relative(iacPath, check.file_path)}. ${check.check?.description || ''}`.trim(),
      severity,
      confidence: 'confirmed',
      resource: `${path.relative(iacPath, check.file_path)}:${check.file_line_range?.join('-') || '?'}`,
      evidence: `Check ID: ${check.check_id}, Resource: ${check.resource}, File: ${check.file_path}`,
    });
  }

  return findings;
}

module.exports = { id: 'TOOL-CHECKOV', name: 'checkov IaC misconfiguration scan', run };
