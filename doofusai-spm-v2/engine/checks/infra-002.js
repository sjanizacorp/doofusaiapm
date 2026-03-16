/**
 * Check: INFRA-002 — Unencrypted / World-Readable Model Artefact Storage
 * Target type: ai_infra
 *
 * Checks S3/GCS bucket configs for public ACLs, missing SSE, no versioning.
 * Uses the AWS SDK if credentials are available; otherwise uses config metadata.
 */

const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  const findings = [];

  // ── S3 checks (metadata-based — doesn't require live SDK) ────────────────

  if (target.storage_type === 's3' || target.artifact_bucket) {
    if (target.bucket_public === true || target.acl === 'public-read' || target.acl === 'public-read-write') {
      findings.push({
        id: uuidv4(),
        title: 'Model artefact S3 bucket is publicly readable',
        description: `The S3 bucket "${target.artifact_bucket}" has a public ACL. Training data, model weights, and hyperparameters are exposed to the internet without authentication.`,
        severity: 'critical',
        confidence: 'confirmed',
        resource: target.artifact_bucket,
        evidence: `ACL: ${target.acl || 'public-read'}`,
      });
    }

    if (!target.sse_enabled && !target.encryption) {
      findings.push({
        id: uuidv4(),
        title: 'Model artefact storage not encrypted at rest',
        description: 'Server-side encryption is not enabled on the model artefact bucket. Model weights and training data are stored in plaintext.',
        severity: 'high',
        confidence: 'probable',
        resource: target.artifact_bucket || target.name,
        evidence: 'sse_enabled: false, encryption: null',
      });
    }

    if (!target.versioning_enabled) {
      findings.push({
        id: uuidv4(),
        title: 'No versioning on model artefact storage',
        description: 'Bucket versioning is disabled. Accidental deletion or a supply-chain attack overwriting model weights cannot be rolled back.',
        severity: 'medium',
        confidence: 'probable',
        resource: target.artifact_bucket || target.name,
        evidence: 'versioning_enabled: false',
      });
    }
  }

  // ── Network segmentation ────────────────────────────────────────────────

  if (!target.vpc_isolated && !target.private_network) {
    findings.push({
      id: uuidv4(),
      title: 'AI infrastructure not network-isolated',
      description: 'The AI training or serving infrastructure is not deployed in an isolated VPC or private network segment. Lateral movement from a compromised workload could reach ML endpoints directly.',
      severity: 'high',
      confidence: 'possible',
      resource: target.name,
      evidence: 'vpc_isolated: false, private_network: false',
    });
  }

  return findings;
}

module.exports = { id: 'INFRA-002', name: 'Unencrypted Model Artefact Storage', run };
