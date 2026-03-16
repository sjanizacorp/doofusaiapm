/**
 * Check wrapper: detect-secrets
 * https://github.com/Yelp/detect-secrets
 *
 * Scans a directory or file for exposed secrets/credentials.
 * Requires: pip install detect-secrets
 *
 * Target config expected:
 *   target.scan_path  — absolute path to scan (repo root, config dir, etc.)
 *   target.exclude    — array of glob patterns to exclude (optional)
 */

const { execFile } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const SEVERITY_MAP = {
  HexHighEntropyString:    'high',
  Base64HighEntropyString: 'high',
  AWSKeyDetector:          'critical',
  ArtifactoryDetector:     'high',
  AzureStorageKeyDetector: 'critical',
  BasicAuthDetector:       'high',
  CloudantDetector:        'high',
  DiscordBotTokenDetector: 'medium',
  GitHubTokenDetector:     'critical',
  GoogleCloudKeyDetector:  'critical',
  HubSpotDetector:         'medium',
  JwtTokenDetector:        'high',
  KeywordDetector:         'medium',
  MailchimpDetector:       'medium',
  NpmDetector:             'high',
  SendGridDetector:        'medium',
  SlackDetector:           'high',
  SoftlayerDetector:       'medium',
  StripeDetector:          'critical',
  TwilioKeyDetector:       'high',
};

function runDetectSecrets(scanPath, excludePatterns = []) {
  return new Promise((resolve, reject) => {
    const args = ['scan', '--json', scanPath];
    for (const p of excludePatterns) {
      args.push('--exclude-files', p);
    }

    execFile('detect-secrets', args, { timeout: 25_000, maxBuffer: 5_1200 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        // detect-secrets returns non-zero when secrets found — that's ok
        if (err.code !== 1) return reject(new Error(`detect-secrets failed: ${stderr || err.message}`));
      }
      try {
        resolve(JSON.parse(stdout || '{}'));
      } catch {
        reject(new Error('Failed to parse detect-secrets output'));
      }
    });
  });
}

async function run(target, config) {
  const findings = [];
  const scanPath = target.scan_path;

  if (!scanPath) {
    return [{
      id: uuidv4(),
      title: 'detect-secrets: no scan_path configured',
      description: 'The scan_path field is required for detect-secrets to run.',
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  if (!fs.existsSync(scanPath)) {
    return [{
      id: uuidv4(),
      title: `detect-secrets: scan path does not exist (${scanPath})`,
      description: 'The configured scan_path does not exist on this system.',
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  let result;
  try {
    result = await runDetectSecrets(scanPath, target.exclude || []);
  } catch (err) {
    // Tool not installed — surface as info finding
    return [{
      id: uuidv4(),
      title: 'detect-secrets not installed',
      description: `Could not run detect-secrets: ${err.message}. Install with: pip install detect-secrets`,
      severity: 'info',
      confidence: 'confirmed',
      resource: target.name,
    }];
  }

  const secretResults = result.results || {};
  for (const [filePath, secrets] of Object.entries(secretResults)) {
    for (const secret of secrets) {
      const severity = SEVERITY_MAP[secret.type] || 'medium';
      findings.push({
        id: uuidv4(),
        title: `Exposed secret: ${secret.type}`,
        description: `detect-secrets found a potential ${secret.type} in ${path.relative(scanPath, filePath)} at line ${secret.line_number}. Secrets in source files or config can be exfiltrated by any attacker with repo read access.`,
        severity,
        confidence: secret.is_verified ? 'confirmed' : 'probable',
        resource: `${path.relative(scanPath, filePath)}:${secret.line_number}`,
        evidence: `Type: ${secret.type}, File: ${filePath}, Line: ${secret.line_number}`,
      });
    }
  }

  return findings;
}

module.exports = { id: 'TOOL-DETECT-SECRETS', name: 'detect-secrets credential scan', run };
