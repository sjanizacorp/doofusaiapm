/**
 * Scoring Model
 * Each finding → severity weight + confidence multiplier → composite score.
 * Overall posture = 100 − weighted penalty from all open findings.
 */

const SEVERITY_WEIGHTS = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2,
  info: 0,
};

const CONFIDENCE_MULTIPLIERS = {
  confirmed: 1.0,
  probable: 0.75,
  possible: 0.5,
};

/**
 * Score a single finding (0–10 CVSS-style composite).
 */
function scoreFinding(finding) {
  const base = SEVERITY_WEIGHTS[finding.severity] ?? 0;
  const multiplier = CONFIDENCE_MULTIPLIERS[finding.confidence] ?? 0.5;
  return parseFloat((base * multiplier).toFixed(2));
}

/**
 * Compute overall posture score (0–100) from an array of open findings.
 * Uses diminishing-returns capping so a flood of low findings can't
 * push the score below 0.
 */
function computePostureScore(findings) {
  const open = findings.filter(f => f.status === 'open' || f.status === 'acknowledged');
  if (open.length === 0) return 100;

  const totalPenalty = open.reduce((sum, f) => {
    return sum + scoreFinding(f);
  }, 0);

  // Normalise: 100 penalty points = score 0; scale is non-linear
  const raw = Math.max(0, 100 - totalPenalty * 1.5);
  return parseFloat(raw.toFixed(1));
}

/**
 * Map a posture score to a risk tier.
 */
function scoreTier(score) {
  if (score >= 90) return { tier: 'Healthy',           color: '#22c55e', code: 'healthy' };
  if (score >= 70) return { tier: 'Needs Attention',   color: '#f59e0b', code: 'attention' };
  if (score >= 40) return { tier: 'At Risk',           color: '#f97316', code: 'at_risk' };
  return              { tier: 'Critical',              color: '#ef4444', code: 'critical' };
}

module.exports = { scoreFinding, computePostureScore, scoreTier, SEVERITY_WEIGHTS };
