/**
 * Check Updater — fetches latest framework version info and compares
 * against what is installed, returning an update report.
 */
const https = require('https');
const fs   = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const CURRENT_VERSION = '1.2.0';

const SOURCES = [
  {
    id: 'owasp-llm',
    name: 'OWASP LLM Top 10 (2025)',
    url: 'https://api.github.com/repos/OWASP/www-project-top-10-for-large-language-model-applications/releases/latest',
    parseVersion: d => d.tag_name || 'unknown',
  },
  {
    id: 'mitre-atlas',
    name: 'MITRE ATLAS',
    url: 'https://api.github.com/repos/mitre-atlas/atlas-data/releases/latest',
    parseVersion: d => d.tag_name || 'unknown',
  },
  {
    id: 'checkov',
    name: 'checkov (IaC checks)',
    url: 'https://api.github.com/repos/bridgecrewio/checkov/releases/latest',
    parseVersion: d => d.tag_name || 'unknown',
  },
  {
    id: 'garak',
    name: 'garak (LLM prober)',
    url: 'https://api.github.com/repos/NVIDIA/garak/releases/latest',
    parseVersion: d => d.tag_name || 'unknown',
  },
];

function httpsGet(url, ms = 8000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'DoofusAI-SPM/1.2.0', Accept: 'application/vnd.github.v3+json' }, timeout: ms }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function getInstalledChecks(engineRoot) {
  const dirs = [path.join(engineRoot, 'policy'), path.join(engineRoot, 'custom-policies')];
  const checks = [];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const file of fs.readdirSync(dir).filter(f => f.match(/\.(yaml|yml|json)$/))) {
      try {
        const raw = fs.readFileSync(path.join(dir, file), 'utf8');
        for (const doc of raw.split(/^---\s*$/m).filter(d => d.trim())) {
          const p = yaml.load(doc);
          if (p && p.id) checks.push(p);
        }
      } catch { /* skip */ }
    }
  }
  return checks;
}

function getInstalledModules(engineRoot) {
  const dir = path.join(engineRoot, 'checks');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => {
    const full = path.join(dir, f);
    const stat = fs.statSync(full);
    const content = fs.readFileSync(full, 'utf8');
    const idMatch = content.match(/id:\s*['"`]([^'"`]+)['"`]/);
    const nameMatch = content.match(/name:\s*['"`]([^'"`]+)['"`]/);
    return { file: f, id: idMatch ? idMatch[1] : f.replace('.js',''), name: nameMatch ? nameMatch[1] : f, size: stat.size, mtime: stat.mtime, code: content };
  });
}

async function checkSource(source) {
  try {
    const r = await httpsGet(source.url);
    if (r.status !== 200) return { source: source.name, id: source.id, error: `HTTP ${r.status}`, hasUpdate: false };
    return {
      source: source.name, id: source.id,
      latestVersion: source.parseVersion(r.body),
      publishedAt: r.body.published_at || null,
      releaseNotes: r.body.body ? r.body.body.slice(0, 400) : null,
      hasUpdate: true,
      url: r.body.html_url || source.url,
    };
  } catch (err) {
    return { source: source.name, id: source.id, error: err.message, hasUpdate: false };
  }
}

async function checkForUpdates(engineRoot) {
  const installedChecks = getInstalledChecks(engineRoot);
  const installedModules = getInstalledModules(engineRoot);
  const sourceResults = await Promise.allSettled(SOURCES.map(s => checkSource(s)));
  const sources = sourceResults.map((r, i) =>
    r.status === 'fulfilled' ? r.value : { source: SOURCES[i].name, id: SOURCES[i].id, error: r.reason?.message, hasUpdate: false }
  );
  const frameworkCoverage = {};
  for (const c of installedChecks)
    for (const ref of (c.framework_refs || []))
      frameworkCoverage[ref.framework] = (frameworkCoverage[ref.framework] || 0) + 1;

  return {
    checkedAt: new Date().toISOString(),
    currentVersion: CURRENT_VERSION,
    installedChecks: installedChecks.length,
    installedModules: installedModules.length,
    frameworkCoverage,
    sources,
    checks: installedChecks.map(c => ({
      id: c.id, name: c.name, severity: c.severity,
      enabled: c.enabled !== false, target_types: c.target_types,
      frameworks: (c.framework_refs || []).map(r => `${r.framework}:${r.id || r.function || ''}`),
      tags: c.tags || [], description: c.description,
    })),
    modules: installedModules,
  };
}

module.exports = { checkForUpdates, getInstalledChecks, getInstalledModules, CURRENT_VERSION };
