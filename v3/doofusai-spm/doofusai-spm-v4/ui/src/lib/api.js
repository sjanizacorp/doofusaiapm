/**
 * API client — all fetch calls to the DoofusAI SPM backend.
 * Falls back to mock data when VITE_API_URL is not set (dev/demo mode).
 */

const BASE = import.meta.env.VITE_API_URL || null;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function request(method, path, body) {
  if (!BASE) throw new ApiError(0, 'NO_BACKEND');

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, err.error || res.statusText);
  }

  return res.json();
}

// ── Scans ─────────────────────────────────────────────────────────────────────

export async function startScan(target, opts = {}) {
  return request('POST', '/api/v1/scans', { target, ...opts });
}

export async function listScans(limit = 20) {
  return request('GET', `/api/v1/scans?limit=${limit}`);
}

export async function getScan(id) {
  return request('GET', `/api/v1/scans/${id}`);
}

// ── Findings ──────────────────────────────────────────────────────────────────

export async function listFindings({ scanId, severity, status, targetType, limit } = {}) {
  const params = new URLSearchParams();
  if (scanId)     params.set('scan_id', scanId);
  if (severity)   params.set('severity', severity);
  if (status)     params.set('status', status);
  if (targetType) params.set('target_type', targetType);
  if (limit)      params.set('limit', limit);
  return request('GET', `/api/v1/findings?${params}`);
}

export async function updateFindingStatus(id, status) {
  return request('PATCH', `/api/v1/findings/${id}/status`, { status });
}

// ── Reports ───────────────────────────────────────────────────────────────────

export async function getReport(scanId, { format, severity } = {}) {
  const params = new URLSearchParams();
  if (format)   params.set('format', format);
  if (severity) params.set('severity', severity);
  return request('GET', `/api/v1/reports/${scanId}?${params}`);
}

// ── Policies ──────────────────────────────────────────────────────────────────

export async function listPolicies() {
  return request('GET', '/api/v1/policies');
}

export async function reloadPolicies() {
  return request('POST', '/api/v1/policies/reload');
}

// ── Poll helper ───────────────────────────────────────────────────────────────

/**
 * Poll a scan until it leaves 'running'/'pending' state.
 * @param {string} scanId
 * @param {function} onUpdate  Called with latest scan data each poll
 * @param {number}   interval  Poll interval in ms (default 2000)
 * @returns {Promise<scan>}
 */
export async function pollScan(scanId, onUpdate, interval = 2000) {
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const data = await getScan(scanId);
        onUpdate(data.scan);
        if (data.scan.status === 'completed' || data.scan.status === 'failed') {
          resolve(data);
        } else {
          setTimeout(tick, interval);
        }
      } catch (err) {
        reject(err);
      }
    };
    tick();
  });
}
