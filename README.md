# DoofusAI SPM — DoofusAI Security Posture Management

# DISCLAIMER: This software is provided "as is" and without warranty of any kind, express or implied. In no event shall the author be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. Any action you take based on this code is strictly at your own risk.

Production-grade platform for scanning AI/ML infrastructure against OWASP LLM Top 10,
MITRE ATLAS, NIST AI RMF, and custom policies. Dark terminal UI, pluggable check engine,
open-source tool integrations.

## Architecture

```
doofusai-spm/
├── engine/
│   ├── checks/              # Check modules (one file per policy)
│   │   ├── owasp-llm01.js   # Prompt injection
│   │   ├── owasp-llm06.js   # Sensitive info / API key exposure
│   │   ├── infra-001.js     # Unauthenticated ML endpoints
│   │   ├── infra-002.js     # Unencrypted artefact storage
│   │   ├── registry-001.js  # Unsigned artefacts / pickle risk
│   │   ├── registry-002.js  # Missing SBOM / model card issues
│   │   ├── app-001.js       # Excessive agency
│   │   ├── app-002.js       # Insecure RAG / PII leakage
│   │   ├── tool-detect-secrets.js
│   │   ├── tool-garak.js
│   │   ├── tool-llm-guard.js
│   │   └── tool-checkov.js
│   ├── loaders/             # Target connectors (future: live SDK integrations)
│   ├── policy/              # Built-in YAML policies
│   ├── custom-policies/     # Drop custom YAML/JSON here (gitignored)
│   ├── policyLoader.js      # YAML → Zod-validated Policy objects
│   ├── runner.js            # Worker-thread isolated check execution
│   ├── scoring.js           # CVSS-style scoring + posture computation
│   ├── db.js                # SQLite persistence (WAL mode)
│   └── scanner.js           # Top-level scan orchestrator
├── api/
│   └── server.js            # Express REST API + OpenAPI 3.1
├── ui/
│   └── src/
│       ├── App.jsx           # Full React SPA (5 screens)
│       ├── main.jsx
│       └── lib/api.js        # API client with mock fallback
├── data/                    # SQLite database (gitignored)
├── .env.example
└── package.json
```

## Quick start

```bash
# Requires Node.js 18+
# No native compilation — uses sql.js (pure-JS SQLite)
 1. Install all dependencies (run from the doofusai-spm root)
npm install        # installs all server + engine deps at root
cd ui && npm install && cd ..   # installs React/Vite deps
# or just: npm run install:all

# 2. Configure environment
cp .env.example .env
# Edit .env — add any API keys you want to scan against

# 3. Start (API + UI hot-reload)
npm run dev

# API:  http://localhost:3001
# UI:   http://localhost:5173
# Docs: http://localhost:3001/api/docs
```

> **Node 25 / macOS users**: this release uses `sql.js` (pure WebAssembly SQLite)
> instead of `better-sqlite3`, so there is nothing to compile. `npm install` should
> complete without any `node-gyp` or C++ errors regardless of your Xcode or
> Python version.

## Scan targets

| Type | Config key | Description |
|------|-----------|-------------|
| `llm_api` | `system_prompt`, `model_name`, `api_key_env` | OpenAI, Anthropic, Azure, Bedrock |
| `ai_infra` | `host`, `storage_type`, `artifact_bucket`, `sse_enabled` | MLflow, Jupyter, S3, GCS |
| `model_registry` | `artefact_formats`, `signature_verification`, `public` | HuggingFace, MLflow Registry |
| `ai_app` | `tools`, `vector_db`, `pii_filter_enabled`, `human_in_the_loop` | RAG, agents, chatbots |

## Running a scan via API

```bash
curl -X POST http://localhost:3001/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": {
      "type": "llm_api",
      "name": "prod-openai-gateway",
      "model_name": "gpt-4o",
      "api_key_env": "OPENAI_API_KEY"
    }
  }'
```

## Custom policies
Drop a `.yaml` file in `engine/custom-policies/`:

```yaml
id: MY-CUSTOM-001
name: My custom check
description: What this detects.
severity: high
target_types: [llm_api]
check_module: checks/my-custom-check
enabled: true
remediation: |
  1. Step one.
  2. Step two.
framework_refs:
  - framework: OWASP_LLM
    id: LLM01
tags: [custom]
```

Then create `engine/checks/my-custom-check.js`:

```js
const { v4: uuidv4 } = require('uuid');

async function run(target, config) {
  // Return an array of Finding objects
  return [{
    id: uuidv4(),
    title: 'My finding title',
    description: 'What was found.',
    severity: 'high',
    confidence: 'confirmed',
    resource: target.name,
    evidence: 'Supporting detail',
  }];
}

module.exports = { id: 'MY-CUSTOM-001', name: 'My custom check', run };
```

Call `POST /api/v1/policies/reload` to hot-load without restart.

## Open-source tool prerequisites

```bash
pip install detect-secrets garak llm-guard checkov
```

Tools degrade gracefully — if not installed, they emit an `info`-severity finding
explaining the missing dependency rather than crashing.

## REST API
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Start a scan (async, returns scan_id) |
| `GET`  | `/api/v1/scans` | List recent scans |
| `GET`  | `/api/v1/scans/:id` | Poll status + get results |
| `GET`  | `/api/v1/findings` | List findings (filter by severity/status/target) |
| `PATCH`| `/api/v1/findings/:id/status` | Update finding status |
| `GET`  | `/api/v1/reports/:scan_id` | Get posture report (JSON or summary) |
| `GET`  | `/api/v1/policies` | List loaded policies |
| `POST` | `/api/v1/policies/reload` | Hot-reload policies from disk |

Full OpenAPI 3.1 spec: `GET /api/openapi.json`
Interactive docs: `http://localhost:3001/api/docs`

## Security design

- **No secrets in DB** — API keys accepted only via `api_key_env` (env var name), never stored
- **Automatic redaction** — API keys, email addresses, phone numbers redacted before any DB write
- **Worker thread isolation** — each check runs in its own thread with 30s timeout
- **Policy hot-reload** — drop YAML files and reload without restart
- **SQLite WAL mode** — concurrent reads during scan writes
- 
