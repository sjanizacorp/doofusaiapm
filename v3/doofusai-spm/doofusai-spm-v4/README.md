# DoofusAI SPM — AI Security Posture Management

**Author:** Shahryar Jahangir &nbsp;·&nbsp; **Company:** Aniza Corp &nbsp;·&nbsp; **Version:** 3.0.0

AI security scanning platform. Assesses LLM APIs, AI infrastructure, model registries,
AI-integrated applications, and CI/CD pipelines against OWASP LLM Top 10 (2025),
MITRE ATLAS v5.4.0, and NIST AI RMF. 25 built-in checks. Dark terminal dashboard.

---

## Quick Start

```bash
./start.sh          # auto-detects Docker or native Node.js
./stop.sh           # stop everything
./uninstall.sh      # remove app (keep data)
./uninstall.sh --purge  # remove everything including scan data
```

### npm aliases

```bash
npm start              # auto-detect start
npm run start:native   # force native Node.js
npm run start:docker   # force Docker
npm run start:build    # Docker + rebuild images
npm run stop           # stop
npm run uninstall      # uninstall (keep data)
npm run uninstall:purge# uninstall (remove all data)
```

---

## Access

| Service   | URL                            |
|-----------|--------------------------------|
| Dashboard | http://localhost:5173          |
| API       | http://localhost:3001          |
| API Docs  | http://localhost:3001/api/docs |

---

## Requirements

**Native:**  Node.js 18+, npm
**Docker:**  Docker Desktop or Docker Engine + Compose v2

No C++ compiler needed — uses sql.js (pure WebAssembly SQLite).

---

## Configuration

```bash
cp .env.example .env   # edit and add your API keys
```

API keys read from environment variables only — never stored in the database.

---

## Optional Tools

```bash
pip install detect-secrets garak llm-guard checkov
```

---

## Scripts

| Script          | What it does                                     |
|-----------------|--------------------------------------------------|
| `./start.sh`    | Auto-detect Docker/native and start the app      |
| `./stop.sh`     | Stop all running processes (Docker + native)     |
| `./uninstall.sh`| Remove app files and Docker resources            |
| `./uninstall.sh --purge` | Remove everything including scan data |

---

## Version History

| Version | Changes |
|---------|---------|
| 3.0.0   | Left sidebar nav, reactive dashboard (scans update live), check family selector in wizard, accurate check counts in update report, About page (Shahryar Jahangir / Aniza Corp), stop.sh, uninstall.sh |
| 1.2.2   | Fixed duplicate `path` require in server.js; fixed JSX syntax error in filter bar |
| 1.2.1   | Docker support, start.sh unified launcher |
| 1.2.0   | Full OWASP LLM Top 10, CI/CD target, ATLAS 2025, Check Registry, update checker |
| 1.1.3   | sql.js async fix, module resolution fix |
| 1.0.0   | Initial release |

---

*© 2026 Aniza Corp. DoofusAI SPM is the intellectual property of Shahryar Jahangir.*
