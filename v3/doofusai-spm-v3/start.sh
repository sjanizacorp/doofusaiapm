#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# DoofusAI SPM — Unified Start Script
# Author: Shahryar Jahangir
#
# Usage:
#   ./start.sh                  # auto-detect: Docker if available, else native
#   ./start.sh --native         # force native Node.js mode
#   ./start.sh --docker         # force Docker Compose mode
#   ./start.sh --docker --build # Docker mode, rebuild images first
#   ./start.sh --stop           # stop and remove Docker containers
#   ./start.sh --help           # show this help
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[doofusai]${RESET} $*"; }
ok()   { echo -e "${GREEN}[doofusai]${RESET} $*"; }
warn() { echo -e "${YELLOW}[doofusai]${RESET} ⚠  $*"; }
err()  { echo -e "${RED}[doofusai]${RESET} ✗  $*" >&2; }
hr()   { echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""
DOCKER_BUILD=false
DOCKER_STOP=false

# ── Parse args ─────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --native)  MODE="native"  ;;
    --docker)  MODE="docker"  ;;
    --build)   DOCKER_BUILD=true ;;
    --stop)    DOCKER_STOP=true  ;;
    --help|-h)
      hr
      echo -e "${BOLD}DoofusAI SPM — Start Script${RESET}"
      hr
      echo ""
      echo "  Usage: ./start.sh [options]"
      echo ""
      echo "  Options:"
      echo "    (none)          Auto-detect: Docker if available, else native"
      echo "    --native        Force native Node.js mode"
      echo "    --docker        Force Docker Compose mode"
      echo "    --docker --build  Rebuild Docker images before starting"
      echo "    --stop          Stop and remove Docker containers"
      echo "    --help          Show this message"
      echo ""
      echo "  Native mode requires:  Node.js 18+, npm"
      echo "  Docker mode requires:  Docker Desktop or Docker Engine + Compose v2"
      echo ""
      echo "  URLs (both modes):"
      echo "    Dashboard  →  http://localhost:5173"
      echo "    API        →  http://localhost:3001"
      echo "    API Docs   →  http://localhost:3001/api/docs"
      echo ""
      exit 0
      ;;
    *)
      err "Unknown option: $arg  (run ./start.sh --help)"
      exit 1
      ;;
  esac
done

# ── Banner ─────────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}${CYAN}  DoofusAI SPM v3.1.0 — AI Security Posture Management${RESET}"
echo -e "  Author: Shahryar Jahangir"
hr
echo ""

# ── Stop mode ─────────────────────────────────────────────────────────────────
if $DOCKER_STOP; then
  log "Stopping Docker containers…"
  cd "$SCRIPT_DIR"
  if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    docker compose down && ok "Containers stopped."
  elif command -v docker-compose &>/dev/null; then
    docker-compose down && ok "Containers stopped."
  else
    err "Docker Compose not found."
    exit 1
  fi
  exit 0
fi

# ── Auto-detect mode ───────────────────────────────────────────────────────────
if [[ -z "$MODE" ]]; then
  if command -v docker &>/dev/null && (docker compose version &>/dev/null 2>&1 || command -v docker-compose &>/dev/null); then
    MODE="docker"
    log "Docker detected — using Docker mode. Use --native to override."
  else
    MODE="native"
    log "Docker not detected — using native Node.js mode."
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# NATIVE MODE
# ══════════════════════════════════════════════════════════════════════════════
start_native() {
  log "Starting in native mode…"
  echo ""

  # ── Node.js version check ──────────────────────────────────────────────────
  if ! command -v node &>/dev/null; then
    err "Node.js not found. Install Node.js 18+ from https://nodejs.org"
    exit 1
  fi

  NODE_VERSION=$(node -e "process.stdout.write(process.versions.node)")
  NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
  if (( NODE_MAJOR < 18 )); then
    err "Node.js $NODE_VERSION detected. Version 18+ required."
    exit 1
  fi
  ok "Node.js $NODE_VERSION ✓"

  # ── npm check ─────────────────────────────────────────────────────────────
  if ! command -v npm &>/dev/null; then
    err "npm not found."
    exit 1
  fi
  ok "npm $(npm -v) ✓"

  # ── .env setup ────────────────────────────────────────────────────────────
  cd "$SCRIPT_DIR"
  if [[ ! -f ".env" ]]; then
    if [[ -f ".env.example" ]]; then
      cp .env.example .env
      warn ".env created from .env.example — add your API keys before scanning."
    else
      warn "No .env file found. API keys will not be available."
    fi
  else
    ok ".env found ✓"
  fi

  # ── Install dependencies ───────────────────────────────────────────────────
  if [[ ! -d "node_modules" ]]; then
    log "Installing root dependencies…"
    npm install --silent
  fi

  if [[ ! -d "ui/node_modules" ]]; then
    log "Installing UI dependencies…"
    (cd ui && npm install --silent)
  fi
  ok "Dependencies installed ✓"

  # ── Create data directory ──────────────────────────────────────────────────
  mkdir -p data
  ok "Data directory ready ✓"

  # ── Launch ────────────────────────────────────────────────────────────────
  echo ""
  hr
  ok "  Dashboard  →  http://localhost:5173"
  ok "  API        →  http://localhost:3001"
  ok "  API Docs   →  http://localhost:3001/api/docs"
  hr
  echo ""
  log "Press Ctrl+C to stop."
  echo ""

  npm run dev
}

# ══════════════════════════════════════════════════════════════════════════════
# DOCKER MODE
# ══════════════════════════════════════════════════════════════════════════════
start_docker() {
  log "Starting in Docker mode…"
  echo ""

  # ── Docker check ──────────────────────────────────────────────────────────
  if ! command -v docker &>/dev/null; then
    err "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop"
    exit 1
  fi

  # Check Docker daemon is running
  if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon is not running. Start Docker Desktop and try again."
    exit 1
  fi
  ok "Docker $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ✓"

  # ── Compose command ────────────────────────────────────────────────────────
  COMPOSE_CMD=""
  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  else
    err "Docker Compose not found. Install Docker Desktop (includes Compose v2)."
    exit 1
  fi
  ok "Docker Compose ✓"

  # ── .env setup ────────────────────────────────────────────────────────────
  cd "$SCRIPT_DIR"
  if [[ ! -f ".env" ]]; then
    if [[ -f ".env.example" ]]; then
      cp .env.example .env
      warn ".env created from .env.example — add your API keys before scanning."
    fi
  else
    ok ".env found ✓"
  fi

  # ── Build if requested ─────────────────────────────────────────────────────
  if $DOCKER_BUILD; then
    log "Building Docker images (this may take a few minutes)…"
    $COMPOSE_CMD build --no-cache
    ok "Images built ✓"
  fi

  # ── Launch ────────────────────────────────────────────────────────────────
  echo ""
  log "Starting containers…"
  $COMPOSE_CMD up -d

  # ── Wait for health ────────────────────────────────────────────────────────
  echo ""
  log "Waiting for API to be ready…"
  RETRIES=30
  until curl -sf http://localhost:3001/api/v1/health >/dev/null 2>&1 || (( --RETRIES == 0 )); do
    printf '.'
    sleep 2
  done
  echo ""

  if curl -sf http://localhost:3001/api/v1/health >/dev/null 2>&1; then
    ok "API is healthy ✓"
  else
    warn "API health check timed out — containers may still be starting."
    log "Check logs with: docker compose logs -f"
  fi

  echo ""
  hr
  ok "  Dashboard  →  http://localhost:5173"
  ok "  API        →  http://localhost:3001"
  ok "  API Docs   →  http://localhost:3001/api/docs"
  hr
  echo ""
  log "To view logs:  docker compose logs -f"
  log "To stop:       ./start.sh --stop"
  echo ""
}

# ── Dispatch ───────────────────────────────────────────────────────────────────
case "$MODE" in
  native) start_native ;;
  docker) start_docker ;;
esac
