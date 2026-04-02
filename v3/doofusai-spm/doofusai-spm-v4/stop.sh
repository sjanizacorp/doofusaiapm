#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# DoofusAI SPM v3.0 — Stop Script
# Author: Shahryar Jahangir / Aniza Corp
#
# Stops all running DoofusAI SPM processes (native and/or Docker).
# Usage: ./stop.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${CYAN}[doofusai]${RESET} $*"; }
ok()   { echo -e "${GREEN}[doofusai]${RESET} $*"; }
warn() { echo -e "${YELLOW}[doofusai]${RESET} ⚠  $*"; }
hr()   { echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

hr
echo -e "${BOLD}${CYAN}  DoofusAI SPM v3.0 — Stop${RESET}"
hr
echo ""

STOPPED_ANYTHING=false

# ── Stop Docker containers ────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  COMPOSE_CMD=""
  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  fi

  if [[ -n "$COMPOSE_CMD" ]]; then
    # Check if containers are actually running
    if $COMPOSE_CMD ps --quiet 2>/dev/null | grep -q .; then
      log "Stopping Docker containers…"
      $COMPOSE_CMD down
      ok "Docker containers stopped."
      STOPPED_ANYTHING=true
    else
      log "No Docker containers running."
    fi
  fi
fi

# ── Stop native Node.js processes ─────────────────────────────────────────────
API_PIDS=$(pgrep -f "node.*api/server.js" 2>/dev/null || true)
VITE_PIDS=$(pgrep -f "vite" 2>/dev/null | grep -v "grep" || true)

if [[ -n "$API_PIDS" ]]; then
  log "Stopping API server (PID: $API_PIDS)…"
  echo "$API_PIDS" | xargs kill -SIGTERM 2>/dev/null || true
  sleep 1
  echo "$API_PIDS" | xargs kill -SIGKILL 2>/dev/null || true
  ok "API server stopped."
  STOPPED_ANYTHING=true
fi

if [[ -n "$VITE_PIDS" ]]; then
  log "Stopping Vite UI server (PID: $VITE_PIDS)…"
  echo "$VITE_PIDS" | xargs kill -SIGTERM 2>/dev/null || true
  sleep 1
  ok "Vite UI server stopped."
  STOPPED_ANYTHING=true
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if $STOPPED_ANYTHING; then
  ok "DoofusAI SPM stopped."
else
  warn "Nothing was running."
fi
echo ""
