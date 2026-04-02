#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# DoofusAI SPM v3.0 — Uninstall Script
# Author: Shahryar Jahangir / Aniza Corp
#
# Completely removes DoofusAI SPM:
#   - Stops all running processes
#   - Removes Docker images and volumes
#   - Removes node_modules
#   - Optionally removes the database and all scan data
#
# Usage:
#   ./uninstall.sh           # remove app, keep data
#   ./uninstall.sh --purge   # remove everything including scan database
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${CYAN}[doofusai]${RESET} $*"; }
ok()   { echo -e "${GREEN}[doofusai]${RESET} $*"; }
warn() { echo -e "${YELLOW}[doofusai]${RESET} ⚠  $*"; }
err()  { echo -e "${RED}[doofusai]${RESET} ✗  $*" >&2; }
hr()   { echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PURGE=false

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=true ;;
    --help|-h)
      echo ""
      echo "  Usage: ./uninstall.sh [--purge]"
      echo ""
      echo "  (no flags)  Remove app files and Docker resources, keep scan data"
      echo "  --purge     Remove everything including the scan database (irreversible)"
      echo ""
      exit 0 ;;
  esac
done

hr
echo -e "${BOLD}${CYAN}  DoofusAI SPM v3.0 — Uninstall${RESET}"
hr
echo ""

if $PURGE; then
  warn "PURGE MODE — all scan data will be permanently deleted."
else
  log "Standard uninstall — scan data will be preserved in ./data/"
fi
echo ""

# Confirm
read -r -p "$(echo -e "${YELLOW}Are you sure you want to uninstall DoofusAI SPM? [y/N] ${RESET}")" confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  log "Uninstall cancelled."
  exit 0
fi
echo ""

# ── Step 1: Stop everything ───────────────────────────────────────────────────
log "Stopping all DoofusAI SPM processes…"
bash "$SCRIPT_DIR/stop.sh" 2>/dev/null || true

# ── Step 2: Docker cleanup ────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  COMPOSE_CMD=""
  if docker compose version &>/dev/null 2>&1; then COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then COMPOSE_CMD="docker-compose"; fi

  if [[ -n "$COMPOSE_CMD" ]]; then
    log "Removing Docker containers and images…"
    if $PURGE; then
      $COMPOSE_CMD down --rmi all -v 2>/dev/null && ok "Containers, images, and volumes removed." || warn "Docker cleanup had errors (containers may already be removed)."
    else
      $COMPOSE_CMD down --rmi all 2>/dev/null && ok "Containers and images removed (data volume preserved)." || warn "Docker cleanup had errors."
    fi
  fi

  # Remove named images explicitly
  for img in doofusai-spm-api:3.0.0 doofusai-spm-ui:3.0.0; do
    docker rmi "$img" 2>/dev/null && log "Removed image $img" || true
  done
fi

# ── Step 3: node_modules ──────────────────────────────────────────────────────
log "Removing node_modules…"
rm -rf "$SCRIPT_DIR/node_modules"
rm -rf "$SCRIPT_DIR/ui/node_modules"
ok "node_modules removed."

# ── Step 4: Optionally remove data ────────────────────────────────────────────
if $PURGE; then
  log "Removing scan database and all data…"
  rm -rf "$SCRIPT_DIR/data"
  ok "Scan data removed."
else
  warn "Scan data preserved in $SCRIPT_DIR/data/ — delete manually if not needed."
fi

# ── Step 5: Summary ───────────────────────────────────────────────────────────
echo ""
hr
ok "  DoofusAI SPM has been uninstalled."
if ! $PURGE; then
  log "  Scan data is preserved in: $SCRIPT_DIR/data/"
  log "  To also remove scan data, run: ./uninstall.sh --purge"
fi
log "  To remove the project folder itself: cd .. && rm -rf $(basename "$SCRIPT_DIR")"
hr
echo ""
