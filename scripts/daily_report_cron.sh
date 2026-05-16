#!/usr/bin/env bash
# Cron-friendly wrapper for /daily-report.
#
# Why this exists: cron starts with a minimal $PATH and does not source any
# shell init files. NVM-managed Node (used by Claude CLI) and the project
# venv are both invisible by default. This script sets them up explicitly.
#
# Usage:
#   ./scripts/daily_report_cron.sh                 # writes to logs/, prints
#   ./scripts/daily_report_cron.sh | post-to-slack # use as part of pipeline
#
# Cron example (8am daily, log retained for 30 days):
#   0 8 * * * /home/hacker/Project/threat_watch/scripts/daily_report_cron.sh \
#       >> /home/hacker/Project/threat_watch/logs/cron.log 2>&1

set -euo pipefail

# --- Project paths (edit if you move the project) ---------------------------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR"

# --- Load Node via NVM (Claude CLI needs Node) ------------------------------
# NVM's nvm.sh defines `nvm use`; without it `node` won't be in PATH under cron.
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
  nvm use --silent default >/dev/null 2>&1 || true
fi

# --- Activate venv (so `python` in the skill resolves to project deps) ------
if [ -f "$VENV_DIR/bin/activate" ]; then
  # shellcheck disable=SC1091
  . "$VENV_DIR/bin/activate"
fi

# --- Resolve claude binary --------------------------------------------------
CLAUDE_BIN="${CLAUDE_BIN:-}"
if [ -z "$CLAUDE_BIN" ]; then
  if command -v claude >/dev/null 2>&1; then
    CLAUDE_BIN="$(command -v claude)"
  elif [ -x "$HOME/.local/bin/claude" ]; then
    CLAUDE_BIN="$HOME/.local/bin/claude"
  else
    echo "[$(date -Is)] ERROR: claude CLI not found in PATH or $HOME/.local/bin" >&2
    exit 127
  fi
fi

# --- Run /daily-report ------------------------------------------------------
cd "$PROJECT_DIR"
STAMP="$(date +%Y-%m-%d)"
OUT_FILE="$LOG_DIR/daily-report-$STAMP.md"

echo "[$(date -Is)] running $CLAUDE_BIN -p '/daily-report' in $PROJECT_DIR"

# --max-budget-usd caps spend per run; tune as you like.
# Tee so both the log file and stdout receive the output (Slack pipe friendly).
"$CLAUDE_BIN" \
  --print \
  --max-budget-usd 2 \
  --dangerously-skip-permissions \
  "/daily-report" \
  | tee "$OUT_FILE"

echo "[$(date -Is)] done. saved to $OUT_FILE"

# --- Optional: post to Slack -----------------------------------------------
# If SLACK_WEBHOOK_URL is set in env (or .env), post the report body.
if [ -n "${SLACK_WEBHOOK_URL:-}" ] && command -v curl >/dev/null 2>&1; then
  # Slack messages have a 40KB limit; truncate aggressively.
  BODY="$(head -c 35000 "$OUT_FILE")"
  PAYLOAD="$(python -c "import json,sys; print(json.dumps({'text': sys.stdin.read()}))" <<< "$BODY")"
  curl -fsS -X POST -H "Content-Type: application/json" \
       -d "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null \
    || echo "[$(date -Is)] WARN: slack post failed" >&2
fi
