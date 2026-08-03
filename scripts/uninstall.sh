#!/bin/bash
set -euo pipefail

# ForceField Plugin — Cleanup
# Removes venv and compiled artifacts. Does not remove sigma rules repo.
# Hook deregistration is handled by the Claude Code plugin system.

SIGMA_DIR="$HOME/.claude/forcefield/sigma"

echo "=== ForceField — Cleanup ==="

if [[ -d "$SIGMA_DIR/venv" ]]; then
  echo "Removing Python venv..."
  rm -rf "$SIGMA_DIR/venv"
fi

if [[ -f "$SIGMA_DIR/rules.json" ]]; then
  echo "Removing compiled rules..."
  rm -f "$SIGMA_DIR/rules.json"
fi

# The parent directory also holds remembered approvals and the subagent spawn
# counters, which are not this script's to delete. Only the sigma subdirectory
# is, and only once it is empty.
rmdir "$SIGMA_DIR" 2>/dev/null || true

echo ""
echo "Cleanup complete."
echo "Note: SigmaHQ rules repo at ${SIGMA_REPO:-\$HOME/.sigma-rules} was not removed."
echo "To disable the plugin, remove it from Claude Code settings."
