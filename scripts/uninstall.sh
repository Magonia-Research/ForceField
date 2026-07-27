#!/bin/bash
set -euo pipefail

# Portcullis Plugin — Cleanup
# Removes venv and compiled artifacts. Does not remove sigma rules repo.
# Hook deregistration is handled by the Claude Code plugin system.

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Portcullis — Cleanup ==="

if [[ -d "$PLUGIN_ROOT/.venv" ]]; then
    echo "Removing Python venv..."
    rm -rf "$PLUGIN_ROOT/.venv"
fi

if [[ -f "$PLUGIN_ROOT/hooks/sigma_rules.json" ]]; then
    echo "Removing compiled rules..."
    rm -f "$PLUGIN_ROOT/hooks/sigma_rules.json"
fi

echo ""
echo "Cleanup complete."
echo "Note: SigmaHQ rules repo at ${SIGMA_REPO:-\$HOME/.sigma-rules} was not removed."
echo "To disable the plugin, remove it from Claude Code settings."
