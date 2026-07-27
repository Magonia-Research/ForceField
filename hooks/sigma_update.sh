#!/bin/bash
set -euo pipefail

# Auto-update sigma rules on session start (max once per 24h)

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
RULES_JSON="$PLUGIN_ROOT/hooks/sigma_rules.json"
SIGMA_REPO="${SIGMA_REPO:-$HOME/.sigma-rules}"
COMPILER="$PLUGIN_ROOT/hooks/sigma_compiler.py"
VENV_PYTHON="$PLUGIN_ROOT/.venv/bin/python3"
COOLDOWN_SECONDS=86400

# Skip if rules were updated within cooldown period
if [[ -f "$RULES_JSON" ]]; then
    last_modified=$(stat -f %m "$RULES_JSON" 2>/dev/null || stat -c %Y "$RULES_JSON" 2>/dev/null || echo 0)
    now=$(date +%s)
    age=$(( now - last_modified ))
    if [[ $age -lt $COOLDOWN_SECONDS ]]; then
        exit 0
    fi
fi

# Skip if repo or compiler or venv missing
[[ -d "$SIGMA_REPO" ]] || exit 0
[[ -f "$COMPILER" ]] || exit 0
[[ -f "$VENV_PYTHON" ]] || exit 0

# Pull latest rules and recompile (background, non-blocking)
(
    cd "$SIGMA_REPO"
    git pull origin master --quiet 2>/dev/null || true
    "$VENV_PYTHON" "$COMPILER" \
        --sigma-path "$SIGMA_REPO" \
        --output "$RULES_JSON" \
        --products linux,macos \
        --min-level medium \
        > /dev/null 2>&1
) &

exit 0
