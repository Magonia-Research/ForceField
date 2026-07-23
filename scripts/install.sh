#!/bin/bash
set -euo pipefail

# Portcullis Plugin — Post-install Setup
# Creates venv for sigma compiler and compiles initial rules.
# The plugin hooks work without this (bundled rules), but auto-update requires it.

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIGMA_REPO="${SIGMA_REPO:-$HOME/.sigma-rules}"
VENV_DIR="$PLUGIN_ROOT/.venv"

echo "=== Portcullis — Post-Install Setup ==="
echo ""

# 1. Clone or update SigmaHQ rules
if [[ -d "$SIGMA_REPO" ]]; then
    echo "[1/3] Updating sigma rules at $SIGMA_REPO..."
    (cd "$SIGMA_REPO" && git pull origin master --quiet 2>/dev/null) || true
else
    echo "[1/3] Cloning SigmaHQ rules to $SIGMA_REPO..."
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$SIGMA_REPO"
fi

# 2. Create venv with pyyaml (for compiler only)
if [[ ! -f "$VENV_DIR/bin/python3" ]]; then
    echo "[2/3] Creating Python venv for compiler..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet pyyaml
else
    echo "[2/3] Python venv already exists"
fi

# 3. Compile rules
echo "[3/3] Compiling sigma rules (Linux + macOS, medium+ severity)..."
"$VENV_DIR/bin/python3" "$PLUGIN_ROOT/hooks/sigma_compiler.py" \
    --sigma-path "$SIGMA_REPO" \
    --output "$PLUGIN_ROOT/hooks/sigma_rules.json" \
    --products linux,macos \
    --min-level medium

RULE_COUNT=$(python3 -c "import json; print(len(json.load(open('$PLUGIN_ROOT/hooks/sigma_rules.json'))['rules']))" 2>/dev/null || echo "?")

echo ""
echo "=== Setup complete ==="
echo ""
echo "  Rules compiled: $RULE_COUNT detection rules active"
echo "  Auto-update: rules refresh from SigmaHQ on session start (24h cooldown)"
echo ""
echo "  To customize sigma repo location: export SIGMA_REPO=/your/path"
echo "  To recompile manually: $VENV_DIR/bin/python3 $PLUGIN_ROOT/hooks/sigma_compiler.py --help"
