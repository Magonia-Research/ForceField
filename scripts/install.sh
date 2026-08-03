#!/bin/bash
set -euo pipefail

# ForceField Plugin — Post-install Setup
#
# Optional. It sets up ONE guard: sigma_engine, which needs compiled rules.
# Every other guard is stdlib-only and works from a fresh checkout with no setup
# at all. The compiled rules are not shipped, so until this script runs
# sigma_engine finds no rule file and silently no-ops by design.
#
# This is the only part of ForceField that installs a dependency (pyyaml, into a
# venv, hash-pinned) or fetches anything from the network.
#
# Both the venv and the compiled rules are written OUTSIDE the plugin directory.
# That directory is a cache the plugin system replaces wholesale on every
# reinstall, which used to take this script's entire output with it. See
# hooks/sigma_engine.py for the second reason: ~/.claude/forcefield/ is covered
# by filesystem_guard and the plugin root is not.

#   ./scripts/install.sh                                  sigma setup only
#   ./scripts/install.sh --posture passive --log warn      ...and pick a posture
#
# The posture flags are a convenience pass-through to scripts/posture.sh, which
# is the real owner and works standalone. Posture applies to every guard, so it
# must not require running this script; this script sets up one guard, so it must
# not be the only way to set a posture.

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

POSTURE_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --posture | --preset)
      POSTURE_ARGS+=(--preset "${2:-}")
      shift 2
      ;;
    --posture=* | --preset=*)
      POSTURE_ARGS+=(--preset "${1#*=}")
      shift
      ;;
    --log)
      POSTURE_ARGS+=(--log "${2:-}")
      shift 2
      ;;
    --log=*)
      POSTURE_ARGS+=(--log "${1#*=}")
      shift
      ;;
    -h | --help)
      sed -n '4,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "install.sh: unknown argument '$1' (try --help)" >&2
      exit 2
      ;;
  esac
done

# Run first, and let a bad value stop the script before it clones anything: a
# typo in --posture should not cost a SigmaHQ clone to find out about.
if [[ ${#POSTURE_ARGS[@]} -gt 0 ]]; then
  "$PLUGIN_ROOT/scripts/posture.sh" "${POSTURE_ARGS[@]}"
  echo ""
fi

SIGMA_REPO="${SIGMA_REPO:-$HOME/.sigma-rules}"
SIGMA_URL="${SIGMA_URL:-https://github.com/SigmaHQ/sigma.git}"
STATE_DIR="$HOME/.claude/forcefield"
SIGMA_DIR="$STATE_DIR/sigma"
VENV_DIR="$SIGMA_DIR/venv"
REQUIREMENTS="$PLUGIN_ROOT/scripts/requirements-sigma.txt"
RULES_JSON="$SIGMA_DIR/rules.json"

echo "=== ForceField — Post-Install Setup ==="
echo ""

# Owner-only, matching the memo store that shares this directory.
mkdir -p "$SIGMA_DIR"
chmod 700 "$STATE_DIR" "$SIGMA_DIR" 2>/dev/null || true

# 1. Clone or update SigmaHQ rules.
#
# These are third-party YAML detection rules from a repo we do not control, so
# every git call against it is deliberately inert: no submodules (the
# CVE-2024-32002 / CVE-2025-48384 hook-execution path git_guard exists to prompt
# on), and core.hooksPath pointed at nothing so a hook has nowhere to run from.
# The resolved commit is printed — an unattended rule update that changes what
# gets flagged should at least be attributable.
#
# BOTH branches need the flag, not just the clone. `pull` runs post-merge and
# post-checkout, so the update path executes hooks that the clone path cannot.
# It is also the branch that runs on every re-install after the first, and the
# arming write need not be in this repo at all: a global core.hooksPath in
# ~/.gitconfig reaches it, and git_guard only *asks* on that key because
# pre-commit legitimately sets it. hooks/sigma_update.sh carries the flag on all
# three of its verbs; this file had it on one of two.
if [[ -d "$SIGMA_REPO" ]]; then
  echo "[1/3] Updating sigma rules at $SIGMA_REPO..."
  # Failure here used to be swallowed with `2>/dev/null || true`, which left
  # stale rules behind and said nothing. Stale rules are a fine outcome; not
  # knowing they are stale is not.
  if ! git -c core.hooksPath=/dev/null -C "$SIGMA_REPO" \
    pull --quiet --no-recurse-submodules origin master; then
    echo "      WARNING: update failed — continuing with the rules already on disk."
    echo "      They may be out of date. Check network access and $SIGMA_REPO."
  fi
else
  echo "[1/3] Cloning SigmaHQ rules to $SIGMA_REPO..."
  git -c core.hooksPath=/dev/null clone --depth 1 --no-recurse-submodules \
    "$SIGMA_URL" "$SIGMA_REPO"
fi
echo "      source: $SIGMA_URL"
echo "      commit: $(git -C "$SIGMA_REPO" rev-parse --short HEAD 2>/dev/null || echo '?')"

# 2. Create venv with pyyaml (for the compiler only).
#
# --require-hashes: pyyaml is the one dependency ForceField installs, and it is
# installed onto the host. An unpinned `pip install pyyaml` trusts whatever the
# index serves at that moment; the hash file pins the version AND every artifact
# it is allowed to be. --only-binary=:all: keeps it from falling back to building
# an sdist, which would run setup.py from the downloaded archive.
#
# An existing venv is reused untouched. If the host python already carries a
# matching pyyaml, `python3 -m venv --system-site-packages "$VENV_DIR"` before
# running this script gets the compiler working with nothing installed at all.
if [[ ! -f "$VENV_DIR/bin/python3" ]]; then
  echo "[2/3] Creating Python venv for the compiler..."
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet --require-hashes --only-binary=:all: \
    --disable-pip-version-check --no-input -r "$REQUIREMENTS"
else
  echo "[2/3] Python venv already exists"
fi

# 3. Compile rules
echo "[3/3] Compiling sigma rules (Linux + macOS, medium+ severity)..."
"$VENV_DIR/bin/python3" "$PLUGIN_ROOT/hooks/sigma_compiler.py" \
  --sigma-path "$SIGMA_REPO" \
  --output "$RULES_JSON" \
  --products linux,macos \
  --min-level medium

# The path goes through argv, not string interpolation into the program text.
# Interpolated, a plugin path containing a quote produced a SyntaxError and the
# rule count silently became "?" — a install path with an apostrophe in it is
# not exotic on macOS.
RULE_COUNT=$(python3 -c \
  'import json,sys; print(len(json.load(open(sys.argv[1]))["rules"]))' \
  "$RULES_JSON" 2>/dev/null || echo "?")

echo ""
echo "=== Setup complete ==="
echo ""
echo "  Rules compiled: $RULE_COUNT detection rules active"
echo "  Auto-update: rules refresh from SigmaHQ on session start (24h cooldown)"
echo "  Location: $SIGMA_DIR (outside the plugin, so reinstalling keeps it)"
echo ""
echo "  To customize sigma repo location: export SIGMA_REPO=/your/path"
echo "  To recompile manually: $VENV_DIR/bin/python3 $PLUGIN_ROOT/hooks/sigma_compiler.py --help"
echo "  To pick a posture or log level: $PLUGIN_ROOT/scripts/posture.sh --help"
