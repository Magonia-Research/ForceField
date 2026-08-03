#!/bin/bash
set -euo pipefail

# ForceField — posture, log-level and free-text selector
#
# Writes the trusted config at ~/.claude/forcefield.json. That file can only ever
# LOOSEN a guard (hooks/config.py clamps downgrade-only), so nothing here can
# make ForceField block something it would not otherwise block.
#
# Separate from install.sh on purpose: install.sh is optional and sets up exactly
# one guard (sigma_engine, which needs compiled rules). Posture applies to every
# guard and must be settable without cloning SigmaHQ or creating a venv.
#
#   scripts/posture.sh                              show what is configured now
#   scripts/posture.sh --preset passive             never prompt; still block known exploits
#   scripts/posture.sh --log warn                   drop the routine allow record per Bash call
#   scripts/posture.sh --free-text owner            keep command lines out of every shared sink
#   scripts/posture.sh --preset passive --log warn
#   scripts/posture.sh --reset                      back to full strength

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/.claude/forcefield.json"

PRESET=""
LOG_LEVEL=""
FREE_TEXT=""
RESET=false
SHOW_ONLY=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)
      PRESET="${2:-}"
      SHOW_ONLY=false
      shift 2
      ;;
    --preset=*)
      PRESET="${1#*=}"
      SHOW_ONLY=false
      shift
      ;;
    --log)
      LOG_LEVEL="${2:-}"
      SHOW_ONLY=false
      shift 2
      ;;
    --log=*)
      LOG_LEVEL="${1#*=}"
      SHOW_ONLY=false
      shift
      ;;
    --free-text)
      FREE_TEXT="${2:-}"
      SHOW_ONLY=false
      shift 2
      ;;
    --free-text=*)
      FREE_TEXT="${1#*=}"
      SHOW_ONLY=false
      shift
      ;;
    --reset)
      RESET=true
      SHOW_ONLY=false
      shift
      ;;
    -h | --help)
      sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "posture.sh: unknown argument '$1' (try --help)" >&2
      exit 2
      ;;
  esac
done

# config.py owns the vocabulary; reading it here rather than restating it keeps
# the script from drifting out of step with the module it configures.
export FORCEFIELD_HOOKS="$PLUGIN_ROOT/hooks"
export FORCEFIELD_CONFIG="$CONFIG"
export FORCEFIELD_PRESET="$PRESET"
export FORCEFIELD_LOG="$LOG_LEVEL"
export FORCEFIELD_FREE_TEXT="$FREE_TEXT"
export FORCEFIELD_RESET="$RESET"
export FORCEFIELD_SHOW="$SHOW_ONLY"

mkdir -p "$(dirname "$CONFIG")"

python3 <<'PY'
import json
import os
import sys

sys.path.insert(0, os.environ["FORCEFIELD_HOOKS"])
import config  # noqa: E402

path = os.environ["FORCEFIELD_CONFIG"]
preset = os.environ["FORCEFIELD_PRESET"]
log_level = os.environ["FORCEFIELD_LOG"]
free_text = os.environ["FORCEFIELD_FREE_TEXT"]
reset = os.environ["FORCEFIELD_RESET"] == "true"
show_only = os.environ["FORCEFIELD_SHOW"] == "true"

PRESET_HELP = {
    "strict": "prompts on a Sigma match too, and lowers the Sigma severity floor",
    "balanced": "the default; full strength except that a Sigma match warns",
    "permissive": "prompts for everything, blocks nothing",
    "passive": "never prompts; logs and keeps working, but still blocks a known exploit",
}
LOG_HELP = {
    "debug": "everything, plus a record when a silent guard ran and found nothing",
    "info": "the default; every decision including the routine allow per Bash call",
    "warn": "warn / ask / redact / deny only",
    "error": "deny / block only",
}
FREE_TEXT_HELP = {
    "admin": "the default; command lines reach the file sink and the OS log",
    "owner": "command lines reach the 0600 file sink only",
}

try:
    with open(path, encoding="utf-8") as handle:
        current = json.load(handle)
    if not isinstance(current, dict):
        current = {}
except (OSError, json.JSONDecodeError):
    current = {}


def show():
    have = os.path.exists(path)
    print("  config file:    %s%s" % (path, "" if have else "  (none yet)"))
    print("  preset:         %s" % current.get(
        "preset", "%s  (default)" % config.DEFAULT_PRESET))
    print("  log_level:      %s" % current.get(
        "log_level", "%s  (default)" % config.DEFAULT_LOG_LEVEL))
    print("  log_free_text:  %s" % current.get(
        "log_free_text", "%s  (default)" % config.DEFAULT_LOG_FREE_TEXT))
    overrides = current.get("guards")
    if isinstance(overrides, dict) and overrides:
        print("  per-guard:      %s" % ", ".join(sorted(overrides)))
    projects = current.get("projects")
    if isinstance(projects, dict) and projects:
        print("  per-project:    %d entr%s" % (len(projects), "y" if len(projects) == 1 else "ies"))


if show_only:
    print("=== ForceField posture ===")
    print("")
    show()
    print("")
    print("  presets:  %s" % "  ".join(sorted(PRESET_HELP)))
    print("  log:      %s" % "  ".join(config.LOG_LEVELS))
    print("  free-text: %s" % "  ".join(config.LOG_FREE_TEXT_LEVELS))
    print("")
    print("  set with: scripts/posture.sh --preset <name> [--log <level>]"
          " [--free-text <policy>]")
    raise SystemExit(0)

if preset and preset not in config.PRESETS:
    print("posture.sh: unknown preset %r; choose one of: %s"
          % (preset, ", ".join(sorted(config.PRESETS))), file=sys.stderr)
    raise SystemExit(2)
if log_level and log_level not in config.LOG_LEVELS:
    print("posture.sh: unknown log level %r; choose one of: %s"
          % (log_level, ", ".join(config.LOG_LEVELS)), file=sys.stderr)
    raise SystemExit(2)
if free_text and free_text not in config.LOG_FREE_TEXT_LEVELS:
    print("posture.sh: unknown free-text policy %r; choose one of: %s"
          % (free_text, ", ".join(config.LOG_FREE_TEXT_LEVELS)), file=sys.stderr)
    raise SystemExit(2)

if reset:
    # Only the keys this script owns. Per-guard and per-project overrides are
    # hand-written and are not this script's to throw away.
    #
    # `log_verbosity` is popped as well, once. That key was REPLACED by
    # `log_level`, not deprecated -- config.py never reads it again -- so this is
    # a one-time removal of a dead key by a command the operator ran
    # deliberately, not a compatibility path. Leaving it behind would only
    # mislead the next person to read the file.
    current.pop("preset", None)
    current.pop("log_level", None)
    current.pop("log_verbosity", None)
    current.pop("log_free_text", None)
if preset:
    current["preset"] = preset
if log_level:
    current["log_level"] = log_level
if free_text:
    current["log_free_text"] = free_text

if current:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(current, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, 0o600)
elif os.path.exists(path):
    os.remove(path)

print("=== ForceField posture ===")
print("")
show()
print("")
if preset:
    print("  %s: %s" % (preset, PRESET_HELP.get(preset, "")))
if log_level:
    print("  %s: %s" % (log_level, LOG_HELP.get(log_level, "")))
if free_text:
    print("  %s: %s" % (free_text, FREE_TEXT_HELP.get(free_text, "")))
if preset == "passive":
    print("")
    print("  Passive never prompts, so the log is the only place a finding")
    print("  surfaces. Keep log_level at 'info' (the default) and read it:")
    print("    tail -f ~/.claude/hooks/security.log")
print("")
print("  A repo's own .claude/forcefield.json cannot reach these settings:")
print("  it is floored at 'ask' and cannot touch the log level or the")
print("  free-text policy at all.")
PY
