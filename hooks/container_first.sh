#!/usr/bin/env bash
set -euo pipefail

# Container-First Enforcement Hook
# Fires before Bash tool calls. Blocks rm -rf and reminds
# when a command should run in a Podman container.

# Fail-open: any unexpected error exits 0 (allow) rather than blocking
trap 'exit 0' ERR

CMD=$(head -c 1048576 | jq -r '.tool_input.command')

# -----------------------------------------------------------
# Logging helper (fire-and-forget)
# -----------------------------------------------------------

log_event() {
    local decision="$1" pattern="$2"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local json="{\"ts\":\"$ts\",\"hook\":\"container_first\",\"decision\":\"$decision\",\"pattern\":\"$pattern\",\"command\":$(printf '%s' "$CMD" | jq -Rs .)}"

    if [[ "$(uname)" == "Darwin" ]]; then
        /usr/bin/log emit --subsystem com.anthropic.claude-code.hooks --category security --type default --public "$json" 2>/dev/null || true
    fi
    logger -t cc-security -p auth.warning "$json" 2>/dev/null || true
    echo "$json" >> ~/.claude/hooks/security.log 2>/dev/null || true
}

# -----------------------------------------------------------
# Block: rm with recursive + force flags
# -----------------------------------------------------------

if echo "$CMD" | grep -qiE '(^|;[[:space:]]*|&&[[:space:]]*|[|][|][[:space:]]*|[|][[:space:]]*)rm[[:space:]]' \
  && echo "$CMD" | grep -qiE '(^|[[:space:]])-[a-zA-Z]*[rR]|--recursive' \
  && echo "$CMD" | grep -qiE '(^|[[:space:]])-[a-zA-Z]*[fF]|--force'; then
  log_event "deny" "rm_rf"
  echo 'BLOCKED: Use trash instead of rm -rf' >&2
  exit 2
fi

# -----------------------------------------------------------
# Block: Obfuscation (hex/octal escape sequences, parameter
# expansion tricks). Checked BEFORE allowlist to catch evasion.
# -----------------------------------------------------------

if echo "$CMD" | grep -qE '(\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\$\{[^}]*#|\$\{[^}]*%%)'; then
  log_event "deny" "obfuscation"
  echo 'BLOCKED: Obfuscated command detected (hex/octal escapes or parameter expansion tricks).' >&2
  echo 'If this is legitimate, write it in plain text.' >&2
  exit 2
fi

# -----------------------------------------------------------
# Block: Container escape techniques (never legitimate in dev)
# -----------------------------------------------------------

if echo "$CMD" | grep -qE '(nsenter\s+|unshare\s+.*--mount|ptrace)'; then
  log_event "deny" "container_escape"
  echo 'BLOCKED: Container escape technique detected (nsenter/unshare/ptrace).' >&2
  echo 'These tools break container isolation and have no legitimate dev use.' >&2
  exit 2
fi

# -----------------------------------------------------------
# Ask: Over-privileged container flags
# -----------------------------------------------------------

if echo "$CMD" | grep -qE '(--privileged|--pid=host|--net=host|-v\s+/:/|mount\s+.*-o\s+.*bind)'; then
  log_event "ask" "container_overprivileged"
  REASON='CONTAINER-FIRST: Over-privileged container detected.\n\nBest practices:\n- Use --cap-add=<SPECIFIC_CAP> instead of --privileged\n- Use --network=<name> instead of --net=host\n- Mount specific paths read-only (-v /path:/path:ro) instead of mounting /\n- For nested containers, use --device /dev/fuse instead of --privileged\n\nIf this is genuinely required (e.g., CI runner, GPU access), approve to proceed.'
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}' "$REASON"
  exit 0
fi

# -----------------------------------------------------------
# Block: Kernel/system manipulation
# -----------------------------------------------------------

if echo "$CMD" | grep -qE '(insmod|modprobe|sysctl\s+-w|echo.*>\s*/proc/|echo.*>\s*/sys/)'; then
  log_event "deny" "kernel_manipulation"
  echo 'BLOCKED: Kernel/system manipulation detected.' >&2
  echo 'Loading modules or writing to /proc and /sys is not permitted.' >&2
  exit 2
fi

# -----------------------------------------------------------
# Compound command gate: if the command contains chaining
# operators, skip the allowlist (compound commands must go
# through all detection checks below).
# -----------------------------------------------------------

IS_COMPOUND=false
if echo "$CMD" | grep -qE '(;|&&|\|\||[|])'; then
  IS_COMPOUND=true
fi

# -----------------------------------------------------------
# Allowlist: commands that legitimately run on the host.
# These exit silently (no reminder).
# Only applies to simple (non-compound) commands.
# -----------------------------------------------------------

if [[ "$IS_COMPOUND" == "false" ]]; then
  # Git, file operations, clipboard, Finder
  if echo "$CMD" | grep -qE \
    '^\s*(git |ls |pwd|cd |mkdir |mv |cp |trash |open |pbcopy|pbpaste|wc |stat |file |diff |chmod |test )'; then
    log_event "allow" "allowlist_fileops"
    exit 0
  fi

  # Container runtimes themselves
  if echo "$CMD" | grep -qE '^\s*(podman |docker )'; then
    log_event "allow" "allowlist_container"
    exit 0
  fi

  # Host-installed dev tools (already vetted, part of toolchain)
  if echo "$CMD" | grep -qE \
    '^\s*(rg |fd |ast-grep |shellcheck |shfmt |actionlint |zizmor |prek |wt |gh |jq |yq )'; then
    log_event "allow" "allowlist_devtools"
    exit 0
  fi

  # Host-installed language toolchain (isolation-aware by design)
  if echo "$CMD" | grep -qE \
    '^\s*(uv |ruff |ty |pipx |npx |oxlint |oxfmt |tsc |cargo clippy|cargo fmt|cargo test|cargo deny|cargo careful)'; then
    log_event "allow" "allowlist_toolchain"
    exit 0
  fi

  # Simple info commands
  if echo "$CMD" | grep -qE \
    '^\s*(echo |printf |which |type |command |cat |head |tail |env |export |source |true|false|:)'; then
    log_event "allow" "allowlist_info"
    exit 0
  fi
fi

# -----------------------------------------------------------
# Detect: package managers installing to host
# These get a STRONG reminder via "ask" (user must confirm).
# -----------------------------------------------------------

INSTALL_PATTERN='(pip3?\s+install|python3?\s+-m\s+pip\s+install|npm\s+install|pnpm\s+(add|install)|yarn\s+add|gem\s+install|cargo\s+install|brew\s+install|apt-get\s+install|conda\s+install)'

if echo "$CMD" | grep -qiE "$INSTALL_PATTERN"; then
  log_event "ask" "host_pkg_install"
  REASON='CONTAINER-FIRST: Package install detected on host OS.\n\n- Python: podman run --rm -v ./data:/data:ro python:3.13-slim sh -c "pip install PKG && python /data/script.py"\n- Node: podman run --rm -v ./src:/src:ro node:22-slim npx <tool>\n- System: podman run --rm <image> instead of brew/apt-get\n- Rust: cargo install goes to ~/.cargo/bin — clean up after\n\nIf this install is necessary on the host, approve to proceed.'
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}' "$REASON"
  exit 0
fi

# -----------------------------------------------------------
# Detect: interpreters / build tools that could be
# containerized. Lighter reminder via additionalContext.
# -----------------------------------------------------------

INTERP_PATTERN='(^|\s|;|&&|\|\||\|)\s*(python3?|node|ruby|perl|java|javac|go\s+run|go\s+build|make|cmake|gcc|g\+\+|clang)\s'

if echo "$CMD" | grep -qiE "$INTERP_PATTERN"; then
  log_event "allow" "host_interpreter"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"CONTAINER-FIRST: This runs an interpreter/build tool on the host. Consider: podman run --rm -v ./<dir>:/<dir>:ro <image> <command>. Host execution OK if: needs hardware access, writes to project dir, or is a quick one-liner with no deps."}}'
  exit 0
fi

# -----------------------------------------------------------
# Default: allow, no reminder needed
# -----------------------------------------------------------
log_event "allow" "default"
exit 0
