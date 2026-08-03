#!/bin/bash
set -euo pipefail

# Auto-update sigma rules on session start (max once per 24h)

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
SIGMA_REPO="${SIGMA_REPO:-$HOME/.sigma-rules}"

# The compiler is plugin code and moves with the plugin. The rules and the venv
# are state and deliberately do not: the plugin directory is a cache that every
# reinstall replaces wholesale. See hooks/sigma_engine.py.
COMPILER="$PLUGIN_ROOT/hooks/sigma_compiler.py"
SIGMA_DIR="$HOME/.claude/forcefield/sigma"
RULES_JSON="$SIGMA_DIR/rules.json"
VENV_PYTHON="$SIGMA_DIR/venv/bin/python3"
COOLDOWN_SECONDS=86400

# The SessionStart event, read before anything can consume it. This hook used to
# ignore its stdin entirely, so the one record it writes carried no session.id
# and its TraceId was the no-session sentinel -- 4 of 122 records in a full
# Linux capture, and the only 4 that could not be joined to the session that
# produced them. Read here rather than in the background subshell below, which
# the parent's exit detaches from stdin.
#
# Bounded in BYTES and in TIME, which `head -c 65536` was not. `head` returns at
# N bytes or at EOF and waits indefinitely for whichever comes first, so a
# caller that does not close stdin held this hook to its 10 s hooks.json timeout
# -- measured 0.014 s to 8.003 s and killed. This hook was the last one in the
# plugin that did not depend on the harness closing stdin, and reading the event
# is not worth acquiring that dependency. `select` gives the read a deadline;
# past it the hook proceeds with whatever arrived, which for the cooldown check
# and the rules refresh means everything except the session id.
EVENT=$(python3 -c 'import select, sys, time
chunks, deadline = [], time.monotonic() + 2.0
size = 0
while size < 65536:
    left = deadline - time.monotonic()
    if left <= 0 or not select.select([sys.stdin.buffer], [], [], left)[0]:
        break
    piece = sys.stdin.buffer.read1(65536 - size)
    if not piece:
        break
    chunks.append(piece)
    size += len(piece)
sys.stdout.buffer.write(b"".join(chunks))' 2>/dev/null || true)

# Skip if rules were updated within cooldown period.
#
# GNU coreutils first, BSD second, and the result validated before any
# arithmetic touches it. The old order was `stat -f %m || stat -c %Y`, which is
# BSD-then-GNU and is wrong in a way no exit status catches: GNU stat reads `-f`
# as "display file system status" and `%m` as a FILE operand, so it writes the
# %m error to stderr (swallowed), writes the real file's *filesystem* block to
# STDOUT, and exits 1 -- so the `||` fallback also ran and appended the mtime to
# that blob. `age=$((now - last_modified))` then evaluated the identifier `File`
# and, under `set -euo pipefail`, killed the hook: "line 22: File: unbound
# variable", rc=1, no record, on every Linux session that had a compiled
# ruleset. Measured in python:3.9-slim (GNU coreutils 9.7) and on macOS 26.5.2
# (BSD stat), both directions.
#
# The case guard is the part that makes it safe rather than merely correct: an
# arithmetic expansion of attacker- or platform-shaped text is a shell injection
# primitive as well as a crash, and this hook has no business trusting either
# stat to have printed a number.
if [[ -f "$RULES_JSON" ]]; then
  last_modified=$(stat -c %Y "$RULES_JSON" 2>/dev/null || stat -f %m "$RULES_JSON" 2>/dev/null || echo 0)
  case "$last_modified" in
    '' | *[!0-9]*) last_modified=0 ;;
  esac
  now=$(date +%s)
  age=$((now - last_modified))
  if [[ $age -lt $COOLDOWN_SECONDS ]]; then
    exit 0
  fi
fi

# Skip if repo or compiler or venv missing
[[ -d "$SIGMA_REPO" ]] || exit 0
[[ -f "$COMPILER" ]] || exit 0
[[ -f "$VENV_PYTHON" ]] || exit 0

# Pull latest rules and recompile (background, non-blocking).
#
# **The redirection on the closing paren is what makes "non-blocking" true.**
# `( … ) &` alone detaches the PROCESS and not the DESCRIPTORS: the subshell
# inherits this hook's stdout pipe and keeps the write end open for as long as
# it runs. Claude Code waits for stdout EOF, not for the hook process. Measured
# against the installed binary (claude 2.1.220, hook registered with a 5 s
# timeout): a hook whose parent exits in 1.4 ms but leaves a detached child
# holding stdout produced a 24.9 s turn (`duration_ms=24946`). Measured on this
# subshell specifically: `parent exited at 0.039s rc=0 ; stdout EOF at 30.260s`.
# The body is a SigmaHQ `git pull` plus a full rule compile, neither of which
# has any bound, so the declared 10 s SessionStart timeout bounded nothing.
#
# stdin is closed too (`<&-`), and unlike the stdout half that one has a
# precondition. Measured on bash 3.2.57 (macOS) and 5.2.37 (Debian 13) alike:
# with job control OFF -- which is every non-interactive script, this one
# included -- POSIX already assigns an asynchronous list a stdin with the
# properties of /dev/null, so `( … ) &` does NOT inherit this hook's stdin and
# `<&-` changes nothing. With job control ON (`set -m`, or `bash -m`) it DOES,
# on both bash versions: a write to the hook's stdin after the hook has exited
# is accepted by the still-running child instead of raising EPIPE, so a caller
# writing an event to this hook is held by a descendant it cannot see.
# `<&-` is the belt for that case and is asserted under it in
# `tests/test_portability.py`; the earlier claim that it is simply "the same
# class of hold from the other direction" was never measured and is not true
# without the precondition.
#
# The git command here has to match scripts/install.sh's, and did not. The
# installer clones with `core.hooksPath=/dev/null --no-recurse-submodules`
# precisely because a rules repo is third-party content; this path then updated
# the same repo every 24 hours, unattended, with a bare `git pull` — no
# submodule refusal (CVE-2024-32002 / CVE-2025-48384) and no hooksPath neutering,
# so a `post-merge` hook committed upstream would execute on session start. The
# hardened form was written once and the unattended caller kept the weak one.
#
# SIGMA_REF pins the rules to a reviewed commit or tag. Unset, this tracks
# master as before; set, the repo is fetched and checked out at exactly that ref
# and never advances on its own.
(
  cd "$SIGMA_REPO"
  before=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  if [[ -n "${SIGMA_REF:-}" ]]; then
    git -c core.hooksPath=/dev/null fetch --quiet --no-recurse-submodules \
      origin "$SIGMA_REF" 2>/dev/null || true
    git -c core.hooksPath=/dev/null checkout --quiet --no-recurse-submodules \
      "$SIGMA_REF" 2>/dev/null || true
  else
    git -c core.hooksPath=/dev/null pull --quiet --no-recurse-submodules \
      origin master 2>/dev/null || true
  fi
  after=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

  "$VENV_PYTHON" "$COMPILER" \
    --sigma-path "$SIGMA_REPO" \
    --output "$RULES_JSON" \
    --products linux,macos \
    --min-level medium \
    >/dev/null 2>&1

  # A rule refresh changes what every subsequent Bash call is measured against,
  # and it left no trace at all: this hook was one of the two that never logged,
  # so "which upstream commit was I running?" had no answer after the fact.
  if [[ "$before" != "$after" ]]; then
    # jq is container_first.sh's dependency, not this hook's, and python3 is
    # already required on the next line -- so the id comes out of the event with
    # the interpreter that is about to write the record. One line, single
    # quoted: tests/test_portability.py parses every `python3 -c` program in
    # scripts/ and hooks/ under the 3.9 grammar.
    SESSION_ID=$(printf '%s' "$EVENT" | python3 -c \
      'import json,sys; print(json.load(sys.stdin).get("session_id") or "")' \
      2>/dev/null || true)
    printf '%s' "$SIGMA_REPO" |
      python3 "$PLUGIN_ROOT/hooks/hook_logging.py" \
        --hook sigma_update \
        --decision allow \
        --pattern "rules_advanced:$before->$after" \
        --session-id "$SESSION_ID" \
        --command-stdin >/dev/null 2>&1 || true
  fi
) >/dev/null 2>&1 <&- &

exit 0
