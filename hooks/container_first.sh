#!/usr/bin/env bash
set -euo pipefail

# Container-First Enforcement Hook
# Fires before Bash tool calls. Blocks rm -rf and reminds
# when a command should run in a Podman container.

# Fail-open: any unexpected error exits 0 (allow) rather than blocking
trap 'exit 0' ERR

# Record a decision taken BEFORE the payload has been parsed. It cannot carry the
# command (there is no $CMD yet, and on the jq-missing path there never will be)
# or any correlation id, so it carries the reason instead -- which is the whole
# of what there is to know. Defined above emit_ask because emit_ask exits, and
# log_event() below is defined far too late to help these three paths: they
# previously produced a prompt with no record at all, which is the one asymmetry
# with security_dispatcher, whose equivalent paths have always logged.
log_event_bare() {
  python3 "$(dirname "${BASH_SOURCE[0]}")/hook_logging.py" \
    --hook container_first \
    --decision ask \
    --pattern "$1" \
    --tool-name Bash </dev/null >/dev/null 2>&1 || true
}

# Emit an ask when the command cannot be inspected. Failing to a prompt (never a
# silent allow) closes the fail-open holes where jq is missing or the payload is
# too large / malformed to parse.
emit_ask() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}' "$1"
  log_event_bare "${2:-uninspectable}"
  exit 0
}

# jq is required to parse the hook payload; without it, prompt rather than
# waving the command through.
if ! command -v jq >/dev/null 2>&1; then
  emit_ask "ForceField container-first guard cannot inspect this command: jq is not installed. Approve only if you trust it." "jq_missing"
fi

# Read 1 MiB + 1 byte so an oversized payload (which would truncate and break
# JSON parsing, failing open) is detected rather than silently allowed.
INPUT=$(head -c 1048577)
if [[ ${#INPUT} -gt 1048576 ]]; then
  emit_ask "ForceField could not inspect this Bash command: it exceeds 1 MiB. Approve only if you trust it." "oversized_input"
fi

if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command' 2>/dev/null); then
  if [[ -n "$INPUT" ]]; then
    emit_ask "ForceField could not inspect this Bash command: malformed hook input. Approve only if you trust it." "unparseable_input"
  fi
  exit 0
fi

# The correlation ids, from the same payload the command came out of. This guard
# is the highest-volume record producer in the plugin, and without these its
# records joined to nothing -- not to the session, not to the tool call that
# sigma_engine and security_dispatcher recorded for the very same command.
# `// empty` so an absent field yields "" rather than the string "null".
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
TOOL_USE_ID=$(printf '%s' "$INPUT" | jq -r '.tool_use_id // empty' 2>/dev/null || true)
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)

# A heredoc body is stdin, not a command line. `bash <<EOF` executes it;
# `git commit -F - <<EOF` and `cat > NOTES.md <<EOF` file it away as a commit
# message or a document. Every check here scanned the body as command text
# regardless, so writing `container run --rm alpine true; pip install evil` in a
# commit message -- as the example proving a container cannot launder a host
# install -- asked the user to containerize their own sentence.
#
# Only a body consumed by a text-filing command, on a line that does not pipe it
# onward, is dropped. An interpreter, an unrecognized command, a pipeline, an
# unterminated heredoc and any parse trouble all keep their body, so this can
# only ever cost a false positive and never hide an executed payload.
#
# The split of the text before the operator is quote-blind on purpose: an
# over-split shortens the prefix, which makes the consumer match FAIL and the
# body be kept, so being wrong there is being conservative.
strip_heredocs() {
  awk -v SQ="'" '
    { lines[NR] = $0 }
    END {
      # Built as a dynamic regex string, not a /literal/, so that SQ
      # concatenates: the delimiter of a `<<EOF` is usually quoted.
      RE = "<<-?[ \t]*[" SQ "\"]?[A-Za-z_][A-Za-z0-9_]*[" SQ "\"]?"
      i = 1
      while (i <= NR) {
        line = lines[i]; print line; i++
        if (match(line, RE) == 0) continue
        before = substr(line, 1, RSTART - 1)
        rest = substr(line, RSTART + RLENGTH)
        delim = substr(line, RSTART, RLENGTH)
        sub(/^<<-?[ \t]*/, "", delim); gsub(SQ, "", delim); gsub(/"/, "", delim)
        if (rest ~ /<</ || substr(line, RSTART) ~ /\|/) continue
        n = split(before, parts, /(&&|\|\||;|&|\|)/)
        if (parts[n] !~ /^[ \t]*(sudo[ \t]+)?(git|cat|tee)([ \t]|$)/) continue
        j = i
        while (j <= NR && lines[j] !~ "^[ \t]*" delim "[ \t]*$") j++
        if (j > NR) continue
        print lines[j]; i = j + 1
      }
    }'
}

SCAN=$(printf '%s' "$CMD" | strip_heredocs)

# -----------------------------------------------------------
# Logging helper (fire-and-forget)
# -----------------------------------------------------------

# Routed through hook_logging.py rather than hand-building a record here. The
# flat {ts,hook,decision,pattern,command} line this replaces shared the log file
# with the OTel/OCSF records but none of their fields, so every documented jq
# recipe (all of which filter on .Attributes) silently skipped it — including
# container-first's hard denies. It also never saw redact_secrets, so a
# credential on the command line landed in clear, and it appended with a raw >>
# behind the rotating handler's back. The command goes over stdin, not argv, so
# it is not exposed in the process table.
#
# CALL IT AFTER THE `printf`, NEVER BEFORE. This is bash's version of the
# emit-before-log ordering every python guard holds: `log_event` starts a whole
# python interpreter, and putting that ahead of the verdict measured 1.153 s
# before the first byte of an `ask` reached stdout with a contended log, and
# 3.130 s before a `deny` reached stderr. Measured on this shell: bash's printf
# builtin puts the bytes in the pipe immediately (first stdout byte at 0.015 s
# from a script that then slept 2 s), so the reorder genuinely delivers the
# decision first rather than only appearing to.
#
# The `deny` rung is the exception it cannot fix -- its verdict IS `exit 2`, and
# nothing can precede the exit. That one is bounded instead, by the process
# logging budget inside hook_logging/log_sinks, which caps everything this call
# can wait on at LOG_BUDGET_SECONDS.
log_event() {
  local decision="$1" pattern="$2"
  printf '%s' "$CMD" | python3 "$(dirname "${BASH_SOURCE[0]}")/hook_logging.py" \
    --hook container_first \
    --decision "$decision" \
    --pattern "$pattern" \
    --session-id "${SESSION_ID:-}" \
    --tool-use-id "${TOOL_USE_ID:-}" \
    --cwd "${CWD:-}" \
    --tool-name Bash \
    --command-stdin >/dev/null 2>&1 || true
}

# -----------------------------------------------------------
# Tiered-config ceiling for this guard. Full strength ("deny") by
# default; ~/.claude/forcefield.json (trusted) or the project
# .claude/forcefield.json (untrusted, floored at ask) can soften it.
# Fast path: with no config file anywhere, stay at deny without paying a
# python start-up. That shortcut hardcodes what config.DEFAULT_PRESET
# resolves this guard to -- correct only while the default preset leaves
# container_first at its natural max, which test_config.py asserts so a
# future default cannot silently bypass the config here. Any resolution
# error falls back to deny (full strength), never to allow.
# resolve_ceiling in config.py owns the trust model, so this bash guard
# honors exactly the same rules as the python guards without
# reimplementing them.
# -----------------------------------------------------------
# Two rungs, not one: a ceiling may be a per-rung map (the `passive` posture is
# {deny: deny, ask: warn}), so the ceiling governing a would-be block and the one
# governing a would-be prompt can differ. Resolved in a single python start-up.
# With a plain-string ceiling both answers are that string, which is why
# emit_ask2 still treats `deny` as "ask stays ask".
CEILING_DENY="deny"
CEILING_ASK="deny"
if [[ -f "$HOME/.claude/forcefield.json" || -f "$PWD/.claude/forcefield.json" ]]; then
  _SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
  _RUNGS=$(python3 -c "import sys; sys.path.insert(0, '$_SCRIPT_DIR'); import config; print(config.resolve_ceiling('container_first', 'deny'), config.resolve_ceiling('container_first', 'ask'))" 2>/dev/null || echo "deny deny")
  read -r _cd _ca <<<"$_RUNGS"
  case "$_cd" in deny | ask | warn | allow | off) CEILING_DENY="$_cd" ;; esac
  case "$_ca" in deny | ask | warn | allow | off) CEILING_ASK="$_ca" ;; esac
fi

# Emit a would-be DENY through the config ceiling: block (deny), prompt
# (ask), warn (systemMessage), or silently allow. The default ceiling
# reproduces the block exactly.
emit_deny() {
  local pattern="$1" stderr_msg="$2"
  case "$CEILING_DENY" in
    deny)
      printf '%s\n' "$stderr_msg" >&2
      log_event "deny" "$pattern"
      exit 2
      ;;
    ask)
      printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"ForceField container-first guard flagged this command (%s). Config softened the block to a prompt; approve only if you trust it."}}' "$pattern"
      log_event "ask" "$pattern"
      exit 0
      ;;
    warn)
      printf '{"systemMessage":"ForceField container-first guard flagged this command (%s). Config downgraded the block to a warning."}' "$pattern"
      log_event "warn" "$pattern"
      exit 0
      ;;
    *)
      log_event "allow" "$pattern"
      exit 0
      ;;
  esac
}

# Emit a would-be ASK through the config ceiling (ask stays ask unless a
# trusted config lowers it to warn or off).
emit_ask2() {
  local pattern="$1" reason="$2"
  case "$CEILING_ASK" in
    deny | ask)
      printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}' "$reason"
      log_event "ask" "$pattern"
      exit 0
      ;;
    warn)
      printf '{"systemMessage":"%s"}' "$reason"
      log_event "warn" "$pattern"
      exit 0
      ;;
    *)
      log_event "allow" "$pattern"
      exit 0
      ;;
  esac
}

# -----------------------------------------------------------
# Normalize the command for threat matching only (NORM is never
# executed). This collapses the obfuscations that let an rm slip
# past a plain-string match: ${IFS}/$IFS become spaces, quotes and
# backslashes are removed (\rm, 'rm'), an absolute path is reduced
# to its basename (/bin/rm -> rm), and wrapper / env-assignment
# prefixes are dropped (env rm, FOO=bar rm -> rm). Raw $CMD is kept
# for logging and for the obfuscation check below. The threat greps
# still require an operator boundary before rm, so 'git rm' and
# similar sub-commands stay allowed.
# -----------------------------------------------------------

# _dq/_sq hold the quote characters so the ANSI-C ($'...') and locale ($"...")
# quoting prefix can be stripped without quote-escaping hell: dropping the `$`
# that immediately precedes a quote makes a token spelled $'rm' normalize to rm
# once the quotes themselves are removed below.
_dq='"'
_sq="'"
# shellcheck disable=SC2016,SC1003  # the sed/tr operands are a literal ${IFS} regex
# and a literal backslash for detection-only NORM matching, not shell expansions.
#
# Factored into a function because the host-install check further down needs the
# same normalization applied to a *single segment*: the quote stripping that
# defeats `pip 'install' x` also destroys the quoting that says which part of a
# command is an argument rather than a command, so segmenting has to happen on
# the raw text and normalization has to happen per segment afterwards.
normalize_text() {
  local _t
  _t=$(sed -E 's/\$\{IFS\}/ /g; s/\$IFS/ /g' |
    sed -E "s/\\\$[$_dq$_sq]//g" |
    tr -d '\\' | tr -d '"' | tr -d "'")
  _t=$(printf '%s' "$_t" |
    sed -E 's#(^|[[:space:];&|(])[^[:space:];&|]*/rm([[:space:]]|$)#\1rm\2#g')
  for _ in 1 2 3; do
    _t=$(printf '%s' "$_t" | sed -E \
      's/(^|[[:space:];&|(])([A-Za-z_][A-Za-z0-9_]*=[^[:space:];&|]*|env|command|builtin|exec|time|nice|nohup|stdbuf|setsid)[[:space:]]+/\1/g')
  done
  printf '%s' "$_t"
}

NORM=$(printf '%s' "$SCAN" | normalize_text)

# -----------------------------------------------------------
# Resolve statement-local variable assignments so a flag or token
# split into a variable (x=rf; rm -$x) is matched on its expanded
# form. A dangerous same-command expansion must be assigned in this
# same command string (a separate Bash call cannot share it), and
# only safe single-token values are inlined, so this can only reveal
# the real command -- never mask one -- keeping the DENY checks below
# zero-false-positive. The bare form requires a non-identifier
# boundary so $x never corrupts $xyz; capped so a padded payload
# cannot stall the hook.
# -----------------------------------------------------------
_assignments=$(printf '%s' "$NORM" |
  grep -oE '(^|[;&|[:space:]])[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_.:/-]+' |
  sed -E 's/^[^A-Za-z_]+//' | head -n 100 || true)
if [[ -n "$_assignments" ]]; then
  while IFS= read -r _pair; do
    [[ "$_pair" == *=* ]] || continue
    _name=${_pair%%=*}
    _val=${_pair#*=}
    NORM=$(printf '%s' "$NORM" | sed -E \
      -e "s#\\\$\\{${_name}\\}#${_val}#g" \
      -e "s#\\\$${_name}([^A-Za-z0-9_]|\$)#${_val}\\1#g")
  done <<<"$_assignments"
fi

# -----------------------------------------------------------
# Block: rm with recursive + force flags
#
# The recursive and force flags must belong to THE rm. This used to be
# three independent greps ANDed together -- rm at a command position
# anywhere, a recursive flag anywhere, a force flag anywhere -- so the
# flags did not have to be the rm's at all. `rm notes.txt && rsync -r
# --force src/ dst/` denied: a plain non-recursive delete, plus flags
# belonging to a different command. That is a false positive on the DENY
# tier, which is contractually zero-false-positive, so it was a contract
# violation rather than friction.
#
# RM_RF_FLAGS (shared with the indirect check below) already encodes the
# adjacency requirement, so the fix is to use the primitive that check
# has always used. The intervening span excludes shell operators, which
# is what stops a match from reaching into the next command.
# -----------------------------------------------------------

# A bare `|` is deliberately NOT a command position here. `... | rm -rf x` is
# not a shell idiom -- rm does not read paths from stdin -- so the pipe form
# that matters is `| xargs rm -rf`, which INDIRECT_RM below catches on its own.
# Meanwhile a bare `|` is extremely common inside a quoted regex, and this guard
# scans raw text with no quote awareness: the alternation in
# `rg 'rm_rf|rm -rf|rm -r '` was read as a pipe introducing a command, and the
# search denied. Dropping it removes that whole false-positive family and costs
# no real detection. `||` is still a command position, via its own branch.
# A privilege or environment wrapper still leaves `rm` as the command being run,
# so `sudo rm -rf /` must be caught -- it was not, because `rm` there sits after a
# plain space, which is deliberately not a command position (that is what keeps
# `git rm` allowed). Only known wrapper words count, and only dash-flags and
# VAR=value assignments may sit between the wrapper and the rm. That restriction
# is the point: allowing arbitrary words would let the span cross a container
# invocation, so `sudo docker run --rm -v /a:/b img sh -c ...` would match on the
# `--rm` and deny a containerized build -- a DENY false positive, which the
# contract forbids. `sudo -u root rm -rf x` (a bare word argument) is therefore
# NOT caught; under-reaching here is the correct trade against that FP.
RM_WRAPPER='((sudo|doas|command|exec|nohup|time|nice|ionice|env)[[:space:]]+(-[^[:space:]]*[[:space:]]+|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*)*'
RM_AT_CMD_POS="(^|;[[:space:]]*|&&[[:space:]]*|[|][|][[:space:]]*)${RM_WRAPPER}rm[[:space:]]+"
# Flag orderings for recursive+force, combined or adjacent. `--force -r` and
# `-f --recursive` were absent: narrowing the direct check onto a primitive
# with holes would have traded a false positive for a false negative, so they
# are added here and the indirect check gains them too.
RM_RF_FLAGS='(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-r[[:space:]]+-f|-f[[:space:]]+-r|--recursive[[:space:]]+--force|--force[[:space:]]+--recursive|--recursive[[:space:]]+-f|-r[[:space:]]+--force|--force[[:space:]]+-r|-f[[:space:]]+--recursive)([[:space:]]|$)'

if grep -qiE "${RM_AT_CMD_POS}([^;&|<>()]*[[:space:]])?${RM_RF_FLAGS}" <<<"$NORM"; then
  emit_deny "rm_rf" 'BLOCKED: Use trash instead of rm -rf'
fi

# -----------------------------------------------------------
# Block: recursive force-delete reached past the argument
# boundary the rm_rf check above intentionally skips (so 'git rm'
# stays allowed). `find -exec rm -rf` and `xargs rm -rf` carry the
# exact rm -rf semantics; the recursive+force flags are required on
# the rm itself (adjacent), so a plain `find -exec rm {}` or
# `xargs rm` stays allowed and an unrelated -r elsewhere (e.g.
# `find -regex ... -exec rm -f`) cannot cross-contaminate.
# -----------------------------------------------------------

INDIRECT_RM="(-exec(dir)?[[:space:]]+|xargs([[:space:]]+-[^[:space:]]+)*[[:space:]]+)${RM_WRAPPER}rm[[:space:]]+"

if grep -qiE "${INDIRECT_RM}${RM_RF_FLAGS}" <<<"$NORM"; then
  emit_deny "rm_rf_indirect" 'BLOCKED: Use trash instead of recursive force-delete (find -exec rm -rf / xargs rm -rf).'
fi

# Block: bare `find <path> -delete` wipes the entire tree (rm -rf
# equivalent, no rm token at all). A scoping predicate (-name,
# -type, ...) between the path and -delete breaks this match, so
# filtered cleanup like `find . -name '*.pyc' -delete` stays allowed.
if grep -qiE '(^|;[[:space:]]*|&&[[:space:]]*|[|][|]?[[:space:]]*)[[:space:]]*find([[:space:]]+[^[:space:]-][^[:space:]]*)?[[:space:]]+-delete([[:space:]]|$)' <<<"$NORM"; then
  emit_deny "find_delete" 'BLOCKED: bare "find <path> -delete" wipes the whole tree. Use trash, or add a filter (-name/-type/...).'
fi

# -----------------------------------------------------------
# Block: Obfuscation (hex/octal/ASCII-unicode escape sequences).
# \u00XX and \U000000XX are the ASCII range where command tokens live
# ($'rm' -> rm); \uXXXX above 007F (accents, symbols, emoji)
# is legitimate display text and is intentionally NOT matched. Checked
# BEFORE allowlist to catch evasion. Parameter-expansion forms
# like ${#arr[@]}, ${var##*/}, ${file%%.*} are NOT flagged: they
# are common, legitimate shell, and hard-denying them (a deny,
# not an ask) violated the zero-false-positive rule.
# -----------------------------------------------------------

if grep -qE '(\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\u00[0-7][0-9a-fA-F]|\\U000000[0-7][0-9a-fA-F])' <<<"$SCAN"; then
  emit_deny "obfuscation" $'BLOCKED: Obfuscated command detected (hex/octal escape sequences).\nIf this is legitimate, write it in plain text.'
fi

# -----------------------------------------------------------
# Block: Container escape techniques (never legitimate in dev)
#
# Anchored to command position. `deny` is the plugin's one contractual
# zero-false-positive rung and the only rung a user running with permissions
# skipped ever sees, so an unanchored match here is a hard block on ordinary
# work. Bare `ptrace` had no anchor at all and `nsenter` only a trailing space,
# which between them blocked grepping the kernel source, naming a log file,
# listing a directory and writing a commit message about the tool. There is no
# `ptrace` executable on either platform (it is a syscall), so anchoring the
# branch to command position costs no real detection.
#
# NORM has already had transparent prefixes (env/command/exec/nice/VAR=) and
# ${IFS}/quote obfuscation removed, so a command word here starts the string or
# follows a top-level operator, past an optional sudo/doas and an optional path.
# -----------------------------------------------------------

ESC_CMD_POS='(^|[;&|(][[:space:]]*)[[:space:]]*(sudo[[:space:]]+|doas[[:space:]]+)?([^[:space:];&|]*/)?'

# unshare still needs the mount-namespace flag, and it has to be in the SAME
# segment: `[^;&|[:space:]]+` cannot cross an operator, so `unshare --fork; ls -m`
# does not assemble a match out of two unrelated commands.
ESCAPE_PATTERN="${ESC_CMD_POS}(nsenter|ptrace)([[:space:]]|\$)|${ESC_CMD_POS}unshare([[:space:]]+[^;&|[:space:]]+)*[[:space:]]+(--mount|-[a-zA-Z]*m)([[:space:]]|\$)"

if grep -qE "$ESCAPE_PATTERN" <<<"$NORM" ||
  grep -qE '(^|[[:space:];&|(=])[A-Za-z_][A-Za-z0-9_]*=(unshare|nsenter)([[:space:];&|/]|$)' <<<"$SCAN"; then
  emit_deny "container_escape" $'BLOCKED: Container escape technique detected (nsenter/unshare/ptrace).\nThese tools break container isolation and have no legitimate dev use.'
fi

# -----------------------------------------------------------
# Ask: Over-privileged container flags. Checked against both NORM
# (catches quote/IFS obfuscation of a flag like --privileged) and the
# raw CMD (NORM strips key=value tokens, which would otherwise hide
# `--security-opt seccomp=unconfined`).
# -----------------------------------------------------------

# Escape-grade capabilities are effectively equivalent to --privileged
# (mount/namespace/module/raw-IO/file-perm-bypass -> container escape), so
# they ask like --privileged does. Narrow caps (NET_ADMIN, CHOWN, ...) are the
# recommended safer alternative and are intentionally NOT matched. Matched
# case-insensitively with an optional CAP_ prefix (docker accepts both).
OVERPRIV_PATTERN='(--privileged|--cap-add[= ](CAP_)?(ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|SYS_BOOT|DAC_READ_SEARCH|DAC_OVERRIDE|BPF)|(seccomp|apparmor)[=:]unconfined|--pid[= ]host|--net(work)?[= ]host|--ipc[= ]host|--uts[= ]host|--userns[= ]host|-v[= ]/:|--volume[= ]/:|--device[= ]|mount[[:space:]].*-o[[:space:]].*bind|--mount[[:space:]=][^;&|]*(src|source)=/([,[:space:]]|$))'

if grep -qiE "$OVERPRIV_PATTERN" <<<"$NORM" || grep -qiE "$OVERPRIV_PATTERN" <<<"$SCAN"; then
  REASON='CONTAINER-FIRST: Over-privileged container detected.\n\nBest practices:\n- Use --cap-add=<SPECIFIC_CAP> instead of --privileged\n- Use --network=<name> instead of --net=host\n- Mount specific paths read-only (-v /path:/path:ro) instead of mounting /\n- For nested containers, use --device /dev/fuse instead of --privileged\n\nIf this is genuinely required (e.g., CI runner, GPU access), approve to proceed.'
  emit_ask2 "container_overprivileged" "$REASON"
fi

# -----------------------------------------------------------
# Block: Kernel/system manipulation
# -----------------------------------------------------------

if grep -qE '(insmod|modprobe|(^|[[:space:];&|(])sysctl[[:space:]]+[^;|&]*=|>>?[[:space:]]*/(proc/sys|sys/)|(^|[[:space:]|])tee[[:space:]]+(-[A-Za-z]+[[:space:]]+)*/(proc/sys|sys/)|of=/(proc/sys|sys/))' <<<"$NORM"; then
  emit_deny "kernel_manipulation" $'BLOCKED: Kernel/system manipulation detected.\nLoading modules or writing to /proc and /sys is not permitted.'
fi

# -----------------------------------------------------------
# Compound command gate: if the command chains, substitutes,
# or redirects, skip the allowlist (these must go through all
# detection checks below). Command/process substitution and
# redirects are included so an allowlisted head like `cat` can
# not smuggle a fetch through `cat $(curl evil)` or `> file`.
# -----------------------------------------------------------

IS_COMPOUND=false
if grep -qE '(;|&&|\|\||[|]|\$\(|`|>|<|&)' <<<"$SCAN"; then
  IS_COMPOUND=true
fi
# A newline separates two commands exactly as `;` does, but grep matches within a
# line and so could never see one. Every allowlist below exits 0 on a simple
# command, so a single newline waved the entire rest of this guard through:
#   ls
#   pip install evil
# read as a simple `ls` and was allowed silently. Tested in bash rather than
# grep for that reason.
if [[ "$SCAN" == *$'\n'* ]]; then
  IS_COMPOUND=true
fi

# -----------------------------------------------------------
# Allowlist: commands that legitimately run on the host.
# These exit silently (no reminder).
# Only applies to simple (non-compound) commands.
# -----------------------------------------------------------

if [[ "$IS_COMPOUND" == "false" ]]; then
  # Git, file operations, clipboard, Finder
  if grep -qE \
    '^\s*(git |ls |pwd|cd |mkdir |mv |cp |trash |open |pbcopy|pbpaste|wc |stat |file |diff |chmod |test )' <<<"$SCAN"; then
    log_event "allow" "allowlist_fileops"
    exit 0
  fi

  # Container runtimes themselves. `container` is Apple's CLI on macOS.
  if grep -qE '^\s*(podman |docker |nerdctl |container )' <<<"$SCAN"; then
    log_event "allow" "allowlist_container"
    exit 0
  fi

  # Host-installed dev tools (already vetted, part of toolchain)
  if grep -qE \
    '^\s*(rg |fd |ast-grep |shellcheck |shfmt |actionlint |zizmor |prek |wt |gh |jq |yq )' <<<"$SCAN"; then
    log_event "allow" "allowlist_devtools"
    exit 0
  fi

  # Host-installed language toolchain (isolation-aware by design)
  if grep -qE \
    '^\s*(uv |ruff |ty |pipx |npx |oxlint |oxfmt |tsc |cargo clippy|cargo fmt|cargo test|cargo deny|cargo careful)' <<<"$SCAN"; then
    log_event "allow" "allowlist_toolchain"
    exit 0
  fi

  # Simple info commands. `env` and `source` are intentionally excluded:
  # both run arbitrary commands, so they must not get a silent wave-through.
  #
  # `command` belongs in that excluded set for exactly the same reason -- bare
  # `command X` runs X -- and allowlisting it head-first meant this branch
  # exited before the install and interpreter checks below were ever reached, so
  # `command pip install evil` was silently allowed while `pip install evil`
  # asked. The two halves of this file disagreed: CMD_PREFIX already names
  # `command[[:space:]]+` as a transparent prefix to see PAST, not a command to
  # trust. Only the lookup form (`command -v`/`-V`), which executes nothing,
  # stays on the allowlist.
  if grep -qE \
    '^\s*(echo |printf |which |type |command[[:space:]]+-[vV]([[:space:]]|$)|cat |head |tail |export |true|false|:)' <<<"$SCAN"; then
    log_event "allow" "allowlist_info"
    exit 0
  fi
fi

# -----------------------------------------------------------
# Detect: package managers installing to host
# Passive reminder only -- see the posture note further down.
# -----------------------------------------------------------

# Installers that write to the host on every platform.
INSTALL_PORTABLE='pip3?\s+install|python3?\s+-m\s+pip\s+install|npm\s+install|pnpm\s+(add|install)|yarn\s+add|gem\s+install|cargo\s+install|brew\s+install|conda\s+install'
# ...and the ones that need a Linux host to mean anything. On macOS there is no
# apt database to modify, so this is not a low-severity finding, it is an
# impossible one: the command must be reaching a container, a VM or another
# machine over ssh, none of which is the host. macOS' own manager is `brew`,
# which stays in the portable set above, so nothing goes uncovered.
INSTALL_LINUX_ONLY='apt(-get)?\s+install|aptitude\s+install|dnf\s+install|yum\s+install|pacman\s+-S'

# Windows joins macOS here: a hook seeing MINGW/MSYS/CYGWIN means Claude Code is
# running natively, so its Bash tool is Git Bash, which has no apt either. Claude
# Code running INSIDE WSL reports Linux from uname and keeps reminding about
# everything, which is correct -- there the distro IS the host.
#
# This guard is the ONLY place the host-vs-container question is asked.
# supply_chain_guard used to ask it too, through `global_install` and
# `system_pkg_install`, and that was the wrong owner: nothing about a bare-host
# `pip install requests` is a supply-chain finding. What that guard defends is
# PROVENANCE -- an arbitrary-URL install, a plaintext registry, a typosquat, a
# fetch piped to a shell -- and a container changes none of it. Those two patterns
# are gone, which is why dnf/yum/pacman appear above: their managers moved here
# with the question, instead of the coverage being dropped.
#
# One measured consequence, accepted rather than worked around: `ssh prod-box
# apt-get install nginx` and `wsl apt-get install curl` used to prompt, because
# supply_chain's pattern was unanchored and reached them. This guard requires the
# install phrase in COMMAND position and after `ssh prod-box` it is not, so both
# forms are now allowed silently on every platform. Installing on a persistent
# machine elsewhere is still a host-hygiene question, not a supply-chain one, and
# this guard does not prompt for host hygiene.
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
case "$UNAME_S" in
  Darwin | MINGW* | MSYS* | CYGWIN* | Windows_NT)
    INSTALL_PATTERN="($INSTALL_PORTABLE)"
    ;;
  *)
    INSTALL_PATTERN="($INSTALL_PORTABLE|$INSTALL_LINUX_ONLY)"
    ;;
esac

# A container runtime at the START of a segment. An install inside one of these
# is running in a container, which is the whole point of this guard — asking
# about it told the user to containerize a command that already was. `container`
# is Apple's CLI; without it the recommended runtime on this platform read as a
# bare host install.
CONTAINER_RUN='^[[:space:]]*(sudo[[:space:]]+)?(podman|docker|nerdctl|container|apptainer|singularity|lima|colima)[[:space:]]+(run|exec|build|compose)([[:space:]]|$)'

# Decide per segment rather than over the whole string, so a container
# invocation cannot launder a host install that sits in a *different* segment
# (`container run --rm alpine true; pip install evil` still asks).
#
# The split has to respect quoting. Splitting on every separator was believed
# safe because it "only ever yields more segments to check, never fewer" — but
# more segments is not conservative here, it is wrong in both directions. It
# manufactures command positions that do not exist: the body of
# `container run img sh -c "apt-get update && apt-get install jq"` became a bare
# `apt-get install jq` segment with no container prefix left on it, so the guard
# asked the user to containerize a command that already was. The same fabricated
# split fires on an install phrase quoted as an argument to something else.
#
# The install phrase has to be in COMMAND position — at the start of a segment,
# past any transparent prefix — not merely present somewhere in the text. An
# unanchored match fired on the phrase inside a quoted argument to some other
# program: `printf "%s" "pip install requests" | ...` never runs pip, and neither
# does `grep "npm install" file`, but both asked.
# Transparent prefixes a command word may hide behind. Written once: three
# checks now anchor on it, and a fourth spelling would be a fourth thing to keep
# in step.
CMD_PREFIX='^[[:space:]]*(sudo[[:space:]]+|doas[[:space:]]+|nohup[[:space:]]+|time[[:space:]]+|command[[:space:]]+|env[[:space:]]+([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*)*'

INSTALL_CMD_POS="${CMD_PREFIX}${INSTALL_PATTERN}"

# ...except when the wrapper is itself a shell, where the quoted body IS the
# command: `bash -c "pip install evil"` is a genuine host install and must still
# ask. Anchored in command position for the same reason the install phrase is:
# unanchored, a `sh -c` mentioned inside somebody else's quoted argument dragged
# the whole segment in with it.
SHELL_CMD_POS="${CMD_PREFIX}([^[:space:]]*/)?(ba|z|k|da|a)?sh[[:space:]]+(-[A-Za-z]*[[:space:]]+)*-[A-Za-z]*c([[:space:]]|\$)"

# Interpreters and build tools that could be containerized. This gets the
# lightest rung in the plugin — allow plus a note — and that is exactly why it
# went unaudited: it never produced a complaint, so nobody looked, while it was
# the ONLY check in this file that neither anchored to command position nor
# skipped container invocations. Unanchored it fired on `make` inside a
# filename and on an interpreter named in somebody else's quoted argument;
# container-blind it advised containerizing commands already in a container.
#
# Same defect as the install check, one severity rung down. Severity governs
# whether a matching-model bug is ever reported, not whether it exists, so this
# is now evaluated inside the same per-segment loop and inherits both fixes.
INTERP_PATTERN='(python3?|node|ruby|perl|java|javac|go[[:space:]]+run|go[[:space:]]+build|make|cmake|gcc|g\+\+|clang)'
INTERP_CMD_POS="${CMD_PREFIX}([^[:space:]]*/)?${INTERP_PATTERN}([[:space:]]|\$)"

# Split on top-level separators only — ones outside single and double quotes.
# On unbalanced quotes the parse is not trustworthy, so it falls back to the
# naive split: over-segmenting can over-ask, which is the safe direction to be
# wrong in when the input is already malformed.
split_toplevel() {
  # Lines are accumulated and processed in END rather than setting RS to some
  # sentinel: a quoted string may span newlines, so the scan has to see the whole
  # command at once, and a multi-character RS is not portable (POSIX awk keeps
  # only its first character).
  awk -v SQ="'" '
    { all = all (NR > 1 ? "\n" : "") $0 }
    END {
      n = length(all); seg = ""; q = ""
      for (i = 1; i <= n; i++) {
        c = substr(all, i, 1)
        if (q == SQ) { if (c == SQ) q = ""; seg = seg c; continue }
        if (q == "\"") {
          if (c == "\\" && i < n) { seg = seg c substr(all, i + 1, 1); i++; continue }
          if (c == "\"") q = ""
          seg = seg c; continue
        }
        if (c == "\\" && i < n) { seg = seg c substr(all, i + 1, 1); i++; continue }
        if (c == "\"" || c == SQ) { q = c; seg = seg c; continue }
        if (c == ";" || c == "&" || c == "|" || c == "\n") { print seg; seg = ""; continue }
        seg = seg c
      }
      if (q != "") { gsub(/(&&|\|\||;|\|)/, "\n", all); print all; exit }
      print seg
    }'
}

# -----------------------------------------------------------
# The registered 5s timeout is a security boundary, not a comfort setting: a
# hook killed at the deadline returns no verdict at all and the harness allows
# the call. So the cost of this loop IS the guard's fail-open path, reachable by
# padding a command with well-formed filler. Two shapes used to reach it and
# both are closed here.
#
# 1. Segment COUNT. Each iteration paid a fork-heavy normalize_text plus four
#    greps, so cost was linear with a large constant. The prefilter below makes
#    the whole loop conditional on the command containing an install or
#    interpreter token ANYWHERE -- checked against both SCAN and the
#    already-computed NORM, because normalization is character-level and
#    anchored on the same operators the split uses, so a token that per-segment
#    normalization would reveal is present in whole-string NORM too. Padding
#    made of commands this guard does not care about now costs two greps total
#    instead of thousands.
# 2. Segment LENGTH. The blank test `[[ -n "${_seg//[[:space:]]/}" ]]` built a
#    whole new string per segment and measured ~cubic in its length: 0.12s /
#    0.59s / 3.6s / 25.5s at 1k / 2k / 4k / 8k characters. A pattern match
#    answers the same question without constructing anything.
#
# The residual case -- a real install token plus thousands of segments of
# filler, where the install sits last so the early break never fires -- is
# bounded by SEG_MAX and fails CLOSED to a prompt, the same way the missing-jq
# and oversized-payload paths above do. Silently allowing is the one outcome a
# budget overrun must not produce.
# -----------------------------------------------------------

# Inspecting one segment costs ~17 forks (normalize_text is a four-stage
# pipeline plus four more seds, then up to eight greps), which measured ~35ms --
# so the budget is spent on process creation, not matching. Two fork-free bash
# tests below decide which segments have to pay it.
#
# SEG_TOKENS is deliberately loose and counts only as TRIAGE: over-matching
# costs time (the safe direction), under-matching would lose a detection, so it
# lists the bare manager and interpreter words rather than trying to be precise.
# Bare `install`/`add` are excluded because every install spelling already
# carries its manager's name, and including them made an ordinary `git add`
# chain pay full price.
#
# It has to list every manager INSTALL_PATTERN can match, and that coupling is easy
# to miss: adding dnf/yum/pacman above without adding them here left `dnf install -y
# curl` silent on Linux, because triage dropped the segment before the install check
# ever ran. Caught by running the suite on Linux, where a macOS laptop cannot see it.
SEG_TOKENS='(pip|python|npm|pnpm|yarn|gem|cargo|brew|apt|aptitude|dnf|yum|pacman|conda|node|ruby|perl|java|javac|go|make|cmake|gcc|g\+\+|clang)'

# The characters and words normalize_text actually acts on: ${IFS} and $'..'
# need `$`, quote/backslash stripping needs those characters, the basename
# reduction needs `/`, and the prefix strip needs `=` or one of the wrapper
# words. A segment carrying none of them normalizes to itself, so computing
# $_segnorm and re-matching against it is pure cost.
SEG_NORMWORDS='(^|[[:space:];&|(])(env|command|builtin|exec|time|nice|nohup|stdbuf|setsid)[[:space:]]'

# Sized from measurement against the EXPENSIVE segment shape, not the cheap one:
# a segment carrying a quote or `=` forces normalize_text and costs ~40ms, while
# a plain `make all` costs ~11ms. 40 x 40ms is ~1.6s, roughly a third of the 5s
# budget, leaving room for a slower machine. Exceeding it prompts; it never
# allows.
SEG_MAX=40

host_install=false
host_interp=false
if grep -qiE "$INSTALL_PATTERN|$INTERP_PATTERN" <<<"$SCAN" ||
  grep -qiE "$INSTALL_PATTERN|$INTERP_PATTERN" <<<"$NORM"; then
  _segn=0
  while IFS= read -r _seg; do
    [[ "$_seg" == *[![:space:]]* ]] || continue

    # Fork-free triage. A segment matters only if it carries a manager or
    # interpreter token, or a character normalization could turn into one --
    # `p"i"p install x` has no bare `pip` until the quotes come off. Filler the
    # guard has no opinion about (`true`, `ls`, `cd x`) exits here having cost
    # nothing, which is what keeps a padded command inside the budget.
    if ! [[ "$_seg" =~ $SEG_TOKENS ]] && [[ "$_seg" != *[\'\"\\\$=]* ]]; then
      continue
    fi

    # Counted AFTER triage, so the cap bounds real inspection rather than
    # payload size, and ordinary filler never consumes it.
    _segn=$((_segn + 1))
    if ((_segn > SEG_MAX)); then
      emit_ask2 "segment_cap" "ForceField could not fully inspect this Bash command: more than $SEG_MAX of its segments carry a package-install or interpreter token, which would outrun the guard's time budget. Approve only if you trust it."
    fi
    # A container invocation is skipped whole: everything it carries, including
    # a quoted shell body, runs in the container. That is the outcome this guard
    # exists to produce.
    grep -qE "$CONTAINER_RUN" <<<"$_seg" && continue
    _cands=("$_seg")
    if [[ "$_seg" == *[\'\"\\\$=/]* ]] || [[ "$_seg" =~ $SEG_NORMWORDS ]]; then
      _segnorm=$(printf '%s' "$_seg" | normalize_text)
      [[ "$_segnorm" == "$_seg" ]] || _cands+=("$_segnorm")
    fi
    for _cand in "${_cands[@]}"; do
      grep -qE "$CONTAINER_RUN" <<<"$_cand" && continue
      grep -qiE "$INTERP_CMD_POS" <<<"$_cand" && host_interp=true
      if grep -qiE "$INSTALL_CMD_POS" <<<"$_cand"; then
        :
      elif grep -qE "$SHELL_CMD_POS" <<<"$_cand" && grep -qiE "$INSTALL_PATTERN" <<<"$_cand"; then
        :
      else
        continue
      fi
      host_install=true
      break
    done
    [[ "$host_install" == "true" ]] && break
  done < <(printf '%s' "$SCAN" | split_toplevel)
fi

# -----------------------------------------------------------
# Container-first advice is PASSIVE, on purpose.
# -----------------------------------------------------------
# Both reminders below are `allow` + additionalContext: context for the model, no
# prompt, no human in the loop. Preferring a container is a hygiene preference, not
# a security boundary -- a host install is untidy, not an attack -- and gating it
# cost more than it bought. An unattended agent that hits a prompt mid-workflow
# stalls or reports a failure it never actually attempted, which is a worse outcome
# than the install it was trying to avoid.
#
# The genuine boundaries are untouched and still block or prompt: `emit_deny` for
# rm -rf, obfuscation, container escape and kernel writes, and `emit_ask2` for
# escape-grade container flags (--privileged, --cap-add SYS_ADMIN) and for
# segment_cap, where the guard is admitting it could not finish inspecting.
#
# Name a runtime that EXISTS. The advice used to prescribe `podman` unconditionally;
# on this machine only Apple's `container` CLI is installed, so the one instruction
# the reminder gave could not be followed, which is the least reliable thing a
# reminder can do. Detected per invocation, and when nothing is installed the
# reminder says so rather than prescribing a tool that is not there. Every flag used
# below (--rm, -v, -w) was verified present on the Apple CLI and is spelled the same
# way by podman, docker and nerdctl.
#
# Preference is platform-shaped, and only ever among runtimes actually installed:
# on macOS, Apple's `container` first, because it is the native one and needs no VM
# of its own; everywhere else podman first, being the rootless daemonless default.
# Whatever is found first wins, so a machine with only docker or only nerdctl is
# told to use that rather than a tool it does not have. Apple's CLI is macOS-only,
# so it is not looked for elsewhere -- that also keeps a same-named binary on a
# Linux PATH from being mistaken for it.
case "$UNAME_S" in
  Darwin) _rt_order=(container podman docker nerdctl) ;;
  *) _rt_order=(podman docker nerdctl) ;;
esac
CONTAINER_RUNTIME=""
for _rt in "${_rt_order[@]}"; do
  if command -v "$_rt" >/dev/null 2>&1; then
    CONTAINER_RUNTIME="$_rt"
    break
  fi
done

if [[ -n "$CONTAINER_RUNTIME" ]]; then
  RUN_HINT="$CONTAINER_RUNTIME run --rm -v <hostdir>:/work -w /work"
  RUN_BARE="$CONTAINER_RUNTIME run --rm"
  # A failed container attempt leaves NOTHING behind, so the recovery is a fresh
  # run, not a repair. Said explicitly because the opposite assumption -- that a
  # half-finished run left state worth resuming -- is what strands a workflow.
  RETRY_HINT='If an earlier containerized attempt failed or was interrupted, start a FRESH run rather than trying to resume it: the container was discarded on exit, so no partial state survived and there is nothing to continue from.'
else
  RUN_HINT=""
  RETRY_HINT='No container runtime is installed on this machine, so host execution is the only option here.'
fi

if [[ "$host_install" == "true" ]]; then
  if [[ -n "$RUN_HINT" ]]; then
    CTX="CONTAINER-FIRST: this installs packages on the host OS. Not blocked and no approval needed -- proceed if the host is genuinely what you want. A container is preferred because it is discarded on exit and leaves no host state behind.\n\n  $RUN_HINT python:3.13-slim sh -c \\\"pip install PKG && python script.py\\\"\n  $RUN_BARE <image> apt-get install <pkg>\n\n$RETRY_HINT\n\nHost execution is the right call when the command needs hardware access, must write outside the mount, or is a quick one-liner with no dependencies."
  else
    CTX="CONTAINER-FIRST: this installs packages on the host OS. Not blocked and no approval needed. $RETRY_HINT"
  fi
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"%s"}}' "$CTX"
  log_event "allow" "host_pkg_install"
  exit 0
fi

# -----------------------------------------------------------
# Report: interpreter / build tool on the host (decided in the
# segment loop above). Lighter reminder, same passive shape.
# -----------------------------------------------------------

if [[ "$host_interp" == "true" ]]; then
  if [[ -n "$RUN_HINT" ]]; then
    CTX="CONTAINER-FIRST: this runs an interpreter/build tool on the host. Not blocked. Consider: $RUN_HINT <image> <command>. Host execution is fine when it needs hardware access, writes to the project dir, or is a quick one-liner with no deps."
  else
    CTX="CONTAINER-FIRST: this runs an interpreter/build tool on the host. Not blocked, and no container runtime is installed here."
  fi
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"%s"}}' "$CTX"
  log_event "allow" "host_interpreter"
  exit 0
fi

# -----------------------------------------------------------
# Default: allow, no reminder needed
# -----------------------------------------------------------
log_event "allow" "default"
exit 0
