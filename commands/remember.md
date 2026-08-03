---
description: Stop ForceField re-prompting for an action you just approved
allowed-tools: Bash(python3 ${CLAUDE_PLUGIN_ROOT}/hooks/memo.py:*)
argument-hint: "[list | forget <key> | --global | --days N]"
---

Manage ForceField's remembered approvals by running `hooks/memo.py`.

Claude Code has no "don't ask again" that works on a hook prompt — a PreToolUse
hook's `ask` is returned as the final permission decision without `permissions.allow`
ever being consulted, so adding an allow rule does nothing. This command is the
replacement: it records that the user approved one exact command, and the guard
stops asking about that command.

Run exactly one of these, based on `$ARGUMENTS`:

- empty → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/memo.py add --last`
  Remembers the most recent `ask` from the security log.
- `list` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/memo.py list`
- `forget <key>` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/memo.py forget <key>`
- `forget --expired` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/memo.py forget --expired`
- otherwise pass the flags through to `add --last` (`--global`, `--days N`, `--forever`).

Then report the tool's output to the user verbatim — do not paraphrase a refusal.

If the command refuses, relay the reason and do not try to work around it. The
refusals are deliberate and each one means something specific:

- **locked / never allowlistable** — the pattern is on `exfil_guard`'s
  `NEVER_ALLOWLIST` or `allowlist.py`'s `_NEVER_SUPPRESSIBLE`. These are the
  patterns the project decided may never be silenced, such as credential reads
  and git RCE primitives. There is no flag that overrides this, by design.
- **contains a credential** — the command has a secret in it. The fix is to
  rotate the secret and pass it via an environment variable, not to remember it.
- **no recent ask found** — nothing in the log to remember. The user has to hit
  the prompt first, approve it, and then run this.
- **store is full** — 200 exceptions means the friction is class-shaped, not
  command-shaped. Suggest a `~/.claude/forcefield.json` guard mode change or a
  `.claude/hook-allowlist.json` entry instead.

Never edit `~/.claude/forcefield/memos.json` directly, and never suggest that the
user disable a guard to get past a prompt this command declined to remember.
