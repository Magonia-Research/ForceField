---
description: Inspect a repository's submodules before you clone it
allowed-tools: Bash(python3 ${CLAUDE_PLUGIN_ROOT}/hooks/inspect_remote.py:*)
argument-hint: "<url> | list | forget <key>"
---

Inspect a remote repository before cloning it, by running `hooks/inspect_remote.py`.

`git clone` executes code *during* the clone — CVE-2024-32002 and CVE-2025-48384
both land an executable hook while the clone is still running — so the only useful
time to read `.gitmodules` is before it. `git_guard` already does that in-hook, but
only for github.com, gitlab.com and codeberg.org: a `PreToolUse` hook is fail-open
on a 5s budget and must not make arbitrary outbound requests to a URL the model
chose. This command has neither constraint, because the user ran it and the user
typed the URL. It is the path for the repositories the hook refuses to cover —
self-hosted forges, SSH remotes, private instances.

Run exactly one of these, based on `$ARGUMENTS`:

- a URL → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/inspect_remote.py inspect <url>`
- `list` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/inspect_remote.py list`
- `forget <key>` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/inspect_remote.py forget <key>`
- `forget --expired` → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/inspect_remote.py forget --expired`
- empty → ask the user which repository to inspect. Do not guess a URL.

Then report the tool's output to the user verbatim. Do not paraphrase the verdict
and do not soften it.

There are exactly three outcomes, and they are not on a spectrum:

- **DO NOT CLONE** — the remote's `.gitmodules` carries the literal signature of a
  known clone-time RCE exploit, named in the output. Do not clone it, do not clone
  it into a container to "have a look", and do not offer a workaround. Suggest
  reporting it to the forge it is published on.
- **Safe to clone** — the `.gitmodules` was retrieved at a named commit and carries
  no known signature. Say what that does and does not cover: it is a statement
  about the clone, not about the code. Nothing here says the repository is
  trustworthy to run.
- **INCONCLUSIVE** — nothing was retrieved. Never report this as clean, never round
  it up to "probably fine", and never re-run with something weakened to force a
  verdict. The repository is uninspected and the decision has to be made on other
  grounds.

The command refuses two URL forms outright, before git is ever spawned, and neither
refusal has a flag that overrides it:

- **`ext::` and other `<helper>::` transports** — git hands a remote-helper address
  to the shell, so merely asking git about the URL would be the code execution the
  inspection exists to prevent.
- **`file://`** — a local clone is the amplifier for CVE-2024-32002, and a
  repository already on this disk can be read directly instead.

A recorded `DO NOT CLONE` is what the guard consults later: the subsequent clone of
that repository is denied outright rather than prompted on, at any commit, until you
revoke the verdict with `forget`. A clean verdict is keyed by repository *and* commit,
so it stops applying the moment the remote moves — that is deliberate, and a re-prompt
after an upstream push is the system working. Never edit
`~/.claude/forcefield/inspections.json` directly.

A clean verdict does not make the clone silent. `git_guard` asks on any clone that has
not disarmed the clone-time execution surface, whatever this command found, because
what `.gitmodules` says and how the clone is run are two different questions. Clone with:

```
git -c core.hooksPath=/dev/null clone --no-recurse-submodules <url>
```
