# ForceField

Security hardening for Claude Code. Local detection, pre-action blocking, and a security log you
can query.

ForceField puts a policy gate in front of every tool call the agent makes: command execution,
file I/O, credential handling, agent spawning, MCP tool calls, outbound fetches, and the output
that comes back. Twenty-three registered hooks evaluate each call against deterministic patterns
and compiled SigmaHQ rules, then allow it, inject context, prompt you, or block it. Enforcement
is in code, not model discretion.

**Docs: [magonia-research.github.io/forcefield-docs](https://magonia-research.github.io/forcefield-docs/)**

## Install

```bash
git -c core.hooksPath=/dev/null clone --no-recurse-submodules \
    https://github.com/Magonia-Research/ForceField.git
```

That is longer than `git clone` on purpose, and it is the same command ForceField will ask you
for the next time you clone anything: hooks cannot run out of the repository being fetched, and
no config level can recurse submodules behind you. See
[the clone redirect](docs/threat-model.md#the-clone-redirect).

The repo ships `.claude-plugin/marketplace.json`, so add the checkout as a marketplace rather
than as a plugin directory:

```
/plugin marketplace add /path/to/ForceField
/plugin install forcefield@magonia-research
```

That is the whole install. Every guard except the Sigma engine works immediately.

**Optional, for SigmaHQ rules.** Creates a venv for the compiler and clones SigmaHQ. The engine
silently no-ops until this runs.

```bash
cd /path/to/ForceField && ./scripts/install.sh
```

The venv and compiled rules go to `~/.claude/forcefield/sigma/`, not into the plugin directory,
which is a cache that every reinstall replaces. Run it once, not once per update.

**Requirements:** `python3` (3.9 or newer) and `bash`. No `requirements.txt`, on purpose: a guard
that cannot run because a dependency failed to resolve is a guard that is not running.

## Pick a posture

Ships as `balanced`: every blocking guard at full strength, with a Sigma match softened from a
prompt to a logged warning.

```bash
scripts/posture.sh                                     # show what is configured
scripts/posture.sh --preset passive --log findings     # never prompt, log everything that fires
```

`passive` is for unattended work, and the cost is real: every heuristic finding becomes a log line
instead of a question. Read the log either way. The four presets are `balanced`, `strict`,
`permissive` and `passive`; see [configuration](docs/configuration.md).

## What it catches

| Class | Examples | Rung |
|---|---|---|
| [Clone-time repo takeover](docs/threat-model.md#repository-takeover-at-clone-time) | CVE-2024-32002 and CVE-2025-48384 submodule surface, 17 RCE-capable git config keys, `.git/hooks` writes | ask, graded on evidence |
| | Any `git clone` that has not disarmed that surface | ask, with the hardened command |
| | `git clone ext::`, which hands its URL to a shell | **deny** |
| [Data exfiltration](docs/threat-model.md#data-exfiltration) | Relay and tunneling domains, netcat, `/dev/tcp` reverse shells | **deny** |
| | Data POSTs, DNS-label encoding, cloud metadata SSRF, `scp`/`rsync` | ask |
| [Supply chain](docs/threat-model.md#supply-chain) | Fetch piped into a shell | **deny** |
| | Typosquats by edit distance, arbitrary-URL installs, plaintext registries | ask |
| [Prompt injection](docs/threat-model.md#indirect-prompt-injection) | Role manipulation, fake system tags, zero-width characters in file content | warn + context |
| [Credential disclosure](docs/threat-model.md#credential-disclosure) | Keys in prompts, file writes, credential-store reads | block / ask |
| | Keys in tool output, and in the log itself | redact |
| [Excessive agency](docs/threat-model.md#excessive-agency) | Credentials in subagent prompts, spawn rate limit | **deny** |
| [MCP tool poisoning](docs/threat-model.md#mcp-tool-poisoning) | Credential and exfil patterns in any tool's arguments | ask |

Commands are shell-normalized before matching, so `${IFS}`, backslash escapes and intra-word
quoting do not evade a pattern.

**Findings on the clone-time surface are graded on measured evidence, not command shape.**
`git_guard` checks the host's git version against each advisory's per-branch fix set, reads
`.gitmodules` where it exists, and can fetch it from an allowlisted forge without cloning. A
recursive clone stops prompting on a patched host and hard-denies when the repository carries an
actual exploit signature. See [how a finding is graded](docs/threat-model.md#how-a-git-finding-is-graded).

**`/forcefield:inspect <url>` reads a repository before you clone it**, covering the self-hosted
and SSH remotes the in-hook fetch will not touch. It uses `--no-checkout`, because both CVEs fire
during checkout. A recorded `DO NOT CLONE` then denies the clone itself rather than prompting on it.

**Every other clone is redirected, not judged.** A plain `git clone` prompts, and the reason
carries the command that would not have — the one in [Install](#install), with your URL spliced
in. Run that and there is no prompt. It does not stop on a patched git, because disabling hooks
and refusing submodule recursion are not patches for either CVE.

## Check what a hook decides

Feed any hook event JSON on stdin. Empty stdout means allow.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git submodule update --init --recursive"},"hook_event_name":"PreToolUse"}' \
  | python3 hooks/security_dispatcher.py
```

On a patched host that does not prompt at all. There is no `permissionDecision`, only context,
because the prompt would have cited a bug that cannot fire there:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
 "additionalContext": "ForceField security finding (advisory - the call was not blocked): GIT GUARD: submodule_update (context only)\n\nMatched: git submodule update --init\ngit 2.50.1 is patched for CVE-2024-32002 and CVE-2025-48384, so the clone-time RCE path is closed here.\n\nStill treat the repository's contents as untrusted: a clean .gitmodules says nothing about what the code does once you run it."}}
```

A clone is the one shape where a patched git is not the whole answer, so it prompts on any host —
and says what to run instead:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git clone https://github.com/example/repo.git"},"hook_event_name":"PreToolUse"}' \
  | python3 hooks/security_dispatcher.py | python3 -c 'import json,sys; print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecisionReason"].rsplit("Run instead:",1)[-1])'
```

```
  /forcefield:inspect https://github.com/example/repo.git
  git -c core.hooksPath=/dev/null clone --no-recurse-submodules https://github.com/example/repo.git
```

## Read the log

Records are OpenTelemetry logs carrying an OCSF Detection Finding projection, written to
`~/.claude/hooks/security.log` as JSON Lines, plus the macOS unified log, journald or syslog where
available.

```bash
# Detections that did not enforce: config downgraded, allowlisted, or remembered
jq -c 'select(.Attributes."forcefield.config_downgraded" == true
              or .Attributes."forcefield.suppressed" == true
              or .Attributes."forcefield.memo_hit" == true)' ~/.claude/hooks/security.log

# Which guard drives your friction, most frequent first
jq -r '[.Attributes."forcefield.guard", .Attributes."forcefield.decision"] | @tsv' \
    ~/.claude/hooks/security.log | sort | uniq -c | sort -rn
```

The file sink rotates in-process at a hard size ceiling. On Linux you can hand it to `logrotate`
as well, as yourself, with no root:

```bash
scripts/rotation-config.sh              # print the stanza
scripts/rotation-config.sh --install    # write it to ~/.config/forcefield/
```

On macOS the same command explains why there is nothing to install, since `newsyslog` refuses any
config unless it is running as root, and states the in-process ceiling that stands instead.

## Documentation

| Page | What is in it |
|---|---|
| [Threat model](docs/threat-model.md) | Each attack class, the hooks that cover it, a real log record, and the primary disclosure it comes from |
| [Hook reference](docs/hooks.md) | All 23 registrations, which 10 of Claude Code's 31 events they use and why not the other 21, the decision ladder, precedence, fail-open |
| [Configuration](docs/configuration.md) | Trust levels, presets, per-rung mode maps, allowlists, remembered approvals, known friction |
| [Architecture](docs/architecture.md) | Hook contract, Sigma pipeline, command normalization, file map, test suites |
| [Log reference](docs/logging/) | Record schema, one measured record per hook, worked `jq` queries, known gaps |

## Scope

ForceField gates the tool calls Claude Code exposes to a hook. It does not sandbox the agent, does
not inspect what the model is thinking, and does not gate anything reached through a tool it is
not registered for. Four limits are worth knowing before you rely on it:

- **Hooks are fail-open.** A guard that crashes or times out does not block the call, because a
  security hook that breaks legitimate work gets uninstalled. Run ForceField alongside a sandbox,
  not instead of one.
- **Guards are heuristics over text.** They match commands, not intent. A novel encoding or a
  payload assembled at runtime will pass.
- **Configuration can only loosen.** The clamp moves a decision down the ladder and can never
  fabricate a stricter one. A project-level config file, which a cloned repo can ship, caps at
  `ask`.
- **Under `bypassPermissions` you get deny-only enforcement.** A hook `ask` is discarded rather
  than shown. A hook `deny` is absolute in every mode.

[Scope limits](docs/threat-model.md#scope-limits) gives each of these in full, with the reasoning.

To report a vulnerability in ForceField itself, open a private report through
[GitHub Security Advisories](https://github.com/Magonia-Research/ForceField/security/advisories/new)
rather than a public issue.

## Contributing

Register a new guard in `hooks/hooks.json`, follow the
[hook contract](docs/architecture.md#hook-contract) (fail-open, stdlib-only, allowlist and logging
integration), add assertions to `tests/test_plugin.py`, and update the tables in
[docs/hooks.md](docs/hooks.md). Run every suite before opening a PR:

```bash
for t in tests/test_*.py; do python3 "$t" || break; done
```

`test_docs.py` checks the docs against the tree: cross-links and heading anchors resolve, the file
map and suite table match what ships, every counted claim is read out of the code, and every
documented log record carries the envelope the code actually emits. If you edit `docs/`, run
`scripts/sync-docs.sh` to push the change to the
[published site](https://github.com/Magonia-Research/forcefield-docs), or `--check` to see the
drift.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
