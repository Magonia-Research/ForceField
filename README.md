# Portcullis — Security Hardening Plugin for Claude Code

Claude Code plugin that hardens your instance with layered, defense-in-depth security hooks covering the full attack surface: command execution, file I/O, credential handling, agent spawning, MCP tool calls, prompt injection defense, and output validation — grounded in OWASP LLM Top 10 principles.

## What it does

### Coverage map

```
              ┌─────────────────────────────────────────────┐
              │  UserPromptSubmit                           │
              │  • blocks pasted private keys, warns on tokens │
              └───────────────────────┬─────────────────────┘
                                      │
              ┌───────────────────────▼─────────────────────┐
              │  Claude processes                           │
              │  (CLAUDE.md rules via /portcullis:harden)   │
              └───────────────────────┬─────────────────────┘
                                      │
  ── PreToolUse — gate before the call ───────────────────────────────────
     Bash        → container-first · sigma · exfil · supply-chain · git · cred-read
     Write/Edit  → credential-leak scan · filesystem destination guard
     Read        → filesystem credential-store gate
     WebFetch    → outbound URL: SSRF / exfil-domain / encoded-blob
     mcp__*      → credential + exfil scan of tool arguments
     Agent       → least-privilege checks + subagent constraint injection

  ── PostToolUse — inspect the result ────────────────────────────────────
     Bash          → output credential scan + redact
     Read          → injection defense + output credential scan + redact
     Agent|SendMsg → parent-targeting injection / credential-leak scan

  ── Session lifecycle ───────────────────────────────────────────────────
     SessionStart → sigma rule update (24h) · re-inject security baseline
     SubagentStop → validate subagent output before the parent trusts it
     PreCompact / SessionEnd / Stop → compaction audit · cleanup · checklist

  Every gating/prompting guard's decision is clampable by the tiered
  strictness config (deny > ask > redact > warn > allow > off); see below.
```

### Hooks (enforcement layer)

| Hook | Event | Matcher | Function |
|------|-------|---------|----------|
| Container-First | PreToolUse | Bash | Blocks rm -rf, obfuscation, escape techniques (nsenter/ptrace), kernel manipulation. Asks before over-privileged containers. Enforces container isolation for package installs and interpreters |
| Sigma Engine | PreToolUse | Bash | Evaluates commands against compiled SigmaHQ process_creation rules (Linux/macOS, medium+ severity; ~106 by default). On a match it **asks** — never a hard block, since the rules are broad heuristics. Config-tunable per preset (ask/warn decision and severity floor) |
| Security Dispatcher | PreToolUse | Bash | Exfiltration detection (ngrok, netcat, reverse shell via `/dev/tcp`, data POST, DNS-label exfil, cloud-metadata SSRF, scp/rsync/sftp to remote, curl upload, push-to-URL) + supply chain guard (typosquats, fetch-to-shell via pipe / `$(...)` / `<(...)`, unsafe installs) + git guard (recursive submodule clones and `submodule update --init` per CVE-2024-32002 / CVE-2025-48384, `git config` / `-c` / `--config` RCE primitives, `GIT_*` env RCE, `.git/hooks` and `.git/config` writes) + credential-file read guard (asks before `cat`/`head`/`bat`/`strings`/`xxd` of `.env`, `~/.ssh`, `~/.aws`, `.npmrc`, keychains, ...) |
| Credential Guard | PreToolUse | Write / Edit | Detects API keys, tokens, private keys, and passwords in file writes |
| Filesystem Guard | PreToolUse | Write / Edit / MultiEdit / NotebookEdit / Read | Guards the *destination path* of a write (credential stores, shell/login init files, persistence locations, `/etc`, and Portcullis' own config under `$CLAUDE_PLUGIN_ROOT`) and gates reads of credential stores. Path canonicalization (expanduser/expandvars/realpath) resists `../` and symlink evasion. All findings **ask** |
| MCP Guard | PreToolUse | mcp__.\* | Detects credential/exfil patterns in MCP tool arguments. Scans every `mcp__*` tool by default (any server can be an exfil channel); the network-capable prefix list is a severity hint, not the scan gate |
| Agent Guard | PreToolUse | Agent | Enforces least-privilege agent spawning: blocks credential leakage, detects prompt injection, dangerous modes, excessive privilege, sensitive paths, prompt size. Injects security constraints into subagent prompts. Rate-limits spawns |
| WebFetch Guard | PreToolUse | WebFetch | Inspects the outbound URL before the fetch leaves the host. Denies known exfil/tunneling domains (ngrok, webhook.site, interact.sh, ...); asks on embedded credentials, base64/hex blobs, sensitive-keyword params, or overlong values in the query string |
| Output Credential Scanner | PostToolUse | Bash, Read | Redacts high-confidence credentials in tool output in place (AWS `AKIA`/`ASIA`, GitHub `ghp_`/`gho_`/`ghs_`, GitLab `glpat-`, npm, Anthropic keys, private keys); warns on low-confidence. On Bash it scans command output (skipping intentional credential searches); on Read it scans the returned file content, so a live secret in a file is redacted before it reaches the transcript |
| Injection Defense | PostToolUse | Read | Detects indirect prompt injection in file contents: role manipulation, fake system tags, instruction overrides, fake approvals, unicode/zero-width chars, hidden HTML directives, AI-addressed text, fake conversations, prompt-extraction, mode-escalation. Warns Claude to treat file instructions as data |
| Subagent Stop Guard | SubagentStop | — | Validates subagent output before parent trusts it: credential leaks, injection targeting parent, embedded commands, exfiltration staging. Emits a Stop-family `{"decision":"block"}` so the reason is fed back to the parent |
| Agent Output Guard | PostToolUse | Agent \| SendMessage | Scans a subagent's returned text and inter-agent SendMessage payloads for parent-targeting injection, leaked credentials, embedded commands, and exfiltration staging; warns the parent (systemMessage) to treat the output as untrusted data |
| Prompt Credential Guard | UserPromptSubmit | — | Blocks private keys pasted into chat. Warns Claude not to echo high-confidence API tokens. Suggests environment variable alternatives |
| Sigma Update | SessionStart | — | Auto-updates SigmaHQ rules (24h cooldown) |
| Session Baseline | SessionStart / PreCompact | — | Re-injects the security baseline (TIER 0-3 instruction hierarchy) at every session start, so it survives compaction (SessionStart fires on the `compact` trigger). On PreCompact, logs the compaction event (non-blocking, never blocks compaction) |
| Session Cleanup | SessionEnd | — | Removes this session's agent-spawn state and sweeps stale spawn files (>24h) left by crashed sessions |
| Stop Checklist | Stop | — | Security hygiene reminder at session end (secrets, containers, temp files) |

### Skill: `/portcullis:harden`

Injects behavioral security rules into your project's `CLAUDE.md` that hooks **cannot** enforce — things like:

- **Secret handling in output** — never echo credentials back in responses
- **Indirect prompt injection defense** — refuse instructions embedded in fetched content
- **MCP data minimization** — send only minimum data to external tools
- **Credential placeholders** — use env vars, never hardcode realistic-looking secrets
- **Multi-step attack awareness** — detect chained requests that combine into exfiltration

Run `/portcullis:harden` in any project to add these rules to that project's CLAUDE.md.

## Install

### As a Claude Code plugin

```bash
# Clone the repo
git clone https://github.com/Magonia-Research/Portcullis.git

# Add to Claude Code (use the local path)
# In Claude Code: /plugins add /path/to/Portcullis
```

### Enable sigma rule auto-updates (optional)

```bash
cd /path/to/Portcullis
./scripts/install.sh
```

This creates a Python venv for the sigma compiler and clones SigmaHQ rules. Without this step, the plugin works with all guards except sigma rule matching.

## Security Architecture

### OWASP LLM Top 10 coverage

| OWASP ID | Threat | Portcullis defense |
|----------|--------|---------------------|
| LLM01 | Prompt Injection | Injection defense (PostToolUse[Read]), agent guard injection patterns, CLAUDE.md rules |
| LLM02 | Insecure Output Handling | Output credential scanner, subagent stop guard, injection defense |
| LLM06 | Sensitive Information Disclosure | Credential guard (write), output scanner (Bash + Read output), filesystem guard (credential-store reads), prompt credential guard (user input), agent guard (prompts) |
| LLM08 | Excessive Agency | Agent guard (mode checks, privilege patterns, rate limiting, constraint injection), container-first |

### Decision model

- **deny** — Zero-FP patterns hard-block without user prompt (exfil domains, netcat, reverse shell via `/dev/tcp`, fetch-to-shell via pipe / `$(...)` / `<(...)`, rm -rf, hex/octal-escape obfuscation, escape techniques, kernel manipulation, high-confidence credentials in agent prompts, spawn rate limit exceeded)
- **ask** — User must explicitly approve (data POST, DNS-label exfil, cloud-metadata SSRF, scp/rsync/sftp to remote, curl upload, git push to a URL, typosquats, dangerous installs, download-then-run, credential patterns, reading a credential file (`.env`, `~/.ssh`, `~/.aws`, keychains, ...), a write to a guarded destination (shell init, persistence, `/etc`, plugin config), a SigmaHQ rule match, over-privileged containers, host package installs, recursive submodule clones and `submodule update --init`, git config RCE primitives (`core.hooksPath` / `core.sshCommand` / `credential.helper` / ...), `GIT_*` env RCE, `.git/hooks` and `.git/config` writes, agent prompt injection, dangerous agent modes, excessive privilege, sensitive paths, subagent output anomalies)
- **redact** — Credential values replaced in-place with `[REDACTED: pattern_name]` in command output (high-confidence only, preserves surrounding context)
- **warn (systemMessage)** — Context injected for Claude: credential handling reminders, prompt injection warnings on file reads, low-confidence pattern alerts
- **allow + context** — Soft reminder shown to Claude (interpreter on host, container suggestion, security constraints injected into subagent prompts)

The full intrusiveness ladder, used by the config clamp below, is `deny > ask > redact > warn > allow > off`.

### Tiered strictness configuration

By default every gating guard runs at full strength — its natural maximum decision — so Portcullis ships strict and never weakens itself silently. To trade strictness for less friction on a machine or a project, add a `portcullis.json`. Config can only ever **loosen** a guard down the ladder above; it can never fabricate a stricter block, so the zero-false-positive-deny guarantee holds through any configuration.

Two sources, separated by trust:

| File | Trust | May |
|------|-------|-----|
| `~/.claude/portcullis.json` | trusted — only you can write your home dir | loosen any guard to any rung, including fully disabling one (`allow` / `off`); scope overrides to a path via a `projects` map |
| `<project>/.claude/portcullis.json` | untrusted — a cloned repo may ship it | soften a blocking guard only as far as `ask` — never `warn` / `allow` / `off`, so a hostile repo cannot blind the guard standing between it and exfiltration |

```json
{
  "preset": "balanced",
  "guards": {
    "webfetch_guard": { "mode": "ask" },
    "sigma_engine":   { "mode": "warn", "severity_floor": "high" }
  },
  "projects": {
    "/path/to/a/trusted/repo": { "preset": "permissive" }
  }
}
```

Presets: **strict** (identical to the full-strength default), **balanced** (softens the two highest-false-positive blocking guards to `ask` and the heuristic Sigma engine to `warn`), **permissive** (prompts for everything, blocks nothing). A per-guard `mode` overrides the preset; `severity_floor` (`low`/`medium`/`high`) tunes which Sigma rules can fire. Anything missing, unknown, or malformed fails open to the built-in default. The eleven gating guards are configurable; the advisory/output guards (injection defense, output scanner, prompt/subagent credential guards) are always-on and cannot be silenced by any config.

### Hook event coverage

| Event | When it fires | What Portcullis does |
|-------|---------------|----------------------|
| PreToolUse | Before any tool executes | Gates dangerous Bash commands, file writes and their destinations, credential-store reads, MCP calls, agent spawns, and outbound WebFetch URLs |
| PostToolUse | After a tool returns output | Redacts credential leaks in Bash output and Read file content in place, scans Read content for injection, and scans Agent/SendMessage output for parent-targeting injection |
| UserPromptSubmit | When user sends a message | Catches pasted credentials before they enter conversation |
| SubagentStop | When a subagent completes | Validates output before parent acts on it |
| SessionStart | Session begins (incl. after compaction) | Updates sigma rule database (24h cooldown); re-injects the security baseline |
| PreCompact | Before a manual or auto compaction | Logs the compaction event (non-blocking) |
| SessionEnd | Session ends | Cleans up per-session agent-spawn state |
| Stop | Session ends | Security hygiene checklist reminder |

### Hooks vs. CLAUDE.md rules

| Layer | Mechanism | What it covers |
|-------|-----------|----------------|
| Hooks | Block/prompt/redact at execution time | Exfiltration, credential writes/reads, dangerous commands, supply chain, agent spawning, output validation |
| CLAUDE.md | Behavioral instructions | Response content, decision-making, data minimization, prompt injection defense, multi-step attack awareness |

Hooks enforce hard boundaries. CLAUDE.md rules cover what hooks physically cannot — Claude's own judgment when generating responses, handling external data, and writing code. Both layers are needed because hooks are fail-open by design.

### Precedence

When multiple hooks fire on the same tool call, Claude Code uses `deny > ask > allow`. The security dispatcher runs the exfil, supply-chain, git, and credential-read guards in one process and returns the highest-precedence result; a hard-deny from any of them bypasses per-project suppression.

### Fail-open design

All hooks are fail-open: if a hook crashes, times out, or produces invalid output, the command proceeds. Security hooks should never block legitimate work due to their own bugs.

The agent guard uses a **two-phase fail-open**: it parses input and builds the security constraint response first (cheap, can't crash), then runs detection checks (may crash). If detection crashes, the constraint response is still returned — so subagents always get security constraints even on hook failure.

## Components

```
.claude-plugin/plugin.json           Plugin metadata
skills/harden/SKILL.md               /portcullis:harden skill
hooks/hooks.json                     Hook registration (matchers, timeouts)
hooks/container_first.sh             Container-first enforcement (bash/jq)
hooks/sigma_engine.py                 SigmaHQ rule evaluator; asks on match, config-clamped (stdlib only)
hooks/sigma_compiler.py              Compiles sigma YAML -> JSON (requires pyyaml venv)
hooks/sigma_update.sh                Auto-updates rules on session start
hooks/security_dispatcher.py         Consolidated Bash dispatcher (exfil + supply chain + git + cred-read)
hooks/exfil_guard.py                 Data exfiltration pattern detection
hooks/supply_chain_guard.py          Typosquat + dangerous install detection
hooks/git_guard.py                   Git clone-time RCE + config-hijack detection (via dispatcher)
hooks/credential_access_guard.py     Credential-file read pre-block (via dispatcher)
hooks/credential_guard.py            Credential leak detection in file writes
hooks/filesystem_guard.py            Write-destination + credential-store-read guard (Write/Edit/Read)
hooks/mcp_guard.py                   MCP tool argument monitoring
hooks/agent_guard.py                 Agent spawn security guard (PreToolUse)
hooks/webfetch_guard.py              Outbound WebFetch URL guard (PreToolUse)
hooks/normalize.py                   Shared command canonicalizer (detection-only)
hooks/subagent_stop_guard.py         Subagent output validation (SubagentStop)
hooks/agent_output_guard.py          Inter-agent output scan (PostToolUse[Agent|SendMessage])
hooks/output_credential_scanner.py   Credential scan + redact for Bash and Read output (PostToolUse)
hooks/injection_defense.py           Indirect prompt injection defense (PostToolUse)
hooks/prompt_credential_guard.py     User prompt credential paste detection (UserPromptSubmit)
hooks/session_baseline.py            Security-baseline re-injection (SessionStart) + compaction audit (PreCompact)
hooks/session_cleanup.py             Per-session state cleanup (SessionEnd)
hooks/stop_checklist.py              Security completion checklist at session end
hooks/hook_logging.py                Shared OTel/OCSF logging + config clamp (Unified Log + syslog + file)
hooks/config.py                      Tiered strictness config (portcullis.json clamp)
hooks/allowlist.py                   Per-project suppression via .claude/hook-allowlist.json
scripts/install.sh                   Post-install setup (venv + sigma compilation)
scripts/uninstall.sh                 Cleanup (removes venv + compiled rules)
tests/test_plugin.py                 Guard-logic integration tests (744 assertions)
tests/test_config.py                 Tiered-config clamp tests (69 assertions)
tests/test_sigma_engine.py            Sigma engine test suite (subprocess)
```

## Per-project allowlists

Create `.claude/hook-allowlist.json` in your project to suppress specific patterns:

```json
{
  "exfil_guard": {
    "suppress_patterns": ["curl_post_data"],
    "suppress_paths": ["src/api/client.py"]
  },
  "credential_guard": {
    "suppress_paths": ["tests/fixtures/**", "**/*.example"]
  },
  "supply_chain_guard": {
    "suppress_patterns": ["global_install"]
  },
  "agent_guard": {
    "suppress_patterns": ["sensitive_path"]
  },
  "output_credential_scanner": {
    "suppress_patterns": ["generic_secret"]
  },
  "injection_defense": {
    "suppress_patterns": ["role_manipulation"],
    "suppress_paths": ["docs/security/**"]
  }
}
```

## Querying security logs

Every decision is written as one OpenTelemetry log record carrying an OCSF Detection Finding projection in its `Attributes` (`ocsf.class_uid` 2004). Severity is normalized once, so a filter never has to text-match a decision: `deny`/`block` → `SeverityText` `ERROR` / `ocsf.severity_id` 4, `redact` → `WARN`/3, `ask` → `WARN`/3, `warn` → `WARN`/2, `allow` → `INFO`/1. An unknown decision reports at `WARN`, never a silent `INFO`.

```bash
# Fallback file (JSON Lines) — one OTel record per line
tail -f ~/.claude/hooks/security.log

# High-severity findings (deny/block) by OCSF severity — not a fragile text match
jq -c 'select(.Attributes."ocsf.severity_id" >= 4)' ~/.claude/hooks/security.log

# By OTel severity text, by decision, or by guard
jq -c 'select(.SeverityText == "ERROR")' ~/.claude/hooks/security.log
jq -c 'select(.Attributes."portcullis.decision" == "redact")' ~/.claude/hooks/security.log
jq -c 'select(.Attributes."portcullis.guard" == "agent_guard")' ~/.claude/hooks/security.log

# Calls that the tiered config loosened (records the natural decision it came from)
jq -c 'select(.Attributes."portcullis.config_downgraded" == true)' ~/.claude/hooks/security.log

# macOS Unified Log — all hook events from the last hour
log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' --last 1h --style ndjson

# Linux journald
journalctl -t cc-security --since "1 hour ago" -o json-pretty
```

## Requirements

- Python 3.9+ (3.10+ recommended)
- jq (for container-first hook)
- Git (for sigma rule updates)
- Claude Code

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
