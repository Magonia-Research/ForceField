# Portcullis — Security Hardening Plugin for Claude Code

Claude Code plugin that hardens your instance with layered, defense-in-depth security hooks covering the full attack surface: command execution, file I/O, credential handling, agent spawning, MCP tool calls, prompt injection defense, and output validation — grounded in OWASP LLM Top 10 principles.

## What it does

### Coverage map

```
                          ┌─────────────────────────────┐
                          │     User prompt enters      │
                          │    (UserPromptSubmit)       │
                          │  • Blocks private keys      │
                          │  • Warns on API tokens      │
                          └──────────────┬──────────────┘
                                         │
                          ┌──────────────▼──────────────┐
                          │     Claude processes        │
                          │    (CLAUDE.md rules via     │
                          │     /portcullis:harden)     │
                          └──────────────┬──────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
   ┌──────────▼──────────┐   ┌──────────▼──────────┐   ┌──────────▼──────────┐
   │   Bash (PreToolUse)  │   │  Write/Edit (Pre)   │   │   Agent (Pre)       │
   │  • Container-first   │   │  • Credential guard │   │  • 7 detection      │
   │  • Sigma rules       │   │                     │   │    checks           │
   │  • Exfil/supply      │   │                     │   │  • Constraint       │
   │    chain guard       │   │                     │   │    injection        │
   └──────────┬───────────┘   └─────────────────────┘   └──────────┬──────────┘
              │                                                     │
   ┌──────────▼──────────┐                              ┌──────────▼──────────┐
   │  Bash (PostToolUse)  │                              │   SubagentStop      │
   │  • Output credential │                              │  • Output cred scan │
   │    scanner           │                              │  • Injection detect │
   └──────────────────────┘                              └─────────────────────┘
              │
   ┌──────────▼──────────┐
   │  Read (PostToolUse)  │
   │  • Injection defense │
   └──────────────────────┘
```

### Hooks (enforcement layer)

| Hook | Event | Matcher | Function |
|------|-------|---------|----------|
| Container-First | PreToolUse | Bash | Blocks rm -rf, obfuscation, escape techniques (nsenter/ptrace), kernel manipulation. Asks before over-privileged containers. Enforces container isolation for package installs and interpreters |
| Sigma Engine | PreToolUse | Bash | Evaluates commands against ~100+ SigmaHQ process_creation rules (Linux/macOS, medium+ severity) |
| Security Dispatcher | PreToolUse | Bash | Exfiltration detection (ngrok, netcat, data POST) + supply chain guard (typosquats, pipe-to-shell, unsafe installs) |
| Credential Guard | PreToolUse | Write / Edit | Detects API keys, tokens, private keys, and passwords in file writes |
| MCP Guard | PreToolUse | mcp__.\* | Detects credential/exfil patterns in MCP tool arguments (network-capable tools only) |
| Agent Guard | PreToolUse | Agent | Enforces least-privilege agent spawning: blocks credential leakage, detects prompt injection, dangerous modes, excessive privilege, sensitive paths, prompt size. Injects security constraints into subagent prompts. Rate-limits spawns |
| Output Credential Scanner | PostToolUse | Bash | Scans command output for leaked credentials. Redacts high-confidence matches (AWS, GitHub, Anthropic keys, private keys). Warns on low-confidence. Skips safe commands and intentional credential searches |
| Injection Defense | PostToolUse | Read | Detects indirect prompt injection in file contents: role manipulation, fake system tags, instruction overrides, fake approvals, unicode/zero-width chars, hidden HTML directives. Warns Claude to treat file instructions as data |
| Subagent Stop Guard | SubagentStop | — | Validates subagent output before parent trusts it: blocks credential leaks, detects injection targeting parent, embedded commands, exfiltration staging |
| Prompt Credential Guard | UserPromptSubmit | — | Blocks private keys pasted into chat. Warns Claude not to echo high-confidence API tokens. Suggests environment variable alternatives |
| Sigma Update | SessionStart | — | Auto-updates SigmaHQ rules (24h cooldown) |
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
| LLM06 | Sensitive Information Disclosure | Credential guard (write), output scanner (read), prompt credential guard (user input), agent guard (prompts) |
| LLM08 | Excessive Agency | Agent guard (mode checks, privilege patterns, rate limiting, constraint injection), container-first |

### Decision model

- **deny** — Zero-FP patterns hard-block without user prompt (exfil domains, netcat, pipe-to-shell, rm -rf, obfuscation, escape techniques, kernel manipulation, high-confidence credentials in agent prompts, spawn rate limit exceeded)
- **ask** — User must explicitly approve (data POST, typosquats, dangerous installs, credential patterns, over-privileged containers, host package installs, agent prompt injection, dangerous agent modes, excessive privilege, sensitive paths, subagent output anomalies)
- **redact** — Credential values replaced in-place with `[REDACTED: pattern_name]` in command output (high-confidence only, preserves surrounding context)
- **warn (systemMessage)** — Context injected for Claude: credential handling reminders, prompt injection warnings on file reads, low-confidence pattern alerts
- **allow + context** — Soft reminder shown to Claude (interpreter on host, container suggestion, security constraints injected into subagent prompts)

### Hook event coverage

| Event | When it fires | What Portcullis does |
|-------|---------------|----------------------|
| PreToolUse | Before any tool executes | Gates dangerous commands, file writes, MCP calls, agent spawns |
| PostToolUse | After a tool returns output | Scans Bash output for credential leaks, Read output for injection |
| UserPromptSubmit | When user sends a message | Catches pasted credentials before they enter conversation |
| SubagentStop | When a subagent completes | Validates output before parent acts on it |
| SessionStart | Session begins | Updates sigma rule database (24h cooldown) |
| Stop | Session ends | Security hygiene checklist reminder |

### Hooks vs. CLAUDE.md rules

| Layer | Mechanism | What it covers |
|-------|-----------|----------------|
| Hooks | Block/prompt/redact at execution time | Exfiltration, credential writes/reads, dangerous commands, supply chain, agent spawning, output validation |
| CLAUDE.md | Behavioral instructions | Response content, decision-making, data minimization, prompt injection defense, multi-step attack awareness |

Hooks enforce hard boundaries. CLAUDE.md rules cover what hooks physically cannot — Claude's own judgment when generating responses, handling external data, and writing code. Both layers are needed because hooks are fail-open by design.

### Precedence

When multiple hooks fire on the same tool call, Claude Code uses: `deny > ask > allow`. The security dispatcher runs both exfil and supply chain guards and returns the highest-precedence result.

### Fail-open design

All hooks are fail-open: if a hook crashes, times out, or produces invalid output, the command proceeds. Security hooks should never block legitimate work due to their own bugs.

The agent guard uses a **two-phase fail-open**: it parses input and builds the security constraint response first (cheap, can't crash), then runs detection checks (may crash). If detection crashes, the constraint response is still returned — so subagents always get security constraints even on hook failure.

## Components

```
.claude-plugin/plugin.json           Plugin metadata
skills/harden/SKILL.md               /portcullis:harden skill
hooks/hooks.json                     Hook registration (matchers, timeouts)
hooks/container_first.sh             Container-first enforcement (bash/jq)
hooks/sigma_engine.py                 SigmaHQ rule evaluator (stdlib only)
hooks/sigma_compiler.py              Compiles sigma YAML -> JSON (requires pyyaml venv)
hooks/sigma_update.sh                Auto-updates rules on session start
hooks/security_dispatcher.py         Exfil + supply chain consolidated dispatcher
hooks/exfil_guard.py                 Data exfiltration pattern detection
hooks/supply_chain_guard.py          Typosquat + dangerous install detection
hooks/credential_guard.py            Credential leak detection in file writes
hooks/mcp_guard.py                   MCP tool argument monitoring
hooks/agent_guard.py                 Agent spawn security guard (PreToolUse)
hooks/subagent_stop_guard.py         Subagent output validation (SubagentStop)
hooks/output_credential_scanner.py   Bash output credential scanner (PostToolUse)
hooks/injection_defense.py           Indirect prompt injection defense (PostToolUse)
hooks/prompt_credential_guard.py     User prompt credential paste detection (UserPromptSubmit)
hooks/stop_checklist.py              Security completion checklist at session end
hooks/hook_logging.py                Shared logging (macOS Unified Log + syslog + file)
hooks/allowlist.py                   Per-project suppression via .claude/hook-allowlist.json
scripts/install.sh                   Post-install setup (venv + sigma compilation)
scripts/uninstall.sh                 Cleanup (removes venv + compiled rules)
tests/test_plugin.py                 Integration tests (41 test assertions)
tests/test_sigma_engine.py            Sigma engine test suite
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

```bash
# macOS Unified Log — all hook events from last hour
log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' --last 1h --style ndjson

# macOS — only deny decisions
log show --predicate 'subsystem == "com.anthropic.claude-code.hooks" AND composedMessage CONTAINS "deny"' --last 1h

# macOS — credential redaction events
log show --predicate 'subsystem == "com.anthropic.claude-code.hooks" AND composedMessage CONTAINS "redact"' --last 1h

# Linux journald
journalctl -t cc-security --since "1 hour ago" -o json-pretty

# Fallback file (JSON Lines)
tail -f ~/.claude/hooks/security.log
jq -c 'select(.decision == "deny")' ~/.claude/hooks/security.log
jq -c 'select(.hook == "agent_guard")' ~/.claude/hooks/security.log
```

## Requirements

- Python 3.9+ (3.10+ recommended)
- jq (for container-first hook)
- Git (for sigma rule updates)
- Claude Code

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
