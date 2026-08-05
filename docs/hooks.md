# Hook reference

Twenty-three registrations in `hooks/hooks.json` across twenty scripts. `filesystem_guard`,
`output_credential_scanner` and `session_baseline` each run on two events or matchers. One
process and a 5s timeout each, 10s for the SessionStart Sigma update, fail-open by design. Each
reads hook-event JSON on stdin and writes either nothing (allow) or a decision on stdout.

## Which Claude Code events ForceField uses

Claude Code 2.1.220 exposes **31** registrable hook events. ForceField registers on **10** of
them. The other 21 are listed below with the reason, so the coverage boundary is a decision you
can check rather than an omission you have to infer.

### The 10 in use

| Event | Registrations | What ForceField does there |
|---|---|---|
| `PreToolUse` | 9 | The main gate. Every guard that can stop a call runs here. |
| `PostToolUse` | 4 | Rewrites output and injects context after a tool has run. |
| `UserPromptSubmit` | 1 | Blocks a pasted private key before the prompt reaches the model. |
| `SessionStart` | 3 | Sigma rule update, security baseline, repository audit. |
| `PreCompact` | 1 | Re-injects the instruction hierarchy so it survives summarization. |
| `SessionEnd` | 1 | Per-session state cleanup and the `session.end` record. |
| `SubagentStop` | 1 | Validates subagent output before the parent trusts it. |
| `Stop` | 1 | End-of-turn security hygiene reminder. |
| `PermissionDenied` | 1 | Records the outcome of a call that was denied. |
| `FileChanged` | 1 | Records changes to watched paths, whatever process made them. |

### The 21 not used

| Events | Why not |
|---|---|
| `PermissionRequest` | Fires before the permission dialog. It cannot see the answer, and a second gate in front of the gate adds a prompt without adding a decision. |
| `PostToolUseFailure`, `StopFailure` | A tool that failed did not act. The pre-call gate already ran. |
| `PostToolBatch` | Per-call `PostToolUse` already covers every call in the batch. |
| `SubagentStart` | `PreToolUse[Agent]` is the spawn gate and it can rewrite the child's prompt, which `SubagentStart` cannot. |
| `UserPromptExpansion` | Expansion is Claude Code rewriting the user's own prompt. `UserPromptSubmit` sees the result. |
| `PostCompact` | `PreCompact` re-injects the baseline before the context is summarized, which is the point at which it matters. |
| `Setup`, `ConfigChange`, `InstructionsLoaded` | Configuration and instruction loading. A real surface, since a cloned repo ships `.claude/` files, but `filesystem_guard` gates writes to them and `repo_audit` reports what a repository carries at session start. |
| `Notification`, `MessageDisplay`, `TeammateIdle` | Presentation and idle signalling. No security decision. |
| `Elicitation`, `ElicitationResult` | MCP elicitation. `mcp_guard` gates the tool call itself. |
| `TaskCreated`, `TaskCompleted` | Task bookkeeping, not tool execution. |
| `WorktreeCreate`, `WorktreeRemove`, `CwdChanged`, `DirectoryAdded` | Workspace movement. `repo_audit` runs at session start; a per-directory audit on every move would cost a prompt per `cd`. |

Two of these are worth knowing as gaps rather than decisions. `ConfigChange` and
`InstructionsLoaded` are the surface where a cloned repository's own instruction files reach the
agent, and ForceField covers that at write time and at session start rather than at load time.
An instruction file already on disk when the session opens is reported by `repo_audit`, not
blocked.

## What `FileChanged` sees that nothing else does

It is a filesystem watcher over absolute paths, not a post-write tool callback, so it fires for a
change made by any process at all: a shell redirect, a script the agent wrote and then ran, a
package postinstall, a Makefile, an external editor. Those reach disk without passing
`PreToolUse[Write|Edit]` and without appearing in a command string, so no other registration
observes them.

The event carries no decision channel — its `hookSpecificOutput` accepts only `watchPaths`, and
the watcher settles for 500ms before firing — so `file_watch_guard` records the change and, for
ForceField's own control surface, warns. It never blocks, because it cannot.

`watch_roots.py` supplies the paths, delivered through `SessionStart`'s `watchPaths`. Two shapes,
and the split is forced rather than stylistic: Claude Code watches directories **recursively with
no depth bound**, so credential stores and persistence directories are watched whole (creating a
new file there is itself the threat) while shell init files and individual `/etc` entries are
named one by one (their parent is far too large to watch). `~/.claude` is deliberately not a root
for the same reason: it contains the session transcripts, the plugin cache, and ForceField's own
log, so watching it would mean every record written triggers an event that writes a record.

Each event is classified three ways, from the write ledger rather than from the path: a change is
accounted for by a gated tool call, by ForceField writing its own state, or by nothing. Only the
third is `out_of_band`, and that does not mean malicious — your own editor saving a watched file
lands there too.

## Blocked, then re-routed

A command that gets blocked and whose target is then written through a different tool is a bypass
shape. Measured across two weeks of this project's own logs: 513 blocking decisions, and simple
temporal adjacency matched 41% of them, all of it ordinary unrelated work. Requiring the written
path to appear in the blocked command left 26 pairs, every one of them the same shape and every
one benign.

So the shape is detectable at high precision and says nothing about intent. `filesystem_guard`
and `security_dispatcher` record it always and prompt only when the re-routed target is itself a
protected sink. Over the measured period that split would have prompted zero times while still
covering the case that matters. Correlation is on path only, from shell redirection and explicit
output flags: a blocked command naming no file is not correlated at all.

## Coverage map

```
  UserPromptSubmit ──► pasted private keys blocked, tokens warned
         │
         ▼
  Claude processes ──► CLAUDE.md rules via /forcefield:full-power-to-shields
         │
  ── PreToolUse: gate before the call ───────────────────────────────────
     Bash        → container-first · sigma · exfil · supply-chain · git
                   · cred-read · self-protection
     Write/Edit  → credential-leak scan · filesystem destination guard
     Read        → filesystem credential-store gate
     WebFetch    → outbound URL: SSRF / exfil-domain / encoded-blob
     mcp__*      → credential + exfil scan of tool arguments
     Agent       → least-privilege checks + subagent constraint injection

  ── PostToolUse: inspect the result ────────────────────────────────────
     Bash          → output credential scan + redact
     Read          → injection defense + output credential scan + redact
     Agent|SendMsg → parent-targeting injection / credential-leak scan

  ── Session lifecycle ──────────────────────────────────────────────────
     SessionStart → sigma rule update (24h) · security baseline · repo audit
     SubagentStop → validate subagent output before the parent trusts it
     PermissionDenied → record what happened to a call ForceField asked about
     PreCompact / SessionEnd / Stop → re-inject baseline · cleanup · checklist
```

## Prompt entry

| Hook | Event | What it does |
|---|---|---|
| Prompt Credential Guard | UserPromptSubmit | Blocks pasted private keys, warns on API tokens, suggests env-var alternatives |

## PreToolUse

| Hook | Matcher | What it does |
|---|---|---|
| Container-First | Bash | Denies `rm -rf`, obfuscation, escape techniques (nsenter/unshare/ptrace), kernel manipulation. Asks on over-privileged containers. A host package install or interpreter gets a context-only reminder, never a prompt |
| Sigma Engine | Bash | Evaluates compiled SigmaHQ `process_creation` rules (Linux/macOS, medium and above; 106 by default). Never denies, because the rules are broad heuristics: a match is a natural `ask` that the shipped `balanced` preset softens to a logged warning, and `strict` prompts on. Off until `scripts/install.sh` compiles a ruleset. [What it catches, and its leading-token limit](threat-model.md#known-attacker-behavior-from-sigmahq) |
| Security Dispatcher | Bash | Five guards in one process: **exfil** (relay domains, netcat, `/dev/tcp`, data POST, DNS-label, metadata SSRF, scp/rsync), **supply-chain** (typosquats, fetch-to-shell, arbitrary-URL installs, plaintext registries), **git** ([clone-time RCE](threat-model.md#repository-takeover-at-clone-time), config RCE primitives, `GIT_*` env, `.git/hooks` writes, [graded on measured evidence](threat-model.md#how-a-git-finding-is-graded)), **credential-read** (`.env`, `~/.ssh`, `~/.aws`, keychains), **self-protection** (shell writes to ForceField's and Claude Code's own config). Scans the first 8 KiB and asks on anything longer |
| Credential Guard | Write/Edit | Detects API keys, tokens, private keys and passwords in file writes |
| Filesystem Guard | Write/Edit/MultiEdit/NotebookEdit, and Read | Guards the write *destination* (credential stores, shell init, persistence, `/etc`, plugin config) and gates credential-store reads. Canonicalizes paths to resist `../` and symlink evasion. All findings **ask** |
| MCP Guard | `mcp__.*` | Scans every MCP tool's arguments for credential and exfil patterns. Any server can be an exfil channel |
| Agent Guard | Agent | Least-privilege spawning: blocks credential leakage, detects injection, dangerous modes, excessive privilege, sensitive paths, prompt size. Injects constraints into subagent prompts. Rate-limits spawns over a rolling hour (10 ask, 20 deny), clearable with `agent_guard.py --reset-spawns <session-id>` |
| WebFetch Guard | WebFetch | Denies known exfil and tunneling domains, asks on embedded credentials, encoded blobs, or sensitive query params |

## PostToolUse

| Hook | Matcher | What it does |
|---|---|---|
| Output Credential Scanner | Bash, Read | Redacts high-confidence credentials in place (AWS, GitHub, GitLab, npm, Anthropic, private keys), warns on low-confidence |
| Injection Defense | Read | Detects indirect prompt injection in file contents: role manipulation, fake system tags, instruction overrides, zero-width chars, hidden HTML. Warns Claude to treat file content as data |
| Agent Output Guard | Agent\|SendMessage | Scans subagent and inter-agent output for parent-targeting injection, leaked credentials, embedded commands |

## Session lifecycle

| Hook | Event | What it does |
|---|---|---|
| Sigma Update | SessionStart | Auto-updates SigmaHQ rules on a 24h cooldown |
| Session Baseline | SessionStart, PreCompact | Re-injects the TIER 0 to 3 instruction hierarchy so it survives compaction, and logs compaction without ever blocking it. On SessionStart it also writes the `session.start` record: plugin version, resolved config tier, interpreter, hook roster, compiled-rule state, and what every log sink is doing |
| Repo Audit | SessionStart | Audits the repository the session opened in and reports what it carries: planted git hooks, RCE-capable config keys, submodule signatures. `warn` for a known exploit signature, `warn_low` for an inventory finding |
| Subagent Stop Guard | SubagentStop | Validates subagent output before the parent trusts it. **Blocks** on a credential. Injection, embedded commands and exfil indicators are advisory, because a Stop-family rejection reason is fed back to the model as its next instruction, and a block that quoted the trigger would put it straight into the retry |
| Permission Outcome | PermissionDenied | Records a `permission.outcome` for a denied tool call, so an `ask` in the log has an outcome. Never gates: the call is already denied by the time it runs. Whether the event fires on human denials or only on policy denials is **not established**, so the record carries the event's own `reason` without interpreting it |
| Session Cleanup | SessionEnd | Removes per-session spawn state, sweeps stale files older than 24h, writes the `session.end` record |
| Stop Checklist | Stop | Security hygiene reminder: secrets, containers, temp files. The one registration that writes no log record |

Every gating guard's decision is clampable by the
[tiered strictness config](configuration.md). Every hook's actual log record is in
[records by hook](logging/01-records-by-hook.md).

## Decision model

The intrusiveness ladder, used by the config clamp: `deny > ask > redact > warn > allow > off`.

| Decision | Meaning | Examples |
|---|---|---|
| **deny** | Zero-false-positive patterns, hard-blocked without a prompt | Relay/exfil domains, netcat, `/dev/tcp` reverse shell, fetch-piped-to-shell, `git clone ext::`, `rm -rf`, hex/octal obfuscation, escape techniques, high-confidence credentials in agent prompts, spawn rate limit |
| **ask** | User must approve | Data POST, DNS-label exfil, metadata SSRF, scp/rsync/sftp, curl upload, typosquats, arbitrary-URL or plaintext-registry installs, credential-file reads, guarded write destinations, Sigma match, submodule RCE, git config RCE primitives, an unhardened `git clone`, agent injection or excessive privilege |
| **redact** | Credential values replaced with `[REDACTED: pattern_name]` | High-confidence keys only, surrounding context preserved |
| **warn** | Context injected via `systemMessage` | Credential-handling reminders, injection warnings on file reads, low-confidence alerts |
| **allow + context** | Soft reminder, no gate | Host package install, interpreter on host, subagent constraint injection |

**Why `ask` carries the weight.** Most guards prompt rather than block, precisely so the deny
tier can stay reserved for patterns with no legitimate reading. A guard that hard-denies
something with a real workflow behind it gets the whole plugin uninstalled, and an uninstalled
plugin defends nothing. `git_guard` is the clearest case: `pre-commit` legitimately sets
`core.hooksPath` and monorepos legitimately set `core.fsmonitor`, so those ask. `ext::`, whose
documented purpose is to run its URL as a command, denies.

**One guard grades its rung on evidence.** For the three patterns whose entire rationale is the
two clone-time CVEs, `git_guard` consults `git_forensics` and moves the decision in either
direction: down to `warn` on a patched host, up to `deny` on a measured exploit signature. Full
model: [how a git finding is graded](threat-model.md#how-a-git-finding-is-graded).

**And one finding is a redirect rather than a verdict.** Every `git clone` that has not disarmed
the clone-time execution surface asks, and the reason carries the exact command that would not
have: `git -c core.hooksPath=/dev/null clone --no-recurse-submodules <url>`. Run that and there
is no prompt. It is the only place ForceField answers a finding with a replacement command
instead of a judgement about the one you typed — the friction is meant to be spent once, on
learning the safer spelling. See [the clone redirect](threat-model.md#the-clone-redirect).

## Precedence

Claude Code applies `deny > ask > allow` when several hooks fire on one call. The dispatcher
returns the highest of its five guards, so every guard runs and a lower-severity match can never
pre-empt a hard deny. A hard deny bypasses per-project suppression.

**Under `bypassPermissions` you get deny-only enforcement.** A hook `ask` is discarded rather
than shown, so every finding raised at `ask` passes silently: most of the filesystem, MCP, agent,
git and credential-read checks, and every Sigma match. A hook `deny` is absolute in every mode.
Read from the Claude Code 2.1.220 bundle rather than measured end to end, so treat the exact rung
list as approximate and the shape as reliable.

## Fail-open

A hook that crashes, times out, or emits invalid output never blocks the call. Security hooks
should not break legitimate work through their own bugs. The agent guard is two-phase, building
its constraint-injection response before running detection, so subagents still receive
constraints if detection crashes.

That makes anything which can *provoke* a failure a bypass, so the dispatcher isolates each guard
(one raising costs only its own verdict), bounds the text it scans, and turns "I could not fully
inspect this" into an `ask` rather than a silent pass. The 5s timeout is a security boundary: a
hook killed mid-scan never delivers its verdict, so a computed hard deny becomes a silent allow.

## Skill: `/forcefield:full-power-to-shields`

Injects behavioral rules into a project's `CLAUDE.md` that hooks **cannot** enforce: never
echoing credentials in responses, refusing instructions embedded in fetched content, MCP data
minimization, credential placeholders, and multi-step attack awareness. Both layers exist because
hooks are fail-open.

## Adding or changing a guard

Register it in `hooks/hooks.json`, follow the [hook contract](architecture.md#hook-contract), add
assertions to `tests/test_plugin.py`, and update the tables above.
