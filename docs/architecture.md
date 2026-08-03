# Architecture

Two defense layers. Hooks enforce hard boundaries at execution time; the `/forcefield:full-power-to-shields` skill
injects behavioral rules into a project's `CLAUDE.md` for what hooks physically cannot check. Both
exist because hooks are [fail-open](hooks.md#fail-open).

## Hook contract

Every guard follows the same contract.

**Transport.** stdin carries hook-event JSON (`tool_name`, `tool_input`, `hook_event_name`). stdout
carries either nothing (allow) or JSON with `hookSpecificOutput.permissionDecision`
(`deny` / `ask` / `allow`) plus `permissionDecisionReason`, and/or a `systemMessage` injected as
context for Claude.

**Decisions route through `clamp_and_emit`.** Every gating guard passes its decision to
`hook_logging.clamp_and_emit`, which applies the tiered [config](configuration.md) ceiling before
building the response and logging it, then checks for a remembered approval. It logs the *clamped*
decision and adds `forcefield.natural` plus `forcefield.config_downgraded` when the two differ, so
the log records what was detected as well as what was enforced. The clamp is downgrade-only.

**Fail-open is an invariant.** A crash, timeout or invalid output must never block the tool call. No
exception may escape a guard. The 5s timeout is part of the same boundary: a hook killed mid-scan
never delivers its verdict, so anything that can provoke a failure is a bypass. The dispatcher
isolates each guard, bounds the text it scans to the first 8 KiB, and turns "I could not fully
inspect this" into an `ask` rather than a silent pass.

**Stdlib only at runtime.** Hooks run under the user's system `python3` with a **3.9 floor**: no
`match` statements, no `X | Y` unions in runtime code. There is no `pyproject.toml` or
`requirements.txt`, on purpose: a security hook that cannot run because a dependency failed to
resolve is a security hook that is not running. The single exception is `sigma_compiler.py`, which
needs `pyyaml` and only runs inside the venv `scripts/install.sh` creates.
`container_first.sh` additionally requires `jq`.

**`hooks/` is not a package.** Shared modules are imported after
`sys.path.insert(0, str(Path(__file__).parent))`.

**Logic is importable; plumbing lives in `main()`.** Guard logic sits in functions
(`run_exfil_guard`, `check_content`, `check_git`, …) so the tests can import and call them directly.
The dispatcher-only guards expose importable functions and have no `main()` at all;
`security_dispatcher.py` owns their stdin/stdout, suppression and logging.

**`patterns.py` is the shared bottom of the import graph.** `CREDENTIAL_PATTERNS` lives there and is
re-exported by `credential_guard`, because every guard imports `hook_logging` and the reverse edge
would be a cycle.

## Sigma pipeline

Offline compile, online evaluate.

```
SessionStart ──► hooks/sigma_update.sh          (24h cooldown via stamp file)
                   │
                   ├─► git pull ~/.sigma-rules            ($SIGMA_REPO)
                   └─► sigma_compiler.py  (venv, pyyaml)
                          │
                          └─► ~/.claude/forcefield/sigma/rules.json    (106 rules)
                                 │
PreToolUse[Bash] ──► hooks/sigma_engine.py  (stdlib only) ──► ask on match
```

If the compiled rules are absent the engine silently no-ops, so the plugin works without ever
running `install.sh`. A match emits `ask`, never a hard deny, because the rules are broad heuristics
written for endpoint telemetry, not for a developer shell. `config.py` supplies both the decision
ceiling and the runtime `severity_floor` that drops rules below the floor.

The venv and compiled rules go to `~/.claude/forcefield/sigma/`, not into the plugin directory,
which is a cache that every reinstall replaces.

## Command normalization

`normalize.py` canonicalizes a command before any pattern matches it, so shell obfuscation buys
nothing: `${IFS}` and `$IFS` token separators, backslash escapes (`g\it` → `git`), intra-word
quoting (`gi"t"` → `git`), redundant path slashes (`.git//hooks` → `.git/hooks`) and line
continuations all collapse first.

For a guard whose findings are `ask`, widening a match only adds a prompt, which is why
`git_guard` normalizes aggressively.

## Components

<details markdown="1">
<summary><strong>File map</strong></summary>

```
hooks/hooks.json                     Hook registration (matchers, timeouts)
hooks/security_dispatcher.py         Bash dispatcher: exfil + supply-chain + git + cred-read + self-protection
  hooks/exfil_guard.py                 Data exfiltration patterns
  hooks/supply_chain_guard.py          Typosquats + dangerous installs
  hooks/git_guard.py                   Clone-time RCE + config hijack
  hooks/git_forensics.py               Evidence layer: CVE preconditions, .gitmodules signatures
  hooks/credential_access_guard.py     Credential-file read pre-block
hooks/container_first.sh             Container-first enforcement (bash/jq)
hooks/sigma_engine.py                SigmaHQ evaluator; asks on match (stdlib only)
hooks/sigma_compiler.py              Compiles sigma YAML -> JSON (needs pyyaml venv)
hooks/sigma_update.sh                Rule auto-update on session start
hooks/credential_guard.py            Credential leaks in file writes
hooks/filesystem_guard.py            Write-destination + credential-store-read guard
hooks/mcp_guard.py                   MCP tool argument scanning
hooks/agent_guard.py                 Agent spawn guard + constraint injection
hooks/file_watch_guard.py            FileChanged watcher: sensitive-path changes, in or out of band
hooks/webfetch_guard.py              Outbound WebFetch URL guard
hooks/output_credential_scanner.py   Credential scan + redact (Bash, Read)
hooks/injection_defense.py           Indirect prompt injection defense
hooks/prompt_credential_guard.py     Pasted-credential detection
hooks/subagent_stop_guard.py         Subagent output validation
hooks/permission_outcome.py          PermissionDenied -> permission.outcome record
hooks/agent_output_guard.py          Inter-agent output scan
hooks/repo_audit.py                  SessionStart audit of what this repo can execute
hooks/inspect_remote.py              /forcefield:inspect implementation (pre-clone fetch)
hooks/session_baseline.py            Baseline re-injection + compaction audit
hooks/session_cleanup.py             Per-session state cleanup
hooks/stop_checklist.py              Session-end hygiene checklist
hooks/normalize.py                   Shared command canonicalizer
hooks/shell_context.py               Shell parsing shared by the Bash guards
hooks/patterns.py                    Shared detection + credential patterns
hooks/watch_roots.py                 Concrete paths for the FileChanged watcher
hooks/write_ledger.py                Per-session state: gated writes, self-writes, pending blocks
hooks/hook_event.py                  Explicit stdin decode + correlation ids from the event
hooks/portable_lock.py               Bounded-wait file lock (flock / msvcrt.locking)
hooks/log_sinks.py                   Per-platform sinks, confidentiality, rotation
hooks/hook_logging.py                OTel/OCSF logging + config clamp + memo check
hooks/config.py                      Tiered strictness config
hooks/allowlist.py                   Per-project suppression
hooks/memo.py                        Remembered approvals (ask -> allow) + CLI
.claude-plugin/plugin.json           Plugin metadata
.claude-plugin/marketplace.json      Marketplace manifest
commands/remember.md                 /forcefield:remember command
commands/inspect.md                  /forcefield:inspect command
skills/full-power-to-shields/SKILL.md /forcefield:full-power-to-shields skill
scripts/install.sh                   Setup (venv + sigma compilation)
scripts/posture.sh                   Pick a preset / log level / free-text policy
scripts/rotation-config.sh           Hand the file sink to the OS log rotator
scripts/sync-docs.sh                 Push docs/ to the Pages repo; --check reports drift
scripts/uninstall.sh                 Cleanup
```

</details>

## Testing

Tests are plain executable assert scripts, not pytest. Each file runs top to bottom and stops at the
first failed assert; the only granularity is per file.

```bash
for t in tests/test_*.py; do python3 "$t" || break; done
```

| Suite | Covers |
|---|---|
| `test_plugin.py` | Guard logic, imported in-process |
| `test_config.py` | Tiered-config clamp, and the two HOME-only logging keys |
| `test_sigma_engine.py` | Sigma engine, run as a subprocess per case |
| `test_sigma_compiler.py` | Compiler; skips the round trip without `pyyaml` |
| `test_container_first.py` | `container_first.sh` as a subprocess; skips without `jq` |
| `test_redos.py` | Super-linearity check over every compiled pattern |
| `test_false_positives.py` | Benign corpus: `deny` must never fire on ordinary work |
| `test_warn_rung.py` | The `warn` rung across all 12 config-governed guards |
| `test_reason_scrub.py` | A decision reason never carries a credential value |
| `test_memo_lifecycle.py` | Memo lock contention, forced logging, lifecycle records |
| `test_credential_obfuscation.py` | Credentials the shell reassembles from quoted fragments |
| `test_git_forensics.py` | The git evidence layer: per-branch CVE version comparison, `.gitmodules` signatures, the repo audit, and the raw-fetch host allowlist |
| `test_repo_audit.py` | The SessionStart audit: silence when clean, exploit signatures unsuppressible, fail-open on an unreadable repo |
| `test_inspect.py` | Pre-clone inspection: `ext::`/`file://` refused before git runs, both fetch paths, inconclusive never reported as clean, and a recorded verdict reaching the clone |
| `test_docs.py` | The docs themselves: relative links and heading anchors resolve, the file map and suite table match the tree, every doc is mapped to a site page |
| `test_portability.py` | Every hook imports with the POSIX-only modules blocked, the file lock holds across processes on both backends, the tree parses under the 3.9 grammar, and the Windows Event Log command is built without being run |
| `test_log_sinks.py` | The logging subsystem under failure: every sink degrading, a hard deny surviving inside the hook timeout, the rollover under concurrent processes, every level, and the four record types this rework added |
| `test_verdict_ordering.py` | Every `hooks.json` registration delivers its verdict before it does any logging, measured against a real stalled sink, and the two that cannot are bounded by the process logging budget |
| `test_file_watch.py` | The write ledger's HMAC (forged, unsigned, relocated and memo-signed lines all rejected), self-write suppression in both directions, the watch-root correspondence gate, and the correlation target extractor |
| `_isolated_home.py` | Helper: redirects `$HOME` so tests never touch the real log or memo store |
| `_fake_msvcrt.py` | Helper: a documented-contract stand-in for `msvcrt`, so the Windows lock branch is exercised on POSIX |

`test_sigma_engine.py` skips its match-expecting cases (and stays green) unless the rules have been
compiled by `install.sh`; the benign cases always run.

## Exercising a hook by hand

Feed any hook event JSON on stdin. Empty stdout means allow.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git clone --recursive https://example.com/x.git"},"hook_event_name":"PreToolUse"}' \
  | python3 hooks/security_dispatcher.py
```
