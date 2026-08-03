# Configuration

ForceField ships the `balanced` preset: every guard that blocks runs at full strength, and the one
thing it softens is a SigmaHQ rule match, from a prompt to a logged warning.

Config can only **loosen** a guard down the [ladder](hooks.md#decision-model); it can never
fabricate a stricter block, so the zero-false-positive-deny guarantee holds through any
configuration, including a hostile one.

## Two files, two trust levels

| File | Trust | May |
|------|-------|-----|
| `~/.claude/forcefield.json` | **trusted**, since only you write your home directory | Loosen any guard to any rung, including `off`; scope overrides by path via `projects` |
| `<project>/.claude/forcefield.json` | **untrusted**, since a cloned repo may ship one | Soften a blocking guard only as far as `ask` |

> **Why the project file is capped at `ask`:** a repository you have just cloned is exactly the
> thing the guards are watching. If a repo could set `exfil_guard` to `off` in its own checked-in
> config, it would blind the guard standing between it and your credentials before you read a line
> of it. Capping it at `ask` means a hostile repo can add friction at worst; it can never remove the
> human from the loop.

## Format

```json
{
  "preset": "balanced",
  "log_level": "info",
  "log_free_text": "admin",
  "guards": {
    "webfetch_guard": { "mode": "ask" },
    "sigma_engine":   { "mode": "warn", "severity_floor": "high" },
    "git_guard":      { "mode": { "deny": "deny", "ask": "warn" } }
  },
  "projects": {
    "/path/to/a/trusted/repo": { "preset": "permissive" }
  }
}
```

Set it without editing JSON:

```bash
scripts/posture.sh                                     # show what is configured
scripts/posture.sh --preset passive --log findings     # pick a posture
scripts/install.sh --posture passive --log findings    # or during sigma setup
```

## Presets

| Preset | Behaviour |
|--------|-----------|
| `balanced` | **the default**, applied when no config names a preset; `strict` except that a Sigma match warns instead of prompting |
| `strict` | prompts on a Sigma match too, and drops the Sigma severity floor to `low` so more rules fire |
| `permissive` | prompts for everything, blocks nothing |
| `passive` | **never prompts**: every finding becomes a logged warning and work continues, except a known-exploit finding, which still blocks |

## Ceilings and per-rung maps

A plain ceiling clamps every rung at or above it, so setting a blocking guard to `ask` takes its
`deny` down with it, and `deny` fires only on the zero-false-positive tier. That is why no default
preset softens a blocking guard: it would block less than `passive` does.

**Passive** is the posture for unattended or flow-critical work, and the one setting a single
ceiling cannot express. So a `mode` may also be a **per-rung map**:

```json
"git_guard": { "mode": { "deny": "deny", "ask": "warn" } }
```

That is exactly what `passive` sets on every guard. The line it draws is one the guards already
drew, since a guard emits `deny` only for its own hard-deny set and everything heuristic emits `ask`, so
passive just stops turning the heuristics into questions.

> **The cost is real.** Under `passive` every heuristic finding becomes a log line rather than a
> question, so nothing stops an unreviewed action except the hard-deny tier. On the clone-time
> surface the loss is smaller than it used to be, because a recursive clone is already context-only on a
> patched git, and a measured exploit signature in `.gitmodules` still denies, because
> [evidence outranks posture](threat-model.md#how-a-git-finding-is-graded). Read the log.

### Disabling the remote pre-flight

`git_guard` can fetch a remote's `.gitmodules` from an allowlisted forge *without cloning it*, to
decide a fresh clone on content rather than on shape. It is the only place a guard reaches the
network. To turn it off without disabling the guard:

```bash
export FORCEFIELD_NO_REMOTE_INSPECT=1
```

Findings then fall back to host preconditions and on-disk evidence alone, which means a recursive
clone from an unknown repository prompts rather than being cleared. The fetch is already confined to
exactly-matched forge hosts, capped at 1.5s inside the hook's 5s budget, and bounded in response
size; disable it if any outbound request from a hook is unacceptable in your environment.

## Log level

`log_level` is a floor on the OTel `SeverityNumber`, the same ladder the severity table uses, so
there is one ordering rather than two:

| `log_level` | floor | contains |
|---|---|---|
| `debug` | 5 | everything below, plus `guard_ran`, a record that a conditionally-silent guard ran and found nothing |
| **`info`** (default) | 9 | `off`, `allow`, `warn_low`, `warn`, `ask`, `redact`, `deny`, `block` |
| `warn` | 13 | `warn`, `ask`, `redact`, `deny`, `block` |
| `error` | 17 | `deny`, `block` |

No level can drop a record the suppression machinery depends on. A `deny` or `block`, a decision
nobody modelled, any `lifecycle` or `permission` record, anything from `memo` or `inspect_remote`,
anything whose *natural* decision was a deny, anything config downgraded, and any memo hit are all
written at every level. That is a property of the record rather than a flag a call site has to
remember. The old model's `force=True` was missed on exactly the path that needed it most, so a
hard deny softened to `warn` by config vanished from the log entirely.

`log_verbosity` was **replaced** by `log_level`, not aliased. An unmigrated config simply carries an
unrecognised key and falls back to `info`, and that direction is safe: `gating` was the quietest
old setting, and `info` is exactly as complete as the old `all`. An unmigrated config gets *more*
logging, never less. `scripts/posture.sh --reset` removes the dead key once.

## Free-text disclosure

`log_free_text` decides which sinks may carry the fields that hold attacker-influenced or
environment free text: `command.line`, `file.path`, `process.working_directory`,
`session.transcript_path`, `agent.transcript_path`:

| value | effect |
|---|---|
| `admin` (default) | free text reaches the 0600 file sink, the macOS unified log (whose store is `drwxr-x--- root:admin`, re-checked at runtime) and the systemd journal |
| `owner` | free text reaches the 0600 file sink only |

This key can only ever *tighten* disclosure. There is no value that widens it past what the
per-sink measurement licenses, so it is the mirror of the "config may only loosen enforcement"
rule rather than an exception to it.

Credential values are masked out of those fields, in every sink, at every setting, but masking is
**pattern-based**, so what it covers is exactly the credential patterns the guards detect with plus
the redaction-only set (tokens and keys by prefix, URL userinfo, `curl -u`/`--user`/`-U`,
`smbclient -U user%pass`, `mysql -p`, `Authorization:` headers, `X-Api-Key:`-style headers,
`--password=`, `PGPASSWORD=`). A secret in a shape no pattern names reaches whichever sinks this
setting allows. `owner` is the setting that bounds that exposure to the 0600 file.

## Native sinks and the environment

`FORCEFIELD_LOG_SINKS` narrows the *native* sinks, the machine-global ones (`oslog`, `journald`,
`syslog`, `winevt`), for the processes that inherit it. It exists for the test suite, which spawns
real hooks and would otherwise write fabricated records into the operator's real unified log or
journal; no `$HOME` diversion can prevent that, because neither store is under `$HOME`.

```bash
export FORCEFIELD_LOG_SINKS=none        # file sink only
export FORCEFIELD_LOG_SINKS=journald    # the file sink plus journald, if this host has one
```

Two things it cannot do:

* **It cannot remove the file sink.** `~/.claude/hooks/security.log` is unioned in after the
  variable is read, at every value including `none`.
* **A value it does not recognise is ignored entirely**, and the platform default stands.
  `FORCEFIELD_LOG_SINKS=oslgo` used to select exactly what `none` selects, so a typo removed every
  machine-global copy of the audit trail with nothing recorded anywhere. An **empty** value is
  ignored the same way: it is not a token, and `FORCEFIELD_LOG_SINKS=$SOMETHING_UNSET` is one
  shell expansion from it.

Whatever it did is on the `session.start` record as `forcefield.sinks.env`, next to
`forcefield.sinks`: the value read, whether it was honoured, and any token that was rejected. So
"this host has no journal" and "this host has a journal and the environment switched it off" are
different readings rather than the same silence.

Both keys are **trusted-config only**: a repo can soften a guard, but it can never turn down the
record of what the guards did, nor change how much of that record reaches a sink other accounts
can read.

A per-guard `mode` overrides the preset; `severity_floor` tunes which Sigma rules fire. Anything
missing or malformed fails open to the default. Twelve gating guards are configurable: the eleven
PreToolUse ones plus the subagent-stop guard. The advisory guards (injection defense, output
scanner, agent output guard, prompt credential guard) are always on, because none of them blocks
anything and turning them off only removes information.

## Per-project allowlists

Create `.claude/hook-allowlist.json` to suppress specific patterns or paths:

```json
{
  "exfil_guard": {
    "suppress_patterns": ["curl_post_data"],
    "suppress_paths": ["src/api/client.py"]
  },
  "credential_guard": {
    "suppress_paths": ["tests/fixtures/**", "**/*.example"]
  },
  "injection_defense": {
    "suppress_patterns": ["role_manipulation"],
    "suppress_paths": ["docs/security/**"]
  }
}
```

> **An allowlist cannot suppress a hard `deny`.** Loosening one requires a preset or per-guard
> `mode` in your **trusted** home config, never a repo file: a cloned repo cannot allowlist away the
> guard standing between it and your credentials.

A suppression is a detection that did not enforce, and it is logged as one, so query
`forcefield.suppressed`, not severity. See
[known gaps](logging/00-field-reference.md#known-gaps).

## Remembered approvals: `/forcefield:remember`

Claude Code's own "don't ask again" does not work on a ForceField prompt. A PreToolUse hook's `ask`
is returned as the final permission decision *without* `permissions.allow` ever being consulted, so
adding an allow rule changes nothing. Nor can a hook see which button you pressed. ForceField
therefore needs one explicit command afterwards.

```bash
/forcefield:remember              # remember the most recent ask
/forcefield:remember list         # show what is remembered
/forcefield:remember forget <key> # undo one
```

That exact command stops prompting. The mechanism is deliberately narrow:

| | |
|---|---|
| Turns | `ask` → `allow` only; a hard `deny` is never memoizable |
| Matches | one exact command (whitespace runs collapsed), no wildcards |
| Scope | this project only; `--global` is opt-in |
| Expiry | 30 days; `--days N`, or `--forever` if you insist |
| Stored | `~/.claude/forcefield/memos.json`, mode `0600`, never in the repo |
| Refused for | anything on `NEVER_ALLOWLIST` / `_NEVER_SUPPRESSIBLE` (credential reads, git RCE primitives, exfil relays), and any command containing a credential |
| Logged | every hit writes an `allow` record with `forcefield.memo_hit` and `forcefield.natural: ask` |

The store lives under `$HOME` for the same reason the tiered config does: `<cwd>/.claude/` is
untrusted, and a memo file inside a repo would let that repo, or the agent, disarm the guard
watching it. Writes to the store are themselves guarded (`filesystem_guard`, `forcefield_memos`) on
both the file-editing tools and the Bash path, and each entry is HMAC-signed with a key in
`~/.claude/forcefield/memo.key` (0600): an entry the `remember` command did not write is ignored.

Prefer a config change when the noise is class-shaped rather than command-shaped. Two hundred
remembered exceptions signals that a guard's `mode` or the `severity_floor` is the real fix.

## Known friction and how to loosen it

Reach for the narrowest relief: remember one approved command (`/forcefield:remember`) → allowlist
one pattern or path → soften one guard (`guards.<name>.mode`) → pick a preset → disable a guard for
one project (home config only).

| Legitimate workflow that trips a guard | Guard | Level | Relief |
|------|------|------|------|
| Host package install instead of a container: `pip`, `npm`, `pnpm`, `yarn`, `gem`, `cargo`, `brew`, `conda`, `apt`, `aptitude`, `dnf`, `yum`, `pacman` | container-first | context only | Nothing to relieve: never prompts at any ceiling. Names a runtime that is actually installed (Apple's `container` first on macOS, podman first elsewhere, else docker/nerdctl) and says to relaunch rather than resume a failed run. Container preference is hygiene, not a security boundary, and a prompt here strands unattended agents. System managers are Linux-only, so off Linux they are not reported; nor is an install past `ssh host` or `wsl`, where the phrase is not in command position |
| Dev server, `base64`, interpreter one-liner caught by a broad rule | sigma_engine | ask | `severity_floor: high`, or `sigma_engine: warn` |
| `curl … \| sh` installer (rustup, nvm) | supply_chain_guard | **deny** | `permissive`, or `supply_chain_guard: ask` in **home** config |
| Install from a plaintext `http://` index or registry | supply_chain_guard | ask | Verify the index is a trusted internal mirror, or use the default https one. `pipx install`, `uv pip install --require-hashes` and `pip install -e` do not exempt it |
| `scp` / `rsync` / `curl -d` to your own host | exfil_guard | ask | Allowlist `remote_copy` / `curl_post_data`; relay domains stay denied |
| Reading a project `.env` in dev | credential_access_guard | ask | Allowlist that path under `suppress_paths` |
| Fake keys in fixtures / `.env.example` | credential_guard | ask | Placeholders are already skipped; else `suppress_paths` |
| Editing `~/.zshrc` / `~/.gitconfig` | filesystem_guard | ask | Allowlist the path, or disable for that project |
| Shell write to `~/.claude/forcefield.json`, `settings.json`, anything under `~/.claude/forcefield/` | filesystem_guard | ask | Intentional: these decide what the guards do next, and cannot be suppressed or remembered |
| Recursive submodule clone in a trusted repo | git_guard | ask *(context only on a patched git)* | Update git first, which closes both CVEs and the prompt stops on its own. Otherwise allowlist `recursive_submodule_clone` for that repo |
| `git clone ext::…` | git_guard | **deny** | Not loosenable except by preset. The transport runs its URL as a shell command; see [the threat model](threat-model.md#the-eleven-patterns) |
| Many subagent spawns hitting the rate limit | agent_guard | **deny** | `permissive`; the 10/20 limit is not otherwise tunable |
| MCP call carrying base64 or a long token | mcp_guard | ask | Allowlist the pattern for that server |
| WebFetch URL with an encoded query blob | webfetch_guard | ask | Allowlist it, or `webfetch_guard: warn` in home config; exfil domains stay denied |

> **Before allowlisting `recursive_submodule_clone`,** read
> [repository takeover at clone time](threat-model.md#repository-takeover-at-clone-time). "A repo I
> trust" is the assumption both CVE-2024-32002 and CVE-2025-48384 are designed to defeat. Patching
> git is the fix, and the guard notices, so the prompt disappears on its own once the host is patched.
> An allowlist only removes the prompt, and it removes it on unpatched hosts too, where the prompt
> was the last thing standing.

If ForceField is broadly too loud, set a `preset` once rather than disabling guards one at a time.
