# Log reference

Every ForceField decision is one OpenTelemetry log record carrying an OCSF Detection Finding
projection (`ocsf.class_uid` 2004). Everything on these pages came from running the shipped hooks.

## Where the log is written

| Sink | Path | Notes |
|---|---|---|
| **File (always on)** | `~/.claude/hooks/security.log` | JSON Lines, one record per line, mode 0600 in a 0700 directory |
| Rotated copies | `~/.claude/hooks/security.log.1` through `.log.7` | Rotates at 8 MiB, keeps 7, so the chain caps at 64 MiB |
| Rotation lock | `~/.claude/hooks/.rotate.lock` | |
| macOS unified log | no file path; subsystem `com.anthropic.claude-code.hooks` | read with `log show` |
| Linux journald | the journal, `SYSLOG_IDENTIFIER=cc-security` | read with `journalctl -t cc-security` |
| Linux without journald | whatever `/dev/log` is wired to, commonly `/var/log/messages` | |
| Windows | `%USERPROFILE%\.claude\hooks\security.log`, plus the Application channel | |

The file sink is the archive. It is the only sink whose retention this project controls, and the
only one that never truncates or fragments a record. Because the path resolves from `$HOME`,
running a hook with a different `HOME` redirects the log, which is how the test suites and the
capture harness keep fabricated attacks out of your real log.

Every session start writes the live sink inventory, including the resolved path, into
`forcefield.sinks`. That record is how you tell "a sink was down" from "nothing happened":

```bash
jq -c 'select(.Attributes."forcefield.guard" == "session_baseline") | .Attributes."forcefield.sinks"' \
    ~/.claude/hooks/security.log | tail -1
```

## The pages

| Page | Covers |
|---|---|
| [Field reference](00-field-reference.md) | The schema: top-level fields, every `Attributes` key, decision to severity, sinks, credential masking, worked `jq` queries, known gaps |
| [Records by hook](01-records-by-hook.md) | One measured record per hook, for all 23 registrations |
| [Platforms](02-platforms.md) | Which platforms run the hooks, what each sink does with the same record, and how to read the log on each |

## Read this before writing a detection

- **Start with [known gaps](00-field-reference.md#known-gaps).** Nothing records whether an
  `ask` was approved. Every sink fails silently. Both matter more than any field name.
- **Hunting for what a guard detected, not what it enforced?** Query `forcefield.natural`, not
  `forcefield.decision`. The two differ whenever config downgraded a finding or a remembered
  approval waved it through.
- **Looking for coverage that was switched off?** A disabled guard reports *below* `allow`, so no
  severity-based alert will surface it. Query `forcefield.decision == "off"`, plus
  `forcefield.suppressed` and `forcefield.memo_hit`, by name.
- **Forwarding to a SIEM?** What a sink receives follows from that sink's measured
  confidentiality, not from the platform. At `CONF_ADMIN`, the free-text floor, the record arrives
  whole with `command.line` and `file.path` included: that is the macOS unified log and journald.
  Below it, at `CONF_LOCAL`, the free-text fields are replaced by `forcefield.withheld_fields` and
  `forcefield.detail_in`, so the detection is visible and its evidence is not: that is a
  non-journald `/dev/log` datagram and the Windows Application channel.
- **On Windows?** The code paths are implemented and tested on POSIX against documented
  contracts, which is a weaker claim than every other platform here carries. Nothing has ever run
  on a Windows host. [Platforms](02-platforms.md#platform-support) splits implemented from
  tested, row by row. Use WSL2, which is a Linux target and is measured.

## Quick queries

```bash
# High-severity findings, by OCSF severity rather than a fragile text match
jq -c 'select(.Attributes."ocsf.severity_id" >= 4)' ~/.claude/hooks/security.log

# Detections that did not enforce: config downgraded, allowlisted, or remembered
jq -c 'select(.Attributes."forcefield.config_downgraded" == true
              or .Attributes."forcefield.suppressed" == true
              or .Attributes."forcefield.memo_hit" == true)' ~/.claude/hooks/security.log

# Which guard drives your friction, most frequent first
jq -r '[.Attributes."forcefield.guard", .Attributes."forcefield.decision"] | @tsv' \
    ~/.claude/hooks/security.log | sort | uniq -c | sort -rn

# Everything the git guard prompted on: the clone-time RCE surface
jq -c 'select(.Attributes."forcefield.guard" == "git_guard")' ~/.claude/hooks/security.log
```

Full recipe set, including timeline ordering across rotations:
[field reference](00-field-reference.md#worked-jq-queries).
