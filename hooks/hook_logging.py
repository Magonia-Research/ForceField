"""Cross-platform security event logging for Claude Code hooks.

One normalized event is built per decision and handed to every selected sink.
The record shape follows the OpenTelemetry Logs Data Model (field names,
``SeverityNumber``/``SeverityText``) and carries an OCSF Detection Finding
projection (``ocsf.*`` ids) in its ``Attributes``, so a downstream SIEM mapping
is a rename rather than a re-derivation. ``Timestamp`` and ``ObservedTimestamp``
are uint64 nanoseconds, which is the OTel spec type; the human-readable RFC 3339
rendering is preserved at ``Attributes["ocsf.metadata"].original_time``, which is
OCSF's own home for it. A single decision->severity table drives every sink and
every level, so a new decision can never silently fall through to INFO.

This module owns the *record*. ``log_sinks`` owns every write path, which sink
exists on this platform, how much of a record each one may carry, and rotation.
The split is not tidiness: the confidentiality rule that decides whether
``command.line`` reaches a native sink is a measured property of the sink, and
keeping it here as a macOS special case is what made it both too narrow and too
blunt.

Query examples. Note the absolute path: ``log`` is a zsh *builtin*, so a bare
``log show ...`` in the default macOS shell fails with "too many arguments"
rather than querying anything.

    # macOS - all hook events from last hour
    /usr/bin/log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' \
        --style ndjson --last 1h

    # Fallback file - only high-severity findings (deny/block => ocsf 4)
    jq -c 'select(.Attributes."ocsf.severity_id" >= 4)' ~/.claude/hooks/security.log

    # Fallback file - by OTel severity text
    jq -c 'select(.SeverityText == "ERROR")' ~/.claude/hooks/security.log

    # Fallback file - the command line behind a unified-log alert
    jq -c 'select(.Attributes."forcefield.guard" == "exfil_guard")' \
        ~/.claude/hooks/security.log

    # Linux - all hook events from last hour
    journalctl -t cc-security --since "1 hour ago" -o json --all
"""

from __future__ import annotations

import atexit
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
import log_sinks  # noqa: E402
from hook_event import read_regular_text, read_stdin_text  # noqa: E402
from patterns import redact_secrets  # noqa: E402

# One normalized severity table for every decision ForceField emits, replacing
# the two partial maps that let warn/redact/block fall through to INFO. Columns:
#   OTel SeverityNumber, OTel SeverityText, macOS `log emit --type`,
#   OCSF severity_id, OCSF action_id.
# Sources: OTel Logs Data Model SeverityNumber bands (9-12 INFO, 13-16 WARN,
# 17-20 ERROR); OCSF Detection Finding severity_id {1 Info,2 Low,3 Medium,
# 4 High} and action_id {1 Allowed,2 Denied}.
#
# The python-logging column is gone with stdlib logging. It was a third ladder
# that could drift from the other two; the syslog PRI it used to supply is now
# derived from the SeverityNumber in ``log_sinks._syslog_severity``, which
# reproduces the measured wire values exactly.
_SEV = {
    #            otel_num  otel_text  macos      ocsf_sev  ocsf_action
    "deny":    (17, "ERROR", "fault",   4, 2),
    "block":   (17, "ERROR", "fault",   4, 2),
    # 4 == Modified, not 1 == Allowed. The output scanner rewrites the credential
    # value in place; reporting that as "allowed" understates what happened.
    "redact":  (15, "WARN",  "error",   3, 4),
    "ask":     (14, "WARN",  "default", 3, 0),
    "warn":    (13, "WARN",  "default", 2, 1),
    "warn_low": (11, "INFO", "info",    2, 1),
    "allow":   (10, "INFO",  "info",    1, 1),
    # A guard the user deliberately switched off is the *least* interesting
    # record in the file. Falling through to the unknown-decision default gave it
    # OCSF Medium (3) — above a genuine warn (2) and above allow (1) — so any
    # `severity_id >= 3` SIEM rule fired hardest on suppression. It sits strictly
    # BELOW `allow` on the OTel number and keeps `ocsf.severity_id` 1 for exactly
    # that reason; it moved out of the DEBUG band only because a guard the
    # operator disabled is a security-relevant configuration effect on a specific
    # tool call, not a diagnostic — and zero `off` records ever reached the macOS
    # unified log while the file sink recorded them in the same window.
    "off":     (9,  "INFO",  "info",    1, 1),
    # The only decision below `off`. It records that a conditionally-silent guard
    # ran and found nothing, which is the difference between "clean" and "never
    # executed". In the ladder rather than falling through to _DEFAULT_SEV: an
    # unknown decision reports WARN, which would defeat the entire point.
    "guard_ran": (5, "DEBUG", "debug",  1, 1),
}
# An unknown decision reports at WARN, never a silent INFO under-report.
_DEFAULT_SEV = (13, "WARN", "default", 3, 0)

# The level model: one floor per level on the SAME OTel ladder above, so there is
# exactly one ordering. ``config._RANK`` is the *clamp* ladder (intrusiveness,
# "how much friction may config remove") and is never consulted for a logging
# decision — reusing it was the measured defect that kept a `warn_low` heuristic
# which redacted nothing and dropped a `redact` that rewrote a live token out of
# the transcript.
#
# Every level has content nothing else has:
#   debug 5   + guard_ran
#   info  9   off, allow, warn_low, warn, ask, redact, deny, block   <- default
#   warn  13  warn, ask, redact, deny, block
#   error 17  deny, block
_LEVEL_FLOOR = {"debug": 5, "info": 9, "warn": 13, "error": 17}

# Records the suppression machinery must never be able to suppress. This is a
# property of a record CLASS, which is why it used to need a `force=True` flag
# passed by hand at three call sites — and why one path that needed it never got
# it: `should_log` floored on the *clamped* decision, so `exfil_guard -> warn`
# plus the old `gating` verbosity left an `nc -e /bin/sh` HARD_DENY hit neither
# blocked nor recorded, and took the config-downgrade breadcrumb with it.
#
# A frozenset also survives the arrival of a new level. The old property ("no
# level can drop a deny") rested on arithmetic that happened to hold.
_UNSUPPRESSIBLE_DECISIONS = frozenset({"deny", "block"})
_UNSUPPRESSIBLE_CLASSES = frozenset({"lifecycle", "permission"})
_UNSUPPRESSIBLE_GUARDS = frozenset({"memo", "inspect_remote"})

# OCSF Application Lifecycle (class_uid 6002) activity ids, read from
# schema.ocsf.io/1.5.0/classes/application_lifecycle rather than recalled:
# 0 Unknown, 1 Install, 2 Remove, 3 Start, 4 Stop, 5 Restart, 6 Enable,
# 7 Disable, 8 Update, 99 Other. Pinned by a test.
OCSF_LIFECYCLE_START = 3
OCSF_LIFECYCLE_STOP = 4
OCSF_LIFECYCLE_OTHER = 99

# (category_uid, class_uid, default activity_id) per record class. `type_uid` is
# always class_uid * 100 + activity_id. `record_class` is an EXPLICIT argument,
# never inferred: a heuristic that could silently mis-class a finding as
# lifecycle would hide it from every `class_uid == 2004` SIEM rule.
_RECORD_CLASSES = {
    "finding": (2, 2004, 1),            # Detection Finding / Create
    "lifecycle": (6, 6002, OCSF_LIFECYCLE_OTHER),
    "permission": (2, 2004, 1),         # + ocsf.status_id
}
_DEFAULT_RECORD_CLASS = "finding"

# The OCSF schema version the `ocsf.*` projection is built against.
OCSF_SCHEMA_VERSION = "1.5.0"

# Correlation fields Claude Code puts on the stdin of every hook event, mapped to
# the attribute name they keep in a record. Every one of these is already in the
# dict the hook parsed; before this they were dropped at 38 of 42 call sites, so
# three PreToolUse hooks wrote three records for one tool call with no shared key.
_CONTEXT_ATTRS = (
    ("session_id", "session.id"),
    ("tool_use_id", "tool.call.id"),
    ("prompt_id", "prompt.id"),
    ("tool_name", "tool.name"),
    ("permission_mode", "claude_code.permission_mode"),
    ("cwd", "process.working_directory"),
    ("transcript_path", "session.transcript_path"),
    ("agent_id", "agent.id"),
    ("agent_type", "agent.type"),
    ("agent_transcript_path", "agent.transcript_path"),
)

# Every attribute carrying attacker-influenced or environment free text. Each one
# goes through ``_scrub`` and is named in ``forcefield.redacted_fields`` when it
# is hit. Declared explicitly, and pinned by a test, so the next such field
# cannot be added without a decision about masking it.
#
# A path is not obviously credential-bearing, which is exactly why it is in here:
# a build directory or a transcript path under a token-named worktree is a real
# shape. ``forcefield.pattern`` is scrubbed but deliberately NOT withheld from a
# low-confidentiality sink (``log_sinks.FREE_TEXT_FIELDS``) — it is the field a
# SIEM rule keys on.
_FREE_TEXT_ATTRS = (
    "command.line",
    "file.path",
    "forcefield.pattern",
    "process.working_directory",
    "session.transcript_path",
    "agent.transcript_path",
)

# Known extra keys promoted to namespaced OTel-style attribute names.
_ATTR_RENAME = {
    "tool": "tool.name",
    "suppressed": "forcefield.suppressed",
    "agent_id": "agent.id",
    "agent_type": "agent.type",
    "agent_transcript_path": "agent.transcript_path",
    "claude_code_version": "claude_code.version",
}

# Upper bound on the text handed to ``redact_secrets`` when scrubbing one log
# attribute. Every redaction pattern is linear, so this is belt-and-braces
# rather than the fix — but a hook has a 5s budget and a log record is never
# worth spending it. Truncation is marked so a reader knows the field is partial.
MAX_REDACT_BYTES = 65_536

# How deep into a nested ``extra`` value the credential scrub will walk. Bounded
# so a self-referential or pathologically nested structure cannot spend the hook's
# budget here; anything deeper is left as-is rather than recursed into forever.
MAX_SCRUB_DEPTH = 4

# ...and how many values it will walk in total. Depth alone is not a bound: at
# MAX_SCRUB_DEPTH 4 a container 256 wide at every level is 4.3e9 values, and a
# flat list is unbounded outright. Measured on the hook interpreter: a
# one-million-element list in ``extra`` spent **4.319 s** inside this walk, which
# is the whole 5 s hook timeout for a log record. No guard passes a
# variable-length container in ``extra`` today, so this is latent rather than
# reachable -- but "no caller does that yet" is not a bound, and the next guard
# author who returns "here is everything I matched" would find one.
#
# Past the bound the remaining values are DROPPED, not passed through: passing
# an unscrubbed value into a log record is the one outcome this walk exists to
# prevent, so the truncation marker is the safe direction and the record says so
# in ``forcefield.redacted_fields`` alongside a ``[...N unscanned values
# dropped]`` sentinel in place of the tail.
MAX_SCRUB_VALUES = 2_048
_SCRUB_DROPPED = "...[%d unscanned values dropped]"

# How many native-sink writes this process gave up to stay inside
# ``log_sinks.LOG_BUDGET_SECONDS``. The budget itself lives in ``log_sinks``,
# which owns every blocking write path and is the only layer that can see what
# a rollover wait and a native write cost between them. It used to live here as
# a per-*drain* deadline, which bounded exactly one drain of the deferred queue
# and nothing else: the 35 synchronous ``log_security_event`` call sites paid a
# full ``timeout=2`` each with no cap (measured 8.044 s for four records), and a
# second drain after ``emit()`` was handed a fresh budget (measured 4.024 s for
# two records either side of the verdict). One budget, one process.
_native_writes_skipped = 0

# Per-process, so ``session.end`` can report how much this process wrote and a
# reader can tell a truncated tail from a quiet one. It is a PROCESS count, not
# a session count -- a hook is one process -- and the docs say which.
_records_emitted = 0

_plugin_version_cache: str | None = None
_host_name_cache: str | None = None

# Log records queued by ``clamp_and_emit`` and written only after the decision
# has reached stdout. Ordering is the point: logging runs regex over attacker-
# controlled command text, and a hook that overruns its 5s timeout is killed
# with its verdict undelivered — which turned a correctly-computed hard deny
# into a silent allow. The decision now leaves the process first; logging is
# latency after that, never a suppression channel.
_DEFERRED: list[tuple[tuple[Any, ...], dict[str, Any]]] = []


def _severity(decision: str) -> tuple[int, str, str, int, int]:
    return _SEV.get(decision, _DEFAULT_SEV)


def _write_to_sinks(event: dict[str, Any], severity_number: int,
                    macos_type: str) -> None:
    """Hand one record to every selected sink, at that sink's confidentiality.

    The JSON is rendered once per *confidentiality class*, not once per sink: on
    a host with a file sink and a native sink at the same class there is one
    ``json.dumps``, and where the classes differ the second render is the whole
    reason the free-text fields can be withheld from one and not the other.

    Past the process logging budget the native sinks are skipped and the file
    sink is still written, because the file sink is the archive and it costs
    0.027 ms. The budget is re-read per sink rather than once per record: a
    single slow native write can exhaust it, and the next sink in the same
    record must see that.

    **The projected record travels with the projected line, and that pairing is
    the whole disclosure boundary.** This used to hand ``write()`` a projected
    *line* and the unprojected *record*, which was correct for exactly one code
    path — the one where the line fits the sink's ceiling. Every rung below it
    re-renders the record (``log_sinks.fragments`` falls back through
    ``_capped`` and ``_minimal``, and ``_MINIMAL_ATTRS`` names ``command.line``
    outright), and ``_journal_fields`` builds its ``FORCEFIELD_*`` fields from
    the record rather than the line — so a record too large to fragment put
    every withheld field back into a sink that sat below the disclosure floor.
    On Linux and Windows that fires at default settings, because syslog and the
    Application channel are ``CONF_LOCAL`` and projected unconditionally. There
    is one record shape per confidentiality class here, and it is cached
    alongside its line so the two cannot drift apart again.
    """
    global _native_writes_skipped  # noqa: PLW0603

    projected: dict[int, tuple[dict[str, Any], str]] = {}
    for name in sorted(log_sinks.selected()):
        try:
            if name != log_sinks.NAME_FILE:
                if log_sinks.budget_remaining() <= 0:
                    if log_sinks.accepts(name, event, severity_number):
                        _native_writes_skipped += 1
                    continue
            conf = log_sinks.confidentiality(name)
            pair = projected.get(conf)
            if pair is None:
                record = log_sinks.project(event, conf)
                pair = (record, log_sinks.render(record))
                projected[conf] = pair
            log_sinks.write(name, pair[0], pair[1], severity_number, macos_type)
        except Exception:  # noqa: BLE001 - one sink must never hide the next
            continue


def _scrub(value: str, attr_name: str, redacted: list[str]) -> str:
    """Strip credential values out of one attribute, noting that it was hit."""
    if len(value) > MAX_REDACT_BYTES:
        value = value[:MAX_REDACT_BYTES] + "...[TRUNCATED]"
    cleaned, matched = redact_secrets(value)
    if matched and attr_name not in redacted:
        redacted.append(attr_name)
    return cleaned


def _scrub_any(
    value: Any, attr_name: str, redacted: list[str], depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    """Scrub every string reachable inside ``value``, container or not.

    The scrub used to reach only *top-level* strings, so a guard passing
    ``extra={"matches": [...]}`` — the obvious shape for "here is what I matched"
    — wrote its contents to the log verbatim. No guard passes a nested structure
    today, so nothing leaked in practice; the defect was that the documented
    invariant ("every string in extra is masked") was wider than the code, which
    is exactly the gap the next guard author would fall into.

    Dict keys are scrubbed as well as values: a key is just as capable of
    carrying a token, and it is a string either way.

    Bounded in **both** directions. ``MAX_SCRUB_DEPTH`` stops a self-referential
    or deeply nested structure; ``MAX_SCRUB_VALUES`` stops a wide one, which the
    depth bound never could — a flat million-element list measured 4.319 s here,
    the whole hook timeout for one log record. ``budget`` is a one-element list
    so the count is shared across the whole walk rather than reset per container;
    a caller passing ``None`` gets a fresh one.
    """
    if budget is None:
        budget = [MAX_SCRUB_VALUES]
    budget[0] -= 1
    if isinstance(value, str):
        return _scrub(value, attr_name, redacted)
    if depth >= MAX_SCRUB_DEPTH:
        return value
    if isinstance(value, dict):
        cleaned_map = {}
        for index, (key, item) in enumerate(value.items()):
            if budget[0] <= 0:
                cleaned_map[_SCRUB_DROPPED % (len(value) - index)] = None
                if attr_name and attr_name not in redacted:
                    redacted.append(attr_name)
                break
            cleaned_map[_scrub_any(key, attr_name, redacted, depth + 1, budget)] = \
                _scrub_any(item, attr_name, redacted, depth + 1, budget)
        return cleaned_map
    if isinstance(value, (list, tuple)):
        cleaned = []
        for index, item in enumerate(value):
            if budget[0] <= 0:
                cleaned.append(_SCRUB_DROPPED % (len(value) - index))
                if attr_name and attr_name not in redacted:
                    redacted.append(attr_name)
                break
            cleaned.append(_scrub_any(item, attr_name, redacted, depth + 1, budget))
        return tuple(cleaned) if isinstance(value, tuple) else cleaned
    return value


def _context_attributes(
    context: dict[str, Any] | None, redacted: list[str],
) -> dict[str, Any]:
    """Correlation attributes, straight from the event Claude Code sent us.

    ``hook_event.context_from_event`` extracts these from the stdin dict every
    hook already parsed, so this costs no new I/O and invents nothing: a
    non-string value never reaches here, and a missing key simply produces no
    attribute rather than an empty one.

    Two of them are free text (the cwd, the transcript path) and go through the
    same ``_scrub`` as a command line. A path is not obviously credential-bearing,
    which is precisely why: a worktree named after a token is a real shape.
    """
    attributes: dict[str, Any] = {}
    if not isinstance(context, dict):
        return attributes
    for key, attr_name in _CONTEXT_ATTRS:
        value = context.get(key)
        if not isinstance(value, str) or not value:
            continue
        if attr_name in _FREE_TEXT_ATTRS:
            value = _scrub(value, attr_name, redacted)
        attributes[attr_name] = value
    return attributes


def _optional_attributes(
    *,
    pattern_matched: str | None,
    command: str | None,
    file_path: str | None,
    extra: dict[str, Any] | None,
    redacted: list[str],
) -> dict[str, Any]:
    """Namespaced attributes for whatever the caller supplied, with credentials
    scrubbed out of every free-text field.

    A record is written for every decision including ``allow``, so any secret in
    a command line, a URL or a file path would otherwise be persisted verbatim to
    a log that outlives the session.

    ``forcefield.pattern`` is scrubbed too. It is *mostly* a fixed vocabulary, but
    not entirely: several guards interpolate matched input into it
    (``typosquat:{typo}``, ``output_credential:{name}``). Those are package and
    pattern names rather than secret values, so this is bounding an edge rather
    than closing a leak — but "mostly a fixed vocabulary" is not a property worth
    resting an exemption on.
    """
    attributes: dict[str, Any] = {}
    # One walk budget for the whole record, not one per ``extra`` key: a
    # per-value bound is no bound at all when the caller controls how many
    # values there are.
    budget = [MAX_SCRUB_VALUES]
    if pattern_matched is not None:
        attributes["forcefield.pattern"] = _scrub(
            pattern_matched, "forcefield.pattern", redacted,
        )
    for attr_name, value in (
        ("command.line", command),
        ("file.path", file_path),
    ):
        if value is not None:
            attributes[attr_name] = _scrub(value, attr_name, redacted)
    for key, value in (extra or {}).items():
        # The key is scrubbed too, and not only for symmetry: it becomes the
        # attribute *name*, so an unscrubbed one wrote the secret into the field
        # name, where no value-side masking would ever look at it again. The
        # breadcrumb records the CLEANED name — noting the redaction under the
        # raw key would have put the secret straight back into the record.
        if key not in _ATTR_RENAME and isinstance(key, str):
            hits: list[str] = []
            key = _scrub(key, "", hits)
            if hits and f"forcefield.{key}" not in redacted:
                redacted.append(f"forcefield.{key}")
        attr_name = _ATTR_RENAME.get(key, f"forcefield.{key}")
        attributes[attr_name] = _scrub_any(value, attr_name, redacted,
                                           budget=budget)
    return attributes


def _plugin_version() -> str:
    """This plugin's version, read once from its own manifest.

    ``CLAUDE_PLUGIN_ROOT`` is not in a hook process's environment (measured), so
    the manifest is found relative to this file instead. An unreadable manifest
    yields ``"unknown"`` rather than raising: a version string is never worth a
    tool call.

    The read goes through ``read_regular_text`` — ``O_NONBLOCK`` plus ``S_ISREG``
    on the descriptor — because this sits on the Resource block of **every**
    record, so it is on the hook path of nearly every registration. Measured with
    a plain ``read_text``: one ``mkfifo`` of this manifest took
    ``security_dispatcher`` to 6.005 s and ``container_first.sh``'s ``exit 2``
    hard deny on ``rm -rf /`` to a SIGKILL with zero bytes — a computed block
    turned into a silent allow, by a path any same-uid process can replace.
    """
    global _plugin_version_cache  # noqa: PLW0603
    if _plugin_version_cache is None:
        version = "unknown"
        try:
            manifest = (
                Path(__file__).resolve().parent.parent
                / ".claude-plugin" / "plugin.json"
            )
            data = json.loads(read_regular_text(manifest, 65_536))
            if isinstance(data, dict) and isinstance(data.get("version"), str):
                version = data["version"]
        except Exception:  # noqa: BLE001 - a missing manifest is not a hook failure
            version = "unknown"
        _plugin_version_cache = version
    return _plugin_version_cache


def _host_name() -> str:
    """The machine name, cheaply and portably. ``""`` when it cannot be had.

    ``os.uname`` is POSIX-only, so it is reached through ``getattr``; ``platform``
    is the portable fallback and is imported inside the function because the
    POSIX path never needs it.
    """
    global _host_name_cache  # noqa: PLW0603
    if _host_name_cache is None:
        name = ""
        try:
            uname = getattr(os, "uname", None)
            if uname is not None:
                name = uname().nodename
            else:
                import platform

                name = platform.node()
        except Exception:  # noqa: BLE001 - a hostname is never worth a tool call
            name = ""
        _host_name_cache = name or ""
    return _host_name_cache


def _user_name() -> str:
    """Who this process is running as. ``""`` only when nothing can say.

    The environment first, because that is what the operator sees and it costs
    nothing. It is not enough on its own: measured in a Linux container, ``USER``,
    ``USERNAME`` and ``LOGNAME`` were all unset while the process was root, so
    every record in a 122-record capture carried ``user.name: ""`` -- and
    ``user.id`` is behind ``resource_full``, so those records identified nobody
    at all. journald stamps ``_UID`` itself from ``SO_PEERCRED``; the file sink,
    which is the only sink present in exactly that container case, does not.

    ``pwd`` is POSIX-only and is imported inside the function, inside a ``try``:
    on Windows the import is a ``ModuleNotFoundError``, which is the failure this
    whole rework existed to remove, and the environment already answers there.
    """
    for variable in ("USER", "USERNAME", "LOGNAME"):
        value = os.environ.get(variable)
        if value:
            return value
    try:
        import pwd

        getuid = getattr(os, "getuid", None)
        if getuid is not None:
            return pwd.getpwuid(getuid()).pw_name or ""
    except Exception:  # noqa: BLE001 - a user name is never worth a tool call
        pass
    return ""


def resource(full: bool = False, instance_id: str | None = None) -> dict[str, Any]:
    """OTel ``Resource``: what produced this record.

    Five keys on every record. It is what separates the machine-global native
    sinks' mixed populations — 82,829 records written by a harness under a
    temporary ``$HOME`` appeared in the unified log with nothing to tell them
    from real ones — and a native-sink record has to be self-describing, because
    an investigator reading it may not be able to read the file it points at.

    ``full`` adds the five fields that are constant for the whole session and
    are therefore carried once, on ``session.start``, rather than costing bytes
    on every record. ``os.getuid`` is Unix-only and is reached through
    ``getattr``; on Windows ``user.id`` is ``None`` rather than a guess.
    """
    out: dict[str, Any] = {
        "service.name": "forcefield",
        "service.version": _plugin_version(),
        "host.name": _host_name(),
        "user.name": _user_name(),
        "process.pid": os.getpid(),
    }
    if not full:
        return out
    try:
        out["os.type"] = sys.platform
        out["process.parent_pid"] = os.getppid()
        out["process.runtime.version"] = sys.version.split()[0]
        getuid = getattr(os, "getuid", None)
        out["user.id"] = str(getuid()) if getuid is not None else None
        if instance_id:
            out["service.instance.id"] = instance_id
    except Exception:  # noqa: BLE001 - a description is never worth a tool call
        pass
    return out


def _hex_digest(text: str, length: int) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:length]


def _trace_id(session_id: str | None) -> str:
    """A 32-hex, W3C-shaped trace id, present on EVERY record.

    A Claude Code session id is a v4 UUID, which is exactly 32 hex digits once
    the dashes come off — so the common case is a reshape, not a hash, and the
    dashed form is still on the record as ``session.id``. Anything else is
    hashed, and a record with no session at all gets a stable sentinel, so the
    field never varies in presence. Before this it was a 36-char dashed UUID on
    0.35% of records, which no W3C-aware reader would accept.
    """
    if session_id:
        stripped = session_id.replace("-", "").lower()
        if len(stripped) == 32 and all(c in "0123456789abcdef" for c in stripped):
            return stripped
        return _hex_digest(session_id, 32)
    return _hex_digest("forcefield:no-session", 32)


def build_event(
    hook_name: str,
    decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    context: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    record_class: str = _DEFAULT_RECORD_CLASS,
    event_name: str | None = None,
    natural: str | None = None,
    activity_id: int | None = None,
    status_id: int | None = None,
    resource_full: bool = False,
) -> dict[str, Any]:
    """Build one OTel-aligned log record with an OCSF projection.

    The severity fields come straight from the shared ``_SEV`` table, so the OTel
    ``SeverityNumber`` and the ``ocsf.severity_id`` never disagree and no decision
    is under-reported. All security detail lives in namespaced ``Attributes``,
    with credential values masked — see ``_optional_attributes``.

    ``record_class`` is explicit and defaults to ``finding``, which reproduces
    what every existing call site already meant. On a non-``finding`` record
    ``forcefield.decision`` is *the rung the record was written at*, not a claim
    that ForceField decided anything — read ``forcefield.record_class`` first.

    ``event_name`` names the record where that differs from the guard that wrote
    it (``session.start`` emitted by ``session_baseline``); it defaults to
    ``hook_name``, so a finding is unaffected.
    """
    # Function-local, like every other import that only one code path needs:
    # `datetime` costs 1.7 ms on the hook interpreter and three PreToolUse
    # hooks fire per Bash tool call, so paying it at module scope charged every
    # hook process for a timestamp that only a written record uses.
    from datetime import datetime

    otel_num, otel_text, _, ocsf_sev, ocsf_action = _severity(decision)
    if record_class not in _RECORD_CLASSES:
        record_class = _DEFAULT_RECORD_CLASS
    category_uid, class_uid, default_activity = _RECORD_CLASSES[record_class]
    if not isinstance(activity_id, int):
        activity_id = default_activity
    name = event_name or hook_name
    context = context if isinstance(context, dict) else {}
    redacted: list[str] = []

    attributes: dict[str, Any] = {"forcefield.record_class": record_class}
    attributes.update(_context_attributes(context, redacted))
    attributes["forcefield.guard"] = hook_name
    attributes["forcefield.decision"] = decision
    # Unconditional. It occurred zero times in 7,502 records before this, so a
    # reader could not distinguish "not downgraded" from "this build has no such
    # field" — which is also why `forcefield.config_downgraded` stays
    # conditional: absence is no longer ambiguous. Do NOT derive "downgraded" as
    # natural != decision; the memo path writes natural "ask" with decision
    # "allow" and that is not a config downgrade.
    attributes["forcefield.natural"] = natural if natural is not None else decision
    attributes.update(_optional_attributes(
        pattern_matched=pattern_matched,
        command=command,
        file_path=file_path,
        extra=extra,
        redacted=redacted,
    ))
    if redacted:
        attributes["forcefield.redacted_fields"] = redacted

    # A rollover this process could not complete is otherwise invisible: the
    # append still succeeds, so the only symptom is a log that quietly grows
    # past its budget. Carried on the next record rather than raised, because
    # the failure is survivable and the record is not.
    if log_sinks.rotation_failed():
        attributes["forcefield.rotation_failed"] = True

    # The two drop counters ride the same rail, and for the same reason they
    # cannot ride ``session.end``. Both are PROCESS-local module globals and a
    # hook is one process, so the process that writes ``session.end`` is never
    # the process that dropped anything: measured, a dispatcher that dropped
    # four consecutive denies against an undrained ``/dev/log`` reported
    # ``native_records_dropped = 1`` in itself and ``0`` in the reporting
    # process, and ``records_emitted`` on ``session.end`` was ``0`` by
    # construction because it is read while building the only record that
    # process will ever emit. Carried here they land on the next record the
    # DROPPING process writes -- which is also the record an investigator can
    # join to the tool call it belongs to.
    #
    # The residue, stated rather than hidden: a process whose last record is the
    # one that dropped has nowhere to carry the count. That record is still in
    # the file sink, which never drops; what is unreported is the size of the
    # native-sink gap behind it.
    skipped = native_writes_skipped()
    if skipped:
        attributes["forcefield.native_writes_skipped"] = skipped
    dropped = log_sinks.native_records_dropped()
    if dropped:
        attributes["forcefield.native_records_dropped"] = dropped

    now_ns = time.time_ns()
    original_time = (
        datetime.fromtimestamp(now_ns / 1_000_000_000)
        .astimezone().isoformat(timespec="milliseconds")
    )
    session_id = attributes.get("session.id")
    tool_call_id = attributes.get("tool.call.id")

    attributes.update({
        "ocsf.category_uid": category_uid,
        "ocsf.class_uid": class_uid,
        "ocsf.activity_id": activity_id,
        "ocsf.type_uid": class_uid * 100 + activity_id,
        "ocsf.severity_id": ocsf_sev,
        "ocsf.action_id": ocsf_action,
    })
    if status_id is not None:
        attributes["ocsf.status_id"] = status_id

    # Read the pattern back out of the attributes rather than re-interpolating the
    # argument: the attribute has been through the scrub, the argument has not,
    # and a Body built from the raw value reintroduces whatever the scrub removed.
    scrubbed_pattern = attributes.get("forcefield.pattern")
    title = f"{name}: {scrubbed_pattern}" if scrubbed_pattern else name
    body = f"{name}: {decision}"
    if scrubbed_pattern:
        body += f" ({scrubbed_pattern})"

    # The three OCSF-REQUIRED Detection Finding attributes that were absent, so
    # every record ForceField ever wrote failed a strict validator. Pure data,
    # no new mechanism. `finding_info.uid` is deterministic, so the three hooks
    # that fire on one command produce three stable, distinct uids under one
    # SpanId; `title` is built from the SCRUBBED pattern, never the argument.
    attributes["ocsf.time"] = now_ns // 1_000_000
    attributes["ocsf.metadata"] = {
        "product": {"name": "ForceField", "version": _plugin_version()},
        "version": OCSF_SCHEMA_VERSION,
        "original_time": original_time,
    }
    attributes["ocsf.finding_info"] = {
        "uid": _hex_digest("|".join([
            session_id or "", tool_call_id or "", hook_name,
            str(scrubbed_pattern or ""),
        ]), 16),
        "title": title,
    }

    event: dict[str, Any] = {
        "Timestamp": now_ns,
        "ObservedTimestamp": time.time_ns(),
        "SeverityNumber": otel_num,
        "SeverityText": otel_text,
        "TraceId": _trace_id(session_id),
    }
    # The join that did not exist: three PreToolUse[Bash] hooks write records for
    # the SAME tool call, and nothing tied them together.
    if tool_call_id:
        event["SpanId"] = _hex_digest(tool_call_id, 16)
    event["EventName"] = f"forcefield.{name}"
    event["Body"] = body
    event["Resource"] = resource(full=resource_full,
                                 instance_id=session_id if resource_full else None)
    event["Attributes"] = attributes
    return event


def _is_unsuppressible(
    decision: str,
    guard_name: str,
    record_class: str,
    natural: str | None,
    extra: dict[str, Any] | None,
) -> bool:
    """Whether the level model is allowed to drop this record at all.

    The suppression machinery must not be suppressible. That is a property of a
    record class rather than of a rung, which is why it used to be a ``force``
    flag passed by hand — and why the one path that needed it most never got it:
    the old floor ran on the *clamped* decision, so a hard-deny hit downgraded to
    ``warn`` by config vanished entirely, taking its own breadcrumb with it.

    An unknown decision is unsuppressible on purpose: nobody modelled it, so
    nobody has decided it is safe to drop.
    """
    if decision in _UNSUPPRESSIBLE_DECISIONS:
        return True
    if decision not in _SEV:
        return True
    if record_class in _UNSUPPRESSIBLE_CLASSES:
        return True
    if guard_name in _UNSUPPRESSIBLE_GUARDS:
        return True
    if natural in _UNSUPPRESSIBLE_DECISIONS:
        return True
    if extra:
        if extra.get("config_downgraded"):
            return True
        if extra.get("memo_hit"):
            return True
    return False


def _should_record(
    decision: str,
    guard_name: str,
    record_class: str,
    natural: str | None,
    extra: dict[str, Any] | None,
) -> bool:
    """Whether this record clears the configured level floor.

    Runs BEFORE ``build_event``, preserving the property that a dropped record
    costs nothing: redaction is the expensive part, and the records a level drops
    are exactly the routine ``allow`` ones every Bash call produces.

    ``config`` is imported inside the function so this module stays free of the
    cycle, and behind a catch because config must never be able to mute a guard:
    an unreadable config logs everything.
    """
    if _is_unsuppressible(decision, guard_name, record_class, natural, extra):
        return True
    try:
        from config import resolve_log_level

        floor = _LEVEL_FLOOR.get(resolve_log_level(), _LEVEL_FLOOR["info"])
    except Exception:  # noqa: BLE001 - config must never be able to mute a guard
        floor = _LEVEL_FLOOR["info"]
    return _severity(decision)[0] >= floor


def log_security_event(
    hook_name: str,
    decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    context: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    record_class: str = _DEFAULT_RECORD_CLASS,
    event_name: str | None = None,
    natural: str | None = None,
    activity_id: int | None = None,
    status_id: int | None = None,
    resource_full: bool = False,
) -> dict[str, Any]:
    """Log a security event to every selected sink.

    Fire-and-forget: never raises. Returns an empty dict on any failure, and on a
    record below the configured level -- see ``_should_record``, which also holds
    the set of records no level may drop.
    """
    global _records_emitted  # noqa: PLW0603
    try:
        if not _should_record(decision, hook_name, record_class, natural, extra):
            return {}

        event = build_event(
            hook_name,
            decision,
            pattern_matched=pattern_matched,
            command=command,
            file_path=file_path,
            context=context,
            extra=extra,
            record_class=record_class,
            event_name=event_name,
            natural=natural,
            activity_id=activity_id,
            status_id=status_id,
            resource_full=resource_full,
        )
        otel_num, _, macos_type, _, _ = _severity(decision)
        _write_to_sinks(event, otel_num, macos_type)
        _records_emitted += 1
        return event
    except Exception:
        return {}


def log_guard_ran(hook_name: str, context: dict[str, Any] | None = None) -> None:
    """Record that a conditionally-silent guard ran and found nothing.

    Six guards return without writing anything when their scan is clean, so
    "clean" and "never executed" are the same observation in the log. This
    closes that at SeverityNumber 5, below every other decision, so it exists
    only at ``log_level: debug`` and costs one dict lookup at the default.

    Queued rather than written: every one of the six call sites sits on the
    clean path *before* the guard writes its empty response to stdout, which is
    the ordering ``emit`` exists to hold.
    """
    defer_log(hook_name, "guard_ran", context=context)


def records_emitted() -> int:
    """How many records this process actually wrote. For the session record."""
    return _records_emitted


def _build_rotation_record(rotated_to: str, rotated_bytes: int) -> dict[str, Any]:
    """The ``log.rotated`` marker, in the one record envelope.

    Registered with ``log_sinks`` so the sink layer never has to build a second
    envelope for the one record that originates inside it. It is written under
    the rotation lock with a raw ``os.write``, not through the sink dispatch, so
    this only shapes the record — it does not write it.
    """
    return build_event(
        "log_sinks", "allow",
        record_class="lifecycle",
        event_name="log.rotated",
        activity_id=OCSF_LIFECYCLE_OTHER,
        extra={"rotated_to": rotated_to, "rotated_bytes": rotated_bytes},
    )


log_sinks.set_record_builder(_build_rotation_record)


def _memo_hit(
    guard_name: str, pattern_matched: str | None, subject: str | None,
) -> dict[str, Any] | None:
    """A previously remembered approval for this exact ask, or None.

    Local import so ``memo`` can reach back into the guards' lock lists without a
    cycle. Any failure falls through to prompting, which is the safe direction.
    """
    if not subject:
        return None
    try:
        from memo import find_memo

        return find_memo(guard_name, pattern_matched, subject)
    except Exception:  # noqa: BLE001 - never let a memo lookup block a tool call
        return None


def defer_log(*args: Any, **kwargs: Any) -> None:
    """Queue a log record to be written after the decision reaches stdout.

    **This, not ``log_security_event``, is what a guard calls before it has
    emitted its verdict.** The ordering is the whole point of ``emit``: a hook
    killed at the 5 s timeout delivers no decision at all, so any work done
    before stdout is flushed is work that can cost a computed hard deny. Only 6
    of the 21 registrations reached ``emit`` before logging when this was
    measured; the rest called ``log_security_event`` synchronously and wrote
    stdout afterwards, and one of them -- ``prompt_credential_guard``'s private
    key ``block`` -- was measured lost outright, 0 bytes of stdout, when the
    logging ahead of it stalled.

    Arguments are captured, not evaluated later, so a caller reading a counter
    into ``extra`` still records the value it saw at decision time.
    """
    _DEFERRED.append((args, kwargs))


def flush_deferred() -> None:
    """Write every queued log record. Safe to call more than once.

    Bounding is not this function's job any more. ``log_sinks`` holds one
    budget for the whole process, so a second drain after ``emit()`` cannot be
    handed a fresh allowance and a synchronous call site cannot escape the
    ceiling by not queueing. Past the budget the native sinks are skipped and
    the file sink still takes every record, at 0.027 ms each.
    """
    while _DEFERRED:
        args, kwargs = _DEFERRED.pop(0)
        try:
            log_security_event(*args, **kwargs)
        except Exception:  # noqa: BLE001 - logging must never block a tool call
            pass


def native_writes_skipped() -> int:
    """How many native-sink writes this process dropped to stay inside the budget."""
    return _native_writes_skipped


def _encode_response(response: dict[str, Any] | None) -> str:
    """Serialize a hook response to a single string, never raising.

    ``json.dump(obj, stream)`` writes *incrementally*: it emits valid bytes right
    up to an unserializable member and only then raises, leaving a truncated
    fragment like ``{"bad":`` on stdout. Claude Code parses that as malformed,
    gets no decision, and fails open — the same failure shape the emit-before-log
    ordering was introduced to prevent. Encoding to a string first means the
    decision either goes out whole or is replaced by a value that will.

    ``default=str`` is the salvage path: it keeps a decision that merely carries
    an odd value (a Path, an exception) rather than discarding it.
    """
    try:
        return json.dumps(response if response else {})
    except (TypeError, ValueError):
        pass
    try:
        return json.dumps(response if response else {}, default=str)
    except Exception:  # noqa: BLE001 - stdout must still receive valid JSON
        return "{}"


def emit(response: dict[str, Any] | None) -> None:
    """Write a hook response to stdout, flush it, then write the queued logs.

    Every hook ends here instead of calling ``json.dump`` directly — all 21
    registrations, not the 6 that reached it when this was measured. The flush is
    the security-relevant part: once the bytes are in the pipe, a subsequent
    timeout kill costs a log record rather than the verdict itself. The write is
    a single ``str`` so it is all-or-nothing — see ``_encode_response``.

    The write is wrapped because a hook whose stdout is already broken has no
    verdict to deliver either way, and raising here would replace a silent
    failure with a traceback on the hook's stderr. The drain still runs.
    """
    try:
        sys.stdout.write(_encode_response(response))
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 - a closed stdout is silence, not a traceback
        pass
    finally:
        flush_deferred()


# Backstop for any path that returns without calling ``emit``: the queue still
# drains on a normal exit. ``flush_deferred`` pops, so a double drain is a no-op.
atexit.register(flush_deferred)


def clamp_decision(
    guard_name: str,
    natural_decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    context: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Clamp a guard's natural decision by the tiered config, log it, return it.

    Split out of ``clamp_and_emit`` for the guards whose hook event does not
    speak the PreToolUse schema. ``SubagentStop``'s only decision control is a
    top-level ``block``, so it cannot use the response ``clamp_and_emit``
    builds -- but it still has to be governed by the same ceiling and land in
    the same log, rather than deciding for itself off to one side.

    ``config`` is imported here rather than at module scope to keep this module
    free of cycles, and called behind a catch because it sits on the critical
    path of every gating guard: an exception raised while resolving a *ceiling*
    used to propagate out to the dispatcher's fail-open handler and take the
    whole decision with it. Config is only ever permitted to loosen, so failing
    to read it must leave the guard at full strength, never switch it off.
    """
    try:
        from config import effective_decision

        decision = effective_decision(guard_name, natural_decision)
    except Exception:  # noqa: BLE001 - unusable config must not disarm a guard
        decision = natural_decision
    # ``forcefield.natural`` is now written unconditionally by ``build_event``,
    # so only the downgrade breadcrumb is conditional. Absence of
    # ``config_downgraded`` is unambiguous precisely because ``natural`` is
    # always there, and keeping it conditional preserves the documented jq
    # recipe verbatim.
    merged = dict(extra) if extra else None
    if decision != natural_decision:
        merged = dict(merged or {})
        merged["config_downgraded"] = True
    defer_log(
        guard_name, decision,
        pattern_matched=pattern_matched, command=command,
        file_path=file_path, context=context, extra=merged,
        natural=natural_decision,
    )
    return decision


def _scrub_reason(guard_name: str, reason: str) -> str:
    """Mask credential values out of the text a decision hands to its channels.

    A guard that matches *on* a credential quotes back what it matched.
    ``exfil_guard``'s ``sensitive_in_curl`` alert -- whose risk line reads
    "Credential pattern in curl command" -- carries a ``Matched: <command>``
    line, and that command is the one with the token in it. ``build_event`` has
    masked the log side since it existed, so the same secret was scrubbed out of
    the audit trail and handed back in clear text through
    ``permissionDecisionReason`` at deny and ask, and at warn through
    ``systemMessage`` (human) and ``additionalContext`` (the model's context
    window). One scrub here covers every guard and every rung, because the warn
    branch builds both of its channels from the same string.

    Deliberately NOT bounded the way ``_scrub`` bounds a log attribute.
    ``MAX_REDACT_BYTES`` exists because a log record is not worth a slice of the
    hook's 5s budget -- a record is discardable, and truncating one costs a
    reader some context. A reason is not discardable: it is the only thing the
    human reads before approving, so cutting it silently would trade this defect
    for a worse one. The cost that ceiling protects against is not present here
    either -- every guard slices what it interpolates (120 chars in
    exfil/git/webfetch, 200 in filesystem, 8-12 in the credential-aware ones),
    so the longest reason any guard builds from a 500 KB command measures 580
    bytes, and every redaction pattern is linear.

    Wrapped because this now runs on the critical path, *before* the decision
    reaches stdout. A scrub that cannot complete degrades the explanation and
    nothing else: the clamped decision still gates exactly as it would have, so
    the fail-open invariant holds, and the credential stays masked rather than
    being waved through on an error path.
    """
    try:
        cleaned, _ = redact_secrets(reason)
        return cleaned
    except Exception:  # noqa: BLE001 - must neither leak nor block a tool call
        return (
            "ForceField %s fired. Its explanation could not be rendered safely "
            "and was withheld; see the security log for detail." % guard_name
        )


def clamp_and_emit(
    guard_name: str,
    natural_decision: str,
    reason: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    context: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Clamp a guard's natural decision by the tiered config, log it, and build
    the PreToolUse hook response.

    ``deny``/``ask`` -> a permissionDecision; ``warn`` -> context only
    (systemMessage); ``allow``/``off`` -> None (a config downgrade waves the call
    through). The clamp only ever loosens, so zero-false-positive-deny holds. The
    caller writes the returned dict (or ``{}`` when None) to stdout. Shared by the
    dispatcher and every standalone PreToolUse guard so the behavior is identical.

    An ``ask`` the user explicitly chose to remember (``/forcefield:remember``) is
    waved through here, before the config clamp — Claude Code returns a hook's
    ask as the final permission decision without consulting ``permissions.allow``,
    so this is the only layer that can stop a repeat prompt. Only ``ask`` is
    memoizable; a ``deny`` never is.

    ``reason`` is credential-scrubbed before either channel is built — see
    ``_scrub_reason`` for why that belongs here rather than in each guard.
    """
    if natural_decision == "ask":
        memo = _memo_hit(guard_name, pattern_matched, command or file_path)
        if memo is not None:
            defer_log(
                guard_name, "allow",
                pattern_matched=pattern_matched, command=command,
                file_path=file_path, context=context,
                extra={
                    "memo_hit": True,
                    "memo_key": memo.get("key", "")[:12],
                    "memo_uses": memo.get("uses"),
                },
                natural="ask",
            )
            return None

    decision = clamp_decision(
        guard_name, natural_decision,
        pattern_matched=pattern_matched, command=command,
        file_path=file_path, context=context, extra=extra,
    )
    # One scrub, above both branches: a guard that matched on a credential
    # quotes it back, and every channel below is built from this string.
    reason = _scrub_reason(guard_name, reason)
    if decision in ("deny", "ask"):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            },
        }
    if decision == "warn":
        # Two channels that do not overlap: ``systemMessage`` is shown to the
        # human and never enters the model's context, while ``additionalContext``
        # enters the model's context and is never shown to the human. Returning
        # only the first — as this did — meant the rung "tell the agent without
        # interrupting the person" did not exist. The agent went on working with
        # no idea a guard had fired, so demoting a check from ``ask`` to ``warn``
        # bought quiet by discarding the finding rather than by delivering it
        # less intrusively, and every such demotion traded detection for silence.
        #
        # No ``permissionDecision`` here, deliberately. An explicit ``allow`` is
        # a decision, not a note: it would let a warn satisfy a prompt the user
        # would otherwise have been shown. A warn must be able to inform without
        # ever loosening the outcome, so it carries context only.
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": (
                    "ForceField security finding (advisory — the call was not "
                    "blocked): " + reason
                ),
            },
            "systemMessage": reason,
        }
    return None


def _main_cli(argv: list[str]) -> int:
    """Emit one security record from the command line.

    Exists so ``container_first.sh`` — the one guard written in bash — can share
    this module's record shape instead of hand-building a second, incompatible
    one. Its flat ``{ts,hook,decision,pattern,command}`` line carried no
    ``SeverityText`` and no ``ocsf.*`` fields, so every documented jq recipe
    silently skipped it, including its hard denies; it bypassed credential
    masking entirely; and it appended with a raw ``>>`` behind the rotating
    handler's back.

    The command is read from stdin, never argv: an argv-borne command line is
    visible to every other user via ``ps``.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Emit a ForceField security record.")
    parser.add_argument("--hook", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--pattern", default=None)
    parser.add_argument("--session-id", default=None)
    # The correlation ids the shell guard already has in its parsed event. Without
    # them the highest-volume producer in the whole plugin wrote records that
    # joined to nothing -- not to the session, not to the tool call the other two
    # PreToolUse[Bash] hooks recorded for the same command.
    parser.add_argument("--tool-use-id", default=None)
    parser.add_argument("--prompt-id", default=None)
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--tool-name", default=None)
    parser.add_argument(
        "--command-stdin", action="store_true",
        help="read the command text from stdin (avoids exposing it in ps)",
    )
    args = parser.parse_args(argv)

    command = None
    if args.command_stdin:
        # Bytes, decoded explicitly: the command arrives from a shell hook whose
        # payload is whatever the model typed, and the platform locale is not a
        # safe guess about it. An unreadable stdin yields "" and never raises.
        command = read_stdin_text(MAX_REDACT_BYTES * 2)
    context = {}
    for key, value in (
        ("session_id", args.session_id),
        ("tool_use_id", args.tool_use_id),
        ("prompt_id", args.prompt_id),
        ("cwd", args.cwd),
        ("tool_name", args.tool_name),
    ):
        if value:
            context[key] = value
    try:
        log_security_event(
            args.hook, args.decision,
            pattern_matched=args.pattern, command=command,
            context=context,
        )
    except Exception:  # noqa: BLE001 - logging must never fail a guard
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(_main_cli(sys.argv[1:]))
