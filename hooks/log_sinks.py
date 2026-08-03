"""Where a ForceField security record goes, and how much of it each place gets.

Stdlib only, Python 3.9 floor. This module owns every write path: the JSON Lines
file under ``~/.claude/hooks``, the macOS unified log, the systemd journal, a
plain ``/dev/log`` datagram, and the Windows Application event log. At module
scope it imports nothing from ``hooks/`` except ``portable_lock``, and in
particular it never imports ``hook_logging`` or ``patterns`` at all -- the
record arrives already built and already credential-scrubbed. ``config`` is
read exactly once, lazily, inside ``_free_text_min``, for the one knob that can
only ever tighten what a sink is given.

**Confidentiality decides content, and it is measured per sink.** The old code
had one hardcoded rule -- "withhold the free-text fields from the macOS unified
log" -- which was both too narrow (a world-readable ``/var/log/messages`` on a
BusyBox host got the whole command line) and too blunt (the macOS store is
``drwxr-x--- root:admin``, which is a real access control, so the withholding
cost every macOS operator the field that Sysmon EventID 1 and auditd ``execve``
exist to record). The rule is now a property of the sink:

    a sink receives the free-text fields iff its measured confidentiality is
    >= FREE_TEXT_MIN_CONFIDENTIALITY.

The same three lines therefore put ``command.line`` into the macOS unified log
and keep it out of the Windows Application channel, and a sink whose
confidentiality nobody measured is ``CONF_UNKNOWN``, which is treated as
``CONF_LOCAL`` and never better.

**Three hard contracts, on every sink, because each closes a measured defect.**

1. *Never raises.* ``write`` returns True/False. A sink that threw past its own
   boundary made the next sink's write unreachable.
2. *Never blocks past a bounded deadline.* Socket sinks are non-blocking; a
   blocking ``sendto`` to a journald whose receive queue is full was measured
   not to return inside 5 s, which is the entire hook budget. Subprocess sinks
   carry ``timeout=2``.
3. *Never writes to stdout or stderr.* Against a stale ``/dev/log``, stdlib
   logging's ``handleError`` printed 1902 bytes of traceback **and the whole
   record including the command line** to the hook's stderr. There is no
   ``lastResort``, no ``raiseExceptions``, and no ``print`` in this module.

That third contract is why ``logging`` is gone from the hook path entirely
rather than being configured into silence: ``raiseExceptions = False`` is a
global mutation of a shared stdlib module that any later contributor can revert
with no test failing, while owning the write path makes the property structural.
It also returns the 7.9 ms that ``import logging, logging.handlers`` costs on
the hook interpreter, three times per Bash tool call.

``subprocess``, ``socket`` and ``struct`` are imported **inside** the sink
functions that need them, so macOS never pays for ``socket`` and Linux never
pays for ``subprocess``.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent))
import portable_lock  # noqa: E402

# ---------------------------------------------------------------------------
# Identity, shared by every sink so one query finds every record
# ---------------------------------------------------------------------------

SUBSYSTEM = "com.anthropic.claude-code.hooks"
CATEGORY = "security"
SYSLOG_IDENT = "cc-security"

NAME_FILE = "file"
NAME_OSLOG = "oslog"
NAME_JOURNALD = "journald"
NAME_SYSLOG = "syslog"
NAME_WINEVT = "winevt"

# ---------------------------------------------------------------------------
# Confidentiality
# ---------------------------------------------------------------------------

CONF_OWNER = 3      # only the record's owner can read it
CONF_ADMIN = 2      # the machine's administrators can read it
CONF_LOCAL = 1      # any authenticated local account can read it
CONF_UNKNOWN = 0    # not established -> treated as CONF_LOCAL, never better

FREE_TEXT_MIN_CONFIDENTIALITY = CONF_ADMIN

# The attributes that carry attacker-influenced or environment free text.
# Credential values are already masked out of them before a record reaches this
# module; a command line is sensitive on its own, which is what this set is
# about, and so is the absolute path of a working directory or a transcript.
#
# This is a SUBSET of ``hook_logging._FREE_TEXT_ATTRS`` (what gets scrubbed).
# ``forcefield.pattern`` is scrubbed but deliberately not withheld: it is the
# field a SIEM rule keys on, and withholding it would leave a low-confidentiality
# sink with a finding it cannot classify.
FREE_TEXT_FIELDS = (
    "command.line",
    "file.path",
    "process.working_directory",
    "session.transcript_path",
    "agent.transcript_path",
)

# The three OS endpoints, named rather than inlined so a fault-injection test can
# point one at nothing and prove the sink degrades instead of raising.
LOG_BINARY = "/usr/bin/log"
JOURNAL_SOCKET = "/run/systemd/journal/socket"
SYSLOG_SOCKET = "/dev/log"

# The unified-log store. Measured on macOS 26.5.2: drwxr-x--- root:admin, world
# bits 0o0, while /var/db above it is 0755 -- so `os.stat` succeeds for an
# ordinary process and the *parent* is the access control. `log show` opens the
# store files as the calling user, holding no privileged descriptor, so this
# directory is what decides who can read a historical record.
_UNIFIED_STORE = "/var/db/diagnostics"

# ---------------------------------------------------------------------------
# The file sink's budget
# ---------------------------------------------------------------------------

FALLBACK_MAX_BYTES = 8 * 1024 * 1024    # was 5 MB
FALLBACK_BACKUP_COUNT = 7               # was 3  -> 64 MB total, was 20 MB

# Bound on ONE unified-log message. This is the store's own ceiling, not a
# budget we chose: `logd` cuts the message and every read interface then renders
# a `<…>` marker where the rest was. Measured on macOS 26.5.2 (25F84) by
# emitting a marked payload at every size from 800 to 16000 bytes and reading it
# back with `log show --style ndjson`:
#
#     --type default / info / error   intact to 1015, cut from 1016
#     --type fault                    intact to 1985, cut from 1986
#     --type debug                    never persisted at all
#
# The previous value here was 16_384, which is 16x the real ceiling, so nothing
# in this module ever noticed: 14 of 15 records in a full capture arrived as
# JSON severed mid-string, taking `command.line` with them. `fault` is the one
# type with a larger allowance and it is reachable only by `deny`/`block`, so it
# is keyed off the emitted type rather than applied uniformly.
UNIFIED_LOG_MAX_BYTES = 1_015
UNIFIED_LOG_FAULT_MAX_BYTES = 1_985

# Whole-datagram ceiling for the plain-syslog sink, PRI header included. This is
# the largest datagram that SURVIVES, following the same convention as
# UNIFIED_LOG_MAX_BYTES above -- not the smallest that is cut.
#
# The transport is not the binding limit -- the AF_UNIX SOCK_DGRAM ceiling
# measured on Linux 6.18.5 is 212,960 bytes -- the *daemon* is. Re-measured
# against BusyBox syslogd 1.37.0 in `python:3.9-slim` at every datagram size:
# **1023 bytes stored intact, 1024 stored cut.** That is RFC 3164 s4.1's "the
# total length of the packet MUST be 1024 bytes or less" implemented as a
# 1024-byte buffer with a terminator, and since a `/dev/log` sink cannot tell
# rsyslog from BusyBox at the socket, the smaller number governs.
#
# The previous value was 1_024, which is the FIRST CUT size and therefore one
# byte inside the cut region. That was not latent bookkeeping: `_split` computes
# its envelope budget at the widest index/count, so a fragment is exactly this
# size on the wire from the tenth fragment of an 11-fragment record onwards, and
# one byte off it removes the closing brace. The fragment then does not parse,
# and because fragmentation is all-or-nothing the WHOLE record is lost --
# measured at cmd_len=9000: 11 fragments sent, one unparseable, 0 records
# reassembled. A worse failure mode than the truncation this replaced.
SYSLOG_MAX_BYTES = 1_023

# Well inside both the 31,839-character insertion-string limit and the
# 32,767-character CreateProcessW command-line limit. UNVERIFIED against a real
# `eventcreate.exe`: no Windows host was available.
EVENTCREATE_PAYLOAD_MAX = 8_000

# How many messages one record may be split across when it does not fit a sink's
# ceiling.
#
# 16 x 1015 bytes of unified-log payload is ~14 KB of record, which covers the
# largest record the Bash guards can build (MAX_COMMAND_SCAN_BYTES is 8 KiB) and
# happens to be the budget the old 16_384 constant claimed. `log emit` costs a
# measured 3.1 ms, so 16 fragments is 50 ms; a deadline exists for the other
# case, where the emitter hangs and 16 unbounded calls would run past the 5 s
# hook budget that is itself a security boundary.
#
# **That deadline is `LOG_BUDGET_SECONDS`, and it is the only one.** There was a
# second constant here, `EMIT_BUDGET_SECONDS = 2.0`, described as the per-record
# ceiling. It could never bind and was deleted on 2026-08-02:
# `budget_remaining()` returns `LOG_BUDGET_SECONDS - _budget_spent` clamped at 0
# and `_spend` only ever adds, so `min(EMIT_BUDGET_SECONDS, budget_remaining())`
# was always the second term, and the per-call `subprocess` timeout derived from
# it was always `remaining` for the same reason. A per-RECORD cap larger than
# the per-PROCESS cap is not a bound, and documenting it as one made
# `docs/logging/00-field-reference.md` assert a deadline that could not fire.
# Removing it changed no measured behaviour; see MEASURED.md, 2026-08-02.
FRAGMENT_MAX_COUNT = 16

# One process, one logging budget.
#
# Three bounds used to sit on this path and not one of them bounded the
# *process*: ``portable_lock``'s 1.0 s deadline bounds one rotation acquisition,
# a per-record subprocess ceiling bounded one record's subprocess sink, and the
# old drain
# budget bounded one drain of the deferred queue. Multiply any of them by the
# record count and the hook timeout is gone. Measured on this tree before the
# budget existed: six records with ``.rotate.lock`` held by another process took
# **6.059 s**, and four synchronous WARN records against a hung emitter took
# **8.044 s** -- both past the 5 s at which Claude Code kills a hook. That kill
# is a security boundary, not a latency budget: a killed hook delivers no
# verdict, so a correctly computed hard deny becomes a silent allow.
#
# So the ceiling is on the process. Every second spent waiting for the rotation
# lock or talking to a native sink comes out of one pot; once it is empty,
# rotation is skipped and the native sinks are skipped for the rest of this
# process, and both facts are reported on the NEXT record this process writes
# (``forcefield.rotation_failed`` and ``forcefield.native_writes_skipped``).
# Not on ``session.end``: that is a different process and these are module
# globals, so it could only ever have reported zero.
#
# The file sink is never skipped and never charged, and that exemption is a
# structural claim, not a measured average: its open is O_NONBLOCK and refuses
# anything that is not a regular file, so there is no unbounded wait on it to
# charge. What the archive can lose is a *rollover*, which costs an oversized
# file and not a record.
LOG_BUDGET_SECONDS = 1.0

# A record reaches a native sink when its OTel SeverityNumber is at least this
# (the WARN band: warn / ask / redact / deny / block) or when it is a lifecycle
# record. Everything else exists only in the file sink.
#
# This is not a new restriction, it is the existing *silent* one made explicit
# and deterministic. Measured on the macOS unified log: 0 of 43 `allow` records
# survived a 10-minute window, `Info`'s oldest survivor was 11m48s old against
# 20.5h for `Default`, and no `off` record has ever appeared there at all. The
# floor spends 3.3 ms per record only on records the store actually keeps, and
# it shrinks the argv-exposure window to the ~3% of records a control fired on.
NATIVE_SINK_MIN_SEVERITY = 13

# Lifecycle records bypass the floor: they are the heartbeat, and a session
# record in the native sink is the only cheap way to tell "the file sink died"
# from "nothing happened".
_FLOOR_EXEMPT_CLASSES = frozenset({"lifecycle"})

# Environment allowlist of *native* sink names. `none` or the empty string
# selects no native sink. Deliberately an environment variable and not a config
# key: it has to work before config is read, and it has to be inheritable by a
# subprocess-driven test case, which is the reason it exists -- a suite that
# spawns real hooks would otherwise write fabricated records into the operator's
# real machine-global log, and no `$HOME` diversion can stop that, because the
# unified log and the journal are not under `$HOME`.
#
# Two properties keep it from being a way to silence the audit trail:
#
#   * It can never remove the file sink, which is unioned in after this.
#   * An unrecognised token means the WHOLE variable is ignored and the platform
#     default stands. `FORCEFIELD_LOG_SINKS=oslgo` used to drop every native
#     sink silently, so a typo in a settings file degraded the posture with
#     nothing recorded anywhere. It now degrades nothing and is reported.
#
# What it does is reported rather than assumed: `env_selection()` feeds
# `forcefield.sinks.env` on the `session.start` record, so "the journal exists
# here and ForceField is not writing to it" carries its reason.
ENV_SINKS = "FORCEFIELD_LOG_SINKS"

# The names the variable may carry. `file` is deliberately absent: naming it
# would not add the file sink (it is unconditional) and omitting it must not
# remove it, so accepting the token would only be a way to write a value that
# looks like it turns the archive off.
NATIVE_SINK_NAMES = frozenset({NAME_OSLOG, NAME_JOURNALD, NAME_SYSLOG,
                               NAME_WINEVT})

_selected: Optional[frozenset] = None
_conf_cache: Dict[str, int] = {}
_store_restricted: Optional[bool] = None
_free_text_floor: Optional[int] = None
_file_dir: Optional[Path] = None
_dir_prepared = False
_rotation_failed = False
_record_builder = None
_budget_spent = 0.0

# What one `log emit` costs, seeded from the macOS measurement (3.1 ms) with a
# safety factor and then raised to the worst this process has actually seen. It
# is only ever used to decide whether a MULTI-fragment record can be emitted
# whole, so over-estimating drops a native copy the file sink still holds, while
# under-estimating leaves orphan fragments in the store. Monotonic on purpose:
# it never falls back towards an optimistic number after a slow call.
_emit_cost_estimate = 0.010
_native_records_dropped = 0


# ---------------------------------------------------------------------------
# The process-wide logging budget
# ---------------------------------------------------------------------------

def budget_remaining() -> float:
    """Seconds of *blocking* work this process may still spend on logging.

    Read before every rotation attempt and before every native-sink write, so a
    stalled lock or a hung emitter costs latency once and then stops costing
    anything at all. Never negative, so a caller can pass it straight to a
    timeout.
    """
    remaining = LOG_BUDGET_SECONDS - _budget_spent
    return remaining if remaining > 0 else 0.0


def _spend(seconds: float) -> None:
    """Charge blocking time to the process budget. Never raises."""
    global _budget_spent  # noqa: PLW0603
    try:
        if seconds > 0:
            _budget_spent += seconds
    except Exception:  # noqa: BLE001 - accounting must never break a write
        pass


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def env_selection() -> Dict[str, Any]:
    """How ``FORCEFIELD_LOG_SINKS`` was read on this process. Never raises.

    Recomputed on every call rather than cached: the cache would be a second
    thing to reset, and a test that reset only ``_selected`` would then measure
    a stale answer. The read is one ``os.environ`` lookup and a split.

    ``honoured`` is False either because the variable is unset or because it
    carried a token this module does not recognise -- in which case the platform
    default stands and ``unrecognised`` names what was rejected.

    An EMPTY value is treated as unset, not as "select nothing". ``bogus`` no
    longer degrades the posture and neither may ``FORCEFIELD_LOG_SINKS=""``,
    which is one unset shell expansion away: ``FORCEFIELD_LOG_SINKS=$UNSET_VAR``
    used to remove journald and the unified log with nothing to say a setting
    had been mistyped. Turning the native sinks off is spelled ``none``, which
    is a token and stays honoured.
    """
    raw = os.environ.get(ENV_SINKS)
    state = {"set": raw is not None, "value": raw, "honoured": False,
             "names": None, "unrecognised": []}
    if raw is None or not raw.strip():
        return state
    names, rejected = set(), []
    for part in raw.split(","):
        token = part.strip().lower()
        if not token or token == "none":
            continue
        if token in NATIVE_SINK_NAMES:
            names.add(token)
        else:
            rejected.append(token[:32])
    state["unrecognised"] = sorted(rejected)
    if not rejected:
        state["honoured"] = True
        # A list, not a set: this dict is rendered into a record, and json
        # cannot serialise a set -- it would take the salvage path and lose the
        # rest of the attribute.
        state["names"] = sorted(names)
    return state


def _env_allowlist():
    """The native-sink allowlist to apply, or None when the default stands."""
    return env_selection()["names"]


def _candidates():
    """The native sinks this platform could offer, most-preferred first.

    macOS has no ``/dev/log`` candidate on purpose. Measured: syslogd runs with
    ``ASL_DISABLE=1`` and discards socket input -- a uniquely tagged record
    reached the 0600 file and ``log emit`` and nothing else. The datagram was
    CPU spent on a black hole.

    On Linux the journald-versus-anything-else question is answered by one
    ``os.path.exists``. journald creates ``/run/systemd/journal/socket`` itself,
    with no socket activation, even when it is not PID 1; rsyslog and BusyBox
    create only ``/dev/log``. So the existence of that path *is* the measurement
    that licenses ``command.line`` on this host.
    """
    if sys.platform == "darwin":
        return (NAME_OSLOG,)
    if os.name == "nt":
        return (NAME_WINEVT,)
    if sys.platform.startswith("linux"):
        if os.path.exists("/run/systemd/journal/socket"):
            return (NAME_JOURNALD,)
        if os.path.exists(SYSLOG_SOCKET):
            return (NAME_SYSLOG,)
    return ()


def _probe():
    sinks = {NAME_FILE}
    allow = _env_allowlist()
    for name in _candidates():
        if allow is None or name in allow:
            sinks.add(name)
    return frozenset(sinks)


def selected() -> frozenset:
    """Which sinks this process writes to. Resolved once, never raises."""
    global _selected  # noqa: PLW0603
    if _selected is None:
        try:
            _selected = _probe()
        except Exception:  # noqa: BLE001 - a failed probe still logs to the file
            _selected = frozenset({NAME_FILE})
    return _selected


def _unified_store_restricted() -> bool:
    """True when the unified-log store denies traversal to non-group users.

    Re-checked at runtime rather than hardcoded, so an OS release that widens
    the store, or an admin who loosens it, returns ForceField to withholding
    without needing a new version. Unknown means withhold: failing closed here
    costs a log field and can never block a tool call.
    """
    global _store_restricted  # noqa: PLW0603
    if _store_restricted is None:
        try:
            _store_restricted = (os.stat(_UNIFIED_STORE).st_mode & 0o007) == 0
        except OSError:
            _store_restricted = False
    return _store_restricted


def confidentiality(name: str) -> int:
    """How exposed anything written to ``name`` is. Cached per process.

    Every value here is a measurement, not a guess:

    file      OWNER -- 0600 in a 0700 directory on macOS and in a Linux
              container, created 0600 by the open itself with no chmod race.
              On Windows this rests on the user-profile DACL instead, because
              ``os.chmod`` sets only the read-only flag there.
    oslog     ADMIN -- /var/db/diagnostics is 0750 root:admin with world bits 0,
              re-checked at runtime; LOCAL if that check fails.
    journald  ADMIN -- system.journal is 0640 root:systemd-journal with
              other::---, and under the default SplitMode=uid a per-user journal
              carries an ACL naming only that user (a cross-uid read was
              measured denied). ADMIN is the floor because SplitMode is
              configurable, and a classification must be its floor.
    syslog    LOCAL -- BusyBox syslogd writes /var/log/messages 0644; rsyslog
              writes auth.log 0640 root:adm. The two are indistinguishable at
              the socket, so the floor governs.
    winevt    LOCAL -- the default Application-channel SDDL grants
              (A;;0x1;;;AU): Authenticated Users may read.
    """
    if name in _conf_cache:
        return _conf_cache[name]
    try:
        if name == NAME_FILE:
            conf = CONF_OWNER
        elif name == NAME_OSLOG:
            conf = CONF_ADMIN if _unified_store_restricted() else CONF_LOCAL
        elif name == NAME_JOURNALD:
            conf = CONF_ADMIN
        elif name in (NAME_SYSLOG, NAME_WINEVT):
            conf = CONF_LOCAL
        else:
            conf = CONF_UNKNOWN
    except Exception:  # noqa: BLE001 - an unknown sink is never a trusted one
        conf = CONF_UNKNOWN
    _conf_cache[name] = conf
    return conf


def _free_text_min() -> int:
    """The operator's free-text disclosure floor, resolved once per process.

    ``FREE_TEXT_MIN_CONFIDENTIALITY`` (CONF_ADMIN) is the shipped floor; the
    ``log_free_text: "owner"`` config key raises it to CONF_OWNER, which
    restores the old macOS withholding losslessly for an operator who declines
    the trade -- nothing moves out of the 0600 file, the unified log merely
    stops gaining a copy. That key can only ever TIGHTEN disclosure, which is
    why it is safe for config to hold at all.

    ``config`` is imported here, not at module scope: this module is a layer
    below it in the import graph and must stay importable without it. An
    unreadable config keeps the shipped floor, and a value that somehow came
    back lower than the shipped floor is ignored -- config may tighten, never
    loosen, this particular knob.
    """
    global _free_text_floor  # noqa: PLW0603
    if _free_text_floor is None:
        floor = FREE_TEXT_MIN_CONFIDENTIALITY
        try:
            import config  # noqa: PLC0415

            resolved = config.resolve_free_text_confidentiality()
            if isinstance(resolved, int) and resolved > floor:
                floor = resolved
        except Exception:  # noqa: BLE001 - config must never widen disclosure
            floor = FREE_TEXT_MIN_CONFIDENTIALITY
        _free_text_floor = floor
    return _free_text_floor


# ---------------------------------------------------------------------------
# Projection and rendering
# ---------------------------------------------------------------------------

def project(record: Dict[str, Any], conf: int) -> Dict[str, Any]:
    """The part of a record a sink at this confidentiality may carry.

    Replaces the hardcoded, macOS-only withholding. The record is not mutated;
    a trimmed copy is returned, so the same record object can be projected
    differently for two sinks in the same write.
    """
    try:
        if conf >= _free_text_min():
            return record
        attributes = record.get("Attributes")
        if not isinstance(attributes, dict):
            return record
        withheld = [name for name in FREE_TEXT_FIELDS if name in attributes]
        if not withheld:
            return record
        projected = dict(record)
        trimmed = {k: v for k, v in attributes.items() if k not in withheld}
        trimmed["forcefield.withheld_fields"] = withheld
        trimmed["forcefield.detail_in"] = str(file_path())
        projected["Attributes"] = trimmed
        return projected
    except Exception:  # noqa: BLE001 - a projection failure must not lose the record
        return record


def render(record: Dict[str, Any]) -> str:
    """Serialize one record to the single line every sink carries.

    ``ensure_ascii=True`` is an **invariant, not a default**. Every hook now
    decodes its stdin with ``surrogateescape``, so a command line containing a
    byte that is not valid UTF-8 reaches this function holding a lone surrogate.
    Measured: under ``ensure_ascii=True`` that serialises to pure ASCII
    (``\\udc87`` as an escape) and encodes to UTF-8 safely; under
    ``ensure_ascii=False`` it raises ``UnicodeEncodeError``. A later "make the
    log readable" change here would silently drop every record whose command
    line carries an invalid byte -- which is exactly the record an investigator
    wants most.

    ``default=str`` is the salvage path: an ``extra`` value that is not
    JSON-native costs its own fidelity, never the whole record.

    **This function never raises**, which is the module's first contract and was
    not true of the ``default=str`` retry. Measured: an object whose ``__str__``
    raises came back out of the retry as ``RuntimeError``; a non-string dict key
    that ``str()`` cannot rescue came back as ``TypeError``; and a
    self-referential structure re-raised ``ValueError: Circular reference
    detected`` because ``default`` is never consulted for a cycle. Every caller
    already wraps this, so the effect was a silently dropped record rather than a
    blocked tool call -- but a contract the suite asserts and the code does not
    hold is one refactor away from being load-bearing. The floor below the retry
    is a scalar-only salvage that cannot fail: no container survives it, so
    there is no cycle to detect and no ``default`` to consult, and the marker
    says the record is partial rather than leaving a reader to guess.
    """
    try:
        return json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        pass
    try:
        return json.dumps(record, separators=(",", ":"), ensure_ascii=True,
                          default=str)
    except Exception:  # noqa: BLE001 - str() itself can raise; cycles re-raise
        pass
    try:
        salvage: Dict[str, Any] = {}
        for key, value in record.items():
            if not isinstance(key, str):
                continue
            if value is None or isinstance(value, (str, bool, int)):
                salvage[key] = value
            elif isinstance(value, float) and -1e308 < value < 1e308:
                # Excludes NaN (every comparison is False) and both infinities,
                # which json.dumps would otherwise render as bare tokens that no
                # strict JSON parser accepts.
                salvage[key] = value
        salvage["forcefield.render_failed"] = True
        return json.dumps(salvage, separators=(",", ":"), ensure_ascii=True)
    except Exception:  # noqa: BLE001 - the floor is a constant, and constants hold
        return '{"forcefield.render_failed":true}'


# ---------------------------------------------------------------------------
# Fragmentation: how a record crosses a sink that has a message ceiling
#
# Every sink here except the file and the journal has a hard per-message limit
# it enforces by CUTTING, and a JSON document cut mid-string is a fragment no
# parser will read. The rule this module now holds is:
#
#     every message a sink emits is, on its own, a parseable JSON object.
#
# A record that fits goes whole. A record that does not is split across numbered
# fragments, each of which is its own small JSON envelope carrying a slice of
# the rendered line. `reassemble` joins them back into the exact original bytes.
#
# The alternative -- a smaller projection that fits in one message -- was
# measured impossible on macOS rather than rejected on taste. A real
# `supply_chain_guard` deny renders to 1364 bytes and its CONF_LOCAL projection
# to 1210, both over the 1015-byte ceiling; a real `session.start` renders to
# 1408 and its CONF_LOCAL projection to *1508*, because withholding two fields
# adds `forcefield.withheld_fields` and `forcefield.detail_in`. There is no
# projection of an OTel+OCSF envelope that fits in 1015 bytes, so anything that
# keeps one record shape has to fragment.
# ---------------------------------------------------------------------------

# The fragment envelope's keys, kept short because every byte of envelope is a
# byte of record that does not fit. `pc.b` is the total byte length of the
# rendered record, so a reader can verify a reassembly rather than trust it.
_FRAGMENT_KEY = "pc.frag"

# What a reduced record keeps when even fragmenting cannot carry it. Ordered by
# what a SIEM keys on first.
_MINIMAL_ATTRS = (
    "forcefield.record_class",
    "forcefield.guard",
    "forcefield.decision",
    "forcefield.pattern",
    "session.id",
    "tool.name",
    "command.line",
)


def _index_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    """The three fields every fragment repeats so a grep can find the record.

    On the plain-syslog path fragmentation is not the exception, it is the rule:
    measured on Linux, 33 of 33 messages were fragments and 0 of 15 records
    crossed whole, because the smallest projection a real guard produces is
    ~1.2 KB against a 1,006-byte payload budget. Without these, no message in
    ``/var/log/messages`` carries ``forcefield.decision``, ``forcefield.guard``
    or ``session.id`` in any readable form, and the only reader that can recover
    one is a Python function inside this plugin -- which is not "complete for
    breach forensics" for anybody who does not have the plugin.

    All three are already in the projected record and none is ever withheld
    (``forcefield.pattern`` is scrubbed but not withheld precisely because it is
    what a SIEM keys on), so repeating them discloses nothing new. They cost
    ~75 bytes of every fragment, which is ~8% more fragments on the syslog path.
    """
    attributes = record.get("Attributes")
    if not isinstance(attributes, dict):
        return {}
    out = {}
    for key, short in (("forcefield.guard", "pc.g"),
                       ("forcefield.decision", "pc.v"),
                       ("session.id", "pc.s")):
        value = attributes.get(key)
        if isinstance(value, str) and value:
            out[short] = value[:64]
    return out


def _fragment(ident: str, index: int, count: int, total: int, data: str,
              index_fields: Optional[Dict[str, Any]] = None) -> str:
    """One fragment envelope. ASCII-only, like every other rendered line."""
    envelope = {_FRAGMENT_KEY: ident, "pc.i": index, "pc.n": count,
                "pc.b": total}
    if index_fields:
        envelope.update(index_fields)
    envelope["pc.d"] = data
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)


def _fit_slice(text: str, start: int, budget: int) -> str:
    """The longest prefix of ``text[start:]`` whose JSON escaping fits ``budget``.

    Splitting the *raw* line and escaping each slice afterwards is what makes
    this safe: there is no escape sequence to cut in half, because the escaping
    happens after the cut. The back-off is proportional, so it converges in two
    or three passes even on text where every character doubles.
    """
    take = min(budget, len(text) - start)
    while take > 0:
        piece = text[start:start + take]
        size = len(json.dumps(piece, ensure_ascii=True)) - 2
        if size <= budget:
            return piece
        take = min(take - 1, max(1, take * budget // size))
    return ""


def _split(line: str, limit: int, index_fields=None):
    """``line`` as <= FRAGMENT_MAX_COUNT fragments, or None if it needs more.

    The fragment id is the SHA-1 of the line rather than a random value, so two
    runs of the same hook over the same event produce byte-identical messages --
    a capture that differs only in a nonce cannot be diffed across platforms.
    """
    import hashlib

    encoded = line.encode("utf-8", "replace")
    total = len(encoded)
    ident = hashlib.sha1(encoded).hexdigest()[:16]
    # The widest index and count the envelope can carry, so the real envelope is
    # never longer than the one this budget was computed from.
    head = len(_fragment(ident, FRAGMENT_MAX_COUNT, FRAGMENT_MAX_COUNT, total,
                         "", index_fields))
    budget = limit - head
    if budget < 1:
        return None
    slices = []
    position = 0
    while position < len(line):
        piece = _fit_slice(line, position, budget)
        if not piece:
            return None
        slices.append(piece)
        position += len(piece)
        if len(slices) > FRAGMENT_MAX_COUNT:
            return None
    count = len(slices)
    return [_fragment(ident, index + 1, count, total, piece, index_fields)
            for index, piece in enumerate(slices)]


def _capped(record: Dict[str, Any], cap: int) -> Dict[str, Any]:
    """The record with every over-long attribute value cut, inside its string.

    Cutting a *value* keeps the document parseable, which cutting the document
    does not. The two breadcrumbs say which fields were cut and where the whole
    thing still lives.
    """
    attributes = record.get("Attributes")
    if not isinstance(attributes, dict):
        return record
    trimmed = {}
    cut = []
    for key, value in attributes.items():
        if isinstance(value, str) and len(value) > cap:
            trimmed[key] = value[:cap] + "...[%d more chars]" % (len(value) - cap)
            cut.append(key)
        else:
            trimmed[key] = value
    if not cut:
        return record
    trimmed["forcefield.truncated_fields"] = cut
    trimmed["forcefield.detail_in"] = str(file_path())
    reduced = dict(record)
    reduced["Attributes"] = trimmed
    return reduced


# What the floor rung keeps of ``Body``. Body is the human sentence, not a
# field a SIEM keys on, and it is bounded only by MAX_REDACT_BYTES upstream --
# 64 KiB, which is twice the whole 16 x 1985-byte fragment ladder.
_MINIMAL_BODY_CHARS = 200


def _minimal(record: Dict[str, Any]) -> Dict[str, Any]:
    """The floor: the envelope, the fields a SIEM keys on, and nothing else.

    Unreachable for any record a guard builds -- it exists so that
    ``fragments`` is total rather than nearly total, because the one thing this
    layer may never do is emit something that does not parse.

    That claim was false while this kept ``Body`` whole: a Body no rung could
    shrink made ``fragments`` return ``[]``, and oslog, syslog and winevt then
    emitted **nothing at all** for the record. Measured with a 200 KB Body:
    ``fragments(..., 1985) -> 0``. Body is cut here for the same reason every
    attribute is, and ``forcefield.detail_in`` already names where the whole
    record still lives.
    """
    attributes = record.get("Attributes")
    keep: Dict[str, Any] = {}
    if isinstance(attributes, dict):
        for key in _MINIMAL_ATTRS:
            value = attributes.get(key)
            if isinstance(value, str):
                keep[key] = value[:64]
            elif value is not None:
                keep[key] = value
    keep["forcefield.reduced"] = True
    keep["forcefield.detail_in"] = str(file_path())
    reduced = {k: v for k, v in record.items() if k != "Attributes"}
    reduced.pop("Resource", None)
    body = reduced.get("Body")
    if isinstance(body, str) and len(body) > _MINIMAL_BODY_CHARS:
        reduced["Body"] = body[:_MINIMAL_BODY_CHARS]
    reduced["Attributes"] = keep
    return reduced


def fragments(record: Dict[str, Any], line: str, limit: int):
    """Every message this record becomes on a sink whose ceiling is ``limit``.

    One element when the record fits, which is the ordinary case and costs one
    length check. Otherwise a numbered set, each element parseable JSON, that
    ``reassemble`` joins back into ``line`` byte for byte.

    Returns an empty list only if the record could not be rendered at all --
    never a payload that does not parse.

    **Contract: ``line`` must be ``render(record)``.** Only the first rung uses
    ``line``; every rung below it re-renders ``record``, so a caller that passes
    a projected line beside an unprojected record gets the projection back the
    moment a record is too large to fragment. ``write()`` guarantees the pairing
    by re-projecting and, if that changed anything, re-rendering -- this is a
    module-internal function and callers outside ``write()`` own the invariant
    themselves.
    """
    try:
        if len(line.encode("utf-8", "replace")) <= limit:
            return [line]
        index_fields = _index_fields(record)
        parts = _split(line, limit, index_fields)
        if parts is not None:
            return parts
        for cap in (1024, 512, 256, 128, 64, 32, 16):
            parts = _split(render(_capped(record, cap)), limit, index_fields)
            if parts is not None:
                return parts
        parts = _split(render(_minimal(record)), limit, index_fields)
        return parts if parts is not None else []
    except Exception:  # noqa: BLE001 - a sink that cannot bound a record writes none
        return []


# How many alternative joins one fragment group may be tried in. A group only
# has alternatives when two messages claim the same id, count, byte length AND
# index with different data -- i.e. when something forged one. The bound is what
# stops a flood of forgeries turning the reader into an exponential search.
_REASSEMBLY_MAX_CANDIDATES = 256


def _fragment_group(parsed: Dict[str, Any]):
    """``(id, count, bytes, index, data)`` from a fragment, or None if malformed.

    Every field is validated rather than subscripted. ``reassemble`` reads a
    sink, and on macOS that sink is the unified log, which **any local account
    can write** with one unprivileged ``/usr/bin/log emit`` -- so every value
    here is attacker-controlled input, not this module's own output. The old
    code did ``parsed["pc.i"]`` on it: a message carrying ``pc.frag`` and nothing
    else raised ``KeyError`` out of the only function in this module without an
    ``except``, and a list-valued ``pc.frag`` raised ``TypeError: unhashable``.
    Either killed the whole read, losing every genuine record in the stream.
    """
    ident = parsed.get(_FRAGMENT_KEY)
    index = parsed.get("pc.i")
    count = parsed.get("pc.n")
    total = parsed.get("pc.b")
    data = parsed.get("pc.d")
    if not isinstance(ident, str) or not ident:
        return None
    # bool is an int subclass and is never a valid index or count.
    for value in (index, count, total):
        if not isinstance(value, int) or isinstance(value, bool):
            return None
    if not isinstance(data, str):
        return None
    if count < 1 or total < 0 or index < 1 or index > count:
        return None
    return (ident, count, total, index, data)


def _join_candidates(slots, count: int):
    """Every join of one alternative per index, newest-first, bounded.

    ``slots`` maps index -> ordered list of distinct data strings. In the honest
    case every list has one element and this yields exactly one join.
    """
    import itertools

    ordered = [slots[index] for index in range(1, count + 1)]
    width = 1
    for choices in ordered:
        width *= len(choices)
        if width > _REASSEMBLY_MAX_CANDIDATES:
            return
    for combination in itertools.islice(itertools.product(*ordered),
                                        _REASSEMBLY_MAX_CANDIDATES):
        yield "".join(combination)


def reassemble(messages):
    """Whole records from a stream of sink messages, and the ids still missing.

    Returns ``(records, incomplete)``. A message that is not a fragment passes
    through unchanged, so a reader can feed it everything a sink returned.

    **Never raises.** That is the module's first contract and this is the
    function a reader points at a live sink, so it holds against arbitrary input
    rather than against this module's own output.

    Two things a forged message must not be able to do, both measured against the
    real macOS store with an unprivileged ``log emit``:

    *Suppress a genuine record.* A group used to be keyed on the id alone with
    ``counts[ident]`` overwritten by the last message seen, so one fragment
    reusing a genuine id with a larger ``pc.n`` moved the whole group to
    ``incomplete`` and the genuine deny vanished from the reader's output -- not
    flagged as tampered, absent. The group key is now ``(id, count, bytes)``, so
    a forgery that disagrees about any of the three forms its own group and
    leaves the genuine one intact, and a forgery that agrees about all three
    still only adds an *alternative* at its index rather than replacing what is
    there.

    *Tamper with a group.* The id is ``sha1(line)[:16]`` by design, which makes
    it a checksum as well as a key: a reassembly is accepted only when the
    joined line both matches ``pc.b`` and re-hashes to the id it was filed
    under, so a group whose joined bytes disagree with its own id is refused and
    reported in ``incomplete`` rather than returned.

    **That is reassembly INTEGRITY, not authenticity, and the difference is
    load-bearing.** The id binds a group to its OWN bytes and authenticates
    nothing: an attacker who can write to the store emits their own line and
    computes the id of their own line. Measured — an unprivileged ``log emit``
    (uid 501, no ``sudo``) produced a line this function returns as a genuine
    record, and the non-fragment branch above does not even reach the hash,
    which is the cheaper path for any record under the 1015-byte ceiling. The
    macOS unified log is writable by any local process, so treat everything this
    returns as attacker-influenced; the 0600 file sink is the record of
    authority. Closing this would take a MAC over the line keyed by something
    the attacker cannot read, which this module deliberately does not have.
    """
    import hashlib

    whole = []
    # (ident, count, total) -> {index: [data, ...]}
    pending = {}
    seen_ids = []
    for message in messages:
        try:
            parsed = json.loads(message)
        except Exception:  # noqa: BLE001 - a foreign message is not a record
            continue
        if not isinstance(parsed, dict) or _FRAGMENT_KEY not in parsed:
            whole.append(parsed)
            continue
        fields = _fragment_group(parsed)
        if fields is None:
            continue
        ident, count, total, index, data = fields
        if ident not in seen_ids:
            seen_ids.append(ident)
        slots = pending.setdefault((ident, count, total), {})
        alternatives = slots.setdefault(index, [])
        if data not in alternatives:
            alternatives.append(data)

    assembled_ids = set()
    for (ident, count, total), slots in pending.items():
        try:
            if sorted(slots) != list(range(1, count + 1)):
                continue
            for line in _join_candidates(slots, count):
                encoded = line.encode("utf-8", "replace")
                if len(encoded) != total:
                    continue
                if hashlib.sha1(encoded).hexdigest()[:16] != ident:
                    continue
                try:
                    record = json.loads(line)
                except Exception:  # noqa: BLE001 - a join that does not parse is not a record
                    continue
                whole.append(record)
                assembled_ids.add(ident)
                break
        except Exception:  # noqa: BLE001 - one poisoned group never costs the others
            continue

    incomplete = [ident for ident in seen_ids if ident not in assembled_ids]
    return whole, incomplete


# ---------------------------------------------------------------------------
# The file sink
# ---------------------------------------------------------------------------

def file_dir() -> Path:
    global _file_dir  # noqa: PLW0603
    if _file_dir is None:
        _file_dir = Path.home() / ".claude" / "hooks"
    return _file_dir


def file_path() -> Path:
    return file_dir() / "security.log"


def rotation_failed() -> bool:
    """Whether this process gave up on a rollover. A breadcrumb, not a state."""
    return _rotation_failed


def native_records_dropped() -> int:
    """How many records a native sink refused WHOLE in this process.

    Distinct from ``hook_logging.native_writes_skipped``, which counts records
    the process logging budget never offered to a sink at all. This counts the
    ones a sink took and then declined: a multi-fragment record it could not
    promise to finish, or one no reduction rung could bound. Both ride the next
    record THIS process writes, because a record absent from the OS log with no
    breadcrumb reads exactly like a tool call that never happened -- and
    because a counter that is a module global cannot be reported by any other
    process, which is what ``session.end`` was trying to do.
    """
    return _native_records_dropped


def _harden_log_mode() -> None:
    """Keep the log, its backups and its directory owner-only.

    The security log carries command lines and file paths -- and, where a
    redaction pattern does not cover a shape, credential material. Called on
    *every* rotation path including "someone else already rotated" and "the lock
    could not be taken": those two used to return early, and a rotation that
    took one of them left the backups at whatever the umask produced.

    A no-op in substance on Windows, where ``os.chmod`` sets only the read-only
    flag; there the protection is the user-profile DACL and the docs say so.
    """
    try:
        os.chmod(str(file_dir()), 0o700)
    except OSError:
        pass
    base = str(file_path())
    for index in range(FALLBACK_BACKUP_COUNT + 1):
        path = base if index == 0 else "%s.%d" % (base, index)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _prepare_dir() -> None:
    global _dir_prepared  # noqa: PLW0603
    if _dir_prepared:
        return
    try:
        file_dir().mkdir(parents=True, exist_ok=True)
        os.chmod(str(file_dir()), 0o700)
    except OSError:
        pass
    _dir_prepared = True


def _open_append(path: str) -> int:
    """The one write descriptor. Created 0600 by the open itself.

    ``O_APPEND`` makes a single write atomic against concurrent writers, which
    is what keeps malformed lines at zero across processes.
    ``getattr(os, "O_BINARY", 0)`` is 0 on POSIX and stops the Windows CRT
    turning our ``\\n`` into ``\\r\\n``: the file sink owns its newline byte.

    ``O_NONBLOCK`` and the ``S_ISREG`` check are the sink's one unbounded path,
    closed. This module exempts the file sink from ``LOG_BUDGET_SECONDS`` on the
    grounds that a raw append measured 0.027 ms and no number of appends can
    threaten the budget — which is a statement about the *write* and was never
    one about the *open*. Opening a FIFO ``O_WRONLY`` blocks until a reader
    appears: forever, raising nothing for the caller's ``except Exception`` to
    catch, and with no deadline to expire. Measured before this line existed:
    one ``mkfifo ~/.claude/hooks/security.log`` — a command no guard denies,
    prompts on or records — hung 22 of 25 registrations past their 5 s timeout,
    and ``container_first``'s hard deny *is* ``exit 2``, so a computed block on
    ``rm -rf`` came out as ``-9`` instead. A silent allow, permanently, on every
    subsequent Bash call.

    ``O_NONBLOCK`` is a no-op on a regular file on every POSIX platform and 0 on
    Windows; on a FIFO with no reader the open fails with ``ENXIO`` instead of
    waiting. ``S_ISREG`` on the descriptor — never on a prior ``stat``, which
    races — covers the case where a reader *is* attached, and everything else
    the path could have become. A non-regular log file means no file sink for
    this record; the native sinks are unaffected, and the caller is unaffected,
    because the whole point is that the verdict survives.
    """
    flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def set_record_builder(builder) -> None:
    """Install the one function that knows the record envelope.

    ``hook_logging`` owns the record; this module owns the write paths. The
    rotation marker is the single record that originates *here*, and building a
    second envelope for it is how two envelopes drift -- so the builder is
    injected instead. ``hook_logging`` registers it at import time, and every
    guard imports ``hook_logging``, so on every real path it is installed before
    a rollover can happen.

    An unregistered builder means no marker, deliberately: a half-conformant
    record written by the layer that promised not to build records is worse than
    a missing breadcrumb, and the rollover itself is unaffected either way.
    """
    global _record_builder  # noqa: PLW0603
    _record_builder = builder


def _rotation_record(rotated_to: str, rotated_bytes: int):
    """The ``log.rotated`` marker, or None when no builder is registered.

    Written under the rotation lock with a plain ``os.write`` on a fresh
    descriptor, deliberately not through ``write()``: re-entering the sink layer
    during a rotation in progress is how a rotation becomes recursive. Every
    field is machine-generated, so there is nothing here to scrub.

    It answers a question nothing else could: a reader who finds a truncated
    tail can tell a rotation from a loss.
    """
    if _record_builder is None:
        return None
    return _record_builder(rotated_to, rotated_bytes)


def _rename_chain(path: str) -> bool:
    """``security.log -> .1 -> .2 -> ... -> .N``, oldest dropped.

    Retried three times. On Windows a rename or unlink of a file another process
    holds open fails with a sharing violation, and ``PermissionError`` is an
    ``OSError`` subclass, so a bare swallow would let the log grow without
    bound. Dropping stdlib ``logging`` already shrank that window from "the
    whole hook process" to the ~30 us of one raw append; the retries cover what
    is left, and the caller records a breadcrumb if they all fail.
    """
    for attempt in range(3):
        try:
            oldest = "%s.%d" % (path, FALLBACK_BACKUP_COUNT)
            if os.path.exists(oldest):
                os.remove(oldest)
            for index in range(FALLBACK_BACKUP_COUNT - 1, 0, -1):
                source = "%s.%d" % (path, index)
                if os.path.exists(source):
                    os.replace(source, "%s.%d" % (path, index + 1))
            if os.path.exists(path):
                os.replace(path, "%s.1" % path)
            return True
        except OSError:
            if attempt == 2:
                return False
            time.sleep(portable_lock._POLL_SECONDS)
    return False


def _rotate(path: str) -> None:
    """Roll the log over, once, across every process that shares it.

    Every hook invocation is its own process with its own idea of the file size,
    so without coordination several enter the rollover at once and rename the
    log over each other's copies. Measured at 39.7% of records lost when
    rollovers were forced without the lock.

    Two properties do the work. The lock makes the rename chain mutually
    exclusive, and the size is re-checked once the lock is held so only the
    process that still finds an oversized file rotates -- the others simply
    append. Failing to take the lock is survivable and deliberately does not
    stop the write: an oversized file is better than a lost record.

    **Attempted at most until the budget runs out, and never again once it has
    failed.** The lock deadline bounds one acquisition; ``_write_file`` calls
    this on *every* write while the file is oversized, so a lock held by another
    process cost 1.0 s per record with no cap of any kind -- measured at 6.059 s
    for six records, past the timeout that would have killed the hook. The flag
    already existed and was written on failure; nothing read it. Now it does,
    and the budget covers the case where the rotation succeeds but is slow.
    """
    global _rotation_failed  # noqa: PLW0603
    budget = budget_remaining()
    if _rotation_failed or budget <= 0:
        return
    started = time.monotonic()
    handle = None
    try:
        try:
            flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NONBLOCK", 0))
            descriptor = os.open(str(file_dir() / ".rotate.lock"), flags, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                # Same reasoning as `_open_append`: a lock path that is not a
                # regular file is a path somebody replaced, and locking it is
                # meaningless. No lock means no rotation, which is survivable.
                os.close(descriptor)
                raise OSError(errno.EINVAL, "not a regular file")
            handle = os.fdopen(descriptor, "r+b")
        except OSError:
            handle = None
        lock = portable_lock.locked_handle(
            handle, min(portable_lock.DEFAULT_TIMEOUT_SECONDS, budget))
        try:
            if not lock.acquire():
                _rotation_failed = True
                return
            try:
                size = os.stat(path).st_size
            except OSError:
                return
            if size < FALLBACK_MAX_BYTES:
                return                      # someone else already rotated
            if not _rename_chain(path):
                _rotation_failed = True
                return
            try:
                record = _rotation_record("security.log.1", size)
                if record is not None:
                    marker = render(record)
                    fd = _open_append(path)
                    try:
                        os.write(fd, marker.encode("utf-8", "replace") + b"\n")
                    finally:
                        os.close(fd)
            except Exception:  # noqa: BLE001 - the marker is never worth the write
                pass
        finally:
            # On EVERY path, including the two that return early. Those two used
            # to skip it, so a contended or already-done rotation left backups
            # readable by anyone the umask allowed.
            _harden_log_mode()
            lock.release()
    finally:
        _spend(time.monotonic() - started)
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


def _write_file(line: str) -> bool:
    """Append one record. 0.027 ms measured, and the only sink that never drops.

    "Never drops" is a statement about contention and about the other sinks'
    ceilings, not a promise that an unopenable path produces a record: when the
    log is a directory, a FIFO or anything else that is not a regular file, this
    returns False and the caller carries on. The one thing it may never do is
    fail to return.
    """
    _prepare_dir()
    path = str(file_path())
    data = line.encode("utf-8", "replace") + b"\n"
    try:
        size = os.stat(path).st_size
    except OSError:
        size = 0
    if size + len(data) > FALLBACK_MAX_BYTES:
        _rotate(path)
    try:
        descriptor = _open_append(path)
    except OSError:
        return False
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    return True


# ---------------------------------------------------------------------------
# macOS: the unified log
# ---------------------------------------------------------------------------

def _write_oslog(record: Dict[str, Any], line: str, macos_type: str) -> bool:
    """``/usr/bin/log emit``, carrying the whole record including ``command.line``.

    Absolute path because ``log`` is a zsh *builtin*: a bare ``log emit`` in the
    default macOS shell fails with "too many arguments" rather than emitting
    anything. ``--public`` because without it the whole ``eventMessage`` renders
    as ``<private>`` on every read interface and lifting that needs root -- an
    empty record, not a protected one.

    The payload travels in argv, which was measured capturable 20 times out of
    20 by a same-uid process and 0 times out of 49 across uids. Same-uid code
    can already read the 0600 file sink, so this channel gives an attacker in
    the coding-agent threat model nothing new. Do not "fix" it with the libc
    ``syslog`` bridge: that reaches the unified log 235x cheaper but lands with
    no subsystem and no category, which breaks every documented predicate.

    One `log emit` per fragment, under a single deadline for the whole record:
    the per-call ``timeout=2`` alone would let a hung emitter spend 32 s here,
    and a hook killed at 5 s delivers no verdict at all. That per-record
    deadline is itself capped by whatever is left of the process budget, because
    one record's ceiling says nothing about four of them -- four synchronous
    WARN records against a hung emitter measured 8.044 s.

    **A fragmented record is refused before the first fragment when the budget
    cannot afford it -- and every abandonment is COUNTED.** That is the whole of
    the promise, and the stronger form this docstring used to state ("emitted
    whole or not at all") was not true of the code beneath it. The pre-flight
    gate below is exactly that: a check against ``_emit_cost_estimate``, which
    is re-derived from what emitting on THIS machine actually costs rather than
    assuming the measured 3.1 ms median. What it cannot cover is a store that is
    affordable when the record starts and slow by the middle of it: the emitter
    is a subprocess per fragment, nothing already emitted can be recalled, and
    both remaining exits -- the between-calls deadline and a ``TimeoutExpired``
    inside one call -- leave the fragments already sent as a group
    ``reassemble`` reports as ``incomplete``. Measured with a 0.6 s stub: 4
    fragments needed, 2 emitted. Neither exit used to increment
    ``_native_records_dropped``, so an operator saw the orphan group and no
    count; both do now, and the count rides the next record this process writes.

    Bounded, and the bound is measured rather than argued: ``/usr/bin/log emit``
    on this host is median 6.95 ms / p99 11.33 ms / max 12.82 ms over 400 calls
    at 16-way concurrency, against the 62 ms (16 fragments) or 167 ms (6) an
    orphan needs -- 5-13x the worst this host produces. It is the slow-store
    case ``LOG_BUDGET_SECONDS`` exists for, and it costs forensics, never a
    verdict: the verdict is on stdout before any sink is touched.
    """
    import subprocess

    global _emit_cost_estimate  # noqa: PLW0603
    global _native_records_dropped  # noqa: PLW0603

    macos_type = oslog_type(record, macos_type)
    limit = (UNIFIED_LOG_FAULT_MAX_BYTES if macos_type == "fault"
             else UNIFIED_LOG_MAX_BYTES)
    payloads = fragments(record, line, limit)
    if not payloads:
        _native_records_dropped += 1
        return False
    allowance = budget_remaining()
    if allowance <= 0:
        return False
    if len(payloads) > 1 and allowance < len(payloads) * _emit_cost_estimate:
        # Refused before the first fragment, so no orphans. But a record dropped
        # whole with no breadcrumb is indistinguishable from one that never
        # happened, and the refusal costs 0 s, so `_emit_cost_estimate` stays
        # high and every later multi-fragment record in the process takes the
        # same path. Counted, and reported on the next record this process
        # writes beside the budget-exhausted skips.
        _native_records_dropped += 1
        return False
    # ONE exit for every way this record can fail to reach the store, so there
    # is one place the drop is counted and one thing to gate. There used to be
    # two -- the between-calls deadline `return False` and the blanket `except`
    # over `TimeoutExpired` -- and NEITHER incremented the counter, so a store
    # that went slow mid-record left an orphan group in the log and nothing
    # anywhere said a record had been lost. Which of the two fires is a matter
    # of whether the emitter overran its own per-call timeout or the loop simply
    # ran out of budget between calls; they mean the same thing to a reader, and
    # splitting them meant a test could only ever gate one.
    deadline = time.monotonic() + allowance
    delivered = False
    try:
        for payload in payloads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            started = time.monotonic()
            subprocess.run(
                [
                    LOG_BINARY, "emit",
                    "--subsystem", SUBSYSTEM,
                    "--category", CATEGORY,
                    "--type", macos_type,
                    "--public", payload,
                ],
                capture_output=True,
                timeout=min(LOG_BUDGET_SECONDS, remaining),
                check=False,
            )
            _emit_cost_estimate = max(_emit_cost_estimate,
                                      time.monotonic() - started)
        else:
            delivered = True
    except Exception:  # noqa: BLE001 - a missing or slow `log` is not a hook failure
        delivered = False
    if not delivered:
        # Whatever is already in the store is an orphan group `reassemble` can
        # only file under `incomplete`, and the record as a whole did not make
        # it. Counted like every other native drop, and carried on the next
        # record this process writes.
        _native_records_dropped += 1
    return delivered


# ---------------------------------------------------------------------------
# Linux: the systemd journal, native protocol
# ---------------------------------------------------------------------------

_FIELD_NAME_MAX = 64
_FIELD_ALLOWED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def valid_field_name(name: str) -> bool:
    """journald's own rule: non-empty, <=64 bytes, [A-Z0-9_], not leading _ or digit.

    A leading underscore is reserved for the trusted fields journald stamps
    itself. Invalid names are dropped rather than raised on.
    """
    if not name or len(name) > _FIELD_NAME_MAX:
        return False
    if name[0] == "_" or name[0].isdigit():
        return False
    for char in name:
        if char not in _FIELD_ALLOWED:
            return False
    return True


def encode_field(name: str, value: Any) -> bytes:
    """One field, in the simple form or -- when the value has a newline -- binary.

    ``struct.pack("<Q", ...)`` is the documented wire encoding and is
    little-endian on every architecture. Note that both machines this was
    verified on are little-endian, so the round trip does not by itself
    discriminate ``<Q`` from ``=Q``; the format string is from the protocol, not
    from the test.
    """
    import struct

    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", "replace")
    key = name.encode("ascii")
    if b"\n" in raw:
        return key + b"\n" + struct.pack("<Q", len(raw)) + raw + b"\n"
    return key + b"=" + raw + b"\n"


def encode_entry(fields) -> bytes:
    out = []
    for name, value in fields:
        if not valid_field_name(name):
            continue
        out.append(encode_field(name, value))
    return b"".join(out)


def _journal_fields(record: Dict[str, Any], line: str, severity_number: int):
    """The record as journald sees it: one field per attribute, plus the whole JSON.

    ``FORCEFIELD_EVENT_JSON`` carries the complete rendered record so nothing is
    lost to the field-name rules, and the flattened ``FORCEFIELD_*`` fields make
    ``journalctl`` filtering work without a jq pass.

    Reading these back in a test or a doc needs ``journalctl -o json --all``:
    without ``--all`` a large field comes back as ``null``, which looks exactly
    like a data loss that is not happening.
    """
    body = record.get("Body")
    fields = [
        ("MESSAGE", body if isinstance(body, str) else line),
        ("PRIORITY", _syslog_severity(severity_number)),
        ("SYSLOG_IDENTIFIER", SYSLOG_IDENT),
        ("SYSLOG_FACILITY", 4),
        ("FORCEFIELD_EVENT_JSON", line),
    ]
    attributes = record.get("Attributes")
    if isinstance(attributes, dict):
        for key, value in attributes.items():
            if not isinstance(key, str):
                continue
            name = "FORCEFIELD_" + "".join(
                char if char in _FIELD_ALLOWED else "_" for char in key.upper()
            )
            if isinstance(value, (dict, list, tuple)):
                value = render(value) if isinstance(value, dict) else json.dumps(
                    list(value), separators=(",", ":"), ensure_ascii=True, default=str)
            fields.append((name, value))
    return fields


def _memfd_payload(payload: bytes):
    """A sealed memfd holding ``payload``, or None if the kernel will not.

    ``import fcntl`` stays inside this function: a module-scope one is exactly
    what made the old logging module unimportable on Windows, and this path is
    Linux-only by construction.
    """
    try:
        fd = os.memfd_create("forcefield-journal", os.MFD_ALLOW_SEALING)
    except (AttributeError, OSError):
        return None
    try:
        os.write(fd, payload)
        import fcntl

        # F_ADD_SEALS = 1033; SEAL_SHRINK|GROW|WRITE|SEAL = 0xF
        fcntl.fcntl(fd, 1033, 0xF)
        return fd
    except (ImportError, OSError):
        try:
            os.close(fd)
        except OSError:
            pass
        return None


def _write_journald(record: Dict[str, Any], line: str, severity_number: int) -> bool:
    """One datagram to journald's native socket. Non-blocking, always.

    A blocking ``sendto`` to a journald whose 8 MiB receive queue is full was
    measured not to return within 5 s -- the entire hook budget -- and even
    ``settimeout(0.05)`` cost 60 ms per call once the queue filled.
    ``setblocking(False)`` failed with EAGAIN in 0.2 ms. Dropping a log record
    is the correct trade against a killed verdict.

    Process identity in a journal record is *attested*: journald stamps
    ``_UID``/``_PID``/``_COMM``/``_CMDLINE`` from ``SO_PEERCRED`` and discards
    forged ones. The file sink cannot offer that.
    """
    import errno
    import socket

    sock = None
    try:
        payload = encode_entry(_journal_fields(record, line, severity_number))
        if not payload:
            return False
        sock = socket.socket(socket.AF_UNIX,
                             socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
        sock.setblocking(False)
        try:
            sock.sendto(payload, JOURNAL_SOCKET)
            return True
        except BlockingIOError:
            return False                    # journald is not draining; drop it
        except OSError as exc:
            if exc.errno not in (errno.EMSGSIZE, errno.ENOBUFS):
                return False
        fd = _memfd_payload(payload)
        if fd is None:
            return False
        try:
            sock.connect(JOURNAL_SOCKET)
            socket.send_fds(sock, [b""], [fd])
            return True
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - the journal is never worth a tool call
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Linux fallback: a plain /dev/log datagram
# ---------------------------------------------------------------------------

def _syslog_severity(severity_number: int) -> int:
    """RFC 5424 severity from the OTel SeverityNumber -- one ladder, not two.

    The old code took this from a ``logging`` level column in the severity
    table, which was a third ladder that could drift from the other two. The
    arithmetic below reproduces the measured wire values exactly: a deny went
    out as PRI <34> (facility 4 x 8 + crit 2) and a warn as <36> (+ warning 4).
    """
    if severity_number >= 17:
        return 2        # crit
    if severity_number >= 13:
        return 4        # warning
    if severity_number >= 9:
        return 6        # info
    return 7            # debug


def _sendto_bounded(sock, datagram: bytes, deadline: float) -> bool:
    """One datagram to ``SYSLOG_SOCKET``, retrying a full queue until ``deadline``.

    ``EAGAIN``/``ENOBUFS`` on a non-blocking ``AF_UNIX`` datagram socket means
    the receiver's queue is momentarily full, not that the message cannot be
    delivered; a syslogd draining a burst produces exactly that. The socket
    stays non-blocking -- the deadline is the bound, so this cannot outlive the
    process logging budget the way a blocking ``sendto`` could. Any other
    ``OSError`` (a stale socket, no listener) is final and reported at once.
    """
    while True:
        try:
            sock.sendto(datagram, SYSLOG_SOCKET)
            return True
        except (BlockingIOError, InterruptedError):
            pass
        except OSError as exc:
            if exc.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK):
                return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.001)


def _write_syslog(record: Dict[str, Any], line: str, severity_number: int) -> bool:
    """A single RFC 3164-shaped datagram to /dev/log. Never blocks, never raises.

    Reached only when there is no journald socket, i.e. rsyslog or BusyBox. Both
    are CONF_LOCAL, so ``line`` has already been projected without the free-text
    fields by the time it arrives here.

    One datagram per fragment, and the budget subtracts the PRI header because
    BusyBox's 1024-byte ceiling counts it. This used to cut the JSON itself --
    and overshoot its own limit by the 14 bytes of the marker it appended after
    the cut -- so a 1907-byte `session.start` went on the wire as an unparseable
    1831-byte datagram while the transport would have carried 212,960.

    **The burst is completed or the record is counted lost.** ``_write_oslog``
    got that rule; this did not, and it is the sink that sends N datagrams in a
    tight non-blocking loop. Measured against a real BusyBox syslogd: past ~11
    fragments ``sendto`` meets ``EAGAIN`` part way through, eleven or twelve
    parseable fragments land in ``/var/log/messages`` with nothing marking them
    as a partial group, and because reassembly is all-or-nothing the whole record
    is lost -- ``(0 records, 1 incomplete)``. Two things close it: a bounded
    retry, because ``EAGAIN`` on a datagram socket means the receiver's queue is
    momentarily full rather than the message being undeliverable, and a count on
    the record that still does not make it, so ``session.end`` says so.

    Latent rather than live today -- fourteen guards driven with 60 KB inputs
    produced a largest ``CONF_LOCAL`` projection of 5 fragments -- but the
    largest attribute in that record is ``forcefield.hooks.registered``, which
    grows with every registration added.
    """
    import socket

    global _native_records_dropped  # noqa: PLW0603

    sock = None
    try:
        pri = 4 * 8 + _syslog_severity(severity_number)
        prefix = "<%d>%s: " % (pri, SYSLOG_IDENT)
        limit = SYSLOG_MAX_BYTES - len(prefix.encode("utf-8", "replace"))
        payloads = fragments(record, line, limit)
        if not payloads:
            _native_records_dropped += 1
            return False
        allowance = budget_remaining()
        if len(payloads) > 1 and allowance <= 0:
            _native_records_dropped += 1
            return False            # all or nothing: no orphan fragments
        deadline = time.monotonic() + max(allowance, 0.0)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setblocking(False)
        for payload in payloads:
            datagram = (prefix + payload).encode("utf-8", "replace")
            if not _sendto_bounded(sock, datagram, deadline):
                _native_records_dropped += 1
                return False
        return True
    except Exception:  # noqa: BLE001 - a stale socket is silence, not a traceback
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Windows: the Application event log
# ---------------------------------------------------------------------------

# Keyed off the same severity ladder as everything else, so the two cannot
# drift. /ID must be in 1..1000.
_WINEVT_ENTRY = (
    #  min severity, entry type,     event id
    (17, "ERROR", 401),
    (15, "WARNING", 302),
    (14, "WARNING", 301),
    (13, "WARNING", 201),
    (11, "INFORMATION", 202),
    (10, "INFORMATION", 101),
    (9, "INFORMATION", 102),
)
_WINEVT_UNKNOWN = ("WARNING", 299)


def winevt_entry(severity_number: int):
    """(entry type, event id) for one record. Exposed so a test can sweep it."""
    for floor, entry_type, event_id in _WINEVT_ENTRY:
        if severity_number >= floor:
            return entry_type, event_id
    return _WINEVT_UNKNOWN


def _sanitize_for_argv(text: str) -> str:
    """Make one JSON line safe as an ``eventcreate.exe /D`` argument.

    Three distinct hazards, none of them theoretical for a record that is mostly
    quotes and may carry matched attacker input:

    * ``"`` becomes ``'``. ``subprocess.list2cmdline`` escapes quotes per the
      MSVC CRT rules and ``eventcreate.exe`` is not guaranteed to unescape them
      the same way.
    * every ``%`` is doubled. The event viewer treats ``%n`` in a logged string
      as an insertion string, so an attacker-influenced ``forcefield.pattern``
      -- several guards interpolate matched input into it -- could otherwise
      rewrite the rendered message.
    * control characters, newline, carriage return and NUL become a space. Any
      of them truncates or splits the argument.
    """
    out = []
    for char in text:
        if char == '"':
            out.append("'")
        elif char == "%":
            out.append("%%")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def winevt_commands(record: Dict[str, Any], line: str, severity_number: int):
    """The exact command lines, one per fragment. Built separately from running
    them so they are testable off Windows.

    ``eventcreate.exe`` is the only writer that needs neither registration nor
    elevation and ships in-box. ``NTEventLogHandler`` is disqualified twice: it
    imports pywin32, and on ImportError it ``print()``s to stdout -- which in a
    Claude Code hook *is* the decision channel. There is deliberately no ``/SO``:
    registering a source writes HKLM, i.e. it needs an administrator, and a
    security hook that only logs when installed elevated is a hook that does not
    log.

    ``_sanitize_for_argv`` runs after the fragmenting and does make the rendered
    message non-JSON on this one sink -- the double quotes become single ones.
    That is an argv-safety decision taken against ``eventcreate.exe``'s
    unverified unescaping, not a size decision, and it is the one sink whose
    message a JSON parser cannot read. UNVERIFIED: no Windows host was
    available to measure what ``eventcreate.exe`` actually does with a quote.
    """
    entry_type, event_id = winevt_entry(severity_number)
    return [
        [
            "eventcreate.exe",
            "/L", "APPLICATION",
            "/T", entry_type,
            "/ID", str(event_id),
            "/D", _sanitize_for_argv(payload),
        ]
        for payload in fragments(record, line, EVENTCREATE_PAYLOAD_MAX)
    ]


def _write_winevt(record: Dict[str, Any], line: str, severity_number: int) -> bool:
    if os.name != "nt":
        return False
    import subprocess

    commands = winevt_commands(record, line, severity_number)
    if not commands:
        return False
    allowance = budget_remaining()
    if allowance <= 0:
        return False
    deadline = time.monotonic() + allowance
    try:
        for command in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            subprocess.run(command, capture_output=True,
                           timeout=min(LOG_BUDGET_SECONDS, remaining),
                           check=False)
        return True
    except Exception:  # noqa: BLE001 - a missing eventcreate.exe is not a failure
        return False


# ---------------------------------------------------------------------------
# The dispatch surface
# ---------------------------------------------------------------------------

def _floor_exempt(record: Dict[str, Any]) -> bool:
    """Whether this record's class bypasses ``NATIVE_SINK_MIN_SEVERITY``."""
    attributes = record.get("Attributes")
    record_class = None
    if isinstance(attributes, dict):
        record_class = attributes.get("forcefield.record_class")
    return record_class in _FLOOR_EXEMPT_CLASSES


def accepts(name: str, record: Dict[str, Any], severity_number: int) -> bool:
    """Whether ``name`` takes this record at all. The native severity floor."""
    if name == NAME_FILE:
        return True
    if severity_number >= NATIVE_SINK_MIN_SEVERITY:
        return True
    return _floor_exempt(record)


# The macOS message types the unified log actually RETAINS. Measured on this
# host over a 30-hour window, bucketed by `messageType`: Default's oldest
# survivor was 23.78 h old, Error's 23.78 h and Fault's 23.73 h -- and Info's was
# **6 minutes**.
OSLOG_RETAINED_TYPES = frozenset({"default", "error", "fault"})


def oslog_type(record: Dict[str, Any], macos_type: str) -> str:
    """The ``log emit --type`` a record is written at.

    ``session.start`` and ``session.end`` are decision ``allow``, severity 10,
    which maps to ``info`` -- and lifecycle records are the ONE class exempted
    from ``NATIVE_SINK_MIN_SEVERITY``, on the stated ground that "a session.start
    in the native sink is the only cheap way to tell 'the file sink died' from
    'nothing happened'". Emitted at ``info`` that exemption spent the emit and
    bought six minutes of retention: by the time anyone asks the question, the
    heartbeat is gone. The exemption has to carry the type that survives, so a
    record that is only in the native sink BECAUSE of its class is written at
    ``default``. Nothing else is promoted -- a finding's type still comes from
    its own severity.
    """
    if macos_type in OSLOG_RETAINED_TYPES:
        return macos_type
    if _floor_exempt(record):
        return "default"
    return macos_type


def write(name: str, record: Dict[str, Any], line: str,
          severity_number: int, macos_type: str) -> bool:
    """Write one record to one sink. Returns success; never raises, never blocks.

    Both the record and the pre-rendered line arrive, so the JSON is serialised
    once per *confidentiality class* rather than once per sink: journald wants
    structured fields, the Windows channel wants a projection, and the file sink
    wants exactly the line.

    Every native write is charged to the process budget here rather than inside
    each sink, so there is one place that decides what logging has cost so far
    and one place that cannot be forgotten by the next sink someone adds.

    The file sink is deliberately not charged, and the reason is *structural*
    rather than statistical. It used to be stated as "an append measured at
    0.027 ms, and no number of appends can threaten the budget" — an observation
    about the file, not a bound on the syscall, and false the moment the path is
    not a regular file. It is now true by construction: the rollover charges
    itself, the open is ``O_NONBLOCK`` and refuses anything but a regular file
    (``_open_append``), and a write to a regular file with ``O_APPEND`` has no
    unbounded wait to charge. A sink that cannot block does not need a budget;
    one that can, has one.

    **The projection is re-applied here, at the sink, and that is not
    belt-and-braces.** ``project`` is idempotent — a record with no free-text
    attribute left in it comes back unchanged — so a caller that already
    projected pays one dict scan and nothing else. What it buys is that the
    disclosure floor becomes a property of the sink layer rather than of the
    caller's bookkeeping: a caller that hands over a projected *line* and an
    unprojected *record* used to disclose every withheld field the moment the
    record was too large to fragment, because every rung below ``fragments``'
    fast path re-renders the record and ``_journal_fields`` never reads the line
    at all. Nothing downstream of this call can now carry a field this sink's
    confidentiality does not license, whatever it was handed.
    """
    started = time.monotonic()
    try:
        if name not in selected():
            return False
        if not accepts(name, record, severity_number):
            return False
        if name == NAME_FILE:
            return _write_file(line)
        floored = project(record, confidentiality(name))
        if floored is not record:
            record = floored
            line = render(record)
        if name == NAME_OSLOG:
            return _write_oslog(record, line, macos_type)
        if name == NAME_JOURNALD:
            return _write_journald(record, line, severity_number)
        if name == NAME_SYSLOG:
            return _write_syslog(record, line, severity_number)
        if name == NAME_WINEVT:
            return _write_winevt(record, line, severity_number)
        return False
    except Exception:  # noqa: BLE001 - a sink that raises hides the next sink
        return False
    finally:
        if name != NAME_FILE:
            _spend(time.monotonic() - started)


def describe() -> Dict[str, Any]:
    """What every sink on this platform is doing, for the session record.

    Reports the *unselected* candidates too. "There is no journald here" and
    "journald is here and I am writing to it" are different facts, and an
    investigator reading a native record needs to know which one held.
    """
    out: Dict[str, Any] = {}
    try:
        active = selected()
        names = set(active) | set(_candidates()) | {NAME_FILE}
        for name in sorted(names):
            conf = confidentiality(name)
            entry: Dict[str, Any] = {
                "available": name in active,
                "confidentiality": conf,
                "carries_free_text": conf >= _free_text_min(),
            }
            if name == NAME_FILE:
                entry["path"] = str(file_path())
                entry["mode"] = _mode_of(str(file_path()))
                entry["dir_mode"] = _mode_of(str(file_dir()))
                entry["max_bytes"] = FALLBACK_MAX_BYTES
                entry["backup_count"] = FALLBACK_BACKUP_COUNT
                entry["rotation_failed"] = rotation_failed()
            elif name == NAME_OSLOG:
                entry["store_world_readable"] = not _unified_store_restricted()
            elif name == NAME_JOURNALD:
                entry["socket"] = JOURNAL_SOCKET
            elif name == NAME_SYSLOG:
                entry["socket"] = SYSLOG_SOCKET
            out[name] = entry
    except Exception:  # noqa: BLE001 - a description is never worth a tool call
        pass
    return out


def _mode_of(path: str):
    try:
        return "0%o" % (os.stat(path).st_mode & 0o777)
    except OSError:
        return None
