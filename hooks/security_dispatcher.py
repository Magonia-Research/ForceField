#!/usr/bin/env python3
"""Consolidated security dispatcher for Claude Code Bash hooks.

Runs five guards in a single Python process — exfil, supply-chain, git,
credential-read and ForceField's own config self-protection — eliminating four
interpreter cold-starts.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)

Returns the highest-precedence decision (deny > ask > allow). Each guard is
isolated, so one raising costs only its own verdict; the command text is bounded
before scanning, because the 5s hook timeout is a security boundary and a hook
killed mid-scan fails open.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from patterns import (  # noqa: E402
    MAX_COMMAND_SCAN_BYTES,
    MAX_STDIN_BYTES,
    DECISION_PRECEDENCE as _DECISION_PRECEDENCE,
)

# Guard imports run before ``main``'s try/except, so a syntax error in any one
# guard, a half-finished install or a missing module raised here, the process
# exited non-zero and Claude Code failed open — four guards gone with no log
# record and nothing shown to the user. Liveness is the correct direction, but
# the silence is not: the dispatcher already turns "I could not inspect this"
# into an ask one case over (_emit_ask_uninspectable). This gives an unusable
# guard set the same treatment.
_IMPORT_ERROR: str | None = None
# Bound before the import so a partial failure leaves the risk lookup empty
# rather than undefined: the message falls back to the generic sentence instead
# of raising NameError from inside a guard.
FS_PATTERN_RISKS: dict[str, str] = {}
try:
    from exfil_guard import check_command as exfil_check  # noqa: E402
    from exfil_guard import format_alert as exfil_format  # noqa: E402
    from exfil_guard import HARD_DENY_PATTERNS as EXFIL_HARD_DENY  # noqa: E402
    from supply_chain_guard import (  # noqa: E402
        check_dangerous,
        check_typosquat,
        format_danger_alert,
        format_typosquat_alert,
        allowlist_clears_danger,
        HARD_DENY_PATTERNS as SUPPLY_HARD_DENY,
    )
    from git_guard import check_git  # noqa: E402
    from git_guard import assess as git_assess  # noqa: E402
    from credential_access_guard import check_command as cred_access_check  # noqa: E402
    from credential_access_guard import format_alert as cred_access_format  # noqa: E402
    from credential_access_guard import HARD_DENY_PATTERNS as CRED_ACCESS_HARD_DENY  # noqa: E402
    from allowlist import is_suppressed  # noqa: E402
    from filesystem_guard import check_bash_config_write as fs_bash_config_write  # noqa: E402
    from filesystem_guard import PATTERN_RISKS as FS_PATTERN_RISKS  # noqa: E402
except Exception as _exc:  # noqa: BLE001 - an unusable guard set must still speak
    _IMPORT_ERROR = "%s: %s" % (type(_exc).__name__, _exc)

from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from hook_logging import clamp_and_emit, defer_log, emit, log_security_event  # noqa: E402


def _finish(
    guard_name: str,
    natural_decision: str,
    command: str,
    pattern_name: str,
    reason: str,
    context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Clamp a guard's natural decision by config, log it, and build the response.

    Thin wrapper over ``hook_logging.clamp_and_emit`` so the dispatcher and the
    standalone guards share one clamp / warn / wave-through implementation.
    """
    response = clamp_and_emit(
        guard_name, natural_decision, reason,
        pattern_matched=pattern_name, command=command, context=context,
    )
    # Captured here, written after the verdict reaches stdout. The clamped
    # decision is what counts: a finding the config downgraded to allow blocked
    # nothing, so nothing was routed around.
    decision = _decision_of(response) if response else "allow"
    if decision in ("deny", "ask"):
        _BLOCKED.append((guard_name, pattern_name, decision))
    return response


# Blocked findings from this invocation, captured at decision time and written
# to the ledger only after the verdict is on stdout. Same reason ``defer_log``
# exists: a hook killed at the 5 s timeout must lose bookkeeping, not a decision.
_BLOCKED: list[tuple[str, str, str]] = []


def _record_blocks(session_id: str, command: str, cwd: str | None) -> None:
    """Persist this invocation's blocks, with the file targets the command named.

    Targets come from shell redirection and explicit output flags only. A block
    naming no file is not recorded at all — there is nothing for a later write to
    correlate against, and an entry with no targets would only cost parse time.
    """
    if not _BLOCKED:
        return
    try:
        from write_ledger import extract_targets, record_block  # noqa: PLC0415

        targets = extract_targets(command, cwd)
        if not targets:
            return
        for guard_name, pattern_name, decision in _BLOCKED:
            record_block(session_id, guard_name, pattern_name, decision, targets)
    except Exception:  # noqa: BLE001 - the decision is already delivered
        pass


def _correlation_for(session_id: str, command: str, cwd: str | None):
    """``(correlation, target)`` when this command writes a path an earlier block
    named, else ``(None, "")``.

    Target extraction runs first because it is two regex scans over a bounded
    string, while the ledger read touches the filesystem and verifies a MAC per
    line. A command that writes no file cannot be a re-route, so the expensive
    half never runs for it.
    """
    try:
        from write_ledger import correlate, extract_targets  # noqa: PLC0415

        targets = extract_targets(command, cwd)
        if not targets:
            return (None, "")
        for target in targets:
            found = correlate(session_id, target)
            if found is not None:
                return (found, target)
    except Exception:  # noqa: BLE001 - never let the ledger block a tool call
        pass
    return (None, "")


def _protected_sink(target: str) -> str:
    """The sink name if this path is one ForceField protects, else ''."""
    try:
        from filesystem_guard import check_write_path  # noqa: PLC0415

        found = check_write_path(target)
        return found[0] if found else ""
    except Exception:  # noqa: BLE001
        return ""


def _correlation_response(
    correlation: dict, target: str, command: str,
    context: dict[str, object] | None,
) -> dict[str, object] | None:
    """Record a re-routed write, and gate it only if the target is protected.

    The split is the user's decision and it is grounded in measurement: over two
    weeks of this project's own logs the shape occurred 26 times and not one of
    those targets was a protected sink, so gating on the shape alone would have
    interrupted legitimate work 26 times and caught nothing. Restricting the
    prompt to protected sinks would have prompted zero times over the same
    period while still covering the case that matters.
    """
    sink = _protected_sink(target)
    extra = {
        "correlated_block": "%s:%s" % (correlation.get("guard", ""),
                                       correlation.get("pattern", "")),
        "correlated_decision": correlation.get("decision", ""),
        "correlated_age_s": correlation.get("age_s"),
        "correlated_target": target,
    }
    if not sink:
        defer_log(
            "filesystem_guard", "allow",
            pattern_matched="blocked_command_rerouted", command=command,
            context=context, extra=extra, natural="warn",
        )
        return None

    reason = (
        "BYPASS CORRELATION: blocked_command_rerouted\n\n"
        "Path: %s\n"
        "Sink: %s\n"
        "Earlier: ForceField %s a command naming this exact path %.1fs ago "
        "(%s/%s).\n\n"
        "This command writes that same path through a route the earlier block "
        "did not cover. Approve only if you intended to complete that write."
        % (target[:200], sink, correlation.get("decision", "blocked"),
           correlation.get("age_s") or 0.0, correlation.get("guard", ""),
           correlation.get("pattern", ""))
    )
    # Attributed to ``filesystem_guard``, matching how this dispatcher already
    # reports its Bash-side sink findings: the finding is about a filesystem
    # destination, and that guard is the one the config, the allowlist and
    # ``/forcefield:remember`` already govern for these paths.
    return clamp_and_emit(
        "filesystem_guard", "ask", reason,
        pattern_matched="blocked_command_rerouted", command=command,
        context=context, extra=extra,
    )


def _log_suppressed_allow(
    guard_name: str, pattern_name: str, command: str,
    context: dict[str, object] | None,
) -> None:
    """Record that a finding was waved through by an allowlist suppression.

    A suppressed finding is still a finding: it is logged as an ``allow`` with
    ``suppressed`` set, so the record shows what was matched and why it did not
    gate. Never reached for a hard deny — those do not honor suppression.
    """
    defer_log(
        guard_name, "allow",
        pattern_matched=pattern_name, command=command,
        context=context, extra={"suppressed": True},
    )


def _run_simple_guard(
    guard_name: str,
    check_fn,
    hard_deny_set,
    format_fn,
    command: str,
    context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Run a guard whose shape is "match, honor suppression, deny or ask".

    The three guards below differ only in their check function, hard-deny set
    and alert formatter; everything else — the suppression carve-out for hard
    denies, the natural decision, the clamp — is one policy that must not drift
    between them.
    """
    result = check_fn(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    is_hard_deny = pattern_name in hard_deny_set
    if not is_hard_deny and is_suppressed(guard_name, pattern_name=pattern_name):
        _log_suppressed_allow(guard_name, pattern_name, command, context)
        return None

    natural = "deny" if is_hard_deny else "ask"
    return _finish(
        guard_name, natural, command, pattern_name,
        format_fn(pattern_name, matched_text), context,
    )


def run_exfil_guard(
    command: str, context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Run exfil guard checks. Returns response dict or None."""
    return _run_simple_guard(
        "exfil_guard", exfil_check, EXFIL_HARD_DENY, exfil_format,
        command, context,
    )


def _check_typosquat(
    command: str, context: dict[str, object] | None,
) -> dict[str, object] | None:
    """Typosquatted-package half of the supply-chain guard. Always ask-severity."""
    typo_result = check_typosquat(command)
    if not typo_result:
        return None
    typo, correct, installer = typo_result
    pattern_key = f"typosquat:{typo}"
    if is_suppressed("supply_chain_guard", pattern_name=pattern_key):
        _log_suppressed_allow(
            "supply_chain_guard", pattern_key, command, context,
        )
        return None
    return _finish(
        "supply_chain_guard", "ask", command, pattern_key,
        format_typosquat_alert(typo, correct, installer), context,
    )


def _check_dangerous(
    command: str, context: dict[str, object] | None,
) -> dict[str, object] | None:
    """Dangerous-install half of the supply-chain guard. Carries the hard denies."""
    danger_result = check_dangerous(command)
    if not danger_result:
        return None
    pattern_name, matched_text = danger_result
    is_hard_deny = pattern_name in SUPPLY_HARD_DENY
    # A hard-deny (pipe-to-shell, fetch-exec) is never waved through by the
    # command allowlist or a per-project suppression; only ask-severity
    # patterns honor those layers. The allowlist is scoped to the segment
    # that carries the danger, so a benign install prefix cannot launder a
    # dangerous segment elsewhere in a compound command.
    if not is_hard_deny and (
        is_suppressed("supply_chain_guard", pattern_name=pattern_name)
        or allowlist_clears_danger(command, pattern_name)
    ):
        _log_suppressed_allow(
            "supply_chain_guard", pattern_name, command, context,
        )
        return None
    natural = "deny" if is_hard_deny else "ask"
    return _finish(
        "supply_chain_guard", natural, command, pattern_name,
        format_danger_alert(pattern_name, matched_text), context,
    )


def run_supply_chain_guard(
    command: str, context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Run supply chain guard checks. Returns response dict or None.

    Both halves always run and the stricter result wins. They used to be
    sequential with an early return, and the ask-severity typosquat check ran
    first — so a command carrying *both* a misspelled package and a pipe-to-shell
    returned the typosquat ask and never computed the hard deny at all:

        curl … | bash                        -> deny
        pip install requets && curl … | bash -> ask   (order-independent)

    Suppressing the typosquat from a repo-shipped ``.claude/hook-allowlist.json``
    then took the whole thing to allow, because the deny that should have been
    unsuppressible had never been reached to be protected. ``_pick_highest``
    already resolves severity correctly *across* guards; the bug was that within
    this one guard, a decision was being chosen by evaluation order.
    """
    return _pick_highest(
        _check_dangerous(command, context),
        _check_typosquat(command, context),
    )


def run_git_guard(
    command: str, context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Run git repo-execution guard checks. Returns response dict or None.

    Alone among the four dispatcher guards this does not use
    ``_run_simple_guard``. The others read their decision straight off a
    hard-deny set, which grades a finding by the *shape* of the command. The
    git guard additionally consults ``git_forensics`` — host git version,
    on-disk ``.gitmodules``, and for a fresh clone the remote's ``.gitmodules``
    fetched without cloning — so its natural decision is computed by
    ``git_guard.assess`` and can be stricter *or* looser than the pattern alone
    implies. ``assess`` falls back to the old behaviour whenever no evidence is
    available, so a failed probe costs a prompt, never a block.
    """
    result = check_git(command)
    if result is None:
        return None
    pattern_name, matched_text = result

    natural, reason = git_assess(pattern_name, matched_text, command)

    # A deny is never waved through by a project allowlist — whether it came
    # from the static hard-deny set or from a measured exploit signature in the
    # repository's own .gitmodules.
    if natural != "deny" and is_suppressed("git_guard", pattern_name=pattern_name):
        _log_suppressed_allow("git_guard", pattern_name, command, context)
        return None

    return _finish("git_guard", natural, command, pattern_name, reason, context)


def run_credential_access_guard(
    command: str, context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Run credential-file read guard checks. Returns response dict or None."""
    return _run_simple_guard(
        "credential_access_guard", cred_access_check, CRED_ACCESS_HARD_DENY,
        cred_access_format, command, context,
    )


def run_self_protection_guard(
    command: str, context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Ask before a shell command writes ForceField's or Claude Code's own config.

    ``filesystem_guard`` names all of these sinks but registers only for the
    file-editing tools, leaving the Bash path to them completely unguarded — a
    plain ``echo > ~/.claude/forcefield.json`` could set the trusted config tier
    and loosen every guard, with nothing to prompt on. Always ``ask``: the
    legitimate write and the hostile one are indistinguishable from here.
    """
    result = fs_bash_config_write(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    if is_suppressed("filesystem_guard", pattern_name=pattern_name):
        _log_suppressed_allow(
            "filesystem_guard", pattern_name, command, context,
        )
        return None

    # Prefer the sink's own risk text over the generic sentence. They are not
    # equivalent: a write under ~/.claude/forcefield/ can land on the venv python
    # that sigma_update.sh runs at every SessionStart, and "guard strictness,
    # hook allowlist" does not tell the user they are approving code execution.
    risk = FS_PATTERN_RISKS.get(pattern_name) or (
        "this path controls what ForceField and Claude Code do next "
        "(guard strictness, hook allowlist, remembered approvals, MCP servers)"
    )
    return _finish(
        "filesystem_guard", "ask", command, pattern_name,
        "FILESYSTEM GUARD: shell write to a security-config file\n\n"
        f"Matched: {matched_text}\n"
        f"Risk: {risk}.\n\n"
        "Approve only if you meant to change the security configuration.",
        context,
    )


def _decision_of(result: dict[str, object]) -> str:
    """The decision a guard result actually represents.

    A ``warn`` result is a bare ``{"systemMessage": ...}`` with no
    ``hookSpecificOutput``, so reading ``permissionDecision`` with an ``allow``
    default mis-scored it as the weakest possible decision.
    """
    gate = result.get("hookSpecificOutput")
    if isinstance(gate, dict) and gate.get("permissionDecision"):
        return str(gate["permissionDecision"])
    if result.get("systemMessage"):
        return "warn"
    return "allow"


def _pick_highest(
    a: dict[str, object] | None, b: dict[str, object] | None,
) -> dict[str, object] | None:
    """Return whichever result has the highest-precedence decision.

    Per docs: deny > ask > warn > allow. The loser's ``systemMessage`` is carried
    onto the winner rather than dropped — several guards can have something to
    say about one command, and only one of them can own the gate.
    """
    if a is None:
        return b
    if b is None:
        return a
    winner, loser = a, b
    if _DECISION_PRECEDENCE.get(_decision_of(b), 0) > \
            _DECISION_PRECEDENCE.get(_decision_of(a), 0):
        winner, loser = b, a

    carried = loser.get("systemMessage")
    if carried:
        existing = winner.get("systemMessage")
        if existing and carried not in str(existing):
            winner["systemMessage"] = "%s\n\n%s" % (existing, carried)
        elif not existing:
            winner["systemMessage"] = carried
    return winner


def _emit_ask_uninspectable() -> None:
    """Emit an 'ask' when stdin is too large or malformed to inspect.

    Closes the fail-open hole where a payload larger than MAX_STDIN_BYTES truncates
    and the JSON parse fails: rather than a silent allow, prompt the user. Never a
    hard block (zero-false-positive-deny), never a silent pass.
    """
    emit({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "ForceField could not inspect this Bash command: the hook input "
                f"exceeds {MAX_STDIN_BYTES} bytes or is malformed. Approve only if "
                "you trust this command."
            ),
        },
    })
    log_security_event(
        "security_dispatcher", "ask", command="<uninspectable>",
        extra={"reason": "oversized_or_unparseable_input"},
    )


def _emit_ask_unusable(detail: str) -> None:
    """Emit an 'ask' when the guard set could not be imported."""
    emit({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "ForceField could not load its Bash guards, so this command was "
                f"not inspected ({detail}). Reinstall the plugin, or approve "
                "only if you trust this command."
            ),
        },
    })
    log_security_event(
        "security_dispatcher", "ask", command="<guards-unavailable>",
        extra={"reason": "guard_import_failed", "detail": detail},
    )


_GUARDS = (
    ("exfil_guard", run_exfil_guard),
    ("supply_chain_guard", run_supply_chain_guard),
    ("git_guard", run_git_guard),
    ("credential_access_guard", run_credential_access_guard),
    ("filesystem_guard", run_self_protection_guard),
)


def _run_guards(
    command: str, context: dict[str, object] | None,
) -> tuple[dict[str, object] | None, list[str]]:
    """Run every guard, isolating each one's failure. Returns (winner, failed).

    The five guards used to run as five bare calls inside one try/except, so the
    first to raise discarded the verdicts its peers had *already computed* — a
    crash in the last guard threw away a hard deny from the first. Fail-open is
    the documented intent for a guard that cannot run, but it was never meant to
    be contagious. Each guard now fails alone, and ``main`` turns a failure into a
    prompt rather than letting it pass silently.
    """
    winner: dict[str, object] | None = None
    failed: list[str] = []
    for name, run in _GUARDS:
        try:
            winner = _pick_highest(winner, run(command, context))
        except Exception as exc:  # noqa: BLE001 - one guard must not sink the rest
            failed.append(name)
            defer_log(
                "security_dispatcher", "warn", command=command,
                context=context,
                extra={
                    "reason": "guard_raised",
                    "guard": name,
                    "detail": "%s: %s" % (type(exc).__name__, exc),
                },
            )
    return winner, failed


def _partial_inspection_ask(
    total_bytes: int, oversized: bool, failed: list[str],
    context: dict[str, object] | None = None,
) -> dict[str, object]:
    """An 'ask' for a command ForceField inspected only partially.

    Deliberately not routed through ``clamp_and_emit``: this is the dispatcher
    saying it could not do its job, not a guard reporting a finding, so no
    per-guard config ceiling applies to it. Same reasoning as
    ``_emit_ask_uninspectable`` one case over.
    """
    reasons = []
    if oversized:
        reasons.append(
            f"it is {total_bytes:,} bytes and only the first "
            f"{MAX_COMMAND_SCAN_BYTES:,} were scanned"
        )
    if failed:
        reasons.append("these guards failed to run: " + ", ".join(failed))
    detail = "; ".join(reasons)
    defer_log(
        "security_dispatcher", "ask", command="<partially-inspected>",
        context=context,
        extra={
            "reason": "partial_inspection",
            "detail": detail,
            "command_bytes": total_bytes,
            "failed_guards": failed,
        },
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                f"ForceField could not fully inspect this Bash command: {detail}. "
                "Approve only if you trust this command."
            ),
        },
    }


def main() -> None:
    """Dispatch stdin through exfil and supply-chain guards."""
    if _IMPORT_ERROR is not None:
        _emit_ask_unusable(_IMPORT_ERROR)
        return
    raw = read_stdin_text(MAX_STDIN_BYTES + 1)
    # The ceiling is a byte count and the read is now a byte read, so the check
    # is made on bytes too. ``surrogateescape`` round-trips, so this is exactly
    # the length that arrived -- and it is never smaller than the character
    # count the check used before, so nothing that used to be caught escapes.
    oversized = len(raw.encode("utf-8", "surrogateescape")) > MAX_STDIN_BYTES
    input_data = parse_event(raw)

    if oversized or (raw.strip() and input_data is None):
        _emit_ask_uninspectable()
        return
    if input_data is None:
        emit({})
        return

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    # Every correlation id Claude Code sent, in one dict, extracted once. Three
    # PreToolUse[Bash] hooks fire on the same command; before this they wrote
    # three records with no shared key, so a reconstruction could not tell which
    # findings belonged to the same tool call.
    context = context_from_event(input_data)

    if not command:
        emit({})
        return

    # Bound the text the regexes actually run over. The 5s hook timeout is a
    # security boundary: a hook killed mid-scan never delivers its verdict and
    # Claude Code fails open, so a command large enough to outlast the budget is
    # a bypass. Measured, a 72 KB command took 4.7s and a 180 KB one 11.6s — both
    # computed the correct deny, and neither got to emit it. MAX_STDIN_BYTES is
    # 1 MiB, two orders of magnitude past what 5s of scanning covers.
    #
    # The head is still scanned, so an obvious hard deny in a padded command is
    # still a deny; what the tail can no longer do is buy silence. Anything past
    # the cap ends at an ask, never an allow.
    oversized = len(command) > MAX_COMMAND_SCAN_BYTES
    scanned = command[:MAX_COMMAND_SCAN_BYTES] if oversized else command

    winner, failed = _run_guards(scanned, context)
    if oversized or failed:
        winner = _pick_highest(
            winner,
            _partial_inspection_ask(len(command), oversized, failed, context),
        )

    session_id = str(input_data.get("session_id", "") or "")
    cwd = input_data.get("cwd") or None

    if winner:
        emit(winner)
        _record_blocks(session_id, command, cwd)
        return

    # Nothing gated this command on its own merits. It may still be completing
    # what an earlier block refused, which the guards above cannot see because
    # they judge one command at a time.
    correlation, target = _correlation_for(session_id, scanned, cwd)
    if correlation is not None:
        emit(_correlation_response(correlation, target, command, context))
        return

    emit(None)
    log_security_event("security_dispatcher", "allow", command=command,
                       context=context)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
