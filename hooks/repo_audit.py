#!/usr/bin/env python3
"""SessionStart audit of what the current repository can execute.

``git_forensics.audit_repo`` already knows how to find the artifacts in a
repository that run without anyone asking for them: ``.gitmodules`` exploit
signatures, active git hooks, RCE-capable keys in ``.git/config``, and a
repo-shipped Claude Code settings file carrying hooks (the CVE-2025-59536 /
CVE-2026-21852 surface). ``git_guard`` consults it when a git command is about
to run. Nothing consulted it when a session merely *opened* in the repository --
which is the last moment at which the answer is still cheap to act on.

SessionStart has no decision control, so this hook can only tell. It emits the
audit as ``additionalContext`` for Claude and, for the exploit-signature tier
only, a ``systemMessage`` for the human.

Two properties matter more than coverage here:

- **Findings are graded, not accused.** A repository carrying a pre-commit hook
  installed by ``pre-commit``, ``husky`` or ``lefthook`` is entirely ordinary,
  and is reported as an inventory. Only a ``.gitmodules`` entry matching a known
  exploit signature is written as a warning, because only that one has no
  reading under which an honest repository produces it.
- **Silence when there is nothing to say.** An empty audit emits no context at
  all. A clean bill of health printed on every session start is noise, and noise
  is what teaches a reader to skip the one report that mattered.

Stdlib-only and fail-open in the strongest sense the hook contract asks for: a
broken import, unreadable repository, or unexpected exception yields an empty
response rather than a traceback.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# One guarded block rather than four. Every name below is stdlib-only and
# present in a working install, so the realistic failure is a damaged file --
# and an ImportError raised at module scope runs *before* ``__main__`` can catch
# it, which is the one path that would put a traceback on stderr instead of
# silence. ``MAX_STDIN_BYTES`` is restated so ``main`` can still drain stdin and
# exit quietly when the block fails.
try:
    from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
    from patterns import MAX_STDIN_BYTES  # noqa: E402
    from allowlist import is_suppressed  # noqa: E402
    from hook_logging import defer_log, emit  # noqa: E402
    import git_forensics  # noqa: E402

    _IMPORTS_OK = True
except Exception:  # noqa: BLE001 - a broken import must be silence, not a traceback
    _IMPORTS_OK = False
    MAX_STDIN_BYTES = 1_048_576

    def defer_log(*_args, **_kwargs):  # type: ignore[misc]
        return None

    def emit(response=None):  # type: ignore[misc]
        json.dump(response if response else {}, sys.stdout)

GUARD = "repo_audit"

# Per-category cap on what one report enumerates. A repository with forty hooks
# has a hook problem the fortieth line will not clarify, and SessionStart context
# is charged to every subsequent turn in the session.
MAX_LISTED = 10


def _hook_pattern(path: str) -> str:
    """Allowlist key for one installed hook, e.g. ``git_hook:pre-commit``."""
    return "git_hook:" + os.path.basename(path)


def collect_findings(audit: dict) -> dict:
    """Filter an ``audit_repo`` result through the project allowlist.

    Findings a project has accepted are dropped, keyed by guard name
    ``repo_audit``: ``git_hook:<name>``, ``git_config:<key>``,
    ``agent_config:<relative path>``, and — nominally — the indicator names
    themselves. Nominally, because ``allowlist._NEVER_SUPPRESSIBLE`` locks the
    four ``.gitmodules`` exploit signatures: the allowlist is read from the cwd,
    which under this threat model is the possibly-hostile repository being
    audited, and a repository that could suppress the report of its own exploit
    signature would be shipping its own blindfold. The inventory findings stay
    suppressible, since those are the ones a project legitimately accepts.

    Hooks and agent configs are additionally offered to ``suppress_paths``, so
    ``".git/hooks/*"`` works as a glob for a project that installs many.
    """
    return {
        "indicators": [
            name for name in (audit.get("indicators") or [])
            if not is_suppressed(GUARD, pattern_name=name)
        ],
        "hooks": [
            path for path in (audit.get("hooks") or [])
            if not is_suppressed(GUARD, pattern_name=_hook_pattern(path), file_path=path)
        ],
        "config_keys": [
            key for key in (audit.get("config_keys") or [])
            if not is_suppressed(GUARD, pattern_name="git_config:" + key)
        ],
        "agent_config": [
            rel for rel in (audit.get("agent_config") or [])
            if not is_suppressed(GUARD, pattern_name="agent_config:" + rel, file_path=rel)
        ],
    }


def has_findings(findings: dict) -> bool:
    """Whether anything survived the allowlist. Drives the say-nothing rule."""
    return any(findings.get(key) for key in
               ("indicators", "hooks", "config_keys", "agent_config"))


def finding_names(findings: dict) -> list[str]:
    """The findings as allowlist-shaped names, for ``forcefield.pattern``."""
    names = list(findings.get("indicators") or [])
    names += [_hook_pattern(p) for p in (findings.get("hooks") or [])]
    names += ["git_config:" + k for k in (findings.get("config_keys") or [])]
    names += ["agent_config:" + r for r in (findings.get("agent_config") or [])]
    return names


def _listing(items: list, indent: str = "  ") -> str:
    """Render a bounded, one-per-line listing of ``items``."""
    shown = [indent + str(item) for item in items[:MAX_LISTED]]
    remaining = len(items) - MAX_LISTED
    if remaining > 0:
        shown.append("%s... and %d more" % (indent, remaining))
    return "\n".join(shown)


def _indicator_section(indicators: list) -> str:
    """The exploit-signature paragraph — the only alarming thing this hook says."""
    lines = [
        "KNOWN EXPLOIT SIGNATURE in this repository's .gitmodules: %s"
        % ", ".join(indicators),
    ]
    for name in indicators[:MAX_LISTED]:
        risk = git_forensics.INDICATOR_RISKS.get(name)
        if risk:
            lines.append("  %s: %s" % (name, risk))
    lines.append(
        "  Treat `git submodule update` and any clone with --recurse-submodules "
        "here as unsafe until that entry has been read and accounted for."
    )
    return "\n".join(lines)


def render_context(findings: dict, root: str) -> str:
    """Render the audit as context for Claude, most serious finding first."""
    sections = ["FORCEFIELD REPO AUDIT - %s" % root]

    indicators = findings.get("indicators") or []
    if indicators:
        sections.append(_indicator_section(indicators))

    hooks = findings.get("hooks") or []
    if hooks:
        sections.append(
            "This repository contains %d git %s, which run on the next git "
            "operation:\n%s\nInstalled hooks are ordinary — pre-commit, husky and "
            "lefthook all create them. This is an inventory, not an alert; read "
            "one before running a git command you did not initiate."
            % (len(hooks), "hook" if len(hooks) == 1 else "hooks", _listing(hooks))
        )

    config_keys = findings.get("config_keys") or []
    if config_keys:
        sections.append(
            "This repository's .git/config sets %d %s whose value git runs as a "
            "command:\n%s\nThat is how a repository redirects hooks, the pager or "
            "the SSH command; it is legitimate configuration as well as a known "
            "execution route, so check what the value points at."
            % (len(config_keys), "key" if len(config_keys) == 1 else "keys",
               _listing(config_keys))
        )

    agent_config = findings.get("agent_config") or []
    if agent_config:
        sections.append(
            "This repository ships Claude Code settings that define hooks, which "
            "run on this session's own tool events:\n%s\nRepo-shipped agent hooks "
            "are the CVE-2025-59536 / CVE-2026-21852 surface. Read them before "
            "trusting this project's tooling."
            % _listing(agent_config)
        )

    # Tier-aware, because a fixed sign-off contradicts the report above it. "No
    # action is required" under an exploit signature tells the reader to dismiss
    # the one finding the report exists for, and the last line is the one a
    # skimmer keeps.
    if indicators:
        sections.append(
            "ForceField did not block any of this — SessionStart cannot gate "
            "anything. The exploit signature above is the part that needs a "
            "decision before any git command runs here."
        )
    else:
        sections.append(
            "Advisory only: nothing has been blocked, and nothing above requires "
            "action. It is an inventory of what can execute, not a finding."
        )
    return "\n\n".join(sections)


def render_alert(findings: dict) -> str:
    """The human-facing line. Reserved for the exploit tier — see the docstring."""
    return (
        "ForceField: this repository's .gitmodules carries a known exploit "
        "signature (%s). Nothing has been blocked. Do not run `git submodule "
        "update` or a recursive clone here until you have read that entry."
        % ", ".join(findings.get("indicators") or [])
    )


def build_response(findings: dict, root: str) -> dict:
    """Build the SessionStart response, or ``{}`` when there is nothing to say.

    ``systemMessage`` is attached only for the exploit tier. The two channels do
    not overlap — ``additionalContext`` reaches the model and never the human,
    ``systemMessage`` the reverse — so interrupting a person on every session
    start in every repository that has a pre-commit hook would spend the only
    channel that can reach them on the finding least likely to need them.
    """
    if not has_findings(findings):
        return {}
    response: dict = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": render_context(findings, root),
        },
    }
    if findings.get("indicators"):
        response["systemMessage"] = render_alert(findings)
    return response


def audit_session(cwd: str) -> tuple[dict, str]:
    """Audit the repository containing ``cwd``.

    Returns ``(findings, root)``; ``root`` is ``""`` when ``cwd`` is not inside a
    repository, in which case there is nothing to report and nothing to log.
    """
    root = git_forensics.find_repo_root(cwd)
    if not root:
        return ({}, "")
    return (collect_findings(git_forensics.audit_repo(root)), root)


def main() -> None:
    """Read the SessionStart event, audit the repo, emit context. Fail-open."""
    if not _IMPORTS_OK:
        emit({})
        return

    raw = read_stdin_text(MAX_STDIN_BYTES)
    data = parse_event(raw)
    if data is None:
        emit({})
        return
    if not isinstance(data, dict):
        emit({})
        return

    cwd = data.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        try:
            cwd = os.getcwd()
        except OSError:
            emit({})
            return

    context = context_from_event(data)
    findings, root = audit_session(cwd)
    if not root:
        emit({})
        return

    source = data.get("source", "")
    if not has_findings(findings):
        defer_log(GUARD, "allow", file_path=root, context=context,
                           extra={"source": source})
        emit({})
        return

    # Two rungs, matching the two the report itself draws. A known exploit
    # signature is a WARN record; an inventory of hooks and config keys is
    # ``warn_low`` (OTel INFO), because a session start in a repository with a
    # husky hook is not a security warning and a log full of them would be read
    # exactly as carefully as one.
    decision = "warn" if findings.get("indicators") else "warn_low"
    defer_log(
        GUARD, decision,
        pattern_matched=",".join(finding_names(findings)),
        file_path=root, context=context,
        extra={
            "source": source,
            "hooks": len(findings.get("hooks") or []),
            "config_keys": len(findings.get("config_keys") or []),
            "agent_config": len(findings.get("agent_config") or []),
        },
    )
    emit(build_response(findings, root))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
