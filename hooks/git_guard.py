#!/usr/bin/env python3
"""Git / repo-execution guard hook for Claude Code.

Detects the clone-time remote-code-execution surface and the git-config RCE
primitives that let a cloned or opened repository run code on the host before a
human has reviewed it:

- recursive submodule clones and ``git submodule update --init``, the trigger
  surface for CVE-2024-32002 (submodule path + symlink into ``.git/hooks`` on a
  case-insensitive filesystem) and CVE-2025-48384 (trailing-carriage-return
  submodule path);
- ``git config`` / ``git -c`` / ``--config`` settings that turn a later routine
  git command into command execution (``core.hooksPath``, ``core.fsmonitor``,
  ``core.sshCommand``, ``core.pager``, the per-command ``pager.<cmd>`` family,
  ``core.editor``, ``credential.helper``, ``protocol.file.allow``, and more);
- ``GIT_*`` environment variables run as commands (``GIT_SSH_COMMAND``,
  ``GIT_PROXY_COMMAND``, ``GIT_CONFIG_*``, ...);
- writes into an active ``.git/hooks`` directory (including submodule hook dirs,
  the ``$GIT_DIR/hooks`` form, and paths computed by ``git rev-parse
  --git-path``) or a git config file at the repo (``.git/config``), global
  (``~/.gitconfig``), XDG (``~/.config/git/config``), or system
  (``/etc/gitconfig``) level;
- and any ``git clone`` that has not disarmed that surface, which is redirected
  to the hardened form rather than merely reported (``HARDENED_CLONE``).

Commands are normalized first (``${IFS}``, backslash escapes, intra-word quoting,
redundant slashes) so common shell obfuscations do not evade the patterns.

Returns "ask" so the user approves before an untrusted repository can execute
code. Imported by ``security_dispatcher``, which owns the stdin/stdout plumbing,
allowlist suppression, and logging.
"""

from __future__ import annotations

import os
import re


# git config keys that turn a later routine git command into command execution.
# A few (credential.helper, core.fsmonitor) have legitimate uses, so all git
# findings are "ask" and a per-project allowlist can suppress a pattern.
_RCE_CONFIG_KEYS = (
    r"core\.hooksPath|core\.fsmonitor|core\.sshCommand|core\.pager|core\.editor"
    r"|core\.alternateRefsCommand|protocol\.file\.allow|clone\.recurseSubmodules"
    r"|submodule\.recurse|credential\.helper|diff\.external|sequence\.editor"
    r"|uploadpack\.packObjectsHook|filter\.[^\s.]+\.(?:process|clean|smudge)"
    # per-command pager selector: pager.<cmd> value is run as that subcommand's
    # pager, the same RCE surface as core.pager (e.g. pager.log='touch x').
    r"|pager\.[\w-]+"
    # init.templateDir points at a directory whose hooks/ is COPIED into every
    # repository created or cloned afterwards, so setting it once arms every
    # later `git init`/`git clone` on the machine. GIT_TEMPLATE_DIR, the env
    # spelling of the same primitive, was already covered below; the config
    # spelling and the --template= flag were not.
    r"|init\.templateDir"
    # core.gitProxy runs its value as the proxy program for git:// connections,
    # and protocol.ext.allow re-enables the ext:: transport that git disabled by
    # default precisely because it executes arbitrary commands.
    r"|core\.gitProxy|protocol\.ext\.allow"
)

# git-specific environment variables whose value is executed as a command.
_RCE_ENV_VARS = (
    r"GIT_SSH_COMMAND|GIT_SSH|GIT_PROXY_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS"
    r"|GIT_TEMPLATE_DIR|GIT_EDITOR|GIT_PAGER|GIT_SEQUENCE_EDITOR"
    r"|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_\d+|GIT_CONFIG_VALUE_\d+"
    r"|GIT_CONFIG_PARAMETERS|GIT_CONFIG"
)

# commands that create or modify a file, used to catch writes into .git internals.
_WRITE_VERB = (
    r">>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b|\bchmod\b|\bdd\b|\bof="
    r"|\btruncate\b|\bsed\b|\bpatch\b|\bprintf\b|\bpython[0-9.]*\b|\bperl\b"
    r"|\bruby\b|\bnode\b"
)

# git's own global options: the only tokens that may sit between ``git`` and its
# subcommand. ``unhardened_clone`` is the one git pattern that sees *every*
# clone rather than a flagged minority, so it cannot afford the loose
# ``\bgit\b[^\n]*\bclone\b`` shape the flagged patterns use -- that shape also
# matches ``git log --grep clone`` and ``git commit -m 'clone fix'``, which are
# ordinary commands in any repository. Anchoring ``clone`` to the subcommand
# position is what keeps this quiet. Every branch is length-bounded because the
# hook has a 5s budget and ``tests/test_redos.py`` times every compiled pattern
# in ``hooks/``.
_GIT_GLOBAL_OPT = (
    r"(?:-[cC]\s*\S{1,256}"
    r"|--(?:git-dir|work-tree|namespace|exec-path|config-env|super-prefix)[=\s]\S{1,256}"
    r"|--(?:no-pager|paginate|bare|literal-pathspecs|glob-pathspecs"
    r"|noglob-pathspecs|icase-pathspecs|no-replace-objects|no-optional-locks"
    r"|no-lazy-fetch)"
    r"|-p)"
)

# The hardened clone this guard redirects to. ``scripts/install.sh`` has cloned
# SigmaHQ with this exact form since before the pattern existed.
HARDENED_CLONE = "git -c core.hooksPath=/dev/null clone --no-recurse-submodules"

GIT_PATTERNS: dict[str, re.Pattern[str]] = {
    # --recu[...] covers git's unambiguous prefix abbreviations of
    # --recurse-submodules / --recursive (e.g. --recurse, --recu); no non-recurse
    # git option shares that prefix.
    "recursive_submodule_clone": re.compile(
        r"\bgit\b[^\n]*\bclone\b[^\n]*--recu[\w-]*",
        re.IGNORECASE,
    ),
    # Same submodule checkout surface reached without `clone`: pull/fetch/checkout
    # (and friends) with --recurse-submodules fetch and materialize submodule
    # working-tree content just as a recursive clone does.
    "submodule_recurse_fetch": re.compile(
        r"\bgit\b[^\n]*\b(?:pull|fetch|checkout|switch|restore|reset|read-tree)\b"
        r"[^\n]*--recu[\w-]*",
        re.IGNORECASE,
    ),
    "submodule_update": re.compile(
        r"\bgit\b[^\n]*\bsubmodule\b[^\n]*(?:\bupdate\b|--init)",
        re.IGNORECASE,
    ),
    "git_config_rce_primitive": re.compile(
        r"(?:\bgit\s+config\b|(?:^|\s)-c\b|--config\b)[^\n]*"
        r"\b(?:" + _RCE_CONFIG_KEYS + r")",
        re.IGNORECASE,
    ),
    # A git alias whose value begins with '!' runs as a shell command. Matching
    # only the '!'-prefixed value keeps ordinary aliases (alias.co=checkout) clear.
    "git_alias_shell": re.compile(
        r"(?:\bgit\s+config\b|(?:^|\s)-c\b|--config\b)[^\n]*"
        r"\balias\.[\w-]+\s*=?\s*['\"]?\s*!",
        re.IGNORECASE,
    ),
    "git_env_rce": re.compile(
        r"\b(?:" + _RCE_ENV_VARS + r")\s*=",
    ),
    # --template=<dir> copies that directory's hooks/ into the new repository,
    # so a clone or init pointed at an attacker-writable template runs code on
    # the next git operation. The flag form of init.templateDir above.
    "git_template_dir": re.compile(
        r"\bgit\b[^\n]*\b(?:clone|init)\b[^\n]*--template[=\s]",
        re.IGNORECASE,
    ),
    # --upload-pack / --receive-pack name a program git executes on the far side
    # of the connection, and with a local path they execute it here. Real uses
    # exist (a git installed outside PATH on the server), so this asks.
    "git_pack_program": re.compile(
        r"--(?:upload|receive)-pack[=\s]",
        re.IGNORECASE,
    ),
    # The ext:: transport hands its URL to the shell: `git clone "ext::sh -c
    # payload"` runs payload. Git ships it disabled by default (protocol.ext.allow)
    # for exactly that reason. Hard-denied below -- see HARD_DENY_PATTERNS.
    "git_ext_transport_rce": re.compile(
        r"\bgit\b[^\n]*\b(?:clone|fetch|pull|push|remote|submodule|ls-remote|archive)\b"
        r"[^\n]*(?<![\w.])ext::",
        re.IGNORECASE,
    ),
    # A hooks-dir write reached three ways: the literal .git/(modules/.../)?hooks/,
    # the $GIT_DIR/.../hooks/ env-var form, and a path computed by
    # `git rev-parse --git-path hooks/...` — none of the last two contain the
    # literal .git/...hooks/ substring but all resolve to the active hooks dir.
    "git_hooks_dir_write": re.compile(
        r"(?:" + _WRITE_VERB + r")[^\n]{0,2048}?"
        r"(?:\.git/(?:modules/[^\n]{0,256}/)?hooks/"
        r"|\$\{?GIT_DIR\}?/(?:[^\n]{0,256}/)?hooks/"
        r"|--git-path\b[^\n]{0,256}hooks)",
        re.IGNORECASE,
    ),
    # A config-file write reached at the repo (.git/config), global (~/.gitconfig),
    # XDG (~/.config/git/config), or system (/etc/gitconfig) level; a write to any
    # of them can set core.hooksPath and install code that runs on the next git op.
    "git_config_file_write": re.compile(
        r"(?:" + _WRITE_VERB + r")[^\n]{0,2048}?"
        r"(?:\.git/(?:modules/[^\n]{0,256}/)?config\b"
        r"|\.gitconfig\b"
        r"|\.config/git/config\b"
        r"|/etc/gitconfig\b)",
        re.IGNORECASE,
    ),
    # Every clone that has not disarmed the clone-time execution surface. Last
    # on purpose: `_first_match` returns the first hit, so a clone that ALSO
    # recurses submodules, sets an RCE-capable config key or names an `ext::`
    # URL keeps its more specific -- and in the ext:: case, denying -- finding.
    # `gh repo clone` is the same act through the other common spelling; leaving
    # it out would make the guard bypassable by accident rather than by intent.
    # Exempted by `_is_hardened_clone`, which is what makes this a redirect to a
    # named command rather than a wall.
    "unhardened_clone": re.compile(
        r"\bgit\b(?:\s+" + _GIT_GLOBAL_OPT + r")*\s+clone\b"
        r"|\bgh\s+repo\s+clone\b",
        re.IGNORECASE,
    ),
}

# Almost every git-guard finding is "ask". Those patterns have rare but real
# legitimate uses (pre-commit sets core.hooksPath; monorepos set core.fsmonitor),
# so a hard block would violate the zero-false-positive rule. The user confirms
# per call, and a per-project allowlist can suppress a pattern outright.
#
# One exception, and it is why this set is no longer empty. The `passive` posture
# in config.py stops converting `ask` into a prompt -- which is what the owner
# asked for -- but a guard whose every finding is `ask` then has no floor at all,
# and git is the clone-time takeover surface. `deny` had to mean something here
# before passive was safe to offer.
#
# ext:: is the one git primitive that clears the bar the other hard-deny sets use
# (exfil_guard: reverse_shell, nc_connect; supply_chain_guard: pipe_to_shell):
# there is no reading of the command under which it is not executing an
# attacker-chosen program. The transport's documented purpose is to run its URL
# as a command, and git ships it disabled by default for that reason. It is the
# git spelling of `curl | sh`.
#
# Deliberately NOT here: --recurse-submodules. It is the CVE-2024-32002 trigger
# surface and it stays `ask`, because it is also how thousands of ordinary repos
# are cloned -- hard-denying it would trade a real contract for a theoretical
# one. Under passive that finding warns instead of prompting, which is what
# "never prompt" actually costs.
HARD_DENY_PATTERNS: frozenset[str] = frozenset(["git_ext_transport_rce"])


def _normalize(command: str) -> str:
    """Collapse the shell obfuscations that let a git threat slip past a regex.

    Neutralizes line continuations, ``${IFS}``/``$IFS`` token separators,
    backslash escapes (``g\\it`` -> ``git``), intra-word quoting
    (``gi"t"`` -> ``git``), and redundant path slashes (``.git//hooks``). Every
    git-guard decision is "ask", so widening a match only adds a prompt.
    """
    s = re.sub(r"\\\n", "", command)          # line continuation
    s = re.sub(r"\$\{IFS\}|\$IFS\b", " ", s)   # IFS token separator
    s = re.sub(r"\\(.)", r"\1", s)             # backslash escape
    s = re.sub(r"(?<=[\w.])['\"](?=[\w.])", "", s)  # intra-word / intra-key quotes
    s = re.sub(r"/{2,}", "/", s)               # redundant slashes
    return s


# Reading or removing an RCE-capable config key is not the threat; *setting* one
# is. ``git config --get core.pager`` tells you what is already configured, and
# ``--unset`` takes it away — both were being reported as "turns a later routine
# git command into arbitrary command execution", which is simply not what they do.
# Inspecting your own config is also the natural first move when auditing a repo
# for exactly these keys, so the guard was loudest at the moment it was least
# useful.
_GIT_CONFIG_READ_ONLY = re.compile(
    r"(?i)\bgit\b(?:\s+--\S+)*\s+config\b[^\n]{0,200}?\s--"
    r"(?:get|get-all|get-regexp|get-urlmatch|get-color|get-colorbool"
    r"|list|unset|unset-all|remove-section|name-only|show-origin|show-scope)\b"
)

# ...but ``git -c core.pager=… config --get x`` *does* set the key for that very
# invocation, so an inline setter anywhere in the command revokes the exemption.
_GIT_INLINE_RCE_SET = re.compile(
    r"(?i)(?:(?:^|\s)-c\s*|--config\s*)(?:" + _RCE_CONFIG_KEYS + r")\s*="
)


def _is_read_only_config(normalized: str) -> bool:
    """Whether this is an inspect/remove of a config key rather than a set."""
    return bool(
        _GIT_CONFIG_READ_ONLY.search(normalized)
        and not _GIT_INLINE_RCE_SET.search(normalized)
    )


# ``core.hooksPath`` is on the RCE list because pointing it at repository content
# runs that content. Pointing it at ``/dev/null`` does the exact opposite: it is
# how you turn hooks OFF, and it is half of what ``_is_hardened_clone`` requires.
# Measured on git 2.50.1: a ``post-commit`` hook that fires normally does not
# fire under it, ``rev-parse --git-path hooks`` reports ``/dev/null``, and the
# setting reaches git's own subprocesses through ``GIT_CONFIG_PARAMETERS`` — so
# a submodule checkout spawned by the clone inherits it too.
#
# Both spellings count. ``-c`` is scoped to the one invocation and is what
# ``HARDENED_CLONE`` uses; ``git clone --config`` writes the key into the new
# repository, which git applies "before the remote history is fetched or any
# files checked out" — in force for the window that matters, at the cost of
# persisting into the clone.
_INERT_HOOKS_PATH = re.compile(
    r"(?:^|\s)(?:-c\s*|--config[=\s]\s*)core\.hooksPath\s*=\s*"
    r"['\"]?/dev/null['\"]?(?=$|[\s;&|])",
    re.IGNORECASE,
)

# ``--no-recurse-submodules`` is NOT redundant with clone's default.
# ``clone.recurseSubmodules`` or ``submodule.recurse`` set at any of the four
# config levels makes a bare ``git clone`` recursive with nothing on the command
# line to show it — the composition attack in `docs/threat-model.md`, where the
# config-setting step and the clone step are each individually benign. The
# explicit flag overrides all four. ``--no-recu`` and the rest of git's
# unambiguous abbreviations are accepted, mirroring how the positive form is
# matched above.
_NO_RECURSE_SUBMODULES = re.compile(r"--no-recu[\w-]*", re.IGNORECASE)


def _is_hardened_clone(normalized: str) -> bool:
    """Whether this clone has disarmed the clone-time execution surface."""
    return bool(
        _INERT_HOOKS_PATH.search(normalized)
        and _NO_RECURSE_SUBMODULES.search(normalized)
    )


# The two command words that reach a clone. Anything else leading the segment
# means the literal is being named rather than run.
_CLONE_LEADERS = frozenset({"git", "gh"})


def _unhardened_clone_segment(normalized: str) -> str | None:
    """Text of the first segment here that actually INVOKES an unhardened clone.

    Two refinements the pattern alone cannot make. Both matter more for this
    pattern than for any other in the file, because this is the one that sees
    every clone instead of a flagged minority.

    *Position.* ``grep 'git clone'``, ``echo 'run git clone later' >> NOTES.md``
    and a heredoc commit message about cloning all carry the literal and run
    nothing — the shapes ``tests/test_false_positives.py`` exists to hold the
    line on. ``shell_context`` supplies the quote-aware split; the segment has to
    be led by ``git`` or ``gh`` for the match to mean what the pattern assumed.

    *Scope.* Hardening is judged per segment, not per command, so
    ``<hardened clone> && git clone <other>`` cannot launder the second clone
    with the first one's flags.

    Fails toward the ask. ``shell_context`` degrades toward the caller's prior
    behaviour by design, and the prior behaviour of this pattern is to match.
    """
    try:
        from shell_context import leading_command, split_segments, strip_heredocs

        segments = [segment
                    for segment in split_segments(strip_heredocs(normalized))
                    if leading_command(segment) in _CLONE_LEADERS]
    except Exception:  # noqa: BLE001 - never toward silence
        segments = [normalized]
    for segment in segments:
        match = GIT_PATTERNS["unhardened_clone"].search(segment)
        if match and not _is_hardened_clone(segment):
            return match.group(0)
    return None


def _only_hooks_disabled(normalized: str) -> bool:
    """Whether every RCE-capable config setting here merely turns hooks off.

    Without this carve-out the guard would prompt on the exact command it tells
    you to run instead, which is the one failure that would make the redirect
    worse than no redirect at all.

    Scoped to the *setting*, never to the command: the inert settings are removed
    and the RCE pattern re-run over what is left, so
    ``-c core.hooksPath=/dev/null -c core.pager=evil`` keeps its finding.
    """
    if not _INERT_HOOKS_PATH.search(normalized):
        return False
    return not GIT_PATTERNS["git_config_rce_primitive"].search(
        _INERT_HOOKS_PATH.sub(" ", normalized)
    )


def _first_match(command, skip=frozenset()):
    """First pattern in ``GIT_PATTERNS`` that matches, ignoring ``skip``.

    Two callers with one difference between them. ``check_git`` considers every
    pattern; the downgrade veto in ``assess`` considers only the ones a git
    release cannot make irrelevant. Everything else — the normalization, the walk
    order, the ``git config --get`` carve-out, the return shape — was written
    twice and has to stay identical, which is the drift this closes: cff9082
    added the carve-out to ``check_git`` and 8f4446e re-copied it into the veto.

    ``skip`` is the only axis of variation and must stay that way. It is NOT a
    general filter: narrowing what ``check_git`` sees narrows the ask tier *and*
    the ``git_ext_transport_rce`` deny tier, while narrowing what the veto sees
    silently turns asks into warns on a patched host. Those are two different
    security decisions. Anything that should apply to both belongs in
    ``_normalize``, which they already share.
    """
    normalized = _normalize(command)
    for name, pattern in GIT_PATTERNS.items():
        if name in skip:
            continue
        match = pattern.search(normalized)
        if match:
            if name == "git_config_rce_primitive" and (
                _is_read_only_config(normalized) or _only_hooks_disabled(normalized)
            ):
                continue
            if name == "unhardened_clone":
                segment = _unhardened_clone_segment(normalized)
                if segment is None:
                    continue
                return (name, segment)
            return (name, match.group(0))
    return None


def check_git(command: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_text)`` for the first git threat, else None."""
    return _first_match(command)


PATTERN_RISKS = {
    "recursive_submodule_clone": (
        "Recursive submodule clone can execute attacker-controlled git hooks at "
        "clone time (CVE-2024-32002, CVE-2025-48384)."
    ),
    "submodule_recurse_fetch": (
        "Fetching or checking out with --recurse-submodules fetches and "
        "materializes attacker-controlled submodule content — the same hook "
        "trigger as CVE-2024-32002 / CVE-2025-48384, reached without a clone."
    ),
    "submodule_update": (
        "Initializing submodules fetches and checks out attacker-controlled "
        "submodule content — the same clone-time hook trigger as CVE-2024-32002 "
        "/ CVE-2025-48384, reached without a --recursive clone."
    ),
    "git_config_rce_primitive": (
        "This git config key turns a later routine git command into arbitrary "
        "command execution."
    ),
    "git_alias_shell": (
        "A git alias whose value begins with '!' runs as an arbitrary shell "
        "command as soon as the alias is invoked."
    ),
    "git_env_rce": (
        "This GIT_* environment variable is run as a command by the next git "
        "operation (e.g. GIT_SSH_COMMAND, GIT_PROXY_COMMAND, GIT_CONFIG_*)."
    ),
    "git_template_dir": (
        "--template=<dir> copies that directory's hooks/ into the new "
        "repository, so a clone or init pointed at attacker-writable template "
        "content runs code on the next git operation."
    ),
    "git_pack_program": (
        "--upload-pack / --receive-pack name a program git executes for the "
        "transfer. With a local path, git executes it on this machine."
    ),
    "git_ext_transport_rce": (
        "The ext:: transport hands its URL straight to the shell, so "
        "'git clone \"ext::sh -c payload\"' runs payload. Git ships ext:: "
        "disabled by default (protocol.ext.allow) for exactly that reason. "
        "This is the git spelling of 'curl | sh' and there is no reading of "
        "the command under which it is not executing an attacker-chosen "
        "program."
    ),
    "git_hooks_dir_write": (
        "Writing into a git hooks directory (including via $GIT_DIR or "
        "'git rev-parse --git-path') installs code that runs on the next git "
        "operation."
    ),
    "git_config_file_write": (
        "Writing into a git config file (repo .git/config, global ~/.gitconfig, "
        "XDG ~/.config/git/config, or /etc/gitconfig) can set core.hooksPath or "
        "another key that runs code on the next git operation."
    ),
    "unhardened_clone": (
        "git clone is not a read-only operation. This clone leaves git free to "
        "run a hook out of the repository it is fetching, and leaves "
        "clone.recurseSubmodules — settable in any of the four config levels — "
        "free to pull in submodule content that was never named on this command "
        "line. Both happen before you or the agent have read a line of the code."
    ),
}

PATTERN_ALTERNATIVES = {
    "recursive_submodule_clone": (
        "Clone without --recursive, inspect .gitmodules, then run "
        "'git submodule update --init' after review (with git kept up to date)."
    ),
    "submodule_recurse_fetch": (
        "Inspect .gitmodules and each submodule URL first; fetch or check out "
        "without --recurse-submodules until you have reviewed them."
    ),
    "submodule_update": (
        "Inspect .gitmodules and each submodule URL first; only initialize "
        "submodules you have reviewed, with git kept up to date."
    ),
    "git_config_rce_primitive": (
        "Leave this key unset for untrusted repos. Only set it once you have "
        "reviewed exactly what command it points to."
    ),
    "git_alias_shell": (
        "Do not define shell ('!'-prefixed) aliases from untrusted input; only "
        "set them to a command you have written and reviewed yourself."
    ),
    "git_env_rce": (
        "Unset the variable for untrusted repos. Only set it to a command you "
        "have written and reviewed yourself."
    ),
    "git_template_dir": (
        "Drop --template and let git use its own default templates, or point "
        "it at a template directory you wrote and reviewed yourself."
    ),
    "git_pack_program": (
        "Drop the flag unless you genuinely need to name git's location on the "
        "server, and never take its value from a repo or README you have not "
        "audited."
    ),
    "git_ext_transport_rce": (
        "Do not run this. Obtain the repository over https:// or ssh:// "
        "instead. If a project genuinely requires ext::, read exactly what "
        "command the URL runs before enabling protocol.ext.allow yourself."
    ),
    "git_hooks_dir_write": (
        "Review the hook script before installing it, and never install a hook "
        "carried by a repo you have not audited."
    ),
    "git_config_file_write": (
        "Do not edit .git/config for a repo you have not audited; review exactly "
        "which key is being set and what it points to."
    ),
    # Describes the hardening rather than repeating the command, which
    # `_clone_reason` appends with the real URL spliced in. It still has to
    # stand alone: `assess` falls back to `format_alert` when git_forensics
    # cannot be imported, and that path never reaches `_clone_reason`.
    "unhardened_clone": (
        "Point core.hooksPath at /dev/null for the clone and pass "
        "--no-recurse-submodules, so no hook the repository ships can run and "
        "no config level can recurse submodules behind you. Inspect the remote "
        "first with /forcefield:inspect."
    ),
}


def format_alert(pattern_name: str, matched_text: str) -> str:
    """Build the decision reason for a git-guard finding."""
    risk = PATTERN_RISKS.get(pattern_name, "Potential repo-execution risk")
    alt = PATTERN_ALTERNATIVES.get(pattern_name, "Review before proceeding.")
    msg = f"GIT GUARD: {pattern_name}\n\n"
    msg += f"Matched: {matched_text[:120]}\n"
    msg += f"Risk: {risk}\n\n"
    # A hard deny cannot be approved, so it must not print an approval checklist.
    if pattern_name in HARD_DENY_PATTERNS:
        msg += "This is blocked outright, not offered for approval.\n"
        msg += f"- Instead: {alt}"
    else:
        msg += "Before approving:\n"
        msg += "- Do you trust the repository / source this came from?\n"
        msg += "- Have you reviewed .gitmodules, .git/config, and any hook scripts?\n"
        msg += f"- Safer alternative: {alt}"
    return msg


# --------------------------------------------------------------------------
# Evidence-graded assessment
# --------------------------------------------------------------------------
#
# The patterns above match command *shape*. `assess` folds in what
# git_forensics can actually measure, so a finding is graded by evidence
# rather than by shape alone:
#
#   escalate  a measured exploit signature turns the ask into a deny -- these
#             have no honest reading. Three sources: .gitmodules on disk, a
#             verdict recorded by /forcefield:inspect, and .gitmodules fetched
#             from an allowlisted forge without cloning
#   downgrade a host whose git is patched for both clone-time CVEs turns the
#             ask into a warn
#   default   anything unmeasurable keeps today's ask, unchanged
#
# Evidence is consulted in that order on purpose. A downgrade must never be
# able to override a positive indicator, so every escalation is decided first.
#
# Note what does NOT downgrade: a remote .gitmodules that came back clean. It
# annotates the decision and nothing more. Absence of a known signature is not
# absence of an exploit -- CVE-2024-32002 needs a symlink that lives in the tree
# rather than in .gitmodules, and the file is read at HEAD while the clone may
# name another ref. Only the host's own patch level closes the CVE, so only the
# host's patch level may soften the finding.

# The three patterns whose entire rationale is the two clone-time CVEs. Only
# these are eligible for a version-based downgrade; every other git pattern is
# a documented feature being used as intended, which no git release "fixes".
_CVE_DEPENDENT = frozenset({
    "recursive_submodule_clone",
    "submodule_recurse_fetch",
    "submodule_update",
})

# Patterns graded against evidence about the REMOTE rather than about this host:
# both name a fresh clone of a URL, so a recorded /forcefield:inspect verdict and
# the remote's own .gitmodules are evidence about the thing being fetched.
# `unhardened_clone` is here for the escalations and deliberately NOT in
# `_CVE_DEPENDENT`, because no git release makes an unhardened clone hardened.
_CLONE_PATTERNS = _CVE_DEPENDENT | frozenset({"unhardened_clone"})

# What the downgrade veto ignores. `_first_non_cve_pattern` exists to catch a
# command that ALSO sets a primitive no git release makes safe, so it must not
# see `unhardened_clone`: that is not a primitive the command sets, it is the
# absence of hardening on the very clone being graded, and it matches every
# recursive clone by construction. Leaving it in would silently retire the
# patched-host downgrade instead of qualifying it — which `assess` does properly,
# by letting the unhardened-clone ask stand in place of the downgraded warn.
_VETO_SKIP = _CVE_DEPENDENT | frozenset({"unhardened_clone"})

# Opt out of the pre-clone remote fetch without disabling the guard.
_REMOTE_INSPECT_ENV = "FORCEFIELD_NO_REMOTE_INSPECT"

_CLONE_URL = re.compile(
    r"\bgit\b[^\n]*\bclone\b[^\n]*?(?<![\w.-])"
    r"((?:https?|ssh|git)://[^\s'\"]+|[\w.-]+@[\w.-]+:[^\s'\"]+)",
    re.IGNORECASE,
)


def _first_non_cve_pattern(command):
    """First match that is not one of the two clone-time CVEs, or None.

    Used to veto an evidence-based downgrade: a command can match a submodule
    pattern *and* set an RCE-capable config key, and only the former is made
    irrelevant by a patched git.
    """
    return _first_match(command, skip=_VETO_SKIP)


def _unhardened_clone_match(command):
    """``("unhardened_clone", matched_text)`` for this command, or None.

    The one pattern `assess` has to be able to test out of order. `check_git`
    reports its first match and `unhardened_clone` is checked last, so a clone
    that also recurses submodules arrives here labelled
    `recursive_submodule_clone` — and on a patched host that label downgrades
    while the hardening finding underneath it does not.
    """
    segment = _unhardened_clone_segment(_normalize(command))
    return ("unhardened_clone", segment) if segment is not None else None


def _clone_reason(matched_text: str, command: str) -> str:
    """The unhardened-clone ask, carrying the command to run in its place.

    A prompt that says "this is not hardened" and stops there is a toll booth.
    The URL is spliced into both lines so the replacement is copy-pasteable;
    `hook_logging._scrub_reason` masks a credential embedded in it, on this path
    like every other.
    """
    url_match = _CLONE_URL.search(command)
    url = url_match.group(1)[:200] if url_match else "<url>"
    reason = format_alert("unhardened_clone", matched_text)
    reason += "\n\nRun instead:\n"
    reason += "  /forcefield:inspect %s\n" % url
    reason += "  %s %s\n" % (HARDENED_CLONE, url)
    return reason


def _deny_signatures(indicators):
    """The subset of ``indicators`` that justifies a hard block.

    ``git_forensics.DENY_INDICATORS`` names the four signatures with no honest
    reading. ``scan_gitmodules`` emits nothing else today, which is precisely why
    this filter was missing: it looks like a no-op. But that made the deny tier's
    zero-false-positive contract rest on the two sets happening to coincide, so
    the first advisory-only indicator added to the scanner would have silently
    inherited a hard block. ``tests/test_git_forensics.py`` asserts they agree.
    """
    from git_forensics import DENY_INDICATORS

    return [name for name in (indicators or []) if name in DENY_INDICATORS]


def _indicator_reason(pattern_name, indicators, source):
    """Build the deny reason for measured .gitmodules exploit signatures."""
    from git_forensics import INDICATOR_RISKS

    msg = f"GIT GUARD: {pattern_name}\n\n"
    msg += "Blocked on measured evidence, not on the shape of the command.\n"
    msg += f"Source: {source}\n\n"
    for name in indicators:
        msg += f"- {name}\n  {INDICATOR_RISKS.get(name, 'Known exploit signature.')}\n"
    msg += "\nThis repository carries the literal signature of a known "
    msg += "clone-time RCE exploit. Do not clone or initialize it. Report it "
    msg += "to the host it is published on."
    return msg


def _recorded_danger(pattern_name, url):
    """Deny reason from a stored ``/forcefield:inspect`` verdict, or None.

    The in-hook fetch below reaches four forge hosts. ``/forcefield:inspect``
    reaches every other one — a self-hosted GitLab, an SSH remote, a private
    instance — because it runs as a user command rather than inside a fail-open
    5s hook. Without this the two never met: the user could inspect a repository,
    be told DO NOT CLONE, and then have the clone merely prompt.

    Escalate-only. A clean verdict is not consulted here and cannot downgrade
    anything, for the reason ``inspect_remote.find_danger`` documents.
    """
    try:
        import inspect_remote

        record = inspect_remote.find_danger(url)
        if not record:
            return None
        signatures = _deny_signatures(record.get("indicators"))
        if not signatures:
            return None
    except Exception:  # noqa: BLE001 - an unreadable store is simply no evidence
        return None

    msg = _indicator_reason(
        pattern_name, signatures,
        "/forcefield:inspect of %s at %s" % (record.get("repo"),
                                             (record.get("commit") or "?")[:12]))
    msg += ("\n\nThis verdict was measured by an inspection you ran, and applies "
            "to the repository rather than to that one commit: a later commit "
            "that drops the signature does not unpublish the earlier one. Revoke "
            "it with `inspect_remote.py forget %s` if you disagree."
            % (record.get("key") or "")[:12])
    return msg


def assess(pattern_name, matched_text, command, cwd=None):
    """Return ``(decision, reason)`` for a git finding, graded by evidence.

    Falls back to the guard's existing behaviour whenever evidence is
    unavailable, so a failed probe can never weaken a decision.
    """
    try:
        import git_forensics as forensics
    except Exception:  # noqa: BLE001 - evidence is optional, the guard is not
        return ("deny" if pattern_name in HARD_DENY_PATTERNS else "ask",
                format_alert(pattern_name, matched_text))

    if pattern_name in HARD_DENY_PATTERNS:
        return ("deny", format_alert(pattern_name, matched_text))

    if pattern_name not in _CLONE_PATTERNS:
        return ("ask", format_alert(pattern_name, matched_text))

    # --- escalate: a signature already on disk -----------------------------
    #
    # Scoped to the CVE patterns. `git submodule update` acts on the repository
    # the shell is standing in, so that repository's .gitmodules is evidence
    # about it. A clone of some other URL is not made dangerous by the
    # .gitmodules of whatever directory it happens to be launched from, and
    # `unhardened_clone` matches enough commands that inheriting that mismatch
    # would turn one hostile checkout on disk into a block on every unrelated
    # clone made while standing in it.
    if pattern_name in _CVE_DEPENDENT:
        try:
            root = forensics.find_repo_root(cwd or os.getcwd())
            if root:
                signatures = _deny_signatures(forensics.audit_repo(root)["indicators"])
                if signatures:
                    return ("deny", _indicator_reason(
                        pattern_name, signatures,
                        os.path.join(root, ".gitmodules")))
        except Exception:  # noqa: BLE001
            pass

    url_match = _CLONE_URL.search(command)
    clone_url = url_match.group(1) if url_match else None

    # --- escalate: a verdict the user already paid for ---------------------
    if clone_url:
        recorded = _recorded_danger(pattern_name, clone_url)
        if recorded is not None:
            return ("deny", recorded)

    # --- escalate or downgrade: a signature at the far end of a fresh clone -
    remote_clean = False
    if clone_url and not os.environ.get(_REMOTE_INSPECT_ENV):
        try:
            result = forensics.fetch_remote_gitmodules(clone_url)
            signatures = _deny_signatures(result.get("indicators"))
            if signatures:
                return ("deny", _indicator_reason(
                    pattern_name, signatures, result.get("url", clone_url)))
            if result.get("status") in ("ok", "absent"):
                remote_clean = True
        except Exception:  # noqa: BLE001
            pass

    # `unhardened_clone` stops here. Every escalation above has been consulted;
    # what follows is the version-based downgrade, and there is no git release
    # that makes an unhardened clone hardened. The two settings this asks for
    # are not patches for the two CVEs — one stops a hook the repository ships
    # from running at all, the other overrides a `clone.recurseSubmodules` no
    # git version has ever ignored.
    if pattern_name == "unhardened_clone":
        reason = _clone_reason(matched_text, command)
        if remote_clean:
            reason += ("\nThe remote's .gitmodules was fetched without cloning and "
                       "carries no known exploit signature, which says nothing "
                       "about the code or about the hooks this clone would run.")
        return ("ask", reason)

    # --- downgrade: nothing measurable is exposed --------------------------
    try:
        exposure = forensics.clone_cve_exposure(cwd)
    except Exception:  # noqa: BLE001
        exposure = {"exposed": None, "reason": "probe failed"}

    # check_git reports only its first match, and the submodule patterns are
    # checked before the config ones. So `git -c protocol.file.allow=always
    # clone --recursive .` arrives here labelled `recursive_submodule_clone`
    # while also carrying an RCE primitive. The downgrade rationale is "this
    # git release closed the CVE", which says nothing about a config key the
    # same command sets, so any non-CVE pattern anywhere in the command
    # revokes eligibility.
    companion = _first_non_cve_pattern(command)
    if companion is not None:
        reason = format_alert(companion[0], companion[1])
        reason += (f"\n\nReported alongside {pattern_name}: this command also "
                   "sets a git primitive that no git release makes safe, so the "
                   "clone-time CVE status is not relevant to it.")
        return ("ask", reason)

    if exposure.get("exposed") is False:
        # The CVE half of this finding is closed here; the hardening half is
        # not, and a clone is the one shape where both apply to the same
        # command. Without this, `git clone --recursive <url>` — which cannot
        # be hardened, by construction — would go quiet on a patched host while
        # the strictly safer `git clone <url>` still prompted, so a README that
        # asked for `--recursive` would buy LESS friction than one that did not.
        clone = _unhardened_clone_match(command)
        if clone is not None:
            reason = _clone_reason(clone[1], command)
            reason += ("\n\n%s downgraded to context on this host: %s. That "
                       "closes the two CVEs and nothing else — it does not stop "
                       "a hook this repository ships, and it does not override a "
                       "clone.recurseSubmodules set in any config level."
                       % (pattern_name, exposure["reason"]))
            return ("ask", reason)
        note = f"GIT GUARD: {pattern_name} (context only)\n\n"
        note += f"Matched: {matched_text[:120]}\n"
        note += f"{exposure['reason']}, so the clone-time RCE path is closed here.\n"
        if remote_clean:
            note += "The remote's .gitmodules was fetched without cloning and carries no known exploit signature.\n"
        note += "\nStill treat the repository's contents as untrusted: a clean "
        note += ".gitmodules says nothing about what the code does once you run it."
        return ("warn", note)

    reason = format_alert(pattern_name, matched_text)
    if exposure.get("exposed") is True:
        reason += f"\n\nHost exposure: {exposure['reason']}. Update git."
    if remote_clean:
        reason += ("\n\nThe remote's .gitmodules was fetched without cloning and "
                   "carries no known exploit signature, but this host is still exposed.")
    return ("ask", reason)
