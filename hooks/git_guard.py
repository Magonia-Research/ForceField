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
  (``/etc/gitconfig``) level.

Commands are normalized first (``${IFS}``, backslash escapes, intra-word quoting,
redundant slashes) so common shell obfuscations do not evade the patterns.

Returns "ask" so the user approves before an untrusted repository can execute
code. Imported by ``security_dispatcher``, which owns the stdin/stdout plumbing,
allowlist suppression, and logging.
"""

from __future__ import annotations

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
    # A hooks-dir write reached three ways: the literal .git/(modules/.../)?hooks/,
    # the $GIT_DIR/.../hooks/ env-var form, and a path computed by
    # `git rev-parse --git-path hooks/...` — none of the last two contain the
    # literal .git/...hooks/ substring but all resolve to the active hooks dir.
    "git_hooks_dir_write": re.compile(
        r"(?:" + _WRITE_VERB + r")[^\n]*"
        r"(?:\.git/(?:modules/[^\n]*/)?hooks/"
        r"|\$\{?GIT_DIR\}?/(?:[^\n]*/)?hooks/"
        r"|--git-path\b[^\n]*hooks)",
        re.IGNORECASE,
    ),
    # A config-file write reached at the repo (.git/config), global (~/.gitconfig),
    # XDG (~/.config/git/config), or system (/etc/gitconfig) level; a write to any
    # of them can set core.hooksPath and install code that runs on the next git op.
    "git_config_file_write": re.compile(
        r"(?:" + _WRITE_VERB + r")[^\n]*"
        r"(?:\.git/(?:modules/[^\n]*/)?config\b"
        r"|\.gitconfig\b"
        r"|\.config/git/config\b"
        r"|/etc/gitconfig\b)",
        re.IGNORECASE,
    ),
}

# All git-guard findings are "ask". These patterns have rare but real legitimate
# uses (pre-commit sets core.hooksPath; monorepos set core.fsmonitor), so a hard
# block would violate the zero-false-positive rule. The user confirms per call,
# and a per-project allowlist can suppress a pattern outright.
HARD_DENY_PATTERNS: frozenset[str] = frozenset()


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


def check_git(command: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_text)`` for the first git threat, else None."""
    normalized = _normalize(command)
    for name, pattern in GIT_PATTERNS.items():
        match = pattern.search(normalized)
        if match:
            return (name, match.group(0))
    return None


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
    "git_hooks_dir_write": (
        "Review the hook script before installing it, and never install a hook "
        "carried by a repo you have not audited."
    ),
    "git_config_file_write": (
        "Do not edit .git/config for a repo you have not audited; review exactly "
        "which key is being set and what it points to."
    ),
}


def format_alert(pattern_name: str, matched_text: str) -> str:
    """Build the ask-reason message for a git-guard finding."""
    risk = PATTERN_RISKS.get(pattern_name, "Potential repo-execution risk")
    alt = PATTERN_ALTERNATIVES.get(pattern_name, "Review before proceeding.")
    msg = f"GIT GUARD: {pattern_name}\n\n"
    msg += f"Matched: {matched_text[:120]}\n"
    msg += f"Risk: {risk}\n\n"
    msg += "Before approving:\n"
    msg += "- Do you trust the repository / source this came from?\n"
    msg += "- Have you reviewed .gitmodules, .git/config, and any hook scripts?\n"
    msg += f"- Safer alternative: {alt}"
    return msg
