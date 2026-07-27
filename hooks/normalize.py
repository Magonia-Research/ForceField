#!/usr/bin/env python3
"""Shared command normalizer for Portcullis detection matching.

``normalize_command`` canonicalizes a shell command *for detection matching
only* — the normalized string is never executed. It undoes the cheap shell
obfuscations that let a literal-anchored guard pattern be evaded:

- backslash escapes of command characters (``\\curl`` -> ``curl``,
  ``p\\ip`` -> ``pip``);
- ``${IFS}`` / ``$IFS`` token separators collapsed to a single space;
- intra-word quote splitting (``c'u'rl`` / ``c"u"rl`` / ``cu''rl`` -> ``curl``);
- an absolute or relative path prefix (and any wrapping quotes) on a *known
  sensitive binary* reduced to its basename (``/usr/bin/curl`` -> ``curl``,
  ``./nc`` -> ``nc``, ``'curl'`` -> ``curl``).

The exfil and supply-chain guards match their detection patterns against BOTH
the raw command and this normalized form, so an obfuscated payload is caught
while the raw command remains what the allowlist and the logs see.
Normalization only ever *removes* obfuscation and reduces a known binary to its
basename, so it cannot synthesize a hard-deny substring in a legitimate command.

Stdlib-only, Python 3.9+. Fail-safe: any exception returns the input unchanged.
"""

from __future__ import annotations

import re

# Binaries the exfil and supply-chain guards anchor their patterns on. Only a
# path/quote prefix on one of THESE exact names, at a token boundary, is reduced
# to its basename; an arbitrary path is left alone. Boundary-anchored, so a
# substring (localhost, digit, ghost) is never mistaken for a binary.
_SENSITIVE_BINARIES = (
    "curl", "wget", "nc", "ncat", "netcat", "fetch", "aria2c",
    "scp", "rsync", "sftp", "nslookup", "dig", "host", "drill", "git",
    "pip", "pip3", "npm", "pnpm", "yarn", "npx", "bunx", "uvx", "pipx",
    "cargo", "gem", "python", "python2", "python3", "ruby", "perl",
    "node", "deno", "php", "pwsh", "powershell",
    "bash", "sh", "zsh", "dash", "ash", "ksh",
    "apt", "apt-get", "dnf", "yum", "pacman", "brew", "conda",
)

# Longest-first so the alternation prefers ``netcat`` over ``nc`` at a boundary.
_NAMES_ALT = "|".join(
    re.escape(name)
    for name in sorted(_SENSITIVE_BINARIES, key=len, reverse=True)
)

_LINE_CONTINUATION_RE = re.compile(r"\\\n")
# Strip a backslash only when it escapes a COMMAND character (word char). In the
# shell ``\c`` / ``\i`` / ``\p`` collapse into the command name (``\curl`` runs
# curl, ``p\ip`` runs pip), so undoing them reconstructs the real binary. A
# backslash before punctuation is deliberately left intact: ``\.`` inside a
# quoted regex (``grep 'ngrok\.io'``) is literal data, and stripping it would
# forge a denylist domain / IP out of a legitimate command and trip a hard deny.
# Preserving it is what keeps normalization zero-false-positive on deny.
_BACKSLASH_ESCAPE_RE = re.compile(r"\\([A-Za-z0-9_])")
# ${IFS}, ${IFS%??}, ${IFS:0:1}, $IFS — but NOT ${IFSX}/$IFSX (a different var).
_IFS_RE = re.compile(r"\$\{IFS(?![A-Za-z0-9_])[^}]*\}|\$IFS\b")
_EMPTY_QUOTES_RE = re.compile(r"''|\"\"")
_INTRAWORD_QUOTE_RE = re.compile(r"(?<=\w)['\"](?=\w)")
_PATH_BASENAME_RE = re.compile(
    r"(^|[\s;&|(`])"                 # 1: left boundary (re-emitted)
    r"['\"]?"                        # optional opening quote
    r"(?:[^\s;&|()`'\"<>]*/)?"       # optional absolute/relative path prefix
    r"(" + _NAMES_ALT + r")"         # 2: known sensitive binary basename
    r"['\"]?"                        # optional closing quote
    r"(?=$|[\s;&|)`<>])"             # right boundary
)


def normalize_command(command: str) -> str:
    """Canonicalize a shell command for detection matching only.

    Undoes backslash / ``${IFS}`` / intra-word-quote obfuscation and reduces a
    path- or quote-wrapped known sensitive binary to its basename. The result is
    for pattern matching and is never executed. Returns the input unchanged on
    any error (fail-safe).

    Args:
        command: The raw shell command as Claude Code would run it.

    Returns:
        The canonicalized command, or the untouched input if nothing needed
        rewriting or an exception occurred.
    """
    try:
        # Fast path: with none of these characters present no rewrite applies.
        if not any(ch in command for ch in ("\\", "$", "'", '"', "/")):
            return command
        s = _LINE_CONTINUATION_RE.sub("", command)
        s = _BACKSLASH_ESCAPE_RE.sub(r"\1", s)
        s = _IFS_RE.sub(" ", s)
        s = _EMPTY_QUOTES_RE.sub("", s)
        s = _INTRAWORD_QUOTE_RE.sub("", s)
        s = _PATH_BASENAME_RE.sub(r"\1\2", s)
        return s
    except Exception:
        return command
