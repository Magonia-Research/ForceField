#!/usr/bin/env python3
"""Quote- and position-aware shell scanning, for anchoring detection patterns.

Guards matched their patterns against raw command text, which carries no notion
of where a token sits. To an unanchored regex a hostname in a ``#`` comment, in
a grep pattern, in a local filename, in prose being appended to a file, and in
an actual ``curl`` destination are the same string. That is how the ``deny``
tier -- the one rung contracted to be zero-false-positive, and the only one that
reaches a user running with permissions skipped -- came to deny five things that
were not network destinations at all.

This module supplies the missing structure: where the quotes are, where one
command ends and the next begins, and which hosts a segment actually addresses.

It is NOT a shell parser and must never be used to decide what will execute --
only whether a match sits in a position that means what the pattern assumed.
Every function degrades toward the caller's previous behaviour rather than
toward silence: this exists to remove false positives from ``deny``, and a bug
here must not become a false negative.

``supply_chain_guard._shell_segments`` is deliberately quote-blind, which is
safe for clearing allowlist entries and unsafe for anchoring. This is its
quote-aware counterpart; do not merge them.

Stdlib-only, Python 3.9+. Fail-safe throughout: any exception falls back to
treating the whole command as one unquoted segment.
"""

from __future__ import annotations

import re
import shlex

# Commands that can open a network connection to a host named on their own
# command line. Only these get bare (schemeless) tokens read as destinations;
# for everything else a destination has to look like a URL.
NETWORK_COMMANDS = frozenset([
    "curl", "wget", "aria2c", "fetch", "httpie", "http", "https",
    "nc", "ncat", "netcat", "socat", "telnet",
    "ssh", "scp", "sftp", "rsync", "ftp", "lftp",
])

# Wrappers that precede the real command without changing its network role.
_TRANSPARENT_WRAPPERS = frozenset([
    "sudo", "doas", "env", "nohup", "time", "command", "exec", "builtin",
    "nice", "ionice", "stdbuf", "setsid", "timeout", "xargs",
])

# Flags on the network commands above that consume the NEXT token as a value.
# Anything not listed is treated as a boolean flag, so an unlisted value-taking
# flag can only cost a false positive when its value is itself a blocklisted
# hostname -- whereas defaulting the other way would silently drop destinations
# after every unfamiliar flag.
_VALUE_TAKING_FLAGS = frozenset([
    # curl
    "-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar",
    "-b", "--cookie", "-K", "--config", "-T", "--upload-file",
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form", "-H", "--header", "-A", "--user-agent", "-e", "--referer",
    "-u", "--user", "-x", "--proxy", "-w", "--write-out", "--resolve",
    "--connect-to", "-m", "--max-time", "--retry", "--url", "--cacert",
    # wget
    "-O", "--output-document", "--output-file", "-P", "--directory-prefix",
    "--post-data", "--post-file", "-U", "--referer",
    # ssh / scp / sftp / rsync
    "-i", "-p", "-l", "-F", "-E", "-J", "-W", "-S", "-L", "-R",
    "-c", "-m", "-Q", "-O", "--rsh", "--exclude", "--include", "--files-from",
    # nc / socat
    "-s", "-X", "-q", "-g", "-G", "-w",
])

_SEGMENT_SEPARATORS = frozenset([";", "\n", "|", "&"])

# Container runtimes, and the subcommands that hand work to one. No Python here
# reads these: the live implementation is ``container_first.sh``'s
# ``CONTAINER_RUN`` regex, and this is a declared copy of it that
# ``tests/test_container_first.py`` asserts the shell still agrees with. A
# runtime added to the shell and not here — or the reverse — is caught there
# rather than discovered when a guard prescribes a container to a command that
# already uses one.
#
# Keep them: the parity assertion imports these names directly, so deleting them
# fails that suite rather than degrading it. ``container`` is Apple's CLI on
# macOS; without it the recommended runtime on this platform reads as a bare
# host invocation.
CONTAINER_RUNTIMES = frozenset([
    "podman", "docker", "nerdctl", "container",
    "apptainer", "singularity", "lima", "colima",
])
CONTAINER_SUBCOMMANDS = frozenset(["run", "exec", "build", "compose"])

# Scheme-bearing URL anywhere in a segment. The captured group is the authority
# host: userinfo is dropped, port and path are excluded. A URL is a destination
# regardless of which command mentions it, so that an indirection through a
# variable assignment is still anchored to a real host.
_URL_HOST_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]{0,15}://"
    r"(?:[^/\s'\"@]{0,256}@)?"
    r"([A-Za-z0-9._\-]{1,253})"
)

# An explicit Host: header names the host actually addressed even when the URL
# authority is a front. Without this, anchoring to the URL alone would drop
# domain fronting, which the unanchored pattern did catch.
_HOST_HEADER_RE = re.compile(
    r"(?i)\bhost\s*:\s*([A-Za-z0-9._\-]{1,253})"
)

_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,62}\.)+[A-Za-z]{2,63}$"
)

# ``<<WORD`` / ``<<-WORD`` / ``<<'WORD'``. A herestring (``<<<``) can never
# match: after ``<<`` the delimiter has to start with a word character, and the
# third ``<`` is not one.
_HEREDOC_RE = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# Commands that file a heredoc body away as text -- a commit message, a
# document, a copy on disk -- rather than executing it. Deliberately tiny and
# evidence-driven: every name added here is a body no guard will scan again, so
# it grows only when a real false positive shows it must.
TEXT_CONSUMERS = frozenset(["git", "cat", "tee"])


def _scan_unquoted(command):
    """Yield ``(index, char)`` for every character outside single/double quotes.

    A backslash escapes the next character except inside single quotes, matching
    the shell. Quote characters themselves are not yielded.
    """
    in_single = False
    in_double = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if in_single:
            if char == "'":
                in_single = False
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if in_double:
            if char == '"':
                in_double = False
            index += 1
            continue
        if char == "'":
            in_single = True
            index += 1
            continue
        if char == '"':
            in_double = True
            index += 1
            continue
        yield index, char
        index += 1


def strip_comments(command: str) -> str:
    """Remove ``#`` comments that begin outside quotes at a token boundary.

    A ``#`` inside a word is not a comment (``https://host/x#frag``), and one
    inside quotes is data (``grep '#define' src/``).
    """
    try:
        text = command
        while True:
            cut = None
            for index, char in _scan_unquoted(text):
                if char != "#":
                    continue
                if index == 0 or text[index - 1] in " \t\n":
                    cut = index
                    break
            if cut is None:
                return text
            end = text.find("\n", cut)
            text = text[:cut] + (text[end:] if end != -1 else "")
    except Exception:  # noqa: BLE001 - never let scanning break a guard
        return command


# A shell invoked as a command, by any of its usual names. Matched on the
# basename so ``/bin/bash`` and ``bash`` are the same thing.
_SHELL_NAME_RE = re.compile(r"^(?:ba|z|k|da|a)?sh$|^(?:fish|busybox)$")

# One command may carry several ``-c`` bodies; scan a bounded number so a
# pathological input cannot multiply every caller's regex work without limit.
_MAX_INTERPRETER_BODIES = 8


def interpreter_bodies(command: str):
    """Return the program text this command hands to a shell with ``-c``.

    ``bash -c "curl … | sh"`` is a fetch piped to a shell, but the detectors
    anchor a command to the start of a segment or a shell separator, and a
    double quote is neither -- so the single most copy-pasted spelling of the
    attack was not at "command position" and the hard deny never saw it.

    Widening the anchor to include quote characters is not the fix: it would
    make ``grep -rn 'curl' docs/ | python3 report.py`` a fetch-to-shell again,
    which is one of the false positives that anchoring existed to remove. A
    quoted span is a command when a shell is being handed it as a program, and
    at no other time -- so return exactly those spans and let the caller scan
    them as the command lines they are.

    A body is returned only when the SEGMENT ITSELF invokes a shell, so
    ``docker run img bash -c "curl … | sh"`` yields nothing here. That is a
    boundary, not an oversight: the payload runs inside a container the user
    explicitly asked for, which is the mitigation this whole plugin recommends,
    and denying it would block the safe way to do a risky thing.

    Note the carve-out is emergent rather than enforced -- ``_SHELL_NAME_RE``
    simply does not match ``docker``, exactly as it does not match any other
    non-shell leading word. ``tests/test_plugin.py`` pins the behaviour.
    """
    bodies = []
    try:
        for segment in split_segments(command):
            words = _command_words(segment)
            if not words:
                continue
            if not _SHELL_NAME_RE.match(words[0].rsplit("/", 1)[-1]):
                continue
            for index, token in enumerate(words[1:], start=1):
                if token == "-c" or (
                    token.startswith("-") and not token.startswith("--")
                    and token.endswith("c")
                ):
                    if index + 1 < len(words):
                        bodies.append(words[index + 1])
                    break
            if len(bodies) >= _MAX_INTERPRETER_BODIES:
                break
    except Exception:  # noqa: BLE001 - an extra scan target, never a gate
        return bodies
    return bodies[:_MAX_INTERPRETER_BODIES]


def _consumes_as_text(line: str, start: int, after: int) -> bool:
    """Whether the heredoc opened at ``start`` is filed away rather than run."""
    if "<<" in line[after:] or "|" in line[start:]:
        # A second heredoc on the line, or the body piped onward
        # (``cat <<EOF | bash``), and the simple reading no longer holds.
        return False
    before = split_segments(line[:start])
    return bool(before) and leading_command(before[-1]) in TEXT_CONSUMERS


def strip_heredocs(command: str) -> str:
    """Remove heredoc bodies that are filed as text rather than executed.

    A heredoc body is stdin. ``bash <<EOF`` executes it; ``git commit -F - <<EOF``
    and ``cat > NOTES.md <<EOF`` do not -- they file it away as a commit message
    or a document. Guards scanned the body as command text regardless, so a
    commit message quoting ``curl … | sh`` as the shape a detector must catch was
    itself hard-denied, and prose naming a package manager asked the user to
    containerize a sentence.

    Only a body consumed by a ``TEXT_CONSUMERS`` command, on a line that does not
    pipe it onward, is removed. An interpreter, an unrecognized command, a
    pipeline, an unterminated heredoc and any exception all keep their body, so a
    bug here costs a false positive and never hides an executed payload.
    """
    try:
        lines = command.split("\n")
        kept = []
        index = 0
        while index < len(lines):
            line = lines[index]
            kept.append(line)
            index += 1
            match = _HEREDOC_RE.search(line)
            if not match:
                continue
            delimiter = match.group(2)
            end = index
            while end < len(lines) and lines[end].strip() != delimiter:
                end += 1
            if end >= len(lines):
                continue  # unterminated: scan the body exactly as before
            if _consumes_as_text(line, match.start(), match.end()):
                kept.append(lines[end])
                index = end + 1
        return "\n".join(kept)
    except Exception:  # noqa: BLE001 - fail toward the caller's prior behaviour
        return command


def split_segments(command: str):
    """Split on unquoted ``;`` ``|`` ``&`` and newlines. Comments are removed.

    Empty pieces are dropped, so ``&&`` and ``||`` need no special case. A
    redirection like ``2>&1`` splits harmlessly: the parts carry no host and no
    command word.
    """
    try:
        text = strip_comments(command)
        parts = []
        start = 0
        for index, char in _scan_unquoted(text):
            if char in _SEGMENT_SEPARATORS:
                parts.append(text[start:index])
                start = index + 1
        parts.append(text[start:])
        segments = [part.strip() for part in parts]
        return [segment for segment in segments if segment] or [command]
    except Exception:  # noqa: BLE001
        return [command]


def tokenize(segment: str):
    """Split a segment into shell words, dropping the quotes around them."""
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        # Unbalanced quotes: fall back rather than losing the segment entirely.
        return segment.split()
    except Exception:  # noqa: BLE001
        return segment.split()


def _command_words(segment: str):
    """Tokens of a segment from its command word on, or ``[]``.

    Leading ``VAR=value`` assignments and transparent wrappers are dropped, so
    ``sudo env FOO=1 curl ...`` starts at ``curl``.
    """
    tokens = tokenize(segment)
    for index, token in enumerate(tokens):
        if "=" in token and not token.startswith("=") and "/" not in token.split("=")[0]:
            continue
        if token.rsplit("/", 1)[-1] in _TRANSPARENT_WRAPPERS:
            continue
        return tokens[index:]
    return []


def leading_command(segment: str) -> str:
    """Return the basename of the command a segment invokes, or ``""``."""
    try:
        words = _command_words(segment)
        return words[0].rsplit("/", 1)[-1] if words else ""
    except Exception:  # noqa: BLE001
        return ""


def _bare_host_candidates(segment: str):
    """Hosts named without a scheme by a network command in this segment."""
    tokens = tokenize(segment)
    hosts = []
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            skip_next = token in _VALUE_TAKING_FLAGS
            continue
        # user@host, host:port and host:path (scp/rsync) all name a host.
        candidate = token.rsplit("@", 1)[-1].split(":", 1)[0].split("/", 1)[0]
        if _HOSTNAME_RE.match(candidate):
            hosts.append(candidate.lower())
    return hosts


def destination_hosts(command: str):
    """Return the set of hosts this command actually addresses over the network.

    A host qualifies by being the authority of a URL, the value of a ``Host:``
    header, or a schemeless argument to a network-capable command. A hostname
    appearing only as search text, a filename, a comment or prose is not a
    destination and is not returned.
    """
    hosts = set()
    try:
        for segment in split_segments(command):
            for match in _URL_HOST_RE.finditer(segment):
                hosts.add(match.group(1).lower().rstrip("."))
            for match in _HOST_HEADER_RE.finditer(segment):
                hosts.add(match.group(1).lower().rstrip("."))
            if leading_command(segment) in NETWORK_COMMANDS:
                hosts.update(_bare_host_candidates(segment))
    except Exception:  # noqa: BLE001
        return hosts
    return hosts


def addresses_domain(command: str, domain: str) -> bool:
    """True if ``domain`` (or a subdomain of it) is an actual destination."""
    domain = domain.lower().strip(".")
    for host in destination_hosts(command):
        if host == domain or host.endswith("." + domain):
            return True
    return False


def in_redirect_or_exec_position(command: str, needle: str) -> bool:
    """True if ``needle`` appears where a redirect or ``exec`` target would.

    ``/dev/tcp/`` is a reverse-shell primitive only when something is redirected
    into or out of it; the same text in prose or a doc edit is inert.
    """
    try:
        text = strip_comments(command)
        for match in re.finditer(re.escape(needle), text):
            prefix = text[:match.start()].rstrip()
            if prefix.endswith((">", "<", "&")):
                return True
            if re.search(r"(?:^|[\s;&|])exec\b[^\n;|&]*$", prefix):
                return True
        return False
    except Exception:  # noqa: BLE001 - fail toward the caller's prior behaviour
        return True
