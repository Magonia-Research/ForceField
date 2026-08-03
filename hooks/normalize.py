#!/usr/bin/env python3
"""Shared command normalizer for ForceField detection matching.

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
basename. That is close to, but not the same as, "it cannot synthesize a
hard-deny substring": deleting a character always joins what sat on either side
of it. Line continuations were the case where that mattered, because inside
single quotes the shell keeps a backslash-newline as literal data while the
normalizer removed it, joining two lines the shell would not have joined. The
rule the module actually holds to is narrower and is enforced per-transform: a
rewrite may only be applied where the shell would apply it too.

``assemble_shell_words`` is a second, separate pass that goes much further —
adjacent quoted fragments joined, ``$'...'`` decoded, assignments substituted —
because credential detection needs the word the shell actually builds. It is
deliberately NOT part of ``normalize_command``: what is safe for a high-entropy
vendor-prefixed token is not safe for a hostname, where a quote is the very thing
that separates a mention from a destination. Only ``patterns.redact_secrets``
calls it, so no guard's normalized text changes. See the comment above it.

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

# Upper bound on de-obfuscation passes (see normalize_command).
_MAX_NORMALIZE_PASSES = 4

def _strip_line_continuations(text: str) -> str:
    """Remove backslash-newline, except inside single quotes.

    The shell removes a backslash-newline outside quotes and inside double
    quotes, but inside single quotes it is literal data. Deleting it there joins
    two lines the shell keeps apart, which is enough to assemble a denylist
    hostname out of inert text and trip a hard deny -- and a hard deny is routed
    around both the allowlist and per-project suppression, so there is no appeal.
    """
    out = []
    in_single = False
    in_double = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if in_single:
            if char == "'":
                in_single = False
            out.append(char)
            index += 1
            continue
        if char == "'" and not in_double:
            in_single = True
            out.append(char)
            index += 1
            continue
        if char == '"':
            in_double = not in_double
            out.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            if text[index + 1] == "\n":
                index += 2
                continue
            out.append(char)
            out.append(text[index + 1])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)
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
# ANSI-C ($'...') and locale ($"...") quoting. The shell expands both to the
# bare word, so `$'curl'` runs curl — but the `$` kept the quote from being
# treated as an ordinary one here, and the token never reduced to `curl`.
# ``container_first.sh`` already strips this; the Python normalizer accepted a
# strictly weaker language than the bash one until now.
_DOLLAR_QUOTE_RE = re.compile(r"\$(?=['\"])")
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
        s = command
        # Iterated to a fixpoint (bounded). A single pass is not idempotent:
        # ``\\\c`` -> ``\\c`` -> ``\c``, because _BACKSLASH_ESCAPE_RE consumes
        # one backslash layer per pass. Detection ran on one pass, so a command
        # peeled to its real form only on the second was matched in its
        # half-obfuscated state. Four passes covers the measured worst case
        # (depth 3) with room to spare; the bound keeps this terminating no
        # matter what the rules do.
        for _ in range(_MAX_NORMALIZE_PASSES):
            previous = s
            s = _strip_line_continuations(s)
            s = _DOLLAR_QUOTE_RE.sub("", s)
            s = _BACKSLASH_ESCAPE_RE.sub(r"\1", s)
            s = _IFS_RE.sub(" ", s)
            s = _EMPTY_QUOTES_RE.sub("", s)
            s = _INTRAWORD_QUOTE_RE.sub("", s)
            s = _PATH_BASENAME_RE.sub(r"\1\2", s)
            if s == previous:
                break
        return s
    except Exception:
        return command


def detection_variants(command: str) -> tuple[str, ...]:
    """Return the raw command, its normalized form, and the words bash builds.

    The Bash guards that match against every form had this written out
    identically; it lives here because this module already owns the normalizer
    and depends on nothing else.

    The third variant closes a hard-deny bypass. ``normalize_command`` removes
    quotes only intra-word, so ``curl 'https://'evil.example'/x'`` -- three
    quoted fragments the shell concatenates into one destination -- reached the
    exfil guard with the hostname still split and was **allowed**. The same
    hostname written plainly denied. Assembling the command the way bash does
    puts the destination back together where the guard can see it. Variable
    concatenation (``https://${H}/x``) went the same way and is closed with it.

    The comment below this function used to say assembly could not be shown to
    the guards because it turns ``grep -rn 'evil.example' logs/`` into a hard
    deny. That was true when it was written and is not any more: the deny-tier
    patterns gained positional confirmers, so a hostname now has to be an actual
    destination rather than merely present. Re-measured against the benign
    corpus in ``tests/test_false_positives.py`` -- all 128 commands, every
    tunneling host crossed with every non-destination role -- adding this variant
    changes **zero** decisions while catching all three split forms. That
    measurement is the only reason it is safe, so re-run it before widening
    assembly further.

    Args:
        command: The raw shell command as Claude Code would run it.

    Returns:
        The distinct forms to match against, raw first, in a stable order.
    """
    variants = [command]
    normalized = normalize_command(command)
    if normalized not in variants:
        variants.append(normalized)
    assembled = assemble_shell_words(command)
    if assembled and assembled not in variants:
        variants.append(assembled)
    return tuple(variants)


# --- Shell word assembly ----------------------------------------------------
#
# ``normalize_command`` above is deliberately timid about quotes: it removes them
# only *intra-word* (``c'u'rl``), because to the exfil and supply-chain guards a
# quote once WAS the signal. ``grep -rn 'ngrok.io' logs/`` is a mention, not a
# destination, and back when the deny patterns matched on presence alone,
# stripping those quotes turned a benign grep into a hard deny.
#
# Positional confirmers replaced quoting as that signal, and they are the better
# test: they ask whether the host is being addressed rather than whether the user
# happened to quote it. ``normalize_command`` itself stays narrow -- it is the
# form guards quote back in a reason string, and it should stay recognisable as
# what the user typed -- but ``detection_variants`` now also shows the guards the
# assembled form, which is what closed the split-destination bypass. See its
# docstring for the measurement that made that safe.
#
# Credential detection has the same shape and less hazard still. The
# shell concatenates adjacent quoted strings into a single word, so
# ``"sk-ant-"'api03-AAAA...'`` transmits a live token that no pattern anchored on
# ``sk-ant-`` can see. And a credential pattern is a vendor prefix followed by a
# long high-entropy run -- a shape that removing quotes cannot conjure out of
# ordinary prose the way it can conjure a hostname.
#
# Hence a second, wider pass that lives here (this module owns shell semantics)
# but is exported separately and wired only into ``patterns.redact_secrets``.
# ``normalize_command`` does not call it, so no guard's normalized text changes.
#
# The rule is the same one the module already holds to, applied harder: a rewrite
# is made only where bash would make it. That cuts both ways, and the negative
# half is what keeps this honest -- measured against bash, three forms that look
# like credentials are not:
#
#   "sk\-ant\-api03-..."    inside double quotes bash keeps ``\-`` literal, so
#                           the token actually transmitted is malformed
#   "$PAAAA..."             the variable name is parsed greedily as ``PAAAA...``,
#                           not ``P`` followed by the run
#   "$'\x73k-ant-...'"      ANSI-C quoting is not performed inside double quotes
#
# Each of those must NOT match, and does not, because the pass is a state machine
# over real quoting rules rather than a wider regex. A regex cannot tell the
# inside of a double quote from the outside; that distinction is the whole
# difference between a live credential and a false positive here.

# Cheap gate: with none of these present, assembly cannot change anything.
_ASSEMBLY_TRIGGERS = ("'", '"', "\\", "$")

_UNQUOTED_SPECIAL_RE = re.compile(r"['\"\\$]")
_DOUBLE_SPECIAL_RE = re.compile(r"[\"\\$]")
_ANSI_SPECIAL_RE = re.compile(r"['\\]")
_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HEX_RUN_RE = re.compile(r"[0-9A-Fa-f]{1,8}")
_OCTAL_RUN_RE = re.compile(r"[0-7]{1,3}")

# A leading ``NAME=value`` at a command position. The value run is bounded and
# has no alternation, so this stays linear; it stops at whitespace, which means a
# quoted value containing a space is not resolved. No credential shape has a
# space in it, so that limit costs nothing here.
_ASSIGNMENT_RE = re.compile(
    r"(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]{0,63})=([^\s;&|()<>]{0,512})"
)

# Backslash keeps its literal self inside double quotes except before these.
_DOUBLE_ESCAPABLE = frozenset('$`"\\\n')

# ANSI-C ($'...') single-character escapes.
_ANSI_SIMPLE = {
    "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t", "v": "\v",
    "\\": "\\", "'": "'", '"': '"', "?": "?",
}

# Stand-in for an expansion whose value this module cannot know -- an unset
# variable, or one assigned outside the text being scanned. Emitting nothing
# would join whatever sat on either side and could manufacture a credential out
# of two inert halves; emitting a byte that appears in no credential character
# class keeps the halves apart. NUL cannot occur in a real command line, so it
# never collides with input.
_UNKNOWN_EXPANSION = "\x00"

_STATE_PLAIN, _STATE_SINGLE, _STATE_DOUBLE, _STATE_ANSI = 0, 1, 2, 3


def _ansi_escape(text: str, index: int) -> tuple[str, int]:
    """Decode the ``$'...'`` backslash escape at ``index``.

    Returns the decoded text and the index just past the escape. An escape bash
    does not recognize is returned verbatim, which is what bash does with it.
    """
    length = len(text)
    if index + 1 >= length:
        return ("\\", index + 1)
    char = text[index + 1]
    simple = _ANSI_SIMPLE.get(char)
    if simple is not None:
        return (simple, index + 2)
    if char in ("x", "u", "U"):
        limit = {"x": 2, "u": 4, "U": 8}[char]
        digits = _HEX_RUN_RE.match(text, index + 2)
        if digits is not None:
            body = digits.group(0)[:limit]
            try:
                return (chr(int(body, 16)), index + 2 + len(body))
            except (ValueError, OverflowError):
                return (text[index:index + 2], index + 2)
        return (text[index:index + 2], index + 2)
    digits = _OCTAL_RUN_RE.match(text, index + 1)
    if digits is not None:
        try:
            return (chr(int(digits.group(0), 8)), digits.end())
        except (ValueError, OverflowError):
            return (text[index:index + 2], index + 2)
    return (text[index:index + 2], index + 2)


def _expansion(
    text: str, index: int, variables: dict,
) -> tuple[int, str] | None:
    """Resolve the ``$`` expansion at ``index``, or None if it is not one.

    ``$(`` and ``$1`` and a bare ``$`` are not parameter expansions and return
    None, so the caller emits the ``$`` as the literal it is.
    """
    length = len(text)
    if index + 1 >= length:
        return None
    if text[index + 1] == "{":
        close = text.find("}", index + 2)
        if close < 0:
            return None
        name = text[index + 2:close]
        matched = _VAR_NAME_RE.match(name)
        if matched is not None and matched.end() == len(name):
            return (close + 1, variables.get(name, _UNKNOWN_EXPANSION))
        # ${VAR:-default} and friends: the value is not knowable from the text.
        return (close + 1, _UNKNOWN_EXPANSION)
    matched = _VAR_NAME_RE.match(text, index + 1)
    if matched is None:
        return None
    return (matched.end(), variables.get(matched.group(0), _UNKNOWN_EXPANSION))


def _collect_assignments(text: str) -> dict:
    """Map ``NAME`` to its assembled value for each ``NAME=value`` in ``text``.

    Scanned left to right so a later assignment wins and an earlier one is
    visible to the next, which is the order the shell would apply them. Skipped
    outright unless the text has both an expansion and an assignment in it —
    the scan is linear but it is not free, and it buys nothing without both.
    Both entry points share this so the two passes cannot disagree about what a
    variable held.
    """
    if "$" not in text or "=" not in text:
        return {}
    variables: dict = {}
    for match in _ASSIGNMENT_RE.finditer(text):
        value = match.group(2)
        if value:
            value = _assemble(value, variables, None)
        variables[match.group(1)] = value
    return variables


def _assemble(text: str, variables: dict, spans) -> str:
    """Walk ``text`` as bash would and return the word text it produces.

    When ``spans`` is a list it is filled with one ``(start, end)`` source range
    per emitted character, so a match found in the assembled text can be mapped
    back onto the characters that produced it.
    """
    out: list = []
    length = len(text)
    index = 0
    state = _STATE_PLAIN

    def emit(chunk: str, start: int, end: int, direct: bool) -> None:
        if not chunk:
            return
        out.append(chunk)
        if spans is None:
            return
        if direct:
            spans.extend((start + n, start + n + 1) for n in range(len(chunk)))
        else:
            spans.extend((start, end) for _ in chunk)

    while index < length:
        if state == _STATE_SINGLE:
            close = text.find("'", index)
            if close < 0:
                emit(text[index:], index, length, True)
                break
            emit(text[index:close], index, close, True)
            index, state = close + 1, _STATE_PLAIN
            continue

        if state == _STATE_ANSI:
            hit = _ANSI_SPECIAL_RE.search(text, index)
            if hit is None:
                emit(text[index:], index, length, True)
                break
            at = hit.start()
            emit(text[index:at], index, at, True)
            if text[at] == "'":
                index, state = at + 1, _STATE_PLAIN
                continue
            decoded, index = _ansi_escape(text, at)
            emit(decoded, at, index, False)
            continue

        if state == _STATE_DOUBLE:
            hit = _DOUBLE_SPECIAL_RE.search(text, index)
            if hit is None:
                emit(text[index:], index, length, True)
                break
            at = hit.start()
            emit(text[index:at], index, at, True)
            char = text[at]
            if char == '"':
                index, state = at + 1, _STATE_PLAIN
                continue
            if char == "\\":
                following = text[at + 1:at + 2]
                if following == "\n":
                    index = at + 2
                    continue
                if following and following in _DOUBLE_ESCAPABLE:
                    emit(following, at, at + 2, False)
                    index = at + 2
                    continue
                # Any other backslash is literal data inside double quotes.
                emit(text[at:at + 2], at, at + 2, True)
                index = at + 2
                continue
            expansion = _expansion(text, at, variables)
            if expansion is None:
                emit("$", at, at + 1, True)
                index = at + 1
                continue
            index, value = expansion
            emit(value, at, index, False)
            continue

        hit = _UNQUOTED_SPECIAL_RE.search(text, index)
        if hit is None:
            emit(text[index:], index, length, True)
            break
        at = hit.start()
        emit(text[index:at], index, at, True)
        char = text[at]
        if char == "'":
            index, state = at + 1, _STATE_SINGLE
            continue
        if char == '"':
            index, state = at + 1, _STATE_DOUBLE
            continue
        if char == "\\":
            following = text[at + 1:at + 2]
            if not following:
                emit("\\", at, at + 1, True)
                index = at + 1
                continue
            if following != "\n":
                emit(following, at, at + 2, False)
            index = at + 2
            continue
        following = text[at + 1:at + 2]
        if following == "'":
            index, state = at + 2, _STATE_ANSI
            continue
        if following == '"':
            index, state = at + 2, _STATE_DOUBLE
            continue
        expansion = _expansion(text, at, variables)
        if expansion is None:
            emit("$", at, at + 1, True)
            index = at + 1
            continue
        index, value = expansion
        emit(value, at, index, False)

    return "".join(out)


def assemble_shell_words(text: str) -> str:
    """Return ``text`` as bash would assemble its words, for detection only.

    Adjacent quoted fragments are joined, backslash escapes are applied where
    bash applies them, ``$'...'`` is decoded, and a variable assigned earlier in
    the same text is substituted. The result is never executed. Returns the input
    unchanged when nothing applies or on any error (fail-safe).
    """
    try:
        if not text:
            return text
        for trigger in _ASSEMBLY_TRIGGERS:
            if trigger in text:
                break
        else:
            return text
        variables = _collect_assignments(text)
        return _assemble(text, variables, None)
    except Exception:
        return text


def assemble_shell_words_spans(text: str) -> tuple[str, list]:
    """``assemble_shell_words`` plus a source range per assembled character.

    ``spans[i]`` is the ``(start, end)`` slice of ``text`` that produced
    assembled character ``i``, so a credential located in the assembled form can
    be masked out of the original. Returns ``(text, [])`` on any error, which the
    caller reads as "no mapping available, leave the text alone".
    """
    try:
        if not text:
            return (text, [])
        variables = _collect_assignments(text)
        spans: list = []
        return (_assemble(text, variables, spans), spans)
    except Exception:
        return (text, [])
