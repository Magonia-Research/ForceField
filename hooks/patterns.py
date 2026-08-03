#!/usr/bin/env python3
"""Shared constants for ForceField hooks.

Small values that were duplicated across every guard. Imported the same way as
the other shared hook modules (``hook_logging``, ``allowlist``) — after each
hook does ``sys.path.insert(0, str(Path(__file__).parent))``. Stdlib-only, no
side effects on import.
"""

from __future__ import annotations

import re

try:
    from normalize import assemble_shell_words, assemble_shell_words_spans
except ImportError:  # pragma: no cover - normalize is always beside this module
    def assemble_shell_words(text: str) -> str:
        """Fallback: no shell assembly available, so nothing to assemble."""
        return text

    def assemble_shell_words_spans(text: str) -> tuple[str, list]:
        """Fallback: no shell assembly available, so no source mapping."""
        return (text, [])

# Upper bound on a hook's stdin read — a guard against a pathologically large
# tool-input payload exhausting memory. 1 MiB comfortably covers real commands.
MAX_STDIN_BYTES = 1_048_576

# Upper bound on the command text a Bash guard will actually run its regexes over.
#
# This is a security boundary, not a latency preference. A hook that overruns its
# 5s timeout is killed with its verdict undelivered and Claude Code fails open, so
# a command large enough to outlast the budget is a *bypass*: measured, a correctly
# computed hard deny never reached stdout. MAX_STDIN_BYTES is 1 MiB — two orders of
# magnitude more text than 5s of scanning covers.
#
# Cost per byte is shape-dependent, so this is sized on the measured worst case
# rather than the average. `supply_chain_guard`'s `fetch_then_exec` dominates on
# repeated `curl … -o … ;` text at ~0.1 s/KiB (~100x a benign command), giving
# ~0.8s at this cap — inside budget with room for interpreter start and logging.
# The cost is in the *failure* path, where the engine exhausts every alternative,
# so lazy quantifiers do not help; bounding the input does.
#
# Anything longer is scanned up to the cap and then prompted rather than allowed,
# so truncation can never turn into a silent pass. See `security_dispatcher`.
MAX_COMMAND_SCAN_BYTES = 8_192

# Hook decision precedence: deny beats ask beats warn beats allow. Used to pick
# the highest-severity result when several guards weigh in on one tool call.
# ``warn`` is listed because a warn-clamped guard returns a bare
# ``{"systemMessage": ...}`` with no ``hookSpecificOutput``; scoring that as the
# ``allow`` default silently dropped the warning whenever another guard spoke.
DECISION_PRECEDENCE = {"deny": 4, "ask": 3, "warn": 2, "allow": 1}

# Upper bound on the text a content scanner hands to its detectors. Declared
# here rather than three times over (``injection_defense``, ``mcp_guard``,
# ``agent_output_guard``) so the three cannot drift apart.
MAX_SCAN_BYTES = 204_800


def decode_numeric_array(items: list) -> str | None:
    """Reconstruct text from a list of character codes, or None.

    A secret can be smuggled as an array of integer char/byte codes
    (``[65, 75, 73, 65, ...]``) that never appears as a string value. When every
    element is an int in the Unicode range, decode it so the credential scanners
    can see the reconstructed text. Non-numeric or out-of-range lists return
    None; booleans (an int subclass) disqualify the list.
    """
    if not items:
        return None
    chars = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, int):
            return None
        if item < 0 or item > 0x10FFFF:
            return None
        chars.append(chr(item))
    return "".join(chars)


def extract_string_values(obj) -> list[str]:
    """Collect every string value in a JSON-like object, depth-independent.

    Traversal is iterative with an explicit stack so a value hidden under deep
    nesting is still reached: a fixed recursion cap was an evasion channel, and
    the total work is already bounded by the size-capped input. Children are
    pushed in reverse so they pop in document order, which is what the
    first-match-wins scanners downstream report on. Integer arrays are
    additionally reconstructed as text (see ``decode_numeric_array``) to catch
    char-code-encoded secrets.
    """
    values: list[str] = []
    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            values.append(current)
        elif isinstance(current, dict):
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            decoded = decode_numeric_array(current)
            if decoded is not None:
                values.append(decoded)
            stack.extend(reversed(current))
    return values


# Credential shapes shared by every guard that inspects text for secrets, and by
# ``hook_logging`` to scrub them back out of the records it writes. This lives
# here rather than in ``credential_guard`` because ``hook_logging`` must import
# it and every guard imports ``hook_logging`` — the reverse edge would cycle.
# ``credential_guard`` re-exports it, so its six importers are unaffected.
CREDENTIAL_PATTERNS = {
    "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "github_oauth_token": re.compile(r"gho_[a-zA-Z0-9]{36}"),
    "github_server_token": re.compile(r"ghs_[a-zA-Z0-9]{36}"),
    "github_fine_grained": re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"),
    "gitlab_token": re.compile(r"glpat-[a-zA-Z0-9_-]{20}"),
    "npm_token": re.compile(r"npm_[a-zA-Z0-9]{36}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_sts_key": re.compile(r"ASIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[a-zA-Z0-9/+=]{40}"
    ),
    "private_key_header": re.compile(
        r"-----BEGIN\s+(?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)\s+)?"
        r"PRIVATE\s+KEY-----"
    ),
    # The lookbehind and the bounded runs are load-bearing. ``eyJ`` repeated is
    # its own prefix, so an unanchored form starts a match every 3 bytes and each
    # start consumes to end of input and backtracks — quadratic. Refusing a start
    # that is preceded by a token character leaves exactly one viable start on
    # such input, which is also what a real JWT looks like. Same repair shape as
    # ``supply_chain_guard.fetch_var_exec``.
    "jwt_token": re.compile(
        r"(?<![a-zA-Z0-9_-])eyJ[a-zA-Z0-9_-]{10,4096}\.eyJ[a-zA-Z0-9_-]{10,4096}\."
    ),
    "generic_secret": re.compile(
        r"(?i)(api_key|api_secret|secret_key|access_token|auth_token)"
        r"\s*[=:]\s*['\"]?[a-zA-Z0-9_/+=.-]{16,}"
    ),
    "password_assignment": re.compile(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
    "slack_token": re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    "stripe_key": re.compile(r"(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}"),
}

# A password embedded in a URL's userinfo — ``scheme://user:secret@host``. No
# pattern above matches it: the value carries no keyword beside it and no vendor
# prefix, yet a WebFetch or `git clone` URL is exactly where one turns up. The
# ``secret`` group is what gets masked, so the scheme, username and host survive
# — those are the fields an investigator actually needs.
#
# The lookbehind replaced a bare ``\b``, and the scheme run is bounded. ``.`` is
# not a word character, so on input like ``a.a.a.…`` every ``a`` began a word and
# started a match that scanned to end of input before failing on ``://`` —
# quadratic, and reachable: this runs on every log record, so 56 KB of padding in
# a command blew the 5s hook timeout and the *already-decided* deny was killed
# before it reached stdout. Excluding a start preceded by a scheme character
# leaves one viable start on that input.
# The secret run allows ``@`` and is greedy, so it reaches the LAST ``@`` before
# the authority ends rather than the first. It used to exclude ``@``, which meant
# a password containing one was only half masked:
# ``https://user:S3cr3tP@ssw0rd123@host/p`` rendered as
# ``https://user:[REDACTED:url_userinfo]@ssw0rd123@host/p`` -- 9 of 17 characters
# in clear, with a ``[REDACTED:…]`` label immediately before them telling any
# reader what the adjacent string is, and ``forcefield.redacted_fields``
# asserting the field was masked. ``@`` in a password is ordinary.
#
# What bounds the run is the end of the *authority*: ``/``, whitespace, and —
# added after a measured over-mask — ``?``. With only ``/`` and whitespace
# excluded, a URL carrying userinfo, no path and an ``@`` in a query parameter
# had no bound before the next ``@``, so the greedy run swallowed the host:
# ``https://u:p@host.com?cc=a@b.com&bcc=c@d.com`` rendered as
# ``https://u:[REDACTED:url_userinfo]@d.com`` -- the destination replaced by
# something that reads exactly like a host, on a record whose whole purpose is
# to say where the data was going. A query string cannot be part of userinfo in
# any RFC 3986 reading, so excluding ``?`` costs nothing and puts the host back.
# ``#`` is deliberately NOT excluded even though it ends an authority too: a
# password containing one is ordinary, the suite pins that it must still be
# masked whole, and a leaked credential is a worse outcome than a host lost on
# the rarer shape (a fragment that itself contains an ``@``).
URL_USERINFO_RE = re.compile(
    r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://"
    r"[^\s/:@]{1,256}:(?P<secret>[^\s/?]{1,256})@"
)

# The gap a program-anchored pattern may span between the command name and the
# flag that carries its password.
#
# Bounded, lazy, and — the part that matters — it cannot cross a command
# separator. A gap of `[^\n]{0,128}?` anchors on a program name and then matches
# a *different* program's flag 128 characters later:
# `brew install mysql && cc -p2 -O2 main.c` masked `cc`'s optimisation flag as a
# MySQL password, `apt-get install -y mysql-client && ./build -profile app`
# masked a build profile, and each one both destroyed the command line an
# investigator reads first and added a `forcefield.redacted_fields` entry
# claiming a credential had been masked.
#
# **A separator is a position, not a character.** Excluding `;&|()` as a
# character class was the first attempt and it under-masked far more than it
# over-masked: `&` is what joins a URL's query parameters, `|` turns up inside a
# quoted header value or a JSON body, and a parenthesis turns up anywhere. Five
# of seven realistic `curl -u user:pass` shapes stopped being masked, and the
# password then reached the 0600 file sink and journald -- a machine-global sink
# routinely shipped off-host -- in clear, with `forcefield.redacted_fields`
# EMPTY, so the record positively asserted that nothing had been masked. That is
# the wrong direction to fail in: an over-masked log field costs a field, an
# under-masked one costs a credential.
#
# So the gap refuses the *shapes a separator takes* instead. A `;`, `&` or `|`
# with whitespace on either side, or doubled (`&&`, `||`), is a separator in
# every real command line; `$(` opens a substitution and a backtick is never
# part of a URL or a header value. `?page=1&limit=50`, `'X-Filter: a|b'` and
# `{"q":"a&b"}` carry none of those shapes and are reached again. A pipe written
# with no space on either side (`a|b`) is reachable, which is the deliberate
# over-mask side of the trade.
_SEP_SHAPE = r"(?![;&|]\s|\s[;&|]|[;&|]{2}|\$\()"
_SEG = r"(?:" + _SEP_SHAPE + r"[^\n`])" + r"{0,128}?"

# A published container port, in every spelling `docker run -p` accepts:
# `3306:3306`, `127.0.0.1:3306:3306`, `[::1]:3306:3306`, `8000-8010:8000-8010`,
# and any of those with `/tcp`, `/udp` or `/sctp`. Used as a negative lookahead
# after `-p`, because `mysql` reaches a `-p` most often as the *name or image* of
# a container rather than as the running program, and there is nothing in the
# word `mysql` to tell those apart -- only the value can.
_PORT_MAP = (
    r"(?!"
    r"(?:\d{1,3}(?:\.\d{1,3}){3}:|\[[0-9A-Fa-f:]{2,45}\]:)?"
    r"\d{1,5}(?:-\d{1,5})?:\d{1,5}(?:-\d{1,5})?"
    r"(?:/(?:tcp|udp|sctp))?"
    r"(?![^\s'\"])"
    r")"
)

# A value that is visibly *not* a credential: the angle-bracket form
# documentation uses (`<token>`, `<YOUR_API_KEY>`), or one of the words that
# stand in for a secret in a README, a template or an `echo` that writes one.
# The header-shaped patterns below are the ones that need it, because their
# anchor is a header name rather than a program, and a header name turns up in
# prose and in config templates far more often than `sshpass` does.
#
# Masking one of these is not free. `redact_secrets` is a decision input at
# `memo.py`, where a credential-bearing subject is refused, so
# `echo 'api-key: PLACEHOLDER' >> settings.yml` had `/forcefield:remember` tell
# the user to rotate a credential that does not exist -- and the record gained a
# `forcefield.redacted_fields` entry asserting a masking that masked nothing.
#
# **The vocabulary is CLOSED and every segment of the value must be in it.**
# The first form of this construct was a *prefix* rule --
# `your[_-]?[a-z0-9_-]{0,32}`, `my[_-]?[a-z0-9_-]{0,32}` and
# `[a-z0-9_-]{0,32}[_-]here` -- which asserted nothing about the value being a
# placeholder and therefore exempted every real token that happens to begin
# `my`/`your` or end `_here`, over exactly the length range real tokens occupy.
# Measured: nine values masked at `4f0ebe8` reached the 0600 file sink and
# journald in clear (`mycompany_prod_ab12cd34`, `mytoken-9f3a2b1c55d1`,
# `MyAppKey-77c1f0aa`, `your-tenant-key-4471`, `YOURORG-9f3a2b1c`,
# `my_service_account_key_1`, `mysecrettoken12345`, `session-key-here`,
# `prod_key_here`), with `forcefield.redacted_fields` empty. A word list keeps
# `your-api-key` a placeholder and puts `your-tenant-key-4471` back under the
# mask, because `tenant` and `4471` are not words a template uses for a secret.
_PLACEHOLDER_WORD = (
    r"(?:placeholder|changeme|username|password|passwd|redacted|secrets|secret"
    r"|example|replace|sample|tokens|token|insert|client|bearer|access|enter"
    r"|value|goes|here|keys|auth|pass|user|name|some|your|dummy|fake|test"
    r"|api|app|ids|our|the|key|id|my|me|todo|tbd|none|null|xxx|abc|foo|bar)"
)
# A `printf`/`echo -e` conversion specification is not a value either. Measured:
# `printf 'x-api-key: %s\n' "$API_KEY"` had `api_key_header` consume `%s\n` as
# the header's value, so `/forcefield:remember` refused a command whose entire
# point is that the secret comes from the environment.
#
# **The width field must not start with `0`.** That is printf's own rule -- a
# leading `0` IS the zero-pad flag, never a width digit -- and spelling it
# (`[1-9][0-9]{0,3}` rather than `[0-9]*`) is the only thing keeping this
# construct unambiguous. With `[0-9]*`, `0` was in BOTH `[-+ #0]{0,4}` and the
# width class, so `%0000d` had five parses and a run of eight had `5**8`; every
# one of them is explored because the enclosing `_NOT_A_SECRET` is a NEGATIVE
# lookahead whose trailing `['\"]?(?:\s|$)` then fails. Measured on
# `-H 'Authorization: Bearer ' + '%0000d' * 8 + "!'": 0.1369 s for one 77-byte
# header, 7.275 s at 8 KiB, 59.817 s at `MAX_REDACT_BYTES` -- against a 5 s
# `PreToolUse[Bash]` timeout, which discards the verdict it kills. Both
# repetitions are bounded for the same reason: an unbounded `*` inside a
# `{1,8}` inside a lookahead is a cost multiplier, not a convenience.
_FORMAT_SPECIFIER = (
    r"(?:%[-+ #0]{0,4}(?:[1-9][0-9]{0,3})?(?:\.[0-9]{1,4})?[a-zA-Z]"
    r"|\\[a-zA-Z0-9]{1,3}){1,8}"
)
_NOT_A_SECRET = (
    r"(?!(?:"
    r"<[^>\s]{0,64}>"
    r"|\.{3,}|\*{3,}|x{3,}|X{3,}|_{3,}"
    r"|" + _FORMAT_SPECIFIER +
    r"|" + _PLACEHOLDER_WORD + r"(?:[_-]?" + _PLACEHOLDER_WORD + r"){0,7}"
    r")['\"]?(?:\s|$))"
)

# Shapes worth masking in a log record but deliberately NOT added to
# ``CREDENTIAL_PATTERNS``: that set also drives what ``credential_guard`` blocks
# and asks about, and widening it would trade the zero-false-positive-deny
# guarantee for log hygiene. Redaction is the safe place to be liberal — a
# false positive here costs one over-masked log field and nothing else.
_REDACTION_ONLY_PATTERNS = {
    # The value run is "anything that is not whitespace or a quote", not a
    # base64url class. Measured: `Authorization: Bearer S3cr3tP@ssw0rd123`
    # matched only `S3cr3tP` under `[A-Za-z0-9._~+/=-]`, which is 7 characters,
    # which is under the old floor of 8 -- so the whole header went into the log
    # verbatim. The anchor is the literal `authorization: bearer`, so there is
    # little left for a wider value class to over-match: whatever follows that
    # header IS the credential, at any length.
    #
    # Two exclusions carry through every value group added below.
    #
    # `(?!\$)` keeps the documented SAFE form out --
    # `Authorization: Bearer $ANTHROPIC_API_KEY` -- where the secret is not in
    # the command at all, and masking it would destroy the one thing the record
    # should show: which variable was used.
    #
    # `\x00` is `normalize._UNKNOWN_EXPANSION`, the byte the shell assembler
    # substitutes for an expansion it cannot resolve, chosen precisely because
    # "it appears in no credential character class". A wide value run that
    # includes it breaks that invariant: `Bearer $UNSET" https://x` assembles to
    # `Bearer \x00 https://x`, and a class that accepts NUL matches the sentinel
    # and reports a redaction over nothing.
    #
    # A credential genuinely split across quoted fragments is still caught,
    # because `_redact_assembled` resolves the *known* assignment first and
    # these patterns then run over the assembled text, where the expansion is
    # gone rather than sentinelled.
    "bearer_token": re.compile(
        r"(?i)(?<![/\\])\bauthorization\s*:\s*bearer\s+"
        r"(?P<secret>(?!\$)" + _NOT_A_SECRET + r"[^\s'\"\x00]{1,4096})"
    ),
    "basic_auth_header": re.compile(
        r"(?i)(?<![/\\])\bauthorization\s*:\s*basic\s+"
        r"(?P<secret>(?!\$)" + _NOT_A_SECRET + r"[^\s'\"\x00]{1,4096})"
    ),
    # `curl -u user:pass`, `curl --user`, `curl -U` / `--proxy-user`, and
    # `smbclient -U user%pass`. None of these carry a keyword beside the value
    # and none is a URL, so no pattern above could see them; measured leaking
    # verbatim into the macOS unified log and into a BusyBox
    # /var/log/messages at mode 0644.
    #
    # **The program is the anchor, not the flag**, and that is the whole
    # discriminator. `-u` means "user:password" to `curl` and `smbclient` and
    # something else entirely to everyone else, so a flag-anchored form is not a
    # credential pattern, it is a `-u` pattern -- measured firing on
    # `rsync -u me@server:/data/` (`-u` is `--update`, the `:` is a remote spec),
    # `pip install --user git+https://…` (the `:` is a URL scheme) and
    # `docker run -u 1000:1000` / `docker exec -u root:root` /
    # `podman run -u nobody:nogroup` (the `:` is uid:gid). That is not a free
    # over-mask: `redact_secrets` is a decision input at `memo.py`, where a
    # credential-bearing subject is refused, so `/forcefield:remember` told the
    # user to rotate a credential that did not exist; and `rsync -u host:/path`
    # raises a real `exfil_guard` `remote_copy` ask whose record then lost its
    # destination -- the most useful field on an exfil finding.
    #
    # `_SEG` rather than `[^\n]` for the gap, so the anchor cannot reach across
    # a command separator into an unrelated program's flags.
    "cli_user_password": re.compile(
        r"(?i:\b(?:curl|smbclient|rclone|svn|svnadmin|lftp|httpie)\b)" + _SEG +
        r"(?<![\w-])(?:-u|-U|--user|--proxy-user)[= ]\s{0,8}['\"]?"
        r"[^\s:%'\"\x00]{1,64}[:%](?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # `mysql -pSECRET`: the password is glued to the flag, so there is no
    # separator to key on and `-p` on its own is `mkdir -p`. The command name is
    # therefore the anchor, with a bounded lazy gap for the other flags between
    # them. The gap is scoped case-insensitive and the flag is NOT, because a
    # case-insensitive `-p` would swallow `mysql -P3306`.
    #
    # `mysql -p` with no value (the interactive prompt form) does not match: the
    # value run requires at least one non-space character.
    #
    # Two bounds keep the anchor honest, both from measured false positives.
    # `_SEG` stops the gap crossing a command separator, which is what let
    # `brew install mysql && cc -p2 -O2 main.c` and
    # `apt-get install -y mysql-client && ./build -profile app` mask another
    # program's flag. `(?![:/])` after the name stops an *image tag* anchoring
    # it: in `docker run -d mysql:8 -p3306:3306` the word `mysql` is an argument
    # to `docker`, not a command, and the `-p` is a port map. Both cost the
    # forensic record its command line and add a `forcefield.redacted_fields`
    # entry asserting a credential was masked when none was there, which is a
    # false statement in a security record rather than a cosmetic one.
    #
    # `(?![:/])` only catches the image-tag spelling. `docker run --name mysql
    # -p127.0.0.1:3306:3306 -d mysql:8` puts the anchor on a *container name*,
    # where nothing distinguishes it from a command word, so the discriminator
    # has to be the value: `_PORT_MAP` refuses every spelling of a published
    # port. A password that is byte-for-byte a port publication is not a
    # credential this pattern can be asked to keep.
    "mysql_password_flag": re.compile(
        r"(?i:\b(?:mysql(?:dump|admin|show|check)?|mariadb)\b(?![:/]))" + _SEG +
        r"(?<![\w-])-p" + _PORT_MAP +
        r"(?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # `sshpass -p SECRET`. The one program whose entire purpose is to put a
    # password on a command line, and it was reaching journald in clear with an
    # EMPTY `forcefield.redacted_fields`.
    #
    # No `_SEG` here, and that is the point: sshpass's own options come *before*
    # the command it wraps, so a gap wide enough to hold arbitrary flags reaches
    # straight into that command's flags -- and `-p` on `ssh` is a PORT. With a
    # gap, `sshpass -f /run/pw ssh -p 2222 host` and `sshpass -e scp -P 2222 …`
    # both masked the port as a password: the safe forms of sshpass, where the
    # secret is in a file or the environment and there is no credential on the
    # line at all. The record lost the port and gained a `redacted_fields` entry
    # asserting a credential had been masked, which is a false statement in a
    # security record. Only sshpass's own verbosity flags may sit between the
    # program and its `-p`.
    "sshpass_password": re.compile(
        r"(?i:\bsshpass\b)(?:\s+-[vVh])*\s*"
        r"(?<![\w-])-p[= ]?\s{0,8}['\"]?(?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # `redis-cli -a SECRET` / `--pass SECRET`. `valkey-cli` is the fork and takes
    # the same flags.
    "redis_password_flag": re.compile(
        r"(?i:\b(?:redis-cli|valkey-cli)\b)" + _SEG +
        r"(?<![\w-])(?:-a|--pass)[= ]\s{0,8}['\"]?"
        r"(?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # `openssl … -passin pass:SECRET`. Only the `pass:` source is masked:
    # `env:VAR` and `file:/path` name where the secret lives rather than being
    # it, and masking those would destroy the one thing the record should show.
    "openssl_pass_source": re.compile(
        r"(?<![\w-])-(?i:passin|passout|passphrase)[= ]\s{0,8}['\"]?"
        r"pass:(?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # `docker login -p SECRET` / `--password SECRET`, and the same shape on every
    # other registry client. Anchored on the program AND on the `login`
    # subcommand, because `-p` is a port map to `docker run` and `--password`
    # bare is not otherwise distinguishable from prose. `password_bare` does not
    # reach these: it requires an `=` or `:` separator and this form is
    # space-separated.
    "registry_login_password": re.compile(
        r"(?i:\b(?:docker|podman|nerdctl|buildah|skopeo|helm|az|npm|oc|crane)\s+"
        r"(?:[a-z][a-z-]{0,15}\s+){0,2}login\b)" + _SEG +
        r"(?<![\w-])(?:-p|--password|--password-stdin=)[= ]\s{0,8}['\"]?"
        r"(?P<secret>(?!\$)[^\s'\"\x00]{1,256})"
    ),
    # An API key in a request header. `api_key`/`api-key` with an `=` or an
    # underscore is already `generic_secret`'s; this is the `Header: value`
    # form, which `generic_secret`'s `[a-zA-Z0-9_/+=.-]` value class also could
    # not carry.
    "api_key_header": re.compile(
        r"(?i)(?<![/\\])\b(?:x-api-key|x-auth-token|x-access-token|api-key|apikey)"
        r"\s*:\s*['\"]?"
        r"(?P<secret>(?!\$)" + _NOT_A_SECRET + r"[^\s'\"\x00]{1,512})"
    ),
    # Catches ``--password=x``, ``PGPASSWORD=x`` and ``MYSQL_PWD=x`` alike: the
    # bounded prefix run absorbs a vendor prefix that would defeat a ``\b``.
    "password_bare": re.compile(
        r"(?i)(?<![A-Za-z0-9])[A-Za-z_]{0,32}(?:password|passwd|pwd)"
        r"\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{6,256})"
    ),
    # A current key is ``AIza`` + 35, but the range is deliberately loose: an
    # over-masked log field costs nothing, a leaked one costs a key.
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{30,40}"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/(?P<secret>[A-Za-z0-9/+_-]{8,200})"
    ),
    # The header alone was masked before, leaving the key material in clear on
    # the following lines. The body run is lazy and bounded so it stays linear.
    "private_key_body": re.compile(
        r"(?s)(-----BEGIN[A-Z ]{0,32}PRIVATE KEY-----)"
        r"(?P<secret>.{0,16384}?)(-----END)"
    ),
    "client_secret_assignment": re.compile(
        r"(?i)\b(?:client_secret|refresh_token|session_token|private_token)"
        r"\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9_/+=~.-]{8,512})"
    ),
    # ``webfetch_guard`` detects six ``gh*`` prefixes via ``gh[posur]_``;
    # ``CREDENTIAL_PATTERNS`` masks three (ghp_/gho_/ghs_). The two
    # user-to-server and refresh shapes were therefore *detected* and then
    # written into ``command.line`` verbatim, with no entry in
    # ``forcefield.redacted_fields`` to say so. Redaction-only, deliberately:
    # ``CREDENTIAL_PATTERNS`` keys drive what ``credential_guard`` blocks and
    # are looked up BY NAME in four guards, so widening it would change
    # detection rather than masking.
    "github_scoped_token": re.compile(r"gh[ur]_[A-Za-z0-9]{36}"),
}

# URL userinfo first: it rewrites the whole credential in one pass, so a token
# that also matches a vendor pattern cannot fragment the URL before the userinfo
# rule sees it. The private-key body runs before the header pattern for the same
# reason — the header is its own left delimiter.
_REDACTION_PATTERNS = {"url_userinfo": URL_USERINFO_RE}
_REDACTION_PATTERNS.update(_REDACTION_ONLY_PATTERNS)
_REDACTION_PATTERNS.update(CREDENTIAL_PATTERNS)


def _secret_group_span(match: re.Match) -> tuple[int, int]:
    """Span of the match's ``secret`` group, or ``(-1, -1)`` if it has none."""
    try:
        return match.span("secret")
    except (IndexError, re.error):
        return (-1, -1)


def _mask(name: str, match: re.Match) -> str:
    """Replacement text for one credential match.

    A pattern carrying a ``secret`` group keeps its surrounding context and
    masks only that group; every other pattern is replaced whole, since its
    match *is* the secret.
    """
    start, end = _secret_group_span(match)
    marker = "[REDACTED:" + name + "]"
    if start < 0:
        return marker
    whole = match.group(0)
    offset = match.start()
    return whole[:start - offset] + marker + whole[end - offset:]


def _matches_any(text: str) -> bool:
    """True when any redaction pattern hits — the gate before the mapped pass."""
    for pattern in _REDACTION_PATTERNS.values():
        if pattern.search(text) is not None:
            return True
    return False


def _source_span(match: re.Match, spans: list) -> tuple[int, int] | None:
    """Map one match in the assembled text back onto its source characters."""
    start, end = _secret_group_span(match)
    if start < 0:
        start, end = match.span()
    if end <= start or end > len(spans):
        return None
    return (spans[start][0], spans[end - 1][1])


def _assembled_hits(assembled: str, spans: list) -> list:
    """Every ``(start, end, pattern_name)`` to mask, in source coordinates."""
    hits = []
    for name, pattern in _REDACTION_PATTERNS.items():
        for match in pattern.finditer(assembled):
            span = _source_span(match, spans)
            if span is not None:
                hits.append((span[0], span[1], name))
    return hits


def _merge_hits(hits: list) -> list:
    """Collapse overlapping source ranges so a mask is never applied twice."""
    merged: list = []
    for start, end, name in sorted(hits):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, name])
    return merged


def _redact_assembled(text: str) -> str:
    """Mask credentials that only exist once the shell assembles the text.

    ``"sk-ant-"'api03-AAAA...'`` is a live token the moment bash runs it, but no
    pattern above can see it: the fragments are separated in the source by quote
    characters the shell deletes. The patterns are left alone — widening them to
    tolerate interleaved quotes is what turns a linear credential regex into a
    backtracking one, and it still could not tell a backslash inside double
    quotes (literal, so not a credential) from one outside (an escape, so a
    credential). Instead the text is assembled the way bash would assemble it,
    the unchanged patterns run against that, and each match is mapped back onto
    the source characters that produced it so the mask lands on the original.

    Everything here is skipped unless assembly actually changed the text and a
    pattern actually matched the result, so the ordinary path pays one linear
    scan and nothing more. Measured per call against the pre-change code: text
    with nothing to assemble is unchanged at 0.00 ms; an ordinary quoted command
    at the 8 KiB Bash cap costs +1.1 ms, and the worst synthetic shape (a dollar
    sign every three bytes) +2.2 ms. At the 64 KiB ``MAX_REDACT_BYTES`` log cap
    those become +8.8 ms and +18.0 ms against a 5s hook budget. Both stages are
    linear — the assembler measures 2.0 per doubling, asserted in
    ``tests/test_credential_obfuscation.py`` because ``tests/test_redos.py``
    times compiled patterns and cannot see a function.

    Returns the input unchanged on any error. ``redact_secrets`` runs on every
    log record, so a raise here would cost a guard its audit trail.
    """
    try:
        assembled = assemble_shell_words(text)
        if assembled == text or not _matches_any(assembled):
            return text
        assembled, spans = assemble_shell_words_spans(text)
        if len(spans) != len(assembled):
            return text
        redacted = text
        hits = _merge_hits(_assembled_hits(assembled, spans))
        for start, end, name in reversed(hits):
            redacted = redacted[:start] + "[REDACTED:" + name + "]" + redacted[end:]
        return redacted
    except Exception:
        return text


def redact_secrets(text: str) -> tuple[str, bool]:
    """Replace credential values in ``text`` with ``[REDACTED:<pattern>]``.

    Returns the rewritten text and whether anything matched. Every pattern here
    is linear — no nested quantifiers — so this stays cheap enough to run on
    every log record. The shell-assembly stage runs first, so a credential split
    across quoted fragments is masked at its source characters before the plain
    patterns sweep whatever is left.
    """
    if not isinstance(text, str) or not text:
        return (text, False)
    redacted = _redact_assembled(text)
    for name, pattern in _REDACTION_PATTERNS.items():
        redacted = pattern.sub(lambda m, n=name: _mask(n, m), redacted)
    return (redacted, redacted != text)


# ---------------------------------------------------------------------------
# Encoded-blob heuristics, shared by the outbound guards
# ---------------------------------------------------------------------------
#
# ``agent_guard`` and ``mcp_guard`` carried byte-identical copies of the regex,
# and ``webfetch_guard`` re-inlined the predicate a third time. That is exactly
# the shape 78192ee already repaired one key higher in the same dict, where the
# hand-copied ``exfil_domain`` list had drifted to 7 domains against a canonical
# 18. fc2107c then had to make one bounded-quantifier edit in both files at once.
# Nothing here changes at runtime -- CPython's ``re`` cache already returned the
# same object for both copies -- so the cost being removed is purely the next
# edit that lands in one file.

# A URL whose query value is a long base64 run: the shape of data leaving in a
# parameter rather than in a body. Bounded quantifiers throughout (fc2107c).
ENCODED_URL_DATA = re.compile(
    r"https?://[^\s]{0,2048}?[?&][^=\s]{1,256}=[A-Za-z0-9+/]{40,4096}={0,2}"
)


def looks_encoded(blob: str) -> bool:
    """True when a blob mixes upper, lower and digit like base64 of binary data.

    Ordinary prose, hex digests (no uppercase) and SCREAMING_CASE constants (no
    lowercase/digit) all fail this. Callers pair it with their own length floor,
    and those floors are tuned per call site rather than shared — see the comment
    at each one for what it is protecting.
    """
    return (
        any(c.isupper() for c in blob)
        and any(c.islower() for c in blob)
        and any(c.isdigit() for c in blob)
    )
