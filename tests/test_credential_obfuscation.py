#!/usr/bin/env python3
"""Credential detection against shell-level obfuscation.

`patterns.redact_secrets` masks credentials out of every log record and is what
`memo.remember` consults before writing a command to disk for the life of a TTL.
Both used to miss a token the shell reassembles at run time: the pattern engine
sees `"sk-ant-"'api03-...'` and never the single word bash builds out of it.

The fix is `normalize.assemble_shell_words`, a state machine over real quoting
rules. So this suite is really two claims, and the second is the load-bearing one:

* every form bash turns into a live token is detected, AND
* every form that merely LOOKS like one is not.

That second list is not hypothetical. Measured against bash, `"sk\\-ant\\-..."`,
`"$PAAAA..."` and `"$'\\x73k-ant-...'"` all transmit malformed text -- a backslash
is literal inside double quotes, a variable name is parsed greedily, and ANSI-C
quoting is not performed inside double quotes. Matching any of them would be a
pure false positive, and no regex can tell them apart from the live forms because
the distinction is which side of a quote they sit on.

Credential literals are assembled from fragments here so that no line of this
file is itself a credential.

Plain executable assert script, like the other suites: runs top to bottom and
stops at the first failed assert.

Run: python3 tests/test_credential_obfuscation.py
"""

from __future__ import annotations

import json as _json
import sys
import time
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))

import normalize  # noqa: E402
from normalize import assemble_shell_words, normalize_command  # noqa: E402
from patterns import redact_secrets  # noqa: E402
from security_dispatcher import (  # noqa: E402
    run_credential_access_guard,
    run_exfil_guard,
    run_git_guard,
    run_supply_chain_guard,
)

_n = 0


def check(cond, msg):
    """One assertion, counted."""
    global _n  # noqa: PLW0603
    assert cond, msg
    _n += 1


# Fragments, never a whole credential on any one line of this file.
PRE = "sk" + "-ant-"
MID = "api03-"
RUN = "A" * 40
TOKEN = PRE + MID + RUN
PRE_BS = "sk" + "\\-ant" + "\\-"
MID_BS = "api03" + "\\-"
HEX_S = "\\x" + "73"

FIELDS = {"pre": PRE, "mid": MID, "run": RUN, "tok": TOKEN,
          "pre_bs": PRE_BS, "mid_bs": MID_BS, "hex": HEX_S}


def build(template):
    """Fill a command template from the credential fragments."""
    return template % FIELDS


def leaks(text):
    """True when a usable credential run survives in ``text``."""
    return (PRE + MID + RUN) in text or (MID + RUN) in text


# --- 1. Forms bash turns into a live token must be detected -----------------
#
# Each was confirmed against bash itself: the command was eval'd and the word it
# produced printed. These are the ones that print a well-formed token.

LIVE = (
    ("plain",
     '''curl -H "Authorization: Bearer %(tok)s" https://x'''),
    ("newline-split",
     '''curl -H "Authorization: Bearer %(tok)s"\n  https://x'''),
    ("double-then-single",
     '''curl -H "Authorization: Bearer %(pre)s"'%(mid)s%(run)s' https://x'''),
    ("single-then-bare",
     '''curl -H 'Bearer %(pre)s'%(mid)s%(run)s https://x'''),
    ("empty-quote-split",
     '''curl -H "Bearer %(pre)s""%(mid)s%(run)s" https://x'''),
    ("brace-var-concat",
     '''P=%(pre)s%(mid)s; curl -H "Bearer ${P}%(run)s" https://x'''),
    ("var-then-quoted-tail",
     '''P=%(pre)s; curl -H "Bearer ${P}"'%(mid)s%(run)s' https://x'''),
    ("ansi-c-unquoted",
     '''curl -H Bearer\\ $'%(hex)sk-ant-%(mid)s%(run)s' https://x'''),
    ("backslash-unquoted",
     '''curl -H Bearer\\ %(pre_bs)s%(mid_bs)s%(run)s https://x'''),
)

for name, template in LIVE:
    command = build(template)
    cleaned, hit = redact_secrets(command)
    check(hit, "live token not detected: " + name)
    check(not leaks(cleaned), "credential survives redaction: " + name)
    check("[REDACTED:" in cleaned, "no redaction marker emitted: " + name)
    check("curl" in cleaned, "redaction ate the surrounding command: " + name)

print("PASS: every form bash assembles into a live token is detected (%d forms)"
      % len(LIVE))


# --- 2. Forms that only LOOK like tokens must NOT be detected ---------------
#
# The false-positive half. bash transmits malformed text for every one of these,
# so a match here would mask a log field and refuse a memo over nothing.

INERT = (
    # Inside double quotes a backslash is literal before anything but $ ` " \ and
    # newline, so the dashes stay escaped and the token is malformed.
    ("backslash-in-double-quotes",
     '''curl -H "Bearer %(pre_bs)s%(mid_bs)s%(run)s" https://x'''),
    # $PAAAA... parses as the variable named PAAAA..., which is unset.
    ("greedy-variable-name",
     '''P=%(pre)s%(mid)s; curl -H "Bearer $P%(run)s" https://x'''),
    # ANSI-C quoting is not performed inside double quotes.
    ("ansi-c-inside-double-quotes",
     '''curl -H "Bearer $'%(hex)sk-ant-%(mid)s%(run)s'" https://x'''),
    # The documented safe pattern. An unset expansion must not be resolved into
    # whatever sits beside it.
    ("env-var-indirection",
     '''curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://x'''),
    ("env-var-braced",
     '''curl -H "Authorization: Bearer ${ANTHROPIC_API_KEY}" https://x'''),
    # An unknown expansion must not be deleted, because deleting it would join
    # the halves on either side into a credential that never existed.
    ("unset-var-between-halves",
     '''curl -H "Bearer %(pre)s%(mid)s${NOPE}%(run)s" https://x'''),
    ("unset-var-with-operator",
     '''curl -H "Bearer %(pre)s%(mid)s${NOPE:-x}%(run)s" https://x'''),
    # Prose and paths that merely contain the fragments.
    ("prose-mention",
     '''echo 'rotate the %(pre)s key before shipping' >> NOTES.md'''),
    ("assignment-only-prefix",
     '''P=%(pre)s; echo "$P is only a prefix"'''),
)

for name, template in INERT:
    command = build(template)
    cleaned, hit = redact_secrets(command)
    check(not hit, "false positive on an inert form: " + name)
    check(cleaned == command, "inert form was rewritten: " + name)

print("PASS: no inert lookalike is masked (%d forms, incl. the backslash trap)"
      % len(INERT))


# --- 3. The assembler agrees with bash on the word it builds ----------------

ASSEMBLY = (
    ("adjacent quoted fragments join", '''"ab"'cd'efg''', "abcdefg"),
    ("empty quotes vanish", '''a""b''''''c''', "abc"),
    ("single quotes are literal", r"""'a\-b'""", r"a\-b"),
    ("backslash escapes outside quotes", r"a\-b\-c", "a-b-c"),
    ("backslash is literal inside double quotes", r'"a\-b"', r"a\-b"),
    ("backslash escapes a dollar inside double quotes", r'"a\$b"', "a$b"),
    ("line continuation is removed outside quotes", "a\\\nb", "ab"),
    ("line continuation is kept inside single quotes", "'a\\\nb'", "a\\\nb"),
    ("ansi-c hex is decoded", "$'" + HEX_S + "k'", "sk"),
    ("ansi-c tab is decoded", r"$'a\tb'", "a\tb"),
    ("ansi-c octal is decoded", r"$'\101'", "A"),
    ("dollar-quote is not ansi-c inside double quotes",
     '"$' + "'" + HEX_S + "'" + '"', "$'" + HEX_S + "'"),
    ("command substitution is left alone", "$(cat k)", "$(cat k)"),
    ("positional parameter is left alone", '"$1"', "$1"),
    ("known variable expands", "V=xy; echo ${V}z", "V=xy; echo xyz"),
    ("later assignment wins", "V=a; V=b; echo ${V}", "V=a; V=b; echo b"),
)

for label, source, expected in ASSEMBLY:
    check(assemble_shell_words(source) == expected,
          "assembly disagrees (%s): %r -> %r, expected %r"
          % (label, source, assemble_shell_words(source), expected))

# An unknown expansion becomes a placeholder rather than nothing, so it cannot
# join what sat on either side of it.
placeholder = assemble_shell_words('"a${NOPE}b"')
check(placeholder != "ab", "unknown expansion was deleted, joining its neighbours")
check(placeholder.startswith("a") and placeholder.endswith("b"),
      "unknown expansion did not keep its neighbours in place")
check(normalize._UNKNOWN_EXPANSION not in "".join(
    source for _, source, _ in ASSEMBLY),
    "the placeholder byte occurs in ordinary shell text, so it can collide")

print("PASS: the assembler reproduces bash word assembly (%d cases)"
      % (len(ASSEMBLY) + 3))


# --- 4. normalize_command is untouched, so no guard sees different text -----
#
# The whole reason assembly is a separate export. To the exfil and supply-chain
# guards a quote is a signal: 'ngrok.io' in a grep is a mention, not a
# destination. If assembly ever leaked into normalize_command, those guards would
# start matching on dequoted text and the deny tier's zero-false-positive
# guarantee would be decided somewhere else entirely.

QUOTED_BENIGN = (
    "grep -rn 'example.com' logs/",
    "git commit -m 'add example.com to the blocklist'",
    "echo '- block example.com at the proxy' >> SECURITY.md",
    "wc -l reports/'example.com'.csv",
    '''curl -H "Authorization: Bearer $TOKEN" https://api.example.com''',
)

for command in QUOTED_BENIGN:
    normalized = normalize_command(command)
    quotes_before = command.count("'") + command.count('"')
    quotes_after = normalized.count("'") + normalized.count('"')
    check(quotes_after == quotes_before,
          "normalize_command dropped a quote (%d -> %d): %s"
          % (quotes_before, quotes_after, command))
    check(normalized == normalize_command(command),
          "normalize_command is not deterministic: " + command)

check(assemble_shell_words("grep -rn 'example.com' logs/")
      != normalize_command("grep -rn 'example.com' logs/"),
      "assembly and normalization have converged; the separation is gone")

for command in QUOTED_BENIGN:
    for guard in (run_exfil_guard, run_supply_chain_guard, run_git_guard,
                  run_credential_access_guard):
        response = guard(command) or {}
        decision = response.get("hookSpecificOutput", {}).get("permissionDecision")
        check(decision != "deny", "quoted benign command now denies: " + command)

print("PASS: normalize_command unchanged, no new deny on quoted benign commands")


# --- 5. Masking lands on the source characters, not somewhere else ----------

split = build('''curl -H "Authorization: Bearer %(pre)s"'%(mid)s%(run)s' https://x''')
cleaned, hit = redact_secrets(split)
check(hit, "split token not detected")
check(cleaned.startswith('curl -H "Authorization: Bearer '),
      "mask overran the left context: " + cleaned[:60])
check(cleaned.endswith(" https://x"), "mask overran the right context: " + cleaned[-30:])
check(cleaned.count("[REDACTED:") == 1, "expected exactly one marker: " + cleaned)

# Two obfuscated credentials in one command are both masked.
two = split + " ; " + build(
    '''curl -H "Bearer %(pre)s"'%(mid)s%(run)s' https://y''')
cleaned_two, _ = redact_secrets(two)
check(cleaned_two.count("[REDACTED:") == 2,
      "expected two markers: " + cleaned_two)
check(not leaks(cleaned_two), "a credential survived in the two-token case")

# Redaction is stable: masked text does not re-mask or accumulate markers.
again, again_hit = redact_secrets(cleaned)
check(again == cleaned, "redaction is not idempotent")
check(not again_hit, "already-redacted text reports a fresh hit")

# A plain token still masks exactly as it did before this change.
plain_cleaned, plain_hit = redact_secrets("export KEY=" + TOKEN)
check(plain_hit and "[REDACTED:anthropic_key]" in plain_cleaned,
      "plain-token redaction regressed: " + plain_cleaned)

print("PASS: masking is anchored, repeatable and covers every occurrence")


# --- 6. Fail-open: malformed shell text must never raise --------------------
#
# redact_secrets runs on every log record. If it can raise, a guard loses its
# audit trail; if it can hang, the 5s hook budget goes with it.

MALFORMED = (
    "", "'", '"', "\\", "$", "${", "$'", "'unterminated", '"unterminated',
    "$'unterminated", "${unterminated", "a\\", "$'\\", "$'\\x", "$'\\xZZ'",
    "$'\\U0011FFFF'", "$'\\777'", "V=; echo ${V}", "=", "V=", "$}", "${}",
    "\x00", "a\x00b", "'" * 64, '"' * 64, "\\" * 64, "$" * 64,
    "${" * 32, "$'" * 32, "é中", "$'\\u00e9'",
)

for source in MALFORMED:
    try:
        assembled = assemble_shell_words(source)
        cleaned, _ = redact_secrets(source)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError("raised on malformed input %r: %r" % (source, exc))
    check(isinstance(assembled, str), "assembly returned a non-string: %r" % source)
    check(isinstance(cleaned, str), "redaction returned a non-string: %r" % source)

for value in (None, 12, [], {}, b"bytes"):
    cleaned, hit = redact_secrets(value)
    check(cleaned is value and hit is False,
          "non-string input was not passed through: %r" % (value,))

print("PASS: malformed and non-string input never raises (%d inputs)"
      % (len(MALFORMED) + 5))


# --- 7. Cost stays linear -- test_redos cannot see this ---------------------
#
# test_redos.py times compiled patterns. Assembly is a function, so its cost is
# invisible there, and it runs on every log record. A super-linear assembler
# would be the same class of bug: a hook that overruns its budget is killed and
# Claude Code fails open, which turns a latency defect into a guard bypass.

SHAPES = {
    "quote_storm": "''\"\"''\"\"",
    "dollar_storm": "$X$Y$Z${W}",
    "backslash_storm": "\\a\\b\\c\\d",
    "nested_quotes": "\"a'b\"'c\"d'",
    "unterminated": "'a\"b$c\\d",
    "assign_storm": "V=1 W=2 X=3 Y=4; ",
    "plain": "the quick brown fox jumps over the lazy dog. ",
}
MAX_RATIO = 2.6
MIN_SECONDS_TO_JUDGE = 0.02
MAX_ABSOLUTE_SECONDS = 0.75
BASE_BYTES = 32_768


def elapsed(text):
    """Seconds for one assembly pass over ``text``."""
    start = time.perf_counter()
    assemble_shell_words(text)
    return time.perf_counter() - start


for shape, unit in SHAPES.items():
    small = (unit * (BASE_BYTES // len(unit) + 1))[:BASE_BYTES]
    large = (unit * (2 * BASE_BYTES // len(unit) + 1))[:BASE_BYTES * 2]
    fast, slow = elapsed(small), elapsed(large)
    ratio = slow / fast if fast > 1e-9 else 1.0
    if slow < MIN_SECONDS_TO_JUDGE:
        ratio = min(ratio, 1.0)
    check(ratio <= MAX_RATIO,
          "assembly is super-linear on %r: ratio=%.2f/doubling (%.3fs)"
          % (shape, ratio, slow))
    check(slow <= MAX_ABSOLUTE_SECONDS,
          "assembly over budget on %r: %.3fs for %d bytes"
          % (shape, slow, BASE_BYTES * 2))

# The gate that keeps the ordinary path cheap: text with nothing to assemble is
# returned without a scan.
no_trigger = "the quick brown fox " * 512
check(assemble_shell_words(no_trigger) is no_trigger,
      "text with no quote, backslash or dollar was still scanned")

print("PASS: assembly stays linear under adversarial shapes (%d shapes)"
      % len(SHAPES))



# =============================================================================
# Every credential shape a DETECTOR matches is also masked by the REDACTOR
#
# The two sets are deliberately different -- CREDENTIAL_PATTERNS drives what
# credential_guard blocks and is looked up by name in four guards, so widening it
# changes detection -- but the containment must go one way. A shape a guard
# detects and the masker misses is a token that reaches the log verbatim while a
# record cheerfully reports that a credential was found.
#
# That was not hypothetical. webfetch_guard matched six gh* prefixes via
# `gh[posur]_`; patterns.py masked three. End to end, the guard raised
# credential_in_url and then wrote the token into command.line with no entry in
# forcefield.redacted_fields at all.
#
# This sweep is structural rather than another literal: it walks the compiled
# regexes reachable from hooks/, extracts each leading literal prefix (including
# the branches of a character class), synthesises a conforming value, and asserts
# the masker eats it. It is the check that would have caught the gap on the day
# it was introduced.
# =============================================================================

import re as _re  # noqa: E402

import mcp_guard as _mcp  # noqa: E402
import webfetch_guard as _wf  # noqa: E402
from patterns import CREDENTIAL_PATTERNS, redact_secrets  # noqa: E402

_PREFIX_RE = _re.compile(r"^([A-Za-z_-]{2,})(?:\[([A-Za-z0-9]+)\])?(_|-)")


def _prefixes(pattern_source):
    """Every literal token prefix an alternation-free head can produce.

    ``gh[posur]_`` yields six; ``ghp_`` yields one; a pattern whose head is not a
    literal run yields none and is skipped rather than guessed at.
    """
    match = _PREFIX_RE.match(pattern_source)
    if not match:
        return []
    head, klass, sep = match.group(1), match.group(2), match.group(3)
    if not klass:
        return [head + sep]
    return [head + char + sep for char in klass]


_DETECTORS = {}
for _name, _rx in CREDENTIAL_PATTERNS.items():
    _DETECTORS["patterns.CREDENTIAL_PATTERNS." + _name] = _rx
for _name, _rx in getattr(_mcp, "MCP_EXTRA_CREDENTIAL_PATTERNS", {}).items():
    _DETECTORS["mcp_guard.MCP_EXTRA_CREDENTIAL_PATTERNS." + _name] = _rx
for _name, _rx in getattr(_wf, "URL_PATTERNS", {}).items():
    _DETECTORS["webfetch_guard.URL_PATTERNS." + _name] = _rx

_swept = 0
for _label, _rx in sorted(_DETECTORS.items()):
    for _prefix in _prefixes(getattr(_rx, "pattern", "")):
        _value = _prefix + ("a" * 36)
        if not _rx.search(_value):
            continue                      # the synthesised value is not in scope
        _swept += 1
        _cleaned, _hit = redact_secrets("token=" + _value)
        check(_hit, "%s: %r is detected but redact_secrets reports no hit"
                    % (_label, _prefix))
        check(_value not in _cleaned,
              "%s: %r survives redact_secrets verbatim" % (_label, _prefix))

check(_swept >= 6, "the sweep synthesised something for at least the gh* family")

# The specific pair the sweep exists for, end to end through a log record.
import hook_logging as _hl  # noqa: E402

for _pfx in ("ghu_", "ghr_", "ghp_", "gho_", "ghs_"):
    _tok = _pfx + "A" * 36
    _rec = _hl.build_event("webfetch_guard", "ask",
                           pattern_matched="credential_in_url",
                           command="https://x.example/cb?token=" + _tok)
    check(_tok not in _json.dumps(_rec),
          "%s reaches command.line verbatim" % _pfx)
    check(_rec["Attributes"]["forcefield.redacted_fields"] == ["command.line"],
          "%s is masked but the record does not say so" % _pfx)

print("PASS: every detector prefix is masked by redact_secrets (%d shapes)" % _swept)


# --- 9. The flag- and header-shaped credentials, positive and negative ------
#
# Ten command shapes were measured reaching the macOS unified log, journald and
# a BusyBox `/var/log/messages` at mode 0644 in clear, because none of them
# carries a keyword beside the value and none is a URL. Each pattern added for
# them is anchored to its actual program and flag, so each needs its own
# negative.
#
# **A negative list is only worth what its entries cost to satisfy.** The first
# version of this block had 17 negatives and every one of them omitted the
# separator that makes the pattern fire, so it was green over four real false
# positives found afterwards by differential testing against `origin/main`:
# `rsync -u me@server:/data/`, `pip install --user git+https://…`,
# `docker run -d mysql:8 -p3306:3306` and `docker run -u 1000:1000`. Those four
# are now the *first* entries below, and they are the shape a new negative
# should be modelled on: a benign command that DOES carry the separator, the
# colon, the digits — everything except a credential.
#
# The price of a false positive here is not "one over-masked log field". It is
# that `redact_secrets` is a decision input at `memo.py`, so `/forcefield:remember`
# refuses the command with a security claim that is false; and that an exfil
# finding's record loses its destination while asserting
# `forcefield.redacted_fields: ["command.line"]`.

_PW = "S3cr3tP@ssw0" + "rd123"

_FLAG_POSITIVE = (
    ("cli_user_password", "curl -u deploybot:%s https://api.internal/x" % _PW),
    ("cli_user_password", "curl --user admin:%s https://api.internal/x" % _PW),
    ("cli_user_password", "curl -U proxyuser:%s -x proxy:3128 https://x" % _PW),
    ("cli_user_password", "curl --proxy-user pu:%s https://x" % _PW),
    ("cli_user_password", "smbclient //srv/share -U user%%%s" % _PW),
    ("mysql_password_flag", "mysql -h db -u root -p%s" % _PW),
    ("mysql_password_flag", "mysqldump --single-transaction -u r -p%s db" % _PW),
    ("mysql_password_flag", "mariadb -p%s -e 'select 1'" % _PW),
    ("mysql_password_flag",
     "mysql --defaults-file=/etc/my.cnf --protocol=tcp -h db.internal "
     "-P 3306 -u root -p%s" % _PW),
    ("api_key_header", "curl -H 'X-Api-Key: %s' https://x" % _PW),
    ("api_key_header", 'curl -H "X-Auth-Token: %s" https://x' % _PW),
    ("api_key_header", "curl -H 'X-Access-Token: %s' https://x" % _PW),
    # The gap was the value CLASS, not the length: `S3cr3tP@ssw0rd123` matched
    # only `S3cr3tP` under the old base64url run, which is 7 characters and so
    # under the old floor of 8.
    ("bearer_token", "curl -H 'Authorization: Bearer %s' https://x" % _PW),
    ("bearer_token", "curl -H 'Authorization: Bearer abcd' https://x"),
    ("basic_auth_header", "curl -H 'Authorization: Basic %s' https://x" % _PW),
    # Four ordinary coding-agent shapes measured reaching journald verbatim with
    # an EMPTY `forcefield.redacted_fields`, once the command also earned a deny
    # and the record crossed NATIVE_SINK_MIN_SEVERITY. Masking had been closed
    # shape by shape rather than as a class.
    ("sshpass_password", "sshpass -p %s ssh deploy@build-host" % _PW),
    ("redis_password_flag", "redis-cli -h cache.internal -a %s ping" % _PW),
    ("openssl_pass_source",
     "openssl rsa -in key.pem -passin pass:%s -out plain.pem" % _PW),
    ("registry_login_password",
     "docker login registry.example.com -u ci -p %s" % _PW),
    ("registry_login_password",
     "podman login -u ci --password %s registry.example.com" % _PW),
    ("registry_login_password",
     "helm registry login ghcr.io -u ci -p %s" % _PW),
)

for _want, _command in _FLAG_POSITIVE:
    _clean, _hit = redact_secrets(_command)
    check(_hit, "not masked at all: %s" % _command)
    check(_PW not in _clean, "the password survives masking: %s" % _command)
    check("[REDACTED:%s]" % _want in _clean,
          "masked by the wrong pattern (wanted %s): %s -> %s"
          % (_want, _command, _clean))
    check(_clean.split()[0] == _command.split()[0],
          "masking ate the command name: %s" % _command)

_FLAG_NEGATIVE = (
    # The four measured false positives. Every one of these carries the
    # separator, so a pattern anchored on the FLAG cannot tell them from a
    # credential — only one anchored on the PROGRAM can.
    "rsync -u me@server:/data/ ./backup",              # -u is --update
    "pip install --user git+https://github.com/psf/requests.git",  # a URL scheme
    "docker run -u 1000:1000 alpine id",               # uid:gid
    "docker run -d mysql:8 -p3306:3306",               # an image tag, a port map
    # The same four, in the other spellings that reach them.
    "docker exec -u root:root web sh",
    "podman run -u nobody:nogroup img",
    "docker run --name db -d mysql:8.0 -p3306:3306 -v /data:/var/lib/mysql",
    "kubectl run web --image=nginx -- sh -c 'curl -s http://a:8080/x'",
    # A command separator between the anchor and the flag: two programs, and the
    # second one's flags are not the first one's password.
    "brew install mysql && cc -p2 -O2 main.c",
    "apt-get install -y mysql-client && ./build -profile app",
    "mysqldump db | gzip > /tmp/d.gz && aws s3 cp /tmp/d.gz s3://b -p prod",
    "docker compose exec mysql mysql -uroot -e 'show databases'",
    # `docker run -p` is a port map; only `docker login -p` is a password.
    "docker run -p 8080:80 nginx",
    "podman run -p 127.0.0.1:5432:5432 postgres:16",
    # `-passin` naming where the secret lives rather than being it.
    "openssl rsa -in k.pem -passin env:KEY_PASSPHRASE -out plain.pem",
    "openssl rsa -in k.pem -passin file:/run/secrets/pw -out plain.pem",
    # `-a` and `-p` on programs that are not redis-cli or sshpass.
    "ls -a /etc && ps -p 1",
    "tar -cf out.tar -p ./src",
    # `-u` and `-U` with no separator in the following word.
    "sort -u /tmp/list.txt",
    "git push -u origin main",
    "pip install --user requests",
    "rsync -avu src/ dst/",
    "id -u",
    "useradd -u 1001 bob",
    "ls -U",
    "npm install --userconfig .npmrc",
    # `-p` that is not a mysql password.
    "mkdir -p /tmp/a/b/c",
    "tar -xzf a.tgz -C /tmp -p",
    "ssh -p 2222 host",
    # The interactive form: `-p` with no value must not match.
    "mysql -h db -u root -p",
    # `-P` is a port, and the flag half of the pattern is case-sensitive for it.
    "mysql -P3306 -h db.internal",
    # The documented safe forms. The secret is not in the command at all, and
    # masking the variable name would destroy the only useful thing in the
    # record.
    'curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://x',
    'curl -H "X-Api-Key: ${API_KEY}" https://x',
    'curl -u "deploy:$DEPLOY_TOKEN" https://x',
    'mysql -h db -u root -p"$MYSQL_PWD"',
    # --- round 1 -----------------------------------------------------------
    # A port PUBLICATION, in the spellings that are the ordinary way to expose a
    # database. The previous lookahead recognised bare HOST:CONTAINER only, so
    # the IP-bound and `/proto` forms — and a container NAME rather than an
    # image tag as the anchor — still masked a port map as a MySQL password.
    "docker run --name mysql -p127.0.0.1:3306:3306 -d mysql:8",
    "docker run --name mysql -p3306:3306/tcp -d mysql:8",
    "docker run --name mariadb -p0.0.0.0:3307:3306 mariadb:11",
    "docker run --rm --name mysql-test -p127.0.0.1:33060:33060 mysql:8.4",
    "podman run --name mariadb -p127.0.0.1:3306:3306/tcp mariadb",
    "docker run --name mysql -p8000-8010:8000-8010 mysql:8",
    "docker run --name mysql -p[::1]:3306:3306 mysql:8",
    # sshpass's own options come BEFORE the command it wraps, so a gap wide
    # enough for arbitrary flags reaches into that command's flags — and `-p` on
    # `ssh` is a PORT. These are the SAFE sshpass forms, where the secret is in
    # a file or the environment and there is no credential on the line at all.
    "sshpass -e scp -P 2222 report.csv deploy@10.0.0.5:/tmp/",
    "sshpass -f /run/pw ssh -p 2222 deploy@10.0.0.5 uptime",
    "sshpass -e rsync -e 'ssh -p 2222' a b",
    # A global `(?i)` covered the FLAG as well as the program name, so `-P` was
    # read as `-p` on every program-anchored pattern.
    "redis-cli -h cache.internal -A something ping",
    # A header name is prose far more often than `sshpass` is. A placeholder is
    # not a credential, and masking one had `/forcefield:remember` tell the user
    # to rotate a secret that does not exist.
    "sed -i 's/apikey: old/apikey: new/' config.yaml",
    "echo 'api-key: PLACEHOLDER' >> settings.yml",
    "echo 'Authorization: Bearer <token>' > headers.txt",
    "echo 'X-Api-Key: <YOUR_API_KEY>' >> README.md",
    "echo 'api-key: CHANGEME' >> settings.yml",
    "echo 'api-key: your-api-key' >> settings.yml",
    "echo 'Authorization: Basic REDACTED' > headers.txt",
    "echo 'apikey: xxxxxx' > headers.txt",
    # A `printf` conversion specification is not a value. `api_key_header`
    # consumed `%s\n` as the header's secret, so `/forcefield:remember` refused
    # a command whose entire point is that the key comes from the environment.
    'printf \'x-api-key: %s\\n\' "$API_KEY" > headers.txt',
    'printf \'Authorization: Bearer %s\\n\' "$TOKEN" >> headers.txt',
)

# `_NOT_A_SECRET` is an EXEMPTION, and an exemption that is wrong in the
# under-masking direction is a credential leak, not an over-mask. Its first form
# was a prefix rule (`my[_-]?[a-z0-9_-]{0,32}`, `[a-z0-9_-]{0,32}[_-]here`) that
# asserted nothing about the value being a placeholder, so every one of these
# nine reached the 0600 file sink and journald in clear with
# `forcefield.redacted_fields` empty. They are real token shapes, not
# placeholders: the discriminator is that `tenant`, `prod`, `service`, `session`
# and a hex run are not words a README uses in place of a secret.
_PLACEHOLDER_LOOKALIKE = (
    "mycompany_prod_ab12cd34",
    "mytoken-9f3a2b1c55d1",
    "MyAppKey-77c1f0aa",
    "your-tenant-key-4471",
    "YOURORG-9f3a2b1c",
    "my_service_account_key_1",
    "mysecrettoken12345",
    "session-key-here",
    "prod_key_here",
)
for _value in _PLACEHOLDER_LOOKALIKE:
    for _shape in ("curl -H 'Authorization: Bearer %s' https://api.example.com",
                   "curl -H 'X-Api-Key: %s' https://api.example.com",
                   "curl -H 'Authorization: Basic %s' https://api.example.com"):
        _command = _shape % _value
        _clean, _hit = redact_secrets(_command)
        check(_hit and _value not in _clean,
              "a token that merely LOOKS like a placeholder is still masked -- "
              "the _NOT_A_SECRET vocabulary must stay closed: %s -> %s"
              % (_command, _clean))

# The other direction of the same round: a `&` inside a URL's query string, a
# `|` inside a quoted header value and a `(` anywhere are NOT command
# separators, and excluding them as a character class stopped masking five of
# seven realistic `curl -u user:pass` shapes. The password then reached the 0600
# file sink and journald in clear with `forcefield.redacted_fields` EMPTY, so
# the record asserted that nothing had been masked. Under-masking is the worse
# direction and these pin it.
_SEG_REACH = (
    "curl 'https://api.example.com/v1/items?page=1&limit=50' -u alice:%s",
    "curl -H 'X-Filter: a|b' -u alice:%s https://api.example.com/v1",
    'curl -d \'{"q":"a&b"}\' -u alice:%s https://api.example.com/v1',
    "curl --data-urlencode 'q=a&b' --user alice:%s https://api.x/v1",
    "curl -sS https://api.example.com/v1?a=1&b=2 -u alice:%s -o out.json",
    "curl -H 'X-Trace: (build 12)' -u alice:%s https://api.example.com/v1",
)
for _shape in _SEG_REACH:
    _command = _shape % _PW
    _clean, _hit = redact_secrets(_command)
    check(_hit and _PW not in _clean,
          "an in-argument & | or ( does not stop the program anchor reaching "
          "its own flag: %s -> %s" % (_command, _clean))

for _command in _FLAG_NEGATIVE:
    _clean, _hit = redact_secrets(_command)
    check(not _hit, "over-masked a benign command: %s -> %s"
          % (_command, _clean))
    check(_clean == _command, "rewrote a benign command: %s" % _command)

# A PARTIAL mask is worse than none: it leaves the tail in clear with a
# `[REDACTED:...]` label immediately before it telling any reader what the
# adjacent string is, while `forcefield.redacted_fields` asserts the field was
# masked. `url_userinfo` matched only to the FIRST `@`, so a password containing
# one -- an ordinary thing for a password to contain -- kept 9 of its 17
# characters. Every separator that can appear inside a userinfo password gets a
# case, because the run has to reach the LAST `@` before the authority ends and
# still stop at `/` and at whitespace.
_TAIL = "TAILMARKER99"
for _pw in ("S3cr3tP@" + _TAIL, "a@b@c@" + _TAIL, "p%s!#$&*" % _TAIL,
            "P@ss:word@" + _TAIL):
    _url = "curl https://deploy:%s@host.example.com/api?x=1" % _pw
    _clean, _hit = redact_secrets(_url)
    check(_hit, "a URL password is masked at all: %s" % _pw)
    check(_TAIL not in _clean,
          "the whole password is masked, not a prefix of it: %r -> %r"
          % (_pw, _clean))
    check("host.example.com" in _clean and "/api?x=1" in _clean,
          "and the host and path survive, which is what an investigation needs: "
          "%r" % _clean)
    check(_clean.startswith("curl https://deploy:"),
          "as does the scheme and the username: %r" % _clean)

# The other half of that run's bound: it must stop at `?` as well as at `/`.
# A query string cannot be part of userinfo under RFC 3986, but a query
# parameter carrying an `@` is ordinary (`cc=a@b.com`), and a run that crosses
# the `?` swallows the real host and re-labels a query value as the authority.
# That is worse than a visible over-mask, because the record still READS like a
# host and no reader can tell it is the wrong one.
_QUERY_AT = "curl 'https://u:hunter2@host.example.com?cc=a@b.com&bcc=c@d.com'"
_clean, _hit = redact_secrets(_QUERY_AT)
check(_hit, "a userinfo password before a query string is masked at all")
check("hunter2" not in _clean, "and masked whole: %r" % _clean)
check("host.example.com" in _clean,
      "the userinfo run stops at `?`, so the DESTINATION HOST survives a query "
      "parameter that itself contains an `@`: %r" % _clean)
check(_clean.endswith("?cc=a@b.com&bcc=c@d.com'"),
      "and the query string is left intact rather than absorbed: %r" % _clean)

# The sentinel invariant, stated directly rather than only through the forms
# above: `normalize._UNKNOWN_EXPANSION` exists because it "appears in no
# credential character class", and a wide value run is exactly what breaks that.
import normalize as _normalize  # noqa: E402
from patterns import _REDACTION_PATTERNS  # noqa: E402

for _name, _pattern in _REDACTION_PATTERNS.items():
    check(_pattern.search("x" + _normalize._UNKNOWN_EXPANSION * 64 + "x")
          is None,
          "%s matches a run of the unknown-expansion sentinel" % _name)

print("PASS: the flag- and header-shaped credentials are masked, and %d benign "
      "commands are not (%d positive, %d negative)"
      % (len(_FLAG_NEGATIVE), len(_FLAG_POSITIVE), len(_FLAG_NEGATIVE)))


print("test_credential_obfuscation.py: %d assertions passed" % _n)
