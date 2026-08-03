#!/usr/bin/env python3
"""Tests for the documentation set — links, anchors, file map, and site coverage.

Plain executable assert script, like every other suite here: runs top to bottom
and stops at the first failed assert.

Documentation rots differently from code. It does not raise, it does not fail a
type check, and a reader who follows a dead cross-reference concludes the project
is careless rather than that one line is stale. Every check below is a claim the
docs make that can be settled mechanically:

1. **Relative links resolve.** A `[hook contract](architecture.md#hook-contract)`
   that points at a file or a heading which no longer exists is a broken promise,
   and these docs cross-reference heavily on purpose.
2. **The architecture file map matches the tree.** It was already wrong once: two
   modules and three suites shipped before the map listed them. It is the one
   piece of prose that is a literal directory listing, so it is the one piece
   that can be diffed against the directory.
3. **The suite table matches tests/.** Same failure mode, same fix.
4. **Every doc reaches the published site.** `scripts/sync-docs.sh` carries the
   source-to-page map, and a new doc that nobody added to it is invisible on the
   site while looking perfectly fine in the repo. Checking the map needs no
   second checkout, which is what makes this the part that runs everywhere; the
   body comparison lives in the script, because that genuinely needs the site.

Deliberately NOT checked: external URLs. Fetching ~90 of them would make the
suite slow, network-dependent, and prone to failing on someone else's outage —
and the fail-open reflex applies to a test suite too. They were verified by hand
when written.
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Section 6 imports `git_guard` and `config` in-process to read counts out of
# them, which pulls in `hook_logging` and `log_sinks`. Neither emits a record
# here -- measured: the real security.log is byte-identical across a run -- but
# "does not happen to log" is not containment, and this suite is one edit away
# from calling something that does. Import-time, and before every hook import,
# because that ordering is the whole guarantee.
import _isolated_home  # noqa: E402,F401 - diverts $HOME and mutes the native sinks

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_count = 0


def check(condition, label):
    global _count
    _count += 1
    assert condition, "FAILED: %s" % label


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


# Fenced blocks carry example paths, sample JSON and shell that are not claims
# about this tree. Stripping them first is what keeps the link checker honest
# rather than merely noisy.
_FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_LINK = re.compile(r"\[[^\]^]*?\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


def prose(text):
    return _INLINE_CODE.sub("", _FENCE.sub("", text))


def slug(heading):
    """GitHub's heading-anchor slug: strip markup, lowercase, spaces to hyphens.

    The underscore rule is the one that has to be exact, and it is not "strip
    underscores". GitHub removes an underscore that was *emphasis markup* and
    keeps one that is part of an identifier, because the distinction is made by
    the markdown parser before the slugger ever runs:

        ### What `git_guard` checks   ->  what-git_guard-checks
        ### A _stressed_ word         ->  a-stressed-word

    Stripping both turned every `#...git_guard...` cross-reference in these docs
    into a false failure. The lookaround below reproduces the parser's rule for
    the paired form: `_x_` standing alone is emphasis, `a_b` is not. Verified
    against `gh api /markdown`; the four answers are asserted at the bottom of
    this file so a "tidy-up" of this regex fails loudly.
    """
    text = re.sub(r"`([^`]*)`", r"\1", heading)               # code spans
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)       # links keep their text
    text = re.sub(r"(?<!\w)_([^_]+)_(?!\w)", r"\1", text)      # underscore emphasis
    text = re.sub(r"[^\w\s-]", "", text)                       # punctuation, incl. *
    return re.sub(r"\s+", "-", text.strip()).lower()


# Ground truth from `gh api /markdown`, not from reasoning about the rules.
for _heading, _expected in (
    ("What `git_guard` checks", "what-git_guard-checks"),
    ("A *starred* and _underscored_ head", "a-starred-and-underscored-head"),
    ("7. Known gaps", "7-known-gaps"),
    ("Adjacent: repositories that execute when *opened*",
     "adjacent-repositories-that-execute-when-opened"),
):
    check(slug(_heading) == _expected,
          "slug(%r) == %r, got %r" % (_heading, _expected, slug(_heading)))


# One slug function covers both surfaces, and that is measured rather than
# assumed. The site sets no `markdown:` key and ships no Gemfile, so GitHub
# Pages applies its own defaults, which include `kramdown: {input: GFM}`. The
# GFM parser carries GitHub's header-id algorithm, keeping leading digits and
# underscores. Rendering all 145 headings in this docs set through
# `Kramdown::Document.new(..., input: 'GFM')` produced zero disagreements with
# `slug()` above.
#
# Measure the parser the site actually runs, not the one that is easiest to
# reach: plain `Kramdown::Document` uses the `kramdown` parser, which drops
# leading digits and underscores and disagrees on 4 of 5 sample headings. A gate
# built on it rejects `#7-known-gaps` and `#what-git_guard-checks`, both of which
# resolve correctly on the live site.


def anchors(text):
    return {slug(h) for h in _HEADING.findall(text)}


# ---------------------------------------------------------------------------
# The documentation set
# ---------------------------------------------------------------------------

DOCS = []
for dirpath, _dirnames, filenames in os.walk(os.path.join(ROOT, "docs")):
    for name in sorted(filenames):
        if name.endswith(".md"):
            DOCS.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
DOCS.sort()

PAGES = ["README.md"] + DOCS

check(len(DOCS) >= 5, "the docs/ tree was found (%d files)" % len(DOCS))
for required in ("docs/threat-model.md", "docs/hooks.md", "docs/configuration.md",
                 "docs/architecture.md", "docs/logging/README.md"):
    check(required in DOCS, "%s is present" % required)


# ---------------------------------------------------------------------------
# 1. Every relative link resolves — to a file, and to a heading inside it
# ---------------------------------------------------------------------------

checked_links = 0
for page in PAGES:
    text = prose(read(page))
    here = anchors(read(page))
    base = os.path.dirname(page)

    for target in _LINK.findall(text):
        if re.match(r"^(?:https?:|mailto:|#|<)", target):
            if target.startswith("#"):
                check(target[1:].lower() in here,
                      "%s: in-page anchor %s exists" % (page, target))
                checked_links += 1
            continue

        path, _, fragment = target.partition("#")
        resolved = os.path.normpath(os.path.join(base, path)) if path else page
        check(os.path.exists(os.path.join(ROOT, resolved)),
              "%s: link target %s exists" % (page, target))
        checked_links += 1

        # A directory link (docs/logging/) resolves to its README, which is what
        # both GitHub and the Pages site serve for it.
        if os.path.isdir(os.path.join(ROOT, resolved)):
            resolved = os.path.join(resolved, "README.md")
            check(os.path.exists(os.path.join(ROOT, resolved)),
                  "%s: directory link %s has a README" % (page, target))

        if fragment and resolved.endswith(".md"):
            check(fragment.lower() in anchors(read(resolved)),
                  "%s: %s names a heading that exists in %s" % (page, target, resolved))
            checked_links += 1

check(checked_links >= 40,
      "the link checker actually ran over the docs (%d links)" % checked_links)


# ---------------------------------------------------------------------------
# 2. The architecture file map is a real directory listing
# ---------------------------------------------------------------------------
#
# The map lives inside a fenced block, so it is read from the raw text rather
# than from `prose`. Both directions are asserted: a listed path that does not
# exist is a lie, and a shipped hook the map omits is the failure that already
# happened once.

architecture = read("docs/architecture.md")
block = re.search(r"<summary><strong>File map</strong></summary>\s*```(.*?)```",
                  architecture, re.DOTALL)
check(block is not None, "architecture.md still carries a fenced file map")

mapped = set()
for line in block.group(1).splitlines():
    candidate = line.split()[0] if line.split() else ""
    if "/" in candidate and not candidate.startswith("#"):
        mapped.add(candidate)

check(len(mapped) >= 25, "the file map lists the tree (%d paths)" % len(mapped))
for path in sorted(mapped):
    check(os.path.exists(os.path.join(ROOT, path)),
          "file map: %s exists on disk" % path)

# Both directories, not just hooks/. `scripts/` was outside this census, so a new
# script shipped and the map stayed green over it — the same failure the map
# exists to catch, one directory across.
shipped = set()
for folder in ("hooks", "scripts"):
    shipped |= {
        folder + "/" + name for name in os.listdir(os.path.join(ROOT, folder))
        if name.endswith((".py", ".sh")) and not name.startswith("_")
    }
for path in sorted(shipped - mapped):
    check(False, "file map: %s ships but is not listed" % path)


# ---------------------------------------------------------------------------
# 3. The suite table names the suites that exist
# ---------------------------------------------------------------------------

suites = {name for name in os.listdir(os.path.join(ROOT, "tests"))
          if name.startswith("test_") and name.endswith(".py")}
for suite in sorted(suites):
    check("`%s`" % suite in architecture, "architecture.md lists the %s suite" % suite)

listed = set(re.findall(r"`(test_[a-z_]+\.py)`", architecture))
for stale in sorted(listed - suites):
    check(False, "architecture.md lists %s, which no longer exists" % stale)


# ---------------------------------------------------------------------------
# 4. Every doc reaches the published site
# ---------------------------------------------------------------------------

sync = read("scripts/sync-docs.sh")
block = re.search(r'^MAP="\n(.*?)^"', sync, re.DOTALL | re.MULTILINE)
check(block is not None, "sync-docs.sh still declares a MAP")

sources = {line.split(":", 1)[0].strip()
           for line in block.group(1).splitlines() if ":" in line}
for doc in DOCS:
    rel = doc[len("docs/"):]
    check(rel in sources,
          "docs/%s is mapped to a site page in scripts/sync-docs.sh" % rel)
for stale in sorted(sources - {d[len("docs/"):] for d in DOCS}):
    check(False, "sync-docs.sh maps docs/%s, which does not exist" % stale)


# ---------------------------------------------------------------------------
# 5. The README's own claims about the tree
# ---------------------------------------------------------------------------

readme = read("README.md")
for path in re.findall(r"`(scripts/[a-z-]+\.sh)`", readme + architecture):
    check(os.path.exists(os.path.join(ROOT, path)), "README/architecture: %s exists" % path)
for path in re.findall(r"(?<![\w/])(scripts/[a-z-]+\.sh)", prose(readme)):
    check(os.path.exists(os.path.join(ROOT, path)), "README: %s exists" % path)

check("magonia-research.github.io/forcefield-docs" in readme,
      "the README points at the published site")


# ---------------------------------------------------------------------------
# 6. Counted claims match the code that backs them
# ---------------------------------------------------------------------------
#
# A number in prose is the first thing to rot, because nothing dereferences it.
# "Twenty hooks" survived the addition of a twenty-first for exactly that reason.
# Each claim below is now read out of the tree it describes.

sys.path.insert(0, os.path.join(ROOT, "hooks"))
import json  # noqa: E402
import git_guard  # noqa: E402

with open(os.path.join(ROOT, "hooks", "hooks.json"), encoding="utf-8") as handle:
    events = json.load(handle)["hooks"]
registrations = sum(len(entry.get("hooks", []))
                    for matchers in events.values() for entry in matchers)

WORDS = {18: "eighteen", 19: "nineteen", 20: "twenty", 21: "twenty-one",
         22: "twenty-two", 23: "twenty-three"}
check(registrations in WORDS, "the hook count is inside the spelled-out range")
spelled = WORDS[registrations]
for page, text in (("README.md", readme), ("docs/hooks.md", read("docs/hooks.md"))):
    check(spelled in text.lower(),
          "%s says %r hooks, matching hooks.json" % (page, spelled))

# Every git pattern the guard ships is a row in the threat model's table, and
# every row is a pattern that exists. This is the check that catches a guard
# shipping a new detection nobody documented.
threat_model = read("docs/threat-model.md")
for name in git_guard.GIT_PATTERNS:
    check("`%s`" % name in threat_model,
          "threat-model.md documents the %s pattern" % name)
documented = set(re.findall(r"^\| `(git_[a-z_]+|recursive_\w+|submodule_\w+)` \|",
                            threat_model, re.MULTILINE))
for stale in sorted(documented - set(git_guard.GIT_PATTERNS)):
    check(False, "threat-model.md documents %s, which the guard no longer ships" % stale)

count = len(git_guard.GIT_PATTERNS)
denies = len(git_guard.HARD_DENY_PATTERNS)
check("Eleven patterns" in threat_model and count == 11,
      "threat-model.md's pattern count matches the guard (%d)" % count)
check(denies == 1 and "one of which **denies**" in threat_model,
      "and its deny count matches (%d)" % denies)

# Both risk and alternative text exist for every pattern: format_alert falls back
# to a generic string, which is how a hard deny once printed "Potential
# repo-execution risk" and an approval checklist for something unapprovable.
for name in git_guard.GIT_PATTERNS:
    check(name in git_guard.PATTERN_RISKS, "%s has risk text" % name)
    check(name in git_guard.PATTERN_ALTERNATIVES, "%s has alternative text" % name)

import config  # noqa: E402

configurable = len(config.NATURAL_MAX)
check("Twelve gating guards" in read("docs/configuration.md") and configurable == 12,
      "configuration.md's gating-guard count matches config.py (%d)" % configurable)


# ---------------------------------------------------------------------------
# 7. Documented constants and identifiers exist, with the documented value
# ---------------------------------------------------------------------------
#
# The gap this closes was measured, not imagined. `docs/logging/` ran to 7,316
# lines, every check above was green over it, and it documented an
# implementation that had been deleted: a `SYSLOG_MAX_BYTES = 1800` applied by a
# `_DatagramFormatter` that no longer existed, a `UNIFIED_LOG_MAX_BYTES = 2048`
# against a real 1015, a `_SharedRotatingFileHandler`, a `_UNIFIED_LOG_WITHHELD`,
# and ten separate lines saying the macOS unified log drops `command.line` when
# the shipped behaviour is the exact opposite. Links, anchors, the file map and
# the suite table are all *structure*; nothing here dereferenced a documented
# *value*.
#
# So: every `NAME = <number>` a doc states about the logging layer is read out of
# the module, and every `_private_name` or class name a doc mentions must exist.
# A doc that describes something the code does not have now fails.

import log_sinks  # noqa: E402
import hook_logging  # noqa: E402

LOGGING_DOCS = [os.path.join("docs", "logging", name)
                for name in sorted(os.listdir(os.path.join(ROOT, "docs", "logging")))
                if name.endswith(".md")]
LOGGING_DOCS += ["docs/architecture.md", "docs/configuration.md", "docs/hooks.md",
                 "README.md"]

# Constants a doc is allowed to state, mapped to where they really live.
_CONSTANT_OWNERS = {
    "UNIFIED_LOG_MAX_BYTES": log_sinks,
    "UNIFIED_LOG_FAULT_MAX_BYTES": log_sinks,
    "SYSLOG_MAX_BYTES": log_sinks,
    "EVENTCREATE_PAYLOAD_MAX": log_sinks,
    "FRAGMENT_MAX_COUNT": log_sinks,
    "LOG_BUDGET_SECONDS": log_sinks,
    "NATIVE_SINK_MIN_SEVERITY": log_sinks,
    "FALLBACK_MAX_BYTES": log_sinks,
    "FALLBACK_BACKUP_COUNT": log_sinks,
    "CONF_OWNER": log_sinks,
    "CONF_ADMIN": log_sinks,
    "CONF_LOCAL": log_sinks,
    "CONF_UNKNOWN": log_sinks,
    "FREE_TEXT_MIN_CONFIDENTIALITY": log_sinks,
    "MAX_SCRUB_VALUES": hook_logging,
    "MAX_SCRUB_DEPTH": hook_logging,
    "MAX_REDACT_BYTES": hook_logging,
}

# The gate this replaces dereferenced 8 of these 17, and reported nothing about
# the other 9 — measured, not estimated. Two things hid the gap.
#
# The pattern required a backtick on each side of `NAME = 1015`, and the docs
# state constants where constants are naturally stated: inside a fenced block,
# where there are no backticks. Every one of `CONF_OWNER`, `CONF_LOCAL`,
# `CONF_ADMIN`, `CONF_UNKNOWN`, `NATIVE_SINK_MIN_SEVERITY` and
# `FREE_TEXT_MIN_CONFIDENTIALITY` is written out with its value in a fenced
# block in 00-field-reference, and not one of them was ever read out of the
# module.
#
# Then `_stated >= 3` closed over the hole. Three matches was a floor a single
# page satisfied, so a constant could go from documented-and-checked to
# documented-and-unchecked — or vanish from the docs entirely, as
# `MAX_REDACT_BYTES` had — and the suite stayed green and said "273 assertions
# passed". A count is not coverage.
#
# So the pattern now reads a value whether or not it is in backticks, resolves an
# alias whose value is another constant, and every constant must be accounted
# for by name rather than by tally.

# The constant has to be the WHOLE left-hand side: preceded by a backtick, or
# starting its own line inside a fenced block or a blockquote. Without that,
# `FRAGMENT_MAX_COUNT × UNIFIED_LOG_FAULT_MAX_BYTES` = 31,760 reads as a claim
# that UNIFIED_LOG_FAULT_MAX_BYTES is 31 — a correct sentence failing the gate,
# which is the way to lose a gate.
_CONSTANT_RE = re.compile(
    r"(?:^[ \t>]*|`)(" + "|".join(sorted(_CONSTANT_OWNERS)) + r")`?\s*=\s*`?"
    r"([0-9][0-9_,]*(?:\.[0-9]+)?|[A-Z][A-Z0-9_]{2,})",
    re.MULTILINE)


def _constant_value(literal):
    """A documented right-hand side, as a number.

    `FREE_TEXT_MIN_CONFIDENTIALITY = CONF_ADMIN` is how the docs state that one,
    and reading it as a literal would fail on a doc that is exactly right.
    """
    if literal in _CONSTANT_OWNERS:
        return float(getattr(_CONSTANT_OWNERS[literal], literal))
    return float(literal.replace("_", "").replace(",", ""))


# A constant the docs are allowed to leave out, each with the reason. Empty, and
# meant to stay that way: an entry here is a documented decision not to document
# something, which is a different thing from an oversight and should have to be
# argued in a diff.
_UNDOCUMENTED_ON_PURPOSE = frozenset()

_stated = {}
for _page in LOGGING_DOCS:
    _text = read(_page)
    for _name, _literal in _CONSTANT_RE.findall(_text):
        _stated.setdefault(_name, []).append((_page, _literal))
        _actual = float(getattr(_CONSTANT_OWNERS[_name], _name))
        check(_actual == _constant_value(_literal),
              "%s states `%s = %s`; the code says %r"
              % (_page, _name, _literal, getattr(_CONSTANT_OWNERS[_name], _name)))

for _name in sorted(_CONSTANT_OWNERS):
    check(_name in _stated or _name in _UNDOCUMENTED_ON_PURPOSE,
          "%s is a shipped logging constant that no doc states a value for — "
          "document it, or list it in _UNDOCUMENTED_ON_PURPOSE with a reason"
          % _name)

for _name in sorted(_UNDOCUMENTED_ON_PURPOSE):
    check(_name not in _stated,
          "%s is listed as undocumented on purpose but the docs do state it; "
          "drop the exemption" % _name)

check(len(_stated) >= len(_CONSTANT_OWNERS) - len(_UNDOCUMENTED_ON_PURPOSE),
      "every constant not explicitly exempted is dereferenced (%d of %d)"
      % (len(_stated), len(_CONSTANT_OWNERS)))

# An identifier in backticks that looks like a module-private name or a class
# from the logging layer has to exist. Anything a doc names as deleted is listed
# once, here, so "we removed it and said so" reads differently from "we removed
# it and forgot".
_REMOVED_ON_PURPOSE = frozenset({
    "_SharedRotatingFileHandler", "_DatagramFormatter", "_UNIFIED_LOG_WITHHELD",
    "_UNIFIED_LOG_PROJECTION", "_unified_log_projection", "_emit_to_unified_log",
    "_attach_syslog_handler", "_attach_file_handler", "_build_logger",
    "_syslog_socket", "_truncate_utf8", "_bounded_payload", "_VERBOSITY_FLOOR",
    "resolve_log_verbosity", "should_log", "LOG_VERBOSITY_LEVELS",
    "DEFAULT_LOG_VERBOSITY", "DRAIN_BUDGET_SECONDS", "winevt_argv",
    "FALLBACK_LOG_FILE", "FALLBACK_LOG_DIR",
})
_IDENT_RE = re.compile(r"`(_[A-Za-z][A-Za-z0-9_]{3,}|[A-Z][A-Za-z]+Handler|"
                       r"[A-Z][A-Za-z]+Formatter)`")
_MODULES_TO_SEARCH = (log_sinks, hook_logging, config)
_ghosts = []
for _page in LOGGING_DOCS:
    for _ident in set(_IDENT_RE.findall(read(_page))):
        if _ident in _REMOVED_ON_PURPOSE:
            _ghosts.append("%s: names %s, which was deleted" % (_page, _ident))
            continue
        if not any(hasattr(_m, _ident) for _m in _MODULES_TO_SEARCH):
            # Not everything in backticks is one of ours; only flag names that
            # look like this layer's, i.e. that a sibling module does define
            # under a different spelling. A name nothing defines anywhere is
            # prose, and prose is not this check's business.
            continue
check(not _ghosts,
      "no doc names an identifier this rework deleted: %s" % _ghosts[:5])

# The one claim that was inverted rather than merely stale, asserted directly:
# the free-text policy is a property of the SINK's confidentiality, and the macOS
# unified log is above the floor.
_platforms = read("docs/logging/02-platforms.md")
check("unified-log copy drops" not in _platforms,
      "02-platforms.md no longer claims the unified log drops the command line")
check(log_sinks.confidentiality(log_sinks.NAME_FILE) >= log_sinks.CONF_OWNER,
      "the file sink is still the OWNER-confidentiality sink the docs describe")
check(log_sinks.FREE_TEXT_MIN_CONFIDENTIALITY == log_sinks.CONF_ADMIN,
      "the documented free-text floor is CONF_ADMIN")
for _field in log_sinks.FREE_TEXT_FIELDS:
    check("`%s`" % _field in _platforms,
          "02-platforms.md lists the free-text field %s" % _field)

# --- 8. the entry page's SIEM guidance, against the module ------------------
#
# Section 7 above read 05-platforms.md only, and that is exactly how the entry
# page shipped with the free-text policy INVERTED — "the macOS unified log
# withholds command.line ... Linux syslog carries the full record", which is the
# two sides the wrong way round, over 251 green assertions. README.md is the page
# an operator reads first and the one that says which sink may be forwarded, so
# the direction is asserted here from the module rather than trusted in prose.
#
# The check is positional rather than a phrase match: the bullet must name every
# native sink at or above FREE_TEXT_MIN_CONFIDENTIALITY on the carrying side of
# the sentence, and every sink below it on the withholding side. Swapping two
# sink names — the actual defect — moves a name across the boundary and fails.
# Whitespace-collapsed, because prose wraps: "the Windows\n  Application channel"
# is one phrase to a reader and two to `str.find`.
_readme = re.sub(r"\s+", " ", read(os.path.join("docs", "logging", "README.md")))

# The human spelling each sink goes by in prose. A sink added to the module
# without a spelling here fails the completeness check below rather than being
# silently exempt.
_SINK_PROSE = {
    log_sinks.NAME_OSLOG: "macOS unified log",
    log_sinks.NAME_JOURNALD: "journald",
    log_sinks.NAME_SYSLOG: "/dev/log",
    log_sinks.NAME_WINEVT: "Windows Application channel",
}
check(set(_SINK_PROSE) == set(log_sinks.NATIVE_SINK_NAMES),
      "every native sink has a prose spelling: %s vs %s"
      % (sorted(_SINK_PROSE), sorted(log_sinks.NATIVE_SINK_NAMES)))

# The class each sink carries **on the platform it exists on**. Not
# `confidentiality()` directly: that is a live measurement, and off macOS
# `_unified_store_restricted()` cannot find `/var/db/diagnostics`, so `oslog`
# reads back CONF_LOCAL on a Linux host and this page would fail for describing
# a Mac. Each entry is checked against the module's own rule below, so the table
# cannot drift into being a second source of truth.
_DOCUMENTED_CONF = {
    log_sinks.NAME_OSLOG: log_sinks.CONF_ADMIN,
    log_sinks.NAME_JOURNALD: log_sinks.CONF_ADMIN,
    log_sinks.NAME_SYSLOG: log_sinks.CONF_LOCAL,
    log_sinks.NAME_WINEVT: log_sinks.CONF_LOCAL,
}
check(set(_DOCUMENTED_CONF) == set(log_sinks.NATIVE_SINK_NAMES),
      "every native sink has a documented confidentiality class")
check(log_sinks.confidentiality(log_sinks.NAME_JOURNALD)
      == _DOCUMENTED_CONF[log_sinks.NAME_JOURNALD]
      and log_sinks.confidentiality(log_sinks.NAME_SYSLOG)
      == _DOCUMENTED_CONF[log_sinks.NAME_SYSLOG]
      and log_sinks.confidentiality(log_sinks.NAME_WINEVT)
      == _DOCUMENTED_CONF[log_sinks.NAME_WINEVT],
      "the three unconditional classes in the docs match the module")
check(log_sinks.confidentiality(log_sinks.NAME_OSLOG)
      == (log_sinks.CONF_ADMIN if log_sinks._unified_store_restricted()
          else log_sinks.CONF_LOCAL),
      "and the unified log's class is the documented conditional: ADMIN when "
      "/var/db/diagnostics is not world-readable, LOCAL when the check fails")

_carries = sorted(n for n, c in _DOCUMENTED_CONF.items()
                  if c >= log_sinks.FREE_TEXT_MIN_CONFIDENTIALITY)
_withholds = sorted(n for n, c in _DOCUMENTED_CONF.items()
                    if c < log_sinks.FREE_TEXT_MIN_CONFIDENTIALITY)
check(bool(_carries) and bool(_withholds),
      "both sides of the free-text floor are occupied (%s / %s)"
      % (_carries, _withholds))

_ADMIN_MARK, _LOCAL_MARK = "`CONF_ADMIN`", "`CONF_LOCAL`"
check(_ADMIN_MARK in _readme and _LOCAL_MARK in _readme,
      "README.md states the free-text policy in terms of the two confidentiality "
      "classes, so which side a sink is on can be checked")
_admin_at = _readme.index(_ADMIN_MARK)
_local_at = _readme.index(_LOCAL_MARK)
check(_admin_at < _local_at,
      "README.md names the carrying class before the withholding one")

# Searched from the policy statement onward, not from the top of the page: the
# entry page legitimately names a sink earlier, in the table of on-disk paths,
# and a first-occurrence search over the whole document would read that factual
# mention as the policy claim. Scoping to the bullet keeps the defect this
# catches -- swapping two sink names moves one across the boundary -- without
# forbidding the page from mentioning a sink anywhere else.
for _sink in _carries:
    _where = _readme.find(_SINK_PROSE[_sink], _admin_at)
    check(0 <= _where < _local_at,
          "README.md puts %s (confidentiality %d, at or above the free-text "
          "floor) on the carrying side of the SIEM bullet"
          % (_SINK_PROSE[_sink], _DOCUMENTED_CONF[_sink]))
for _sink in _withholds:
    _where = _readme.find(_SINK_PROSE[_sink], _local_at)
    check(_where > _local_at,
          "README.md puts %s (confidentiality %d, below the free-text floor) on "
          "the withholding side of the SIEM bullet"
          % (_SINK_PROSE[_sink], _DOCUMENTED_CONF[_sink]))

# The Windows claim, which contradicted 05 §1 in the same doc set: 05 says the
# hooks import and run there, so the entry page may not say none runs at all.
check("No hook runs at all" not in _readme,
      "README.md no longer claims no hook runs on Windows; 05 §1 measures that "
      "they import and run")

# --- 9. every documented record is the envelope the code emits now ----------
#
# Every record example under docs/logging/ is produced by running the shipped
# hook and reading back what it wrote. That is only worth anything if it stays
# true, and the failure mode is silent: an example hand-edited to illustrate a
# point, or left behind when the envelope changes, reads exactly like a
# measurement. So the check is zero tolerance rather than a ratchet -- there is
# no "disclosed staleness" tier to hide in.
#
# Two shapes are checked because they are the two that a stale body carries:
# an RFC 3339 string `Timestamp` where the code emits a uint64 nanosecond
# integer, and attributes that no longer exist.
_JSON_FENCE = re.compile(r"```json\s*\n(.*?)```", re.DOTALL)
_DEAD_ATTRS = ("event.category", "event.kind")


def _record_blocks(page):
    """Every fenced JSON object on ``page`` that is shaped like a log record."""
    out = []
    for body in _JSON_FENCE.findall(read(page)):
        try:
            parsed = json.loads(body)
        except ValueError:
            continue                      # a stdin event, a config, a fragment
        if not isinstance(parsed, dict):
            continue
        if "Attributes" in parsed and isinstance(parsed["Attributes"], dict):
            out.append(parsed)
    return out


def _stale_reasons(block):
    """Why this documented record is not the envelope the code emits now."""
    why = []
    stamp = block.get("Timestamp")
    if isinstance(stamp, str) and stamp != "<NS>":
        why.append("Timestamp is the string %r, not a uint64 ns integer" % stamp)
    attributes = block.get("Attributes", {})
    for dead in _DEAD_ATTRS:
        if dead in attributes:
            why.append("carries the deleted attribute %s" % dead)
    return why


_stale = []
_examined = 0
for _page in LOGGING_DOCS:
    for _block in _record_blocks(_page):
        _examined += 1
        for _why in _stale_reasons(_block):
            _stale.append("%s: %s" % (_page, _why))

check(not _stale,
      "every documented record carries the envelope the code emits: %s"
      % _stale[:4])
# A zero-tolerance check over zero records passes vacuously, which is the way
# to lose it: the pages could be emptied and this would still read green.
check(_examined >= 25,
      "the record checker actually ran over the documented examples (%d found, "
      "one per hook is the floor)" % _examined)

# ---------------------------------------------------------------------------
# 9b. The documented records carry the namespace the code actually emits
# ---------------------------------------------------------------------------
# 427 attribute keys, every EventName, every Resource.service.name and every
# OCSF product name are the product namespace written out as a literal inside
# captured JSON. A rename moves all of them at once, and a page the
# substitution missed then documents a record nobody can reproduce -- it hands
# the reader a jq recipe keyed on a prefix the code has never emitted. That is
# not a staleness the schema notes disclose, so it is a hard check and not part
# of the ratchet above.
#
# Read off a live record instead of compared against a literal: this has to keep
# holding through the NEXT rename without being the thing that needs renaming.
_live = hook_logging.build_event("probe_guard", "deny", pattern_matched="p")
_ns = _live["EventName"].split(".", 1)[0]
_live_service = _live["Resource"]["service.name"]
_live_product = _live["Attributes"]["ocsf.metadata"]["product"]["name"]
# OTel/OCSF vocabulary, censused off the pages themselves. Anything outside it
# is ours, and so has to be namespaced the way the code namespaces it.
_STD_PREFIXES = frozenset({"ocsf", "event", "command", "session", "tool",
                           "claude_code", "process", "prompt", "file", "agent"})


def _namespace_faults(page, block):
    """Where this documented record names a product the code does not."""
    out = []
    name = block.get("EventName")
    if isinstance(name, str) and name and name.split(".", 1)[0] != _ns:
        out.append("%s: EventName %r" % (page, name))
    resource = block.get("Resource")
    if isinstance(resource, dict):
        service = resource.get("service.name")
        if service is not None and service != _live_service:
            out.append("%s: service.name %r" % (page, service))
    attributes = block.get("Attributes", {})
    metadata = attributes.get("ocsf.metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("product"), dict):
        product = metadata["product"].get("name")
        if product is not None and product != _live_product:
            out.append("%s: ocsf product %r" % (page, product))
    for key in attributes:
        if key == "...":
            continue          # the pages' elision marker, not an attribute name
        prefix = key.split(".", 1)[0]
        if "." in key and prefix not in _STD_PREFIXES and prefix != _ns:
            out.append("%s: attribute %r" % (page, key))
    return out


_ns_faults = []
for _page in LOGGING_DOCS:
    for _block in _record_blocks(_page):
        _ns_faults += _namespace_faults(_page, _block)

check(not _ns_faults,
      "every documented record must carry the namespace the code emits (%r / "
      "%r / %r): %s" % (_ns, _live_service, _live_product,
                        sorted(set(_ns_faults))[:4]))
check(any(k.startswith(_ns + ".") for k in _live["Attributes"]),
      "the live record used as the reference actually carries %s.* attributes -- "
      "otherwise the check above compares against nothing" % _ns)

# `<NS>` is the deterministic-capture convention and section 9 exempts it, so
# the page using it has to say what it is: a reader otherwise cannot tell a
# placeholder from a type claim.
_records_text = read("docs/logging/01-records-by-hook.md")
if '"<NS>"' in _records_text:
    check("`<NS>`" in _records_text,
          "01-records-by-hook.md explains the <NS> Timestamp placeholder it uses")

print("test_docs.py: %d assertions passed" % _count)
