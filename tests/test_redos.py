#!/usr/bin/env python3
"""Super-linearity regression test for every compiled pattern in hooks/.

A ForceField hook has a 5s budget (``hooks/hooks.json``). Overrunning it is not a
latency bug: Claude Code kills the hook and *discards its stdout wholesale*, so a
quadratic pattern turns a computed hard deny into a silent allow. Three shipped
patterns were quadratic before this test existed, and reviewing ~200 patterns by
hand had already misattributed which ones.

The check is mechanical, and it runs in three families because a pattern can be
expensive in three different ways.

**Context-free** — every pattern against a family of adversarial fillers at
doubling lengths; the time ratio must stay near 2. Linear patterns sit at ~2.0; a
quadratic one lands at ~4.0.

**Anchored** — a filler that does not carry the literal a pattern keys on never
reaches the expensive construct behind it. ``bearer_token``'s cost lives inside a
negative lookahead sitting behind ``authorization\\s*:\\s*bearer\\s+``, and none of
the context-free fillers contains that anchor, so this suite printed PASS on a
tree where ``redact_secrets`` cost **59.8 s** on 64 KiB — past the 5 s timeout at
roughly 5 KB of command line. The anchors are DERIVED from each pattern's own
source (literal seeds, joined and separated every plausible way) and kept only
when the pattern actually matches the result, so they cannot go stale against a
hand-written fixture list.

**Production entry** — ``patterns.redact_secrets`` over the same anchored corpus
at the full ``MAX_REDACT_BYTES`` log cap. All three families time
``pattern.sub``, never ``pattern.search``: ``search`` returns at the FIRST match
and is blind to per-occurrence cost by construction, while every production
caller substitutes across every occurrence. Measured on the shape above:
``search`` was flat at 0.069 s for 8, 16 and 32 repeats while ``sub`` grew
0.62 / 1.18 / 2.30 s.

Run: python3 tests/test_redos.py
"""

import re
import sys
import time
from pathlib import Path

import _isolated_home  # noqa: E402,F401  MUST precede every hook import

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS))

import hook_logging  # noqa: E402
import patterns  # noqa: E402

# A pattern is timed against every filler; the worst ratio is the verdict. Each
# filler targets a different backtracking shape: a single unbroken character run,
# a run broken by a non-class byte, and repeated prefixes of the literals the
# guards key on (a repeated prefix is what makes an unanchored pattern restart).
FILLERS = {
    "a_run": "a",
    "dot_run": "a.",
    "slash_run": "/",
    "url_repeat": "http://",
    "jwt_repeat": "eyJ",
    "subst_repeat": "$(",
    "fetcher_repeat": "curl ",
    "redirect_repeat": ">x ",
    "b64_run": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo",
    "word_bang": "A" * 40 + "!",
}

# Value shapes that are only reachable BEHIND an anchor, appended to the derived
# anchor for the anchored family. Each ends in `!` on purpose: the constructs
# that blow up here live inside a negative lookahead whose tail is
# ``['"]?(?:\s|$)``, and the cost is paid only when that tail FAILS and the
# engine backtracks through every parse of the value. A value followed by
# whitespace matches on the first parse and costs nothing.
ADVERSARIAL_VALUES = {
    # The `_FORMAT_SPECIFIER` shape. `0` was in both `[-+ #0]{0,4}` and a `[0-9]*`
    # width, giving five parses per specifier and 5**8 for a run of eight. Three
    # zeros is where it becomes visible and four is where it bites, so both a
    # four-zero and a six-zero form are timed: a future widening of the flag
    # class would move the cliff, not remove it.
    "pct_zero_spec": "%0000d" * 8 + "!",
    "pct_deep_zero_spec": "%000000d" * 8 + "!",
    "pct_mixed_spec": "%-0004.2f" * 8 + "!",
    # The other `_FORMAT_SPECIFIER` alternative, `\\[a-zA-Z0-9]{1,3}`.
    "esc_run": "\\a" * 8 + "!",
    # The `_PLACEHOLDER_WORD` chain: every segment is in the closed vocabulary,
    # so the chain alternative is entered and then fails on the trailing `!`.
    "placeholder_chain": "my-api-key-token-secret-value-goes-here-pass!",
    "b64_value": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo!",
}

# Modules whose module-level and dict-held patterns are all in scope.
MODULES = [
    "exfil_guard", "supply_chain_guard", "git_guard", "credential_access_guard",
    "credential_guard", "mcp_guard", "webfetch_guard", "filesystem_guard",
    "injection_defense", "agent_guard", "agent_output_guard", "normalize",
    "output_credential_scanner", "prompt_credential_guard", "patterns",
    "subagent_stop_guard", "shell_context",
]

# Timing is noisy at these scales, so a ratio is only trusted once the slower run
# is long enough to measure — below that, scheduler jitter alone clears 2.5 and
# the test would flake. 2.5 leaves headroom over the ~2.0 a linear pattern shows.
MAX_RATIO = 2.5
MIN_SECONDS_TO_JUDGE = 0.05
# Absolute ceiling for one pattern on one filler. Well under the 5s hook budget,
# which several patterns must share.
MAX_ABSOLUTE_SECONDS = 0.75
BASE_REPS = 8_000
# Probe size for the anchored family, in bytes, doubled for the ratio. Small
# because an anchored payload is the expensive one: the `_FORMAT_SPECIFIER`
# blowup cost 1.68 s at 1,848 bytes and 7.28 s at 8,162, so a 2 KiB/4 KiB pair
# clears both gates by a wide margin while costing a healthy tree ~1 ms.
ANCHORED_BYTES = 2_048
# Ceiling for one `redact_secrets` call over a full `MAX_REDACT_BYTES` of
# adversarial input. `redact_secrets` runs once per free-text attribute and
# `hook_logging._FREE_TEXT_ATTRS` has six, all inside `LOG_BUDGET_SECONDS = 1.0`,
# so a single call must stay well under a sixth of that. Measured worst on this
# corpus: 0.091 s on macOS/3.9.6, 0.153 s on python:3.9-slim.
MAX_REDACT_SECONDS = 0.5

# ---------------------------------------------------------------------------
# Anchor derivation
# ---------------------------------------------------------------------------
# Everything below reads a pattern's own source and manufactures a string the
# pattern matches. Nothing is hand-written per pattern, and a manufactured anchor
# is discarded unless the pattern confirms it by matching.

_GROUP_OPEN = re.compile(r"\(\?(?:P[<=]\w+>?|[aiLmsux:=!#]|<[=!])")
_CHAR_CLASS = re.compile(r"\[(?:[^\]\\]|\\.)*\]")
_ESCAPE = re.compile(r"\\[a-zA-Z]")
_SEED = re.compile(r"-{0,2}[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*")
_SEPARATORS = ("", " ", ":", ": ", "=", "/", ".", "://", " -")
_PREFIXES = ("", ".", "-", "--", "/", "~/.")
_BENIGN_VALUE = "AbCd1234efGH5678ijKL"
# Enough seeds to reach the anchor of every shipped pattern that has one; the cap
# bounds the candidate search, which is quadratic in the seed count.
MAX_SEEDS = 8


def literal_seeds(source):
    """Literal word-shaped runs in a regex source, in order, de-duplicated."""
    stripped = _GROUP_OPEN.sub(" ", source)
    stripped = _CHAR_CLASS.sub(" ", stripped)
    stripped = _ESCAPE.sub(" ", stripped)
    stripped = stripped.replace("|", " ")
    seeds = []
    for match in _SEED.finditer(stripped):
        token = match.group(0)
        floor = 1 if token.startswith("-") else 3
        if len(token.lstrip("-")) < floor:
            continue
        if token not in seeds:
            seeds.append(token)
    return seeds[:MAX_SEEDS]


def _seed_groups(seeds):
    """Prefixes, sliding windows and first-plus-one pairs of the seed list."""
    groups = []
    for size in range(1, len(seeds) + 1):
        groups.append(seeds[:size])
    for start in range(len(seeds)):
        for width in (2, 3):
            if start + width <= len(seeds):
                groups.append(seeds[start:start + width])
    for other in range(1, len(seeds)):
        groups.append([seeds[0], seeds[other]])
    unique = []
    for group in groups:
        if group not in unique:
            unique.append(group)
    return unique


def _anchor_candidates(source):
    seen = set()
    for group in _seed_groups(literal_seeds(source)):
        for prefix in _PREFIXES:
            for separator in _SEPARATORS:
                joined = prefix + separator.join(group)
                for candidate in (joined + " ", joined):
                    if candidate not in seen:
                        seen.add(candidate)
                        yield candidate


def engaging_anchor(pattern):
    """A derived prefix this pattern actually matches, or None."""
    for candidate in _anchor_candidates(pattern.pattern):
        try:
            if pattern.search(candidate + _BENIGN_VALUE):
                return candidate
        except Exception:  # noqa: BLE001 - a pattern that errors has no anchor
            return None
    return None


# ---------------------------------------------------------------------------


def collect_patterns():
    """Every compiled pattern reachable from the guard modules, as (label, re)."""
    found = {}
    for mod_name in MODULES:
        try:
            mod = __import__(mod_name)
        except Exception as exc:  # noqa: BLE001 - a missing optional module is not a failure here
            print("  (skipped %s: %s)" % (mod_name, exc))
            continue
        for attr, value in vars(mod).items():
            if isinstance(value, re.Pattern):
                found["%s.%s" % (mod_name, attr)] = value
            elif isinstance(value, dict):
                for key, inner in value.items():
                    if isinstance(inner, re.Pattern):
                        found["%s.%s[%s]" % (mod_name, attr, key)] = inner
    return sorted(found.items())


def _time_sub(pattern, text):
    """Seconds for one substitution pass over the whole text."""
    start = time.perf_counter()
    pattern.sub("", text)
    return time.perf_counter() - start


def _doubling(measure, unit, base_reps):
    """(ratio, slow_seconds) for `measure` over `unit` at base and double reps."""
    fast = measure(unit * base_reps)
    slow = measure(unit * (base_reps * 2))
    ratio = slow / fast if fast > 1e-9 else 1.0
    # Only judge the ratio once the run is long enough to time reliably.
    if slow < MIN_SECONDS_TO_JUDGE:
        ratio = min(ratio, 1.0)
    return ratio, slow


def worst_behaviour(pattern):
    """Worst (ratio, seconds, filler) for one pattern across the filler family."""
    worst = (0.0, 0.0, "")
    for filler_name, unit in FILLERS.items():
        try:
            ratio, slow = _doubling(lambda t: _time_sub(pattern, t), unit, BASE_REPS)
        except Exception:  # noqa: BLE001 - a pattern that errors is not a timing bug
            continue
        if ratio > worst[0] or slow > worst[1]:
            worst = (max(ratio, worst[0]), max(slow, worst[1]), filler_name)
    return worst


def worst_anchored(pattern, anchor):
    """Worst (ratio, seconds, value) behind the pattern's own literal anchor.

    Returns at the first value that clears the absolute ceiling. A pattern that
    is already over budget is reported once; timing its five other values would
    only make a failing run cost minutes.
    """
    worst = (0.0, 0.0, "")
    for value_name, value in ADVERSARIAL_VALUES.items():
        unit = anchor + value + " "
        reps = max(1, ANCHORED_BYTES // len(unit))
        try:
            ratio, slow = _doubling(lambda t: _time_sub(pattern, t), unit, reps)
        except Exception:  # noqa: BLE001
            continue
        if ratio > worst[0] or slow > worst[1]:
            worst = (max(ratio, worst[0]), max(slow, worst[1]), value_name)
        if slow > MAX_ABSOLUTE_SECONDS:
            break
    return worst


def _judge(label, ratio, seconds, filler, failures):
    if ratio > MAX_RATIO and seconds >= MIN_SECONDS_TO_JUDGE:
        failures.append((label, ratio, seconds, filler, "super-linear"))
    elif seconds > MAX_ABSOLUTE_SECONDS:
        failures.append((label, ratio, seconds, filler, "too slow"))


def main() -> int:
    all_patterns = collect_patterns()
    failures = []

    print("Timing %d compiled patterns against %d context-free fillers..."
          % (len(all_patterns), len(FILLERS)))
    for label, pattern in all_patterns:
        ratio, seconds, filler = worst_behaviour(pattern)
        _judge(label, ratio, seconds, filler, failures)

    anchors = {}
    for label, pattern in all_patterns:
        anchor = engaging_anchor(pattern)
        if anchor is not None:
            anchors[label] = anchor
    print("Derived an engaging anchor for %d of %d patterns; timing %d "
          "adversarial values behind each..."
          % (len(anchors), len(all_patterns), len(ADVERSARIAL_VALUES)))
    for label, pattern in all_patterns:
        anchor = anchors.get(label)
        if anchor is None:
            continue
        ratio, seconds, value = worst_anchored(pattern, anchor)
        _judge(label, ratio, seconds, "anchored/" + value, failures)

    # Coverage. `_NOT_A_SECRET` is the construct whose cost is invisible without
    # an anchor -- it is a negative lookahead behind a header literal, and it is
    # where the 59.8 s blowup lived. Every pattern carrying it must be reachable,
    # or this suite is back to printing PASS over an unmeasured construct.
    carriers = [label for label, pattern in all_patterns
                if patterns._NOT_A_SECRET in pattern.pattern]
    unreached = [label for label in carriers if label not in anchors]
    assert carriers, (
        "no pattern embeds patterns._NOT_A_SECRET -- if the construct was "
        "renamed, point this check at the new name rather than deleting it"
    )
    assert not unreached, (
        "%d of %d patterns embedding patterns._NOT_A_SECRET have no derived "
        "anchor, so the adversarial values never reach the lookahead: %s. "
        "Extend literal_seeds/_anchor_candidates until they do."
        % (len(unreached), len(carriers), unreached)
    )
    print("Coverage: all %d patterns embedding _NOT_A_SECRET are anchor-reached."
          % len(carriers))

    # Production entry point. redact_secrets is what hook_logging.build_event
    # calls on every free-text attribute, and it applies every redaction pattern
    # in sequence over the whole text at the MAX_REDACT_BYTES log cap.
    # One entry per distinct anchor: the same three headers appear in both
    # `_REDACTION_ONLY_PATTERNS` and the merged `_REDACTION_PATTERNS`, and
    # `redact_secrets` applies every pattern to every text regardless of which
    # label supplied the anchor. The loop stops at the first over-budget unit —
    # a single blown-up call already costs a minute.
    worst_redact = (0.0, "")
    over_budget = False
    for anchor in sorted(set(anchors[label] for label in carriers)):
        for value_name, value in ADVERSARIAL_VALUES.items():
            unit = anchor + value + " "
            text = unit * (hook_logging.MAX_REDACT_BYTES // len(unit))
            start = time.perf_counter()
            patterns.redact_secrets(text)
            seconds = time.perf_counter() - start
            if seconds > worst_redact[0]:
                worst_redact = (seconds, "%r on %s" % (anchor, value_name))
            if seconds > MAX_REDACT_SECONDS:
                failures.append((anchor, 0.0, seconds, "redact/" + value_name,
                                 "redact_secrets over budget"))
                over_budget = True
                break
        if over_budget:
            break

    for label, ratio, seconds, filler, why in failures:
        print("  FAIL %-52s %s: ratio=%.2f/doubling %.3fs on %r"
              % (label, why, ratio, seconds, filler))

    assert not failures, (
        "%d pattern(s) are super-linear or over budget. An unanchored pattern "
        "with an unbounded quantifier restarts inside long runs; bound the run "
        "and add a lookbehind that pins the start, as "
        "supply_chain_guard.fetch_var_exec does. A construct inside a negative "
        "lookahead pays for EVERY parse of its input when the lookahead's tail "
        "fails, so ambiguity between two adjacent classes is a cost "
        "multiplier." % len(failures)
    )
    print("PASS: all %d patterns stay near-linear under adversarial input, "
          "context-free and behind their own anchors; worst redact_secrets over "
          "%d bytes is %.3fs (%s)"
          % (len(all_patterns), hook_logging.MAX_REDACT_BYTES,
             worst_redact[0], worst_redact[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
