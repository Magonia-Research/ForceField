#!/usr/bin/env python3
"""Test suite for sigma_compiler.py.

The compiler is the one ForceField module that is NOT stdlib-only and NOT a
runtime hook: it needs pyyaml and runs offline, inside the venv that
scripts/install.sh creates, to turn the SigmaHQ YAML tree into the JSON that
sigma_engine.py evaluates. It cannot fail open, because it does not run at hook
time -- but it decides which rules exist at all, and install.sh runs it
unattended on a 24h cooldown against a third-party repository.

pyyaml is resolved three ways so this suite is green on a fresh checkout that has
never run install.sh: the system interpreter, then the venv install.sh builds,
then a stub. Everything under "pure functions" below touches no YAML at all --
the compiler only calls yaml.safe_load inside main() -- so the stub costs
nothing there, and the end-to-end round trip announces a SKIP rather than
asserting when no real parser is available.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

# The venv lives under the REAL home; _isolated_home is about to divert $HOME, so
# the path has to be resolved before that happens.
_REAL_HOME = os.path.expanduser("~")

import _isolated_home  # noqa: F401,E402  MUST precede every hook import

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

_n = 0


def check(cond, msg):
    global _n
    _n += 1
    assert cond, msg


# --- resolve a YAML parser, or stub one -------------------------------------

HAVE_YAML = True
try:
    import yaml  # noqa: F401
except ImportError:
    _venv = Path(_REAL_HOME) / ".claude" / "forcefield" / "sigma" / "venv"
    _site = list(_venv.glob("lib/python*/site-packages"))
    if _site:
        sys.path.insert(0, str(_site[0]))
    try:
        import yaml  # noqa: F401
    except ImportError:
        HAVE_YAML = False
        sys.modules["yaml"] = types.ModuleType("yaml")
        sys.modules["yaml"].YAMLError = type("YAMLError", (Exception,), {})
        sys.modules["yaml"].safe_load = lambda *_a, **_k: None

import sigma_compiler as sc  # noqa: E402


# --- parse_condition --------------------------------------------------------
# The gate that decides whether a rule is representable at all: an unparseable
# condition drops the rule silently, so the supported shapes are the ceiling on
# how much of SigmaHQ this plugin can ever evaluate.

for _cond, _want in (
    ("selection", "single_selection"),
    ("all of selection*", "all_selections"),
    ("1 of selection*", "any_selection"),
    ("selection and not 1 of filter*", "selection_minus_filters"),
    ("selection and not filter", "selection_minus_filters"),
    ("all of selection* and not 1 of filter*", "all_selections_minus_filters"),
    ("1 of selection* and not 1 of filter*", "any_selection_minus_filters"),
    ("selection_a and selection_b", "named_and"),
    ("selection_a and not filter_b", "named_selection_minus_filter"),
    ("selection_a and not 1 of filter*", "named_selection_minus_filters"),
):
    check(sc.parse_condition(_cond)[0] == _want, f"condition {_cond!r} -> {_want}")

check(sc.parse_condition("  selection  ")[0] == "single_selection", "condition is stripped")
check(sc.parse_condition("selection_a and selection_b and selection_c")[0] == "named_and_multi",
      "three named selections")
check(sc.parse_condition("selection_a and selection_b and selection_c")[1]["selections"]
      == ["selection_a", "selection_b", "selection_c"], "named_and_multi keeps every name")
check(sc.parse_condition("selection_a and not something_else")[0] == "named_and_minus_filters",
      "named selection minus an arbitrary negation")

# Unsupported shapes must return (None, None), not raise and not half-parse:
# compile_rule drops the rule on None, which is the safe direction.
for _cond in ("", "not selection", "selection or filter", "1 of them", "keywords"):
    check(sc.parse_condition(_cond) == (None, None), f"unsupported condition {_cond!r} -> None")
print("PASS: parse_condition - supported shapes, and unsupported ones fail closed")


# --- parse_modifier_chain / compile_selection_entry -------------------------
# Modifier precedence is an ordered if/elif, so it is order-sensitive in a way
# the field names are not. `re` wins over everything; a bare field is `exact`.

check(sc.parse_modifier_chain("CommandLine") == ("CommandLine", []), "bare field, no modifiers")
check(sc.parse_modifier_chain("CommandLine|contains|all")
      == ("CommandLine", ["contains", "all"]), "modifier chain split")

check(sc.compile_selection_entry("Image", "/bin/sh")["modifier"] == "exact",
      "no modifier means exact match")
check(sc.compile_selection_entry("CommandLine|contains", "x")["modifier"] == "contains", "contains")
check(sc.compile_selection_entry("CommandLine|startswith", "x")["modifier"] == "startswith",
      "startswith")
check(sc.compile_selection_entry("CommandLine|endswith", "x")["modifier"] == "endswith", "endswith")
check(sc.compile_selection_entry("CommandLine|re", "x.*y")["modifier"] == "re", "re")
check(sc.compile_selection_entry("CommandLine|re|contains", "x")["modifier"] == "re",
      "re outranks contains in the same chain")

check(sc.compile_selection_entry("CommandLine|contains|all", ["a", "b"])["all"] is True,
      "the all modifier sets the flag")
check(sc.compile_selection_entry("CommandLine|contains", ["a", "b"])["all"] is False,
      "no all modifier leaves the flag clear")

# A scalar is wrapped and every value is stringified, so a YAML int or bool
# cannot reach the engine as a non-string and break its matcher.
check(sc.compile_selection_entry("CommandLine", "x")["values"] == ["x"], "scalar becomes a list")
check(sc.compile_selection_entry("CommandLine", [1, True])["values"] == ["1", "True"],
      "non-string YAML scalars are stringified")
print("PASS: modifier chain, precedence, and value normalization")


# --- compile_selection ------------------------------------------------------
# A dict ANDs its fields; a list of dicts ORs the groups. A bare scalar in a list
# is treated as a CommandLine substring, which is the only place the compiler
# guesses a field name.

_and = sc.compile_selection({"Image": "/bin/sh", "CommandLine|contains": "curl"})
check(_and["type"] == "and_fields", "dict selection ANDs fields")
check(len(_and["entries"]) == 2, "both fields survive")

_or = sc.compile_selection([{"Image": "/bin/sh"}, {"Image": "/bin/bash"}])
check(_or["type"] == "or_groups", "list selection ORs groups")
check(len(_or["groups"]) == 2, "both groups survive")

_bare = sc.compile_selection(["nc -e"])
check(_bare["groups"][0][0]["field"] == "CommandLine", "a bare list item defaults to CommandLine")
check(_bare["groups"][0][0]["modifier"] == "contains", "and to a substring match")

check(sc.compile_selection("just a string") is None, "an unrecognized selection shape is dropped")
check(sc.compile_selection(None) is None, "a null selection is dropped")
print("PASS: compile_selection - AND dicts, OR lists, bare items, unknown shapes")


# --- uses_unavailable_fields ------------------------------------------------
# A Bash hook sees a command line and nothing else. A rule keyed on a parent
# process cannot be evaluated, and a rule kept anyway would match on its
# remaining fields alone -- a false positive by construction.

check(sc.uses_unavailable_fields({"ParentImage": "/bin/sh"}) is True, "parent field detected")
check(sc.uses_unavailable_fields({"ParentCommandLine|contains": "x"}) is True,
      "detected through a modifier suffix")
check(sc.uses_unavailable_fields({"CommandLine": "x"}) is False, "supported field is fine")
check(sc.uses_unavailable_fields([{"CommandLine": "x"}, {"IntegrityLevel": "High"}]) is True,
      "detected inside a list form")
check(sc.uses_unavailable_fields(["bare", "strings"]) is False, "bare list items claim no field")
check(sc.uses_unavailable_fields(None) is False, "None is not a field reference")
print("PASS: uses_unavailable_fields - dict, modifier suffix, list, and non-dict shapes")


# --- compile_rule: every reason a rule is dropped ---------------------------

def _rule(**over):
    base = {
        "id": "abc-123",
        "title": "Test Rule",
        "level": "high",
        "description": "d",
        "tags": ["attack.execution", "attack.t1059", "car.2013-02-003"],
        "references": ["https://example.invalid/x"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {"selection": {"CommandLine|contains": "evil"}, "condition": "selection"},
    }
    base.update(over)
    return base


check(sc.compile_rule(_rule()) is not None, "a well-formed rule compiles")
check(sc.compile_rule(_rule(logsource={"category": "network_connection", "product": "linux"}))
      is None, "non process_creation category dropped")
check(sc.compile_rule(_rule(logsource={"category": "process_creation", "product": "windows"}))
      is None, "unsupported product dropped")
check(sc.compile_rule(_rule(logsource={"category": "process_creation"})) is None,
      "missing product dropped")
check(sc.compile_rule(_rule(level="low")) is None, "below the default floor dropped")
check(sc.compile_rule(_rule(detection={"selection": {"CommandLine": "x"}})) is None,
      "missing condition dropped")
check(sc.compile_rule(_rule(detection={"selection": {"CommandLine": "x"},
                                       "condition": "1 of them"})) is None,
      "unparseable condition dropped")
check(sc.compile_rule(_rule(detection={"selection": {"ParentImage": "/bin/sh"},
                                       "condition": "selection"})) is None,
      "a rule whose only selection needs an unavailable field is dropped")

# The subtle one: an `all of selection*` rule needs EVERY selection. Dropping one
# for an unavailable field and keeping the rest would silently loosen the rule
# from "all of these" to "all of the ones we could read".
_partial = _rule(detection={
    "selection_a": {"CommandLine|contains": "evil"},
    "selection_b": {"ParentImage": "/bin/sh"},
    "condition": "all of selection*",
})
check(sc.compile_rule(_partial) is None, "all-of rule with a skipped selection is dropped whole")

# ...whereas `1 of selection*` is still correct with fewer alternatives.
_any = dict(_partial)
_any["detection"] = dict(_partial["detection"], condition="1 of selection*")
check(sc.compile_rule(_any) is not None, "any-of rule survives a skipped selection")

# A filter that needs an unavailable field is dropped while the rule is kept.
# That NARROWS nothing and widens the match, so it is worth pinning as a
# deliberate choice rather than an accident.
_filtered = _rule(detection={
    "selection": {"CommandLine|contains": "evil"},
    "filter": {"ParentImage": "/usr/bin/make"},
    "condition": "selection and not filter",
})
_c = sc.compile_rule(_filtered)
check(_c is not None, "rule with an unevaluable filter still compiles")
check(_c["filters"] == {}, "the unevaluable filter is dropped, widening the match")

_ok = sc.compile_rule(_rule())
check(_ok["tags"] == ["attack.execution", "attack.t1059"], "only MITRE tags are kept")
check(_ok["condition_raw"] == "selection", "the raw condition is preserved for debugging")
check(sc.compile_rule(_rule(title=None, id=None))["title"] is None, "absent title passes through")
print("PASS: compile_rule - category, product, level, condition and field gates")


# --- --min-level and --products actually filter -----------------------------
# Both were accepted, recorded in the output metadata, and then ignored: the
# filter used a hardcoded medium/high/critical set and a hardcoded linux/macos
# pair. A file stamped "min_level": "critical" still carried every medium rule.

check(sc.compile_rule(_rule(level="medium"), "critical") is None, "critical floor drops medium")
check(sc.compile_rule(_rule(level="critical"), "critical") is not None, "critical floor keeps critical")
check(sc.compile_rule(_rule(level="low"), "low") is not None, "low floor keeps low")
check(sc.compile_rule(_rule(level="high"), "medium") is not None, "medium floor keeps high")
check(sc.compile_rule(_rule(level="bogus"), "medium") is None, "an unknown level is dropped")
check(sc.compile_rule(_rule(), "medium", ("macos",)) is None, "product list is honored")
check(sc.compile_rule(_rule(), "medium", ("linux",)) is not None, "matching product is kept")
print("PASS: min_level and products filter rather than only labelling the output")


# --- find_rule_files --------------------------------------------------------

with tempfile.TemporaryDirectory() as _repo:
    _root = Path(_repo)
    for _sub in ("rules", "rules-emerging-threats", "rules-threat-hunting"):
        _d = _root / _sub / "category" / "linux" / "process_creation"
        _d.mkdir(parents=True)
        (_d / "r.yml").write_text("x")
    (_root / "rules" / "category" / "macos" / "process_creation").mkdir(parents=True)
    (_root / "rules" / "category" / "macos" / "process_creation" / "m.yml").write_text("x")
    # Neither a different category nor a non-.yml file is a rule.
    (_root / "rules" / "category" / "linux" / "network_connection").mkdir(parents=True)
    (_root / "rules" / "category" / "linux" / "network_connection" / "n.yml").write_text("x")
    (_root / "rules" / "category" / "linux" / "process_creation" / "notes.md").write_text("x")

    check(len(sc.find_rule_files(_repo, ["linux"])) == 3, "all three rule trees are searched")
    check(len(sc.find_rule_files(_repo, ["linux", "macos"])) == 4, "both products found")
    check(sc.find_rule_files(_repo, ["windows"]) == [], "absent product yields nothing")

check(sc.find_rule_files("/nonexistent/path/xyz", ["linux"]) == [],
      "a missing repo yields nothing rather than raising")
print("PASS: find_rule_files - three trees, product scoping, missing paths")


# --- end-to-end through main() ----------------------------------------------
# Run as a subprocess so argparse and the file write are exercised as install.sh
# invokes them, not just the pure functions above.

if not HAVE_YAML:
    print("SKIP: end-to-end round trip (no pyyaml; run scripts/install.sh to enable)")
else:
    _YAML_RULES = {
        "keep_high.yml": """
title: Keep High
id: 11111111-1111-1111-1111-111111111111
level: high
logsource: {category: process_creation, product: linux}
detection:
  selection: {CommandLine|contains: 'nc -e'}
  condition: selection
tags: [attack.execution]
""",
        "keep_medium.yml": """
title: Keep Medium
id: 22222222-2222-2222-2222-222222222222
level: medium
logsource: {category: process_creation, product: linux}
detection:
  selection: {Image: /bin/sh}
  condition: selection
""",
        "drop_low.yml": """
title: Drop Low
id: 33333333-3333-3333-3333-333333333333
level: low
logsource: {category: process_creation, product: linux}
detection:
  selection: {CommandLine|contains: ls}
  condition: selection
""",
        "drop_parent.yml": """
title: Drop Parent-keyed
id: 44444444-4444-4444-4444-444444444444
level: high
logsource: {category: process_creation, product: linux}
detection:
  selection: {ParentImage: /bin/sh}
  condition: selection
""",
        "malformed.yml": "title: [unclosed\n  bad: : :\n",
        "empty.yml": "",
    }

    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as _out:
        _d = Path(_repo) / "rules" / "category" / "linux" / "process_creation"
        _d.mkdir(parents=True)
        for _name, _body in _YAML_RULES.items():
            (_d / _name).write_text(_body)

        _target = Path(_out) / "nested" / "rules.json"
        _proc = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "sigma_compiler.py"),
             "--sigma-path", _repo, "--output", str(_target),
             "--products", "linux", "--min-level", "medium"],
            capture_output=True, text=True,
        )
        check(_proc.returncode == 0, "compiler exits 0: " + _proc.stderr[-300:])
        check(_target.exists(), "output written, parent directory created")

        _db = json.loads(_target.read_text())
        check(_db["version"] == 1, "schema version stamped")
        check(_db["min_level"] == "medium", "min_level recorded")
        check(_db["products"] == ["linux"], "products recorded")
        check(_db["rule_count"] == len(_db["rules"]), "rule_count matches the list it describes")
        _titles = sorted(r["title"] for r in _db["rules"])
        check(_titles == ["Keep High", "Keep Medium"], "kept exactly the two eligible rules")
        check(_db["rules"][0]["level"] == "high", "output is sorted strictest first")
        # A malformed rule file is a warning, not a failure: one bad file in a
        # third-party repo must not cost the whole ruleset.
        check(len(_db["rules"]) == 2, "malformed and empty files are skipped, not fatal")

        # The same tree at a stricter floor must actually shrink.
        _strict = Path(_out) / "strict.json"
        _proc2 = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "sigma_compiler.py"),
             "--sigma-path", _repo, "--output", str(_strict),
             "--products", "linux", "--min-level", "high"],
            capture_output=True, text=True,
        )
        check(_proc2.returncode == 0, "compiler exits 0 at a stricter floor")
        _sdb = json.loads(_strict.read_text())
        check([r["title"] for r in _sdb["rules"]] == ["Keep High"],
              "a stricter floor drops the medium rule from the file, not just the label")

    print("PASS: end-to-end - filtering, sorting, metadata, and a malformed rule file")


# ---------------------------------------------------------------------------
# The SigmaHQ checkout is fetched inertly
# ---------------------------------------------------------------------------
#
# The rules are third-party YAML from a repository nobody here controls, and both
# scripts that touch it say in prose that the checkout is "deliberately inert".
# Nothing checked that they meant it, and they have now drifted apart twice:
# hooks/sigma_update.sh:35 records the first repair ("The git command here has to
# match scripts/install.sh's, and did not"), and install.sh was still hardening
# its `clone` while leaving its `pull` bare — the branch that runs on every
# re-install after the first, and the one that runs post-merge hooks.
#
# Read as text on purpose. No suite executes either script (install.sh clones a
# ~300 MB repo, sigma_update.sh writes to $HOME), so a text assertion is what is
# available — and it pins every invocation at once rather than the one somebody
# remembered. Both scripts touch no repository but the SigmaHQ checkout, so every
# hook-running verb in them is in scope; `rev-parse` and friends run no hook and
# are not matched.

_HOOK_RUNNING_VERB = re.compile(
    r"\bgit\b(?P<opts>(?:\s+-[cC]\s*[^\s\\]+)*)\s+(?P<verb>clone|pull|fetch|checkout|merge)\b")

for _script in ("scripts/install.sh", "hooks/sigma_update.sh"):
    _text = (HOOKS_DIR.parent / _script).read_text(encoding="utf-8")
    # Join line continuations first: the flags and the verb are routinely split,
    # and drop comment lines so the prose describing the rule is not read as code.
    _flat = re.sub(r"\\\n\s*", " ", _text)
    _code = [ln for ln in _flat.splitlines() if not ln.lstrip().startswith("#")]
    _found = 0
    for _line in _code:
        _match = _HOOK_RUNNING_VERB.search(_line)
        if not _match:
            continue
        _found += 1
        _where = "%s: git %s" % (_script, _match.group("verb"))
        check("core.hooksPath=/dev/null" in _match.group("opts"),
              "%s neuters core.hooksPath" % _where)
        check("--no-recurse-submodules" in _line,
              "%s refuses submodules" % _where)
    check(_found >= 1, "%s: found a hook-running git call to check" % _script)
check(_found >= 3, "sigma_update.sh's three verbs were all reached, got %d" % _found)

print("PASS: every git call against the SigmaHQ checkout is hook-inert")


print(f"test_sigma_compiler.py: {_n} assertions passed")
