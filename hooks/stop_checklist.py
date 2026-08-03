#!/usr/bin/env python3
"""Stop hook: Security Completion Checklist.

Fires at session end. Emits a systemMessage reminding Claude
to verify security hygiene before finishing.

Input: JSON on stdin (Claude Code Stop hook format)
Output: JSON on stdout (hook response with systemMessage)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import read_stdin_text  # noqa: E402

# Restated rather than imported from ``patterns``: this hook parses the event
# only to drain stdin and then discards it, and importing the pattern module to
# learn one integer would put ~400 compiled regexes on the Stop path for nothing.
MAX_STDIN_BYTES = 1_048_576

CHECKLIST = """\
**Security Completion Checklist**

Before finishing, verify:
- No secrets, API keys, or credentials in code output or committed files
- No real credentials were written to non-.env files
- Container cleanup: any containers started were stopped/removed (`podman ps -a`)
- No sensitive data left in /tmp or other world-readable locations
- If packages were installed on host: clean up (`pipx uninstall`, remove node_modules)
- .gitignore covers any new sensitive file paths"""


def main() -> None:
    try:
        json.loads(read_stdin_text(MAX_STDIN_BYTES))
    except (json.JSONDecodeError, OSError, ValueError):
        pass

    response = {"systemMessage": CHECKLIST}
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
