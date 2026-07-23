#!/usr/bin/env python3
"""Shared constants for Portcullis hooks.

Small values that were duplicated across every guard. Imported the same way as
the other shared hook modules (``hook_logging``, ``allowlist``) — after each
hook does ``sys.path.insert(0, str(Path(__file__).parent))``. Stdlib-only, no
side effects on import.
"""

from __future__ import annotations

# Upper bound on a hook's stdin read — a guard against a pathologically large
# tool-input payload exhausting memory. 1 MiB comfortably covers real commands.
MAX_STDIN_BYTES = 1_048_576

# Hook decision precedence: deny beats ask beats allow. Used to pick the
# highest-severity result when several guards weigh in on one tool call.
DECISION_PRECEDENCE = {"deny": 3, "ask": 2, "allow": 1}
