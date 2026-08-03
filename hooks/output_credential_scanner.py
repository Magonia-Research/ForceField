#!/usr/bin/env python3
"""PostToolUse[Bash] and PostToolUse[Read] output credential scanner.

Per OWASP LLM06 (Sensitive Information Disclosure):
Scans Bash command output and Read file content for leaked credentials.
High-confidence matches are redacted via updatedToolOutput.
All matches emit a systemMessage warning.

Input: JSON on stdin (Claude Code PostToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from credential_guard import (  # noqa: E402
    CREDENTIAL_PATTERNS,
    is_placeholder_credential,
    # Shared with credential_guard rather than restated. The hand-copied
    # duplicate this replaces had drifted: it omitted ``aws_secret_key``, which
    # left that pattern in PATTERN_PRIORITY but in neither confidence set — so
    # an AWS secret key matched, claimed its span (masking any later pattern on
    # the line), and was then dropped without a redaction or a log record.
    HIGH_CONFIDENCE_NAMES as HIGH_CONFIDENCE,
)
from allowlist import is_suppressed  # noqa: E402
from hook_logging import defer_log, emit, log_guard_ran  # noqa: E402

# Scan the entire tool response, not just a leading prefix: a live credential
# positioned past a large block of benign output (verbose logs, env dumps) must
# still be caught. Bounded by MAX_STDIN_BYTES, the cap the hook reads under.
MAX_SCAN_BYTES = MAX_STDIN_BYTES

# Heuristic keyword-plus-value shapes. These stay honoring a line-level "# demo"
# comment, which the structural patterns above deliberately ignore. Every name in
# PATTERN_PRIORITY must land in exactly one of the two sets — test_plugin.py
# asserts that partition, since falling through both is a silent detection gap.
LOW_CONFIDENCE = frozenset([
    "generic_secret", "password_assignment",
])

# head/tail are intentionally NOT here: they are common ways to read a
# credential file, so their output must still be scanned for secrets.
# git subcommands that PRINT FILE CONTENTS or patch hunks (``diff``, ``show``,
# ``blame``, and ``log -p``) are likewise excluded — a committed secret is
# routinely surfaced there and must still be scanned/redacted. ``git log``
# without a patch flag prints only commit metadata, so it stays safe.
SAFE_SIMPLE_COMMANDS = re.compile(
    r"^\s*(git\s+(log|status|branch|remote|tag|rev-parse)"
    r"|ls\b|find\s|wc\s|pwd|which\s|type\s"
    r"|mkdir\s|mv\s|cp\s|trash\s|stat\s|file\s)"
)

# Patch-printing flags that make ``git log`` dump full diff hunks (and thus any
# committed secret). Their presence downgrades ``git log`` from safe to scanned.
GIT_PATCH_FLAG = re.compile(r"(?:^|\s)(?:-p|-u|-U\d*|--patch|--unified)\b")

HAS_CHAINING = re.compile(r"[;&|]")

CREDENTIAL_SEARCH_INDICATORS = re.compile(
    r"(?i)(grep|rg|ag|ack)\s+.*(AKIA|ghp_|sk-ant|BEGIN.*PRIVATE|api.key"
    r"|secret|token|password)"
)


def is_safe_command(command: str) -> bool:
    if HAS_CHAINING.search(command):
        return False
    if not SAFE_SIMPLE_COMMANDS.match(command):
        return False
    if re.match(r"^\s*git\s+log\b", command) and GIT_PATCH_FLAG.search(command):
        return False
    return True


def is_credential_search(command: str) -> bool:
    return bool(CREDENTIAL_SEARCH_INDICATORS.search(command))


PATTERN_PRIORITY = [
    "anthropic_key", "aws_access_key", "aws_sts_key", "aws_secret_key",
    "github_token", "github_oauth_token", "github_server_token",
    "github_fine_grained", "gitlab_token", "npm_token", "private_key_header",
    "slack_token", "stripe_key",
    "openai_key", "jwt_token", "generic_secret", "password_assignment",
]


def scan_output(text: str, command: str,
                context: dict | None = None) -> dict | None:
    scan_text = text[:MAX_SCAN_BYTES]
    intentional_search = is_credential_search(command)

    high_matches: list[tuple[str, str]] = []
    low_matches: list[str] = []

    ordered_patterns = [
        (n, CREDENTIAL_PATTERNS[n])
        for n in PATTERN_PRIORITY if n in CREDENTIAL_PATTERNS
    ]

    for line in scan_text.splitlines():
        matched_spans: set[tuple[int, int]] = set()
        for name, pattern in ordered_patterns:
            match = pattern.search(line)
            if not match:
                continue
            span = (match.start(), match.end())
            if any(s <= span[0] < e for s, e in matched_spans):
                continue
            matched_text = match.group(0)
            is_high = name in HIGH_CONFIDENCE
            # ``line`` here is TOOL OUTPUT -- a repo file, or a command's stdout.
            # It is attacker-controlled text, which is why the high-confidence
            # carve-out matters more in this hook than in the Write/Edit gate,
            # where the content is what Claude is writing. A real AKIA/ghp_/sk-
            # value is not neutralized by a '# demo' comment appended to the
            # line; only a fake marker inside the value itself (AWS's own
            # AKIAIOSFODNN7EXAMPLE) suppresses it. See the helper's docstring.
            if is_placeholder_credential(matched_text, line, is_high):
                continue
            if is_suppressed("output_credential_scanner", pattern_name=name):
                continue
            matched_spans.add(span)
            if is_high:
                high_matches.append((name, matched_text))
            elif name in LOW_CONFIDENCE:
                low_matches.append(name)

    if not high_matches and not low_matches:
        return None

    pattern_names = [m[0] for m in high_matches] + low_matches
    command_prefix = command[:40]

    msg = (
        f"CREDENTIAL DETECTED IN COMMAND OUTPUT: "
        f"{', '.join(set(pattern_names))}\n"
        f"The output from '{command_prefix}...' contains what appears "
        f"to be a live credential.\n"
        f"Do NOT echo, log, or forward this value. "
        f"Reference it by name only.\n"
        f"If this credential was needed for a task, suggest the user "
        f"set it as an environment variable."
    )

    if high_matches:
        redacted_text = text
        for name, matched_text in high_matches:
            redacted_text = redacted_text.replace(
                matched_text, f"[REDACTED: {name}]"
            )
        defer_log(
            "output_credential_scanner", "redact",
            pattern_matched=",".join(set(m[0] for m in high_matches)),
            command=command_prefix, context=context,
            extra={"intentional_search": intentional_search},
        )
        return {
            "hookSpecificOutput": {"updatedToolOutput": redacted_text},
            "systemMessage": msg,
        }

    defer_log(
        "output_credential_scanner", "warn_low",
        pattern_matched=",".join(set(pattern_names)),
        command=command_prefix, context=context,
    )
    return {"systemMessage": msg}


def main() -> None:
    raw = read_stdin_text(MAX_STDIN_BYTES)
    data = parse_event(raw)
    if data is None:
        emit({})
        return

    context = context_from_event(data)
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool_name == "Read":
        # Read returns file content directly: there is no command to vet and no
        # safe-command skip — a live credential in a file must be redacted before
        # it enters the transcript. The file path is the scan's source label.
        source = tool_input.get("file_path", "") or "Read"
    else:
        command = tool_input.get("command", "")
        if is_safe_command(command):
            emit({})
            return
        source = command

    response_text = data.get("tool_response", "")
    if not isinstance(response_text, str):
        response_text = json.dumps(response_text) if response_text else ""

    if not response_text:
        log_guard_ran("output_credential_scanner", context)
        emit({})
        return

    result = scan_output(response_text, source, context)
    if result is None:
        # A clean scan of real output. This is the guard whose silence mattered
        # most: it is the only thing standing between a credential in tool
        # output and the transcript, and "clean" looked exactly like "absent".
        log_guard_ran("output_credential_scanner", context)
    emit(result if result else {})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
