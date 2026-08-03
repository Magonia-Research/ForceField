#!/usr/bin/env python3
"""Credential leak blocker hook for Claude Code.

Detects credential patterns in Write/Edit file content.
Returns "ask" so the user can approve or deny.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import re
import sys
from fnmatch import fnmatch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import CREDENTIAL_PATTERNS, MAX_STDIN_BYTES  # noqa: E402,F401
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from allowlist import is_suppressed  # noqa: E402
from hook_logging import (  # noqa: E402
    clamp_and_emit, defer_log, emit, log_guard_ran,
)

# ``CREDENTIAL_PATTERNS`` is defined in ``patterns`` and re-exported here: six
# other guards already import it from this module, and ``hook_logging`` needs it
# to scrub its own records, which it cannot get from here without a cycle.

# Conventional test/fixture DIRECTORY names, matched exactly per path segment.
# A prefix glob (``test*``) plus ``fnmatch`` on the full path was unsafe: its
# ``*`` spans ``/``, so any component beginning with ``test`` (``testbed``,
# ``testing``) skipped the credential scan entirely. Exact-segment matching keeps
# genuine fixture trees excluded while still inspecting a real secret written to
# an incidental ``test*``-named directory.
EXCLUDED_DIR_SEGMENTS = frozenset([
    "test", "tests", "__tests__", "testdata", "test-data", "test_data",
    "fixture", "fixtures", "__fixtures__",
])

# Non-secret example/env FILENAMES, matched against the basename only so the
# wildcard cannot cross a directory separator.
EXCLUDED_FILENAME_GLOBS = ("*.env", "*.env.*", "*.example")

FAKE_VALUE_PATTERNS = re.compile(
    r"(?i)(example|placeholder|dummy|fake|test|xxx|your[_-])"
)

COMMENT_CONTEXT = re.compile(
    r"#\s*(example|placeholder|sample|demo|fake|dummy)", re.IGNORECASE
)


def is_excluded_path(file_path: str) -> bool:
    """True for a conventional test/fixture path or an env/example file.

    Segment-aware: a wildcard never crosses ``/``, and directory names must match
    ``EXCLUDED_DIR_SEGMENTS`` exactly, so a real credential written under an
    incidental ``test*``-named directory is still scanned.
    """
    segments = [seg for seg in file_path.replace("\\", "/").split("/") if seg]
    if not segments:
        return False
    for segment in segments[:-1]:
        if segment.lower() in EXCLUDED_DIR_SEGMENTS:
            return True
    basename = segments[-1]
    for glob_pattern in EXCLUDED_FILENAME_GLOBS:
        if fnmatch(basename, glob_pattern):
            return True
    return False


def is_fake_value(matched_text: str, line: str) -> bool:
    if FAKE_VALUE_PATTERNS.search(matched_text):
        return True
    if COMMENT_CONTEXT.search(line):
        return True
    return False


# Structural credential tokens whose SHAPE is self-authenticating (an AKIA id,
# a ghp_/sk- token, a PEM private-key header, an aws_secret_access_key=<40>
# assignment). An attacker-appended line comment ("# sample", "# demo") must not
# neutralize these — only a fake marker inside the matched VALUE itself (AWS's
# own AKIAIOSFODNN7EXAMPLE) does. Low-confidence heuristic assignments still
# honor the line-level comment context.
HIGH_CONFIDENCE_NAMES = frozenset([
    "openai_key", "anthropic_key", "github_token", "github_oauth_token",
    "github_server_token", "github_fine_grained", "gitlab_token", "npm_token",
    "aws_access_key", "aws_sts_key", "aws_secret_key", "private_key_header",
    "jwt_token", "slack_token", "stripe_key",
])


def is_placeholder_credential(
    matched_text: str, line: str, high_confidence: bool,
) -> bool:
    """Whether a credential match is a placeholder/example, not a live secret.

    High-confidence structural tokens are suppressed only by a fake marker
    inside the matched value; a line-level comment an attacker can append does
    NOT neutralize them. Low-confidence heuristic matches still honor the
    comment context via ``is_fake_value``.
    """
    if high_confidence:
        return bool(FAKE_VALUE_PATTERNS.search(matched_text))
    return is_fake_value(matched_text, line)


def find_credential(
    text: str,
    patterns: dict = CREDENTIAL_PATTERNS,
    high_confidence: frozenset = HIGH_CONFIDENCE_NAMES,
) -> tuple[str, str, str] | None:
    """First real credential in ``text`` as ``(name, matched_text, line)``.

    One scan for the four guards that inspect text for secrets — the Write/Edit
    gate, the agent-prompt gate, and the two subagent-output scanners — so the
    placeholder rule cannot drift between them. Neither argument is mutated.

    ``high_confidence`` is a parameter rather than a constant because
    ``agent_guard`` deliberately treats a narrower set as high-confidence in an
    agent prompt than the file gate does, which changes both the deny/ask split
    and whether a line comment can suppress the match.
    """
    for line in text.splitlines():
        for name, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                matched_text = match.group(0)
                if is_placeholder_credential(
                    matched_text, line, name in high_confidence,
                ):
                    continue
                return (name, matched_text, line)
    return None


def extract_content(tool_name: str, tool_input: dict) -> tuple[str, str]:
    """Extract (file_path, new_content) from tool input."""
    file_path = tool_input.get("file_path", "")

    if tool_name == "Write":
        content = tool_input.get("content", "")
    elif tool_name == "Edit":
        content = tool_input.get("new_string", "")
    else:
        content = ""

    return (file_path, content)


def check_content(
    content: str, file_path: str,
) -> tuple[str, str, str] | None:
    """Return (pattern_name, matched_text, line) or None."""
    if not content:
        return None

    if is_excluded_path(file_path):
        return None

    result = find_credential(content)
    if result is None:
        return None
    name, matched_text, line = result
    return (name, matched_text, line.strip())


PATTERN_DESCRIPTIONS = {
    "openai_key": "OpenAI API key",
    "anthropic_key": "Anthropic API key",
    "github_token": "GitHub personal access token",
    "github_oauth_token": "GitHub OAuth token",
    "github_server_token": "GitHub server-to-server token",
    "github_fine_grained": "GitHub fine-grained token",
    "gitlab_token": "GitLab personal access token",
    "npm_token": "npm access token",
    "aws_access_key": "AWS access key ID",
    "aws_sts_key": "AWS STS temporary access key",
    "aws_secret_key": "AWS secret access key",
    "private_key_header": "Private key file",
    "jwt_token": "JWT token",
    "generic_secret": "API key/secret assignment",
    "password_assignment": "Hardcoded password",
    "slack_token": "Slack token",
    "stripe_key": "Stripe API key",
}


def format_alert(
    pattern_name: str, matched_text: str, file_path: str,
) -> str:
    desc = PATTERN_DESCRIPTIONS.get(pattern_name, "Credential pattern")
    redacted = matched_text[:8] + "..." + matched_text[-4:]
    msg = f"CREDENTIAL GUARD: {desc}\n\n"
    msg += f"Pattern: {pattern_name}\n"
    msg += f"Value: {redacted}\n"
    msg += f"File: {file_path}\n\n"
    msg += "Before approving:\n"
    msg += "- Is this a real credential or a placeholder?\n"
    msg += "- Should this be in a .env file instead?\n"
    msg += "- Is the file in .gitignore?"
    return msg


def main() -> None:
    raw = read_stdin_text(MAX_STDIN_BYTES)
    input_data = parse_event(raw)
    if input_data is None:
        emit({})
        return

    context = context_from_event(input_data)
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    file_path, content = extract_content(tool_name, tool_input)

    if not content:
        # Nothing to scan -- an edit with no content, or a tool shape this guard
        # does not read. Silent before; now distinguishable from not running.
        log_guard_ran("credential_guard", context)
        emit({})
        return

    result = check_content(content, file_path)

    if result is None:
        defer_log(
            "credential_guard", "allow", file_path=file_path, context=context,
        )
        emit({})
        return

    pattern_name, matched_text, _ = result

    if is_suppressed(
        "credential_guard", pattern_name=pattern_name, file_path=file_path,
    ):
        defer_log(
            "credential_guard", "allow",
            pattern_matched=pattern_name, file_path=file_path, context=context,
            extra={"suppressed": True},
        )
        emit({})
        return

    response = clamp_and_emit(
        "credential_guard", "ask",
        format_alert(pattern_name, matched_text, file_path),
        pattern_matched=pattern_name, file_path=file_path, context=context,
    )
    emit(response)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
