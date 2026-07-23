#!/usr/bin/env python3
"""Credential leak blocker hook for Claude Code.

Detects credential patterns in Write/Edit file content.
Returns "ask" so the user can approve or deny.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from fnmatch import fnmatch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

CREDENTIAL_PATTERNS = {
    "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "github_oauth_token": re.compile(r"gho_[a-zA-Z0-9]{36}"),
    "github_server_token": re.compile(r"ghs_[a-zA-Z0-9]{36}"),
    "github_fine_grained": re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"),
    "gitlab_token": re.compile(r"glpat-[a-zA-Z0-9_-]{20}"),
    "npm_token": re.compile(r"npm_[a-zA-Z0-9]{36}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_sts_key": re.compile(r"ASIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*[a-zA-Z0-9/+=]{40}"
    ),
    "private_key_header": re.compile(
        r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"
    ),
    "jwt_token": re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\."
    ),
    "generic_secret": re.compile(
        r"(?i)(api_key|api_secret|secret_key|access_token|auth_token)"
        r"\s*[=:]\s*['\"]?[a-zA-Z0-9_/+=.-]{16,}"
    ),
    "password_assignment": re.compile(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
    "slack_token": re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    "stripe_key": re.compile(r"(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}"),
}

EXCLUDED_FILE_GLOBS = [
    "*.env", "*.env.*",
    "**/test*/**", "**/fixture*/**", "**/*.example",
    "**/tests/**", "**/testdata/**",
]

FAKE_VALUE_PATTERNS = re.compile(
    r"(?i)(example|placeholder|dummy|fake|test|xxx|your[_-])"
)

COMMENT_CONTEXT = re.compile(
    r"#\s*(example|placeholder|sample|demo|fake|dummy)", re.IGNORECASE
)


def is_excluded_path(file_path: str) -> bool:
    for glob_pattern in EXCLUDED_FILE_GLOBS:
        if fnmatch(file_path, glob_pattern):
            return True
    return False


def is_fake_value(matched_text: str, line: str) -> bool:
    if FAKE_VALUE_PATTERNS.search(matched_text):
        return True
    if COMMENT_CONTEXT.search(line):
        return True
    return False


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

    for line in content.splitlines():
        for name, pattern in CREDENTIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                matched_text = match.group(0)
                if is_fake_value(matched_text, line):
                    continue
                return (name, matched_text, line.strip())

    return None


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
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    file_path, content = extract_content(tool_name, tool_input)

    if not content:
        json.dump({}, sys.stdout)
        return

    result = check_content(content, file_path)

    if result is None:
        log_security_event(
            "credential_guard", "allow", file_path=file_path,
        )
        json.dump({}, sys.stdout)
        return

    pattern_name, matched_text, _ = result

    if is_suppressed(
        "credential_guard", pattern_name=pattern_name, file_path=file_path,
    ):
        log_security_event(
            "credential_guard", "allow",
            pattern_matched=pattern_name, file_path=file_path,
            extra={"suppressed": True},
        )
        json.dump({}, sys.stdout)
        return

    log_security_event(
        "credential_guard", "ask",
        pattern_matched=pattern_name, file_path=file_path,
    )

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": format_alert(
                pattern_name, matched_text, file_path
            ),
        },
    }
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
