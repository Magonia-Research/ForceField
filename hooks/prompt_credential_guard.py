#!/usr/bin/env python3
"""UserPromptSubmit credential paste detection.

Per OWASP LLM06 (Sensitive Information Disclosure):
Catches credentials pasted into user messages.
Blocks private keys, warns on high-confidence API tokens.

Input: JSON on stdin (Claude Code UserPromptSubmit hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_STDIN_BYTES = 1_048_576

sys.path.insert(0, str(Path(__file__).parent))
from credential_guard import CREDENTIAL_PATTERNS, is_fake_value  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

BLOCK_PATTERNS = frozenset(["private_key_header"])

WARN_PATTERNS = frozenset([
    "aws_access_key", "anthropic_key", "github_token",
    "github_fine_grained", "slack_token", "stripe_key",
])

SUGGESTED_ENV_VARS = {
    "aws_access_key": "AWS_ACCESS_KEY_ID",
    "anthropic_key": "ANTHROPIC_API_KEY",
    "github_token": "GITHUB_TOKEN",
    "github_fine_grained": "GITHUB_TOKEN",
    "slack_token": "SLACK_TOKEN",
    "stripe_key": "STRIPE_API_KEY",
}

PATTERN_DESCRIPTIONS = {
    "aws_access_key": "AWS access key",
    "anthropic_key": "Anthropic API key",
    "github_token": "GitHub personal access token",
    "github_fine_grained": "GitHub fine-grained token",
    "slack_token": "Slack token",
    "stripe_key": "Stripe API key",
    "private_key_header": "private key",
}

NEARBY_FAKE_CONTEXT = re.compile(
    r"(?i)(example|placeholder|dummy|fake|test|sample|demo)"
)


def has_nearby_fake_context(prompt: str, match_start: int) -> bool:
    window_start = max(0, match_start - 50)
    window_end = min(len(prompt), match_start + 50)
    window = prompt[window_start:window_end]
    return bool(NEARBY_FAKE_CONTEXT.search(window))


def scan_prompt(prompt: str) -> dict | None:
    offset = 0
    for line in prompt.splitlines(keepends=True):
        for name, pattern in CREDENTIAL_PATTERNS.items():
            if name not in BLOCK_PATTERNS and name not in WARN_PATTERNS:
                continue

            match = pattern.search(line)
            if not match:
                continue

            matched_text = match.group(0)
            if is_fake_value(matched_text, line):
                continue
            abs_pos = offset + match.start()
            if has_nearby_fake_context(prompt, abs_pos):
                continue
            if is_suppressed("prompt_credential_guard", pattern_name=name):
                continue

            if name in BLOCK_PATTERNS:
                log_security_event(
                    "prompt_credential_guard", "block",
                    pattern_matched=name,
                )
                return {
                    "decision": "block",
                    "reason": (
                        "Your message contains a private key "
                        "(-----BEGIN ... PRIVATE KEY-----).\n"
                        "Private keys should never be pasted into chat "
                        "— they persist in conversation history.\n"
                        "Instead: reference the key file path, or set "
                        "an environment variable."
                    ),
                }

            if name in WARN_PATTERNS:
                env_var = SUGGESTED_ENV_VARS.get(name, "CREDENTIAL")
                description = PATTERN_DESCRIPTIONS.get(name, "credential")
                log_security_event(
                    "prompt_credential_guard", "warn",
                    pattern_matched=name,
                )
                return {
                    "additionalContext": (
                        f"The user's message contains what appears to be "
                        f"a raw {description}.\n"
                        f"Do NOT echo this value in your response.\n"
                        f"If the user needs you to use this credential, "
                        f"suggest:\n"
                        f"  export {env_var}=<value>\n"
                        f"Then reference os.environ[\"{env_var}\"] in code."
                    ),
                }

        offset += len(line)

    return None


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        data = json.loads(raw)
    except Exception:
        json.dump({}, sys.stdout)
        return

    prompt = (
        data.get("prompt")
        or data.get("user_prompt")
        or data.get("message")
        or ""
    )

    if not prompt:
        json.dump({}, sys.stdout)
        return

    result = scan_prompt(prompt)
    json.dump(result if result else {}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
