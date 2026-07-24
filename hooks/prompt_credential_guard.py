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

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from credential_guard import CREDENTIAL_PATTERNS, is_fake_value  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

BLOCK_PATTERNS = frozenset(["private_key_header"])

# Every high-confidence, distinctive-prefix token type carried by
# ``CREDENTIAL_PATTERNS`` warns here. Low-confidence assignment patterns
# (``generic_secret``, ``password_assignment``) and public-by-nature JWTs are
# deliberately excluded to avoid over-warning; the ``is_fake_value`` /
# ``has_nearby_fake_context`` heuristics still suppress documented placeholders.
WARN_PATTERNS = frozenset([
    "openai_key", "anthropic_key",
    "aws_access_key", "aws_sts_key",
    "github_token", "github_oauth_token", "github_server_token",
    "github_fine_grained", "gitlab_token", "npm_token",
    "slack_token", "stripe_key",
])

SUGGESTED_ENV_VARS = {
    "openai_key": "OPENAI_API_KEY",
    "anthropic_key": "ANTHROPIC_API_KEY",
    "aws_access_key": "AWS_ACCESS_KEY_ID",
    "aws_sts_key": "AWS_ACCESS_KEY_ID",
    "github_token": "GITHUB_TOKEN",
    "github_oauth_token": "GITHUB_TOKEN",
    "github_server_token": "GITHUB_TOKEN",
    "github_fine_grained": "GITHUB_TOKEN",
    "gitlab_token": "GITLAB_TOKEN",
    "npm_token": "NPM_TOKEN",
    "slack_token": "SLACK_TOKEN",
    "stripe_key": "STRIPE_API_KEY",
}

PATTERN_DESCRIPTIONS = {
    "openai_key": "OpenAI API key",
    "anthropic_key": "Anthropic API key",
    "aws_access_key": "AWS access key",
    "aws_sts_key": "AWS STS temporary access key",
    "github_token": "GitHub personal access token",
    "github_oauth_token": "GitHub OAuth token",
    "github_server_token": "GitHub server-to-server token",
    "github_fine_grained": "GitHub fine-grained token",
    "gitlab_token": "GitLab personal access token",
    "npm_token": "npm access token",
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
            is_block = name in BLOCK_PATTERNS
            # A private-key PEM header is unambiguous: no benign paste contains
            # `-----BEGIN ... PRIVATE KEY-----`. The fake-context heuristics (a
            # nearby 'test'/'demo' word, an inline comment) must NOT be able to
            # defeat the block — one such word must not let a live key persist
            # in conversation history. Warn patterns keep both heuristics to
            # avoid over-warning on documented placeholder tokens.
            if not is_block:
                if is_fake_value(matched_text, line):
                    continue
                abs_pos = offset + match.start()
                if has_nearby_fake_context(prompt, abs_pos):
                    continue
            if is_suppressed("prompt_credential_guard", pattern_name=name):
                continue

            if is_block:
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
