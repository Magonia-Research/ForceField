#!/usr/bin/env python3
"""MCP tool monitoring guard for Claude Code.

Detects sensitive data leakage through MCP tool arguments.
MCP tools with network access can exfiltrate data via search queries,
fetch URLs, or tool arguments.

Returns "ask" if sensitive data is detected in MCP tool calls.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402
from credential_guard import CREDENTIAL_PATTERNS, is_fake_value  # noqa: E402

EXFIL_INDICATORS = {
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
    "exfil_domain": re.compile(
        r"(ngrok\.io|requestbin\.com|hookbin\.com|pipedream\.net"
        r"|burpcollaborator\.net|interact\.sh|webhook\.site)"
    ),
    "encoded_url_data": re.compile(
        r"https?://.*[?&][^=]+=[A-Za-z0-9+/]{40,}={0,2}"
    ),
}

NETWORK_CAPABLE_PREFIXES = [
    "mcp__exa__",
    "mcp__context7__",
    "mcp__greptile__",
    "mcp__playwright__",
    "mcp__github__",
    "mcp__gitlab__",
    "mcp__linear__",
    "mcp__discord__",
    "mcp__telegram__",
    "mcp__slack__",
    "mcp__firebase__",
    "mcp__asana__",
]


def is_network_capable(tool_name: str) -> bool:
    for prefix in NETWORK_CAPABLE_PREFIXES:
        if tool_name.startswith(prefix):
            return True
    if tool_name.startswith("mcp__") and "fetch" in tool_name.lower():
        return True
    return False


def extract_all_string_values(obj, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a JSON-like object."""
    if depth > 10:
        return []
    values = []
    if isinstance(obj, str):
        values.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            values.extend(extract_all_string_values(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(extract_all_string_values(item, depth + 1))
    return values


def check_for_credentials(text: str) -> tuple[str, str] | None:
    """Scan text for a real credential, skipping placeholder/example values.

    Uses ``credential_guard``'s shared pattern set and ``is_fake_value`` so MCP
    argument scanning matches the file-write guard and does not flag obvious
    placeholders. Scans line by line to give ``is_fake_value`` its line context.
    """
    for line in text.splitlines():
        for name, pattern in CREDENTIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                matched_text = match.group(0)
                if is_fake_value(matched_text, line):
                    continue
                return (name, matched_text)
    return None


def check_for_exfil(text: str) -> tuple[str, str] | None:
    for name, pattern in EXFIL_INDICATORS.items():
        match = pattern.search(text)
        if match:
            return (name, match.group(0))
    return None


def format_alert(
    pattern_name: str, matched_text: str, tool_name: str, category: str,
) -> str:
    redacted = matched_text[:12] + "..." + matched_text[-4:]
    msg = f"MCP GUARD: {category} in tool arguments\n\n"
    msg += f"Tool: {tool_name}\n"
    msg += f"Pattern: {pattern_name}\n"
    msg += f"Value: {redacted}\n\n"
    msg += "Before approving:\n"
    msg += "- Is this data intended to be sent to this MCP service?\n"
    msg += "- Could this leak credentials or sensitive data?\n"
    msg += "- Does this tool need access to this information?"
    return msg


def _respond(
    tool_name: str, category: str, result: tuple[str, str], net: bool,
) -> dict | None:
    """Build an ask response for a detected pattern, honoring suppression."""
    pattern_name, matched_text = result
    if is_suppressed("mcp_guard", pattern_name=pattern_name):
        log_security_event(
            "mcp_guard", "allow",
            pattern_matched=pattern_name,
            extra={"tool": tool_name, "network_capable": net, "suppressed": True},
        )
        return None
    log_security_event(
        "mcp_guard", "ask",
        pattern_matched=pattern_name,
        extra={"tool": tool_name, "network_capable": net},
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": format_alert(
                pattern_name, matched_text, tool_name, category,
            ),
        },
    }


def evaluate_mcp_tool(tool_name: str, tool_input: dict) -> dict | None:
    """Scan an MCP tool call for credential/exfil leakage; return ask or None.

    Every ``mcp__*`` tool is scanned by default: any MCP server can be an
    exfiltration channel (email draft, doc/file create, webhook relay, code
    execution), so the hardcoded network-capable prefix list is only a
    severity hint recorded in the log, not the gate that decides whether to
    scan.
    """
    if not tool_name.startswith("mcp__"):
        return None

    combined = "\n".join(extract_all_string_values(tool_input))
    if not combined:
        return None

    net = is_network_capable(tool_name)

    cred_result = check_for_credentials(combined)
    if cred_result:
        return _respond(tool_name, "Credential", cred_result, net)

    exfil_result = check_for_exfil(combined)
    if exfil_result:
        return _respond(tool_name, "Exfiltration indicator", exfil_result, net)

    log_security_event(
        "mcp_guard", "allow",
        extra={"tool": tool_name, "network_capable": net},
    )
    return None


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}
    response = evaluate_mcp_tool(tool_name, tool_input)
    json.dump(response if response else {}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
