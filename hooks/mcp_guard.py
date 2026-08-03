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

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import patterns as _patterns  # noqa: E402
from patterns import (  # noqa: E402
    MAX_SCAN_BYTES,
    MAX_STDIN_BYTES,
    looks_encoded,
    extract_string_values as extract_all_string_values,
)
from allowlist import is_suppressed  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from hook_logging import (  # noqa: E402
    clamp_and_emit, defer_log, emit, log_guard_ran,
)
from credential_guard import CREDENTIAL_PATTERNS, FAKE_VALUE_PATTERNS  # noqa: E402
from webfetch_guard import check_url as check_outbound_url  # noqa: E402
from exfil_guard import EXFIL_PATTERNS as _EXFIL_PATTERNS  # noqa: E402

EXFIL_INDICATORS = {
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
    # Single source of truth for known exfil / OOB-interaction / tunneling
    # domains, imported the way ``webfetch_guard`` already does. The
    # hand-copied local list had drifted to 7 of the canonical 18, and the gap
    # was live for a SCHEMELESS domain mention: ``check_urls`` runs first but
    # its extractor requires a scheme, so a bare hostname reached only this
    # pattern. The local key name is kept — it is the reported
    # ``forcefield.pattern`` and the allowlist suppression key.
    "exfil_domain": _EXFIL_PATTERNS["exfil_domains"],
    "encoded_url_data": _patterns.ENCODED_URL_DATA,
}

# Any URL embedded in a tool argument, pulled out so the outbound-destination
# checks in ``webfetch_guard.check_url`` (SSRF hosts, relay domains, encoded
# query blobs) can run against it from the URL start where the host anchor sits.
# The lookbehind and the bounded scheme run keep this linear. Unanchored, every
# character of a long ``[a-zA-Z0-9+.-]`` run began a candidate scheme that scanned
# to end of input before failing on ``://`` — quadratic, and this guard had no
# scan cap, so a large MCP argument blew the 5s timeout and the guard was killed
# without a verdict. A scheme never follows a scheme character.
_URL_IN_TEXT = re.compile(
    r"(?<![a-zA-Z0-9+.-])[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s\"'<>)\]}]{1,4096}"
)

# A base64 blob split into sub-60-char pieces to slip under ``base64_blob``:
# two or more long (>=16 char) base64 tokens joined by whitespace, dots, hyphens
# or underscores (array joins, "insert a separator every N chars"). The token
# floor keeps ordinary words out; the reassembled-length + mixed-class checks in
# ``_looks_encoded`` keep prose, hex digests and single-case identifiers out.
_CHUNKED_B64 = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{16,4096}"
    r"(?:[\s._-]{1,16}[A-Za-z0-9+/=]{16,4096}){1,4096}"
)
_B64_SEPARATORS = re.compile(r"[\s._-]+")

# Provider credential formats missing from the shared credential_guard set.
# These apply ONLY to MCP arguments (message bodies, queries, field values) --
# never source files -- so a bare, fixed-prefix token is enough to flag and no
# assignment is required. Each prefix+length is distinctive, so a match alone is
# false-positive-safe. Every hit resolves to "ask", never a hard deny.
MCP_EXTRA_CREDENTIAL_PATTERNS = {
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "google_oauth_token": re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),
    "sendgrid_key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "twilio_api_key": re.compile(r"\bSK[0-9a-f]{32}\b"),
    "twilio_account_sid": re.compile(r"\bAC[0-9a-f]{32}\b"),
    "digitalocean_token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "slack_app_token": re.compile(r"(?:xapp|xoxe)[.-][A-Za-z0-9.-]{6,}"),
}

# A secret stated in prose ("the db password is <value>") or assigned without
# quotes ("password: <value>") -- forms the structured password/secret patterns
# (which require a quoted or =/: assignment) miss. Precision comes from the
# value: a >=10-char non-space run carrying lower+upper+digit is secret-shaped,
# not an English word, and a password/secret keyword must sit within a short
# window, so ordinary prose ("the password is incorrect") does not match.
_PROSE_SECRET = re.compile(
    r"(?i)\b(?:passwords?|passphrases?|passwd|pwd|secrets?)\b"
    r"[^\n]{0,40}?(?:\bis\b|\bwas\b|[:=])\s*['\"]?"
    r"(?=[^\s'\"]*[a-z])(?=[^\s'\"]*[A-Z])(?=[^\s'\"]*\d)[^\s'\"]{10,}"
)

# Shared set first (so provider-specific names win their own prefixes), then the
# MCP-only extras, then the prose catcher last.
_MCP_CREDENTIAL_PATTERNS = dict(CREDENTIAL_PATTERNS)
_MCP_CREDENTIAL_PATTERNS.update(MCP_EXTRA_CREDENTIAL_PATTERNS)
_MCP_CREDENTIAL_PATTERNS["prose_secret"] = _PROSE_SECRET

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


def check_for_credentials(text: str) -> tuple[str, str] | None:
    """Scan text for a real credential, skipping only placeholder values.

    Uses ``credential_guard``'s shared pattern set. A match is skipped only when
    the matched value ITSELF looks like a placeholder (``FAKE_VALUE_PATTERNS``).
    Unlike the file-write guard, comment context does NOT suppress a hit: an MCP
    argument is a message body, query or field value, not source code, so a
    trailing ``# example`` must never let a live key reach the service.
    """
    for line in text.splitlines():
        for name, pattern in _MCP_CREDENTIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                matched_text = match.group(0)
                if FAKE_VALUE_PATTERNS.search(matched_text):
                    continue
                return (name, matched_text)
    return None


def check_for_exfil(text: str) -> tuple[str, str] | None:
    for name, pattern in EXFIL_INDICATORS.items():
        match = pattern.search(text)
        if match:
            return (name, match.group(0))
    return None


def check_urls(text: str) -> tuple[str, str] | None:
    """Inspect every URL in the arguments for a dangerous outbound destination.

    Reuses the WebFetch guard's ``check_url`` so an MCP fetch/browse tool is held
    to the same outbound policy: cloud-metadata / loopback / private hosts
    (SSRF), known relay domains, embedded credentials and encoded query blobs all
    return a detection. Each URL is matched from its scheme so ``check_url``'s
    host anchor lines up.
    """
    for match in _URL_IN_TEXT.finditer(text):
        result = check_outbound_url(match.group(0))
        if result:
            return result
    return None


def check_for_chunked_exfil(text: str) -> tuple[str, str] | None:
    """Catch a base64 blob split into <60-char chunks to evade ``base64_blob``.

    Reassembles a run of two or more long base64 tokens separated by whitespace,
    dots, hyphens or underscores (array joins, "insert a separator every N
    chars") and flags it only when the concatenation reaches 60 chars and carries
    the mixed upper/lower/digit signature of encoded data.
    """
    for match in _CHUNKED_B64.finditer(text):
        run = match.group(0)
        joined = _B64_SEPARATORS.sub("", run)
        if len(joined) >= 60 and looks_encoded(joined):
            return ("chunked_base64", run[:80])
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
    context: dict | None = None,
) -> dict | None:
    """Build an ask response for a detected pattern, honoring suppression."""
    pattern_name, matched_text = result
    if is_suppressed("mcp_guard", pattern_name=pattern_name):
        defer_log(
            "mcp_guard", "allow",
            pattern_matched=pattern_name, context=context,
            extra={"tool": tool_name, "network_capable": net, "suppressed": True},
        )
        return None
    return clamp_and_emit(
        "mcp_guard", "ask",
        format_alert(pattern_name, matched_text, tool_name, category),
        pattern_matched=pattern_name, context=context,
    )


def evaluate_mcp_tool(
    tool_name: str, tool_input: dict, context: dict | None = None,
) -> dict | None:
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
        # An MCP call with no string arguments at all. "Scanned and clean" and
        # "never ran" were the same silence here; at debug level they are not.
        log_guard_ran("mcp_guard", context)
        return None
    # ``injection_defense`` has had a scan cap since it was written; this guard
    # did not, and read up to MAX_STDIN_BYTES. Detectors run over the head of the
    # payload, which is where a URL or a credential in a real MCP argument sits.
    combined = combined[:MAX_SCAN_BYTES]

    net = is_network_capable(tool_name)

    cred_result = check_for_credentials(combined)
    if cred_result:
        return _respond(tool_name, "Credential", cred_result, net, context)

    url_result = check_urls(combined)
    if url_result:
        return _respond(tool_name, "Outbound URL", url_result, net, context)

    exfil_result = check_for_exfil(combined)
    if exfil_result:
        return _respond(tool_name, "Exfiltration indicator", exfil_result, net,
                        context)

    chunked_result = check_for_chunked_exfil(combined)
    if chunked_result:
        return _respond(tool_name, "Exfiltration indicator", chunked_result, net,
                        context)

    defer_log(
        "mcp_guard", "allow", context=context,
        extra={"tool": tool_name, "network_capable": net},
    )
    return None


def main() -> None:
    raw = read_stdin_text(MAX_STDIN_BYTES)
    input_data = parse_event(raw)
    if input_data is None:
        emit({})
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}
    response = evaluate_mcp_tool(
        tool_name, tool_input, context_from_event(input_data),
    )
    emit(response)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
