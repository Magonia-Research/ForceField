#!/usr/bin/env python3
"""WebFetch outbound-URL guard hook for Claude Code.

Inspects the target URL BEFORE a WebFetch request leaves the host. Blocks
outbound requests to known exfiltration / tunneling domains and flags URLs
that appear to smuggle data — encoded blobs, embedded credentials, or
sensitive-keyword parameters — in the query string.

PreToolUse is the correct event: an outbound guard must judge the URL before
the fetch happens, not after. Fail-open — any crash or malformed input allows
the fetch, matching the plugin-wide invariant.

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
from exfil_guard import EXFIL_PATTERNS as _EXFIL_PATTERNS  # noqa: E402

# Single source of truth for known exfil / OOB-interaction / tunneling domains.
_EXFIL_DOMAINS = _EXFIL_PATTERNS["exfil_domains"]

URL_PATTERNS = {
    "credential_in_url": re.compile(
        r"(sk-[A-Za-z0-9]{20,}"
        r"|gh[posur]_[A-Za-z0-9]{36}"
        r"|AKIA[0-9A-Z]{16}"
        r"|glpat-[A-Za-z0-9_-]{20}"
        r"|xox[bpas]-[A-Za-z0-9-]{10,}"
        r"|npm_[A-Za-z0-9]{36})"
    ),
    "encoded_data_in_url": re.compile(
        r"[?&][^=&]+=(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-fA-F]{40,})"
    ),
    "sensitive_param": re.compile(
        r"[?&](data|secret|password|passwd|token|auth|access[-_]?token"
        r"|api[-_]?key|apikey|private[-_]?key)=",
        re.IGNORECASE,
    ),
    "long_query_value": re.compile(r"[?&][^=&]+=[^=&\s]{80,}"),
}

# SSRF: the request DESTINATION host itself is dangerous — cloud metadata
# endpoints, loopback, private ranges, link-local, *.internal/*.local, and
# obfuscated (decimal/hex/octal) IPs. Anchored to the URL host so a private IP
# appearing only in a path or query string does not trigger.
_URL_HOST = re.compile(
    r"^\s*[a-zA-Z][\w+.-]*://(?:[^/@\s]*@)?(\[[0-9A-Fa-f:.]+\]|[^/:?#\s]+)"
)
_SSRF_METADATA = re.compile(
    r"^(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200"
    r"|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)$",
    re.IGNORECASE,
)
_SSRF_PRIVATE = re.compile(
    r"^(?:localhost|0\.0\.0\.0"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|::1|fe80:[0-9A-Fa-f:]*|f[cd][0-9A-Fa-f]{2}:[0-9A-Fa-f:]*"
    r"|[\w.-]+\.(?:internal|local|localdomain|home\.arpa))$",
    re.IGNORECASE,
)
_SSRF_ENCODED = re.compile(r"^(?:0x[0-9A-Fa-f]+|0[0-7]+|\d{8,10})$")


def _ssrf_host(url: str) -> tuple[str, str] | None:
    """Return an (ssrf_name, raw_host) detection for a dangerous destination host."""
    match = _URL_HOST.match(url)
    if not match:
        return None
    raw_host = match.group(1)
    host = raw_host.strip("[]")
    if _SSRF_METADATA.match(host):
        return ("ssrf_metadata", raw_host)
    if _SSRF_PRIVATE.match(host):
        return ("ssrf_private_host", raw_host)
    if _SSRF_ENCODED.match(host):
        return ("ssrf_encoded_ip", raw_host)
    return None


# Only the domain match is high-confidence enough to hard-block. Everything
# else is "ask" so a false positive costs a confirmation, never a broken fetch.
HARD_DENY_PATTERNS: frozenset[str] = frozenset(["exfil_domain"])

PATTERN_RISKS = {
    "exfil_domain": "Known exfiltration / OOB-interaction / tunneling domain",
    "ssrf_metadata": "Request to a cloud instance-metadata endpoint (SSRF / credential theft)",
    "ssrf_private_host": "Request to a loopback / private / link-local host (SSRF)",
    "ssrf_encoded_ip": "Request to an obfuscated (decimal/hex/octal) IP address (SSRF)",
    "credential_in_url": "Credential or token embedded in the URL",
    "encoded_data_in_url": "Base64/hex-encoded blob in a URL parameter",
    "sensitive_param": "Sensitive keyword (data/secret/token/password) in a URL parameter",
    "long_query_value": "Unusually long URL parameter value (possible data smuggling)",
}


def check_url(url: str) -> tuple[str, str] | None:
    """Return (pattern_name, matched_text) for a suspicious URL, else None.

    Args:
        url: The WebFetch target URL.

    Returns:
        A (pattern_name, matched_text) tuple naming the first detection, or
        None when the URL is clean. ``exfil_domain`` is the only deny; the
        remaining detections are advisory (ask).
    """
    if not url:
        return None

    domain_match = _EXFIL_DOMAINS.search(url)
    if domain_match:
        return ("exfil_domain", domain_match.group(0))

    ssrf = _ssrf_host(url)
    if ssrf:
        return ssrf

    for name in (
        "credential_in_url",
        "encoded_data_in_url",
        "sensitive_param",
        "long_query_value",
    ):
        match = URL_PATTERNS[name].search(url)
        if match:
            return (name, match.group(0))

    return None


def format_alert(pattern_name: str, matched_text: str) -> str:
    """Build the human-readable permission-decision reason."""
    risk = PATTERN_RISKS.get(pattern_name, "Potential data exfiltration via WebFetch")
    msg = f"WEBFETCH GUARD: {pattern_name}\n\n"
    msg += f"Matched: {matched_text[:120]}\n"
    msg += f"Risk: {risk}\n\n"
    msg += "Review:\n"
    msg += "- Was this exact URL provided by the user, or assembled from file/conversation data?\n"
    msg += "- Does the URL carry secrets or encoded data in its parameters?\n"
    msg += "- Is the destination host trusted?"
    return msg


def main() -> None:
    """Entry point: read stdin, inspect the WebFetch URL, emit a decision."""
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    url = tool_input.get("url", "") or tool_input.get("URL", "")

    if not url:
        json.dump({}, sys.stdout)
        return

    result = check_url(url)

    if result is None:
        log_security_event("webfetch_guard", "allow", command=url)
        json.dump({}, sys.stdout)
        return

    pattern_name, matched_text = result

    if is_suppressed("webfetch_guard", pattern_name=pattern_name):
        log_security_event(
            "webfetch_guard", "allow",
            pattern_matched=pattern_name, command=url,
            extra={"suppressed": True},
        )
        json.dump({}, sys.stdout)
        return

    decision = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
    log_security_event(
        "webfetch_guard", decision,
        pattern_matched=pattern_name, command=url,
    )

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format_alert(pattern_name, matched_text),
        },
    }
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
