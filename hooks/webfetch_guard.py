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

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES, looks_encoded  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from allowlist import is_suppressed  # noqa: E402
from hook_logging import clamp_and_emit, defer_log, emit  # noqa: E402
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
        r"[?&](data|secret|password|passwd|pw|pwd|token|auth|access[-_]?token"
        r"|api[-_]?key|apikey|private[-_]?key|session(?:[-_]?id)?|sid|cookie"
        r"|jwt|bearer|credentials?)=",
        re.IGNORECASE,
    ),
    "long_query_value": re.compile(r"[?&][^=&]+=[^=&\s]{80,}"),
}

# F2: the query detectors above anchor on ``[?&]``, so a base64 blob smuggled in
# a path segment escaped every check. A pure-alphanumeric run of >=48 chars that
# mixes letter case AND contains a digit is the signature of base64-encoded
# binary. Excluding ``-``/``_``/``+``/``/`` keeps hyphen/underscore slugs and
# article titles (their separators break the run) from matching, and requiring a
# digit plus mixed case spares single-case hex hashes (git SHAs, content
# digests) and shorter file identifiers (Drive/Docs IDs are < 48 chars).
_PATH_BLOB = re.compile(r"[A-Za-z0-9]{48,}")

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

# Cloud instance-metadata addresses, compared against a canonicalized IP so that
# re-encodings (IPv4-mapped IPv6, short/octal/hex forms) resolve to the same key.
_METADATA_IPS = frozenset(
    ipaddress.ip_address(a)
    for a in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254")
)


def _parse_ipv4_octet(part: str) -> int | None:
    """Parse one inet_aton IPv4 field (decimal, ``0``-octal, or ``0x``-hex)."""
    lowered = part.lower()
    try:
        if lowered.startswith("0x"):
            return int(part, 16) if len(part) > 2 else None
        if part.startswith("0") and len(part) > 1:
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Canonicalize an inet_aton-style IPv4 literal without any DNS resolution.

    Handles the 2-, 3-, and 4-part dotted forms with decimal, octal, or hex
    fields (e.g. ``127.1``, ``0177.0.0.1``, ``0x7f.0x0.0x0.0x1``). Single-field
    forms are left to ``_SSRF_ENCODED``. Returns None for anything that is not a
    purely-numeric dotted literal, so real hostnames fall through untouched.
    """
    parts = host.split(".")
    if not 2 <= len(parts) <= 4:
        return None
    octets = []
    for part in parts:
        value = _parse_ipv4_octet(part)
        if value is None or value < 0:
            return None
        octets.append(value)
    packed = 0
    for value in octets[:-1]:
        if value > 0xFF:
            return None
        packed = (packed << 8) | value
    trailing_bytes = 4 - (len(octets) - 1)
    last = octets[-1]
    if last >= (1 << (8 * trailing_bytes)):
        return None
    packed = (packed << (8 * trailing_bytes)) | last
    try:
        return ipaddress.IPv4Address(packed)
    except ValueError:
        return None


def _classify_ip(ip: ipaddress._BaseAddress, private_name: str) -> str | None:
    """Name the SSRF class of a canonicalized IP, unwrapping IPv4-mapped IPv6."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip in _METADATA_IPS:
        return "ssrf_metadata"
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return private_name
    return None


def _canonical_ssrf(host: str) -> str | None:
    """Catch dangerous hosts that evade the literal regexes by re-encoding.

    Covers IPv4-mapped / expanded / zero-compressed IPv6 and inet_aton-style
    obfuscated IPv4. Public destinations return None so legitimate fetches to
    numeric hosts are never flagged.
    """
    if ":" in host:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        return _classify_ip(ip, "ssrf_private_host")
    ipv4 = _parse_obfuscated_ipv4(host)
    if ipv4 is None:
        return None
    return _classify_ip(ipv4, "ssrf_encoded_ip")


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
    encoded = _canonical_ssrf(host)
    if encoded:
        return (encoded, raw_host)
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
    "encoded_data_in_path": "Base64 blob smuggled in the URL path (possible exfiltration)",
    "sensitive_param": "Sensitive keyword (secret/token/session/cookie/jwt) in a URL parameter",
    "long_query_value": "Unusually long URL parameter value (possible data smuggling)",
}


def _encoded_blob_in_path(url: str) -> str | None:
    """Return a base64-looking blob smuggled in the URL path, else None.

    Inspects only the path component (via ``urlsplit`` — no network), so a
    private IP or ordinary token elsewhere in the URL is not considered.
    """
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    for run in _PATH_BLOB.findall(path):
        if looks_encoded(run):
            return run
    return None


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

    blob = _encoded_blob_in_path(url)
    if blob:
        return ("encoded_data_in_path", blob)

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
    raw = read_stdin_text(MAX_STDIN_BYTES)
    input_data = parse_event(raw)
    if input_data is None:
        emit({})
        return

    context = context_from_event(input_data)
    tool_input = input_data.get("tool_input", {})
    url = tool_input.get("url", "") or tool_input.get("URL", "")

    if not url:
        emit({})
        return

    result = check_url(url)

    if result is None:
        defer_log("webfetch_guard", "allow", command=url,
                           context=context)
        emit({})
        return

    pattern_name, matched_text = result

    if is_suppressed("webfetch_guard", pattern_name=pattern_name):
        defer_log(
            "webfetch_guard", "allow",
            pattern_matched=pattern_name, command=url, context=context,
            extra={"suppressed": True},
        )
        emit({})
        return

    natural = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
    response = clamp_and_emit(
        "webfetch_guard", natural, format_alert(pattern_name, matched_text),
        pattern_matched=pattern_name, command=url, context=context,
    )
    emit(response)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
