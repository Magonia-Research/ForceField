#!/usr/bin/env python3
"""Supply chain guard hook for Claude Code.

Detects typosquatting and dangerous package install patterns.
Returns "ask" so the user can approve or deny.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_STDIN_BYTES = 1_048_576  # 1 MiB guard against oversized input

sys.path.insert(0, str(Path(__file__).parent))
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402


def damerau_levenshtein(s: str, t: str) -> int:
    """Compute Damerau-Levenshtein distance between two strings.

    Supports insertions, deletions, substitutions, and transpositions.
    """
    len_s = len(s)
    len_t = len(t)

    # Short-circuit: if length difference alone exceeds max useful threshold
    if abs(len_s - len_t) > 2:
        return abs(len_s - len_t)

    # Use dict-based approach for the full DL (not optimal substrings)
    d: dict[tuple[int, int], int] = {}
    for i in range(-1, len_s + 1):
        d[i, -1] = i + 1
    for j in range(-1, len_t + 1):
        d[-1, j] = j + 1

    for i in range(len_s):
        for j in range(len_t):
            cost = 0 if s[i] == t[j] else 1
            d[i, j] = min(
                d[i - 1, j] + 1,       # deletion
                d[i, j - 1] + 1,       # insertion
                d[i - 1, j - 1] + cost,  # substitution
            )
            if i > 0 and j > 0 and s[i] == t[j - 1] and s[i - 1] == t[j]:
                d[i, j] = min(d[i, j], d[i - 2, j - 2] + 1)  # transposition

    return d[len_s - 1, len_t - 1]


# Popular packages per ecosystem — DL compares against these
POPULAR_PYPI: frozenset[str] = frozenset([
    "requests", "urllib3", "boto3", "botocore", "setuptools", "pip",
    "certifi", "charset-normalizer", "idna", "typing-extensions",
    "numpy", "packaging", "aiobotocore", "pyyaml", "s3transfer",
    "python-dateutil", "cryptography", "six", "wheel", "jinja2",
    "colorama", "markupsafe", "platformdirs", "pydantic", "pytest",
    "grpcio", "pillow", "protobuf", "filelock", "aiohttp", "attrs",
    "pyasn1", "pandas", "virtualenv", "wrapt", "click", "flask",
    "django", "sqlalchemy", "celery", "redis", "psycopg2", "httpx",
    "beautifulsoup4", "lxml", "scipy", "matplotlib", "scikit-learn",
    "tensorflow", "torch", "transformers", "fastapi", "uvicorn",
    "gunicorn", "black", "ruff", "mypy", "pylint", "flake8",
    "tox", "coverage", "hypothesis", "faker", "rich", "typer",
    "httptools", "orjson", "msgpack", "toml", "tomli",
])

POPULAR_NPM: frozenset[str] = frozenset([
    "lodash", "express", "axios", "react", "react-dom", "next",
    "typescript", "webpack", "babel", "eslint", "prettier",
    "jest", "mocha", "chai", "commander", "chalk", "inquirer",
    "glob", "minimist", "yargs", "dotenv", "cors", "helmet",
    "jsonwebtoken", "bcrypt", "uuid", "moment", "dayjs", "date-fns",
    "socket.io", "mongoose", "sequelize", "prisma", "graphql",
    "apollo-server", "electron", "vue", "angular", "svelte",
    "tailwindcss", "postcss", "sass", "less", "nodemon", "pm2",
    "puppeteer", "playwright", "cypress", "vitest", "esbuild",
    "vite", "rollup", "parcel", "turbo", "nx", "lerna",
    "create-react-app", "create-next-app", "create-vite",
])

POPULAR_CARGO: frozenset[str] = frozenset([
    "tokio", "serde", "serde_json", "reqwest", "clap", "rand",
    "anyhow", "thiserror", "tracing", "hyper", "axum", "actix-web",
    "sqlx", "diesel", "sea-orm", "regex", "rayon", "crossbeam",
    "futures", "async-trait", "tower", "tonic", "prost",
    "chrono", "uuid", "url", "bytes", "log", "env_logger",
    "config", "toml", "once_cell", "lazy_static", "itertools",
    "syn", "quote", "proc-macro2", "cargo-edit", "cargo-watch",
    "ripgrep", "fd-find", "bat", "exa", "starship", "zoxide",
])

# Map installer regex → popular package set
_ECOSYSTEM_MAP: list[tuple[re.Pattern[str], frozenset[str]]] = [
    (re.compile(r"pip3?\s+install\s+"), POPULAR_PYPI),
    (re.compile(r"(uvx|pipx\s+install|pipx\s+run)\s+"), POPULAR_PYPI),
    (re.compile(r"(npm\s+install|pnpm\s+add|yarn\s+add)\s+"), POPULAR_NPM),
    (re.compile(r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+"), POPULAR_NPM),
    (re.compile(r"cargo\s+(install|add)\s+"), POPULAR_CARGO),
]

TYPOSQUAT_CHECKS: list[tuple[re.Pattern[str], list[tuple[re.Pattern[str], str]]]] = [
    (re.compile(r"pip3?\s+install\s+"), [
        (re.compile(r"requets"), "requests"),
        (re.compile(r"requsts"), "requests"),
        (re.compile(r"request\b"), "requests"),
        (re.compile(r"beautifulsoup\b"), "beautifulsoup4"),
        (re.compile(r"python-dateutil2"), "python-dateutil"),
        (re.compile(r"urlib3"), "urllib3"),
        (re.compile(r"urlib"), "urllib3"),
        (re.compile(r"dateuti"), "python-dateutil"),
        (re.compile(r"colorsama"), "colorama"),
        (re.compile(r"colourama"), "colorama"),
    ]),
    (re.compile(r"(npm\s+install|pnpm\s+add|yarn\s+add)\s+"), [
        (re.compile(r"loadsh"), "lodash"),
        (re.compile(r"lodahs"), "lodash"),
        (re.compile(r"expres\b"), "express"),
        (re.compile(r"axois"), "axios"),
        (re.compile(r"axos"), "axios"),
        (re.compile(r"recat"), "react"),
        (re.compile(r"reactjs\b"), "react"),
        (re.compile(r"electorn"), "electron"),
    ]),
    (re.compile(r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+"), [
        (re.compile(r"loadsh"), "lodash"),
        (re.compile(r"lodahs"), "lodash"),
        (re.compile(r"expres\b"), "express"),
        (re.compile(r"axois"), "axios"),
        (re.compile(r"recat"), "react"),
        (re.compile(r"electorn"), "electron"),
        (re.compile(r"creat-react-app"), "create-react-app"),
        (re.compile(r"create-raect-app"), "create-react-app"),
    ]),
    (re.compile(r"(uvx|pipx\s+install|pipx\s+run)\s+"), [
        (re.compile(r"requets"), "requests"),
        (re.compile(r"beautifulsoup\b"), "beautifulsoup4"),
        (re.compile(r"colorsama"), "colorama"),
        (re.compile(r"colourama"), "colorama"),
        (re.compile(r"rufff"), "ruff"),
    ]),
    (re.compile(r"cargo\s+(install|add)\s+"), [
        (re.compile(r"tokoi"), "tokio"),
        (re.compile(r"serdee"), "serde"),
        (re.compile(r"reqwests"), "reqwest"),
    ]),
]

DANGEROUS_INSTALL = {
    "pipe_to_shell": re.compile(
        r"(curl|wget)\s+.*\|\s*(sudo\s+)?"
        r"(bash|sh|zsh|dash|python[23]?|ruby|perl|/bin/sh|/bin/bash)"
    ),
    "pip_url_install": re.compile(
        r"pip3?\s+install\s+https?://"
    ),
    "npm_url_install": re.compile(
        r"npm\s+install\s+https?://"
    ),
    "npx_url_exec": re.compile(
        r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+https?://"
    ),
    "npx_scoped_unknown": re.compile(
        r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+@[^/]+/[^\s]+.*--yes"
    ),
    "uvx_url_exec": re.compile(
        r"(uvx|pipx\s+run)\s+https?://"
    ),
    "force_scripts": re.compile(
        r"npm\s+install\s+.*--ignore-scripts\s*=\s*false"
    ),
    "global_install": re.compile(
        r"(npm\s+install\s+-g\s+|pip3?\s+install\s+(?!-e\s)(?!--editable))"
    ),
    "system_pkg_install": re.compile(
        r"(sudo\s+)?(apt(-get)?\s+install|dnf\s+install|yum\s+install|pacman\s+-S)"
    ),
}

ALLOWLIST_PATTERNS = [
    re.compile(r"pipx\s+install\b"),
    re.compile(r"uv\s+pip\s+install\s+.*--require-hashes"),
    re.compile(r"pip3?\s+install\s+-e\s"),
    re.compile(r"pip3?\s+install\s+--editable\s"),
    re.compile(r"npx\s+--package="),
]


def is_allowlisted(command: str) -> bool:
    for pattern in ALLOWLIST_PATTERNS:
        if pattern.search(command):
            return True
    return False


_PKG_VERSION_STRIP = re.compile(r"[=<>!@\[].*")


def _dl_threshold(name_length: int) -> int:
    """Max edit distance allowed based on package name length."""
    if name_length <= 3:
        return 0  # Too short — exact match only
    if name_length <= 6:
        return 1
    return 2


def _check_dl_against_ecosystem(
    pkg_name: str, popular: frozenset[str],
) -> str | None:
    """Check a package name against popular packages using DL distance.

    Returns the correct popular package name if typosquat detected, else None.
    Skips exact matches (those are legitimate installs).
    """
    if pkg_name in popular:
        return None

    threshold = _dl_threshold(len(pkg_name))
    if threshold == 0:
        return None

    best_match: str | None = None
    best_dist = threshold + 1

    for popular_name in popular:
        # Skip if length difference alone exceeds threshold
        if abs(len(pkg_name) - len(popular_name)) > threshold:
            continue
        dist = damerau_levenshtein(pkg_name, popular_name)
        if dist <= threshold and dist < best_dist:
            best_dist = dist
            best_match = popular_name

    return best_match


def check_typosquat(command: str) -> tuple[str, str, str] | None:
    """Return (typo, correct_package, installer) or None.

    Two-pass detection:
    1. Regex — known-bad typos (zero false positives)
    2. Damerau-Levenshtein — novel typos against popular packages
    """
    # Pass 1: regex (fast, certain)
    for installer_re, typos in TYPOSQUAT_CHECKS:
        match = installer_re.search(command)
        if not match:
            continue
        after_install = command[match.end():]
        packages = re.split(r"\s+", after_install.strip())
        for pkg in packages:
            if pkg.startswith("-"):
                continue
            pkg_clean = _PKG_VERSION_STRIP.sub("", pkg)
            for typo_re, correct in typos:
                if typo_re.search(pkg_clean):
                    return (pkg_clean, correct, match.group(0).strip())

    # Pass 2: Damerau-Levenshtein (catches novel typos)
    for installer_re, popular in _ECOSYSTEM_MAP:
        match = installer_re.search(command)
        if not match:
            continue
        after_install = command[match.end():]
        packages = re.split(r"\s+", after_install.strip())
        for pkg in packages:
            if pkg.startswith("-"):
                continue
            pkg_clean = _PKG_VERSION_STRIP.sub("", pkg)
            if not pkg_clean:
                continue
            correct = _check_dl_against_ecosystem(pkg_clean, popular)
            if correct:
                return (pkg_clean, correct, match.group(0).strip())

    return None


HARD_DENY_PATTERNS: frozenset[str] = frozenset([
    "pipe_to_shell",
])


def check_dangerous(command: str) -> tuple[str, str] | None:
    """Return (pattern_name, matched_text) or None."""
    for name, pattern in DANGEROUS_INSTALL.items():
        match = pattern.search(command)
        if match:
            return (name, match.group(0))
    return None


DANGER_DESCRIPTIONS = {
    "pipe_to_shell": "Piping remote script directly to shell",
    "pip_url_install": "Installing Python package from arbitrary URL",
    "npm_url_install": "Installing npm package from arbitrary URL",
    "npx_url_exec": "Executing package from arbitrary URL via npx/bunx",
    "npx_scoped_unknown": "Auto-approving scoped package execution (--yes bypass)",
    "uvx_url_exec": "Executing Python package from arbitrary URL via uvx/pipx",
    "force_scripts": "Force-enabling install scripts (bypasses safety)",
    "global_install": "Global package install (bypasses project isolation)",
    "system_pkg_install": "System package manager modifies host OS",
}

DANGER_ALTERNATIVES = {
    "pipe_to_shell": "Download first, inspect, then run: curl -o script.sh URL && cat script.sh && bash script.sh",
    "pip_url_install": "Use a requirements file with hashes: uv pip install --require-hashes -r requirements.txt",
    "npm_url_install": "Add to package.json and audit: pnpm add <pkg> && pnpm audit",
    "npx_url_exec": "Install the package first with pnpm add, then run locally",
    "npx_scoped_unknown": "Remove --yes flag to get interactive confirmation, or install the package first",
    "uvx_url_exec": "Install with pipx install <pkg> first, then run the installed binary",
    "force_scripts": "Remove --ignore-scripts=false and audit the package first",
    "global_install": "Use npx (Node) or pipx (Python) for isolated execution",
    "system_pkg_install": "Use a container: podman run --rm <image> apt-get install <pkg>",
}


def format_typosquat_alert(
    typo: str, correct: str, installer: str,
) -> str:
    msg = f"SUPPLY CHAIN GUARD: Possible typosquat\n\n"
    msg += f"Package: {typo}\n"
    msg += f"Did you mean: {correct}\n"
    msg += f"Installer: {installer}\n\n"
    msg += "Before approving:\n"
    msg += f"- Verify the package name is correct (not '{correct}'?)\n"
    msg += "- Check the package on the registry for download count/age\n"
    msg += "- Typosquatting is a common supply chain attack vector"
    return msg


def format_danger_alert(pattern_name: str, matched_text: str) -> str:
    desc = DANGER_DESCRIPTIONS.get(pattern_name, "Dangerous install pattern")
    alt = DANGER_ALTERNATIVES.get(pattern_name, "Consider a safer alternative")
    msg = f"SUPPLY CHAIN GUARD: {desc}\n\n"
    msg += f"Pattern: {pattern_name}\n"
    msg += f"Matched: {matched_text[:120]}\n\n"
    msg += "Before approving:\n"
    msg += "- Is this source trusted and verified?\n"
    msg += "- Could this install malicious code?\n"
    msg += f"- Safer alternative: {alt}"
    return msg


def main() -> None:
    """Entry point: read stdin, check for supply-chain threats."""
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        json.dump({}, sys.stdout)
        return

    typo_result = check_typosquat(command)
    if typo_result:
        typo, correct, installer = typo_result
        pattern_key = f"typosquat:{typo}"
        if is_suppressed("supply_chain_guard", pattern_name=pattern_key):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_key, command=command,
                extra={"suppressed": True},
            )
            json.dump({}, sys.stdout)
            return
        log_security_event(
            "supply_chain_guard", "ask",
            pattern_matched=pattern_key,
            command=command,
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": format_typosquat_alert(
                    typo, correct, installer
                ),
            },
        }
        json.dump(response, sys.stdout)
        return

    if is_allowlisted(command):
        log_security_event(
            "supply_chain_guard", "allow", command=command,
        )
        json.dump({}, sys.stdout)
        return

    danger_result = check_dangerous(command)
    if danger_result:
        pattern_name, matched_text = danger_result
        if is_suppressed("supply_chain_guard", pattern_name=pattern_name):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_name, command=command,
                extra={"suppressed": True},
            )
            json.dump({}, sys.stdout)
            return
        decision = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
        log_security_event(
            "supply_chain_guard", decision,
            pattern_matched=pattern_name,
            command=command,
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": format_danger_alert(
                    pattern_name, matched_text
                ),
            },
        }
        json.dump(response, sys.stdout)
        return

    log_security_event(
        "supply_chain_guard", "allow", command=command,
    )
    json.dump({}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
