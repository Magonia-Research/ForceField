#!/usr/bin/env python3
"""Credential-file access guard for Claude Code Bash commands.

ForceField already redacts credential values *after* a command runs
(``output_credential_scanner``). This guard closes the gap on the read side:
it asks before a shell command reads a known credential store
(``cat .env``, ``head ~/.ssh/id_rsa``, ``bat ~/.aws/credentials``, ...), so the
secret is never dumped into the transcript in the first place.

Every finding is "ask" (never a hard block): reading a local ``.env`` during
development is legitimate, so the user confirms per call and a per-project
allowlist (``credential_access_guard``) can suppress a pattern outright.

Imported by ``security_dispatcher`` — it has no standalone ``main()``.
"""

from __future__ import annotations

import re

try:
    from normalize import detection_variants
except Exception:  # pragma: no cover - fail-open if the module is unavailable
    def detection_variants(command: str) -> tuple[str, ...]:
        return (command,)

# A sensitive read requires BOTH a file-reading command AND a credential-store
# target. Requiring a reader token keeps the false-positive rate low: ``rm .env``
# or ``echo .env`` do not read the file, so they do not match here (they are
# handled, if at all, by the other guards).
#
# Left boundary accepts a shell separator, a path prefix (``/bin/cat``), a
# wrapping quote (``"cat"``) or a leading backslash (``\cat``); the raw+normalized
# match (see ``check_command``) additionally undoes intra-word quote/backslash
# splitting (``c""at``). The trailing lookahead requires the reader to be a whole
# command word terminated by a separator/quote/redirect/EOL, so ``catalog`` and a
# mid-path component (``/var/cat/x``) do not match while ``cat`` still does.
_READERS = re.compile(
    r"(?:^|[\s;&|(<>`$/'\"\\])"
    r"(?:cat|head|tail|less|more|bat|strings|xxd|od|hexdump"
    r"|base64|base32|nl|sed|awk|dd|cut|tac|rev)"
    r"(?=$|[\s'\"<>|;&)])",
    re.IGNORECASE,
)

# Credential stores. ``.env`` excludes the conventional non-secret example
# variants (``.env.example`` / ``.env.sample`` / ...) while still matching real
# secret files like ``.env`` and ``.env.local``.
CREDENTIAL_ACCESS_PATTERNS: dict[str, re.Pattern[str]] = {
    "dotenv_file": re.compile(
        r"\.env(?:rc)?\b(?!\.(?:example|sample|template|dist|defaults?))",
        re.IGNORECASE,
    ),
    "ssh_key": re.compile(r"\.ssh/", re.IGNORECASE),
    "private_key_file": re.compile(
        r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b", re.IGNORECASE
    ),
    "aws_credentials": re.compile(r"\.aws/", re.IGNORECASE),
    "gcloud_credentials": re.compile(r"\.config/gcloud/", re.IGNORECASE),
    "gpg_key": re.compile(r"\.gnupg/", re.IGNORECASE),
    "netrc_file": re.compile(r"\.netrc\b", re.IGNORECASE),
    "npmrc_token": re.compile(r"\.npmrc\b", re.IGNORECASE),
    "pypirc_token": re.compile(r"\.pypirc\b", re.IGNORECASE),
    "pgpass_file": re.compile(r"\.pgpass\b", re.IGNORECASE),
    "git_credentials": re.compile(
        r"\.git-credentials\b|\.config/git/credentials\b", re.IGNORECASE
    ),
    "docker_auth": re.compile(r"\.docker/config\.json\b", re.IGNORECASE),
    "kube_config": re.compile(r"\.kube/", re.IGNORECASE),
    "gh_token": re.compile(r"\.config/gh/", re.IGNORECASE),
    "azure_credentials": re.compile(r"\.azure/", re.IGNORECASE),
    "macos_keychain": re.compile(r"Library/Keychains/", re.IGNORECASE),
    "shadow_file": re.compile(r"/etc/shadow\b", re.IGNORECASE),
    "terraform_state": re.compile(r"\.tfstate\b", re.IGNORECASE),
}

# Nothing here is a hard block — reading a credential file has legitimate uses,
# so a deny would violate the zero-false-positive rule.
HARD_DENY_PATTERNS: frozenset[str] = frozenset()

# One rung below ask: no prompt, but the model is told what the file is and what
# not to do with it.
#
# ``.env`` is the only member and the asymmetry is the point. Every other store
# here holds nothing BUT authentication material, so a read of one is worth
# stopping for. A ``.env`` is a project's ordinary configuration file that also
# tends to hold secrets: grepping one variable out of it is routine, and the
# measured prompts were exactly that — a price constant read from a carbon
# ledger's ``factors.env``. Interrupting each of those buys nothing, because the
# risk is not the read. It is the VALUE reaching the transcript, and that is a
# handling instruction rather than a permission question.
#
# The read side keeps two other controls regardless: ``output_credential_scanner``
# redacts credential values out of the result, and a per-project allowlist can
# still suppress this entirely.
WARN_PATTERNS: frozenset[str] = frozenset(["dotenv_file"])


def check_command(command: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_text)`` for a credential read, else None.

    Matches against both the raw command and its normalized form so shell
    obfuscation (``\\cat``, ``c""at``, an ``${IFS}`` split) cannot hide the
    reader token. Both the reader and a credential store must be present in the
    same variant for a match.
    """
    for text in detection_variants(command):
        if not _READERS.search(text):
            continue
        for name, pattern in CREDENTIAL_ACCESS_PATTERNS.items():
            match = pattern.search(text)
            if match:
                return (name, match.group(0))
    return None


PATTERN_RISKS = {
    "dotenv_file": "Reading a .env file exposes application secrets",
    "ssh_key": "Reading SSH keys exposes private authentication material",
    "private_key_file": "Reading a private key file exposes authentication material",
    "aws_credentials": "Reading AWS credentials exposes cloud access keys",
    "gcloud_credentials": "Reading gcloud config exposes cloud credentials",
    "gpg_key": "Reading GnuPG data exposes private keys",
    "netrc_file": "Reading .netrc exposes stored login credentials",
    "npmrc_token": "Reading .npmrc exposes the npm auth token",
    "pypirc_token": "Reading .pypirc exposes PyPI upload credentials",
    "pgpass_file": "Reading .pgpass exposes stored PostgreSQL passwords",
    "git_credentials": "Reading the git credential store exposes stored git passwords",
    "docker_auth": "Reading Docker config exposes registry auth tokens",
    "kube_config": "Reading kube config exposes cluster credentials",
    "gh_token": "Reading GitHub CLI config exposes the gh auth token",
    "azure_credentials": "Reading Azure config exposes cloud credentials",
    "macos_keychain": "Reading a macOS Keychain exposes stored secrets",
    "shadow_file": "Reading /etc/shadow exposes hashed account passwords",
    "terraform_state": "Reading Terraform state exposes plaintext resource secrets",
}


def format_alert(pattern_name: str, matched_text: str) -> str:
    """Build the reason text for a credential-file read.

    A ``WARN_PATTERNS`` member is addressed to the model rather than to the
    user: nothing is being approved, so "before approving" would be advice
    nobody is in a position to take. What it needs instead is what to do with
    what it is about to see.
    """
    risk = PATTERN_RISKS.get(pattern_name, "Reading a credential store")
    if pattern_name in WARN_PATTERNS:
        return (
            f"CREDENTIAL ACCESS GUARD: {pattern_name} (not blocked)\n\n"
            f"Matched: {matched_text[:120]}\n"
            f"Risk: {risk}\n\n"
            "This command reads a .env file. It is not being stopped, and it "
            "does not need approval.\n\n"
            "Handle the contents as secrets:\n"
            "- Do NOT echo, print, cat or otherwise reproduce any value from "
            "it in your reply, in a summary, or in a file you write.\n"
            "- Do NOT pass a value from it into a subagent prompt, a URL, a "
            "commit message, or a tool argument.\n"
            "- Refer to variables by NAME ($API_KEY, ${DATABASE_URL}), never "
            "by value; use a placeholder if you must show a line.\n"
            "- Read only the key you actually need. If you only need to know "
            "whether a variable is set, test for it rather than printing it."
        )
    msg = f"CREDENTIAL ACCESS GUARD: {pattern_name}\n\n"
    msg += f"Matched: {matched_text[:120]}\n"
    msg += f"Risk: {risk}\n\n"
    msg += "Reading a secret into the transcript can leak it to logs, "
    msg += "context, or a subagent.\n\n"
    msg += "Before approving:\n"
    msg += "- Do you need the secret's value, or just to confirm the file exists?\n"
    msg += "- Prefer referencing the variable (e.g. $API_KEY) over printing it.\n"
    msg += "- Suppress in .claude/hook-allowlist.json if this is routine here."
    return msg
