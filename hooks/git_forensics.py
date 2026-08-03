#!/usr/bin/env python3
"""Evidence layer for the git repo-execution guard.

``git_guard`` matches command *shape*: it can tell that a recursive clone is
about to happen, not whether the repository on the other end is hostile. This
module supplies the evidence that turns that shape into a graded decision.

Four kinds of evidence, in ascending cost:

1. **Host preconditions** (no I/O beyond one ``git --version``). CVE-2024-32002
   and CVE-2025-48384 are both fixed in current git, and CVE-2024-32002
   additionally requires a case-insensitive filesystem. On a patched host the
   CVE rationale for prompting on every recursive clone is simply void.
2. **On-disk indicators** (one file read). For ``git submodule update`` and
   ``--recurse-submodules`` against an existing checkout, ``.gitmodules`` is
   already on disk and carries the actual exploit signatures.
3. **Repository audit** (bounded directory walk). The same indicators plus the
   artifacts that execute when a repo is merely *opened*: active hooks, an
   RCE-capable key in ``.git/config``, a repo-shipped agent config.
4. **Remote pre-flight** (one bounded HTTPS GET, allowlisted hosts only).
   ``.gitmodules`` fetched without cloning, so the decision can be made on
   content rather than on shape.

Every function fails closed *into the caller's existing behaviour*: an
unknowable answer returns ``None``, never a guess. The guard treats ``None`` as
"no new evidence" and keeps whatever decision it would have made anyway, which
preserves the fail-open invariant and means a broken probe can never turn an
``ask`` into an ``allow``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import threading
import unicodedata
import urllib.request
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import close_fd, open_regular_fd, read_fd  # noqa: E402

# ---------------------------------------------------------------------------
# 1. Host preconditions
# ---------------------------------------------------------------------------

# Patched releases per advisory, one entry per maintenance branch.
# CVE-2024-32002: https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv
_CVE_2024_32002_FIXED = (
    (2, 39, 4), (2, 40, 2), (2, 41, 1), (2, 42, 2),
    (2, 43, 4), (2, 44, 1), (2, 45, 1),
)
# CVE-2025-48384: https://github.com/git/git/security/advisories/GHSA-vwqx-4fm8-6qc9
_CVE_2025_48384_FIXED = (
    (2, 43, 7), (2, 44, 4), (2, 45, 4), (2, 46, 4),
    (2, 47, 3), (2, 48, 2), (2, 49, 1), (2, 50, 1),
)

_VERSION_RE = re.compile(r"\bgit version (\d+)\.(\d+)(?:\.(\d+))?")

# One subprocess per matched command, not per Bash call: the guard only asks for
# host preconditions once a submodule pattern has already matched.
_VERSION_TIMEOUT_S = 2.0


def git_version() -> tuple[int, int, int] | None:
    """Return the host git version as ``(major, minor, patch)``, or None.

    None on any failure — git absent, not on PATH, slow, or unparseable output.
    The caller must treat None as "unknown", never as "old" or "new".
    """
    try:
        proc = subprocess.run(
            ["git", "--version"],
            capture_output=True, text=True, timeout=_VERSION_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = _VERSION_RE.search(proc.stdout or "")
    if not match:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3)
    return (int(major), int(minor), int(patch or 0))


def _is_patched(version: tuple[int, int, int], fixes: tuple) -> bool:
    """Whether ``version`` carries the fix, respecting maintenance branches.

    A fix is backported to several branches at once, so 2.45.2 is patched for an
    advisory whose 2.45 fix was 2.45.1 but *not* for one whose 2.45 fix was
    2.45.4. Compare against the fix on the same ``major.minor`` branch when there
    is one, and against the newest branch otherwise.
    """
    same_branch = [f for f in fixes if f[:2] == version[:2]]
    if same_branch:
        return version >= max(same_branch)
    return version >= max(fixes)


def fs_case_insensitive(path: str | None = None) -> bool | None:
    """Whether ``path``'s filesystem is case-insensitive, or None if unknown.

    CVE-2024-32002 requires a case-insensitive filesystem that supports
    symlinks, so this closes that CVE specifically on a typical ext4 host. It
    does *not* close CVE-2025-48384, which needs no case collision.
    """
    directory = path if path and os.path.isdir(path) else None
    try:
        name = "ForceFieldCaseProbe"
        with tempfile.TemporaryDirectory(dir=directory) as tmp:
            with open(os.path.join(tmp, name), "w"):
                pass
            return os.path.exists(os.path.join(tmp, name.lower()))
    except OSError:
        return None


def clone_cve_exposure(path: str | None = None) -> dict:
    """Host-side exposure to the two clone-time RCE CVEs.

    Returns ``exposed`` True when at least one CVE could still fire here, False
    when both are closed by the host's own git and filesystem, and None when the
    git version could not be determined — in which case the caller must keep
    prompting.
    """
    version = git_version()
    if version is None:
        return {"exposed": None, "version": None, "reason": "git version unknown"}

    cve_2024 = not _is_patched(version, _CVE_2024_32002_FIXED)
    cve_2025 = not _is_patched(version, _CVE_2025_48384_FIXED)

    # CVE-2024-32002 needs a case-insensitive filesystem. Only consult the probe
    # when it can change the answer.
    if cve_2024 and not cve_2025:
        if fs_case_insensitive(path) is False:
            cve_2024 = False

    version_text = "%d.%d.%d" % version
    open_cves = []
    if cve_2024:
        open_cves.append("CVE-2024-32002")
    if cve_2025:
        open_cves.append("CVE-2025-48384")

    if open_cves:
        reason = "git %s is unpatched for %s" % (version_text, ", ".join(open_cves))
    else:
        reason = "git %s is patched for CVE-2024-32002 and CVE-2025-48384" % version_text

    return {
        "exposed": bool(open_cves),
        "version": version_text,
        "open_cves": open_cves,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# 2. .gitmodules indicators
# ---------------------------------------------------------------------------

# Zero-width characters that would let ".git" pass a naive equality check.
_INVISIBLE = "​‌‍﻿⁠"

_PATH_LINE = re.compile(r"(?mi)^[ \t]*path[ \t]*=[ \t]*(.+?)[ \t]*$")
_URL_LINE = re.compile(r"(?mi)^[ \t]*url[ \t]*=[ \t]*(.+?)[ \t]*$")

# Indicators that justify a hard deny: each is the literal signature of a known
# exploit, and none has a reading under which an honest repository produces it.
DENY_INDICATORS = frozenset({
    "submodule_path_trailing_cr",
    "submodule_path_dotgit_collision",
    "submodule_path_traversal",
    "submodule_url_ext_transport",
})

INDICATOR_RISKS = {
    "submodule_path_trailing_cr": (
        "A submodule path ends in a carriage return. That is the literal "
        "CVE-2025-48384 signature: git strips the CR when reading the value but "
        "not when writing it, so the submodule is checked out to a different "
        "path than the one shown, and a symlink there can land an executable "
        "post-checkout hook."
    ),
    "submodule_path_dotgit_collision": (
        "A submodule path contains a segment that resolves to '.git'. That is "
        "the CVE-2024-32002 signature: git is fooled into writing into the "
        "repository's own .git directory, planting a hook that runs while the "
        "clone is still in progress."
    ),
    "submodule_path_traversal": (
        "A submodule path escapes the working tree with '..'. Git has rejected "
        "this since the CVE-2018-11235 fix, so a repository carrying it is "
        "probing for an unpatched client."
    ),
    "submodule_url_ext_transport": (
        "A submodule URL uses the ext:: transport, which hands its value to the "
        "shell. Git ships ext:: disabled by default for exactly this reason."
    ),
}


def _segments(path_value: str) -> list[str]:
    """Split a submodule path into comparable segments."""
    return [s for s in path_value.replace("\\", "/").split("/") if s]


def _looks_like_dotgit(segment: str) -> bool:
    """Whether a path segment resolves to '.git' for a case-insensitive FS."""
    folded = unicodedata.normalize("NFKC", segment)
    for char in _INVISIBLE:
        folded = folded.replace(char, "")
    return folded.casefold().rstrip(". ") == ".git"


def scan_gitmodules(text: str) -> list[str]:
    """Return exploit indicators found in ``.gitmodules`` content.

    An empty list means the file parsed and carried none of the known
    signatures. It does not mean the repository is safe.
    """
    if not text:
        return []
    found = []

    # A trailing CR on a path line is CVE-2025-48384 -- but a .gitmodules saved
    # with Windows line endings has a CR on *every* line and is entirely benign.
    # Only a CR that singles out a path line is evidence, so require that the
    # file is not uniformly CRLF before reporting one.
    lines = text.split("\n")
    body = [ln for ln in lines if ln.strip("\r").strip()]
    uniform_crlf = bool(body) and all(ln.endswith("\r") for ln in body)
    if not uniform_crlf:
        for line in lines:
            if line.endswith("\r") and re.match(r"[ \t]*path[ \t]*=", line):
                found.append("submodule_path_trailing_cr")
                break

    for match in _PATH_LINE.finditer(text):
        segments = _segments(match.group(1).rstrip("\r"))
        if any(_looks_like_dotgit(s) for s in segments):
            found.append("submodule_path_dotgit_collision")
        if ".." in segments:
            found.append("submodule_path_traversal")

    for match in _URL_LINE.finditer(text):
        if re.match(r"(?i)^\s*ext::", match.group(1).rstrip("\r").strip()):
            found.append("submodule_url_ext_transport")

    seen = set()
    return [i for i in found if not (i in seen or seen.add(i))]


# ---------------------------------------------------------------------------
# 3. Repository audit
# ---------------------------------------------------------------------------

# git config keys whose value a later routine git command executes. Kept in sync
# with git_guard._RCE_CONFIG_KEYS; duplicated as plain names because this reads
# a config file rather than matching a command line.
_RCE_CONFIG_NAMES = (
    "hookspath", "fsmonitor", "sshcommand", "pager", "editor",
    "alternaterefscommand", "gitproxy", "external", "helper",
    "templatedir", "packobjectshook", "sequence.editor",
)

_MAX_WALK_ENTRIES = 4096


def find_repo_root(start: str) -> str | None:
    """Walk up from ``start`` to the directory containing ``.git``."""
    try:
        current = os.path.abspath(start)
    except (OSError, ValueError):
        return None
    seen = 0
    while seen < 64:
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
        seen += 1
    return None


def _read_text(path: str, limit: int = 262144) -> str | None:
    """Read a bounded amount of text, or None if unreadable.

    Every path this is called with — ``.gitmodules``, ``$GIT_DIR/config``, the
    ``.git`` file, ``.claude/settings.json`` — belongs to the *untrusted
    repository* that is the whole subject of this module, so the open must not be
    a plain one. ``open_regular_fd`` is ``O_NONBLOCK`` plus ``S_ISREG`` on the
    descriptor. Measured with a bare ``open(path, "rb")``: a ``mkfifo
    .gitmodules`` or ``mkfifo .git/config`` in a repo took the PreToolUse[Bash]
    dispatcher past its 5 s timeout with zero bytes of stdout on all four of the
    commands ``git_guard`` exists to grade, and took SessionStart ``repo_audit``
    past it too — the guard whose job is to read a repository's ``.gitmodules``
    switched off by that repository's ``.gitmodules``.
    """
    descriptor = open_regular_fd(path)
    if descriptor is None:
        return None
    try:
        return read_fd(descriptor, limit).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        close_fd(descriptor)


def _git_dir(root: str) -> str | None:
    """Resolve the repository's git directory, following a .git file if needed."""
    candidate = os.path.join(root, ".git")
    if os.path.isdir(candidate):
        return candidate
    text = _read_text(candidate, 4096)
    if text and text.startswith("gitdir:"):
        target = text.split(":", 1)[1].strip()
        if not os.path.isabs(target):
            target = os.path.join(root, target)
        return target if os.path.isdir(target) else None
    return None


def audit_repo(root: str) -> dict:
    """Audit an on-disk repository for clone-time-execution artifacts.

    Local and bounded: no network, no subprocess, one directory listing per
    hooks directory. Returns a findings dict; an unreadable repository yields
    empty findings rather than an error.
    """
    findings: dict = {"root": root, "indicators": [], "hooks": [], "config_keys": [], "agent_config": []}

    modules = _read_text(os.path.join(root, ".gitmodules"))
    if modules:
        findings["indicators"] = scan_gitmodules(modules)

    git_dir = _git_dir(root)
    if git_dir:
        _audit_hooks(git_dir, findings)
        config = _read_text(os.path.join(git_dir, "config"))
        if config:
            findings["config_keys"] = _rce_keys_in_config(config)

    # A repo-shipped agent config executes on open rather than on clone, the
    # surface behind CVE-2025-59536 / CVE-2026-21852.
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        candidate = os.path.join(root, rel)
        if os.path.exists(candidate):
            text = _read_text(candidate)
            if text and '"hooks"' in text:
                findings["agent_config"].append(rel)

    return findings


def _audit_hooks(git_dir: str, findings: dict) -> None:
    """Record executable, non-sample hooks in the repo and its submodules."""
    hook_dirs = [os.path.join(git_dir, "hooks")]
    modules_dir = os.path.join(git_dir, "modules")
    if os.path.isdir(modules_dir):
        try:
            for entry in sorted(os.listdir(modules_dir))[:64]:
                hook_dirs.append(os.path.join(modules_dir, entry, "hooks"))
        except OSError:
            pass

    counted = 0
    for hook_dir in hook_dirs:
        if counted >= _MAX_WALK_ENTRIES or not os.path.isdir(hook_dir):
            continue
        try:
            names = sorted(os.listdir(hook_dir))
        except OSError:
            continue
        for name in names:
            counted += 1
            if counted >= _MAX_WALK_ENTRIES or name.endswith(".sample"):
                continue
            full = os.path.join(hook_dir, name)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                findings["hooks"].append(os.path.relpath(full, os.path.dirname(git_dir)))


def _rce_keys_in_config(config_text: str) -> list[str]:
    """Return RCE-capable keys actually set in a git config file."""
    found = []
    section = ""
    for raw in config_text.split("\n"):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].split('"')[0].strip().lower()
            continue
        if "=" not in line or line.startswith(("#", ";")):
            continue
        key = line.split("=", 1)[0].strip().lower()
        if key in _RCE_CONFIG_NAMES or ("%s.%s" % (section, key)) in _RCE_CONFIG_NAMES:
            found.append("%s.%s" % (section, key) if section else key)
        elif section == "alias" and line.split("=", 1)[1].strip().strip("\"'").startswith("!"):
            found.append("alias.%s" % key)
    return found


# ---------------------------------------------------------------------------
# 4. Remote pre-flight
# ---------------------------------------------------------------------------

# Forge hosts whose raw-file endpoint is a predictable, fast HTTPS GET. Matched
# by EXACT host equality, never by suffix: a substring check would accept
# `evil.com/.github.com/...`, the trusted-domain bypass GitHub documented in
# its own VS Code prompt-injection writeup.
_RAW_ENDPOINTS = {
    "github.com": "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/.gitmodules",
    "www.github.com": "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/.gitmodules",
    "gitlab.com": "https://gitlab.com/{owner}/{repo}/-/raw/HEAD/.gitmodules",
    "codeberg.org": "https://codeberg.org/{owner}/{repo}/raw/branch/HEAD/.gitmodules",
}

FETCH_TIMEOUT_S = 1.5
_MAX_FETCH_BYTES = 65536

_SCP_LIKE = re.compile(r"^(?:(?P<user>[^@/]+)@)?(?P<host>[^:/@]+):(?P<path>.+)$")


def parse_remote(url: str) -> tuple[str, str, str] | None:
    """Return ``(host, owner, repo)`` for a git remote, or None if unparseable.

    Handles ``https://host/o/r.git``, ``ssh://git@host/o/r.git`` and the
    scp-like ``git@host:o/r.git``. Only the host and the first two path
    segments are used; anything deeper is not a forge repo path.
    """
    if not url or not isinstance(url, str):
        return None
    candidate = url.strip().strip("'\"")

    if "://" in candidate:
        parts = urlsplit(candidate)
        host, path = (parts.hostname or ""), parts.path
    else:
        match = _SCP_LIKE.match(candidate)
        if not match:
            return None
        host, path = match.group("host"), match.group("path")

    segments = [s for s in path.split("/") if s]
    if len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not host or not owner or not repo:
        return None
    return (host.lower(), owner, repo)


def fetch_remote_gitmodules(url: str, timeout: float = FETCH_TIMEOUT_S) -> dict:
    """Fetch a remote repository's ``.gitmodules`` without cloning it.

    A single HTTPS GET of a static text file against an exactly-matched forge
    host. No git code path runs, nothing is checked out, and no hook can fire —
    which is what makes this safe to do *before* deciding whether the real clone
    is safe.

    ``timeout`` is a deadline on the whole network operation, enforced on the
    wall clock by ``_fetch_within``; the reason it cannot be enforced by
    ``urlopen`` is measured there.

    ``status`` is one of ``ok`` (content fetched, possibly empty),
    ``absent`` (repo has no submodules), or ``unsupported`` / ``error``
    (no verdict — the caller must fall back to prompting).
    """
    parsed = parse_remote(url)
    if parsed is None:
        return {"status": "unsupported", "reason": "unparseable remote"}
    host, owner, repo = parsed

    template = _RAW_ENDPOINTS.get(host)
    if template is None:
        return {"status": "unsupported", "reason": "host %s not on the raw-fetch allowlist" % host}
    if any(c in owner + repo for c in "?#\\"):
        return {"status": "unsupported", "reason": "unexpected characters in repo path"}

    target = template.format(owner=owner, repo=repo)
    return _fetch_within(target, timeout)


def _get_gitmodules(target: str, timeout: float) -> dict:
    """The GET itself. Runs on a worker thread; never called directly."""
    request = urllib.request.Request(target, method="GET", headers={"User-Agent": "forcefield-git-guard"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https, allowlisted host
            if urlsplit(response.geturl()).scheme != "https":
                return {"status": "error", "reason": "redirected off https"}
            body = response.read(_MAX_FETCH_BYTES).decode("utf-8", "replace")
    except URLError as exc:
        reason = getattr(exc, "code", None) or getattr(exc, "reason", exc)
        if getattr(exc, "code", None) == 404:
            return {"status": "absent", "reason": "no .gitmodules", "indicators": []}
        return {"status": "error", "reason": str(reason)}
    except (OSError, ValueError, UnicodeError) as exc:
        return {"status": "error", "reason": str(exc)}

    return {
        "status": "ok",
        "url": target,
        "indicators": scan_gitmodules(body),
        "submodules": len(_PATH_LINE.findall(body)),
    }


def _fetch_within(target: str, deadline: float) -> dict:
    """Run the GET on a worker thread and give up on the wall clock.

    ``urlopen(timeout=)`` is not a bound on this operation, and the docstring
    above used to call it one. Two paths escape it, both measured in a
    ``python:3.9-slim`` container against a resolver that receives queries and
    never answers:

    * **Name resolution is outside it entirely.** ``socket.create_connection``
      calls ``getaddrinfo(host, port, 0, SOCK_STREAM)`` — a function that takes
      no timeout argument in any Python — and only then does
      ``sock.settimeout(timeout)``. Measured: ``getaddrinfo`` **10.059 s**
      (glibc's ``timeout:5 attempts:2``), and this function **10.035 s** against
      its declared 1.5.
    * **The timeout is per address, not per call.** That same function loops
      over *every* address ``getaddrinfo`` returned and calls
      ``settimeout(timeout)`` afresh inside the loop, so the real bound is
      ``len(addresses) x timeout``. Measured at four blackholed addresses:
      **6.020 s** for a declared 1.5. ``raw.githubusercontent.com`` resolves to
      **eight**, which is 12.0 s.

    Either one is past the 5 s at which Claude Code kills a hook, and that kill
    is a security boundary rather than a latency budget: ``git_guard`` calls
    this on the ``PreToolUse[Bash]`` path to decide whether a clone is safe, and
    a killed hook delivers no verdict, so a correctly computed hard deny leaves
    as a silent allow. An attacker who controls DNS for an allowlisted forge —
    or merely a resolver having a bad day — disables the guard by making it
    slow.

    So the bound is on the wall clock and covers the whole operation:
    resolution, the address loop, the TLS handshake and the read. Measured
    against the same hung resolver: **1.504 s**, and a healthy fetch costs
    0.049–0.117 s, so the deadline has ~13x headroom and manufactures no
    ``error`` verdicts on a working network.

    Abandoning the worker is safe because it is a daemon, and that is measured
    rather than assumed — a thread wedged in a GIL-releasing syscall is exactly
    the kind that could hold finalisation open. Interpreter exit with one
    abandoned costs **0.0257 s median** on Linux (n=5, max 0.0272, against a
    0.0014 s baseline) and **0.0113 s median** on macOS (n=5, max 0.0124,
    against 0.0018 s), always ``rc=0``. It cannot leak either: ``git_guard``
    calls this at most once per hook process, and the process is gone
    milliseconds later.

    Giving up returns ``error``, which is the same no-verdict the caller already
    handles by prompting — it can neither escalate to a deny nor downgrade to a
    clean clone. Failing to answer in time must never be worth more than failing
    to answer.
    """
    outcome = {}

    def run() -> None:
        try:
            outcome["result"] = _get_gitmodules(target, deadline)
        except BaseException as exc:  # noqa: BLE001 - the thread may not raise
            outcome["result"] = {"status": "error", "reason": str(exc)}

    worker = threading.Thread(target=run, name="forcefield-gitmodules", daemon=True)
    try:
        worker.start()
    except RuntimeError as exc:            # thread creation refused
        return {"status": "error", "reason": str(exc)}
    worker.join(deadline)
    result = outcome.get("result")
    if result is None:
        return {"status": "error",
                "reason": "remote fetch exceeded %.1fs" % deadline}
    return result
