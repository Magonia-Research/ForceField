#!/usr/bin/env python3
"""Pre-clone inspection of a remote repository. User-initiated, never a hook.

``git clone`` executes code *during the clone* — CVE-2024-32002 (a submodule
path colliding with ``.git`` on a case-insensitive filesystem) and
CVE-2025-48384 (a trailing carriage return on a submodule path) both land a hook
that runs before anyone has read a line of the repository. The only useful time
to read ``.gitmodules`` is therefore *before* the clone.

``git_guard`` already does that in-hook, but only for the three forges in
``git_forensics._RAW_ENDPOINTS``. That restriction is deliberate and stays: a
``PreToolUse`` hook is fail-open on a 5s budget and must not make arbitrary
outbound requests to a URL the model chose. Neither constraint applies here.
This is a command the *user* ran, against a URL the *user* typed, with no tool
call waiting on it — so it can cover the repositories the hook cannot:
self-hosted forges, SSH remotes, private instances.

Two retrieval paths, tried in that order:

1. **Raw HTTPS GET** for an allowlisted forge — ``fetch_remote_gitmodules``, no
   git code path at all.
2. **No-checkout partial clone** for everything else. ``--no-checkout`` is the
   whole reason this is allowed to exist: *both CVEs fire during checkout*, so
   with no working tree written no submodule path is ever materialized, no
   symlink is created, and no hook can run. The objects are fetched, the file is
   read out of the object store with ``git show``, and the temp dir is removed.

The verdict is recorded against ``<repo>@<commit>``, so the clone the user then
runs is quiet — and a verdict computed at one commit says nothing about another,
which is why the commit is half the key rather than a note in the record.

Named ``inspect_remote`` rather than ``inspect`` on purpose: every hook does
``sys.path.insert(0, hooks_dir)``, so a ``hooks/inspect.py`` would shadow the
stdlib ``inspect`` module for every hook process on the machine.

Stdlib only, 3.9 floor, like every other runtime module here. Usable as a CLI:

    python3 inspect_remote.py https://git.internal.corp/team/repo.git
    python3 inspect_remote.py list
    python3 inspect_remote.py forget <key-prefix>
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
import git_forensics as forensics  # noqa: E402
import memo  # noqa: E402
from hook_event import read_regular_text  # noqa: E402

# Not the hook path, so these are generous compared with FETCH_TIMEOUT_S. They
# are still hard: a clone that cannot be killed is a hung terminal.
CLONE_TIMEOUT_S = 20.0
LS_REMOTE_TIMEOUT_S = 15.0
SHOW_TIMEOUT_S = 5.0

MAX_GITMODULES_BYTES = 65_536

STORE_FILENAME = "inspections.json"
STORE_VERSION = 1
DEFAULT_TTL_DAYS = 30
MAX_STORE_BYTES = 262_144
MAX_VERDICTS = 500

# Domain separator for the MAC. The key is shared with ``memo.py`` (see
# ``_store_key``); this constant is what stops a signature minted for one store
# from verifying in the other.
_MAC_DOMAIN = b"forcefield-inspection-v1\0"

# Verdicts. ``inconclusive`` is not a mild ``clean`` — it means nothing was
# checked, and it is never recorded.
DANGER = "danger"
CLEAN = "clean"
ABSENT = "absent"
INCONCLUSIVE = "inconclusive"
_RECORDABLE = (DANGER, CLEAN, ABSENT)

# Transports git will actually be handed. Everything else is refused before a
# subprocess exists.
_SAFE_SCHEMES = frozenset({"https", "http", "ssh", "git"})

# ``<helper>::<address>`` is git's remote-helper form, and ``ext::`` is the
# member of that family that hands its address to the shell. Refusing the whole
# form rather than the one name closes it for any helper a future git ships.
_REMOTE_HELPER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.-]*::")

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

# true(1) is /usr/bin/true on macOS and /bin/true on most Linux distributions.
# Hardcoding either one means GIT_ASKPASS points at a missing file on the other
# half of the platforms this runs on.
_TRUE_CANDIDATES = ("/bin/true", "/usr/bin/true")
_NO_ASKPASS = "/nonexistent/forcefield-no-askpass"


# ---------------------------------------------------------------------------
# URL admission
# ---------------------------------------------------------------------------


def check_url(url: str) -> str | None:
    """Why ``url`` must not be handed to git, or None if it may be.

    Runs before any subprocess exists. The point of ordering it that way is that
    ``ext::`` executes its argument, so a check that happened after ``git`` had
    been spawned would already have lost.
    """
    if not url or not isinstance(url, str):
        return "no URL given"
    candidate = url.strip().strip("'\"")
    if not candidate:
        return "no URL given"
    if len(candidate) > 2_048:
        return "URL is implausibly long (%d chars)" % len(candidate)
    if any(ch in candidate for ch in "\n\r\t\0"):
        return "URL contains a control character"
    if candidate.startswith("-"):
        # git's own option parser would read it as a flag; `--upload-pack=` is
        # the classic argument-injection payload for exactly this shape.
        return "URL starts with '-', which git would parse as an option"

    helper = _REMOTE_HELPER.match(candidate)
    if helper and "://" not in candidate[: helper.end()]:
        name = candidate.split("::", 1)[0]
        return (
            "refusing the %s:: remote-helper transport — git hands a helper "
            "address to the shell, which is code execution before anything has "
            "been inspected" % name
        )

    if "://" in candidate:
        scheme = (urlsplit(candidate).scheme or "").lower()
        if scheme == "file":
            return (
                "refusing file:// — a local clone is the amplifier for "
                "CVE-2024-32002, and a repository already on this disk can be "
                "read directly rather than cloned"
            )
        if scheme not in _SAFE_SCHEMES:
            return "refusing the %s:// transport (not one of %s)" % (
                scheme,
                ", ".join(sorted(_SAFE_SCHEMES)),
            )
    elif forensics.parse_remote(candidate) is None:
        return "not a recognizable git remote"
    return None


def canonical_repo(url: str) -> str | None:
    """``host/path`` identity for a remote, or None if it will not parse.

    The FULL path, not ``parse_remote``'s first two segments: a self-hosted
    GitLab nests repositories under subgroups, so truncating at two would file
    ``corp/team/sub/alpha`` and ``corp/team/sub/beta`` under one key and let a
    verdict for one answer for the other.

    Host case is folded because DNS is case-insensitive. Path case is not: on a
    case-sensitive forge ``org/Repo`` and ``org/repo`` are two repositories, and
    folding them together is the unsafe direction.
    """
    if not url or not isinstance(url, str):
        return None
    candidate = url.strip().strip("'\"")
    if "://" in candidate:
        parts = urlsplit(candidate)
        host, path = (parts.hostname or ""), parts.path
    else:
        match = forensics._SCP_LIKE.match(candidate)
        if not match:
            return None
        host, path = match.group("host"), match.group("path")
    path = "/".join(s for s in path.split("/") if s)
    if path.endswith(".git"):
        path = path[:-4]
    if not host or not path:
        return None
    return "%s/%s" % (host.lower(), path)


# ---------------------------------------------------------------------------
# The hardened git invocation
# ---------------------------------------------------------------------------


def _askpass() -> str:
    """A path that answers no credential prompt, whether or not it exists.

    If true(1) is found it exits 0 with empty output, which git reads as an
    empty credential. If it is not, the deliberately absent path fails to exec,
    git falls back to the terminal, and ``GIT_TERMINAL_PROMPT=0`` refuses that
    too. Both branches end in "no prompt", which is the only property required.
    """
    for path in _TRUE_CANDIDATES:
        if os.path.exists(path):
            return path
    return _NO_ASKPASS


def _git_env() -> dict[str, str]:
    """Environment for every git call here: it may never wait on a human."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = _askpass()
    env["SSH_ASKPASS"] = _askpass()
    env["GIT_ASKPASS_REQUIRE"] = "never"
    # ssh has its own prompt for a key passphrase or an unknown host key, and
    # neither GIT_TERMINAL_PROMPT nor GIT_ASKPASS covers it. Only set when the
    # user has not — a private instance is exactly where someone has a
    # GIT_SSH_COMMAND they need.
    if not env.get("GIT_SSH_COMMAND"):
        env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
    return env


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole process group. git spawns helpers; killing git is not enough."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, AttributeError):
        try:
            proc.kill()
        except OSError:
            pass


def _run_git(args: list[str], timeout: float, cwd: str | None = None) -> tuple[int, str, str]:
    """Run one git command under a hard timeout. Returns ``(rc, stdout, stderr)``.

    The single subprocess chokepoint in this module, which is what makes the
    hardening auditable in one place and the tests network-free in one stub.

    ``protocol.ext.allow=never`` is prepended to *every* invocation rather than
    to the clone alone: ``ext::`` can arrive in a submodule URL as easily as in
    the URL the user typed, and a flag that is only on the call someone
    remembered is a flag that is off.

    ``start_new_session`` plus an explicit ``killpg`` is the hard part of "hard
    timeout": ``subprocess.run(timeout=...)`` kills only the direct child, and
    ``git-remote-https`` inherits the pipes, so the wait after the kill can hang
    for as long as the helper holds them.

    **Bytes, decoded here — never ``text=True``.** Text mode opens the pipe in
    universal-newlines mode, which rewrites ``\\r\\n`` to ``\\n``. A submodule
    path ending in a carriage return *is* the CVE-2025-48384 signature, so text
    mode deleted the evidence between git and the scanner and the whole clone
    path reported a live exploit as safe to clone. Measured on a local repo
    whose committed blob carried the CR: ``text=True`` yielded 0 carriage
    returns and no indicator, the same bytes decoded here yielded
    ``submodule_path_trailing_cr``.
    """
    argv = ["git", "-c", "protocol.ext.allow=never"] + args
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=_git_env(),
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        return (127, "", "could not run git: %s" % exc)

    def _text(raw: bytes) -> str:
        return (raw or b"").decode("utf-8", "replace")

    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
        return (124, _text(out), _text(err) + "\ntimed out after %.0fs" % timeout)
    return (proc.returncode, _text(out), _text(err))


def resolve_head(url: str, timeout: float = LS_REMOTE_TIMEOUT_S) -> str | None:
    """The commit ``HEAD`` currently points at on the remote, or None.

    ``ls-remote`` reads the ref advertisement and stops. Nothing is fetched,
    nothing is written, and no checkout happens — so it is safe to run against a
    repository that has not been cleared yet, which is the whole situation here.
    """
    rc, out, _ = _run_git(["ls-remote", "--quiet", "--", url, "HEAD"], timeout)
    if rc != 0:
        return None
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "HEAD" and _OBJECT_ID.match(fields[0]):
            return fields[0]
    return None


def fetch_via_clone(url: str, timeout: float = CLONE_TIMEOUT_S) -> dict[str, Any]:
    """Retrieve ``.gitmodules`` with a no-checkout partial clone.

    The fallback for every host not on ``_RAW_ENDPOINTS`` — a self-hosted forge,
    an SSH remote, a private instance — where there is no raw-file endpoint to
    GET and the only way to read the file is to talk git.

    ``--no-checkout`` is what makes that acceptable. Both clone-time RCEs fire
    during *checkout*: CVE-2024-32002 needs the submodule path written into the
    working tree so a symlink can redirect it into ``.git/hooks``, and
    CVE-2025-48384 needs the carriage-returned path materialized so the hook
    lands. With no working tree, neither has anywhere to land — the objects
    arrive, nothing is written out of them, and ``git show`` reads the blob
    straight from the object store.

    ``--filter=blob:none`` keeps that cheap; a server without partial-clone
    support simply sends the blobs and the result is the same.

    Always returns a dict carrying ``workdir``, including on every failure path,
    so the caller (and the suite) can assert the temp directory is gone.
    """
    workdir = tempfile.mkdtemp(prefix="forcefield-inspect-")
    result: dict[str, Any] = {"status": "error", "workdir": workdir, "method": "no-checkout-clone"}
    try:
        rc, _, err = _run_git(
            [
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth=1",
                "--no-tags",
                "--quiet",
                "--",
                url,
                workdir,
            ],
            timeout,
        )
        if rc != 0:
            result["reason"] = _failure_reason(err) or ("git clone exited %d" % rc)
            return result

        rc, out, _ = _run_git(["-C", workdir, "rev-parse", "HEAD"], SHOW_TIMEOUT_S)
        head = out.strip()
        result["commit"] = head if rc == 0 and _OBJECT_ID.match(head) else None

        rc, out, err = _run_git(["-C", workdir, "show", "HEAD:.gitmodules"], SHOW_TIMEOUT_S)
        if rc != 0:
            # git says "path '.gitmodules' does not exist" for a repo with no
            # submodules. That is a real answer, not a failed retrieval.
            if ".gitmodules" in (err or "") and "exist" in (err or ""):
                result["status"] = "absent"
                result["reason"] = "the repository has no .gitmodules"
                return result
            result["reason"] = _failure_reason(err) or ("git show exited %d" % rc)
            return result

        body = out[:MAX_GITMODULES_BYTES]
        result["status"] = "ok"
        result["text"] = body
        result["indicators"] = forensics.scan_gitmodules(body)
        result["submodules"] = len(forensics._PATH_LINE.findall(body))
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _failure_reason(text: str) -> str:
    """The line of git's stderr that actually explains the failure.

    Not simply the first line. A partial clone against a server without filter
    support opens with two ``warning: filtering not recognized by server``
    lines and only then reports what went wrong, so taking the first line
    reported a benign warning as the cause:

        warning: filtering not recognized by server, ignoring   <- reported this
        error: RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly
        fatal: early EOF                                        <- meant this

    An inconclusive verdict whose stated reason is a warning reads like a
    non-event, which is the one way this output must not be misread. ``fatal:``
    is git's final word, so the last one wins; ``error:`` is the first real
    failure when nothing was fatal.
    """
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    fatal = [line for line in lines if line.startswith("fatal:")]
    if fatal:
        return fatal[-1][:300]
    for line in lines:
        if line.startswith("error:"):
            return line[:300]
    for line in lines:
        if not line.startswith("warning:"):
            return line[:300]
    return lines[0][:300] if lines else ""


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


def inspect(url: str) -> dict[str, Any]:
    """Inspect a remote repository's ``.gitmodules``. Never raises.

    Retrieval order is the cheap, no-git path first: an allowlisted forge is one
    static HTTPS GET, and paying for a clone to learn what a GET already answers
    is only more attack surface.
    """
    verdict: dict[str, Any] = {
        "url": url,
        "repo": canonical_repo(url),
        "commit": None,
        "method": None,
        "verdict": INCONCLUSIVE,
        "indicators": [],
        "submodules": None,
        "reason": "",
        "workdir": None,
    }

    refusal = check_url(url)
    if refusal is not None:
        verdict["reason"] = refusal
        return verdict
    if verdict["repo"] is None:
        verdict["reason"] = "could not parse a host and path out of the URL"
        return verdict

    parsed = forensics.parse_remote(url)
    host = parsed[0] if parsed else ""

    try:
        if host in forensics._RAW_ENDPOINTS:
            result = forensics.fetch_remote_gitmodules(url)
            result.setdefault("method", "raw-fetch")
            if result.get("status") in ("ok", "absent"):
                # The raw endpoint serves content, not a commit id, so the half
                # of the key that binds the verdict has to come from the ref
                # advertisement.
                verdict["commit"] = resolve_head(url)
        else:
            result = fetch_via_clone(url)
            verdict["workdir"] = result.get("workdir")
            verdict["commit"] = result.get("commit")
    except Exception as exc:  # noqa: BLE001 - a broken probe reports inconclusive
        verdict["reason"] = "inspection failed: %s: %s" % (type(exc).__name__, exc)
        return verdict

    status = result.get("status")
    # Only a retrieval that produced something names its method. On a failure
    # the honest line is "nothing retrieved", not the name of the path that
    # failed to retrieve it.
    if status in ("ok", "absent"):
        verdict["method"] = result.get("method")

    if status == "ok":
        verdict["indicators"] = list(result.get("indicators") or [])
        verdict["submodules"] = result.get("submodules")
        verdict["verdict"] = DANGER if verdict["indicators"] else CLEAN
        verdict["reason"] = result.get("url") or "retrieved .gitmodules"
    elif status == "absent":
        verdict["verdict"] = ABSENT
        verdict["submodules"] = 0
        verdict["reason"] = result.get("reason") or "the repository has no .gitmodules"
    else:
        verdict["verdict"] = INCONCLUSIVE
        verdict["reason"] = result.get("reason") or "retrieval failed"
    return verdict


def inspect_and_record(url: str, ttl_days: int | None = DEFAULT_TTL_DAYS) -> dict[str, Any]:
    """Inspect, then record the verdict if it is one that may be recorded."""
    verdict = inspect(url)
    verdict["recorded"] = record_verdict(verdict, ttl_days=ttl_days)
    return verdict


# ---------------------------------------------------------------------------
# The verdict store
# ---------------------------------------------------------------------------
#
# A separate file from memos.json, in the same 0700 directory, signed with the
# same key under a different domain separator.
#
# Separate because a memo and a verdict are different objects. A memo says "turn
# this exact ask into an allow" and can only ever loosen; ``memo._signed_fields``
# covers a fixed tuple with no slot for a commit, so a commit added to a memo
# would sit outside the MAC — forgeable, which defeats the one property the
# commit is there to provide. Widening that tuple instead would invalidate every
# memo already in a user's store. And a verdict can be *negative*: "DO NOT CLONE
# at this commit" has no representation in a store that only ever says allow.
#
# Same key because ``memo._store_key`` is where the 0600-from-creation open, the
# ownership and permission check, and the "key is no longer private, distrust
# every signature" logging already live, and a second copy of that is a second
# chance to get it wrong. ``_MAC_DOMAIN`` keeps the two signature spaces
# disjoint: a memo's signed payload is a JSON object and can never start with
# that prefix, so no memo signature verifies here and no verdict signature
# verifies there.


def _store_path() -> Path:
    """Resolved at call time so redirecting ``memo.STORE_DIR`` moves this too."""
    return memo.STORE_DIR / STORE_FILENAME


def verdict_key(repo: str, commit: str) -> str:
    """Stable id for one verdict. NUL-joined so no field can impersonate another."""
    return hashlib.sha256("\0".join(("v1", repo, commit)).encode("utf-8")).hexdigest()


def _signed_fields(record: dict[str, Any]) -> bytes:
    payload = {
        field: record.get(field)
        for field in ("key", "repo", "commit", "verdict", "indicators",
                      "method", "created_at", "expires_at")
    }
    return _MAC_DOMAIN + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sign(record: dict[str, Any]) -> str:
    key = memo._store_key()
    if key is None:
        return ""
    return hmac.new(key, _signed_fields(record), hashlib.sha256).hexdigest()


def _verify(record: dict[str, Any], slot: str) -> bool:
    """Whether this record was written here and belongs in ``slot``.

    Both halves, for the reason ``memo._verify`` documents: a MAC over a
    record's own fields proves only that ForceField signed *some* verdict, never
    that it signed *this* lookup. A genuinely-signed clean verdict re-filed
    under another repository's slot would otherwise clear that repository.
    """
    expected = _sign(record)
    got = record.get("mac")
    if not expected or not isinstance(got, str):
        return False
    if not hmac.compare_digest(expected, got):
        return False
    if record.get("key") != slot:
        return False
    derived = verdict_key(record.get("repo") or "", record.get("commit") or "")
    return hmac.compare_digest(derived, slot)


def _read_store() -> dict[str, Any]:
    """Load the verdict store, or an empty one. Never raises.

    The ``is_file()`` pre-check that used to guard the read was a TOCTOU window:
    it answers about the path, not about the descriptor the read then gets.
    ``read_regular_text`` closes it — ``O_NONBLOCK`` plus ``S_ISREG`` on the
    descriptor itself — and bounds the read at ``MAX_STORE_BYTES`` rather than
    checking a size that could change afterwards.
    """
    path = _store_path()
    raw = read_regular_text(path, MAX_STORE_BYTES)
    if not raw:
        return {"version": STORE_VERSION, "verdicts": {}}
    try:
        data = json.loads(raw)
    except ValueError:
        return {"version": STORE_VERSION, "verdicts": {}}
    if not isinstance(data, dict) or not isinstance(data.get("verdicts"), dict):
        return {"version": STORE_VERSION, "verdicts": {}}
    return data


def _write_store(data: dict[str, Any]) -> None:
    memo._ensure_store_dir()
    path = _store_path()
    tmp = path.with_suffix(".json.tmp.%d" % os.getpid())
    fd = memo._open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        os.write(fd, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _sweep(store: dict[str, Any]) -> int:
    now = time.time()
    stale = [
        key for key, rec in store["verdicts"].items()
        if rec.get("expires_at") is not None and rec["expires_at"] < now
    ]
    for key in stale:
        del store["verdicts"][key]
    return len(stale)


def record_verdict(verdict: dict[str, Any], ttl_days: int | None = DEFAULT_TTL_DAYS) -> bool:
    """Persist a verdict against ``repo@commit``. Returns whether it was stored.

    Refuses three things, each for its own reason. An ``inconclusive`` verdict
    measured nothing, so recording it would turn "we did not look" into a stored
    answer. A missing commit cannot be bound, and an unbound verdict would keep
    applying to a repository that has since changed under it. An unsignable
    record would be indistinguishable from a hand-written one.
    """
    repo, commit = verdict.get("repo"), verdict.get("commit")
    if verdict.get("verdict") not in _RECORDABLE or not repo or not commit:
        return False
    now = time.time()
    record = {
        "key": verdict_key(repo, commit),
        "repo": repo,
        "commit": commit,
        "verdict": verdict["verdict"],
        "indicators": list(verdict.get("indicators") or []),
        "method": verdict.get("method"),
        "created_at": now,
        "expires_at": None if ttl_days is None else now + ttl_days * 86_400,
    }
    record["mac"] = _sign(record)
    if not record["mac"]:
        return False
    try:
        with memo._store_lock():
            store = _read_store()
            _sweep(store)
            if len(store["verdicts"]) >= MAX_VERDICTS:
                return False
            store["verdicts"][record["key"]] = record
            store["version"] = STORE_VERSION
            _write_store(store)
    except (OSError, ValueError, TypeError):
        return False
    _log("warn" if record["verdict"] == DANGER else "allow", "inspection_recorded",
         repo=repo, commit=commit[:12], inspect_verdict=record["verdict"],
         indicators=",".join(record["indicators"]), memo_key=record["key"][:12])
    return True


def find_verdict(url: str, commit: str) -> dict[str, Any] | None:
    """A live recorded verdict for this repo *at this commit*, or None.

    The commit is not a filter applied after the lookup, it is half the lookup
    key: a verdict computed at one commit is evidence about that commit and
    nothing else, and a repository whose HEAD has moved has not been inspected.

    Never raises — every failure here means "no verdict", which sends the caller
    back to whatever it would have done without one.
    """
    try:
        repo = canonical_repo(url)
        if not repo or not commit or not _OBJECT_ID.match(commit):
            return None
        slot = verdict_key(repo, commit)
        record = _read_store()["verdicts"].get(slot)
        if record is None or not _verify(record, slot):
            return None
        expires = record.get("expires_at")
        if expires is not None and expires < time.time():
            return None
        return record
    except Exception:  # noqa: BLE001 - a broken store must never decide anything
        return None


def find_danger(url: str) -> dict[str, Any] | None:
    """A recorded ``danger`` verdict for this repository at *any* commit, or None.

    Deliberately asymmetric with ``find_verdict``, which is commit-exact, and the
    asymmetry is the point rather than a shortcut.

    A **clean** verdict is evidence about one commit and must expire with it. The
    repository may have gained a hostile submodule since it was inspected, so
    clearing a clone on the strength of an older commit's verdict is exactly the
    unbound verdict ``record_verdict`` refuses to store.

    A **danger** verdict runs the other way. It says this repository published the
    literal signature of a clone-time RCE, which is a fact about its publisher
    rather than about one commit. A later commit that drops the signature does not
    make the earlier one unpublished — and if the block were commit-exact, the
    entire evasion would be one empty commit. So it keeps applying until the user
    revokes it with ``inspect_remote.py forget``.

    Sound because it is escalate-only: this can turn an ``ask`` into a ``deny``
    and can never turn anything into an ``allow``. Never raises — every failure
    means "no verdict", which leaves the caller's decision untouched.
    """
    try:
        repo = canonical_repo(url)
        if not repo:
            return None
        now = time.time()
        newest = None
        for record in _read_store()["verdicts"].values():
            if record.get("repo") != repo or record.get("verdict") != DANGER:
                continue
            slot = record.get("key")
            if not isinstance(slot, str) or not _verify(record, slot):
                continue
            expires = record.get("expires_at")
            if expires is not None and expires < now:
                continue
            if newest is None or (record.get("created_at") or 0) > (newest.get("created_at") or 0):
                newest = record
        return newest
    except Exception:  # noqa: BLE001 - a broken store must never decide anything
        return None


def entries() -> list[dict[str, Any]]:
    store = _read_store()
    return sorted(store["verdicts"].values(), key=lambda r: r.get("created_at", 0))


def forget(prefix: str) -> int:
    """Remove verdicts whose key starts with ``prefix``. Returns how many."""
    doomed: list[str] = []
    with memo._store_lock():
        store = _read_store()
        doomed = [key for key in store["verdicts"] if key.startswith(prefix)]
        for key in doomed:
            del store["verdicts"][key]
        if doomed:
            _write_store(store)
    if doomed:
        _log("warn", "inspection_forgotten", count=len(doomed), memo_key=prefix[:12])
    return len(doomed)


def forget_expired() -> int:
    with memo._store_lock():
        store = _read_store()
        gone = _sweep(store)
        if gone:
            _write_store(store)
    return gone


def _log(decision: str, pattern: str, **extra: Any) -> None:
    """Record one inspection event. Best effort, and never level-floored.

    Same contract as the memo records: a stored verdict can quiet a later prompt,
    so it has to leave at least as much trail as the prompt it replaces.
    ``inspect_remote`` is in ``hook_logging._UNSUPPRESSIBLE_GUARDS``, which is
    where that contract now lives.
    """
    try:
        from hook_logging import log_security_event

        log_security_event("inspect_remote", decision, pattern_matched=pattern,
                           extra=extra)
    except Exception:  # noqa: BLE001 - logging must never break an inspection
        pass


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def format_report(verdict: dict[str, Any]) -> str:
    """The user-facing report. Short, and decisive in one direction or the other."""
    method = {
        "raw-fetch": "raw .gitmodules fetch (no git ran)",
        "no-checkout-clone": "no-checkout partial clone (nothing was checked out)",
    }.get(verdict.get("method") or "", "nothing retrieved")

    lines = ["Inspected : %s" % verdict.get("url", ""),
             "Method    : %s" % method]
    if verdict.get("commit"):
        lines.append("Commit    : %s" % verdict["commit"])
    if verdict.get("submodules") is not None:
        lines.append("Submodules: %d" % verdict["submodules"])
    lines.append("")

    state = verdict.get("verdict")
    if state == DANGER:
        names = ", ".join(verdict["indicators"])
        lines.append("DO NOT CLONE — %s" % names)
        for name in verdict["indicators"]:
            lines.append("")
            lines.append("  %s" % name)
            lines.append("  %s" % forensics.INDICATOR_RISKS.get(
                name, "Known clone-time exploit signature."))
        lines.append("")
        lines.append("This repository carries the literal signature of a known "
                     "clone-time RCE exploit. Report it to the host it is "
                     "published on.")
    elif state in (CLEAN, ABSENT):
        detail = ("no submodules at all" if state == ABSENT
                  else "no known clone-time exploit signature")
        lines.append("Safe to clone — %s at this commit." % detail)
        lines.append("")
        lines.append("This is a statement about the clone, not about the code: "
                     "a clean .gitmodules says nothing about what the repository "
                     "does once you run it.")
        if verdict.get("recorded"):
            lines.append("")
            lines.append("Verdict recorded, so cloning this commit will not prompt again.")
        elif not verdict.get("commit"):
            # Keyed off the missing commit rather than off a `recorded` flag: the
            # verdict is unbindable whether or not anyone tried to store it.
            lines.append("")
            lines.append("Not recorded: the commit could not be resolved, and an "
                         "unbound verdict would outlive the thing it verified.")
    else:
        lines.append("INCONCLUSIVE — %s" % (verdict.get("reason") or "retrieval failed"))
        lines.append("")
        lines.append("Nothing was verified. This is not a clean result: treat the "
                     "repository as uninspected and decide on other grounds.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_inspect(args: argparse.Namespace) -> int:
    verdict = inspect_and_record(
        args.url, ttl_days=None if args.forever else args.days)
    print(format_report(verdict))
    return 0 if verdict["verdict"] in (CLEAN, ABSENT) else 1


def _cmd_list(_args: argparse.Namespace) -> int:
    rows = entries()
    if not rows:
        print("No cached inspection verdicts.")
        return 0
    now = time.time()
    for rec in rows:
        left = ("never expires" if rec.get("expires_at") is None
                else "%.0fd left" % max(0, (rec["expires_at"] - now) / 86_400))
        print("%s  %-9s %-14s %s@%s" % (
            rec["key"][:12], rec.get("verdict", "?"), left,
            rec.get("repo", "?"), (rec.get("commit") or "?")[:12]))
    return 0


def _cmd_forget(args: argparse.Namespace) -> int:
    if args.expired:
        print("Forgot %d expired verdict(s)." % forget_expired())
        return 0
    if not args.prefix:
        print("Give a key prefix, or --expired.")
        return 2
    gone = forget(args.prefix)
    print("Forgot %d verdict(s)." % gone)
    return 0 if gone else 1


_SUBCOMMANDS = ("inspect", "list", "forget")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspect_remote.py",
        description="Inspect a repository's .gitmodules before cloning it.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="inspect a remote repository")
    ins.add_argument("url")
    ins.add_argument("--days", type=int, default=DEFAULT_TTL_DAYS)
    ins.add_argument("--forever", action="store_true",
                     help="record the verdict with no expiry")
    ins.set_defaults(func=_cmd_inspect)

    lst = sub.add_parser("list", help="show cached inspection verdicts")
    lst.set_defaults(func=_cmd_list)

    fgt = sub.add_parser("forget", help="drop cached inspection verdicts")
    fgt.add_argument("prefix", nargs="?")
    fgt.add_argument("--expired", action="store_true")
    fgt.set_defaults(func=_cmd_forget)

    raw = list(sys.argv[1:] if argv is None else argv)
    # A bare URL is the overwhelmingly common invocation, so it is accepted
    # without the subcommand rather than being an argparse error.
    if raw and raw[0] not in _SUBCOMMANDS and not raw[0].startswith("-"):
        raw.insert(0, "inspect")
    args = parser.parse_args(raw)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
