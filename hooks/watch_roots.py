#!/usr/bin/env python3
"""Concrete filesystem paths handed to Claude Code's FileChanged watcher.

``filesystem_guard`` holds the sink knowledge as regexes, which answer "does this
path count". The watcher needs the other half: "where should we look". These are
genuinely different questions and this module answers only the second one. The
hook then filters what arrives with ``filesystem_guard``'s patterns verbatim, so
there is no second copy of the sink knowledge to drift out of step.

Two shapes, and the split is forced rather than stylistic. Claude Code calls
chokidar with no ``depth`` bound, so **watching a directory is recursive without
limit**:

* Explicit FILE paths where the set is finite and the parent is far too large to
  watch. ``$HOME`` as a root to catch ``~/.zshrc`` would recurse the whole home
  directory.
* Directory roots where the creation of a *new* file is itself the threat, so no
  file list can work. ``/etc/sudoers.d`` and ``~/.claude/forcefield`` are both in
  this class: an attacker adds a file rather than editing one.

``~/.claude`` is deliberately NOT a root. Recursion would pull in
``plugins/cache/`` and ``projects/``, where session transcripts append
continuously, and ``~/.claude/hooks/security.log`` is ForceField's own log, so
watching its directory means every record written triggers an event that writes a
record. The four files that matter there are named individually instead.

``~/.claude/forcefield`` IS a root, and its cost is known: 1,013 files, of which
1,008 are the Sigma venv. A ``sigma_update.sh`` run therefore produces a burst,
which is exactly what the self-write suppression in ``file_watch_guard`` absorbs.
Watching the parent rather than listing its files is still correct, because a
``memos.json`` that does not exist yet is the thing worth catching.

Stdlib only, and imports nothing from ForceField: this sits at the same level as
``patterns.py`` so that both ``session_baseline`` (which emits the set) and
``file_watch_guard`` (which filters against it) can use it without a cycle.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Shell init files, spelled out because their parent is $HOME. Kept in the same
# order as the ``shell_init`` alternation so the two read as one list.
_SHELL_INIT = (
    ".bashrc", ".zshrc", ".bash_profile", ".zprofile", ".profile",
    ".bash_login", ".bash_logout", ".zshenv", ".zlogin", ".zlogout",
    ".bash_aliases",
)

# Sink names with no watch root, each with the reason. The correspondence gate in
# the test suite requires every write and config sink to appear either here or in
# the root map, so a sink added later cannot quietly go unwatched.
WATCH_EXEMPT: dict[str, str] = {
    "git_config_file": (
        "workspace .git/config is covered by the .git/hooks root's parent only "
        "when a repo is open; a bare config edit is not executable on its own, "
        "and git_hooks carries the execution risk"
    ),
    "fish_init": (
        "~/.config/fish is watched as a directory root; the named entry here "
        "exists because the regex also matches conf.d/ under the same root"
    ),
}


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _user_roots() -> list[Path]:
    home = _home()
    roots = [
        home / ".ssh",
        home / ".aws",
        home / ".gnupg",
        home / ".kube",
        home / ".config" / "gcloud",
        home / ".config" / "fish",
        home / ".config" / "autostart",
        home / ".claude" / "forcefield",
        home / ".docker" / "config.json",
        home / ".npmrc",
        home / ".pypirc",
        home / ".netrc",
        home / ".git-credentials",
        home / ".gitconfig",
        home / ".config" / "git" / "config",
        home / ".mcp.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude" / "hook-allowlist.json",
        home / ".claude" / "forcefield.json",
    ]
    roots.extend(home / name for name in _SHELL_INIT)
    return roots


def _system_roots(platform: str | None = None) -> list[Path]:
    """Machine-wide persistence and privilege paths, gated by platform.

    Emitting a Linux systemd path on darwin costs nothing but says the watch set
    was not thought about, and the correspondence gate reads better when the two
    platforms are explicit.

    ``platform`` is an argument so the gate can ask for the other platform's
    roots. Without it the gate could only ever check this host's slice of the
    design, and would report ``systemd_unit`` as uncovered on macOS and
    ``launch_agents`` as uncovered on Linux.
    """
    platform = platform or sys.platform
    roots = [
        Path("/etc/sudoers"),
        Path("/etc/sudoers.d"),
        Path("/etc/passwd"),
        Path("/etc/shadow"),
        Path("/etc/hosts"),
        Path("/etc/profile"),
        Path("/etc/environment"),
        Path("/etc/pam.d"),
        Path("/etc/ld.so.preload"),
        Path("/etc/ld.so.conf"),
        Path("/etc/rc.local"),
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
    ]
    if platform == "darwin":
        roots.extend([
            _home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ])
    else:
        roots.extend([
            Path("/etc/systemd/system"),
            Path("/var/spool/cron"),
            Path("/var/at"),
            _home() / ".config" / "systemd" / "user",
        ])
    return roots


def _workspace_roots(cwd: str | None) -> list[Path]:
    """The active workspace's own control surface.

    Only ``.claude/`` and ``.git/hooks``, never the repository itself: a source
    tree changes constantly and watching it would drown the signal. A cloned repo
    rewriting its own hooks mid-session is the case this covers.
    """
    if not cwd:
        return []
    try:
        base = Path(cwd).resolve()
    except (OSError, ValueError):
        return []
    return [base / ".claude", base / ".git" / "hooks", base / ".mcp.json"]


def _watchable(path: Path) -> bool:
    """Keep a path only if the watcher can actually act on it.

    A path that exists is watchable. A path that does not exist is still worth
    emitting when its PARENT is watched, because the ``add`` of, say,
    ``/etc/ld.so.preload`` is the event that matters and dropping the entry would
    lose it. Anything else is dropped: chokidar cannot watch a path whose parent
    does not exist either, and passing one costs a wasted watch.
    """
    try:
        if path.exists():
            return True
        return path.parent.is_dir()
    except OSError:
        return False


def watch_roots(cwd: str | None = None) -> list[str]:
    """Absolute paths for ``SessionStart``'s ``watchPaths``, deduped and sorted.

    Sorted so the emitted set is stable between sessions, which makes a diff of
    two ``session.start`` records meaningful.
    """
    candidates = _user_roots() + _system_roots() + _workspace_roots(cwd)
    seen: dict[str, None] = {}
    for path in candidates:
        if not _watchable(path):
            continue
        seen[str(path)] = None
    return sorted(seen)


def all_candidate_roots(cwd: str | None = None) -> list[str]:
    """Every root the design contributes, on either platform, unfiltered.

    For the correspondence gate only. It differs from ``watch_roots`` in two
    ways, and both are deliberate: it unions the macOS and Linux sets, and it
    skips ``_watchable``. The gate is asking whether the *design* covers every
    sink pattern, which is a property of this file rather than of the host it
    happens to run on — a machine with no ``~/.aws`` directory would otherwise
    fail the gate for a sink that is perfectly well covered.
    """
    candidates = (_user_roots() + _system_roots("darwin")
                  + _system_roots("linux") + _workspace_roots(cwd))
    return sorted({str(path) for path in candidates})


if __name__ == "__main__":
    for root in watch_roots(os.getcwd()):
        print(root)
