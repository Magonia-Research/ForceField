#!/usr/bin/env python3
"""Divert ``$HOME`` to a throwaway directory. Import this BEFORE any hook module.

``hooks/log_sinks.py`` resolves the file sink's directory from ``Path.home()``
on first use, and ``hooks/memo.py`` does the same for its store. A suite that
imports a guard therefore appends fabricated attack records to the operator's
real ``~/.claude/hooks/security.log``: in one measurement 794 of 1539 records
were test fixtures, which was enough to invert the conclusions drawn from the
log (a guard read as the top source of prompts on the strength of its own
tests). The records are indistinguishable from real ones after the fact.

Import-time side effect, not a function, because the ordering requirement is the
whole point -- and the sys.modules check below turns "remember to import this
first" from a comment into an error.

Subprocess suites inherit the diverted HOME through ``os.environ`` for free.
"""

import atexit
import os
import shutil
import sys
import tempfile

# Before anything else, and before the sys.modules check below: diverting $HOME
# contains the FILE sink, and nothing else. The native sinks are machine-global
# -- the macOS unified log, the systemd journal, the Windows Application channel
# -- so without this every suite that fabricates an attack payload would write
# it into the operator's real system log, indistinguishable after the fact from
# a genuine finding, and no temporary HOME could take it back. The file sink is
# unioned in unconditionally by log_sinks and is unaffected by this variable, so
# every suite still gets a complete record to assert against.
os.environ["FORCEFIELD_LOG_SINKS"] = "none"

_ALREADY_IMPORTED = [m for m in ("hook_logging", "memo", "log_sinks") if m in sys.modules]
if _ALREADY_IMPORTED:
    raise RuntimeError(
        "tests/_isolated_home.py imported too late: %s already resolved its "
        "paths from the real $HOME. Move this import above every hook import."
        % ", ".join(_ALREADY_IMPORTED)
    )

REAL_HOME = os.path.expanduser("~")
HOME = tempfile.mkdtemp(prefix="forcefield-test-home-")
os.environ["HOME"] = HOME
atexit.register(shutil.rmtree, HOME, True)


def seed(relative_path):
    """Copy ``$REAL_HOME/<relative_path>`` into the throwaway home, if it exists.

    For durable state a suite legitimately needs to read -- the compiled Sigma
    ruleset, which lives outside the repo. Returns True if something was copied.
    Reads only; the real home is never written.
    """
    source = os.path.join(REAL_HOME, relative_path)
    if not os.path.exists(source):
        return False
    destination = os.path.join(HOME, relative_path)
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    shutil.copy2(source, destination)
    return True
