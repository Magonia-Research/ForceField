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
    from normalize import normalize_command
except Exception:  # pragma: no cover - fail-open if the module is unavailable
    def normalize_command(command: str) -> str:
        return command


def _detection_variants(command: str) -> tuple[str, ...]:
    """Return the raw command plus its normalized form, deduplicated."""
    normalized = normalize_command(command)
    if normalized == command:
        return (command,)
    return (command, normalized)


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
    (re.compile(r"(uvx|pipx\s+install|pipx\s+run|uv\s+add|poetry\s+add)\s+"), POPULAR_PYPI),
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
    (re.compile(r"(uvx|pipx\s+install|pipx\s+run|uv\s+add|poetry\s+add)\s+"), [
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

# Fetchers and interpreters shared by the fetch-execute detectors below.
# ``wget2`` (the GNU Wget successor) has no word boundary after ``wget``, so it
# is spelled explicitly rather than left to ``wget\b``.
_FETCHER = r"(?:curl|wget2?|fetch|aria2c)"
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
        r"(?:" + _FETCHER + r"\b|" + _HTTPIE + r")[^\n]*\|\s*(?:"
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
        r"(?<!\w)(?:" + _INTERP + r"|source)\b[^\n]*(?:\$\(|<\(|`)\s*[^\n)]*"
        r"\b" + _FETCHER + r"\b"
        r"|"
        # POSIX dot-source of a substituted fetch. The ``.`` must be a bare
        # command (start of line or right after a separator) with the
        # substitution directly after it, so ``. venv/bin/activate`` and
        # ``diff . <(curl …)`` stay clean.
        r"(?:^|[;&|(\n{])\s*\.\s+(?:\$\(|<\(|`)\s*[^\n)]*\b" + _FETCHER + r"\b"
        r")"
    ),
    "fetch_var_exec": re.compile(
        # fetch captured to a shell variable, then that same variable executed as
        # code by an interpreter (``-c``) or ``eval`` — the assign-then-exec
        # ordering that reverses fetch_exec_substitution:
        #   x=$(curl ...); bash -c "$x"      /      v=`wget ...`; eval "$v"
        # Ask, not deny: the captured value could instead be interpolated as data
        # (``bash script.sh "$x"``), so this is not provably zero-false-positive.
        r"([A-Za-z_]\w*)=(?:\$\(|`)[^\n]*\b" + _FETCHER + r"\b[^\n]*"
        r"(?<!\w)(?:" + _INTERP + r"\s+(?:-\S+\s+)*-c\b|eval\b)[^\n]*\$\{?\1\b"
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
        + _FETCHER + r"\b[^\n]*\s-[oO]\b[^\n]*?(?:&&|\|\||;)[^\n]*?"
        r"(?<!\w)(?:" + _INTERP + r"|source)\b"
        r"|"
        + _FETCHER + r"\b[^\n]*?(?:\s-[oO]\s+|>>?\s*)(?P<f>[^\s;&|<>()'`]+)"
        r"[\s\S]*?(?<!\w)(?:" + _INTERP + r"|source|\.)\s+(?:-\S+\s+)*"
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

    Scans both the raw command and its normalized form so an installer token
    broken by an escape/quote/``${IFS}`` (``p\\ip install``) is still detected.
    """
    for text in _detection_variants(command):
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
    "fetch_exec_substitution",
])


def check_dangerous(command: str) -> tuple[str, str] | None:
    """Return (pattern_name, matched_text) or None.

    Each pattern is tested against both the raw command and its normalized form,
    so an obfuscated fetch-execute (``curl ... | no\\de``) is still caught.
    Dict order puts the hard-deny patterns first, so a deny wins over an
    overlapping ask on the same command.
    """
    variants = _detection_variants(command)
    for name, pattern in DANGEROUS_INSTALL.items():
        for text in variants:
            match = pattern.search(text)
            if match:
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
    "global_install": "Global package install (bypasses project isolation)",
    "system_pkg_install": "System package manager modifies host OS",
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
