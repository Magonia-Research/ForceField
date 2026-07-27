import { normalizeCommand } from '../normalize.js';

const POPULAR_PYPI: ReadonlySet<string> = new Set([
  'requests', 'urllib3', 'boto3', 'botocore', 'setuptools', 'pip',
  'certifi', 'charset-normalizer', 'idna', 'typing-extensions',
  'numpy', 'packaging', 'aiobotocore', 'pyyaml', 's3transfer',
  'python-dateutil', 'cryptography', 'six', 'wheel', 'jinja2',
  'colorama', 'markupsafe', 'platformdirs', 'pydantic', 'pytest',
  'grpcio', 'pillow', 'protobuf', 'filelock', 'aiohttp', 'attrs',
  'pyasn1', 'pandas', 'virtualenv', 'wrapt', 'click', 'flask',
  'django', 'sqlalchemy', 'celery', 'redis', 'psycopg2', 'httpx',
  'beautifulsoup4', 'lxml', 'scipy', 'matplotlib', 'scikit-learn',
  'tensorflow', 'torch', 'transformers', 'fastapi', 'uvicorn',
  'gunicorn', 'black', 'ruff', 'mypy', 'pylint', 'flake8',
  'tox', 'coverage', 'hypothesis', 'faker', 'rich', 'typer',
  'httptools', 'orjson', 'msgpack', 'toml', 'tomli',
]);

const POPULAR_NPM: ReadonlySet<string> = new Set([
  'lodash', 'express', 'axios', 'react', 'react-dom', 'next',
  'typescript', 'webpack', 'babel', 'eslint', 'prettier',
  'jest', 'mocha', 'chai', 'commander', 'chalk', 'inquirer',
  'glob', 'minimist', 'yargs', 'dotenv', 'cors', 'helmet',
  'jsonwebtoken', 'bcrypt', 'uuid', 'moment', 'dayjs', 'date-fns',
  'socket.io', 'mongoose', 'sequelize', 'prisma', 'graphql',
  'apollo-server', 'electron', 'vue', 'angular', 'svelte',
  'tailwindcss', 'postcss', 'sass', 'less', 'nodemon', 'pm2',
  'puppeteer', 'playwright', 'cypress', 'vitest', 'esbuild',
  'vite', 'rollup', 'parcel', 'turbo', 'nx', 'lerna',
  'create-react-app', 'create-next-app', 'create-vite',
]);

const POPULAR_CARGO: ReadonlySet<string> = new Set([
  'tokio', 'serde', 'serde_json', 'reqwest', 'clap', 'rand',
  'anyhow', 'thiserror', 'tracing', 'hyper', 'axum', 'actix-web',
  'sqlx', 'diesel', 'sea-orm', 'regex', 'rayon', 'crossbeam',
  'futures', 'async-trait', 'tower', 'tonic', 'prost',
  'chrono', 'uuid', 'url', 'bytes', 'log', 'env_logger',
  'config', 'toml', 'once_cell', 'lazy_static', 'itertools',
  'syn', 'quote', 'proc-macro2', 'cargo-edit', 'cargo-watch',
  'ripgrep', 'fd-find', 'bat', 'exa', 'starship', 'zoxide',
]);

const _FETCHER = '(?:curl|wget2?|fetch|aria2c)';
const _HTTPIE = '(?:^|[;&|(\\n{])\\s*https?(?=\\s)';
const _INTERP = (
  '(?:bash|sh|zsh|dash|ash|ksh|fish|/bin/(?:ba)?sh|python[23]?|python|ruby' +
  '|perl|node|deno|php|pwsh|powershell|tclsh|lua|Rscript|julia|nu|eval)'
);

const _PIPE_WRAPPER = '(?:sudo|doas|env|xargs|nohup|setsid|stdbuf)';
const _PIPE_PREFIX_UNIT = (
  '(?:[A-Za-z_]\\w*=\\S*' +
  '|' + _PIPE_WRAPPER + '\\b' +
  '|-{1,2}\\S+(?:\\s+[^-\\s]\\S*)?)'
);

const DANGEROUS_INSTALL: ReadonlyMap<string, RegExp> = new Map([
  ['pipe_to_shell', new RegExp(
    '(?:' + _FETCHER + '\\b|' + _HTTPIE + ')[^\\n]*\\|\\s*(?:' +
    _PIPE_PREFIX_UNIT + '\\s+)*' + _INTERP + '\\b'
  )],
  ['fetch_exec_substitution', new RegExp(
    '(?:' +
    '(?<!\\w)(?:' + _INTERP + '|source)\\b[^\\n]*(?:\\$\\(|<\\(|`)\s*[^\\n)]*' +
    '\\b' + _FETCHER + '\\b' +
    '|' +
    '(?:^|[;&|(\\n{])\\s*\\.\\s+(?:\\$\\(|<\\(|`)\\s*[^\\n)]*\\b' + _FETCHER + '\\b' +
    ')'
  )],
  ['fetch_var_exec', new RegExp(
    '([A-Za-z_]\\w*)=(?:\\$\\(|`)[^\\n]*\\b' + _FETCHER + '\\b[^\\n]*' +
    '(?<!\\w)(?:' + _INTERP + '\\s+(?:-\\S+\\s+)*-c\\b|eval\\b)[^\\n]*\\$\\{?\\1\\b'
  )],
  ['fetch_then_exec', new RegExp(
    '(?:' +
    _FETCHER + '\\b[^\\n]*\\s-[oO]\\b[^\\n]*?(?:&&|\\|\\||;)[^\\n]*?' +
    '(?<!\\w)(?:' + _INTERP + '|source)\\b' +
    '|' +
    _FETCHER + '\\b[^\\n]*?(?:\\s-[oO]\\s+|>>?\\s*)(?P<f>[^\\s;&|<>()\'`]+)' +
    '[\\s\\S]*?(?<!\\w)(?:' + _INTERP + '|source|\\.)\\s+(?:-\\S+\\s+)*' +
    '(?P=f)(?!\\w)' +
    ')'
  )],
  ['pip_url_install', /pip3?\s+install\s+https?:\/\//],
  ['npm_url_install', /npm\s+install\s+https?:\/\//],
  ['npx_url_exec', /(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+https?:\/\//],
  ['npx_auto_run', /(npx|bunx|pnpm\s+dlx|yarn\s+dlx)(?:\s+-y\b|\b[^\\n]*\s--yes\b)/],
  ['insecure_registry', /(?:--registry|--index-url|--extra-index-url)(?:\s+|=)http:\/\/|(?:pip3?|uv|pipx)\s+(?:pip\s+)?(?:install|add)\b[^\n;&|]*\s-i(?:=|\s+)http:\/\//],
  ['uvx_url_exec', /(uvx|pipx\s+run)\s+https?:\/\//],
  ['force_scripts', /npm\s+install\s+.*--ignore-scripts\s*=\s*false/],
  ['global_install', /(npm\s+install\s+-g\s+|pip3?\s+install\s+(?!-e\s)(?!--editable))/],
  ['system_pkg_install', /(sudo\s+)?(apt(-get)?\s+install|dnf\s+install|yum\s+install|pacman\s+-S)/],
]);

const ALLOWLIST_PATTERNS: readonly RegExp[] = [
  /pipx\s+install\b/,
  /uv\s+pip\s+install\s+.*--require-hashes/,
  /pip3?\s+install\s+-e\s/,
  /pip3?\s+install\s+--editable\s/,
  /npx\s+--package=/,
];

const _SHELL_SEPARATORS = /\|\||&&|[;|\n]/;

function isAllowlisted(command: string): boolean {
  for (const pattern of ALLOWLIST_PATTERNS) {
    if (pattern.test(command)) return true;
  }
  return false;
}

function shellSegments(command: string): string[] {
  return command.split(_SHELL_SEPARATORS).filter((seg) => seg.trim().length > 0);
}

function segmentMatchesPattern(segment: string, patternName: string): boolean {
  const pattern = DANGEROUS_INSTALL.get(patternName);
  if (!pattern) return false;
  const normalized = normalizeCommand(segment);
  const variants = normalized === segment ? [segment] : [segment, normalized];
  for (const text of variants) {
    if (pattern.test(text)) return true;
  }
  return false;
}

function allowlistClearsDanger(command: string, patternName: string): boolean {
  const carriers = shellSegments(command).filter((seg) => segmentMatchesPattern(seg, patternName));
  if (carriers.length === 0) return false;
  for (const seg of carriers) {
    if (!isAllowlisted(seg)) return false;
  }
  return true;
}

function damerauLevenshtein(s: string, t: string): number {
  const lenS = s.length;
  const lenT = t.length;

  if (Math.abs(lenS - lenT) > 2) return Math.abs(lenS - lenT);

  // Flat array with row-major indexing. Non-null assertions are safe here —
  // all indices are provably within [0, (lenS+1)*(lenT+1)) by loop bounds.
  const cols = lenT + 1;
  const d = new Array<number>((lenS + 1) * cols).fill(0);
  const idx = (i: number, j: number): number => i * cols + j;

  for (let i = 0; i <= lenS; i++) {
    d[idx(i, 0)] = i;
  }
  for (let j = 1; j <= lenT; j++) {
    d[idx(0, j)] = j;
  }

  for (let i = 1; i <= lenS; i++) {
    for (let j = 1; j <= lenT; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      d[idx(i, j)] = Math.min(
        d[idx(i - 1, j)]! + 1,       // deletion
        d[idx(i, j - 1)]! + 1,       // insertion
        d[idx(i - 1, j - 1)]! + cost, // substitution
      );
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        const transposition = d[idx(i - 2, j - 2)]! + 1;
        if (transposition < d[idx(i, j)]!) {
          d[idx(i, j)] = transposition;
        }
      }
    }
  }

  return d[idx(lenS, lenT)]!;
}

function dlThreshold(nameLength: number): number {
  if (nameLength <= 3) return 0;
  if (nameLength <= 6) return 1;
  return 2;
}

function checkDlAgainstEcosystem(pkgName: string, popular: ReadonlySet<string>): string | null {
  if (popular.has(pkgName)) return null;

  const threshold = dlThreshold(pkgName.length);
  if (threshold === 0) return null;

  let bestMatch: string | null = null;
  let bestDist = threshold + 1;

  for (const popularName of popular) {
    if (Math.abs(pkgName.length - popularName.length) > threshold) continue;
    const dist = damerauLevenshtein(pkgName, popularName);
    if (dist <= threshold && dist < bestDist) {
      bestDist = dist;
      bestMatch = popularName;
    }
  }

  return bestMatch;
}

const TYPOSQUAT_CHECKS: readonly [RegExp, readonly [RegExp, string][]][] = [
  [/pip3?\s+install\s+/, [
    [/requets/, 'requests'],
    [/requsts/, 'requests'],
    [/request\b/, 'requests'],
    [/beautifulsoup\b/, 'beautifulsoup4'],
    [/python-dateutil2/, 'python-dateutil'],
    [/urlib3/, 'urllib3'],
    [/urlib/, 'urllib3'],
    [/dateuti/, 'python-dateutil'],
    [/colorsama/, 'colorama'],
    [/colourama/, 'colorama'],
  ]],
  [/(npm\s+install|pnpm\s+add|yarn\s+add)\s+/, [
    [/loadsh/, 'lodash'],
    [/lodahs/, 'lodash'],
    [/expres\b/, 'express'],
    [/axois/, 'axios'],
    [/axos/, 'axios'],
    [/recat/, 'react'],
    [/reactjs\b/, 'react'],
    [/electorn/, 'electron'],
  ]],
  [/(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+/, [
    [/loadsh/, 'lodash'],
    [/lodahs/, 'lodash'],
    [/expres\b/, 'express'],
    [/axois/, 'axios'],
    [/recat/, 'react'],
    [/electorn/, 'electron'],
    [/creat-react-app/, 'create-react-app'],
    [/create-raect-app/, 'create-react-app'],
  ]],
  [/(uvx|pipx\s+install|pipx\s+run|uv\s+add|poetry\s+add)\s+/, [
    [/requets/, 'requests'],
    [/beautifulsoup\b/, 'beautifulsoup4'],
    [/colorsama/, 'colorama'],
    [/colourama/, 'colorama'],
    [/rufff/, 'ruff'],
  ]],
  [/cargo\s+(install|add)\s+/, [
    [/tokoi/, 'tokio'],
    [/serdee/, 'serde'],
    [/reqwests/, 'reqwest'],
  ]],
];

const _ECOSYSTEM_MAP: readonly [RegExp, ReadonlySet<string>][] = [
  [/pip3?\s+install\s+/, POPULAR_PYPI],
  [/(uvx|pipx\s+install|pipx\s+run|uv\s+add|poetry\s+add)\s+/, POPULAR_PYPI],
  [/(npm\s+install|pnpm\s+add|yarn\s+add)\s+/, POPULAR_NPM],
  [/(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+/, POPULAR_NPM],
  [/cargo\s+(install|add)\s+/, POPULAR_CARGO],
];

export const HARD_DENY_PATTERNS: readonly string[] = [
  'pipe_to_shell',
  'fetch_exec_substitution',
];

function _stripVersion(pkg: string): string {
  const idx = pkg.search(/[=<>!@\[]/);
  if (idx === -1) return pkg;
  return pkg.slice(0, idx);
}

function checkTyposquatSingle(command: string): [string, string, string] | null {
  // Pass 1: regex-based known typos
  for (const [installerRe, typos] of TYPOSQUAT_CHECKS) {
    const match = command.match(installerRe);
    if (!match) continue;
    const afterInstall = command.slice(match.index! + match[0].length);
    const packages = afterInstall.trim().split(/\s+/);
    for (const pkg of packages) {
      if (pkg.startsWith('-')) continue;
      const pkgClean = _stripVersion(pkg);
      for (const [typoRe, correct] of typos) {
        if (typoRe.test(pkgClean)) return [pkgClean, correct, match[0].trim()];
      }
    }
  }

  // Pass 2: Damerau-Levenshtein against popular packages
  for (const [installerRe, popular] of _ECOSYSTEM_MAP) {
    const match = command.match(installerRe);
    if (!match) continue;
    const afterInstall = command.slice(match.index! + match[0].length);
    const packages = afterInstall.trim().split(/\s+/);
    for (const pkg of packages) {
      if (pkg.startsWith('-')) continue;
      const pkgClean = _stripVersion(pkg);
      if (!pkgClean) continue;
      const correct = checkDlAgainstEcosystem(pkgClean, popular);
      if (correct) return [pkgClean, correct, match[0].trim()];
    }
  }

  return null;
}

export function checkTyposquat(command: string): [string, string, string] | null {
  try {
    const normalized = normalizeCommand(command);
    const variants = normalized === command ? [command] : [command, normalized];
    for (const text of variants) {
      const result = checkTyposquatSingle(text);
      if (result) return result;
    }
    return null;
  } catch {
    return null;
  }
}

export function checkDangerous(command: string): [string, string] | null {
  try {
    const normalized = normalizeCommand(command);
    const variants = normalized === command ? [command] : [command, normalized];
    for (const [name, pattern] of DANGEROUS_INSTALL) {
      for (const text of variants) {
        const match = text.match(pattern);
        if (match) return [name, match[0]];
      }
    }
    return null;
  } catch {
    return null;
  }
}
