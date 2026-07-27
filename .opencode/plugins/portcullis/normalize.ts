const SENSITIVE_BINARIES = [
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'fetch', 'aria2c',
  'scp', 'rsync', 'sftp', 'nslookup', 'dig', 'host', 'drill', 'git',
  'pip', 'pip3', 'npm', 'pnpm', 'yarn', 'npx', 'bunx', 'uvx', 'pipx',
  'cargo', 'gem', 'python', 'python2', 'python3', 'ruby', 'perl',
  'node', 'deno', 'php', 'pwsh', 'powershell',
  'bash', 'sh', 'zsh', 'dash', 'ash', 'ksh',
  'apt', 'apt-get', 'dnf', 'yum', 'pacman', 'brew', 'conda',
];

const NAMES_ALT = SENSITIVE_BINARIES
  .sort((a, b) => b.length - a.length)
  .map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  .join('|');

const LINE_CONTINUATION_RE = /\\\n/g;
const BACKSLASH_ESCAPE_RE = /\\([A-Za-z0-9_])/g;
const IFS_RE = /\$\{IFS(?![A-Za-z0-9_])[^}]*\}|\$IFS\b/g;
const EMPTY_QUOTES_RE = /''|""/g;
const INTRAWORD_QUOTE_RE = /(?<=\w)['"](?=\w)/g;
const PATH_BASENAME_RE = new RegExp(
  '(^|[\\s;&|(`])' +
  "['\"]?" +
  '(?:[^\\s;&|()`\'"<>]*/)?' +
  '(' + NAMES_ALT + ')' +
  "['\"]?" +
  '(?=$|[\\s;&|)`<>])',
  'g',
);

export function normalizeCommand(command: string): string {
  try {
    if (!'\\$\'"/'.split('').some((ch) => command.includes(ch))) return command;

    let s = command.replace(LINE_CONTINUATION_RE, '');
    s = s.replace(BACKSLASH_ESCAPE_RE, '$1');
    s = s.replace(IFS_RE, ' ');
    s = s.replace(EMPTY_QUOTES_RE, '');
    s = s.replace(INTRAWORD_QUOTE_RE, '');
    s = s.replace(PATH_BASENAME_RE, '$1$2');
    return s;
  } catch {
    return command;
  }
}
