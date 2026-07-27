const _RCE_CONFIG_KEYS = (
  'core\\.hooksPath|core\\.fsmonitor|core\\.sshCommand|core\\.pager|core\\.editor' +
  '|core\\.alternateRefsCommand|protocol\\.file\\.allow|clone\\.recurseSubmodules' +
  '|submodule\\.recurse|credential\\.helper|diff\\.external|sequence\\.editor' +
  '|uploadpack\\.packObjectsHook|filter\\.[^\\s.]+\\.(?:process|clean|smudge)' +
  '|pager\\.[\\w-]+'
);

const _RCE_ENV_VARS = (
  'GIT_SSH_COMMAND|GIT_SSH|GIT_PROXY_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS' +
  '|GIT_TEMPLATE_DIR|GIT_EDITOR|GIT_PAGER|GIT_SEQUENCE_EDITOR' +
  '|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_\\d+|GIT_CONFIG_VALUE_\\d+' +
  '|GIT_CONFIG_PARAMETERS|GIT_CONFIG'
);

const _WRITE_VERB = (
  '>>?|\\btee\\b|\\bcp\\b|\\bmv\\b|\\bln\\b|\\binstall\\b|\\bchmod\\b|\\bdd\\b|\\bof=' +
  '|\\btruncate\\b|\\bsed\\b|\\bpatch\\b|\\bprintf\\b|\\bpython[0-9.]*\\b|\\bperl\\b' +
  '|\\bruby\\b|\\bnode\\b'
);

const GIT_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['recursive_submodule_clone', /\bgit\b[^\n]*\bclone\b[^\n]*--recu[\w-]*/i],
  ['submodule_recurse_fetch', /\bgit\b[^\n]*\b(?:pull|fetch|checkout|switch|restore|reset|read-tree)\b[^\n]*--recu[\w-]*/i],
  ['submodule_update', /\bgit\b[^\n]*\bsubmodule\b[^\n]*(?:\bupdate\b|--init)/i],
  ['git_config_rce_primitive', new RegExp(
    '(?:\\bgit\\s+config\\b|(?:^|\\s)-c\\b|--config\\b)[^\\n]*' +
    '\\b(?:' + _RCE_CONFIG_KEYS + ')', 'i'
  )],
  ['git_alias_shell', new RegExp(
    '(?:\\bgit\\s+config\\b|(?:^|\\s)-c\\b|--config\\b)[^\\n]*' +
    '\\balias\\.[\\w-]+\\s*=?\\s*[\'"]?\\s*!', 'i'
  )],
  ['git_env_rce', new RegExp('\\b(?:' + _RCE_ENV_VARS + ')\\s*=', '')],
  ['git_hooks_dir_write', new RegExp(
    '(?:' + _WRITE_VERB + ')[^\\n]*' +
    '(?:\\.git/(?:modules/[^\\n]*/)?hooks/' +
    '|\\$\\{?GIT_DIR\\}?/(?:[^\\n]*/)?hooks/' +
    '|--git-path\\b[^\\n]*hooks)', 'i'
  )],
  ['git_config_file_write', new RegExp(
    '(?:' + _WRITE_VERB + ')[^\\n]*' +
    '(?:\\.git/(?:modules/[^\\n]*/)?config\\b' +
    '|\\.gitconfig\\b' +
    '|\\.config/git/config\\b' +
    '|/etc/gitconfig\\b)', 'i'
  )],
]);

export const HARD_DENY_PATTERNS: readonly string[] = [];

function _normalize(command: string): string {
  let s = command.replace(/\\\n/g, '');
  s = s.replace(/\$\{IFS\}|\$IFS\b/g, ' ');
  s = s.replace(/\\(.) /g, '$1');
  s = s.replace(/(?<=[\w.])['"](?=[\w.])/g, '');
  s = s.replace(/\/{2,}/g, '/');
  return s;
}

export function checkGit(command: string): [string, string] | null {
  try {
    const normalized = _normalize(command);
    for (const [name, pattern] of GIT_PATTERNS) {
      const match = normalized.match(pattern);
      if (match) return [name, match[0]];
    }
    return null;
  } catch {
    return null;
  }
}
