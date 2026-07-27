import { normalizeCommand } from '../normalize.js';

export const EXFIL_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['base64_in_url', /https?:\/\/.*[?&][^=]+=[A-Za-z0-9+\/]{40,}={0,2}/],
  ['data_in_url', /https?:\/\/[^\/]+\/.*[?&](data|key|secret|password|token)=/],
  ['curl_post_data', /curl\s+.*(-d\s+|--data\s+|--data-raw\s+|--data-binary\s+|--json\b)/],
  ['wget_post', /wget\s+.*(--post-(data|file)|--body-(data|file)|--method[= ](?:PUT|POST|PATCH|DELETE))/],
  ['nc_connect', /(nc|ncat|netcat)\s+.*(-e|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/],
  ['nc_remote', /\b(?:nc|ncat|netcat)\b(?:\s+-\S+)*\s+(?!(?:localhost|::1)(?:\s|$|:))(?:\[[0-9A-Fa-f:]+\]|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}|[A-Za-z0-9][A-Za-z0-9.-]*)\s+\d{1,5}\b/],
  ['exfil_domains', /(ngrok\.io|ngrok-free\.app|ngrok\.app|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator\.net|interact\.sh|canarytokens\.com|webhook\.site|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt|lhr\.life|localhost\.run|pinggy\.io|telebit\.io)/],
  ['pipe_to_network', /\|\s*(curl|wget|nc|ncat)/],
  ['pipe_via_intermediary', /\|\s*(?:xargs|tee|parallel|while\s)[^|]*\b(?:curl|wget|nc|ncat|netcat)\b/],
  ['curl_cmdsubst_url', /curl\b.*?\bhttps?:\/\/\S*(?:\$\(|`)/],
  ['httpie_exfil', /(?:^|[|;&(])\s*https?\s+(?:-\S+\s+)*(?:GET|POST|PUT|PATCH|DELETE|HEAD)\b/],
  ['bulk_transfer', /\b(?:rclone\s+(?:-{1,2}\S+\s+)*(?:copy|copyto|sync|move|moveto|rcat)|(?:magic-wormhole|wormhole|croc)\s+(?:-{1,2}\S+\s+)*send)\b/],
  ['sensitive_in_curl', /curl\s+.*(https?:\/\/.*\b(sk-|ghp_|AKIA)[a-zA-Z0-9_\/-]*|-H\s+['"]Authorization:\s*(Bearer\s+)?[a-zA-Z0-9_-]{20,})/],
  ['bash_credential_write', /(echo|printf|cat|tee)\s+.*\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----)\b.*(>|>>|\|.*tee)/],
  ['dns_exfil', /\b(?:nslookup|dig|host|drill)\b[^\n;|&]*\b[A-Za-z0-9]{25,}\./],
  ['cloud_metadata_ssrf', /(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254|2852039166|0[xX][Aa]9[Ff][Ee][Aa]9[Ff][Ee]|025177524776|[Aa]9[Ff][Ee]:[Aa]9[Ff][Ee])/],
  ['remote_copy', /\b(?:scp|rsync|sftp)\b[^\n]*\s(?:[\w.-]+@)?[\w.-]+:/],
  ['git_push_url', /\bgit\s+push\b[^\n]*\s(?:https?:\/\/|ssh:\/\/|ftp:\/\/|git:\/\/|[\w.-]+@[\w.-]+:)/],
  ['curl_upload', /curl\b[^\n]*(?:\s-T\s|\s--upload-file\b|\s-F\s+\S*=@|\s--form\s+\S*=@)/],
  ['reverse_shell', /\/dev\/(?:tcp|udp)\//],
  ['interactive_shell_redirect', /\b(?:bash|sh|zsh|ksh|dash)\s+-i\b[^\n|;&]*>&/],
  ['git_push_non_origin', /\bgit\s+push\b(?:\s+-\S+)*\s+(?!origin\b|--)[\w][\w.-]*(?=\s|$)/],
]);

const ALLOWLIST_PATTERNS: readonly RegExp[] = [
  /^curl\s+(-[sSkLfO#]+\s+)*https?:\/\//,
  /curl\s+[^|]*https?:\/\/(?:[^/\s@]*@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?(?:[/?\s#]|$)/,
  /^git\s+(push|pull|fetch|clone|remote)\b/,
  /^(npm|cargo|pnpm)\s+publish\b/,
];

const CURL_HAS_DATA_FLAG = /curl\s+.*(-d\s|--data|--data-raw|--data-binary|-F\s|--form\s|--upload-file|-T\s|--json\b)/;

const NEVER_ALLOWLIST: ReadonlySet<string> = new Set([
  'exfil_domains', 'nc_connect', 'bash_credential_write', 'sensitive_in_curl',
  'cloud_metadata_ssrf', 'curl_upload', 'git_push_url', 'reverse_shell',
  'interactive_shell_redirect', 'git_push_non_origin',
  'base64_in_url', 'data_in_url',
  'curl_cmdsubst_url',
]);

export const HARD_DENY_PATTERNS: readonly string[] = [
  'exfil_domains', 'nc_connect', 'reverse_shell',
];

function isAllowlisted(command: string): boolean {
  for (let i = 0; i < ALLOWLIST_PATTERNS.length; i++) {
    const pattern = ALLOWLIST_PATTERNS[i];
    if (!pattern || !pattern.test(command)) continue;
    if (i === 0 && CURL_HAS_DATA_FLAG.test(command)) continue;
    return true;
  }
  return false;
}

export function checkCommand(command: string): [string, string] | null {
  try {
    const normalized = normalizeCommand(command);
    const variants = normalized === command ? [command] : [command, normalized];

    const neverDeny: string[] = [];
    const neverAsk: string[] = [];
    for (const name of NEVER_ALLOWLIST) {
      if (HARD_DENY_PATTERNS.includes(name)) {
        neverDeny.push(name);
      } else {
        neverAsk.push(name);
      }
    }

    for (const name of [...neverDeny, ...neverAsk]) {
      const pattern = EXFIL_PATTERNS.get(name);
      if (!pattern) continue;
      for (const text of variants) {
        const match = text.match(pattern);
        if (match) return [name, match[0]];
      }
    }

    if (isAllowlisted(command)) return null;

    for (const [name, pattern] of EXFIL_PATTERNS) {
      if (NEVER_ALLOWLIST.has(name)) continue;
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
