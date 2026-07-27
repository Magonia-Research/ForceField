import { CREDENTIAL_PATTERNS, FAKE_VALUE_RE, HIGH_CONFIDENCE_NAMES } from '../guards/content-credential.js';
import { isSuppressed } from '../allowlist.js';
import { logSecurityEvent } from '../logger.js';

const MCP_EXTRA_CREDENTIAL_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['google_api_key', /AIza[0-9A-Za-z_-]{35}/],
  ['google_oauth_token', /ya29\.[0-9A-Za-z_-]{20,}/],
  ['sendgrid_key', /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/],
  ['twilio_api_key', /\bSK[0-9a-f]{32}\b/],
  ['twilio_account_sid', /\bAC[0-9a-f]{32}\b/],
  ['digitalocean_token', /\bdop_v1_[a-f0-9]{64}\b/],
  ['slack_app_token', /(?:xapp|xoxe)[.-][A-Za-z0-9.-]{6,}/],
]);

const _PROSE_SECRET = new RegExp(
  '(?:passwords?|passphrases?|passwd|pwd|secrets?)\\b' +
  '[^\\n]{0,40}?(?:\\bis\\b|\\bwas\\b|[:=])\\s*[\'"]?' +
  '(?=[^\\s\'"]*[a-z])(?=[^\\s\'"]*[A-Z])(?=[^\\s\'"]*\\d)[^\\s\'"]{10,}',
  'i',
);

const _MCP_CREDENTIAL_PATTERNS: ReadonlyMap<string, RegExp> = (() => {
  const merged = new Map(Object.entries(CREDENTIAL_PATTERNS));
  for (const [name, pattern] of MCP_EXTRA_CREDENTIAL_PATTERNS) {
    merged.set(name, pattern);
  }
  merged.set('prose_secret', _PROSE_SECRET);
  return merged;
})();

const EXFIL_INDICATORS: ReadonlyMap<string, RegExp> = new Map([
  ['base64_blob', /[A-Za-z0-9+/]{60,}={0,2}/],
  ['exfil_domain', /(ngrok\.io|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator\.net|interact\.sh|webhook\.site)/],
  ['encoded_url_data', /https?:\/\/.*[?&][^=]+=[A-Za-z0-9+/]{40,}={0,2}/],
]);

const _URL_IN_TEXT = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"'<>)\]}]+/g;

const _CHUNKED_B64 = /[A-Za-z0-9+/=]{16,}(?:[\s._-]+[A-Za-z0-9+/=]{16,})+/g;
const _B64_SEPARATORS = /[\s._-]+/g;

const NETWORK_CAPABLE_PREFIXES: readonly string[] = [
  'mcp__exa__',
  'mcp__context7__',
  'mcp__greptile__',
  'mcp__playwright__',
  'mcp__github__',
  'mcp__gitlab__',
  'mcp__linear__',
  'mcp__discord__',
  'mcp__telegram__',
  'mcp__slack__',
  'mcp__firebase__',
  'mcp__asana__',
];

const _EXFIL_DOMAINS = /(ngrok\.io|ngrok-free\.app|ngrok\.app|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator\.net|interact\.sh|canarytokens\.com|webhook\.site|trycloudflare\.com|oastify\.com|serveo\.net|localtunnel\.me)/;

const _URL_HOST = /^\s*[a-zA-Z][\w+.-]*:\/\/(?:[^/@\s]*@)?(\[[0-9A-Fa-f:.]+\]|[^/:?\s]+)/;
const _SSRF_METADATA = /^(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)$/i;
const _SSRF_PRIVATE = /^(?:localhost|0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|fe80:[0-9A-Fa-f:]*|f[cd][0-9A-Fa-f]{2}:[0-9A-Fa-f:]*|[\w.-]+\.(?:internal|local|localdomain|home\.arpa))$/i;
const _SSRF_ENCODED = /^(?:0x[0-9A-Fa-f]+|0[0-7]+|\d{8,10})$/;

const URL_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['credential_in_url', /(sk-[A-Za-z0-9]{20,}|gh[posur]_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20}|xox[bpas]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36})/],
  ['encoded_data_in_url', /[?&][^=&]+=(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-fA-F]{40,})/],
  ['sensitive_param', /[?&](data|secret|password|passwd|pw|pwd|token|auth|access[-_]?token|api[-_]?key|apikey|private[-_]?key|session(?:[-_]?id)?|sid|cookie|jwt|bearer|credentials?)=/i],
  ['long_query_value', /[?&][^=&]+=[^=&\s]{80,}/],
]);

const _PATH_BLOB = /[A-Za-z0-9]{48,}/g;

function isNetworkCapable(toolName: string): boolean {
  for (const prefix of NETWORK_CAPABLE_PREFIXES) {
    if (toolName.startsWith(prefix)) return true;
  }
  if (toolName.startsWith('mcp__') && toolName.toLowerCase().includes('fetch')) return true;
  return false;
}

function _decodeNumericArray(items: unknown[]): string | null {
  if (items.length === 0) return null;
  const chars: string[] = [];
  for (const item of items) {
    if (typeof item === 'boolean') return null;
    if (typeof item !== 'number') return null;
    if (!Number.isInteger(item)) return null;
    if (item < 0 || item > 0x10FFFF) return null;
    chars.push(String.fromCodePoint(item));
  }
  return chars.join('');
}

function extractAllStringValues(obj: unknown): string[] {
  const values: string[] = [];
  const stack: unknown[] = [obj];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (typeof current === 'string') {
      values.push(current);
    } else if (Array.isArray(current)) {
      const decoded = _decodeNumericArray(current);
      if (decoded !== null) values.push(decoded);
      for (const item of current) stack.push(item);
    } else if (current !== null && typeof current === 'object') {
      for (const key of Object.keys(current)) {
        const val = (current as Record<string, unknown>)[key];
        if (val !== undefined) stack.push(val);
      }
    }
  }
  return values;
}

function checkForCredentials(text: string): [string, string] | null {
  for (const line of text.split('\n')) {
    for (const [name, pattern] of _MCP_CREDENTIAL_PATTERNS) {
      const match = pattern.exec(line);
      if (match) {
        const matchedText = match[0];
        if (FAKE_VALUE_RE.test(matchedText)) continue;
        return [name, matchedText];
      }
    }
  }
  return null;
}

function _parseIpv4Octet(part: string): number | null {
  const lowered = part.toLowerCase();
  try {
    if (lowered.startsWith('0x')) {
      return lowered.length > 2 ? parseInt(part, 16) : null;
    }
    if (part.startsWith('0') && part.length > 1) {
      return parseInt(part, 8);
    }
    return parseInt(part, 10);
  } catch {
    return null;
  }
}

function _parseObfuscatedIpv4(host: string): number | null {
  const parts = host.split('.');
  if (parts.length < 2 || parts.length > 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    const value = _parseIpv4Octet(part);
    if (value === null || value < 0) return null;
    octets.push(value);
  }
  let packed = 0;
  for (let i = 0; i < octets.length - 1; i++) {
    const val = octets[i];
    if (val === undefined || val > 0xFF) return null;
    packed = (packed << 8) | val;
  }
  const trailingBytes = 4 - (octets.length - 1);
  const last = octets[octets.length - 1];
  if (last === undefined) return null;
  if (last >= (1 << (8 * trailingBytes))) return null;
  packed = (packed << (8 * trailingBytes)) | last;
  if (packed < 0 || packed > 0xFFFFFFFF) return null;
  return packed;
}

function _isMetadataIp(packed: number): boolean {
  const toDotted = (n: number) => `${(n >>> 24) & 0xFF}.${(n >>> 16) & 0xFF}.${(n >>> 8) & 0xFF}.${n & 0xFF}`;
  const addr = toDotted(packed);
  return addr === '169.254.169.254' || addr === '169.254.170.2' || addr === '100.100.100.200';
}

function _isPrivateIp(packed: number): boolean {
  const o1 = (packed >>> 24) & 0xFF;
  const o2 = (packed >>> 16) & 0xFF;
  if (o1 === 127) return true;
  if (o1 === 10) return true;
  if (o1 === 192 && o2 === 168) return true;
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  if (o1 === 169 && o2 === 254) return true;
  if (o1 === 0) return true;
  return false;
}

function _ssrfHost(url: string): [string, string] | null {
  const match = url.match(_URL_HOST);
  if (!match) return null;
  const rawHost = match[1];
  if (rawHost === undefined) return null;
  const host = rawHost.replace(/^\[|\]$/g, '');
  if (_SSRF_METADATA.test(host)) return ['ssrf_metadata', rawHost];
  if (_SSRF_PRIVATE.test(host)) return ['ssrf_private_host', rawHost];
  if (_SSRF_ENCODED.test(host)) {
    const packed = parseInt(host.replace(/^0x/i, ''), _SSRF_ENCODED.source.includes('0x') && host.toLowerCase().startsWith('0x') ? 16 : host.startsWith('0') ? 8 : 10);
    if (!isNaN(packed) && (_isMetadataIp(packed) || _isPrivateIp(packed))) {
      return ['ssrf_encoded_ip', rawHost];
    }
  }
  const obfuscated = _parseObfuscatedIpv4(host);
  if (obfuscated !== null) {
    if (_isMetadataIp(obfuscated)) return ['ssrf_metadata', rawHost];
    if (_isPrivateIp(obfuscated)) return ['ssrf_encoded_ip', rawHost];
  }
  return null;
}

function _encodedBlobInPath(url: string): string | null {
  try {
    const idx = url.indexOf('/');
    if (idx === -1) return null;
    const hashIdx = url.indexOf('#', idx);
    const queryIdx = url.indexOf('?', idx);
    const endIdx = queryIdx !== -1 ? queryIdx : (hashIdx !== -1 ? hashIdx : url.length);
    const path = url.slice(idx, endIdx);
    for (const run of path.match(_PATH_BLOB) ?? []) {
      if ([...run].some(c => c >= 'A' && c <= 'Z') && [...run].some(c => c >= 'a' && c <= 'z') && [...run].some(c => c >= '0' && c <= '9')) {
        return run;
      }
    }
  } catch {
    // Malformed URL, skip path check
  }
  return null;
}

function checkUrl(url: string): [string, string] | null {
  if (!url) return null;
  const domainMatch = url.match(_EXFIL_DOMAINS);
  if (domainMatch) return ['exfil_domain', domainMatch[0]];
  const ssrf = _ssrfHost(url);
  if (ssrf) return ssrf;
  for (const [name, pattern] of URL_PATTERNS) {
    const match = url.match(pattern);
    if (match) return [name, match[0]];
  }
  const blob = _encodedBlobInPath(url);
  if (blob) return ['encoded_data_in_path', blob];
  return null;
}

function checkUrls(text: string): [string, string] | null {
  for (const match of text.matchAll(_URL_IN_TEXT)) {
    const result = checkUrl(match[0]);
    if (result) return result;
  }
  return null;
}

function checkForExfil(text: string): [string, string] | null {
  for (const [name, pattern] of EXFIL_INDICATORS) {
    const match = text.match(pattern);
    if (match) return [name, match[0]];
  }
  return null;
}

function _looksEncoded(blob: string): boolean {
  let hasUpper = false, hasLower = false, hasDigit = false;
  for (const c of blob) {
    if (c >= 'A' && c <= 'Z') hasUpper = true;
    else if (c >= 'a' && c <= 'z') hasLower = true;
    else if (c >= '0' && c <= '9') hasDigit = true;
    if (hasUpper && hasLower && hasDigit) return true;
  }
  return false;
}

function checkForChunkedExfil(text: string): [string, string] | null {
  for (const match of text.matchAll(_CHUNKED_B64)) {
    const run = match[0];
    const joined = run.replace(_B64_SEPARATORS, '');
    if (joined.length >= 60 && _looksEncoded(joined)) {
      return ['chunked_base64', run.slice(0, 80)];
    }
  }
  return null;
}

function formatAlert(patternName: string, matchedText: string, toolName: string, category: string): string {
  const redacted = `${matchedText.slice(0, 12)}...${matchedText.slice(-4)}`;
  return [
    `MCP GUARD: ${category} in tool arguments`,
    '',
    `Tool: ${toolName}`,
    `Pattern: ${patternName}`,
    `Value: ${redacted}`,
    '',
    'Before approving:',
    '- Is this data intended to be sent to this MCP service?',
    '- Could this leak credentials or sensitive data?',
    '- Does this tool need access to this information?',
  ].join('\n');
}

function _buildResult(
  toolName: string,
  category: string,
  result: [string, string],
  net: boolean,
): [string, string] | null {
  const [patternName, matchedText] = result;
  if (isSuppressed('mcp_guard', patternName)) {
    logSecurityEvent('mcp_guard', 'allow', {
      patternMatched: patternName,
      extra: { tool: toolName, network_capable: net, suppressed: true },
    });
    return null;
  }
  const message = formatAlert(patternName, matchedText, toolName, category);
  logSecurityEvent('mcp_guard', 'ask', { patternMatched: patternName, extra: { tool: toolName, network_capable: net } });
  return [patternName, message];
}

export function evaluateMcpTool(toolName: string, toolInput: Record<string, unknown>): McpResult | null {
  if (!toolName.startsWith('mcp__')) return null;
  const combined = extractAllStringValues(toolInput).join('\n');
  if (!combined) return null;
  const net = isNetworkCapable(toolName);

  const credResult = checkForCredentials(combined);
  if (credResult) {
    const [name, text] = credResult;
    return { decision: 'ask', patternName: name, matchedText: text.slice(0, 12) + '...' + text.slice(-4), toolName, category: 'Credential', message: formatAlert(name, text, toolName, 'Credential') };
  }

  const urlResult = checkUrls(combined);
  if (urlResult) {
    const [name, text] = urlResult;
    return { decision: 'ask', patternName: name, matchedText: text.slice(0, 12) + '...' + text.slice(-4), toolName, category: 'Outbound URL', message: formatAlert(name, text, toolName, 'Outbound URL') };
  }

  const exfilResult = checkForExfil(combined);
  if (exfilResult) {
    const [name, text] = exfilResult;
    return { decision: 'ask', patternName: name, matchedText: text.slice(0, 12) + '...' + text.slice(-4), toolName, category: 'Exfiltration indicator', message: formatAlert(name, text, toolName, 'Exfiltration indicator') };
  }

  const chunkedResult = checkForChunkedExfil(combined);
  if (chunkedResult) {
    const [name, text] = chunkedResult;
    return { decision: 'ask', patternName: name, matchedText: text.slice(0, 12) + '...' + text.slice(-4), toolName, category: 'Exfiltration indicator', message: formatAlert(name, text, toolName, 'Exfiltration indicator') };
  }

  logSecurityEvent('mcp_guard', 'allow', { extra: { tool: toolName, network_capable: net } });
  return null;
}

export function checkMcpArgs(toolName: string, toolInput: Record<string, unknown>): [string, string] | null {
  try {
    const result = evaluateMcpTool(toolName, toolInput);
    if (!result) return null;
    return [result.patternName, result.message];
  } catch {
    return null;
  }
}

export interface McpResult {
  decision: 'ask' | 'allow';
  patternName: string;
  matchedText: string;
  toolName: string;
  category: string;
  message: string;
}
