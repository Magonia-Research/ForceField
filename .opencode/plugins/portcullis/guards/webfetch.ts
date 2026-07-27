import { EXFIL_PATTERNS } from '../guards/exfil.js';

const _EXFIL_DOMAINS = EXFIL_PATTERNS.get('exfil_domains');

export const HARD_DENY_PATTERNS: ReadonlySet<string> = new Set(['exfil_domain']);

const _URL_HOST = /^\s*[a-zA-Z][\w+.-]*:\/\//;
const _SSRF_METADATA = /^(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)$/i;
const _SSRF_PRIVATE = /^(?:localhost|0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|::1|fe80:[0-9A-Fa-f:]*|f[cd][0-9A-Fa-f]{2}:[0-9A-Fa-f:]*|[\w.-]+\.(?:internal|local|localdomain|home\.arpa))$/i;
const _SSRF_ENCODED = /^(?:0x[0-9A-Fa-f]+|0[0-7]+|\d{8,10})$/;

const _CREDENTIAL_IN_URL = /(sk-[A-Za-z0-9]{20,}|gh[posur]_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20}|xox[bpas]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36})/;
const _ENCODED_DATA_IN_URL = /[?&][^=&]+=(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-fA-F]{40,})/;
const _SENSITIVE_PARAM = /[?&](data|secret|password|passwd|pw|pwd|token|auth|access[-_]?token|api[-_]?key|apikey|private[-_]?key|session(?:[-_]?id)?|sid|cookie|jwt|bearer|credentials?)=/i;
const _LONG_QUERY_VALUE = /[?&][^=&]+=[^=&\s]{80,}/;

const _PATH_BLOB = /[A-Za-z0-9]{48,}/g;

function _parseIpv4Octet(part: string): number | null {
  const lowered = part.toLowerCase();
  try {
    if (lowered.startsWith('0x')) return part.length > 2 ? parseInt(part, 16) : null;
    if (part.startsWith('0') && part.length > 1) return parseInt(part, 8);
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
    if (val === undefined || val > 255) return null;
    packed = (packed << 8) | val;
  }
  const trailingBytes = 4 - (octets.length - 1);
  const last = octets[octets.length - 1];
  if (last === undefined) return null;
  if (last >= (1 << (8 * trailingBytes))) return null;
  packed = (packed << (8 * trailingBytes)) | last;
  return packed >>> 0;
}

const _METADATA_PACKED: ReadonlySet<number> = new Set([
  ((169 << 24) | (254 << 16) | (169 << 8) | 254) >>> 0,
  ((169 << 24) | (254 << 16) | (170 << 8) | 2) >>> 0,
  ((100 << 24) | (100 << 16) | (100 << 8) | 200) >>> 0,
]);

function _isMetadataPacked(packed: number): boolean {
  return _METADATA_PACKED.has(packed);
}

function _isPrivateOrSpecialPacked(packed: number): boolean {
  const b1 = (packed >> 24) & 0xff;
  const b2 = (packed >> 16) & 0xff;
  if (b1 === 127) return true;
  if (b1 === 10) return true;
  if (b1 === 172 && b2 >= 16 && b2 <= 31) return true;
  if (b1 === 192 && b2 === 168) return true;
  if (b1 === 0) return true;
  if (b1 === 169 && b2 === 254) return true;
  if (b1 >= 224) return true;
  return false;
}

function _classifyPackedIpv4(packed: number): string | null {
  if (_isMetadataPacked(packed)) return 'ssrf_metadata';
  if (_isPrivateOrSpecialPacked(packed)) return 'ssrf_private_host';
  return null;
}

function _extractV4FromMapped(host: string): string | null {
  const idx = host.lastIndexOf(':');
  if (idx === -1) return null;
  const after = host.slice(idx + 1);
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(after)) return after;
  const hexMatch = /:(\w{4}):(\w{4})$/.exec(host);
  if (hexMatch && hexMatch[1] && hexMatch[2]) {
    const a = parseInt(hexMatch[1], 16);
    const b = parseInt(hexMatch[2], 16);
    return `${(a >> 8) & 0xff}.${a & 0xff}.${(b >> 8) & 0xff}.${b & 0xff}`;
  }
  return null;
}

function _canonicalSsrf(host: string): string | null {
  if (host.includes(':')) {
    const v4 = _extractV4FromMapped(host);
    if (v4) {
      const packed = _parseObfuscatedIpv4(v4);
      if (packed !== null) return _classifyPackedIpv4(packed);
    }
    return null;
  }
  const packed = _parseObfuscatedIpv4(host);
  if (packed === null) return null;
  return _classifyPackedIpv4(packed);
}

function _ssrfHost(url: string): [string, string] | null {
  if (!_URL_HOST.test(url)) return null;
  const protoEnd = url.indexOf('://');
  if (protoEnd === -1) return null;
  let afterProto = url.slice(protoEnd + 3);
  const atIdx = afterProto.indexOf('@');
  if (atIdx !== -1) afterProto = afterProto.slice(atIdx + 1);
  let rawHost: string;
  if (afterProto.startsWith('[')) {
    const closeBracket = afterProto.indexOf(']');
    if (closeBracket === -1) return null;
    rawHost = afterProto.slice(0, closeBracket + 1);
  } else {
    const delimiterIdx = Math.min(
      afterProto.indexOf('/') !== -1 ? afterProto.indexOf('/') : Infinity,
      afterProto.indexOf(':') !== -1 ? afterProto.indexOf(':') : Infinity,
      afterProto.indexOf('?') !== -1 ? afterProto.indexOf('?') : Infinity,
      afterProto.indexOf('#') !== -1 ? afterProto.indexOf('#') : Infinity,
    );
    rawHost = delimiterIdx === Infinity ? afterProto : afterProto.slice(0, delimiterIdx);
  }
  const host = rawHost.replace(/^\[|\]$/g, '');
  if (_SSRF_METADATA.test(host)) return ['ssrf_metadata', rawHost];
  if (_SSRF_PRIVATE.test(host)) return ['ssrf_private_host', rawHost];
  if (_SSRF_ENCODED.test(host)) return ['ssrf_encoded_ip', rawHost];
  const encoded = _canonicalSsrf(host);
  if (encoded) return [encoded, rawHost];
  return null;
}

function _looksEncoded(run: string): boolean {
  let hasUpper = false, hasLower = false, hasDigit = false;
  for (let i = 0; i < run.length; i++) {
    const c = run.charAt(i);
    if (c >= 'A' && c <= 'Z') hasUpper = true;
    else if (c >= 'a' && c <= 'z') hasLower = true;
    else if (c >= '0' && c <= '9') hasDigit = true;
  }
  return hasUpper && hasLower && hasDigit;
}

function _encodedBlobInPath(url: string): string | null {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname;
    _PATH_BLOB.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = _PATH_BLOB.exec(path)) !== null) {
      if (_looksEncoded(match[0])) return match[0];
    }
  } catch {
    const pathMatch = /^https?:\/\/[^\/]+(\/[^?#]*)/.exec(url);
    if (!pathMatch || !pathMatch[1]) return null;
    const path = pathMatch[1];
    _PATH_BLOB.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = _PATH_BLOB.exec(path)) !== null) {
      if (_looksEncoded(match[0])) return match[0];
    }
  }
  return null;
}

export function checkUrl(url: string): [string, string] | null {
  try {
    if (!url || !_EXFIL_DOMAINS) return null;
    const domainMatch = url.match(_EXFIL_DOMAINS);
    if (domainMatch) return ['exfil_domain', domainMatch[0]];
    const ssrf = _ssrfHost(url);
    if (ssrf) return ssrf;
    const credMatch = url.match(_CREDENTIAL_IN_URL);
    if (credMatch) return ['credential_in_url', credMatch[0]];
    const encodedMatch = url.match(_ENCODED_DATA_IN_URL);
    if (encodedMatch) return ['encoded_data_in_url', encodedMatch[0]];
    const sensitiveMatch = url.match(_SENSITIVE_PARAM);
    if (sensitiveMatch) return ['sensitive_param', sensitiveMatch[0]];
    const longMatch = url.match(_LONG_QUERY_VALUE);
    if (longMatch) return ['long_query_value', longMatch[0]];
    const blob = _encodedBlobInPath(url);
    if (blob) return ['encoded_data_in_path', blob];
    return null;
  } catch {
    return null;
  }
}
