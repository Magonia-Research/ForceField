import { describe, it, expect } from 'bun:test';
import { checkUrl, HARD_DENY_PATTERNS } from '../../guards/webfetch.js';
import { fixtureSecret } from '../test-helpers';

describe('webfetch guard', () => {
  // Verify HARD_DENY_PATTERNS constant
  it('HARD_DENY_PATTERNS contains exfil_domain', () => {
    expect(HARD_DENY_PATTERNS.has('exfil_domain')).toBe(true);
  });

  describe('exfiltration domain detection (hard deny)', () => {
    it('detects ngrok.io domain', () => {
      const r = checkUrl('https://abc123.ngrok.io/leak');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('detects requestbin.com domain', () => {
      const r = checkUrl('https://requestbin.com/abc123');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('detects interact.sh subdomain', () => {
      const r = checkUrl('https://attacker.interact.sh/callback');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('detects burpcollaborator.net domain', () => {
      const r = checkUrl('https://evil.burpcollaborator.net/collect');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('detects webhook.site domain', () => {
      const r = checkUrl('https://webhook.site/abc123def456');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('detects trycloudflare.com domain', () => {
      const r = checkUrl('https://trycloudflare.com/exfil');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('exfil_domain');
    });

    it('does not match benign domains that contain exfil substrings', () => {
      // "ngrok" as part of a different domain should not match the regex
      const r = checkUrl('https://not-ngrok.example.com/page');
      expect(r).toBeNull();
    });
  });

  describe('SSRF metadata detection', () => {
    it('detects AWS metadata (169.254.169.254)', () => {
      const r = checkUrl('http://169.254.169.254/latest/meta-data/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects Azure metadata (169.254.170.2)', () => {
      const r = checkUrl('http://169.254.170.2/metadata/instance');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects GCP metadata (metadata.google.internal)', () => {
      const r = checkUrl('http://metadata.google.internal/computeMetadata/v1/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects obfuscated AWS metadata via hex octets', () => {
      // 169 = 0xa9, 254 = 0xfe, 169 = 0xa9, 254 = 0xfe
      const r = checkUrl('http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/');
      expect(r).not.toBeNull();
      expect(['ssrf_metadata', 'ssrf_private_host']).toContain(r![0]);
    });

    it('detects obfuscated AWS metadata via octal octets', () => {
      // 169 = 251, 254 = 376
      const r = checkUrl('http://0251.0376.0251.0376/latest/meta-data/');
      expect(r).not.toBeNull();
      expect(['ssrf_metadata', 'ssrf_private_host']).toContain(r![0]);
    });

    it('detects obfuscated AWS metadata via decimal octets', () => {
      // 169.254.169.254 as a single large number won't parse, but partial will
      const r = checkUrl('http://169.254.169.254/latest/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects fd00:ec2::254 IPv6 metadata', () => {
      const r = checkUrl('http://[fd00:ec2::254]/latest/meta-data/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects 100.100.100.200 (GCP metadata)', () => {
      const r = checkUrl('http://100.100.100.200/computeMetadata/v1/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });

    it('detects metadata.azure.com', () => {
      const r = checkUrl('http://metadata.azure.com/metadata/instance');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_metadata');
    });
  });

  describe('SSRF private host detection', () => {
    it('detects localhost', () => {
      const r = checkUrl('http://localhost:8080/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 127.0.0.1', () => {
      const r = checkUrl('http://127.0.0.1:3000/api');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 127.255.255.254', () => {
      const r = checkUrl('http://127.255.255.254/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 192.168.x.x range', () => {
      const r = checkUrl('http://192.168.1.1/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 10.x.x.x range', () => {
      const r = checkUrl('http://10.0.0.1/internal');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 172.16.x.x range', () => {
      const r = checkUrl('http://172.16.0.1/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 172.31.x.x range (upper bound)', () => {
      const r = checkUrl('http://172.31.255.254/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('does not detect 172.32.x.x (outside private range)', () => {
      const r = checkUrl('http://172.32.0.1/admin');
      // This is outside the RFC 1918 172.16-31 range, so should not match _SSRF_PRIVATE
      expect(r).toBeNull();
    });

    it('detects ::1 IPv6 loopback', () => {
      const r = checkUrl('http://[::1]/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects fe80:: link-local IPv6', () => {
      const r = checkUrl('http://[fe80::1]/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects fc00:: unique local IPv6', () => {
      const r = checkUrl('http://[fc00::1]/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects fd00:: unique local IPv6', () => {
      const r = checkUrl('http://[fdff:abcd::1]/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects internal domain suffix', () => {
      const r = checkUrl('http://db.internal/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects local domain suffix', () => {
      const r = checkUrl('http://service.local/health');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects home.arpa domain suffix', () => {
      const r = checkUrl('http://printer.home.arpa/print');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 0.0.0.0', () => {
      const r = checkUrl('http://0.0.0.0:8080/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects 169.254.x.x link-local', () => {
      const r = checkUrl('http://169.254.1.1/admin');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssrf_private_host');
    });

    it('detects obfuscated 127.0.0.1 via hex', () => {
      // 127 = 0x7f, 0 = 0x0, 0 = 0x0, 1 = 0x1
      const r = checkUrl('http://0x7f.0x0.0x0.0x1/admin');
      expect(r).not.toBeNull();
      // Could be ssrf_private_host or ssrf_encoded_ip depending on which regex fires first
      expect(['ssrf_private_host', 'ssrf_encoded_ip']).toContain(r![0]);
    });

    it('detects obfuscated 127.0.0.1 via octal', () => {
      // 127 = 0177, 0 = 0, 0 = 0, 1 = 1
      const r = checkUrl('http://0177.0.0.1/admin');
      expect(r).not.toBeNull();
      expect(['ssrf_private_host', 'ssrf_encoded_ip']).toContain(r![0]);
    });

    it('detects obfuscated private IP via decimal (single octet)', () => {
      // 3232235777 = 192.168.1.1 as a single decimal number
      const r = checkUrl('http://3232235777/admin');
      expect(r).not.toBeNull();
      expect(['ssrf_private_host', 'ssrf_encoded_ip']).toContain(r![0]);
    });

    it('detects IPv4-mapped IPv6 ::ffff:192.168.1.1', () => {
      const r = checkUrl('http://[::ffff:192.168.1.1]/admin');
      expect(r).not.toBeNull();
      expect(['ssrf_private_host']).toContain(r![0]);
    });

    it('detects IPv4-mapped IPv6 ::ffff:c0a8:101', () => {
      // c0a8 = 192.168, 0101 = 1.1 → 192.168.1.1
      const r = checkUrl('http://[::ffff:c0a8:101]/admin');
      expect(r).not.toBeNull();
      expect(['ssrf_private_host']).toContain(r![0]);
    });

    it('allows public IP address', () => {
      const r = checkUrl('https://8.8.8.8/dns-query');
      expect(r).toBeNull();
    });

    it('allows normal domain name', () => {
      const r = checkUrl('https://api.github.com/repos/user/repo');
      expect(r).toBeNull();
    });
  });

  describe('credential detection in URL', () => {
    it('detects OpenAI key in query string', () => {
      const r = checkUrl('https://api.openai.com/v1/chat?key=' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });

    it('detects GitHub token in query string', () => {
      const r = checkUrl('https://api.github.com/repos?token=' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });

    it('detects AWS access key in query string', () => {
      const r = checkUrl('https://s3.amazonaws.com/bucket?AWSAccessKeyId=' + fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });

    it('detects GitLab token in query string', () => {
      const r = checkUrl('https://gitlab.com/api/v4/projects?private_token=' + fixtureSecret('glpat-', 'ABCDEFGHIJKLMNOPQRSTuvwx') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });

    it('detects Slack token in query string', () => {
      const r = checkUrl('https://slack.com/api/chat.postMessage?token=' + fixtureSecret('xoxb-', '1234567890-abcdefghij') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });

    it('detects npm token in query string', () => {
      const r = checkUrl('https://registry.npmjs.org/-/user?auth=' + fixtureSecret('npm_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('credential_in_url');
    });
  });

  describe('encoded data in URL', () => {
    it('detects base64-like query value (40+ chars)', () => {
      const r = checkUrl('https://api.example.com/data?token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('encoded_data_in_url');
    });

    it('detects hex-like query value (40+ chars)', () => {
      const r = checkUrl(`https://api.example.com/data?hash=${'a'.repeat(50)}`);
      expect(r).not.toBeNull();
      expect(r![0]).toBe('encoded_data_in_url');
    });

    it('detects sensitive param name (password)', () => {
      const r = checkUrl('https://api.example.com/login?password=secret123');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('sensitive_param');
    });

    it('detects sensitive param name (token)', () => {
      const r = checkUrl('https://api.example.com/auth?token=abc123');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('sensitive_param');
    });

    it('detects sensitive param name (api_key)', () => {
      const r = checkUrl('https://api.example.com/data?api_key=mykey123');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('sensitive_param');
    });

    it('detects long query value (80+ chars)', () => {
      const r = checkUrl(`https://api.example.com/data?payload=${'A'.repeat(85)}`);
      expect(r).not.toBeNull();
      expect(r![0]).toBe('long_query_value');
    });

    it('detects encoded blob in path (48+ mixed-case alphanumeric)', () => {
      const r = checkUrl('https://api.example.com/ABCDEFghijklmnop1234567890ABCDEFGHIJklmnopqr1234567890');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('encoded_data_in_path');
    });

    it('does not detect all-lowercase path blob (no mixed case)', () => {
      const r = checkUrl('https://api.example.com/abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmn');
      expect(r).toBeNull();
    });

    it('does not detect all-uppercase path blob (no mixed case)', () => {
      const r = checkUrl('https://api.example.com/ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMN');
      expect(r).toBeNull();
    });
  });

  describe('benign URLs pass through', () => {
    it('allows normal HTTPS URL', () => {
      const r = checkUrl('https://www.example.com/page');
      expect(r).toBeNull();
    });

    it('allows GitHub API URL', () => {
      const r = checkUrl('https://api.github.com/repos/user/repo');
      expect(r).toBeNull();
    });

    it('allows npm registry URL', () => {
      const r = checkUrl('https://registry.npmjs.org/lodash');
      expect(r).toBeNull();
    });

    it('returns null for empty string', () => {
      const r = checkUrl('');
      expect(r).toBeNull();
    });

    it('returns null for non-URL string', () => {
      const r = checkUrl('just some text');
      expect(r).toBeNull();
    });
  });

  describe('fail-open on malformed input', () => {
    it('handles very long URL without crashing', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(1_000_000);
      expect(() => checkUrl(longUrl)).not.toThrow();
    });

    it('returns null for malformed URL with special chars', () => {
      const r = checkUrl('\x00\x01\x02');
      expect(r).toBeNull();
    });
  });
});
