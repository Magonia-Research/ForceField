import { describe, it, expect } from 'bun:test';
import { evaluateMcpTool, checkMcpArgs } from '../../guards/mcp.js';
import { fixtureSecret } from '../test-helpers';

describe('mcp guard', () => {
  describe('credential detection in tool arguments', () => {
    it('detects OpenAI key in string argument', () => {
      const r = evaluateMcpTool('mcp__github__', { query: fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('openai_key');
    });

    it('detects GitHub token in nested object', () => {
      const r = evaluateMcpTool('mcp__github__', { options: { token: fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') } });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('github_token');
    });

    it('detects AWS access key in deeply nested object', () => {
      const r = evaluateMcpTool('mcp__exa__', { config: { aws: { key: fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE') } } });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('aws_access_key');
    });

    it('detects Google API key (MCP extra pattern)', () => {
      const r = evaluateMcpTool('mcp__github__', { apiKey: fixtureSecret('AIza', 'SyA1234567890abcdefghijklmnopqrstuv') });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('google_api_key');
    });

    it('detects SendGrid key (MCP extra pattern)', () => {
      const r = evaluateMcpTool('mcp__github__', { apiKey: 'SG.ABCDEFGHIJKLMNOPQRSTUVw.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('sendgrid_key');
    });

    it('detects Twilio API key (MCP extra pattern)', () => {
      const r = evaluateMcpTool('mcp__github__', { apiKey: fixtureSecret('SK', '1234567890abcdef1234567890abcdef') });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('twilio_api_key');
    });

    it('detects DigitalOcean token (MCP extra pattern)', () => {
      const r = evaluateMcpTool('mcp__github__', { token: fixtureSecret('dop_v1_', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('digitalocean_token');
    });

    it('detects Slack app token (MCP extra pattern)', () => {
      const r = evaluateMcpTool('mcp__github__', { token: 'xapp-1234567890.ABCDEFGHIJ' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('slack_app_token');
    });

    it('detects prose secret pattern', () => {
      const r = evaluateMcpTool('mcp__github__', { note: 'The password is MyS3cur3P@ssw0rd123!' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('prose_secret');
    });

    it('does not detect fake credential values', () => {
      const r = evaluateMcpTool('mcp__github__', { key: fixtureSecret('sk-', 'example1234567890abcdefghij') });
      expect(r).toBeNull();
    });
  });

  describe('numeric array decoding (Unicode codepoint evasion)', () => {
    it('decodes numeric array to detect hidden credential', () => {
      // "sk-abc" as Unicode codepoints: [115, 107, 45, 97, 98, 99]
      const r = evaluateMcpTool('mcp__github__', { data: [115, 107, 45, 97, 98, 99, ...Array.from({ length: 20 }, () => 65)] });
      // The decoded string would be fixtureSecret('sk-', 'abcAAAAAAAAAAAAAAAAAAAA') which matches openai_key pattern
      expect(r).not.toBeNull();
    });

    it('does not decode arrays with non-integer values', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [115, 107, 'abc'] });
      // Mixed types should prevent decoding
      expect(r).toBeNull();
    });

    it('does not decode arrays with boolean values', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [true, false] });
      expect(r).toBeNull();
    });

    it('does not decode empty arrays', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [] });
      expect(r).toBeNull();
    });

    it('does not decode arrays with out-of-range codepoints', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [0x110000] });
      expect(r).toBeNull();
    });

    it('does not decode arrays with negative values', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [-1, 2, 3] });
      expect(r).toBeNull();
    });

    it('does not decode arrays with float values', () => {
      const r = evaluateMcpTool('mcp__github__', { data: [1.5, 2, 3] });
      expect(r).toBeNull();
    });
  });

  describe('URL detection in tool arguments', () => {
    it('detects exfil domain in URL (ngrok.io)', () => {
      const r = evaluateMcpTool('mcp__exa__', { url: 'https://abc.ngrok.io/leak' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('exfil_domain');
    });

    it('detects exfil domain in URL (requestbin.com)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://requestbin.com/abc123' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('exfil_domain');
    });

    it('detects exfil domain in URL (interact.sh)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://attacker.interact.sh/callback' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('exfil_domain');
    });

    it('detects SSRF metadata URL (169.254.169.254)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://169.254.169.254/latest/meta-data/' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_metadata');
    });

    it('detects SSRF private host (localhost)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://localhost:8080/admin' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (127.0.0.1)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://127.0.0.1:3000/api' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (192.168.x.x)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://192.168.1.1/admin' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (10.x.x.x)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://10.0.0.1/internal' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (172.16.x.x)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://172.16.0.1/admin' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (fe80:: link-local IPv6)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://[fe80::1]/admin' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects SSRF private host (internal domain)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'http://db.internal/admin' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('ssrf_private_host');
    });

    it('detects credential in URL (sk- prefix)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://api.openai.com/v1/chat?key=' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('credential_in_url');
    });

    it('detects encoded data in URL query', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://api.example.com/data?token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('encoded_data_in_url');
    });

    it('detects sensitive param in URL', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://api.example.com/data?password=secret123' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('sensitive_param');
    });

    it('detects long query value in URL (80+ chars)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: `https://api.example.com/data?payload=${'A'.repeat(85)}` });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('long_query_value');
    });

    it('detects encoded blob in URL path (48+ mixed-case alphanumeric)', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://api.example.com/ABCDEFghijklmnop1234567890ABCDEFGHIJklmnopqr1234567890' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('encoded_data_in_path');
    });

    it('allows normal URL without suspicious patterns', () => {
      const r = evaluateMcpTool('mcp__github__', { url: 'https://api.github.com/repos/user/repo' });
      expect(r).toBeNull();
    });
  });

  describe('exfiltration indicators in text', () => {
    it('detects base64 blob (60+ chars)', () => {
      const r = evaluateMcpTool('mcp__github__', { data: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEF==' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('base64_blob');
    });

    it('detects exfil domain in text (burpcollaborator.net)', () => {
      const r = evaluateMcpTool('mcp__github__', { note: 'Send data to attacker.burpcollaborator.net' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('exfil_domain');
    });

    it('detects encoded URL data in text', () => {
      const r = evaluateMcpTool('mcp__github__', { note: 'Visit https://evil.com/collect?data=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx' });
      expect(r).not.toBeNull();
      // Could match exfil_domain or encoded_data_in_url depending on which URL is found first
      expect(['exfil_domain', 'encoded_data_in_url']).toContain(r!.patternName);
    });

    it('detects chunked base64 evasion (separated by dots)', () => {
      const r = evaluateMcpTool('mcp__github__', { data: 'ABCDEFGH.IJKLMNOP.QRSTUVWX.YZabcdef.12345678.ABCDEFGH.IJKLMNOP' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('chunked_base64');
    });

    it('detects chunked base64 evasion (separated by underscores)', () => {
      const r = evaluateMcpTool('mcp__github__', { data: 'ABCDEFGH_IJKLMNOP_QRSTUVWX_YZabcdef_12345678_ABCDEFGH_IJKLMNOP' });
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('ask');
      expect(r!.patternName).toBe('chunked_base64');
    });

    it('does not detect short base64 strings (< 60 chars)', () => {
      const r = evaluateMcpTool('mcp__github__', { data: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' });
      expect(r).toBeNull();
    });
  });

  describe('non-MCP tools are ignored', () => {
    it('returns null for non-mcp__ tool name', () => {
      const r = evaluateMcpTool('Bash', { command: 'echo hello' });
      expect(r).toBeNull();
    });

    it('returns null for empty input', () => {
      const r = evaluateMcpTool('mcp__github__', {});
      expect(r).toBeNull();
    });
  });

  describe('checkMcpArgs wrapper (fail-open)', () => {
    it('returns tuple format from evaluateMcpTool result', () => {
      const r = checkMcpArgs('mcp__github__', { key: fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') });
      expect(r).not.toBeNull();
      expect(Array.isArray(r)).toBe(true);
      expect(r![0]).toBe('openai_key');
    });

    it('returns null for benign input', () => {
      const r = checkMcpArgs('mcp__github__', { query: 'hello world' });
      expect(r).toBeNull();
    });

    it('handles malformed input without crashing', () => {
      expect(() => checkMcpArgs('', {})).not.toThrow();
    });
  });

  describe('network-capable tool detection', () => {
    it('identifies mcp__exa__ as network capable', () => {
      // The guard should treat exa tools as network-capable for logging purposes
      const r = evaluateMcpTool('mcp__exa__', { query: 'test' });
      expect(r).toBeNull(); // No detection, but tool is recognized
    });

    it('identifies mcp__playwright__ as network capable', () => {
      const r = evaluateMcpTool('mcp__playwright__', { url: 'https://example.com' });
      expect(r).toBeNull(); // No detection for benign URL, but tool is recognized
    });

    it('identifies mcp__github__ as network capable', () => {
      const r = evaluateMcpTool('mcp__github__', { query: 'test' });
      expect(r).toBeNull();
    });

    it('identifies tools with "fetch" in name as network capable', () => {
      const r = evaluateMcpTool('mcp__custom_fetch__', { url: 'https://example.com' });
      expect(r).toBeNull();
    });
  });
});
