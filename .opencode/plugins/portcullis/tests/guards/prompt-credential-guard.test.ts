import { describe, it, expect } from 'bun:test';
import { scanPrompt, BLOCK_PATTERNS, WARN_PATTERNS, SUGGESTED_ENV_VARS, PATTERN_DESCRIPTIONS, hasNearbyFakeContext, NEARBY_FAKE_CONTEXT } from '../../guards/prompt-credential-guard.js';
import { fixtureSecret } from '../test-helpers';

describe('prompt-credential-guard', () => {
  describe('BLOCK_PATTERNS', () => {
    it('contains private_key_header', () => {
      expect(BLOCK_PATTERNS.has('private_key_header')).toBe(true);
    });

    it('has exactly one pattern', () => {
      expect(BLOCK_PATTERNS.size).toBe(1);
    });
  });

  describe('WARN_PATTERNS', () => {
    const EXPECTED_WARN = [
      'openai_key', 'anthropic_key',
      'aws_access_key', 'aws_sts_key',
      'github_token', 'github_oauth_token', 'github_server_token',
      'github_fine_grained', 'gitlab_token', 'npm_token',
      'slack_token', 'stripe_key',
    ];

    for (const name of EXPECTED_WARN) {
      it(`contains ${name}`, () => {
        expect(WARN_PATTERNS.has(name)).toBe(true);
      });
    }

    it('has exactly 12 warn patterns', () => {
      expect(WARN_PATTERNS.size).toBe(12);
    });
  });

  describe('SUGGESTED_ENV_VARS mapping', () => {
    const EXPECTED_MAP: Record<string, string> = {
      openai_key: 'OPENAI_API_KEY',
      anthropic_key: 'ANTHROPIC_API_KEY',
      aws_access_key: 'AWS_ACCESS_KEY_ID',
      aws_sts_key: 'AWS_ACCESS_KEY_ID',
      github_token: 'GITHUB_TOKEN',
      github_oauth_token: 'GITHUB_TOKEN',
      github_server_token: 'GITHUB_TOKEN',
      github_fine_grained: 'GITHUB_TOKEN',
      gitlab_token: 'GITLAB_TOKEN',
      npm_token: 'NPM_TOKEN',
      slack_token: 'SLACK_TOKEN',
      stripe_key: 'STRIPE_API_KEY',
    };

    for (const [pattern, envVar] of Object.entries(EXPECTED_MAP)) {
      it(`maps ${pattern} to ${envVar}`, () => {
        expect(SUGGESTED_ENV_VARS[pattern]).toBe(envVar);
      });
    }
  });

  describe('PATTERN_DESCRIPTIONS', () => {
    it('describes openai_key as OpenAI API key', () => {
      expect(PATTERN_DESCRIPTIONS.openai_key).toBe('OpenAI API key');
    });

    it('describes private_key_header as private key', () => {
      expect(PATTERN_DESCRIPTIONS.private_key_header).toBe('private key');
    });

    it('has descriptions for all 13 patterns (12 warn + 1 block)', () => {
      expect(Object.keys(PATTERN_DESCRIPTIONS).length).toBe(13);
    });
  });

  describe('NEARBY_FAKE_CONTEXT regex', () => {
    const FAKE_KEYWORDS = ['example', 'placeholder', 'dummy', 'fake', 'test', 'sample', 'demo'];

    for (const kw of FAKE_KEYWORDS) {
      it(`matches keyword: ${kw}`, () => {
        expect(NEARBY_FAKE_CONTEXT.test(kw)).toBe(true);
      });
    }

    it('does not match normal text', () => {
      expect(NEARBY_FAKE_CONTEXT.test('This is a production API key')).toBe(false);
    });
  });

  describe('hasNearbyFakeContext', () => {
    it('detects fake context within 50 chars before match', () => {
      const prompt = 'example: ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '';
      expect(hasNearbyFakeContext(prompt, 9)).toBe(true);
    });

    it('detects fake context within 50 chars after match', () => {
      const prompt = '' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + ' placeholder';
      expect(hasNearbyFakeContext(prompt, 0)).toBe(true);
    });

    it('does not detect fake context beyond 50 char window', () => {
      const farPrefix = 'x'.repeat(60);
      const prompt = `${farPrefix}example: ${fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')}`;
      expect(hasNearbyFakeContext(prompt, farPrefix.length + 9)).toBe(false);
    });

    it('handles match at start of string', () => {
      const prompt = '' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + ' example';
      expect(hasNearbyFakeContext(prompt, 0)).toBe(true);
    });

    it('handles match at end of string', () => {
      const prompt = 'example ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '';
      const pos = prompt.length - 35;
      expect(hasNearbyFakeContext(prompt, pos)).toBe(true);
    });
  });

  describe('scanPrompt — BLOCK decision (private key)', () => {
    it('blocks a PEM private key header', () => {
      const r = scanPrompt('-----BEGIN RSA PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
      expect(r!.patternName).toBe('private_key_header');
    });

    it('blocks a generic private key header', () => {
      const r = scanPrompt('-----BEGIN PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
    });

    it('blocks an EC private key header', () => {
      const r = scanPrompt('-----BEGIN EC PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
    });

    it('block reason mentions private key persistence in history', () => {
      const r = scanPrompt('-----BEGIN RSA PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.reason).toContain('conversation history');
    });

    it('block reason suggests referencing file path instead', () => {
      const r = scanPrompt('-----BEGIN RSA PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.reason).toContain('key file path');
    });

    it('PEM block is NOT defeated by fake-context keywords', () => {
      // PEM headers are unambiguous — fake-context heuristics must not defeat the block.
      const r = scanPrompt('example: -----BEGIN RSA PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
    });

    it('PEM block is NOT defeated by nearby "placeholder" text', () => {
      const r = scanPrompt('placeholder key: -----BEGIN EC PRIVATE KEY-----');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
    });
  });

  describe('scanPrompt — WARN decision (API keys)', () => {
    it('warns on OpenAI API key', () => {
      const r = scanPrompt('My key is ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '');
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('warn');
      expect(r!.patternName).toBe('openai_key');
    });

    it('warns on Anthropic API key', () => {
      const r = scanPrompt(fixtureSecret('sk-', 'ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD'));
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('warn');
      expect(r!.patternName).toBe('anthropic_key');
    });

    it('warns on AWS access key', () => {
      const r = scanPrompt(fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE1234567890ABCDEF'));
      // May or may not match depending on length; try a valid-length one
      expect(r).not.toBeNull();
    });

    it('warns on GitHub personal access token', () => {
      const r = scanPrompt(fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'));
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('warn');
      expect(r!.patternName).toBe('github_token');
    });

    it('warns on npm token', () => {
      const r = scanPrompt(fixtureSecret('npm_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234567890ABCD'));
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('warn');
      expect(r!.patternName).toBe('npm_token');
    });

    it('warn system message suggests environment variable', () => {
      const r = scanPrompt('My key is ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '');
      expect(r).not.toBeNull();
      expect(r!.systemMessage).toContain('OPENAI_API_KEY');
    });

    it('warn system message tells model not to echo the value', () => {
      const r = scanPrompt('My key is ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '');
      expect(r).not.toBeNull();
      expect(r!.systemMessage).toContain('Do NOT echo');
    });

    it('warn reason includes credential description', () => {
      const r = scanPrompt('My key is ' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '');
      expect(r).not.toBeNull();
      expect(r!.reason).toContain('OpenAI API key');
    });
  });

  describe('scanPrompt — fake value suppression (WARN only)', () => {
    it('does not warn on obviously fake OpenAI key with "example" nearby', () => {
      // isFakeValue should catch this
      const r = scanPrompt('Use ' + fixtureSecret('sk-', 'example1234567890abcdefghijklmnop') + ' as your key');
      expect(r).toBeNull();
    });

    it('does not warn on placeholder GitHub token with "placeholder" nearby', () => {
      const r = scanPrompt('Set GITHUB_TOKEN=' + fixtureSecret('ghp_', 'placeholder_token_value_here_1234567890ABCD') + '');
      // hasNearbyFakeContext should suppress this
      expect(r).toBeNull();
    });

    it('does not warn on dummy AWS key with "dummy" nearby', () => {
      const r = scanPrompt('Use a dummy ' + fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE1234567890ABCDEF') + ' for testing');
      expect(r).toBeNull();
    });

    it('does not warn on sample Stripe key with "sample" nearby', () => {
      const r = scanPrompt('Use a sample ' + fixtureSecret('sk_live_', 'abcdefghijklmnopqrstuvwxyz123456789ABCD') + '');
      expect(r).toBeNull();
    });
  });

  describe('scanPrompt — empty / null input', () => {
    it('returns null for empty string', () => {
      expect(scanPrompt('')).toBeNull();
    });

    it('handles prompt with only whitespace', () => {
      const r = scanPrompt('   \n\n  ');
      expect(r).toBeNull();
    });
  });

  describe('scanPrompt — multi-line scanning', () => {
    it('detects credential on second line', () => {
      const prompt = 'Hello world\n' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '';
      const r = scanPrompt(prompt);
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('warn');
    });

    it('stops at first match (first match wins)', () => {
      // Two credentials on different lines — should return the first one found
      const prompt = '' + fixtureSecret('sk-', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') + '\n' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij') + '';
      const r = scanPrompt(prompt);
      expect(r).not.toBeNull();
      // First match wins, so openai_key should be detected before github_token
      expect(r!.patternName).toBe('openai_key');
    });

    it('scans each line independently', () => {
      const prompt = 'Line 1 is clean\n-----BEGIN RSA PRIVATE KEY-----\nLine 3 is also clean';
      const r = scanPrompt(prompt);
      expect(r).not.toBeNull();
      expect(r!.decision).toBe('block');
    });
  });

  describe('scanPrompt — fail-open on malformed input', () => {
    it('handles very long prompt without crashing', () => {
      const longPrompt = 'x'.repeat(1_000_000);
      expect(() => scanPrompt(longPrompt)).not.toThrow();
    });

    it('returns null for extremely long benign content', () => {
      const longPrompt = 'This is a normal line.\n'.repeat(50_000);
      const r = scanPrompt(longPrompt);
      expect(r).toBeNull();
    });
  });
});
