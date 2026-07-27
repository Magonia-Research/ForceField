import { describe, it, expect } from 'bun:test';
import { checkContent, isExcludedPath, isFakeValue, CREDENTIAL_PATTERNS, FAKE_VALUE_RE, HIGH_CONFIDENCE_NAMES, formatAlert } from '../../guards/content-credential.js';
import { fixtureSecret } from '../test-helpers';

describe('content-credential guard', () => {
  describe('OpenAI key detection', () => {
    it('detects sk- prefix with 20+ chars', () => {
      const r = checkContent('const key = "' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('openai_key');
    });

    it('does not detect sk- with fewer than 20 chars after prefix', () => {
      const r = checkContent('const key = "sk-short";', 'src/config.ts');
      expect(r).toBeNull();
    });
  });

  describe('Anthropic key detection', () => {
    it('detects sk-ant- prefix with dashes and alphanumeric chars', () => {
      const r = checkContent('const key = "' + fixtureSecret('sk-', 'ant-abcdefghijklmnopqrstuvwxyz123456') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('anthropic_key');
    });
  });

  describe('GitHub token detection', () => {
    it('detects ghp_ personal access token (36 chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('github_token');
    });

    it('detects gho_ OAuth token (36 chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('gho_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('github_oauth_token');
    });

    it('detects ghs_ server-to-server token (36 chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('ghs_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('github_server_token');
    });

    it('detects github_pat_ fine-grained token (20+ chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('github_pat_', 'ABCDEFGHIJKLMNOPQRST') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('github_fine_grained');
    });
  });

  describe('GitLab token detection', () => {
    it('detects glpat- personal access token (20 chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('glpat-', 'ABCDEFGHIJKLMNOPQRST') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gitlab_token');
    });
  });

  describe('npm token detection', () => {
    it('detects npm_ access token (36 chars)', () => {
      const r = checkContent('const token = "' + fixtureSecret('npm_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npm_token');
    });
  });

  describe('AWS key detection', () => {
    it('detects AKIA access key ID (16 uppercase alphanumeric)', () => {
      const r = checkContent('const key = "' + fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_access_key');
    });

    it('detects ASIA STS temporary access key (16 uppercase alphanumeric)', () => {
      const r = checkContent('const key = "' + fixtureSecret('ASIA', 'IOSFODNN7EXAMPLE') + '";', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_sts_key');
    });

    it('detects aws_secret_access_key assignment (40 chars)', () => {
      const r = checkContent('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'src/config.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_secret_key');
    });
  });

  describe('Private key header detection', () => {
    it('detects -----BEGIN RSA PRIVATE KEY-----', () => {
      const r = checkContent('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...', 'src/key.pem');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });

    it('detects -----BEGIN OPENSSH PRIVATE KEY-----', () => {
      const r = checkContent('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE...', 'src/id_ed25519');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });

    it('detects -----BEGIN PGP PRIVATE KEY BLOCK-----', () => {
      const r = checkContent('-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2', 'src/key.asc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });

    it('detects -----BEGIN ENCRYPTED PRIVATE KEY-----', () => {
      const r = checkContent('-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHzB...', 'src/encrypted.pem');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });

    it('detects -----BEGIN EC PRIVATE KEY-----', () => {
      const r = checkContent('-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIB...', 'src/ec.key');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });

    it('detects -----BEGIN DSA PRIVATE KEY-----', () => {
      const r = checkContent('-----BEGIN DSA PRIVATE KEY-----\nMIIBugM...', 'src/dsa.key');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_header');
    });
  });

  describe('JWT token detection', () => {
    it('detects JWT with two base64url segments separated by dots', () => {
      const r = checkContent('const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";', 'src/auth.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('jwt_token');
    });

    it('does not detect JWT with only one segment', () => {
      const r = checkContent('const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";', 'src/auth.ts');
      expect(r).toBeNull();
    });
  });

  describe('Generic secret detection', () => {
    it('detects api_key assignment (16+ chars)', () => {
      const r = checkContent('api_key = "abcdefghijklmnop"', 'src/config.py');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('generic_secret');
    });

    it('detects secret_key assignment', () => {
      const r = checkContent('secret_key: "mysecretkey123456789"', 'src/config.yaml');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('generic_secret');
    });

    it('detects access_token assignment', () => {
      const r = checkContent('access_token="abcdefghijklmnopqrstuvwx"', 'src/env.sh');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('generic_secret');
    });

    it('does not detect api_key with fewer than 16 chars', () => {
      const r = checkContent('api_key = "short"', 'src/config.py');
      expect(r).toBeNull();
    });
  });

  describe('Password assignment detection', () => {
    it('detects password in quotes (8+ chars)', () => {
      const r = checkContent('password = "MyS3cur3P@ssw0rd"', 'src/config.py');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('password_assignment');
    });

    it('detects passwd in quotes', () => {
      const r = checkContent("passwd: \"AnotherS3cret!\"", 'src/config.yaml');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('password_assignment');
    });

    it('does not detect password with fewer than 8 chars in quotes', () => {
      const r = checkContent('password = "short"', 'src/config.py');
      expect(r).toBeNull();
    });
  });

  describe('Slack token detection', () => {
    it('detects xoxb- bot token', () => {
      const r = checkContent('const slackToken = "' + fixtureSecret('xoxb-', '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx') + '";', 'src/slack.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('slack_token');
    });

    it('detects xoxp- user token', () => {
      const r = checkContent('const slackToken = "' + fixtureSecret('xoxp-', '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx') + '";', 'src/slack.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('slack_token');
    });

    it('detects xoxa- app token', () => {
      const r = checkContent('const slackToken = "' + fixtureSecret('xoxa-', '123456789012-AbCdEfGhIjKlMnOpQrStUvWx') + '";', 'src/slack.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('slack_token');
    });

    it('detects xoxs- signing secret token', () => {
      const r = checkContent('const slackToken = "xoxs-AbCdEfGhIjKlMnOpQrStUvWx";', 'src/slack.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('slack_token');
    });

    it('detects xoxr- refresh token', () => {
      const r = checkContent('const slackToken = "xoxr-123456789012-AbCdEfGhIjKlMnOpQrStUvWx";', 'src/slack.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('slack_token');
    });
  });

  describe('Stripe key detection', () => {
    it('detects sk_test_ secret test key (24+ chars)', () => {
      const r = checkContent('const stripeKey = "' + fixtureSecret('sk_test_', 'ABCDEFGHIJKLMNOPQRSTUVWX') + '";', 'src/stripe.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('stripe_key');
    });

    it('detects pk_live_ public live key (24+ chars)', () => {
      const r = checkContent('const stripeKey = "pk_live_ABCDEFGHIJKLMNOPQRSTUVWX";', 'src/stripe.ts');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('stripe_key');
    });

    it('does not detect sk_test_ with fewer than 24 chars after prefix', () => {
      const r = checkContent('const stripeKey = "sk_test_short";', 'src/stripe.ts');
      expect(r).toBeNull();
    });
  });

  describe('isExcludedPath function', () => {
    it('excludes files in tests/ directory', () => {
      expect(isExcludedPath('tests/config.py')).toBe(true);
    });

    it('excludes files in test/ directory', () => {
      expect(isExcludedPath('test/fixtures/data.json')).toBe(true);
    });

    it('excludes files in __tests__/ directory', () => {
      expect(isExcludedPath('__tests__/auth.test.ts')).toBe(true);
    });

    it('excludes files in testdata/ directory', () => {
      expect(isExcludedPath('testdata/sample.env')).toBe(true);
    });

    it('excludes files in fixtures/ directory', () => {
      expect(isExcludedPath('fixtures/test-data.json')).toBe(true);
    });

    it('excludes files in __fixtures__/ directory', () => {
      expect(isExcludedPath('__fixtures__/credentials.yaml')).toBe(true);
    });

    it('excludes .env files by glob pattern', () => {
      expect(isExcludedPath('.env')).toBe(true);
    });

    it('excludes .env.local files by glob pattern', () => {
      expect(isExcludedPath('.env.local')).toBe(true);
    });

    it('excludes .example files by glob pattern', () => {
      expect(isExcludedPath('config.example')).toBe(true);
    });

    it('does not exclude regular source files', () => {
      expect(isExcludedPath('src/config.ts')).toBe(false);
    });

    it('does not exclude files named "test" in a non-excluded directory', () => {
      // Only directory segments are checked, not the filename itself (except for globs)
      expect(isExcludedPath('src/test')).toBe(false);
    });

    it('handles Windows-style paths by normalizing separators', () => {
      expect(isExcludedPath('tests\\config.py')).toBe(true);
    });

    it('returns false for empty path', () => {
      expect(isExcludedPath('')).toBe(false);
    });
  });

  describe('isFakeValue function', () => {
    it('detects "example" in matched text', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'example1234567890abcdefghij'), 'const key = "' + fixtureSecret('sk-', 'example1234567890abcdefghij') + '";')).toBe(true);
    });

    it('detects "placeholder" in matched text', () => {
      expect(isFakeValue(fixtureSecret('ghp_', 'placeholderABCDEFGHIJKLMNOPQRSTUVWX'), 'token: ' + fixtureSecret('ghp_', 'placeholderABCDEFGHIJKLMNOPQRSTUVWX') + '')).toBe(true);
    });

    it('detects "dummy" in matched text', () => {
      expect(isFakeValue(fixtureSecret('AKIA', 'dummyEXAMPLE1234567890'), 'key = AKIadummyEXAMPLE1234567890')).toBe(true);
    });

    it('detects "fake" in matched text', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'fake_key_abcdefghijklmnopqrstuvwx'), 'key: ' + fixtureSecret('sk-', 'fake_key_abcdefghijklmnopqrstuvwx') + '')).toBe(true);
    });

    it('detects "test" in matched text', () => {
      expect(isFakeValue(fixtureSecret('npm_', 'testABCDEFGHIJKLMNOPQRSTUVWXabcdefghij'), 'token = ' + fixtureSecret('npm_', 'testABCDEFGHIJKLMNOPQRSTUVWXabcdefghij') + '')).toBe(true);
    });

    it('detects "xxx" in matched text', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'), 'key: ' + fixtureSecret('sk-', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx') + '')).toBe(true);
    });

    it('detects "your_" prefix in matched text', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'your_api_key_here_abcdefghijklmnopqr'), 'key = ' + fixtureSecret('sk-', 'your_api_key_here_abcdefghijklmnopqr') + '')).toBe(true);
    });

    it('detects "your-" prefix in matched text', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'your-api-key-here-abcdefghijklmnopqrs'), 'key: ' + fixtureSecret('sk-', 'your-api-key-here-abcdefghijklmnopqrs') + '')).toBe(true);
    });

    it('detects # example comment context', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'reallookingkey1234567890abcdefghij'), '# example key below\nconst key = "' + fixtureSecret('sk-', 'reallookingkey1234567890abcdefghij') + '";')).toBe(true);
    });

    it('detects # placeholder comment context', () => {
      expect(isFakeValue(fixtureSecret('ghp_', 'reallookingtokenABCDEFGHIJKLMNOPQRSTUVWX'), '# placeholder token\ntoken: ' + fixtureSecret('ghp_', 'reallookingtokenABCDEFGHIJKLMNOPQRSTUVWX') + '')).toBe(true);
    });

    it('does not flag a real-looking key without fake indicators', () => {
      expect(isFakeValue(fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), 'const key = "' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '";')).toBe(false);
    });
  });

  describe('HIGH_CONFIDENCE_NAMES set', () => {
    it('contains openai_key', () => {
      expect(HIGH_CONFIDENCE_NAMES.has('openai_key')).toBe(true);
    });

    it('does not contain generic_secret (low confidence)', () => {
      expect(HIGH_CONFIDENCE_NAMES.has('generic_secret')).toBe(false);
    });

    it('does not contain password_assignment (low confidence)', () => {
      expect(HIGH_CONFIDENCE_NAMES.has('password_assignment')).toBe(false);
    });

    it('contains all specific token types', () => {
      const expected = [
        'openai_key', 'anthropic_key', 'github_token', 'github_oauth_token',
        'github_server_token', 'github_fine_grained', 'gitlab_token', 'npm_token',
        'aws_access_key', 'aws_sts_key', 'aws_secret_key', 'private_key_header',
        'jwt_token', 'slack_token', 'stripe_key',
      ];
      for (const name of expected) {
        expect(HIGH_CONFIDENCE_NAMES.has(name)).toBe(true);
      }
    });
  });

  describe('CREDENTIAL_PATTERNS map size', () => {
    it('has exactly 17 patterns', () => {
      const keys = Object.keys(CREDENTIAL_PATTERNS);
      expect(keys.length).toBe(17);
    });
  });

  describe('formatAlert function', () => {
    it('returns a formatted alert with redacted value', () => {
      const alert = formatAlert('openai_key', fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), 'src/config.ts');
      expect(alert).toContain('CREDENTIAL GUARD: OpenAI API key');
      expect(alert).toContain('Pattern: openai_key');
      // Value should be redacted (first 8 + ... + last 4)
      expect(alert).toContain('sk-abcde...3456');
      expect(alert).toContain('File: src/config.ts');
    });

    it('does not truncate short values', () => {
      const alert = formatAlert('generic_secret', 'short', 'src/config.py');
      expect(alert).toContain('Value: short');
    });
  });

  describe('benign content passes through', () => {
    it('allows normal text without credentials', () => {
      expect(checkContent('Hello world, this is a test file.', 'README.md')).toBeNull();
    });

    it('allows code with no credential patterns', () => {
      const code = `function greet(name) {\n  return \`Hello, \${name}!\`;\n}`;
      expect(checkContent(code, 'src/utils.ts')).toBeNull();
    });

    it('returns null for empty content', () => {
      expect(checkContent('', 'src/config.ts')).toBeNull();
    });
  });

  describe('fail-open on malformed input', () => {
    it('handles very long content without crashing', () => {
      const longContent = 'line\n'.repeat(10_000);
      expect(() => checkContent(longContent, 'src/large.ts')).not.toThrow();
    });
  });
});
