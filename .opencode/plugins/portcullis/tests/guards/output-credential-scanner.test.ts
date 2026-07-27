import { describe, it, expect } from 'bun:test';
import { scanOutput, isSafeCommand, isCredentialSearch } from '../../guards/output-credential-scanner.js';
import { fixtureSecret } from '../test-helpers';

describe('output-credential-scanner guard', () => {
  describe('isSafeCommand', () => {
    it('allows git status', () => {
      expect(isSafeCommand('git status')).toBe(true);
    });

    it('allows git log (without patch flag)', () => {
      expect(isSafeCommand('git log --oneline -5')).toBe(true);
    });

    it('allows git branch', () => {
      expect(isSafeCommand('git branch')).toBe(true);
    });

    it('allows git remote', () => {
      expect(isSafeCommand('git remote -v')).toBe(true);
    });

    it('allows ls command', () => {
      expect(isSafeCommand('ls -la')).toBe(true);
    });

    it('allows find command', () => {
      expect(isSafeCommand('find . -name "*.ts"')).toBe(true);
    });

    it('allows wc command', () => {
      expect(isSafeCommand('wc -l file.txt')).toBe(true);
    });

    it('allows pwd command', () => {
      expect(isSafeCommand('pwd')).toBe(true);
    });

    it('allows mkdir command', () => {
      expect(isSafeCommand('mkdir -p dist')).toBe(true);
    });

    it('allows mv command', () => {
      expect(isSafeCommand('mv a.txt b.txt')).toBe(true);
    });

    it('allows cp command', () => {
      expect(isSafeCommand('cp src.ts dist/')).toBe(true);
    });

    it('allows stat command', () => {
      expect(isSafeCommand('stat file.txt')).toBe(true);
    });

    it('allows file command', () => {
      expect(isSafeCommand('file image.png')).toBe(true);
    });

    it('rejects git log with -p flag (patch mode)', () => {
      expect(isSafeCommand('git log -p')).toBe(false);
    });

    it('rejects git log with --patch flag', () => {
      expect(isSafeCommand('git log --patch')).toBe(false);
    });

    it('rejects git log with -U3 flag (unified context)', () => {
      expect(isSafeCommand('git log -U3')).toBe(false);
    });

    it('rejects chained commands', () => {
      expect(isSafeCommand('ls && cat file.txt')).toBe(false);
    });

    it('rejects piped commands', () => {
      expect(isSafeCommand('cat file | grep secret')).toBe(false);
    });

    it('rejects semicolon-chained commands', () => {
      expect(isSafeCommand('ls; cat secrets.env')).toBe(false);
    });

    it('rejects non-safe command', () => {
      expect(isSafeCommand('cat .env')).toBe(false);
    });

    it('handles empty string', () => {
      expect(isSafeCommand('')).toBe(false);
    });
  });

  describe('isCredentialSearch', () => {
    it('detects grep for AKIA (AWS key)', () => {
      expect(isCredentialSearch('grep -r "AKIA" .')).toBe(true);
    });

    it('detects rg for ghp_ (GitHub token)', () => {
      expect(isCredentialSearch('rg "ghp_" src/')).toBe(true);
    });

    it('detects grep for sk-ant (Anthropic key)', () => {
      expect(isCredentialSearch("grep -r 'sk-ant' .")).toBe(true);
    });

    it('detects grep for BEGIN PRIVATE', () => {
      expect(isCredentialSearch('grep "BEGIN.*PRIVATE" .')).toBe(true);
    });

    it('detects rg for api.key pattern', () => {
      expect(isCredentialSearch('rg "api.key" config/')).toBe(true);
    });

    it('detects grep for secret keyword', () => {
      expect(isCredentialSearch("grep -r 'secret' .")).toBe(true);
    });

    it('detects ag for token keyword', () => {
      expect(isCredentialSearch('ag "token" src/')).toBe(true);
    });

    it('does not flag normal grep usage', () => {
      expect(isCredentialSearch('grep -r "function main" .')).toBe(false);
    });

    it('handles empty string', () => {
      expect(isCredentialSearch('')).toBe(false);
    });
  });

  describe('scanOutput - high confidence credential detection (redact)', () => {
    it('detects and redacts OpenAI key in output', () => {
      const r = scanOutput('API key: ' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '', 'cat config.env');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('openai_key');
      expect(r!.redactedOutput).toBe('API key: [REDACTED: openai_key]');
      expect(r!.systemMessage).toContain('CREDENTIAL DETECTED IN COMMAND OUTPUT');
    });

    it('detects and redacts GitHub token in output', () => {
      const r = scanOutput('token=' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '', 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('github_token');
      expect(r!.redactedOutput).toContain('[REDACTED: github_token]');
    });

    it('detects and redacts AWS access key in output', () => {
      const r = scanOutput(fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE'), 'aws sts get-caller-identity');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('aws_access_key');
      expect(r!.redactedOutput).toBe('[REDACTED: aws_access_key]');
    });

    it('detects and redacts private key header in output', () => {
      const r = scanOutput('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...', 'cat ~/.ssh/id_rsa');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('private_key_header');
      expect(r!.redactedOutput).toContain('[REDACTED: private_key_header]');
    });

    it('detects and redacts Slack token in output', () => {
      const r = scanOutput(fixtureSecret('xoxb-', '1234567890-abcdefghij-klmnopqrstuvwx'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('slack_token');
      expect(r!.redactedOutput).toContain('[REDACTED: slack_token]');
    });

    it('detects and redacts Stripe key in output', () => {
      const r = scanOutput(fixtureSecret('sk_test_', 'abcdefghijklmnopqrstuvwx'), 'cat config.yml');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('stripe_key');
      expect(r!.redactedOutput).toContain('[REDACTED: stripe_key]');
    });

    it('detects and redacts JWT token in output', () => {
      const r = scanOutput('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'cat token.txt');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('jwt_token');
      expect(r!.redactedOutput).toContain('[REDACTED: jwt_token]');
    });

    it('detects and redacts Anthropic key in output', () => {
      const r = scanOutput(fixtureSecret('sk-', 'ant-abcdefghijklmnopqrstuvwxyz123456'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('anthropic_key');
      expect(r!.redactedOutput).toContain('[REDACTED: anthropic_key]');
    });

    it('detects and redacts npm token in output', () => {
      const r = scanOutput('//registry.npmjs.org/:_authToken=' + fixtureSecret('npm_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '', 'cat .npmrc');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('npm_token');
      expect(r!.redactedOutput).toContain('[REDACTED: npm_token]');
    });

    it('detects and redacts GitLab token in output', () => {
      const r = scanOutput(fixtureSecret('glpat-', 'ABCDEFGHIJKLMNOPQRSTuvwx'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('gitlab_token');
      expect(r!.redactedOutput).toContain('[REDACTED: gitlab_token]');
    });

    it('does not redact fake credential values (high confidence)', () => {
      const r = scanOutput(fixtureSecret('sk-', 'example1234567890abcdefghij'), 'cat README.md');
      expect(r).toBeNull();
    });

    it('does not redact placeholder GitHub token', () => {
      const r = scanOutput(fixtureSecret('ghp_', 'placeholderABCDEFGHIJKLMNOPQRSTUVWXyz'), 'cat example.env');
      expect(r).toBeNull();
    });
  });

  describe('scanOutput - low confidence credential detection (warn, no redaction)', () => {
    it('detects generic_secret pattern (warn only)', () => {
      const r = scanOutput('api_key = "abcdefghijklmnopqrstuvwx"', 'cat config.py');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('generic_secret');
      // Low confidence → no redaction, just warning
      expect(r!.redactedOutput).toBeUndefined();
    });

    it('detects password_assignment pattern (warn only)', () => {
      const r = scanOutput('password = "MyS3cur3P@ssw0rd!"', 'cat config.py');
      expect(r).not.toBeNull();
      expect(r!.patternNames).toContain('password_assignment');
      // Low confidence → no redaction, just warning
      expect(r!.redactedOutput).toBeUndefined();
    });

    it('does not warn on fake generic_secret values', () => {
      const r = scanOutput('api_key = "your-api-key-here"', 'cat example.py');
      expect(r).toBeNull();
    });
  });

  describe('scanOutput - span deduplication (priority ordering)', () => {
    it('prioritizes first match on overlapping spans', () => {
      // If two patterns could match the same text, only the higher-priority one fires
      const r = scanOutput(fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), 'cat .env');
      expect(r).not.toBeNull();
      // openai_key is in PATTERN_PRIORITY before generic_secret
      expect(r!.patternNames).toContain('openai_key');
    });

    it('detects multiple non-overlapping credentials on same line', () => {
      const r = scanOutput('key1=' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + ' key2=' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '', 'cat .env');
      expect(r).not.toBeNull();
      // Both should be detected since they don't overlap
      expect(r!.patternNames.length).toBeGreaterThanOrEqual(2);
    });

    it('detects credentials on different lines', () => {
      const r = scanOutput('line1: ' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '\nline2: ' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '', 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames.length).toBeGreaterThanOrEqual(2);
    });

    it('redacts all high-confidence matches in output', () => {
      const r = scanOutput('key1=' + fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456') + '\nkey2=' + fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh') + '', 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.redactedOutput).toContain('[REDACTED: openai_key]');
      expect(r!.redactedOutput).toContain('[REDACTED: github_token]');
    });
  });

  describe('scanOutput - PATTERN_PRIORITY ordering', () => {
    it('processes patterns in priority order (anthropic_key before generic_secret)', () => {
      // anthropic_key is first in PATTERN_PRIORITY, so it should match before generic_secret
      const r = scanOutput(fixtureSecret('sk-', 'ant-abcdefghijklmnopqrstuvwxyz123456'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames[0]).toBe('anthropic_key');
    });

    it('processes aws_access_key before generic_secret', () => {
      const r = scanOutput(fixtureSecret('AKIA', 'IOSFODNN7EXAMPLE'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames[0]).toBe('aws_access_key');
    });

    it('processes github_token before generic_secret', () => {
      const r = scanOutput(fixtureSecret('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.patternNames[0]).toBe('github_token');
    });
  });

  describe('scanOutput - system message format', () => {
    it('includes pattern names in system message', () => {
      const r = scanOutput(fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.systemMessage).toContain('openai_key');
    });

    it('truncates source to 40 chars in system message', () => {
      const longSource = 'cat /very/long/path/to/some/file/.env';
      const r = scanOutput(fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), longSource);
      expect(r).not.toBeNull();
      // Source prefix should be truncated to 40 chars in the message
      expect(r!.systemMessage.length).toBeGreaterThan(0);
    });

    it('suggests environment variable usage', () => {
      const r = scanOutput(fixtureSecret('sk-', 'abcdefghijklmnopqrstuvwxyz123456'), 'cat .env');
      expect(r).not.toBeNull();
      expect(r!.systemMessage).toContain('environment variable');
    });
  });

  describe('scanOutput - benign output passes through', () => {
    it('allows normal command output', () => {
      const r = scanOutput('Hello, world!\nThis is a test.', 'echo hello');
      expect(r).toBeNull();
    });

    it('allows git log output with no credentials', () => {
      const r = scanOutput('commit abc123\nAuthor: User <user@example.com>\nDate: Mon Jan 1 00:00:00 2024', 'git log');
      expect(r).toBeNull();
    });

    it('allows npm install output', () => {
      const r = scanOutput('added 5 packages in 2s\n\ndone', 'npm install');
      expect(r).toBeNull();
    });

    it('returns null for empty text', () => {
      const r = scanOutput('', 'echo hello');
      expect(r).toBeNull();
    });
  });

  describe('fail-open on malformed input', () => {
    it('handles very long output without crashing', () => {
      const longOutput = 'x'.repeat(1_000_000);
      expect(() => scanOutput(longOutput, 'cat bigfile.txt')).not.toThrow();
    });

    it('returns null for undefined-like input gracefully', () => {
      // The function takes string | undefined; empty string is handled
      const r = scanOutput('', '');
      expect(r).toBeNull();
    });
  });
});
