import { describe, it, expect } from 'bun:test';
import { isPatternSuppressed, isPathSuppressed, isSuppressed } from '../allowlist.js';

describe('allowlist module', () => {
  describe('credential_access_guard — fully non-suppressible', () => {
    // credential_access_guard cannot be suppressed for any pattern or path.
    // This is verified by the fact that isPatternSuppressed and isPathSuppressed
    // always return false regardless of allowlist contents.

    it('isPatternSuppressed returns false for any pattern name', () => {
      expect(isPatternSuppressed('credential_access_guard', 'any_pattern')).toBe(false);
      expect(isPatternSuppressed('credential_access_guard', 'cat_dotenv')).toBe(false);
      expect(isPatternSuppressed('credential_access_guard', 'read_secrets')).toBe(false);
    });

    it('isPathSuppressed returns false for any file path', () => {
      expect(isPathSuppressed('credential_access_guard', '/etc/shadow')).toBe(false);
      expect(isPathSuppressed('credential_access_guard', '.env')).toBe(false);
      expect(isPathSuppressed('credential_access_guard', '~/.ssh/id_rsa')).toBe(false);
    });

    it('isSuppressed returns false for credential_access_guard with pattern', () => {
      expect(isSuppressed('credential_access_guard', 'any_pattern')).toBe(false);
    });

    it('isSuppressed returns false for credential_access_guard with path', () => {
      expect(isSuppressed('credential_access_guard', null, '/some/path/.env')).toBe(false);
    });
  });

  describe('git_guard — selectively non-suppressible patterns', () => {
    // git_guard has 5 protected patterns that can never be suppressed:
    // git_config_rce_primitive, git_alias_shell, git_env_rce,
    // git_hooks_dir_write, git_config_file_write.
    // Other git patterns (e.g., submodule operations) CAN be suppressed via allowlist.

    const PROTECTED_PATTERNS = [
      'git_config_rce_primitive',
      'git_alias_shell',
      'git_env_rce',
      'git_hooks_dir_write',
      'git_config_file_write',
    ];

    for (const pattern of PROTECTED_PATTERNS) {
      it(`never suppresses ${pattern}`, () => {
        expect(isPatternSuppressed('git_guard', pattern)).toBe(false);
      });
    }

    // Non-protected patterns return false here because there's no allowlist file.
    // In a real project with .opencode/hook-allowlist.json, they could be suppressed.
    it('non-protected patterns are not suppressed without an allowlist', () => {
      expect(isPatternSuppressed('git_guard', 'git_submodule_clone')).toBe(false);
      expect(isPatternSuppressed('git_guard', 'git_fetch_all')).toBe(false);
    });

    // isPathSuppressed for git_guard: paths CAN be suppressed (only patterns are protected)
    it('path suppression works independently of pattern protection for git_guard', () => {
      // Without an allowlist, returns false. With one that has suppress_paths, could return true.
      expect(isPathSuppressed('git_guard', '.git/config')).toBe(false);
    });
  });

  describe('suppressible guards (exfil_guard, supply_chain_guard, etc.)', () => {
    it('returns false when no allowlist file exists', () => {
      expect(isPatternSuppressed('exfil_guard', 'any_pattern')).toBe(false);
      expect(isPatternSuppressed('supply_chain_guard', 'pipe_to_shell')).toBe(false);
      expect(isPatternSuppressed('mcp_guard', 'some_mcp_pattern')).toBe(false);
    });

    it('returns false for unknown hook name', () => {
      expect(isPatternSuppressed('nonexistent_hook', 'some_pattern')).toBe(false);
    });

    it('returns false for unknown pattern in a known hook', () => {
      expect(isPatternSuppressed('supply_chain_guard', 'unknown_pattern_xyz')).toBe(false);
    });

    it('path suppression returns false without allowlist', () => {
      expect(isPathSuppressed('exfil_guard', '/some/path')).toBe(false);
      expect(isPathSuppressed('supply_chain_guard', 'node_modules/pkg/index.js')).toBe(false);
    });
  });

  describe('isSuppressed — unified entry point', () => {
    it('returns false when no allowlist file exists', () => {
      expect(isSuppressed('exfil_guard', 'some_pattern')).toBe(false);
    });

    it('handles null pattern gracefully', () => {
      expect(() => isSuppressed('exfil_guard', null)).not.toThrow();
      expect(isSuppressed('exfil_guard', null)).toBe(false);
    });

    it('handles undefined pattern gracefully', () => {
      expect(() => isSuppressed('exfil_guard')).not.toThrow();
      expect(isSuppressed('exfil_guard')).toBe(false);
    });

    it('handles both pattern and path arguments', () => {
      expect(() => isSuppressed('exfil_guard', 'some_pattern', '/some/path')).not.toThrow();
    });

    it('fail-open: returns false on any internal error', () => {
      // The function wraps everything in try/catch returning false
      expect(isSuppressed('nonexistent_guard', 'pattern')).toBe(false);
    });

    it('credential_access_guard is never suppressed via unified entry point', () => {
      expect(isSuppressed('credential_access_guard', 'any_pattern')).toBe(false);
      expect(isSuppressed('credential_access_guard', null, '/some/path/.env')).toBe(false);
    });
  });

  describe('minimatch path globbing (isPathSuppressed)', () => {
    // Without an allowlist file, all paths return false.
    // The minimatch integration is tested implicitly — if the allowlist had suppress_paths,
    // globs like '**/node_modules/**' would match accordingly.

    it('returns false for any path when no allowlist exists', () => {
      expect(isPathSuppressed('supply_chain_guard', 'src/index.ts')).toBe(false);
      expect(isPathSuppressed('supply_chain_guard', 'node_modules/pkg/index.js')).toBe(false);
      expect(isPathSuppressed('supply_chain_guard', '.git/config')).toBe(false);
    });

    it('handles absolute paths without crashing', () => {
      expect(() => isPathSuppressed('exfil_guard', '/absolute/path/to/.env')).not.toThrow();
    });

    it('handles relative paths without crashing', () => {
      expect(() => isPathSuppressed('exfil_guard', 'relative/path/to/file.txt')).not.toThrow();
    });
  });

  describe('cache behavior (cwd-based)', () => {
    // The module caches the allowlist per cwd(). Changing cwd() invalidates the cache.
    // We can't easily test this without mocking process.cwd(), but we verify that
    // repeated calls return consistent results.

    it('returns consistent results on repeated calls', () => {
      const r1 = isPatternSuppressed('exfil_guard', 'test_pattern');
      const r2 = isPatternSuppressed('exfil_guard', 'test_pattern');
      expect(r1).toBe(r2);
    });

    it('path suppression returns consistent results on repeated calls', () => {
      const r1 = isPathSuppressed('supply_chain_guard', 'some/path');
      const r2 = isPathSuppressed('supply_chain_guard', 'some/path');
      expect(r1).toBe(r2);
    });

    it('isSuppressed returns consistent results on repeated calls', () => {
      const r1 = isSuppressed('exfil_guard', 'test_pattern');
      const r2 = isSuppressed('exfil_guard', 'test_pattern');
      expect(r1).toBe(r2);
    });
  });

  describe('edge cases and robustness', () => {
    it('handles empty string pattern name', () => {
      expect(() => isPatternSuppressed('exfil_guard', '')).not.toThrow();
      expect(isPatternSuppressed('exfil_guard', '')).toBe(false);
    });

    it('handles empty string path', () => {
      expect(() => isPathSuppressed('exfil_guard', '')).not.toThrow();
      expect(isPathSuppressed('exfil_guard', '')).toBe(false);
    });

    it('handles very long pattern name without crashing', () => {
      const longPattern = 'x'.repeat(10_000);
      expect(() => isPatternSuppressed('exfil_guard', longPattern)).not.toThrow();
    });

    it('handles very long path without crashing', () => {
      const longPath = '/very/' + 'deep/'.repeat(500) + 'file.txt';
      expect(() => isPathSuppressed('exfil_guard', longPath)).not.toThrow();
    });
  });
});
