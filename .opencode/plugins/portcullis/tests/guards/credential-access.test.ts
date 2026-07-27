import { describe, it, expect } from 'bun:test';
import { checkCommand, HARD_DENY_PATTERNS } from '../../guards/credential-access.js';
import { BENIGN_COMMANDS } from '../test-helpers.js';

describe('credential-access guard', () => {
  describe('dual-match requirement: reader AND credential store', () => {
    it('detects cat ~/.env', () => {
      const r = checkCommand('cat ~/.env');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('dotenv_file');
    });

    it('detects head ~/.ssh/id_rsa', () => {
      const r = checkCommand('head ~/.ssh/id_rsa');
      expect(r).not.toBeNull();
      // Could match ssh_key or private_key_file depending on regex order
      expect(['ssh_key', 'private_key_file']).toContain(r![0]);
    });

    it('detects tail ~/.aws/credentials', () => {
      const r = checkCommand('tail ~/.aws/credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_credentials');
    });

    it('detects less ~/.config/gcloud/application_default_credentials.json', () => {
      const r = checkCommand('less ~/.config/gcloud/application_default_credentials.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gcloud_credentials');
    });

    it('detects more ~/.gnupg/secring.gpg', () => {
      const r = checkCommand('more ~/.gnupg/secring.gpg');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gpg_key');
    });

    it('detects bat ~/.netrc', () => {
      const r = checkCommand('bat ~/.netrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('netrc_file');
    });

    it('detects strings id_rsa', () => {
      const r = checkCommand('strings id_rsa');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_file');
    });

    it('detects xxd ~/.ssh/authorized_keys', () => {
      const r = checkCommand('xxd ~/.ssh/authorized_keys');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssh_key');
    });

    it('detects od ~/.npmrc', () => {
      const r = checkCommand('od ~/.npmrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npmrc_token');
    });

    it('detects hexdump ~/.pypirc', () => {
      const r = checkCommand('hexdump ~/.pypirc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pypirc_token');
    });

    it('detects base64 ~/.ssh/id_ed25519', () => {
      const r = checkCommand('base64 ~/.ssh/id_ed25519');
      expect(r).not.toBeNull();
      expect(['ssh_key', 'private_key_file']).toContain(r![0]);
    });

    it('detects base32 ~/.aws/credentials', () => {
      const r = checkCommand('base32 ~/.aws/credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_credentials');
    });

    it('detects nl ~/.docker/config.json', () => {
      const r = checkCommand('nl ~/.docker/config.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('docker_auth');
    });

    it('detects sed on .env file', () => {
      const r = checkCommand("sed -n '/API_KEY/p' .env");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('dotenv_file');
    });

    it('detects awk on .git-credentials', () => {
      const r = checkCommand("awk '{print $1}' ~/.git-credentials");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_credentials');
    });

    it('detects dd if=.env', () => {
      const r = checkCommand('dd if=.env of=/tmp/leaked.env');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('dotenv_file');
    });

    it('detects cut on .kube/config', () => {
      const r = checkCommand("cut -d: -f1 ~/.kube/config");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('kube_config');
    });

    it('detects tac /etc/shadow', () => {
      const r = checkCommand('tac /etc/shadow');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shadow_file');
    });

    it('detects rev on .pgpass', () => {
      const r = checkCommand('rev ~/.pgpass');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pgpass_file');
    });

    it('detects cat ~/.config/gh/hosts.yml', () => {
      const r = checkCommand('cat ~/.config/gh/hosts.yml');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gh_token');
    });

    it('detects head ~/.azure/accessTokens.json', () => {
      const r = checkCommand('head ~/.azure/accessTokens.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('azure_credentials');
    });

    it('detects less Library/Keychains/login.keychain-db', () => {
      const r = checkCommand('less ~/Library/Keychains/login.keychain-db');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('macos_keychain');
    });

    it('detects cat .terraform.tfstate', () => {
      const r = checkCommand('cat .terraform.tfstate');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('terraform_state');
    });

    it('detects strings id_ecdsa', () => {
      const r = checkCommand('strings id_ecdsa');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('private_key_file');
    });

    it('detects head ~/.config/git/credentials', () => {
      const r = checkCommand('head ~/.config/git/credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_credentials');
    });

    it('detects cat .envrc', () => {
      const r = checkCommand('cat .envrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('dotenv_file');
    });
  });

  describe('no reader: should NOT match (dual-match requirement)', () => {
    it('allows ls ~/.ssh/', () => {
      // ls is not in the _READERS list
      const r = checkCommand('ls ~/.ssh/');
      expect(r).toBeNull();
    });

    it('allows rm .env', () => {
      // rm is not a reader
      const r = checkCommand('rm .env');
      expect(r).toBeNull();
    });

    it('allows cp .env backup.env', () => {
      // cp is not in the _READERS list (it's a write verb, but credential-access only checks readers)
      const r = checkCommand('cp .env backup.env');
      expect(r).toBeNull();
    });

    it('allows mv ~/.ssh/id_rsa /tmp/', () => {
      // mv is not in the _READERS list
      const r = checkCommand('mv ~/.ssh/id_rsa /tmp/');
      expect(r).toBeNull();
    });

    it('allows chmod 600 ~/.ssh/id_rsa', () => {
      // chmod is not a reader
      const r = checkCommand('chmod 600 ~/.ssh/id_rsa');
      expect(r).toBeNull();
    });

    it('allows touch .env', () => {
      // touch is not a reader
      const r = checkCommand('touch .env');
      expect(r).toBeNull();
    });

    it('allows grep pattern file (grep IS in readers)', () => {
      // grep is NOT in the _READERS list, so this should pass
      const r = checkCommand("grep 'API_KEY' .env");
      expect(r).toBeNull();
    });
  });

  describe('.env exclusion patterns', () => {
    it('allows cat .env.example (excluded by dotenv_file regex)', () => {
      // The regex has a negative lookahead for .example, .sample, etc.
      const r = checkCommand('cat .env.example');
      expect(r).toBeNull();
    });

    it('allows cat .env.sample', () => {
      const r = checkCommand('cat .env.sample');
      expect(r).toBeNull();
    });

    it('allows cat .env.template', () => {
      const r = checkCommand('cat .env.template');
      expect(r).toBeNull();
    });

    it('allows cat .env.dist', () => {
      const r = checkCommand('cat .env.dist');
      expect(r).toBeNull();
    });

    it('allows cat .env.defaults', () => {
      const r = checkCommand('cat .env.defaults');
      expect(r).toBeNull();
    });

    it('allows cat .env.default', () => {
      const r = checkCommand('cat .env.default');
      expect(r).toBeNull();
    });
  });

  describe('HARD_DENY_PATTERNS constant', () => {
    it('is empty (all credential-access patterns are "ask")', () => {
      expect(HARD_DENY_PATTERNS).toEqual([]);
    });
  });

  describe('benign commands pass through', () => {
    for (const cmd of BENIGN_COMMANDS) {
      it(`allows "${cmd}"`, () => {
        expect(checkCommand(cmd)).toBeNull();
      });
    }

    it('allows cat README.md', () => {
      expect(checkCommand('cat README.md')).toBeNull();
    });

    it('allows head package.json', () => {
      expect(checkCommand('head package.json')).toBeNull();
    });
  });

  describe('fail-open on malformed input', () => {
    it('returns null for empty string', () => {
      expect(checkCommand('')).toBeNull();
    });

    it('handles very long command without crashing', () => {
      const longCmd = 'cat ' + 'x'.repeat(100_000);
      expect(() => checkCommand(longCmd)).not.toThrow();
    });
  });
});
