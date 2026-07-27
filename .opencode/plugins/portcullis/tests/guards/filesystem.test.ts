import { describe, it, expect } from 'bun:test';
import { checkWritePath, checkReadPath, checkPathAccess } from '../../guards/filesystem.js';

describe('filesystem guard', () => {
  describe('checkWritePath - SSH sinks', () => {
    it('detects writing to ~/.ssh/authorized_keys', () => {
      const r = checkWritePath('/home/user/.ssh/authorized_keys');
      expect(r).not.toBeNull();
      expect(['ssh_authorized_keys', 'ssh_dir']).toContain(r![0]);
    });

    it('detects writing anywhere under ~/.ssh/', () => {
      const r = checkWritePath('/home/user/.ssh/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('ssh_dir');
    });

    it('detects writing to ~/Library/LaunchAgents/', () => {
      const r = checkWritePath('/Users/john/Library/LaunchAgents/com.evil.plist');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('launch_agents');
    });

    it('detects writing to ~/Library/LaunchDaemons/', () => {
      const r = checkWritePath('/Users/john/Library/LaunchDaemons/com.evil.plist');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('launch_agents');
    });
  });

  describe('checkWritePath - AWS sinks', () => {
    it('detects writing to ~/.aws/', () => {
      const r = checkWritePath('/home/user/.aws/credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_dir');
    });

    it('detects writing to ~/.aws/config', () => {
      const r = checkWritePath('/home/user/.aws/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_dir');
    });
  });

  describe('checkWritePath - GPG sinks', () => {
    it('detects writing to ~/.gnupg/', () => {
      const r = checkWritePath('/home/user/.gnupg/secring.gpg');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gnupg_dir');
    });
  });

  describe('checkWritePath - GCloud sinks', () => {
    it('detects writing to ~/.config/gcloud/', () => {
      const r = checkWritePath('/home/user/.config/gcloud/credentials.db');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gcloud_dir');
    });
  });

  describe('checkWritePath - Kube sinks', () => {
    it('detects writing to ~/.kube/', () => {
      const r = checkWritePath('/home/user/.kube/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('kube_dir');
    });
  });

  describe('checkWritePath - Docker sinks', () => {
    it('detects writing to ~/.docker/config.json', () => {
      const r = checkWritePath('/home/user/.docker/config.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('docker_config');
    });
  });

  describe('checkWritePath - npm/pypi/netrc sinks', () => {
    it('detects writing to ~/.npmrc', () => {
      const r = checkWritePath('/home/user/.npmrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npmrc');
    });

    it('detects writing to ~/.pypirc', () => {
      const r = checkWritePath('/home/user/.pypirc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pypirc');
    });

    it('detects writing to ~/.netrc', () => {
      const r = checkWritePath('/home/user/.netrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('netrc');
    });
  });

  describe('checkWritePath - git sinks', () => {
    it('detects writing to .git/hooks/', () => {
      const r = checkWritePath('/repo/.git/hooks/pre-commit');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks');
    });

    it('detects writing to .git/config', () => {
      const r = checkWritePath('/repo/.git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file');
    });

    it('detects writing to ~/.gitconfig', () => {
      const r = checkWritePath('/home/user/.gitconfig');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_global_config');
    });

    it('detects writing to .git-credentials', () => {
      const r = checkWritePath('/home/user/.git-credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_credentials');
    });
  });

  describe('checkWritePath - shell init sinks', () => {
    it('detects writing to ~/.bashrc', () => {
      const r = checkWritePath('/home/user/.bashrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shell_init');
    });

    it('detects writing to ~/.zshrc', () => {
      const r = checkWritePath('/home/user/.zshrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shell_init');
    });

    it('detects writing to ~/.bash_profile', () => {
      const r = checkWritePath('/home/user/.bash_profile');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shell_init');
    });

    it('detects writing to ~/.profile', () => {
      const r = checkWritePath('/home/user/.profile');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shell_init');
    });
  });

  describe('checkWritePath - fish init sinks', () => {
    it('detects writing to ~/.config/fish/config.fish', () => {
      const r = checkWritePath('/home/user/.config/fish/config.fish');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('fish_init');
    });

    it('detects writing to ~/.config/fish/conf.d/', () => {
      const r = checkWritePath('/home/user/.config/fish/conf.d/evil.fish');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('fish_init');
    });
  });

  describe('checkWritePath - system sinks', () => {
    it('detects writing to /etc/cron/', () => {
      const r = checkWritePath('/etc/cron.d/evil');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('cron');
    });

    it('detects writing to /var/spool/cron', () => {
      const r = checkWritePath('/var/spool/cron/root');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('cron');
    });

    it('detects writing to systemd unit path', () => {
      const r = checkWritePath('/etc/systemd/system/evil.service');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('systemd_unit');
    });

    it('detects writing to /etc/rc.local', () => {
      const r = checkWritePath('/etc/rc.local');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('rc_local');
    });

    it('detects writing to /etc/sudoers', () => {
      const r = checkWritePath('/etc/sudoers');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('etc_sensitive');
    });

    it('detects writing to /etc/shadow', () => {
      const r = checkWritePath('/etc/shadow');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('etc_sensitive');
    });

    it('detects writing to /etc/ld.so.preload', () => {
      const r = checkWritePath('/etc/ld.so.preload');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('etc_sensitive');
    });

    it('detects writing to ~/.config/autostart/', () => {
      const r = checkWritePath('/home/user/.config/autostart/evil.desktop');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('autostart');
    });
  });

  describe('checkWritePath - config sinks', () => {
    it('detects writing to .claude/settings.json', () => {
      const r = checkWritePath('/project/.claude/settings.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('claude_settings');
    });

    it('detects writing to .claude/hook-allowlist.json', () => {
      const r = checkWritePath('/project/.claude/hook-allowlist.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('hook_allowlist');
    });

    it('detects writing to .claude/portcullis.json', () => {
      const r = checkWritePath('/project/.claude/portcullis.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('portcullis_config');
    });

    it('detects writing to .mcp.json', () => {
      const r = checkWritePath('/home/user/.mcp.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('mcp_config');
    });
  });

  describe('checkReadPath - credential access patterns', () => {
    it('detects reading .env file', () => {
      const r = checkReadPath('/project/.env');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('dotenv_file');
    });

    it('does not detect reading .env.example (excluded)', () => {
      const r = checkReadPath('/project/.env.example');
      expect(r).toBeNull();
    });

    it('does not detect reading .env.sample (excluded)', () => {
      const r = checkReadPath('/project/.env.sample');
      expect(r).toBeNull();
    });

    it('detects reading ~/.ssh/id_rsa', () => {
      const r = checkReadPath('/home/user/.ssh/id_rsa');
      expect(r).not.toBeNull();
      // Could match ssh_key or private_key_file depending on which fires first
      expect(['ssh_key', 'private_key_file']).toContain(r![0]);
    });

    it('detects reading ~/.aws/credentials', () => {
      const r = checkReadPath('/home/user/.aws/credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('aws_credentials');
    });

    it('detects reading ~/.config/gcloud/', () => {
      const r = checkReadPath('/home/user/.config/gcloud/application_default_credentials.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gcloud_credentials');
    });

    it('detects reading ~/.gnupg/secring.gpg', () => {
      const r = checkReadPath('/home/user/.gnupg/secring.gpg');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gpg_key');
    });

    it('detects reading .netrc file', () => {
      const r = checkReadPath('/home/user/.netrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('netrc_file');
    });

    it('detects reading .npmrc file', () => {
      const r = checkReadPath('/home/user/.npmrc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('npmrc_token');
    });

    it('detects reading .pypirc file', () => {
      const r = checkReadPath('/home/user/.pypirc');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pypirc_token');
    });

    it('detects reading .pgpass file', () => {
      const r = checkReadPath('/home/user/.pgpass');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('pgpass_file');
    });

    it('detects reading .git-credentials file', () => {
      const r = checkReadPath('/home/user/.git-credentials');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_credentials');
    });

    it('detects reading .docker/config.json', () => {
      const r = checkReadPath('/home/user/.docker/config.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('docker_auth');
    });

    it('detects reading .kube/config', () => {
      const r = checkReadPath('/home/user/.kube/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('kube_config');
    });

    it('detects reading .config/gh/', () => {
      const r = checkReadPath('/home/user/.config/gh/hosts.yml');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('gh_token');
    });

    it('detects reading .azure/ directory', () => {
      const r = checkReadPath('/home/user/.azure/accessTokens.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('azure_credentials');
    });

    it('detects reading Library/Keychains/', () => {
      const r = checkReadPath('/Users/john/Library/Keychains/login.keychain-db');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('macos_keychain');
    });

    it('detects reading /etc/shadow', () => {
      const r = checkReadPath('/etc/shadow');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('shadow_file');
    });

    it('detects reading .tfstate file', () => {
      const r = checkReadPath('/project/terraform.tfstate');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('terraform_state');
    });
  });

  describe('checkReadPath - read sink patterns', () => {
    it('detects reading .my.cnf', () => {
      const r = checkReadPath('/home/user/.my.cnf');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('mysql_cnf');
    });

    it('detects reading .terraform.d/credentials.tfrc.json', () => {
      const r = checkReadPath('/home/user/.terraform.d/credentials.tfrc.json');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('terraform_credentials');
    });

    it('detects reading .config/git/credentials', () => {
      const r = checkReadPath('/home/user/.config/git/credentials');
      expect(r).not.toBeNull();
      // Could match git_credentials or git_credentials_xdg depending on which fires first
      expect(['git_credentials', 'git_credentials_xdg']).toContain(r![0]);
    });
  });

  describe('checkPathAccess - read-only wrapper', () => {
    it('delegates to checkReadPath for credential paths', () => {
      const r = checkPathAccess('/home/user/.ssh/id_rsa');
      expect(r).not.toBeNull();
    });

    it('returns null for benign paths', () => {
      const r = checkPathAccess('/project/src/main.ts');
      expect(r).toBeNull();
    });
  });

  describe('benign write paths pass through', () => {
    it('allows writing to src/ directory', () => {
      const r = checkWritePath('/project/src/main.ts');
      expect(r).toBeNull();
    });

    it('allows writing to build/ directory', () => {
      const r = checkWritePath('/project/build/output.js');
      expect(r).toBeNull();
    });

    it('allows writing to tmp/ directory', () => {
      const r = checkWritePath('/tmp/somefile.txt');
      expect(r).toBeNull();
    });

    it('returns null for empty path', () => {
      const r = checkWritePath('');
      expect(r).toBeNull();
    });
  });

  describe('benign read paths pass through', () => {
    it('allows reading src/ files', () => {
      const r = checkReadPath('/project/src/config.ts');
      expect(r).toBeNull();
    });

    it('allows reading package.json', () => {
      const r = checkReadPath('/project/package.json');
      expect(r).toBeNull();
    });

    it('returns null for empty path', () => {
      const r = checkReadPath('');
      expect(r).toBeNull();
    });
  });

  describe('fail-open on malformed input', () => {
    it('handles very long path without crashing', () => {
      const longPath = '/a/' + 'b'.repeat(1_000_000);
      expect(() => checkWritePath(longPath)).not.toThrow();
      expect(() => checkReadPath(longPath)).not.toThrow();
    });

    it('handles path with null bytes', () => {
      const r = checkWritePath('/etc/\x00shadow');
      // Should not crash; result depends on how realpathSync handles it
      expect(r).toBeNull();
    });
  });
});
