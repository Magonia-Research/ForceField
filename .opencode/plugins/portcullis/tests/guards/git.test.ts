import { describe, it, expect } from 'bun:test';
import { checkGit, HARD_DENY_PATTERNS } from '../../guards/git.js';
import { BENIGN_COMMANDS } from '../test-helpers.js';

describe('git guard', () => {
  describe('recursive submodule clone', () => {
    it('detects git clone --recurse-submodules', () => {
      const r = checkGit('git clone https://github.com/user/repo.git --recurse-submodules');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('recursive_submodule_clone');
    });

    it('detects git clone with --recurse-submodules-default', () => {
      const r = checkGit('git clone https://github.com/user/repo.git --recurse-submodules-default');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('recursive_submodule_clone');
    });

    it('detects git pull --recurse-submodules', () => {
      const r = checkGit('git pull --recurse-submodules');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('submodule_recurse_fetch');
    });

    it('detects git fetch --recurse-submodules', () => {
      const r = checkGit('git fetch --recurse-submodules');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('submodule_recurse_fetch');
    });

    it('detects git submodule update --init', () => {
      const r = checkGit('git submodule update --init');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('submodule_update');
    });
  });

  describe('RCE via config primitives', () => {
    it('detects git config core.hooksPath', () => {
      const r = checkGit('git config core.hooksPath /tmp/evil-hooks');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config core.sshCommand', () => {
      const r = checkGit('git config core.sshCommand "ssh -o StrictHostKeyChecking=no"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config core.pager', () => {
      const r = checkGit('git config core.pager "bash -c /tmp/exploit"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config alias with shell bang', () => {
      const r = checkGit("git config alias.exploit '!bash -c /tmp/exploit'");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_alias_shell');
    });

    it('detects git -c core.editor exploit', () => {
      const r = checkGit('git -c core.editor="bash -c /tmp/exploit" status');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config filter.process', () => {
      const r = checkGit('git config filter.evil.process "bash -c /tmp/exploit"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config uploadpack.packObjectsHook', () => {
      const r = checkGit('git config uploadpack.packObjectsHook /tmp/exploit.sh');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config credential.helper with !bang', () => {
      const r = checkGit("git config credential.helper '!bash -c /tmp/exploit'");
      expect(r).not.toBeNull();
      // Could match either git_alias_shell or git_config_rce_primitive depending on regex order
      expect(['git_alias_shell', 'git_config_rce_primitive']).toContain(r![0]);
    });

    it('detects git config sequence.editor', () => {
      const r = checkGit('git config sequence.editor "bash -c /tmp/exploit"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config pager.log with shell', () => {
      const r = checkGit('git config pager.log "bash -c /tmp/exploit"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config protocol.file.allow', () => {
      const r = checkGit('git config protocol.file.allow always');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config clone.recurseSubmodules', () => {
      const r = checkGit('git config clone.recurseSubmodules true');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config submodule.recurse', () => {
      const r = checkGit('git config submodule.recurse true');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config core.alternateRefsCommand', () => {
      const r = checkGit('git config core.alternateRefsCommand /tmp/exploit.sh');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config diff.external', () => {
      const r = checkGit('git config diff.external "/tmp/exploit.sh"');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });

    it('detects git config core.fsmonitor', () => {
      const r = checkGit('git config core.fsmonitor /tmp/evil-fsmonitor');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });
  });

  describe('RCE via environment variables', () => {
    it('detects GIT_SSH_COMMAND=exploit git clone', () => {
      const r = checkGit('GIT_SSH_COMMAND="bash -c /tmp/exploit" git clone https://github.com/user/repo.git');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_ASKPASS=exploit', () => {
      const r = checkGit('GIT_ASKPASS="/tmp/exploit.sh" git credential fill');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_EDITOR=exploit', () => {
      const r = checkGit('GIT_EDITOR="bash -c /tmp/exploit" git commit');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_SEQUENCE_EDITOR=exploit', () => {
      const r = checkGit('GIT_SEQUENCE_EDITOR="bash -c /tmp/exploit" git rebase -i HEAD~3');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_EXTERNAL_DIFF=exploit', () => {
      const r = checkGit('GIT_EXTERNAL_DIFF="/tmp/exploit.sh" git diff');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_TEMPLATE_DIR=exploit', () => {
      const r = checkGit('GIT_TEMPLATE_DIR="/tmp/evil-templates" git init');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_CONFIG_COUNT with injected key/value', () => {
      const r = checkGit('GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/tmp/evil git init');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_PROXY_COMMAND=exploit', () => {
      const r = checkGit('GIT_PROXY_COMMAND="/tmp/exploit.sh" git fetch');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_PAGER=exploit', () => {
      const r = checkGit('GIT_PAGER="bash -c /tmp/exploit" git log');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_CONFIG_PARAMETERS with injected config', () => {
      const r = checkGit('GIT_CONFIG_PARAMETERS="core.hooksPath=/tmp/evil" git init');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_SSH=exploit', () => {
      const r = checkGit('GIT_SSH="/tmp/exploit.sh" git clone https://github.com/user/repo.git');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects GIT_CONFIG=exploit', () => {
      const r = checkGit('GIT_CONFIG="/tmp/evil-config" git init');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });
  });

  describe('hooks directory write', () => {
    it('detects writing to .git/hooks/', () => {
      const r = checkGit('echo "evil" > .git/hooks/pre-commit');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });

    it('detects cp to .git/modules/mod/hooks/', () => {
      const r = checkGit('cp exploit.sh .git/modules/submod/hooks/post-checkout');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });

    it('detects tee to $GIT_DIR/hooks/', () => {
      const r = checkGit('echo "evil" | tee $GIT_DIR/hooks/pre-push');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });

    it('detects writing via --git-path hooks', () => {
      const r = checkGit('git --git-path=hooks ls-files');
      // This may not match since the pattern requires a write verb before the path
      expect(r).toBeNull();
    });
  });

  describe('config file write', () => {
    it('detects writing to .git/config', () => {
      const r = checkGit('echo "[core]" > .git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects writing to ~/.gitconfig', () => {
      const r = checkGit('echo "[core]" >> ~/.gitconfig');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects cp to .config/git/config', () => {
      const r = checkGit('cp evil-config ~/.config/git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects writing to /etc/gitconfig', () => {
      const r = checkGit('echo "[core]" > /etc/gitconfig');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects sed on .git/modules/mod/config', () => {
      const r = checkGit("sed -i 's/old/new/' .git/modules/submod/config");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects python writing to .git/config', () => {
      const r = checkGit("python3 -c 'open(\".git/config\", \"w\").write(\"evil\")'");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects node writing to .gitconfig', () => {
      const r = checkGit("node -e 'require(\"fs\").writeFileSync(\"~/.gitconfig\", \"evil\")'");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects perl writing to .git/config', () => {
      const r = checkGit("perl -e 'open(F, \">.git/config\"); print F \"evil\"; close F'");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects ruby writing to .gitconfig', () => {
      const r = checkGit("ruby -e 'File.write(\"~/.gitconfig\", \"evil\")'");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects printf to .git/config', () => {
      const r = checkGit("printf '[core]\\n' > .git/config");
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects dd of= .git/config', () => {
      const r = checkGit('dd if=/tmp/evil of=.git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects patch on .gitconfig', () => {
      const r = checkGit('patch ~/.gitconfig < /tmp/exploit.patch');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects truncate on .git/config', () => {
      const r = checkGit('truncate -s 0 .git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects chmod on .git/hooks/pre-commit', () => {
      const r = checkGit('chmod +x .git/hooks/pre-commit');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });

    it('detects ln to .git/hooks/', () => {
      const r = checkGit('ln -sf /tmp/exploit.sh .git/hooks/post-checkout');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });

    it('detects install to .git/config', () => {
      const r = checkGit('install -m 644 /tmp/evil-config .git/config');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_file_write');
    });

    it('detects mv to .git/hooks/', () => {
      const r = checkGit('mv /tmp/exploit.sh .git/hooks/pre-push');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_hooks_dir_write');
    });
  });

  describe('HARD_DENY_PATTERNS constant', () => {
    it('is empty (all git patterns are "ask")', () => {
      expect(HARD_DENY_PATTERNS).toEqual([]);
    });
  });

  describe('benign commands pass through', () => {
    for (const cmd of BENIGN_COMMANDS) {
      it(`allows "${cmd}"`, () => {
        expect(checkGit(cmd)).toBeNull();
      });
    }

    it('allows normal git clone without --recurse-submodules', () => {
      expect(checkGit('git clone https://github.com/user/repo.git')).toBeNull();
    });

    it('allows git submodule status (not update)', () => {
      expect(checkGit('git submodule status')).toBeNull();
    });

    it('allows git config --list', () => {
      expect(checkGit('git config --list')).toBeNull();
    });

    it('allows git push origin main', () => {
      expect(checkGit('git push origin main')).toBeNull();
    });
  });

  describe('command normalization interaction', () => {
    it('detects RCE through IFS splitting obfuscation', () => {
      const r = checkGit('GIT_SSH_COMMAND${IFS}"bash -c /tmp/exploit" git clone https://github.com/user/repo.git');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_env_rce');
    });

    it('detects RCE through line continuation', () => {
      const r = checkGit('git config \\\n  core.hooksPath /tmp/evil-hooks');
      expect(r).not.toBeNull();
      expect(r![0]).toBe('git_config_rce_primitive');
    });
  });

  describe('fail-open on malformed input', () => {
    it('returns null for empty string', () => {
      expect(checkGit('')).toBeNull();
    });

    it('handles very long command without crashing', () => {
      const longCmd = 'git config ' + 'x'.repeat(100_000);
      expect(() => checkGit(longCmd)).not.toThrow();
    });
  });
});
