import { resolve, sep } from 'node:path';
import { realpathSync } from 'node:fs';
import { homedir } from 'node:os';

const CREDENTIAL_ACCESS_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['dotenv_file', /\.env(?:rc)?\b(?!\.(?:example|sample|template|dist|defaults?))/i],
  ['ssh_key', /\.ssh\//i],
  ['private_key_file', /\bid_(?:rsa|dsa|ecdsa|ed25519)\b/i],
  ['aws_credentials', /\.aws\//i],
  ['gcloud_credentials', /\.config\/gcloud\//i],
  ['gpg_key', /\.gnupg\//i],
  ['netrc_file', /\.netrc\b/i],
  ['npmrc_token', /\.npmrc\b/i],
  ['pypirc_token', /\.pypirc\b/i],
  ['pgpass_file', /\.pgpass\b/i],
  ['git_credentials', /\.git-credentials\b|\.config\/git\/credentials\b/i],
  ['docker_auth', /\.docker\/config\.json\b/i],
  ['kube_config', /\.kube\//i],
  ['gh_token', /\.config\/gh\//i],
  ['azure_credentials', /\.azure\//i],
  ['macos_keychain', /Library\/Keychains\//i],
  ['shadow_file', /\/etc\/shadow\b/i],
  ['terraform_state', /\.tfstate\b/i],
]);

const WRITE_SINK_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['ssh_authorized_keys', /\/\.ssh\/authorized_keys$/i],
  ['ssh_dir', /\/\.ssh\//i],
  ['aws_dir', /\/\.aws\//i],
  ['gnupg_dir', /\/\.gnupg\//i],
  ['gcloud_dir', /\/\.config\/gcloud\//i],
  ['kube_dir', /\/\.kube\//i],
  ['docker_config', /\/\.docker\/config\.json$/i],
  ['npmrc', /\/\.npmrc$/i],
  ['pypirc', /\/\.pypirc$/i],
  ['netrc', /\/\.netrc$/i],
  ['git_credentials', /\/\.git-credentials$/i],
  ['shell_init', /\/\.(?:bashrc|zshrc|bash_profile|zprofile|profile|bash_login|bash_logout|zshenv|zlogin|zlogout|bash_aliases)$/i],
  ['fish_init', /\/\.config\/fish\/(?:config\.fish$|conf\.d\/)/i],
  ['git_hooks', /\/\.git\/hooks\//i],
  ['git_config_file', /\/\.git\/config$/i],
  ['git_global_config', /\/\.gitconfig$|\/\.config\/git\/config$/i],
  ['launch_agents', /\/Library\/(?:LaunchAgents|LaunchDaemons)\//i],
  ['autostart', /\/\.config\/autostart\//i],
  ['cron', /\/(?:etc\/cron|etc\/crontab|var\/at\/|var\/spool\/cron)/i],
  ['systemd_unit', /\/(?:etc|lib|usr\/lib)\/systemd\/system\/|\/systemd\/user\//i],
  ['rc_local', /\/etc\/rc\.local$/i],
  ['etc_sensitive', /\/etc\/(?:sudoers|sudoers\.d\/|passwd|shadow|hosts|profile|environment|pam\.d\/|ld\.so\.preload|ld\.so\.conf)/i],
]);

const CONFIG_SINK_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['claude_settings', /\/\.claude\/settings(?:\.local)?\.json$/i],
  ['hook_allowlist', /\/\.claude\/hook-allowlist\.json$/i],
  ['portcullis_config', /\/\.claude\/portcullis\.json$/i],
  ['mcp_config', /\/\.mcp\.json$/i],
]);

const READ_SINK_PATTERNS: ReadonlyMap<string, RegExp> = new Map([
  ['mysql_cnf', /\/\.my\.cnf$/i],
  ['terraform_credentials', /\/\.terraform\.d\/credentials\.tfrc\.json$/i],
  ['git_credentials_xdg', /\/\.config\/git\/credentials$/i],
]);

function _canonical(path: string): string {
  if (!path) return '';
  let expanded = path.replace(/^~(?=$|\/)/, homedir());
  expanded = expanded.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_m, varName) => {
    return process.env[varName] ?? '';
  });
  if (!expanded.startsWith('/')) {
    expanded = resolve(process.cwd(), expanded);
  }
  try {
    return realpathSync(expanded);
  } catch {
    return expanded;
  }
}

function _pluginRootReal(): string {
  const root = process.env['OPencode_PLUGIN_ROOT'] ?? '';
  return root ? _canonical(root) : '';
}

export function checkWritePath(path: string): [string, string] | null {
  try {
    const canonical = _canonical(path);
    if (!canonical) return null;
    const pluginRoot = _pluginRootReal();
    if (pluginRoot && (canonical === pluginRoot || canonical.startsWith(pluginRoot + sep))) {
      return ['portcullis_plugin', canonical];
    }
    for (const [name, pattern] of CONFIG_SINK_PATTERNS) {
      if (pattern.test(canonical)) return [name, canonical];
    }
    for (const [name, pattern] of WRITE_SINK_PATTERNS) {
      if (pattern.test(canonical)) return [name, canonical];
    }
    return null;
  } catch {
    return null;
  }
}

export function checkReadPath(path: string): [string, string] | null {
  try {
    const canonical = _canonical(path);
    if (!canonical) return null;
    for (const [name, pattern] of CREDENTIAL_ACCESS_PATTERNS) {
      if (pattern.test(canonical) || pattern.test(path)) return [name, canonical];
    }
    for (const [name, pattern] of READ_SINK_PATTERNS) {
      if (pattern.test(canonical) || pattern.test(path)) return [name, canonical];
    }
    return null;
  } catch {
    return null;
  }
}

export function checkPathAccess(filePath: string): [string, string] | null {
  try {
    const result = checkReadPath(filePath);
    if (result) return result;
    return null;
  } catch {
    return null;
  }
}
