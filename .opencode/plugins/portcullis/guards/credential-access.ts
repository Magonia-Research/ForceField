import { normalizeCommand } from '../normalize.js';

const _READERS = new RegExp(
  '(?:^|[\\s;&|(<>`$\/\'"\\\\])' +
  '(?:cat|head|tail|less|more|bat|strings|xxd|od|hexdump' +
  '|base64|base32|nl|sed|awk|dd|cut|tac|rev)' +
  '(?=$|[\\s\'"<>|;&)])', 'i');

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

export const HARD_DENY_PATTERNS: readonly string[] = [];

export function checkCommand(command: string): [string, string] | null {
  try {
    const normalized = normalizeCommand(command);
    const variants = normalized === command ? [command] : [command, normalized];
    for (const text of variants) {
      if (!_READERS.test(text)) continue;
      for (const [name, pattern] of CREDENTIAL_ACCESS_PATTERNS) {
        const match = text.match(pattern);
        if (match) return [name, match[0]];
      }
    }
    return null;
  } catch {
    return null;
  }
}
