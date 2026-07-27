import { CREDENTIAL_PATTERNS, isFakeValue } from './content-credential.js';
import { isSuppressed } from '../allowlist.js';
import { logSecurityEvent } from '../logger.js';

export const BLOCK_PATTERNS: ReadonlySet<string> = new Set(['private_key_header']);

// High-confidence token types that trigger a warning (not a block).
// Low-confidence assignment patterns and JWTs are excluded to avoid over-warning.
export const WARN_PATTERNS: ReadonlySet<string> = new Set([
  'openai_key', 'anthropic_key',
  'aws_access_key', 'aws_sts_key',
  'github_token', 'github_oauth_token', 'github_server_token',
  'github_fine_grained', 'gitlab_token', 'npm_token',
  'slack_token', 'stripe_key',
]);

export const SUGGESTED_ENV_VARS: Record<string, string> = {
  openai_key: 'OPENAI_API_KEY',
  anthropic_key: 'ANTHROPIC_API_KEY',
  aws_access_key: 'AWS_ACCESS_KEY_ID',
  aws_sts_key: 'AWS_ACCESS_KEY_ID',
  github_token: 'GITHUB_TOKEN',
  github_oauth_token: 'GITHUB_TOKEN',
  github_server_token: 'GITHUB_TOKEN',
  github_fine_grained: 'GITHUB_TOKEN',
  gitlab_token: 'GITLAB_TOKEN',
  npm_token: 'NPM_TOKEN',
  slack_token: 'SLACK_TOKEN',
  stripe_key: 'STRIPE_API_KEY',
};

export const PATTERN_DESCRIPTIONS: Record<string, string> = {
  openai_key: 'OpenAI API key',
  anthropic_key: 'Anthropic API key',
  aws_access_key: 'AWS access key',
  aws_sts_key: 'AWS STS temporary access key',
  github_token: 'GitHub personal access token',
  github_oauth_token: 'GitHub OAuth token',
  github_server_token: 'GitHub server-to-server token',
  github_fine_grained: 'GitHub fine-grained token',
  gitlab_token: 'GitLab personal access token',
  npm_token: 'npm access token',
  slack_token: 'Slack token',
  stripe_key: 'Stripe API key',
  private_key_header: 'private key',
};

export const NEARBY_FAKE_CONTEXT: RegExp = /(example|placeholder|dummy|fake|test|sample|demo)/i;

/** Checks a ~100-char window around `matchStart` for placeholder keywords. */
export function hasNearbyFakeContext(prompt: string, matchStart: number): boolean {
  const start = Math.max(0, matchStart - 50);
  const end = Math.min(prompt.length, matchStart + 50);
  return NEARBY_FAKE_CONTEXT.test(prompt.slice(start, end));
}

export interface PromptCredentialResult {
  decision: 'block' | 'warn';
  patternName: string;
  reason: string;
  systemMessage?: string;
}

/** Scans a user prompt for pasted credentials. First match wins. */
export function scanPrompt(prompt: string): PromptCredentialResult | null {
  try {
    if (!prompt) return null;

    let offset = 0;
    for (const line of prompt.split(/\r?\n/)) {
      for (const [name, pattern] of Object.entries(CREDENTIAL_PATTERNS)) {
        if (!BLOCK_PATTERNS.has(name) && !WARN_PATTERNS.has(name)) continue;

        const match = pattern.exec(line);
        if (!match) continue;

        const matchedText = match[0];
        const isBlock = BLOCK_PATTERNS.has(name);

        // PEM headers are unambiguous — fake-context heuristics must not defeat the block.
        if (!isBlock) {
          if (isFakeValue(matchedText, line)) continue;
          const absPos = offset + match.index;
          if (hasNearbyFakeContext(prompt, absPos)) continue;
        }

        if (isSuppressed('prompt_credential_guard', name ?? null)) continue;

        if (isBlock) {
          logSecurityEvent('prompt_credential_guard', 'block', { patternMatched: name });
          return {
            decision: 'block',
            patternName: name,
            reason: [
              'Your message contains a private key (-----BEGIN ... PRIVATE KEY-----).',
              'Private keys should never be pasted into chat — they persist in conversation history.',
              'Instead: reference the key file path, or set an environment variable.',
            ].join('\n'),
          };
        }

        const envVar = SUGGESTED_ENV_VARS[name] ?? 'CREDENTIAL';
        const description = PATTERN_DESCRIPTIONS[name] ?? 'credential';
        logSecurityEvent('prompt_credential_guard', 'warn', { patternMatched: name });
        return {
          decision: 'warn',
          patternName: name,
          reason: `Possible ${description} detected in user message`,
          systemMessage: [
            `The user's message contains what appears to be a raw ${description}.`,
            'Do NOT echo this value in your response.',
            `If the user needs you to use this credential, suggest:`,
            `  export ${envVar}=<value>`,
            `Then reference os.environ["${envVar}"] in code.`,
          ].join('\n'),
        };
      }
      offset += line.length + 1; // +1 for the stripped newline
    }

    return null;
  } catch {
    return null;
  }
}
