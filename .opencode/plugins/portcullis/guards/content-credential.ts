import { minimatch } from 'minimatch';

export const CREDENTIAL_PATTERNS: Record<string, RegExp> = {
  openai_key: /sk-[a-zA-Z0-9]{20,}/,
  anthropic_key: /sk-ant-[a-zA-Z0-9-]{20,}/,
  github_token: /ghp_[a-zA-Z0-9]{36}/,
  github_oauth_token: /gho_[a-zA-Z0-9]{36}/,
  github_server_token: /ghs_[a-zA-Z0-9]{36}/,
  github_fine_grained: /github_pat_[a-zA-Z0-9_]{20,}/,
  gitlab_token: /glpat-[a-zA-Z0-9_-]{20}/,
  npm_token: /npm_[a-zA-Z0-9]{36}/,
  aws_access_key: /AKIA[0-9A-Z]{16}/,
  aws_sts_key: /ASIA[0-9A-Z]{16}/,
  aws_secret_key: /aws_secret_access_key\s*[=:]\s*['"]?[a-zA-Z0-9/+=]{40}/i,
  private_key_header: /-----BEGIN\s+(?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)\s+)?PRIVATE\s+KEY-----/,
  jwt_token: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\./,
  generic_secret: /(api_key|api_secret|secret_key|access_token|auth_token)\s*[=:]\s*['"]?[a-zA-Z0-9_/+=.-]{16,}/i,
  password_assignment: /(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/i,
  slack_token: /xox[baprs]-[a-zA-Z0-9-]+/,
  stripe_key: /(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}/,
};

const EXCLUDED_DIR_SEGMENTS = new Set([
  'test', 'tests', '__tests__', 'testdata', 'test-data', 'test_data',
  'fixture', 'fixtures', '__fixtures__',
]);

const EXCLUDED_FILENAME_GLOBS = ['*.env', '*.env.*', '*.example'];

export const FAKE_VALUE_RE = /(example|placeholder|dummy|fake|test|xxx|your[_-])/i;
export const COMMENT_CONTEXT_RE = /\#\s*(example|placeholder|sample|demo|fake|dummy)/i;

export const HIGH_CONFIDENCE_NAMES = new Set([
  'openai_key', 'anthropic_key', 'github_token', 'github_oauth_token',
  'github_server_token', 'github_fine_grained', 'gitlab_token', 'npm_token',
  'aws_access_key', 'aws_sts_key', 'aws_secret_key', 'private_key_header',
  'jwt_token', 'slack_token', 'stripe_key',
]);

export function isExcludedPath(filePath: string): boolean {
  const segments = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
  if (segments.length === 0) return false;
  for (const segment of segments.slice(0, -1)) {
    if (EXCLUDED_DIR_SEGMENTS.has(segment.toLowerCase())) return true;
  }
  const basename = segments[segments.length - 1];
  if (!basename) return false;
  for (const globPattern of EXCLUDED_FILENAME_GLOBS) {
    if (minimatch(basename, globPattern)) return true;
  }
  return false;
}

export function isFakeValue(matchedText: string, line: string): boolean {
  if (FAKE_VALUE_RE.test(matchedText)) return true;
  if (COMMENT_CONTEXT_RE.test(line)) return true;
  return false;
}

export function isPlaceholderCredential(
  matchedText: string,
  line: string,
  highConfidence: boolean,
): boolean {
  if (highConfidence) {
    return FAKE_VALUE_RE.test(matchedText);
  }
  return isFakeValue(matchedText, line);
}

export function checkContent(
  content: string,
  filePath: string,
): [string, string] | null {
  if (!content || isExcludedPath(filePath)) return null;

  for (const line of content.split('\n')) {
    for (const [name, pattern] of Object.entries(CREDENTIAL_PATTERNS)) {
      const match = pattern.exec(line);
      if (match) {
        const matchedText = match[0];
        if (isFakeValue(matchedText, line)) continue;
        return [name, matchedText];
      }
    }
  }
  return null;
}

export function formatAlert(
  patternName: string,
  matchedText: string,
  filePath: string,
): string {
  const descriptions: Record<string, string> = {
    openai_key: 'OpenAI API key',
    anthropic_key: 'Anthropic API key',
    github_token: 'GitHub personal access token',
    github_oauth_token: 'GitHub OAuth token',
    github_server_token: 'GitHub server-to-server token',
    github_fine_grained: 'GitHub fine-grained token',
    gitlab_token: 'GitLab personal access token',
    npm_token: 'npm access token',
    aws_access_key: 'AWS access key ID',
    aws_sts_key: 'AWS STS temporary access key',
    aws_secret_key: 'AWS secret access key',
    private_key_header: 'Private key file',
    jwt_token: 'JWT token',
    generic_secret: 'API key/secret assignment',
    password_assignment: 'Hardcoded password',
    slack_token: 'Slack token',
    stripe_key: 'Stripe API key',
  };
  const desc = descriptions[patternName] ?? 'Credential pattern';
  const redacted = matchedText.length > 12 ? `${matchedText.slice(0, 8)}...${matchedText.slice(-4)}` : matchedText;
  return [
    `CREDENTIAL GUARD: ${desc}`,
    '',
    `Pattern: ${patternName}`,
    `Value: ${redacted}`,
    `File: ${filePath}`,
    '',
    'Before approving:',
    '- Is this a real credential or a placeholder?',
    '- Should this be in a .env file instead?',
    '- Is the file in .gitignore?',
  ].join('\n');
}
