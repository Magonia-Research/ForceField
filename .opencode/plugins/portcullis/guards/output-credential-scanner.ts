import {
  CREDENTIAL_PATTERNS,
  FAKE_VALUE_RE,
  HIGH_CONFIDENCE_NAMES,
  isFakeValue,
} from '../guards/content-credential.js';
import { isSuppressed } from '../allowlist.js';
import { logSecurityEvent } from '../logger.js';

const SAFE_SIMPLE_COMMANDS = new RegExp(
  '^\\s*(git\\s+(log|status|branch|remote|tag|rev-parse)' +
  '|ls\\b|find\\s|wc\\s|pwd|which\\s|type\\s' +
  '|mkdir\\s|mv\\s|cp\\s|trash\\s|stat\\s|file\\s)',
);

const GIT_PATCH_FLAG = new RegExp(
  '(?:^|\\s)(?:-p|-u|-U\\d*|--patch|--unified)\\b',
);

const HAS_CHAINING = /[;&|]/;

const CREDENTIAL_SEARCH_INDICATORS = new RegExp(
  '(grep|rg|ag|ack)\\s+.*(AKIA|ghp_|sk-ant|BEGIN.*PRIVATE|api.key' +
  '|secret|token|password)',
  'i',
);

const PATTERN_PRIORITY: readonly string[] = [
  'anthropic_key', 'aws_access_key', 'aws_sts_key', 'aws_secret_key',
  'github_token', 'github_oauth_token', 'github_server_token',
  'github_fine_grained', 'gitlab_token', 'npm_token', 'private_key_header',
  'slack_token', 'stripe_key',
  'openai_key', 'jwt_token', 'generic_secret', 'password_assignment',
];

export interface OutputCredentialResult {
  redactedOutput?: string;
  systemMessage: string;
  patternNames: string[];
}

/** Scan tool output for leaked credentials. Returns null if no matches. */
export function scanOutput(text: string, source: string): OutputCredentialResult | null {
  try {
    const intentionalSearch = isCredentialSearch(source);
    const highMatches: [string, string][] = [];
    const lowMatches: string[] = [];

    const orderedPatterns = PATTERN_PRIORITY
      .filter((n) => n in CREDENTIAL_PATTERNS)
      .map((n) => [n, CREDENTIAL_PATTERNS[n]] as [string, RegExp]);

    for (const line of text.split('\n')) {
      const matchedSpans: Set<[number, number]> = new Set();

      for (const [name, pattern] of orderedPatterns) {
        const match = pattern.exec(line);
        if (!match) continue;

        const spanStart = match.index;
        const spanEnd = spanStart + match[0].length;

        let overlaps = false;
        for (const [s, e] of matchedSpans) {
          if (s <= spanStart && spanStart < e) {
            overlaps = true;
            break;
          }
        }
        if (overlaps) continue;

        const matchedText = match[0];
        const isHigh = HIGH_CONFIDENCE_NAMES.has(name);

        if (isHigh) {
          if (FAKE_VALUE_RE.test(matchedText)) continue;
        } else if (isFakeValue(matchedText, line)) {
          continue;
        }

        if (isSuppressed('output_credential_scanner', name)) continue;

        matchedSpans.add([spanStart, spanEnd]);

        if (isHigh) {
          highMatches.push([name, matchedText]);
        } else {
          lowMatches.push(name);
        }
      }
    }

    if (highMatches.length === 0 && lowMatches.length === 0) return null;

    const patternNames = [...highMatches.map((m) => m[0]), ...lowMatches];
    const sourcePrefix = source.slice(0, 40);

    const msg = [
      `CREDENTIAL DETECTED IN COMMAND OUTPUT: ${[...new Set(patternNames)].join(', ')}`,
      `The output from '${sourcePrefix}...' contains what appears to be a live credential.`,
      'Do NOT echo, log, or forward this value. Reference it by name only.',
      'If this credential was needed for a task, suggest the user set it as an environment variable.',
    ].join('\n');

    if (highMatches.length > 0) {
      let redactedText = text;
      for (const [name, matchedText] of highMatches) {
        redactedText = redactedText.replaceAll(matchedText, `[REDACTED: ${name}]`);
      }

      logSecurityEvent('output_credential_scanner', 'redact', {
        patternMatched: [...new Set(highMatches.map((m) => m[0]))].join(','),
        command: sourcePrefix,
        extra: { intentional_search: intentionalSearch },
      });

      return {
        redactedOutput: redactedText,
        systemMessage: msg,
        patternNames,
      };
    }

    logSecurityEvent('output_credential_scanner', 'warn_low', {
      patternMatched: [...new Set(patternNames)].join(','),
      command: sourcePrefix,
    });

    return {
      systemMessage: msg,
      patternNames,
    };
  } catch {
    return null;
  }
}

/** Check if a command is safe to skip scanning (git status, ls, etc.) */
export function isSafeCommand(command: string): boolean {
  try {
    if (HAS_CHAINING.test(command)) return false;
    if (!SAFE_SIMPLE_COMMANDS.test(command)) return false;
    if (/^\s*git\s+log\b/.test(command) && GIT_PATCH_FLAG.test(command)) return false;
    return true;
  } catch {
    return false;
  }
}

/** Check if a command appears to be intentionally searching for credentials */
export function isCredentialSearch(command: string): boolean {
  try {
    return CREDENTIAL_SEARCH_INDICATORS.test(command);
  } catch {
    return false;
  }
}
