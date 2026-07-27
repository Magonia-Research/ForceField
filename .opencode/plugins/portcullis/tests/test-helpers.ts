// Shared test utilities for Portcullis guard unit tests.
// Zero dependencies — uses Bun's built-in `describe`, `it`, `expect`.

import { mock } from 'bun:test';

/** Decision type alias matching the plugin's internal vocabulary. */
export type Decision = 'deny' | 'ask' | 'allow' | 'warn' | 'redact' | 'block';

// ── Mock factories ────────────────────────────────────────────────

/** Create a mock allowlist file at `.opencode/hook-allowlist.json`. */
export function mockAllowlist(data: Record<string, unknown>): void {
  const { readFileSync } = require('node:fs');
  mock.module('node:fs', () => ({
    ...require('node:fs'),
    readFileSync: (path: string | Buffer, _enc?: string) => {
      if (typeof path === 'string' && path.endsWith('hook-allowlist.json')) {
        return JSON.stringify(data);
      }
      return readFileSync(path, _enc);
    },
  }));
}

/** Create a mock config file at `.opencode/portcullis.json`. */
export function mockConfig(data: Record<string, unknown>): void {
  const { readFileSync } = require('node:fs');
  mock.module('node:fs', () => ({
    ...require('node:fs'),
    readFileSync: (path: string | Buffer, _enc?: string) => {
      if (typeof path === 'string' && path.endsWith('portcullis.json')) {
        return JSON.stringify(data);
      }
      return readFileSync(path, _enc);
    },
  }));
}

/** Stub `process.cwd()` to return a fake project root. */
export function mockCwd(fakeCwd: string): () => void {
  const orig = process.cwd;
  Object.defineProperty(process, 'cwd', { value: () => fakeCwd, configurable: true });
  return () => { Object.defineProperty(process, 'cwd', { value: orig, configurable: true }); };
}

// ── Assertion helpers ─────────────────────────────────────────────

/** Assert that a guard returned null (no detection). */
export function expectNoMatch(actual: [string, string] | null): void {
  expect(actual).toBeNull();
}

/** Assert that a guard detected the expected pattern name. */
export function expectPattern(actual: [string, string] | null, expectedName: string): void {
  expect(actual).not.toBeNull();
  expect(actual![0]).toBe(expectedName);
}

/** Assert that a result object has the expected decision type. */
export function expectDecision(result: { decision?: Decision } | null, expected: Decision): void {
  expect(result).not.toBeNull();
  expect(result!.decision).toBe(expected);
}

/** Assert that a result's patternName starts with the expected prefix. */
export function expectPatternPrefix(
  result: { patternName?: string } | null,
  expectedPrefix: string,
): void {
  expect(result).not.toBeNull();
  expect(result!.patternName).toBeDefined();
  expect(result!.patternName!).toContain(expectedPrefix);
}

/** Assert that a result's message contains the expected substring. */
export function expectMessageContains(
  result: { message?: string; systemMessage?: string } | null,
  expectedSubstr: string,
): void {
  const msg = result?.message ?? result?.systemMessage ?? '';
  expect(msg).toContain(expectedSubstr);
}

/** Assert that a redacted output contains the expected [REDACTED: name] tag. */
export function expectRedacted(output: string | undefined, patternName: string): void {
  expect(output).toBeDefined();
  expect(output!).toContain(`[REDACTED: ${patternName}]`);
}

// ── Test data factories ───────────────────────────────────────────

/**
 * Build a synthetic credential fixture from a provider prefix and a body.
 *
 * The two halves are kept apart so the joined literal never appears
 * contiguously in source. These are detection test vectors, not live
 * credentials, but written whole they match provider patterns and trip
 * GitHub push protection and any scanner run against a clone. The value
 * returned is identical to the literal it replaces.
 */
export function fixtureSecret(prefix: string, body: string): string {
  return prefix + body;
}

/** Generate a fake credential value that matches the OpenAI key pattern. */
export function fakeOpenaiKey(): string {
  return 'sk-' + 'a'.repeat(32);
}

/** Generate a fake GitHub token. */
export function fakeGithubToken(): string {
  return 'ghp_' + 'A'.repeat(36);
}

/** Generate a fake AWS access key ID. */
export function fakeAwsAccessKey(): string {
  return 'AKIA' + 'A'.repeat(16);
}

/** Generate a base64 blob of the given length. */
export function b64Blob(len: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out + '==';
}

/** A benign command that should never trigger any guard. */
export const BENIGN_COMMANDS: readonly string[] = [
  'ls -la',
  'git status',
  'echo hello world',
  'cat README.md',
  'pwd',
];
