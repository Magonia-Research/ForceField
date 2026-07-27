import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cwd } from 'node:process';
import { minimatch } from 'minimatch';

const MAX_ALLOWLIST_BYTES = 65_536;

let cache: Record<string, unknown> | null = null;
let lastCwd = '';

function resetCache() {
  const currentCwd = cwd();
  if (currentCwd !== lastCwd) {
    cache = null;
    lastCwd = currentCwd;
  }
}

const NEVER_SUPPRESSIBLE: Record<string, ReadonlySet<string> | true> = {
  credential_access_guard: true,
  git_guard: new Set([
    'git_config_rce_primitive',
    'git_alias_shell',
    'git_env_rce',
    'git_hooks_dir_write',
    'git_config_file_write',
  ]),
};

function isNeverSuppressible(hookName: string, patternName: string | null): boolean {
  const protected_ = NEVER_SUPPRESSIBLE[hookName];
  if (!protected_) return false;
  if (protected_ === true) return true;
  return patternName != null && protected_.has(patternName);
}

function loadAllowlist(): Record<string, unknown> {
  resetCache();
  if (cache !== null) return cache;

  const cwdStr = cwd();
  const allowlistPath = join(cwdStr, '.opencode', 'hook-allowlist.json');

  try {
    const raw = readFileSync(allowlistPath, 'utf-8').slice(0, MAX_ALLOWLIST_BYTES);
    const data = JSON.parse(raw);
    cache = typeof data === 'object' && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : {};
  } catch {
    cache = {};
  }

  return cache;
}

export function isPatternSuppressed(hookName: string, patternName: string): boolean {
  if (isNeverSuppressible(hookName, patternName)) return false;

  const allowlist = loadAllowlist();
  const hookConfig = allowlist[hookName];
  if (typeof hookConfig !== 'object' || hookConfig === null || Array.isArray(hookConfig)) return false;

  const suppressed = (hookConfig as Record<string, unknown>)['suppress_patterns'];
  if (!Array.isArray(suppressed)) return false;
  return suppressed.includes(patternName);
}

export function isPathSuppressed(hookName: string, filePath: string): boolean {
  if (isNeverSuppressible(hookName, null)) return false;

  const allowlist = loadAllowlist();
  const hookConfig = allowlist[hookName];
  if (typeof hookConfig !== 'object' || hookConfig === null || Array.isArray(hookConfig)) return false;

  const suppressedPaths = (hookConfig as Record<string, unknown>)['suppress_paths'];
  if (!Array.isArray(suppressedPaths)) return false;

  for (const globPattern of suppressedPaths) {
    if (typeof globPattern === 'string' && minimatch(filePath, globPattern)) return true;
  }

  return false;
}

export function isSuppressed(
  hookName: string,
  patternName?: string | null,
  filePath?: string | null,
): boolean {
  try {
    if (patternName && isPatternSuppressed(hookName, patternName)) return true;
    if (filePath && isPathSuppressed(hookName, filePath)) return true;
  } catch {
    return false;
  }
  return false;
}
