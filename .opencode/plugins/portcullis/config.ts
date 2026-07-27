import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { cwd } from 'node:process';

const MAX_CONFIG_BYTES = 65_536;

const RANK: Record<string, number> = {
  off: 0,
  allow: 1,
  warn: 2,
  redact: 3,
  ask: 4,
  deny: 5,
};

export const NATURAL_MAX: Record<string, string> = {
  container_first: 'deny',
  exfil_guard: 'deny',
  supply_chain_guard: 'deny',
  git_guard: 'ask',
  credential_access_guard: 'ask',
  credential_guard: 'ask',
  mcp_guard: 'ask',
  agent_guard: 'deny',
  webfetch_guard: 'deny',
  filesystem_guard: 'ask',
  sigma_engine: 'ask',
};

export const PRESETS: Record<string, Record<string, string>> = {
  strict: {
    container_first: 'deny',
    exfil_guard: 'deny',
    supply_chain_guard: 'deny',
    git_guard: 'ask',
    credential_access_guard: 'ask',
    credential_guard: 'ask',
    mcp_guard: 'ask',
    agent_guard: 'deny',
    webfetch_guard: 'deny',
    filesystem_guard: 'ask',
    sigma_engine: 'ask',
  },
  balanced: {
    container_first: 'deny',
    exfil_guard: 'deny',
    supply_chain_guard: 'ask',
    git_guard: 'ask',
    credential_access_guard: 'ask',
    credential_guard: 'ask',
    mcp_guard: 'ask',
    agent_guard: 'deny',
    webfetch_guard: 'ask',
    filesystem_guard: 'ask',
    sigma_engine: 'warn',
  },
  permissive: {
    container_first: 'ask',
    exfil_guard: 'ask',
    supply_chain_guard: 'ask',
    git_guard: 'ask',
    credential_access_guard: 'ask',
    credential_guard: 'ask',
    mcp_guard: 'ask',
    agent_guard: 'ask',
    webfetch_guard: 'ask',
    filesystem_guard: 'ask',
    sigma_engine: 'warn',
  },
};

const PRESET_SEVERITY_FLOOR = { strict: 'low', balanced: 'medium', permissive: 'high' };
export const DEFAULT_SEVERITY_FLOOR = 'medium';
const VALID_FLOORS = new Set(Object.values(PRESET_SEVERITY_FLOOR));

let homeCache: Record<string, unknown> | null = null;
let projectCache: Record<string, unknown> | null = null;
let lastCwd = '';

function resetCache() {
  const currentCwd = cwd();
  if (currentCwd !== lastCwd) {
    homeCache = null;
    projectCache = null;
    lastCwd = currentCwd;
  }
}

function readConfig(path: string): Record<string, unknown> {
  try {
    const raw = readFileSync(path, 'utf-8').slice(0, MAX_CONFIG_BYTES);
    const data = JSON.parse(raw);
    return typeof data === 'object' && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function homeConfigPath(): string {
  return join(homedir(), '.config', 'opencode', 'portcullis.json');
}

function projectConfigPath(cwdStr: string): string {
  return join(cwdStr, '.opencode', 'portcullis.json');
}

function getHomeConfig(): Record<string, unknown> {
  resetCache();
  if (homeCache !== null) return homeCache;
  homeCache = readConfig(homeConfigPath());
  return homeCache;
}

function getProjectConfig(): Record<string, unknown> {
  resetCache();
  if (projectCache !== null) return projectCache;
  const cwdStr = cwd();
  const projPath = projectConfigPath(cwdStr);
  const homePath = homeConfigPath();
  try {
    const same = realpathSync(projPath) === realpathSync(homePath);
    projectCache = same ? {} : readConfig(projPath);
  } catch {
    projectCache = {};
  }
  return projectCache;
}

function guardOverride(config: Record<string, unknown>, guardName: string): Record<string, unknown> {
  const guards = config['guards'];
  if (typeof guards !== 'object' || guards === null || Array.isArray(guards)) return {};
  const override = (guards as Record<string, unknown>)[guardName];
  return typeof override === 'object' && override !== null && !Array.isArray(override) ? (override as Record<string, unknown>) : {};
}

function homeProjectEntry(home: Record<string, unknown>, cwdStr: string): Record<string, unknown> {
  const projects = home['projects'];
  if (typeof projects !== 'object' || projects === null || Array.isArray(projects)) return {};
  let best: Record<string, unknown> = {};
  let bestLen = -1;
  for (const [prefix, entry] of Object.entries(projects as Record<string, unknown>)) {
    if (typeof prefix !== 'string' || typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const normalized = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    if ((cwdStr === normalized || cwdStr.startsWith(normalized + '/')) && (prefix.length ?? 0) > bestLen) {
      best = entry as Record<string, unknown>;
      bestLen = prefix.length ?? 0;
    }
  }
  return best;
}

export function clamp(decision: string, ceiling: string): string {
  const dRank = RANK[decision];
  const cRank = RANK[ceiling];
  if (dRank == null || cRank == null) return decision;
  return dRank <= cRank ? decision : ceiling;
}

function floorUntrusted(guardName: string, ceiling: string): string {
  const askRank = RANK['ask'] ?? 0;
  if (guardName in NATURAL_MAX && ((RANK[ceiling] ?? 5) < askRank)) return 'ask';
  return ceiling;
}

function ceilingFrom(config: Record<string, unknown>, guardName: string): string | null {
  const guardCfg = guardOverride(config, guardName);
  const overrideMode = guardCfg['mode'];
  if (typeof overrideMode === 'string' && overrideMode in RANK) return overrideMode;
  const preset = config['preset'];
  if (typeof preset === 'string' && preset in PRESETS) {
    const presetMap = PRESETS[preset];
    return (presetMap as Record<string, string>)[guardName] ?? null;
  }
  return null;
}

export function resolveCeiling(guardName: string): string {
  const naturalMax = NATURAL_MAX[guardName] ?? 'deny';
  const cwdStr = cwd();
  const home = getHomeConfig();

  let ceiling = naturalMax;

  const projCeiling = ceilingFrom(getProjectConfig(), guardName);
  if (projCeiling != null) ceiling = floorUntrusted(guardName, projCeiling);

  const homeCeiling = ceilingFrom(home, guardName);
  if (homeCeiling != null) ceiling = homeCeiling;

  const entryCeiling = ceilingFrom(homeProjectEntry(home, cwdStr), guardName);
  if (entryCeiling != null) ceiling = entryCeiling;

  const ceilingRank = RANK[ceiling];
  const naturalRank = RANK[naturalMax];
  if (ceilingRank != null && naturalRank != null && ceilingRank > naturalRank) ceiling = naturalMax;
  return ceiling;
}

export function resolveSeverityFloor(guardName: string = 'sigma_engine'): string {
  const home = getHomeConfig();
  const cwdStr = cwd();
  const configs = [homeProjectEntry(home, cwdStr), home, getProjectConfig()];

  for (const cfg of configs) {
    const guardCfg2 = guardOverride(cfg, guardName);
    const floor = guardCfg2['severity_floor'];
    if (typeof floor === 'string' && VALID_FLOORS.has(floor)) return floor;
  }
  for (const cfg of configs) {
    const preset = cfg['preset'];
    if (typeof preset === 'string' && preset in PRESET_SEVERITY_FLOOR) {
      const floorMap = PRESET_SEVERITY_FLOOR;
      return (floorMap as Record<string, string>)[preset] ?? DEFAULT_SEVERITY_FLOOR;
    }
  }
  return DEFAULT_SEVERITY_FLOOR;
}

export function effectiveDecision(guardName: string, decision: string): string {
  return clamp(decision, resolveCeiling(guardName));
}
