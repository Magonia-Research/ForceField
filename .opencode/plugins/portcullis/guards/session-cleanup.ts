import { logSecurityEvent } from '../logger.js';

export interface SessionCleanupResult {
  removed: number;
}

/** Cleans up per-session state on session end.

In OpenCode, guard state lives in-process (e.g., the spawn-rate Map in agent-spawn.ts),
so there is no disk state to remove. The Python version removes $TMPDIR/portcullis/spawn-{id}.json
files and sweeps stale entries older than 24h — that logic does not apply here. */
export function cleanupSessionState(sessionId: string): SessionCleanupResult {
  try {
    logSecurityEvent('session_cleanup', 'allow', { sessionId, extra: { removed: 0 } });
    return { removed: 0 };
  } catch {
    return { removed: 0 };
  }
}
