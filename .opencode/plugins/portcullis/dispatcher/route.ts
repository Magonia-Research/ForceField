import { effectiveDecision } from '../config.js';
import { isSuppressed } from '../allowlist.js';
import { clampAndEmit, logSecurityEvent } from '../logger.js';
import { DECISION_PRECEDENCE } from '../constants.js';
import type { PromptCredentialResult } from '../guards/prompt-credential-guard.js';
import type { SessionCleanupResult } from '../guards/session-cleanup.js';

type GuardResult = {
  decision: 'deny' | 'ask' | 'allow';
  hookName: string;
  patternName?: string;
  reason?: string;
};

function pickHighest(results: GuardResult[]): GuardResult | null {
  if (results.length === 0) return null;
  let best: GuardResult | null = null;
  for (const r of results) {
    const rank = DECISION_PRECEDENCE[r.decision] ?? 0;
    if (!best || rank > (DECISION_PRECEDENCE[best.decision] ?? 0)) {
      best = r;
    }
  }
  return best;
}

export async function routeBashBefore(
  command: string,
): Promise<GuardResult | null> {
  const results: GuardResult[] = [];

  try {
    const { checkCommand: checkExfil } = await import('../guards/exfil.js');
    const exfilMatch = checkExfil(command);
    if (exfilMatch) {
      const [patternName, matchedText] = exfilMatch;
      results.push({ decision: 'ask', hookName: 'exfil_guard', patternName, reason: `Exfiltration pattern detected: ${matchedText.slice(0, 120)}` });
    }
  } catch {
    logSecurityEvent('exfil_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  try {
    const { checkDangerous, checkTyposquat } = await import('../guards/supply-chain.js');
    const dangerMatch = checkDangerous(command);
    if (dangerMatch) {
      const [patternName, matchedText] = dangerMatch;
      results.push({ decision: 'ask', hookName: 'supply_chain_guard', patternName, reason: `Supply chain risk: ${matchedText.slice(0, 120)}` });
    }
    const typoMatch = checkTyposquat(command);
    if (typoMatch) {
      const [typo, correct] = typoMatch;
      results.push({ decision: 'ask', hookName: 'supply_chain_guard', patternName: 'typosquat', reason: `Possible typosquat: ${typo} → ${correct}` });
    }
  } catch {
    logSecurityEvent('supply_chain_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  try {
    const { checkGit } = await import('../guards/git.js');
    const gitMatch = checkGit(command);
    if (gitMatch) {
      const [patternName, matchedText] = gitMatch;
      results.push({ decision: 'ask', hookName: 'git_guard', patternName, reason: `Git risk: ${matchedText.slice(0, 120)}` });
    }
  } catch {
    logSecurityEvent('git_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  try {
    const { checkCommand: checkCredAccess } = await import('../guards/credential-access.js');
    const credMatch = checkCredAccess(command);
    if (credMatch) {
      const [patternName, matchedText] = credMatch;
      results.push({ decision: 'ask', hookName: 'credential_access_guard', patternName, reason: `Credential access: ${matchedText.slice(0, 120)}` });
    }
  } catch {
    logSecurityEvent('credential_access_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  const highest = pickHighest(results);
  if (!highest) return null;

  for (const r of results) {
    if (r.patternName && isSuppressed(r.hookName, r.patternName)) {
      logSecurityEvent(r.hookName, 'allow', { extra: { suppressed: true, command } });
      const idx = results.indexOf(r);
      if (idx > -1) results.splice(idx, 1);
    }
  }

  const afterSuppression = pickHighest(results);
  if (!afterSuppression) return null;

  const ceiling = effectiveDecision(afterSuppression.patternName ?? 'exfil_guard', afterSuppression.decision);

  logSecurityEvent(
    afterSuppression.patternName ?? 'bash_dispatcher',
    ceiling,
    { command: command.slice(0, 500), extra: { patternMatched: afterSuppression.patternName } },
  );

  return { ...afterSuppression, decision: ceiling as 'deny' | 'ask' | 'allow' };
}

export async function routeWriteBefore(
  toolName: string,
  filePath: string,
  content: string,
): Promise<GuardResult | null> {
  if (!content) return null;

  try {
    const { checkContent } = await import('../guards/content-credential.js');
      const match = checkContent(content, filePath);
      if (match) {
        const [patternName, matchedText] = match;
        if (isSuppressed('credential_guard', patternName, filePath)) {
          logSecurityEvent('credential_guard', 'allow', { extra: { suppressed: true, filePath } });
        return null;
      }
      const ceiling = effectiveDecision('credential_guard', 'ask');
      logSecurityEvent('credential_guard', ceiling, { patternMatched: patternName, filePath });
      return { decision: ceiling as 'deny' | 'ask' | 'allow', hookName: 'credential_guard', patternName, reason: `Credential in file content: ${matchedText.slice(0, 8)}...` };
    }
  } catch {
    logSecurityEvent('credential_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  return null;
}

export async function routeMcpBefore(_toolName: string, _toolInput: Record<string, unknown>): Promise<GuardResult | null> {
  try {
    const { checkMcpArgs } = await import('../guards/mcp.js');
      const result = checkMcpArgs(_toolName, _toolInput);
      if (result) {
        const [patternName, reason] = result;
        if (isSuppressed('mcp_guard', patternName)) {
          logSecurityEvent('mcp_guard', 'allow', { extra: { suppressed: true } });
        return null;
      }
      const ceiling = effectiveDecision('mcp_guard', 'ask');
      logSecurityEvent('mcp_guard', ceiling, { patternMatched: patternName });
      return { decision: ceiling as 'deny' | 'ask' | 'allow', hookName: 'mcp_guard', patternName, reason };
    }
  } catch {
    logSecurityEvent('mcp_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  return null;
}

export async function routeAgentBefore(_prompt: string): Promise<GuardResult | null> {
  try {
    const { checkAgentPrompt } = await import('../guards/agent-spawn.js');
    const result = checkAgentPrompt(_prompt);
    if (result) {
      const [patternName, reason] = result;
      const ceiling = effectiveDecision('agent_guard', 'ask');
      logSecurityEvent('agent_guard', ceiling, { patternMatched: patternName });
      return { decision: ceiling as 'deny' | 'ask' | 'allow', hookName: 'agent_guard', patternName, reason };
    }
  } catch {
    logSecurityEvent('agent_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  return null;
}

export async function routeWebfetchBefore(_url: string): Promise<GuardResult | null> {
  try {
    const { checkUrl } = await import('../guards/webfetch.js');
    const result = checkUrl(_url);
    if (result) {
      const [patternName, reason] = result;
      const ceiling = effectiveDecision('webfetch_guard', 'ask');
      logSecurityEvent('webfetch_guard', ceiling, { patternMatched: patternName });
      return { decision: ceiling as 'deny' | 'ask' | 'allow', hookName: 'webfetch_guard', patternName, reason };
    }
  } catch {
    logSecurityEvent('webfetch_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  return null;
}

export async function routeReadBefore(_filePath: string): Promise<GuardResult | null> {
  try {
    const { checkPathAccess } = await import('../guards/filesystem.js');
    const result = checkPathAccess(_filePath);
    if (result) {
      const [patternName, reason] = result;
      const ceiling = effectiveDecision('filesystem_guard', 'ask');
      logSecurityEvent('filesystem_guard', ceiling, { patternMatched: patternName });
      return { decision: ceiling as 'deny' | 'ask' | 'allow', hookName: 'filesystem_guard', patternName, reason };
    }
  } catch {
    logSecurityEvent('filesystem_guard', 'allow', { extra: { error: 'module load failed' } });
  }

  return null;
}

export async function routeBashAfter(
  output: string,
  source: string = 'Bash',
): Promise<string> {
  try {
    const { scanOutput } = await import('../guards/output-credential-scanner.js');
    const result = scanOutput(output, source);
    if (result?.redactedOutput) {
      return result.redactedOutput;
    }
    return output;
  } catch {
    logSecurityEvent('output_scanner', 'allow', { extra: { error: 'module load failed' } });
    return output;
  }
}

export async function routeReadAfter(
  output: string,
  filePath: string = '',
): Promise<string> {
  try {
    const { scanOutput } = await import('../guards/output-credential-scanner.js');
    let redacted = output;
    const credResult = scanOutput(output, filePath || 'Read');
    if (credResult?.redactedOutput) {
      redacted = credResult.redactedOutput;
    }

    const { scanContent } = await import('../guards/injection-defense.js');
    const injectionResult = scanContent(redacted, filePath);
    if (injectionResult) {
      logSecurityEvent('injection_defense', 'warn', {
        patternMatched: injectionResult.patternNames.join(','),
        filePath,
      });
    }

    return redacted;
  } catch {
    return output;
  }
}

export async function routeTaskAfter(
  output: string,
): Promise<string> {
  try {
    const { scanSubagentOutput } = await import('../guards/subagent-output.js');
    const result = scanSubagentOutput(output);
    if (result) {
      logSecurityEvent('subagent_output', 'warn', { patternMatched: result.patternNames.join(',') });
      return result.redactedOutput;
    }
    return output;
  } catch {
    return output;
  }
}

export async function routeSessionStart(): Promise<{ systemMessage?: string } | null> {
  try {
    const { handleSessionStart } = await import('../guards/session-baseline.js');
    return handleSessionStart();
  } catch {
    logSecurityEvent('session_baseline', 'allow', { extra: { error: 'module load failed' } });
    return null;
  }
}

export async function routePromptSubmit(prompt: string): Promise<PromptCredentialResult | null> {
  try {
    const { scanPrompt } = await import('../guards/prompt-credential-guard.js');
    return scanPrompt(prompt);
  } catch {
    logSecurityEvent('prompt_credential_guard', 'allow', { extra: { error: 'module load failed' } });
    return null;
  }
}

export async function routeSessionEnd(sessionId: string): Promise<SessionCleanupResult> {
  try {
    const { cleanupSessionState } = await import('../guards/session-cleanup.js');
    return cleanupSessionState(sessionId);
  } catch {
    logSecurityEvent('session_cleanup', 'allow', { extra: { error: 'module load failed' } });
    return { removed: 0 };
  }
}
