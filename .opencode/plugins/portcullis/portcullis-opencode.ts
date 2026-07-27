import { randomUUID } from 'node:crypto';
import { getSessionId, setSessionId, logSecurityEvent } from './logger.js';
import { routeBashBefore, routeWriteBefore, routeMcpBefore, routeAgentBefore, routeWebfetchBefore, routeReadBefore, routeBashAfter, routeReadAfter, routeTaskAfter, routeSessionStart, routeSessionEnd } from './dispatcher/route.js';

interface PluginContext {
  directory: string;
  worktree?: string | undefined;
  project?: unknown;
  client?: unknown;
  $?: unknown;
}

export const PortcullisPlugin = async ({ directory, client }: PluginContext) => {
  const sessionId = randomUUID();
  setSessionId(sessionId);

  logSecurityEvent('plugin_init', 'info', {
    extra: { message: 'Portcullis plugin initialized', directory },
  });

  return {
    'tool.execute.before': async (input: unknown, _output: unknown) => {
      const data = input as Record<string, unknown>;
      const toolName = data['tool'] as string | undefined;
      if (!toolName || typeof toolName !== 'string') return;

      try {
        if (toolName === 'Bash' || toolName === 'bash') {
          const args = data['args'] as Record<string, unknown> | undefined;
          const command = (typeof args?.['command'] === 'string' ? args['command'] : typeof data['command'] === 'string' ? data['command'] : '') as string;
          if (!command) return;
          const result = await routeBashBefore(command);
          if (!result) return;

          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          if (result.decision === 'ask' && client && typeof client === 'object' && 'session' in client) {
            const session = (client as Record<string, unknown>)['session'];
            if (session && typeof session === 'object' && 'prompt' in session) {
              const promptFn = (session as Record<string, unknown>)['prompt'];
              if (typeof promptFn === 'function') {
                try {
                  promptFn.call(session, { noReply: true, parts: [{ type: 'text', text: result.reason ?? '' }] });
                } catch {
                  // Context injection failure is non-critical
                }
              }
            }
          }
          return;
        }

        if (typeof toolName === 'string' && toolName.startsWith('mcp__')) {
          const args = data['args'] as Record<string, unknown> | undefined;
          const result = await routeMcpBefore(toolName, args ?? {});
          if (!result) return;
          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          return;
        }

        const writeTools = ['Write', 'write', 'Edit', 'edit'];
        if (writeTools.includes(toolName)) {
          const args = data['args'] as Record<string, unknown> | undefined;
          const filePath = typeof args?.['filePath'] === 'string' ? (args['filePath'] as string) : '';
          const content = typeof args?.['content'] === 'string' ? (args['content'] as string) : typeof args?.['newString'] === 'string' ? (args['newString'] as string) : '';
          const result = await routeWriteBefore(toolName, filePath, content);
          if (!result) return;
          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          return;
        }

        const readTools = ['Read', 'read'];
        if (readTools.includes(toolName)) {
          const args = data['args'] as Record<string, unknown> | undefined;
          const filePath = typeof args?.['filePath'] === 'string' ? (args['filePath'] as string) : '';
          const result = await routeReadBefore(filePath);
          if (!result) return;
          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          return;
        }

        if (toolName === 'Task' || toolName === 'task') {
          const args = data['args'] as Record<string, unknown> | undefined;
          const prompt = typeof args?.['prompt'] === 'string' ? (args['prompt'] as string) : '';
          const result = await routeAgentBefore(prompt);
          if (!result) return;
          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          return;
        }

        const fetchTools = ['WebFetch', 'webfetch', 'web_fetch', 'fetch'];
        if (fetchTools.includes(toolName)) {
          const args = data['args'] as Record<string, unknown> | undefined;
          const url = typeof args?.['url'] === 'string' ? (args['url'] as string) : '';
          const result = await routeWebfetchBefore(url);
          if (!result) return;
          if (result.decision === 'deny') {
            throw new Error(`Portcullis [${result.patternName}]: ${result.reason ?? 'Blocked by security policy'}`);
          }
          return;
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('Portcullis[')) {
          throw err;
        }
        logSecurityEvent('dispatcher', 'allow', { extra: { error: String(err) } });
      }
    },

    'tool.execute.after': async (input: unknown, output: unknown) => {
      const data = input as Record<string, unknown>;
      const toolName = data['tool'] as string | undefined;
      if (!toolName || typeof toolName !== 'string') return;

      try {
        const outData = output as Record<string, unknown> | undefined;
        let rawResult: string = '';

        if (outData) {
          const resultVal = outData['result'] ?? outData['output'] ?? outData['content'] ?? '';
          rawResult = typeof resultVal === 'string' ? resultVal : String(resultVal);
        }

        if (!rawResult) return;

        if (toolName === 'Bash' || toolName === 'bash') {
          const args = data['args'] as Record<string, unknown> | undefined;
          const command = typeof args?.['command'] === 'string' ? args['command'] : '';
          const redacted = await routeBashAfter(rawResult, command);
          if (redacted !== rawResult && outData) {
            outData['result'] = redacted;
          }
          return;
        }

        const readTools = ['Read', 'read'];
        if (readTools.includes(toolName)) {
          const args = data['args'] as Record<string, unknown> | undefined;
          const filePath = typeof args?.['filePath'] === 'string' ? args['filePath'] : '';
          const redacted = await routeReadAfter(rawResult, filePath);
          if (redacted !== rawResult && outData) {
            outData['result'] = redacted;
          }
          return;
        }

        if (toolName === 'Task' || toolName === 'task') {
          await routeTaskAfter(rawResult);
          return;
        }
      } catch (err) {
        logSecurityEvent('post_tool_use', 'allow', { extra: { error: String(err) } });
      }
    },

    'session.created': async (_input: unknown, _output: unknown) => {
      logSecurityEvent('session', 'allow', { sessionId, extra: { message: 'Session created' } });
      const result = await routeSessionStart();
      if (result?.systemMessage && client && typeof client === 'object' && 'session' in client) {
        const session = (client as Record<string, unknown>)['session'];
        if (session && typeof session === 'object' && 'prompt' in session) {
          const promptFn = (session as Record<string, unknown>)['prompt'];
          if (typeof promptFn === 'function') {
            try {
              promptFn.call(session, { noReply: true, parts: [{ type: 'text', text: result.systemMessage }] });
            } catch {
              // Context injection failure is non-critical
            }
          }
        }
      }
      return;
    },

    'session.deleted': async (_input: unknown, _output: unknown) => {
      await routeSessionEnd(sessionId);
      logSecurityEvent('session', 'allow', { sessionId, extra: { message: 'Session deleted' } });
      return;
    },

    'file.edited': async (input: unknown, _output: unknown) => {
      const data = input as Record<string, unknown>;
      const filePath = typeof data['filePath'] === 'string' ? data['filePath'] : '';
      if (!filePath) return;
      logSecurityEvent('file_edited', 'allow', { extra: { filePath } });
      return;
    },

    'command.executed': async (input: unknown, _output: unknown) => {
      const data = input as Record<string, unknown>;
      const command = typeof data['command'] === 'string' ? data['command'] : '';
      if (!command) return;
      logSecurityEvent('command_audit', 'allow', {
        sessionId,
        command,
        extra: { postFact: true },
      });
      return;
    },

    'experimental.session.compacting': async (_input: unknown, output: unknown) => {
      const ctx = output as Record<string, unknown> | undefined;
      if (ctx?.['context'] && Array.isArray(ctx['context'])) {
        logSecurityEvent('compacting', 'allow', { extra: { contextLength: ctx['context'].length } });
      }
      return;
    },

    'permission.asked': async (_input: unknown, _output: unknown) => {
      return;
    },

    'permission.replied': async (_input: unknown, _output: unknown) => {
      return;
    },
  };
};
