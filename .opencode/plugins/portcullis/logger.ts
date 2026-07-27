import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { randomUUID } from 'node:crypto';
import { execSync } from 'node:child_process';
import { createSocket, type Socket as DgramSocket } from 'node:dgram';

const SUBSYSTEM = 'com.opencode.portcullis';
const CATEGORY = 'security';
const SYSLOG_IDENT = 'oc-security';

const FALLBACK_LOG_DIR = join(homedir(), '.config', 'opencode', 'hooks');
const FALLBACK_LOG_FILE = join(FALLBACK_LOG_DIR, 'security.log');
const MAX_BYTES = 5 * 1024 * 1024;
const BACKUP_COUNT = 3;

interface SecurityEvent {
  Timestamp: string;
  ObservedTimestamp: number;
  SeverityNumber: number;
  SeverityText: string;
  EventName: string;
  Body: string;
  TraceId?: string;
  Attributes: Record<string, unknown>;
}

type Decision = 'deny' | 'block' | 'redact' | 'ask' | 'warn' | 'allow' | 'debug';

const SEV: Record<Decision, [number, string, string, number, number]> = {
  deny:   [17, 'ERROR', 'fault', 4, 2],
  block:  [17, 'ERROR', 'fault', 4, 2],
  redact: [15, 'WARN',  'error', 3, 1],
  ask:    [14, 'WARN',  'default', 3, 0],
  warn:   [13, 'WARN',  'default', 2, 1],
  allow:  [9,  'INFO',  'info', 1, 1],
  debug:  [5,  'DEBUG', 'debug', 1, 0],
};
const DEFAULT_SEV: typeof SEV['allow'] = [13, 'WARN', 'default', 3, 0];

const ATTR_RENAME: Record<string, string> = {
  tool: 'tool.name',
  suppressed: 'portcullis.suppressed',
};

let sessionId: string | null = null;
let syslogSocket: DgramSocket | null = null;

function severity(decision: string): [number, string, string, number, number] {
  return SEV[decision as Decision] ?? DEFAULT_SEV;
}

function initSessionId(): string {
  if (!sessionId) sessionId = randomUUID();
  return sessionId;
}

function rotateFile(filePath: string): void {
  try {
    for (let i = BACKUP_COUNT - 1; i >= 1; i--) {
      const src = `${filePath}.${i}`;
      const dst = `${filePath}.${i + 1}`;
      if (existsSync(src)) {
        renameSync(src, dst);
      }
    }
    if (existsSync(filePath)) {
      renameSync(filePath, `${filePath}.1`);
    }
  } catch {
    // Rotation failure is non-critical
  }
}

function writeJsonLines(event: SecurityEvent): void {
  try {
    mkdirSync(FALLBACK_LOG_DIR, { recursive: true });
    if (existsSync(FALLBACK_LOG_FILE)) {
      try {
        const st = statSync(FALLBACK_LOG_FILE);
        if (st.size >= MAX_BYTES) rotateFile(FALLBACK_LOG_FILE);
      } catch {
        // Stat failure, proceed with append
      }
    }
    const line = JSON.stringify(event, null, 0);
    appendFileSync(FALLBACK_LOG_FILE, line + '\n', 'utf-8');
  } catch {
    // File write failure is non-critical
  }
}

function emitMacosLog(message: string, macosType: string): void {
  try {
    execSync(
      `logger --syslog '${SUBSYSTEM}.${CATEGORY}' --level ${macosType.toUpperCase()} "${message.replace(/"/g, '\\"')}"`,
      { timeout: 2000, stdio: 'ignore' },
    );
  } catch {
    // macOS log failure is non-critical
  }
}

function getSyslogSocket(): DgramSocket | null {
  if (syslogSocket) return syslogSocket;
  try {
    const socket = createSocket('udp4');
    socket.unref();
    syslogSocket = socket;
    return socket;
  } catch {
    return null;
  }
}

function emitSyslog(message: string): void {
  try {
    const socket = getSyslogSocket();
    if (!socket) return;
    const syslogPath = existsSync('/var/run/syslog') ? '/var/run/syslog' : '/dev/log';
    const pri = '<28>';
    const payload = `${pri}${SYSLOG_IDENT}: ${message}`;
    socket.send(payload, 0, payload.length, 514, syslogPath);
  } catch {
    // Syslog failure is non-critical
  }
}

export function buildEvent(
  hookName: string,
  decision: string,
  opts: {
    patternMatched?: string | null;
    command?: string | null;
    filePath?: string | null;
    userResponse?: string | null;
    sessionId?: string | null;
    extra?: Record<string, unknown> | null;
  } = {},
): SecurityEvent {
  const [otelNum, otelText, _macosType, ocsfSev, ocsfAction] = severity(decision);

  const attributes: Record<string, unknown> = {
    'event.category': 'security',
    'event.kind': 'security_detection',
    'portcullis.guard': hookName,
    'portcullis.decision': decision,
  };

  if (opts.patternMatched) attributes['portcullis.pattern'] = opts.patternMatched;
  if (opts.command) attributes['command.line'] = opts.command;
  if (opts.filePath) attributes['file.path'] = opts.filePath;
  if (opts.userResponse) attributes['user.response'] = opts.userResponse;

  const sid = opts.sessionId ?? sessionId;
  if (sid) attributes['session.id'] = sid;

  if (opts.extra) {
    for (const [key, value] of Object.entries(opts.extra)) {
      attributes[ATTR_RENAME[key] ?? `portcullis.${key}`] = value;
    }
  }

  attributes['ocsf.category_uid'] = 2;
  attributes['ocsf.class_uid'] = 2004;
  attributes['ocsf.activity_id'] = 1;
  attributes['ocsf.type_uid'] = 200401;
  attributes['ocsf.severity_id'] = ocsfSev;
  attributes['ocsf.action_id'] = ocsfAction;

  let body = `${hookName}: ${decision}`;
  if (opts.patternMatched) body += ` (${opts.patternMatched})`;

  const event: SecurityEvent = {
    Timestamp: new Date().toISOString(),
    ObservedTimestamp: Date.now() * 1_000_000,
    SeverityNumber: otelNum,
    SeverityText: otelText,
    EventName: `portcullis.${hookName}`,
    Body: body,
    Attributes: attributes,
  };
  if (sid) event.TraceId = sid;
  return event;
}

export function logSecurityEvent(
  hookName: string,
  decision: string,
  opts: Parameters<typeof buildEvent>[2] = {},
): SecurityEvent {
  try {
    const event = buildEvent(hookName, decision, opts);
    const message = JSON.stringify(event);

    writeJsonLines(event);

    if (platform() === 'darwin') {
      emitMacosLog(message, SEV[decision as Decision]?.[2] ?? DEFAULT_SEV[2]);
    } else if (platform() === 'linux') {
      emitSyslog(message);
    }

    return event;
  } catch {
    return buildEvent(hookName, decision, opts);
  }
}

export function clampAndEmit(
  guardName: string,
  naturalDecision: string,
  reason: string,
  opts: {
    patternMatched?: string | null;
    command?: string | null;
    filePath?: string | null;
    sessionId?: string | null;
  } = {},
): string | null {
  const { effectiveDecision: effDec } = require('./config.js');
  const decision = effDec(guardName, naturalDecision);

  if (decision !== naturalDecision) {
    const merged: Parameters<typeof logSecurityEvent>[2] = { ...opts };
    merged.extra = { natural: naturalDecision, configDowngraded: true };
    logSecurityEvent(guardName, decision, merged);
  } else {
    logSecurityEvent(guardName, decision, opts);
  }

  if (decision === 'deny' || decision === 'ask') {
    return reason;
  }
  return null;
}

export function setSessionId(id: string): void {
  sessionId = id;
}

export function getSessionId(): string {
  return initSessionId();
}
