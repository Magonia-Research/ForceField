export const MAX_STDIN_BYTES = 1_048_576;

export const DECISION_PRECEDENCE: Record<string, number> = {
  deny: 3,
  ask: 2,
  allow: 1,
};
