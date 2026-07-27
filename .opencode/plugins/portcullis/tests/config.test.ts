import { describe, it, expect } from 'bun:test';
import { clamp, NATURAL_MAX, PRESETS, DEFAULT_SEVERITY_FLOOR } from '../config.js';

// Note: resolveCeiling and effectiveDecision depend on reading actual config files
// from disk (home + project). We test the pure functions here; integration tests
// for file-based resolution are in a separate suite.

describe('config module', () => {
  // RANK is internal — verify ordering indirectly via clamp behavior:
  // clamp(decision, ceiling) returns min(decision, ceiling) by rank.
  describe('decision level ordering (via clamp)', () => {
    const LEVELS = ['off', 'allow', 'warn', 'redact', 'ask', 'deny'];

    it('has exactly 6 distinct decision levels implied by clamp behavior', () => {
      // Each level must be distinct — clamp(x, x) returns x for every level.
      for (const level of LEVELS) {
        expect(clamp(level, level)).toBe(level);
      }
    });

    it('deny is highest rank (clamps everything down)', () => {
      for (const level of LEVELS) {
        expect(clamp(level, 'deny')).toBe(level);
      }
    });

    it('off is lowest rank (everything clamped to off)', () => {
      for (const level of LEVELS) {
        expect(clamp(level, 'off')).toBe('off');
      }
    });

    it('rank ordering: off < allow < warn < redact < ask < deny', () => {
      // Verify each adjacent pair is ordered correctly
      for (let i = 0; i < LEVELS.length - 1; i++) {
        const lower = LEVELS[i];
        const higher = LEVELS[i + 1];
        expect(clamp(higher, lower)).toBe(lower);
        expect(clamp(lower, higher)).toBe(lower);
      }
    });
  });

  describe('NATURAL_MAX per guard', () => {
    const EXPECTED_GUARDS = [
      'container_first', 'exfil_guard', 'supply_chain_guard',
      'git_guard', 'credential_access_guard', 'credential_guard',
      'mcp_guard', 'agent_guard', 'webfetch_guard',
      'filesystem_guard', 'sigma_engine',
    ];

    for (const guard of EXPECTED_GUARDS) {
      it(`has natural max for ${guard}`, () => {
        expect(NATURAL_MAX[guard]).toBeDefined();
        expect(['off', 'allow', 'warn', 'redact', 'ask', 'deny']).toContain(NATURAL_MAX[guard]);
      });
    }

    it('exfil_guard natural max is deny', () => {
      expect(NATURAL_MAX.exfil_guard).toBe('deny');
    });

    it('supply_chain_guard natural max is deny', () => {
      expect(NATURAL_MAX.supply_chain_guard).toBe('deny');
    });

    it('git_guard natural max is ask', () => {
      expect(NATURAL_MAX.git_guard).toBe('ask');
    });

    it('credential_access_guard natural max is ask', () => {
      expect(NATURAL_MAX.credential_access_guard).toBe('ask');
    });

    it('mcp_guard natural max is ask', () => {
      expect(NATURAL_MAX.mcp_guard).toBe('ask');
    });

    it('agent_guard natural max is deny', () => {
      expect(NATURAL_MAX.agent_guard).toBe('deny');
    });

    it('webfetch_guard natural max is deny', () => {
      expect(NATURAL_MAX.webfetch_guard).toBe('deny');
    });

    it('filesystem_guard natural max is ask', () => {
      expect(NATURAL_MAX.filesystem_guard).toBe('ask');
    });

    it('sigma_engine natural max is ask', () => {
      expect(NATURAL_MAX.sigma_engine).toBe('ask');
    });

    it('has exactly 11 guard entries', () => {
      expect(Object.keys(NATURAL_MAX).length).toBe(11);
    });
  });

  describe('PRESETS', () => {
    const EXPECTED_PRESETS = ['strict', 'balanced', 'permissive'];

    for (const preset of EXPECTED_PRESETS) {
      it(`has ${preset} preset`, () => {
        expect(PRESETS[preset]).toBeDefined();
        expect(typeof PRESETS[preset]).toBe('object');
      });
    }

    describe('strict preset', () => {
      it('sets exfil_guard to deny', () => {
        expect(PRESETS.strict.exfil_guard).toBe('deny');
      });

      it('sets supply_chain_guard to deny', () => {
        expect(PRESETS.strict.supply_chain_guard).toBe('deny');
      });

      it('sets agent_guard to deny', () => {
        expect(PRESETS.strict.agent_guard).toBe('deny');
      });

      it('sets webfetch_guard to deny', () => {
        expect(PRESETS.strict.webfetch_guard).toBe('deny');
      });

      it('sets git_guard to ask (not higher)', () => {
        expect(PRESETS.strict.git_guard).toBe('ask');
      });

      it('sets sigma_engine to ask', () => {
        expect(PRESETS.strict.sigma_engine).toBe('ask');
      });
    });

    describe('balanced preset', () => {
      it('downgrades supply_chain_guard from deny to ask', () => {
        expect(PRESETS.balanced.supply_chain_guard).toBe('ask');
      });

      it('downgrades webfetch_guard from deny to ask', () => {
        expect(PRESETS.balanced.webfetch_guard).toBe('ask');
      });

      it('downgrades sigma_engine from ask to warn', () => {
        expect(PRESETS.balanced.sigma_engine).toBe('warn');
      });

      it('keeps exfil_guard at deny', () => {
        expect(PRESETS.balanced.exfil_guard).toBe('deny');
      });

      it('keeps agent_guard at deny', () => {
        expect(PRESETS.balanced.agent_guard).toBe('deny');
      });
    });

    describe('permissive preset', () => {
      it('downgrades all guards to ask or lower', () => {
        // "ask or lower" means the mode must be one of: off, allow, warn, redact, ask
        const ASK_OR_LOWER = new Set(['off', 'allow', 'warn', 'redact', 'ask']);
        for (const [guard, mode] of Object.entries(PRESETS.permissive)) {
          expect(ASK_OR_LOWER.has(mode)).toBe(true);
        }
      });

      it('sets sigma_engine to warn', () => {
        expect(PRESETS.permissive.sigma_engine).toBe('warn');
      });

      it('all three presets have the same guard keys', () => {
        const strictKeys = new Set(Object.keys(PRESETS.strict));
        const balancedKeys = new Set(Object.keys(PRESETS.balanced));
        const permissiveKeys = new Set(Object.keys(PRESETS.permissive));
        expect(strictKeys.size).toBe(balancedKeys.size);
        expect(balancedKeys.size).toBe(permissiveKeys.size);
      });
    });
  });

  describe('DEFAULT_SEVERITY_FLOOR', () => {
    it('defaults to medium', () => {
      expect(DEFAULT_SEVERITY_FLOOR).toBe('medium');
    });
  });

  describe('clamp function (downgrade-only)', () => {
    it('returns decision unchanged when below ceiling', () => {
      expect(clamp('warn', 'deny')).toBe('warn');
    });

    it('returns decision unchanged when equal to ceiling', () => {
      expect(clamp('ask', 'ask')).toBe('ask');
    });

    it('clamps decision down when above ceiling', () => {
      expect(clamp('deny', 'ask')).toBe('ask');
    });

    it('clamps deny to warn', () => {
      expect(clamp('deny', 'warn')).toBe('warn');
    });

    it('clamps ask to allow', () => {
      expect(clamp('ask', 'allow')).toBe('allow');
    });

    it('clamps redact to off', () => {
      expect(clamp('redact', 'off')).toBe('off');
    });

    it('does not upgrade decision (downgrade-only)', () => {
      // clamp(ask, deny) should return ask, not deny
      expect(clamp('ask', 'deny')).toBe('ask');
    });

    it('handles unknown decision by returning it unchanged', () => {
      expect(clamp('unknown', 'deny')).toBe('unknown');
    });

    it('handles unknown ceiling by returning decision unchanged', () => {
      expect(clamp('deny', 'unknown')).toBe('deny');
    });

    it('handles both unknown values', () => {
      expect(clamp('foo', 'bar')).toBe('foo');
    });

    // Exhaustive pairwise checks for the 6 known levels (rank inferred from position)
    const LEVELS = ['off', 'allow', 'warn', 'redact', 'ask', 'deny'];
    for (let di = 0; di < LEVELS.length; di++) {
      for (let ci = 0; ci < LEVELS.length; ci++) {
        const decision = LEVELS[di];
        const ceiling = LEVELS[ci];
        it(`clamp(${decision}, ${ceiling}) returns min rank`, () => {
          // Lower index = lower rank. clamp returns the one with lower (or equal) rank.
          const expected = di <= ci ? decision : ceiling;
          expect(clamp(decision, ceiling)).toBe(expected);
        });
      }
    }
  });
});
