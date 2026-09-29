import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  BRUTE_FORCE_LINES,
  PUBLISHED_ATTACKS,
  advantageBits,
  largestSingleKeyAdvantage,
  fastestIn,
} from './attacks';

describe('the sourced attack table', () => {
  it('gives every row a citation that names a primary paper and where in it', () => {
    for (const attack of PUBLISHED_ATTACKS) {
      expect(attack.citation.authors.length, attack.id).toBeGreaterThan(0);
      expect(attack.citation.title.length, attack.id).toBeGreaterThan(0);
      expect(attack.citation.venue.length, attack.id).toBeGreaterThan(0);
      expect(attack.citation.locator, attack.id).toMatch(/Table|Section|Abstract/);
      expect(attack.citation.url, attack.id).toMatch(/^https:\/\/eprint\.iacr\.org\//);
      expect(attack.citation.year, attack.id).toBeGreaterThanOrEqual(2009);
    }
  });

  it('carries an attack model, a goal, and time, data and memory for every row', () => {
    for (const attack of PUBLISHED_ATTACKS) {
      expect(['single-key', 'related-key'], attack.id).toContain(attack.model);
      expect(attack.modelDetail.length, attack.id).toBeGreaterThan(0);
      expect(attack.goal.length, attack.id).toBeGreaterThan(0);
      for (const value of [attack.log2Time, attack.log2Data, attack.log2Memory]) {
        expect(Number.isFinite(value), attack.id).toBe(true);
        expect(value, attack.id).toBeGreaterThan(0);
      }
    }
  });

  it('holds full-round key recovery only — reduced-round work is a different exhibit', () => {
    for (const attack of PUBLISHED_ATTACKS) {
      expect(attack.rounds, attack.id).toBe(attack.fullRounds);
    }
    expect(PUBLISHED_ATTACKS.map((attack) => attack.fullRounds)).toEqual(
      PUBLISHED_ATTACKS.map((attack) => ({ 128: 10, 192: 12, 256: 14 })[attack.keyBits]),
    );
  });

  it('keeps each row under its own brute-force line', () => {
    for (const attack of PUBLISHED_ATTACKS) {
      expect(attack.log2Time, attack.id).toBeLessThan(attack.keyBits);
      expect(advantageBits(attack), attack.id).toBeGreaterThan(0);
    }
  });

  it('plots every row against a brute-force line the chart actually draws', () => {
    const drawn = new Set(BRUTE_FORCE_LINES.map((line) => line.keyBits));
    for (const attack of PUBLISHED_ATTACKS) {
      expect(drawn.has(attack.keyBits), attack.id).toBe(true);
      expect(attack.target).toBe(`AES-${attack.keyBits}`);
    }
  });

  it('labels each complexity with the exponent the row plots', () => {
    for (const attack of PUBLISHED_ATTACKS) {
      const timeExponent = attack.timeLabel.match(/2\^([\d.]+)/)?.[1];
      expect(timeExponent, attack.id).toBeDefined();
      expect(Number(timeExponent), attack.id).toBeCloseTo(attack.log2Time, 6);

      const dataExponent = attack.dataLabel.match(/2\^([\d.]+)/)?.[1];
      if (dataExponent !== undefined) {
        expect(Number(dataExponent), attack.id).toBeCloseTo(attack.log2Data, 6);
      } else {
        // The minimum-data rows count pairs outright rather than as a power of two.
        const pairs = Number(attack.dataLabel.match(/^(\d+) known plaintexts$/)?.[1]);
        expect(Number.isFinite(pairs), attack.id).toBe(true);
        expect(2 ** attack.log2Data, attack.id).toBeCloseTo(pairs, 6);
      }

      const memoryExponent = attack.memoryLabel.match(/2\^([\d.]+)/)?.[1];
      expect(memoryExponent, attack.id).toBeDefined();
      expect(Number(memoryExponent), attack.id).toBeCloseTo(attack.log2Memory, 6);
    }
  });

  it('gives every row a unique id', () => {
    const ids = PUBLISHED_ATTACKS.map((attack) => attack.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('finds the best single-key advantage and the fastest row in each model', () => {
    const best = largestSingleKeyAdvantage();
    expect(best.model).toBe('single-key');
    // The most any published single-key attack buys over brute force: AES-192's
    // full-codebook biclique, and it is worth 2.49 bits.
    expect(best.id).toBe('biclique-2014-aes192-codebook');
    expect(advantageBits(best)).toBeCloseTo(192 - 189.51, 6);
    expect(advantageBits(best)).toBeLessThan(3);

    expect(fastestIn('single-key').log2Time).toBe(125.56);
    expect(fastestIn('related-key').log2Time).toBe(92);
  });

  it('keeps a related-key row far below what any single-key row reaches', () => {
    const singleKeyFloor = Math.min(
      ...PUBLISHED_ATTACKS.filter((attack) => attack.model === 'single-key').map(
        (attack) => attack.keyBits - attack.log2Time,
      ),
    );
    const relatedKeyBest = Math.max(
      ...PUBLISHED_ATTACKS.filter((attack) => attack.model === 'related-key').map(advantageBits),
    );
    expect(relatedKeyBest).toBeGreaterThan(singleKeyFloor);
    expect(relatedKeyBest).toBeGreaterThan(100);
  });

  it('agrees with the counts and figures the README states in prose', () => {
    // Hand-authored prose against the computed value: the README quotes both of
    // these, and a row added or removed here should break that sentence loudly
    // rather than leaving the README quietly wrong.
    const readme = readFileSync(new URL('../../README.md', import.meta.url), 'utf-8');
    const words: Record<number, string> = {
      11: 'eleven',
      12: 'twelve',
      13: 'thirteen',
      14: 'fourteen',
      15: 'fifteen',
    };
    expect(readme).toContain(`${words[PUBLISHED_ATTACKS.length]} published key-recovery attacks`);
    expect(readme).toContain(
      `is ${advantageBits(largestSingleKeyAdvantage()).toFixed(2)} bits faster than brute force`,
    );
  });
});
