import { describe, expect, it } from 'vitest';
import {
  ABSURD_MULTIPLIER,
  KEYSPACE_TARGETS,
  RATE_FLOOR_PER_SECOND,
  SECONDS_PER_YEAR,
  bitsReachableIn,
  extrapolate,
  formatDuration,
  formatMultiplier,
  isAbsurdMultiplier,
  measureRate,
} from './rate';

describe('measured search rate', () => {
  it('divides the candidates the worker checked by the time that run took', () => {
    const rate = measureRate(65_536, 800);
    expect(rate.candidatesPerSecond).toBeCloseTo(81_920, 6);
    expect(rate.floored).toBe(false);
    expect(rate.timerLimited).toBe(false);
  });

  it('floors an unusably slow device and says it floored', () => {
    const rate = measureRate(1, 10_000);
    expect(rate.candidatesPerSecond).toBe(RATE_FLOOR_PER_SECOND);
    expect(rate.floored).toBe(true);
  });

  it('marks a rate the clock was too coarse to measure as a lower bound', () => {
    const rate = measureRate(2_048, 0);
    expect(rate.timerLimited).toBe(true);
    expect(rate.candidatesPerSecond).toBe(2_048_000);
  });

  it('refuses to invent a rate when nothing was searched', () => {
    expect(() => measureRate(0, 500)).toThrow(/at least one tested candidate/);
    expect(() => measureRate(10, -1)).toThrow(/non-negative elapsed time/);
  });
});

describe('extrapolation', () => {
  it('projects the measured rate onto a larger keyspace', () => {
    const projected = extrapolate(40, 1_000, 1);
    expect(projected.candidates).toBe(2 ** 40);
    expect(projected.seconds).toBeCloseTo(2 ** 40 / 1_000, 6);
    expect(projected.log2Seconds).toBeCloseTo(40 - Math.log2(1_000), 9);
  });

  it('divides the keyspace by rate times multiplier, not by either alone', () => {
    const single = extrapolate(80, 50_000, 1);
    const scaled = extrapolate(80, 50_000, 1e6);
    expect(scaled.effectiveRatePerSecond).toBe(5e10);
    expect(single.seconds / scaled.seconds).toBeCloseTo(1e6, 3);
  });

  it('stays finite across the whole axis the chart draws, up to 2^256', () => {
    for (const target of KEYSPACE_TARGETS) {
      const projected = extrapolate(target.bits, 80_000, 1);
      expect(Number.isFinite(projected.seconds)).toBe(true);
      expect(Number.isFinite(projected.log2Seconds)).toBe(true);
    }
    expect(Number.isFinite(extrapolate(256, 1, 1).seconds)).toBe(true);
  });

  it('rejects a rate or multiplier that would fabricate a number', () => {
    expect(() => extrapolate(32, 0, 1)).toThrow(/positive measured rate/);
    expect(() => extrapolate(32, 100, 0)).toThrow(/positive multiplier/);
    expect(() => extrapolate(32, 100, Number.NaN)).toThrow(/positive multiplier/);
  });

  it('labels a multiplier past the page’s declared line as absurd', () => {
    expect(isAbsurdMultiplier(ABSURD_MULTIPLIER)).toBe(true);
    expect(isAbsurdMultiplier(ABSURD_MULTIPLIER / 10)).toBe(false);
    expect(isAbsurdMultiplier(1e30)).toBe(true);
  });

  it('inverts cleanly: the bits a rate clears in a second round-trip', () => {
    const bits = bitsReachableIn(1, 65_536);
    expect(bits).toBeCloseTo(16, 9);
    expect(extrapolate(bits, 65_536, 1).seconds).toBeCloseTo(1, 9);
  });
});

describe('duration formatting', () => {
  it('scales from microseconds to scientific years', () => {
    expect(formatDuration(2e-6)).toMatch(/microseconds$/);
    expect(formatDuration(0.05)).toMatch(/milliseconds$/);
    expect(formatDuration(5)).toMatch(/seconds$/);
    expect(formatDuration(300)).toMatch(/minutes$/);
    expect(formatDuration(7_200)).toMatch(/hours$/);
    expect(formatDuration(86_400 * 3)).toMatch(/days$/);
    expect(formatDuration(SECONDS_PER_YEAR * 5)).toBe('5.00 years');
    expect(formatDuration(SECONDS_PER_YEAR * 1.5e40)).toBe('1.5 × 10^40 years');
  });

  it('never reports a duration it did not compute', () => {
    expect(formatDuration(0)).toBe('no measurable time');
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe('not finite');
  });

  it('says the real number below a microsecond rather than rounding it to zero', () => {
    // An absurd multiplier can push 2^32 here; "0.00 microseconds" would read as
    // "instant", which is a different claim from "very small".
    expect(formatDuration(6e-26)).toBe('6.0 × 10^-26 seconds');
    expect(formatDuration(1e-9)).toBe('1.0 × 10^-9 seconds');
    expect(formatDuration(5e-7)).toBe('5.0 × 10^-7 seconds');
    expect(formatDuration(2e-6)).toBe('2.00 microseconds');
  });

  it('writes multipliers as powers of ten', () => {
    expect(formatMultiplier(1)).toBe('×1');
    expect(formatMultiplier(1e9)).toBe('×10^9');
    expect(formatMultiplier(1e21)).toBe('×10^21');
  });

  it('still reads cleanly for the odd numbers a learner types', () => {
    // The multiplier field accepts anything; none of these are powers of ten.
    expect(formatMultiplier(2_500)).toBe('×2.5 × 10^3');
    expect(formatMultiplier(7.5e18)).toBe('×7.5 × 10^18');
    expect(formatMultiplier(64)).toBe('×64.0');
    expect(formatMultiplier(2.5)).toBe('×2.50');
  });
});
