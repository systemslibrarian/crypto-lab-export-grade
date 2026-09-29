// Exhibit 5 arithmetic. Nothing here searches anything: it divides the count the
// Exhibit 3 worker already reports by the time that same run already took, then
// projects that one number across larger keyspaces. Every result is an
// extrapolation and the UI is required to say so.

/** Julian year, the length NIST and IAU use for "year". */
export const SECONDS_PER_YEAR = 31_557_600;

/**
 * Below one candidate per second an extrapolation stops meaning anything, so the
 * rate is floored here and the UI labels the floor. A device this slow is the
 * edge case, not the norm.
 */
export const RATE_FLOOR_PER_SECOND = 1;

/**
 * `performance.now()` is deliberately coarsened in browsers. A run that reports
 * less than this did not measure a rate so much as hit the clock's resolution,
 * so the quoted rate becomes a lower bound and says so.
 */
export const TIMER_FLOOR_MS = 1;

/**
 * This page's own editorial line, not a measurement and not a physical constant:
 * a scale-up assuming more than 10^21 parallel engines is labelled absurd rather
 * than quietly rendered as though someone could build it.
 */
export const ABSURD_MULTIPLIER = 1e21;

export interface RateMeasurement {
  /** Candidates the worker actually tested. */
  checked: number;
  /** Milliseconds that run spent inside the search loop. */
  elapsedMs: number;
  /** checked / (elapsedMs / 1000), after the floors below are applied. */
  candidatesPerSecond: number;
  /** True when the raw rate fell under RATE_FLOOR_PER_SECOND and was clamped up. */
  floored: boolean;
  /** True when elapsedMs fell under the clock's resolution, making the rate a lower bound. */
  timerLimited: boolean;
}

/**
 * Turn one finished (or cancelled) Exhibit 3 run into the single rate this lab
 * quotes. Throws rather than inventing a number when nothing was searched.
 */
export function measureRate(checked: number, elapsedMs: number): RateMeasurement {
  if (!Number.isFinite(checked) || checked <= 0) {
    throw new RangeError('A rate needs at least one tested candidate');
  }
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) {
    throw new RangeError('A rate needs a non-negative elapsed time');
  }

  const timerLimited = elapsedMs < TIMER_FLOOR_MS;
  const seconds = Math.max(elapsedMs, TIMER_FLOOR_MS) / 1000;
  const raw = checked / seconds;
  const floored = raw < RATE_FLOOR_PER_SECOND;

  return {
    checked,
    elapsedMs,
    candidatesPerSecond: floored ? RATE_FLOOR_PER_SECOND : raw,
    floored,
    timerLimited,
  };
}

export interface ScaleTier {
  id: string;
  label: string;
  /** What the learner is assuming when they pick this tier. Editable, never asserted. */
  assumption: string;
  defaultMultiplier: number;
}

/**
 * Three named scale-ups. Every multiplier is a starting point the learner edits,
 * and the copy that ships with each one describes it as an assumption.
 */
export const SCALE_TIERS: ScaleTier[] = [
  {
    id: 'browser',
    label: 'This browser',
    assumption: 'One tab on this machine — the run you measured, multiplied by nothing.',
    defaultMultiplier: 1,
  },
  {
    id: 'farm',
    label: 'A GPU farm',
    assumption:
      'Assume engines this many times faster in total than this tab. Pick the number yourself; the page does not know what hardware you mean.',
    defaultMultiplier: 1e9,
  },
  {
    id: 'global',
    label: 'An implausible global effort',
    assumption:
      'Assume a total speed-up nobody has built or budgeted. The number is yours to set, and the page will say when you have set an absurd one.',
    defaultMultiplier: 1e15,
  },
];

export interface KeyspaceTarget {
  bits: number;
  label: string;
  detail: string;
  /** Set on the two targets this lab measured or is labelled with. */
  thisLab?: 'measured' | 'labelled';
}

/** The log2 axis for Exhibit 5, smallest keyspace first. */
export const KEYSPACE_TARGETS: KeyspaceTarget[] = [
  {
    bits: 32,
    label: 'TEA1 effective register',
    detail: 'What Exhibit 2 computes and Exhibit 3 searches a window of.',
    thisLab: 'measured',
  },
  {
    bits: 40,
    label: 'Eight bits further',
    detail: 'Two hundred and fifty-six times the register, and nothing else changed.',
  },
  { bits: 56, label: 'DES key length', detail: 'The key length FIPS 46-3 specified for DES.' },
  {
    bits: 80,
    label: 'TEA1 key on the label',
    detail: 'The ten key bytes the cipher accepts before initialization discards their entropy.',
    thisLab: 'labelled',
  },
  { bits: 128, label: 'AES-128 key', detail: 'Exhibit 6 plots the published attacks against this line.' },
  { bits: 256, label: 'AES-256 key', detail: 'The largest AES key size.' },
];

export interface Extrapolation {
  bits: number;
  /** 2^bits — the candidate count, exact as a double through 2^256. */
  candidates: number;
  /** Effective rate after the learner's multiplier. */
  effectiveRatePerSecond: number;
  seconds: number;
  /** log2 of the wall-clock seconds; the position the chart plots. */
  log2Seconds: number;
}

/**
 * candidates / (measured rate x assumed multiplier). The UI prints this formula
 * beside the chart, because an extrapolation whose arithmetic is hidden is a claim.
 */
export function extrapolate(
  bits: number,
  candidatesPerSecond: number,
  multiplier: number,
): Extrapolation {
  if (!Number.isFinite(candidatesPerSecond) || candidatesPerSecond <= 0) {
    throw new RangeError('Extrapolation needs a positive measured rate');
  }
  if (!Number.isFinite(multiplier) || multiplier <= 0) {
    throw new RangeError('Extrapolation needs a positive multiplier');
  }

  const candidates = 2 ** bits;
  const effectiveRatePerSecond = candidatesPerSecond * multiplier;
  const seconds = candidates / effectiveRatePerSecond;

  return {
    bits,
    candidates,
    effectiveRatePerSecond,
    seconds,
    log2Seconds: Math.log2(seconds),
  };
}

/** Is this multiplier past the page's declared absurdity line? */
export function isAbsurdMultiplier(multiplier: number): boolean {
  return Number.isFinite(multiplier) && multiplier >= ABSURD_MULTIPLIER;
}

/**
 * The keyspace this rate clears in exactly `seconds`. Drawn on the chart as the
 * learner's own one-second and one-year marks, so the chart reads as cost rather
 * than as a picture of exponents.
 */
export function bitsReachableIn(seconds: number, ratePerSecond: number): number {
  return Math.log2(seconds * ratePerSecond);
}

const SCALES: { limit: number; divisor: number; unit: string }[] = [
  { limit: 1e-3, divisor: 1e-6, unit: 'microseconds' },
  { limit: 1, divisor: 1e-3, unit: 'milliseconds' },
  { limit: 60, divisor: 1, unit: 'seconds' },
  { limit: 3_600, divisor: 60, unit: 'minutes' },
  { limit: 86_400, divisor: 3_600, unit: 'hours' },
  { limit: SECONDS_PER_YEAR, divisor: 86_400, unit: 'days' },
];

function significant(value: number): string {
  if (value >= 100) return value.toFixed(0);
  if (value >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

/**
 * A duration string that stays readable from microseconds to 10^60 years. Above
 * a thousand years it switches to scientific notation rather than printing a
 * number nobody can read.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'not finite';
  if (seconds <= 0) return 'no measurable time';

  // An absurd multiplier can drive a duration below a microsecond, where
  // "0.00 microseconds" would read as zero. Say the actual number instead.
  if (seconds < 1e-6) {
    const exponent = Math.floor(Math.log10(seconds));
    return `${(seconds / 10 ** exponent).toFixed(1)} × 10^${exponent} seconds`;
  }

  for (const scale of SCALES) {
    if (seconds < scale.limit) return `${significant(seconds / scale.divisor)} ${scale.unit}`;
  }

  const years = seconds / SECONDS_PER_YEAR;
  if (years < 1_000) return `${significant(years)} years`;

  const exponent = Math.floor(Math.log10(years));
  const mantissa = years / 10 ** exponent;
  return `${mantissa.toFixed(1)} × 10^${exponent} years`;
}

/** "1e9" is unreadable in a sentence; "10^9" is not. */
export function formatMultiplier(multiplier: number): string {
  if (multiplier === 1) return '×1';
  const exponent = Math.log10(multiplier);
  if (Number.isInteger(exponent) && Math.abs(exponent) >= 3) return `×10^${exponent}`;
  if (multiplier >= 1_000) return `×${multiplier.toExponential(1).replace('e+', ' × 10^')}`;
  return `×${significant(multiplier)}`;
}
