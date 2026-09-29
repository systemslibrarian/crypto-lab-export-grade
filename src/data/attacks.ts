// Exhibit 6's single sourced data file.
//
// EVERY row below was read out of the primary paper's own summary table, not out
// of a survey, a Wikipedia entry, or anybody's memory. The `locator` field names
// the table the numbers came from so a reader can check the row against the PDF.
// Where two papers restate each other's figure differently, each row carries the
// figure ITS OWN paper prints — see the note on BICLIQUE_2011_AES128.
//
// Scope: key recovery against the FULL round count only. Reduced-round results
// are the security-margin view, which crypto-lab-iron-serpent already owns.

export interface Citation {
  authors: string;
  title: string;
  venue: string;
  year: number;
  url: string;
  /** Which table or section inside that paper these numbers were read from. */
  locator: string;
}

export type AttackModel = 'single-key' | 'related-key';

export interface PublishedAttack {
  id: string;
  target: 'AES-128' | 'AES-192' | 'AES-256';
  /** Nominal key length, and the brute-force line this row is plotted against. */
  keyBits: 128 | 192 | 256;
  /** Rounds attacked, which for every row here equals the cipher's full count. */
  rounds: number;
  fullRounds: number;
  attack: string;
  model: AttackModel;
  /** What the model costs the attacker in reality: related keys, weak-key class. */
  modelDetail: string;
  goal: string;
  log2Time: number;
  timeLabel: string;
  log2Data: number;
  dataLabel: string;
  log2Memory: number;
  memoryLabel: string;
  citation: Citation;
  note?: string;
}

const BOGDANOV_2011: Citation = {
  authors: 'Andrey Bogdanov, Dmitry Khovratovich, Christian Rechberger',
  title: 'Biclique Cryptanalysis of the Full AES',
  venue: 'ASIACRYPT 2011 (full version, IACR ePrint 2011/449)',
  year: 2011,
  url: 'https://eprint.iacr.org/2011/449',
  locator: 'Table 1, "Biclique key recovery for AES"',
};

const BOGDANOV_2014: Citation = {
  authors: 'Andrey Bogdanov, Donghoon Chang, Mohona Ghosh, Somitra Kumar Sanadhya',
  title: 'Bicliques with Minimal Data and Time Complexity for AES',
  venue: 'ICISC 2014 (extended version, IACR ePrint 2014/932)',
  year: 2014,
  url: 'https://eprint.iacr.org/2014/932',
  locator: 'Table 1, "Key recovery with bicliques for full AES"',
};

const BIRYUKOV_2009: Citation = {
  authors: 'Alex Biryukov, Dmitry Khovratovich',
  title: 'Related-key Cryptanalysis of the Full AES-192 and AES-256',
  venue: 'ASIACRYPT 2009 (IACR ePrint 2009/317)',
  year: 2009,
  url: 'https://eprint.iacr.org/2009/317',
  locator: 'Table 1, "Best attacks on AES-192 and AES-256"',
};

const BIRYUKOV_NIKOLIC_2009: Citation = {
  authors: 'Alex Biryukov, Dmitry Khovratovich, Ivica Nikolić',
  title: 'Distinguisher and Related-Key Attack on the Full AES-256',
  venue: 'CRYPTO 2009 (extended version, IACR ePrint 2009/241)',
  year: 2009,
  url: 'https://eprint.iacr.org/2009/241',
  locator: 'Abstract and Table 1, "Best attacks on AES-256"',
};

const GUO_2022: Citation = {
  authors: 'Jian Guo, Ling Song, Haoyang Wang',
  title: 'Key Structures: Improved Related-Key Boomerang Attack against the Full AES-256',
  venue: 'ACISP 2022 (IACR ePrint 2022/845)',
  year: 2022,
  url: 'https://eprint.iacr.org/2022/845',
  locator: 'Table 1, "Comparison with previous key-recovery attacks on full AES-256"',
};

export const PUBLISHED_ATTACKS: PublishedAttack[] = [
  {
    id: 'biclique-2011-aes128',
    target: 'AES-128',
    keyBits: 128,
    rounds: 10,
    fullRounds: 10,
    attack: 'Biclique (independent-biclique)',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success rate 1.',
    goal: 'Secret key recovery',
    log2Time: 126.18,
    timeLabel: '2^126.18 computations',
    log2Data: 88,
    dataLabel: '2^88 chosen ciphertexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2011,
    note: 'The paper’s abstract rounds this to 2^126.1; its Table 1 prints 2^126.18, and the table is what this row quotes.',
  },
  {
    id: 'biclique-2011-aes192',
    target: 'AES-192',
    keyBits: 192,
    rounds: 12,
    fullRounds: 12,
    attack: 'Biclique (independent-biclique)',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success rate 1.',
    goal: 'Secret key recovery',
    log2Time: 189.74,
    timeLabel: '2^189.74 computations',
    log2Data: 80,
    dataLabel: '2^80 chosen ciphertexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2011,
  },
  {
    id: 'biclique-2011-aes256',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Biclique (independent-biclique)',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success rate 1.',
    goal: 'Secret key recovery',
    log2Time: 254.42,
    timeLabel: '2^254.42 computations',
    log2Data: 40,
    dataLabel: '2^40 chosen ciphertexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2011,
    note: 'The 2014 paper below re-estimates this same attack at 2^254.52 in its Section 6.3 footnote.',
  },
  {
    id: 'biclique-2014-aes128-min-data',
    target: 'AES-128',
    keyBits: 128,
    rounds: 10,
    fullRounds: 10,
    attack: 'Biclique at the unicity distance',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success probability 1.',
    goal: 'Secret key recovery, minimum data',
    log2Time: 126.67,
    timeLabel: '2^126.67 computations',
    log2Data: 1,
    dataLabel: '2 known plaintexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
    note: 'The row that answers "but the data is impossible": strip the data to two known plaintexts and the time barely moves.',
  },
  {
    id: 'biclique-2014-aes192-min-data',
    target: 'AES-192',
    keyBits: 192,
    rounds: 12,
    fullRounds: 12,
    attack: 'Biclique at the unicity distance',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success probability 1.',
    goal: 'Secret key recovery, minimum data',
    log2Time: 190.9,
    timeLabel: '2^190.9 computations',
    log2Data: 1,
    dataLabel: '2 known plaintexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
  },
  {
    id: 'biclique-2014-aes256-min-data',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Biclique at the unicity distance',
    model: 'single-key',
    modelDetail: 'No related keys assumed. Success probability 1.',
    goal: 'Secret key recovery, minimum data',
    log2Time: 255,
    timeLabel: '2^255 computations',
    log2Data: Math.log2(3),
    dataLabel: '3 known plaintexts',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
  },
  {
    id: 'biclique-2014-aes128-codebook',
    target: 'AES-128',
    keyBits: 128,
    rounds: 10,
    fullRounds: 10,
    attack: 'Biclique with the full codebook',
    model: 'single-key',
    modelDetail: 'No related keys assumed, but every plaintext-ciphertext pair is required.',
    goal: 'Secret key recovery, fastest known',
    log2Time: 125.56,
    timeLabel: '2^125.56 computations',
    log2Data: 128,
    dataLabel: '2^128 (the entire codebook)',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
    note: 'The fastest published single-key attack on full AES-128, and it costs the whole codebook to get there.',
  },
  {
    id: 'biclique-2014-aes192-codebook',
    target: 'AES-192',
    keyBits: 192,
    rounds: 12,
    fullRounds: 12,
    attack: 'Biclique with the full codebook',
    model: 'single-key',
    modelDetail: 'No related keys assumed, but every plaintext-ciphertext pair is required.',
    goal: 'Secret key recovery, fastest known',
    log2Time: 189.51,
    timeLabel: '2^189.51 computations',
    log2Data: 128,
    dataLabel: '2^128 (the entire codebook)',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
  },
  {
    id: 'biclique-2014-aes256-codebook',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Biclique with the full codebook',
    model: 'single-key',
    modelDetail: 'No related keys assumed, but every plaintext-ciphertext pair is required.',
    goal: 'Secret key recovery, fastest known',
    log2Time: 253.87,
    timeLabel: '2^253.87 computations',
    log2Data: 128,
    dataLabel: '2^128 (the entire codebook)',
    log2Memory: 8,
    memoryLabel: '2^8',
    citation: BOGDANOV_2014,
  },
  {
    id: 'related-key-2009-aes192',
    target: 'AES-192',
    keyBits: 192,
    rounds: 12,
    fullRounds: 12,
    attack: 'Related-key amplified boomerang',
    model: 'related-key',
    modelDetail: 'Requires 4 keys related by differences the attacker chooses.',
    goal: 'Secret key recovery',
    log2Time: 176,
    timeLabel: '2^176',
    log2Data: 123,
    dataLabel: '2^123',
    log2Memory: 152,
    memoryLabel: '2^152',
    citation: BIRYUKOV_2009,
  },
  {
    id: 'related-key-2009-aes256',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Related-key boomerang',
    model: 'related-key',
    modelDetail: 'Requires 4 keys related by differences the attacker chooses. Works for all keys.',
    goal: 'Secret key recovery',
    log2Time: 99.5,
    timeLabel: '2^99.5',
    log2Data: 99.5,
    dataLabel: '2^99.5',
    log2Memory: 77,
    memoryLabel: '2^77',
    citation: BIRYUKOV_2009,
    note: 'Far below 2^256 — and unreachable, because no protocol hands an attacker four chosen-difference keys.',
  },
  {
    id: 'related-key-2009-aes256-weak',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Related-key differential',
    model: 'related-key',
    modelDetail: 'Works for one key in 2^35; the 2^96 figures are per key.',
    goal: 'Secret key recovery',
    log2Time: 131,
    timeLabel: '2^131 total',
    log2Data: 96,
    dataLabel: '2^96 per key',
    log2Memory: 65,
    memoryLabel: '2^65',
    citation: BIRYUKOV_NIKOLIC_2009,
    note: 'The first published attack on full AES-256, and it only applies to a weak-key class.',
  },
  {
    id: 'key-structure-2022-aes256',
    target: 'AES-256',
    keyBits: 256,
    rounds: 14,
    fullRounds: 14,
    attack: 'Key-structure boomerang',
    model: 'related-key',
    modelDetail: 'Requires 2^19 related keys — the price paid for the lower time.',
    goal: 'Secret key recovery',
    log2Time: 92,
    timeLabel: '2^92',
    log2Data: 91,
    dataLabel: '2^91',
    log2Memory: 89,
    memoryLabel: '2^89',
    citation: GUO_2022,
    note: 'Table 1 row at s = 0. The abstract states the data and time figures in the opposite order; Table 1 and Section 4 agree with each other and are what this row quotes.',
  },
];

/** The brute-force lines Exhibit 6 plots every attack against. */
export const BRUTE_FORCE_LINES: { keyBits: 128 | 192 | 256; label: string }[] = [
  { keyBits: 128, label: 'AES-128 brute force' },
  { keyBits: 192, label: 'AES-192 brute force' },
  { keyBits: 256, label: 'AES-256 brute force' },
];

/** How far under its own brute-force line a published attack sits, in bits. */
export function advantageBits(attack: PublishedAttack): number {
  return attack.keyBits - attack.log2Time;
}

/**
 * The single-key row that beats brute force by the most bits. That best case is
 * the sharpest form of "academically broken": it is still only a couple of bits.
 */
export function largestSingleKeyAdvantage(): PublishedAttack {
  const singleKey = PUBLISHED_ATTACKS.filter((attack) => attack.model === 'single-key');
  return singleKey.reduce((best, attack) =>
    advantageBits(attack) > advantageBits(best) ? attack : best,
  );
}

/** The lowest published time against full AES in a given model. */
export function fastestIn(model: AttackModel): PublishedAttack {
  const rows = PUBLISHED_ATTACKS.filter((attack) => attack.model === model);
  return rows.reduce((best, attack) => (attack.log2Time < best.log2Time ? attack : best));
}
