import { tea1ExpandIv, tea1Inner } from '../tea1/core';

export const MINIMUM_KNOWN_KEYSTREAM_BYTES = 4;

export interface RegisterSearchInput {
  frameNumber: number;
  targetKeystream: Uint8Array;
  startRegister: number;
  endRegisterExclusive: number;
}

export interface RegisterSearchResult {
  register: number;
  checked: number;
}

export function findRegisterInRange(input: RegisterSearchInput): RegisterSearchResult | null {
  const { frameNumber, targetKeystream, startRegister, endRegisterExclusive } = input;
  if (targetKeystream.length < MINIMUM_KNOWN_KEYSTREAM_BYTES) {
    throw new RangeError(
      `At least ${MINIMUM_KNOWN_KEYSTREAM_BYTES} known keystream bytes are required`,
    );
  }
  if (
    !Number.isSafeInteger(startRegister) ||
    !Number.isSafeInteger(endRegisterExclusive) ||
    startRegister < 0 ||
    endRegisterExclusive > 0x1_0000_0000 ||
    startRegister >= endRegisterExclusive
  ) {
    throw new RangeError('Search bounds must describe a non-empty 32-bit register range');
  }

  const expandedIv = tea1ExpandIv(frameNumber);
  let checked = 0;

  for (let candidate = startRegister; candidate < endRegisterExclusive; candidate += 1) {
    const candidateKeystream = tea1Inner(expandedIv, candidate, targetKeystream.length);
    checked += 1;

    if (candidateKeystream.every((byte, index) => byte === targetKeystream[index])) {
      return { register: candidate >>> 0, checked };
    }
  }

  return null;
}