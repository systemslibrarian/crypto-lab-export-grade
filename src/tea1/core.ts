// Copyright 2023, Midnight Blue.
// Licensed under the Apache License, Version 2.0.
// Modified into TypeScript for crypto-lab-export-grade.

import { TEA1_LUT_A, TEA1_LUT_B, TEA1_SBOX } from './constants';
import { tea1InitKeyRegister } from './keyload';

export interface Tea1IvState {
  high: number;
  low: number;
}

export function tea1ExpandIv(shortIv: number): Tea1IvState {
  const frame = shortIv >>> 0;
  const xored = (frame ^ 0x96724fa1) >>> 0;
  const rotated = ((xored << 8) | (xored >>> 24)) >>> 0;

  return {
    high: ((frame >>> 8) | (rotated << 24)) >>> 0,
    low: ((rotated >>> 8) | (frame << 24)) >>> 0,
  };
}

export function tea1StateWordToNewByte(stateWord: number, lookup: Uint16Array): number {
  let stateByte0 = stateWord & 0xff;
  let stateByte1 = (stateWord >>> 8) & 0xff;
  let output = 0;

  for (let index = 0; index < 8; index += 1) {
    const distance =
      ((stateByte0 >>> 7) & 1) |
      ((stateByte0 << 1) & 2) |
      ((stateByte1 << 1) & 12);
    if ((lookup[index] & (1 << distance)) !== 0) {
      output |= 1 << index;
    }

    stateByte0 = ((stateByte0 >>> 1) | (stateByte0 << 7)) & 0xff;
    stateByte1 = ((stateByte1 >>> 1) | (stateByte1 << 7)) & 0xff;
  }

  return output;
}

export function tea1ReorderStateByte(stateByte: number): number {
  let output = 0;
  output |= (stateByte << 6) & 0x40;
  output |= (stateByte << 1) & 0x20;
  output |= (stateByte << 2) & 0x08;
  output |= (stateByte >>> 3) & 0x14;
  output |= (stateByte >>> 2) & 0x01;
  output |= (stateByte >>> 5) & 0x02;
  output |= (stateByte << 4) & 0x80;
  return output;
}

export function tea1Inner(
  initialIv: Tea1IvState,
  initialKeyRegister: number,
  keystreamLength: number,
): Uint8Array {
  if (!Number.isSafeInteger(keystreamLength) || keystreamLength < 0) {
    throw new RangeError('Keystream length must be a non-negative safe integer');
  }

  const keystream = new Uint8Array(keystreamLength);
  let ivHigh = initialIv.high >>> 0;
  let ivLow = initialIv.low >>> 0;
  let keyRegister = initialKeyRegister >>> 0;
  let skipRounds = 54;

  for (let byteIndex = 0; byteIndex < keystreamLength; byteIndex += 1) {
    for (let round = 0; round < skipRounds; round += 1) {
      const sboxOutput = TEA1_SBOX[((keyRegister >>> 24) ^ keyRegister) & 0xff];
      keyRegister = ((keyRegister << 8) | sboxOutput) >>> 0;

      const derivedByte12 = tea1StateWordToNewByte((ivLow >>> 8) & 0xffff, TEA1_LUT_A);
      const derivedByte56 = tea1StateWordToNewByte((ivHigh >>> 8) & 0xffff, TEA1_LUT_B);
      const reorderedByte4 = tea1ReorderStateByte(ivHigh & 0xff);
      const newByte = (derivedByte56 ^ (ivHigh >>> 24) ^ reorderedByte4 ^ sboxOutput) & 0xff;

      ivHigh = (((ivHigh << 8) | (ivLow >>> 24)) ^ derivedByte12) >>> 0;
      ivLow = ((ivLow << 8) | newByte) >>> 0;
    }

    keystream[byteIndex] = ivHigh >>> 24;
    skipRounds = 19;
  }

  return keystream;
}

export function tea1(frameNumber: number, key: Uint8Array, keystreamLength: number): Uint8Array {
  return tea1Inner(tea1ExpandIv(frameNumber), tea1InitKeyRegister(key), keystreamLength);
}

// [extension] A TEA3 comparison should implement this same frame/key/length boundary.