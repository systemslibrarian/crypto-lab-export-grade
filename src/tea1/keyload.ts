// Copyright 2023, Midnight Blue.
// Licensed under the Apache License, Version 2.0.
// Modified into TypeScript for crypto-lab-export-grade.

import { TEA1_SBOX } from './constants';

export const TEA1_KEY_BYTES = 10;
export const TEA1_REGISTER_BITS = 32;

export interface KeyLoadStep {
  index: number;
  inputByte: number;
  previousRegister: number;
  sboxIndex: number;
  sboxOutput: number;
  register: number;
}

function assertTea1Key(key: Uint8Array): void {
  if (key.length !== TEA1_KEY_BYTES) {
    throw new RangeError(`TEA1 keys must contain exactly ${TEA1_KEY_BYTES} bytes`);
  }
}

export function traceTea1KeyLoad(key: Uint8Array): KeyLoadStep[] {
  assertTea1Key(key);

  const steps: KeyLoadStep[] = [];
  let register = 0;

  for (let index = 0; index < key.length; index += 1) {
    const previousRegister = register;
    const inputByte = key[index];
    const sboxIndex = ((register >>> 24) ^ inputByte ^ register) & 0xff;
    const sboxOutput = TEA1_SBOX[sboxIndex];
    register = ((register << 8) | sboxOutput) >>> 0;
    steps.push({ index, inputByte, previousRegister, sboxIndex, sboxOutput, register });
  }

  return steps;
}

export function tea1InitKeyRegister(key: Uint8Array): number {
  const steps = traceTea1KeyLoad(key);
  return steps[steps.length - 1].register;
}