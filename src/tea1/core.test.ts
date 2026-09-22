// Copyright 2023, Midnight Blue.
// Licensed under the Apache License, Version 2.0.
// Vectors copied into TypeScript for crypto-lab-export-grade.

import { describe, expect, it } from 'vitest';
import { tea1, tea1ExpandIv, tea1Inner } from './core';
import { tea1InitKeyRegister, traceTea1KeyLoad } from './keyload';

describe('TEA1 reference vectors', () => {
  it('matches the all-zero-key known-answer test', () => {
    const result = tea1(0x11111111, new Uint8Array(10), 10);

    expect(Array.from(result)).toEqual([
      0xd3, 0x3f, 0xd8, 0xa6, 0x05, 0xa0, 0xa1, 0xbb, 0x90, 0x23,
    ]);
  });

  it('matches the nonzero-key known-answer test', () => {
    const key = new Uint8Array([
      0xa7, 0x98, 0x39, 0xe4, 0xba, 0x88, 0xee, 0x54, 0xa0, 0x29,
    ]);

    expect(Array.from(tea1(0x01234567, key, 10))).toEqual([
      0x1d, 0xec, 0x9c, 0x7e, 0xc6, 0x22, 0x3d, 0x87, 0xc2, 0xcc,
    ]);
  });
});

describe('TEA1 key loading', () => {
  it('loads ten key bytes into one 32-bit register', () => {
    const key = new Uint8Array([
      0xa7, 0x98, 0x39, 0xe4, 0xba, 0x88, 0xee, 0x54, 0xa0, 0x29,
    ]);
    const steps = traceTea1KeyLoad(key);

    expect(steps).toHaveLength(10);
    expect(steps.at(-1)?.register).toBe(tea1InitKeyRegister(key));
    expect(steps.every((step) => step.register >= 0 && step.register <= 0xffffffff)).toBe(true);
  });

  it('feeds the derived register into the same keystream core', () => {
    const key = new Uint8Array(10);
    const fromFullKey = tea1(0x11111111, key, 10);
    const fromRegister = tea1Inner(
      tea1ExpandIv(0x11111111),
      tea1InitKeyRegister(key),
      10,
    );

    expect(fromRegister).toEqual(fromFullKey);
  });

  it('rejects keys that are not exactly 80 bits', () => {
    expect(() => tea1InitKeyRegister(new Uint8Array(9))).toThrow(/exactly 10 bytes/);
    expect(() => tea1InitKeyRegister(new Uint8Array(11))).toThrow(/exactly 10 bytes/);
  });
});