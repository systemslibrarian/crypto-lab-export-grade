import { describe, expect, it } from 'vitest';
import { tea1ExpandIv, tea1Inner } from '../tea1/core';
import { findRegisterInRange } from './brute';

describe('TEA1 effective-key search', () => {
  it('recovers a register by reproducing the real TEA1 keystream', () => {
    const frameNumber = 0x11111111;
    const targetRegister = 733;
    const targetKeystream = tea1Inner(tea1ExpandIv(frameNumber), targetRegister, 5);

    const result = findRegisterInRange({
      frameNumber,
      targetKeystream,
      startRegister: 0,
      endRegisterExclusive: 1_024,
    });

    expect(result).toEqual({ register: targetRegister, checked: targetRegister + 1 });
    expect(tea1Inner(tea1ExpandIv(frameNumber), result!.register, 5)).toEqual(targetKeystream);
  });

  it('returns null when the target is outside the searched range', () => {
    const frameNumber = 0x11111111;
    const targetKeystream = tea1Inner(tea1ExpandIv(frameNumber), 1_025, 4);

    expect(
      findRegisterInRange({
        frameNumber,
        targetKeystream,
        startRegister: 0,
        endRegisterExclusive: 1_024,
      }),
    ).toBeNull();
  });

  it('rejects a target too short to identify a register reliably', () => {
    expect(() =>
      findRegisterInRange({
        frameNumber: 0,
        targetKeystream: new Uint8Array(3),
        startRegister: 0,
        endRegisterExclusive: 1,
      }),
    ).toThrow(/At least 4/);
  });
});