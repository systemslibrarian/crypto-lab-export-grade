import { describe, expect, it } from 'vitest';
import { tea1ExpandIv, tea1Inner } from '../tea1/core';
import { findRegisterInRange } from './brute';
import { tea1InitKeyRegister } from '../tea1/keyload';

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

  it('returns a matching candidate that need not be the generating register', () => {
    // Independently reproduced with Midnight Blue's C tea1.c at
    // defed030f6155ac70ff5d8bea97b348cb92ee1f6. These two distinct registers
    // share four bytes, then diverge; rechecking the same four is not new evidence.
    const frameNumber = 0x11111111;
    const key = new Uint8Array([0, 0, 0, 0, 0, 0, 0x28, 0xd2, 0xa8, 0xb3]);
    expect(tea1InitKeyRegister(key)).toBe(0xb911);
    const targetKeystream = new Uint8Array([0xb2, 0xb7, 0x46, 0x08]);
    const result = findRegisterInRange({ frameNumber, targetKeystream, startRegister: 0, endRegisterExclusive: 65_536 });
    expect(result).toEqual({ register: 0x958e, checked: 0x958f });
    expect(tea1Inner(tea1ExpandIv(frameNumber), 0x958e, 8)).toEqual(
      new Uint8Array([0xb2, 0xb7, 0x46, 0x08, 0x67, 0x27, 0x83, 0x50]),
    );
    expect(tea1Inner(tea1ExpandIv(frameNumber), 0xb911, 8)).toEqual(
      new Uint8Array([0xb2, 0xb7, 0x46, 0x08, 0x9c, 0x3c, 0x3b, 0x68]),
    );
  }, 15_000); // The full 2^16-window computation also runs under coverage instrumentation.

  it('additional known bytes distinguish the independently verified collision pair', () => {
    expect(findRegisterInRange({
      frameNumber: 0x11111111,
      targetKeystream: new Uint8Array([0xb2, 0xb7, 0x46, 0x08, 0x9c, 0x3c, 0x3b, 0x68]),
      startRegister: 0,
      endRegisterExclusive: 65_536,
    })).toEqual({ register: 0xb911, checked: 0xb912 });
  }, 15_000);
});
