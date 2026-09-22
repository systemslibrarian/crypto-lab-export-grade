import './style.css';

import type { AttackResponse } from '../attack/protocol';
import { tea1, tea1ExpandIv, tea1Inner } from '../tea1/core';
import { TEA1_REGISTER_BITS, tea1InitKeyRegister, traceTea1KeyLoad } from '../tea1/keyload';

const KAT_FRAME = 0x11111111;
const KAT_KEY = new Uint8Array(10);
const KAT_EXPECTED = new Uint8Array([
  0xd3, 0x3f, 0xd8, 0xa6, 0x05, 0xa0, 0xa1, 0xbb, 0x90, 0x23,
]);
const ATTACK_WINDOW_SIZE = 0x1_0000;

interface CipherInputs {
  key: Uint8Array;
  frameNumber: number;
  outputLength: number;
}

interface AttackFixture {
  frameNumber: number;
  key: Uint8Array;
  plaintext: Uint8Array;
  targetKeystream: Uint8Array;
  startRegister: number;
  endRegisterExclusive: number;
  fingerprint: string;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLElement)) {
    throw new Error(`Missing required element #${id}`);
  }
  return element as T;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function formatBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(' ');
}

function formatRegister(register: number): string {
  return `0x${(register >>> 0).toString(16).padStart(8, '0')}`;
}

function parseHexBytes(value: string, label: string, expectedBytes?: number): Uint8Array {
  const compact = value.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) {
    throw new Error(`${label} must contain complete hexadecimal bytes.`);
  }
  if (expectedBytes !== undefined && compact.length !== expectedBytes * 2) {
    throw new Error(`${label} must contain exactly ${expectedBytes} bytes.`);
  }

  return Uint8Array.from(
    compact.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)),
  );
}

function parseFrameNumber(value: string): number {
  const compact = value.trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]{1,8}$/i.test(compact)) {
    throw new Error('Frame number must be 1–8 hexadecimal digits.');
  }
  return Number.parseInt(compact, 16) >>> 0;
}

function readCipherInputs(): CipherInputs {
  const key = parseHexBytes(keyInput.value, 'Key', 10);
  const frameNumber = parseFrameNumber(frameInput.value);
  const outputLength = Number.parseInt(lengthInput.value, 10);
  if (!Number.isInteger(outputLength) || outputLength < 4 || outputLength > 32) {
    throw new Error('Output length must be between 4 and 32 bytes.');
  }
  return { key, frameNumber, outputLength };
}

function xorBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  return Uint8Array.from(left, (byte, index) => byte ^ right[index]);
}

const keyInput = requireElement<HTMLInputElement>('key-input');
const frameInput = requireElement<HTMLInputElement>('frame-input');
const lengthInput = requireElement<HTMLInputElement>('length-input');
const cipherForm = requireElement<HTMLFormElement>('cipher-form');
const cipherError = requireElement<HTMLParagraphElement>('cipher-error');
const keystreamOutput = requireElement<HTMLOutputElement>('keystream-output');
const cipherByteCount = requireElement<HTMLSpanElement>('cipher-byte-count');
const katVerdict = requireElement<HTMLDivElement>('kat-verdict');

const keyBitGrid = requireElement<HTMLDivElement>('key-bit-grid');
const registerBitGrid = requireElement<HTMLDivElement>('register-bit-grid');
const registerOutput = requireElement<HTMLOutputElement>('register-output');
const nominalBits = requireElement<HTMLOutputElement>('nominal-bits');
const effectiveBits = requireElement<HTMLOutputElement>('effective-bits');
const loadStepLabel = requireElement<HTMLSpanElement>('load-step-label');
const loadEquation = requireElement<HTMLParagraphElement>('load-equation');
const loadReset = requireElement<HTMLButtonElement>('load-reset');
const loadNext = requireElement<HTMLButtonElement>('load-next');
const loadAll = requireElement<HTMLButtonElement>('load-all');
const reductionVerdict = requireElement<HTMLDivElement>('reduction-verdict');
const traceBody = requireElement<HTMLTableSectionElement>('trace-body');

const plaintextInput = requireElement<HTMLInputElement>('plaintext-input');
const ciphertextOutput = requireElement<HTMLElement>('ciphertext-output');
const knownStreamOutput = requireElement<HTMLElement>('known-stream-output');
const searchRangeOutput = requireElement<HTMLElement>('search-range-output');
const attackError = requireElement<HTMLParagraphElement>('attack-error');
const attackStart = requireElement<HTMLButtonElement>('attack-start');
const attackCancel = requireElement<HTMLButtonElement>('attack-cancel');
const attackProgress = requireElement<HTMLProgressElement>('attack-progress');
const attackPercent = requireElement<HTMLSpanElement>('attack-percent');
const attackCount = requireElement<HTMLParagraphElement>('attack-count');
const attackStatus = requireElement<HTMLParagraphElement>('attack-status');
const retiredStatus = requireElement<HTMLParagraphElement>('retired-status');
const attackResult = requireElement<HTMLDivElement>('attack-result');
const recoveredRegister = requireElement<HTMLElement>('recovered-register');
const verificationOutput = requireElement<HTMLParagraphElement>('verification-output');

let reductionStep = 0;
let requestSequence = 0;
let activeRequestId: number | null = null;
let activeFixture: AttackFixture | null = null;
let resultFingerprint: string | null = null;
let attackWorker: Worker | null = null;

function renderKat(): void {
  const actual = tea1(KAT_FRAME, KAT_KEY, KAT_EXPECTED.length);
  const matches = bytesEqual(actual, KAT_EXPECTED);
  katVerdict.dataset.state = matches ? 'ok' : 'error';
  katVerdict.dataset.kat = matches ? 'pass' : 'fail';
  katVerdict.textContent = matches
    ? 'KAT MATCH — real TEA1 agrees with the upstream fixture'
    : 'KAT FAILURE — implementation does not match the upstream fixture';
}

function renderCipher(): void {
  try {
    const inputs = readCipherInputs();
    const stream = tea1(inputs.frameNumber, inputs.key, inputs.outputLength);
    keystreamOutput.value = formatBytes(stream);
    cipherByteCount.textContent = `${inputs.outputLength} BYTES`;
    cipherError.hidden = true;
    renderKat();
  } catch (error) {
    cipherError.textContent = error instanceof Error ? error.message : 'Invalid cipher input.';
    cipherError.hidden = false;
  }
}

function makeBitGroup(byte: number, label: string, state?: string): HTMLDivElement {
  const group = document.createElement('div');
  group.className = 'bit-group';
  group.setAttribute('role', 'listitem');
  group.setAttribute('aria-label', `${label}: ${byte.toString(2).padStart(8, '0')}`);
  if (state !== undefined) group.dataset.state = state;

  for (const bit of byte.toString(2).padStart(8, '0')) {
    const cell = document.createElement('span');
    cell.className = `bit bit-${bit}`;
    cell.textContent = bit;
    cell.setAttribute('aria-hidden', 'true');
    group.append(cell);
  }
  return group;
}

function registerBytes(register: number): Uint8Array {
  return new Uint8Array([
    register >>> 24,
    register >>> 16,
    register >>> 8,
    register,
  ]);
}

function renderReduction(): void {
  try {
    const { key } = readCipherInputs();
    const trace = traceTea1KeyLoad(key);
    const register = reductionStep === 0 ? 0 : trace[reductionStep - 1].register;

    nominalBits.value = String(key.byteLength * 8);
    effectiveBits.value = String(Uint32Array.BYTES_PER_ELEMENT * 8);
    nominalBits.dataset.bits = String(key.byteLength * 8);
    effectiveBits.dataset.bits = String(Uint32Array.BYTES_PER_ELEMENT * 8);
    loadStepLabel.textContent = `${reductionStep} / ${key.length} loaded`;
    registerOutput.value = formatRegister(register);

    keyBitGrid.replaceChildren(
      ...Array.from(key, (byte, index) =>
        makeBitGroup(
          byte,
          `Key byte ${index + 1}`,
          index < reductionStep ? 'consumed' : index === reductionStep ? 'next' : 'waiting',
        ),
      ),
    );
    registerBitGrid.replaceChildren(
      ...Array.from(registerBytes(register), (byte, index) =>
        makeBitGroup(byte, `Register byte ${index + 1}`),
      ),
    );

    const traceRows = trace.slice(0, reductionStep).map((step) => {
        const row = document.createElement('tr');
        for (const value of [
          String(step.index + 1),
          `0x${step.inputByte.toString(16).padStart(2, '0')}`,
          `0x${step.sboxIndex.toString(16).padStart(2, '0')}`,
          `0x${step.sboxOutput.toString(16).padStart(2, '0')}`,
          formatRegister(step.register),
        ]) {
          const cell = document.createElement('td');
          cell.textContent = value;
          row.append(cell);
        }
        return row;
      });
    if (traceRows.length === 0) {
      const row = document.createElement('tr');
      row.className = 'trace-empty';
      const cell = document.createElement('td');
      cell.colSpan = 5;
      cell.textContent = 'No key-load rounds executed yet.';
      row.append(cell);
      traceRows.push(row);
    }
    traceBody.replaceChildren(...traceRows);

    if (reductionStep === 0) {
      loadEquation.textContent = 'Register starts at 0x00000000.';
    } else {
      const step = trace[reductionStep - 1];
      loadEquation.textContent = `${formatRegister(step.previousRegister)} + key[${step.index}] 0x${step.inputByte.toString(16).padStart(2, '0')} → S[0x${step.sboxIndex.toString(16).padStart(2, '0')}] = 0x${step.sboxOutput.toString(16).padStart(2, '0')} → ${formatRegister(step.register)}`;
    }

    const complete = reductionStep === trace.length;
    loadNext.disabled = complete;
    loadAll.disabled = complete;
    reductionVerdict.dataset.state = complete ? 'alarm' : 'pending';
    reductionVerdict.dataset.claim = complete ? 'ok-and-broken' : 'pending';
    reductionVerdict.textContent = complete
      ? `OK-AND-BROKEN — the KAT passes, while the generator receives ${TEA1_REGISTER_BITS} computed bits.`
      : 'Load all ten bytes to inspect the working key.';
  } catch (error) {
    reductionVerdict.dataset.state = 'error';
    reductionVerdict.textContent = error instanceof Error ? error.message : 'Invalid key.';
    loadNext.disabled = true;
    loadAll.disabled = true;
  }
}

function attackFingerprint(key: Uint8Array, frameNumber: number, plaintext: Uint8Array): string {
  return `${formatBytes(key)}|${frameNumber >>> 0}|${formatBytes(plaintext)}`;
}

function buildAttackFixture(): AttackFixture {
  const { key, frameNumber } = readCipherInputs();
  const plaintext = parseHexBytes(plaintextInput.value, 'Known plaintext');
  if (plaintext.length < 4 || plaintext.length > 8) {
    throw new Error('Known plaintext must contain between 4 and 8 bytes.');
  }
  if (plaintext.every((byte) => byte === 0)) {
    throw new Error('Use a nonzero known plaintext so the fixture cannot be mistaken for raw keystream.');
  }

  const targetKeystream = tea1(frameNumber, key, plaintext.length);
  const ciphertext = xorBytes(plaintext, targetKeystream);
  const derivedKeystream = xorBytes(plaintext, ciphertext);
  const effectiveRegister = tea1InitKeyRegister(key);
  const startRegister = Math.floor(effectiveRegister / ATTACK_WINDOW_SIZE) * ATTACK_WINDOW_SIZE;
  const endRegisterExclusive = startRegister + ATTACK_WINDOW_SIZE;
  const fingerprint = attackFingerprint(key, frameNumber, plaintext);

  ciphertextOutput.textContent = formatBytes(ciphertext);
  knownStreamOutput.textContent = formatBytes(derivedKeystream);
  searchRangeOutput.textContent = `${formatRegister(startRegister)}–${formatRegister(endRegisterExclusive - 1)}`;
  attackError.hidden = true;

  return {
    frameNumber,
    key,
    plaintext,
    targetKeystream: derivedKeystream,
    startRegister,
    endRegisterExclusive,
    fingerprint,
  };
}

function setAttackProgress(checked: number, total: number): void {
  const percent = total === 0 ? 0 : (checked / total) * 100;
  attackProgress.max = total;
  attackProgress.value = checked;
  attackPercent.textContent = `${percent.toFixed(1)}%`;
  attackCount.textContent = `${checked.toLocaleString()} / ${total.toLocaleString()} tested`;
}

function finishAttackControls(): void {
  activeRequestId = null;
  attackStart.disabled = false;
  attackCancel.disabled = true;
}

function handleAttackMessage(message: AttackResponse): void {
  if (message.requestId !== activeRequestId || activeFixture === null) return;
  setAttackProgress(message.checked, message.total);

  if (message.type === 'progress') {
    attackStatus.textContent = 'Searching with the real TEA1 core in a Web Worker…';
    return;
  }
  if (message.type === 'cancelled') {
    attackStatus.textContent = `Search cancelled cleanly after ${message.checked.toLocaleString()} candidates.`;
    finishAttackControls();
    return;
  }
  if (message.type === 'error') {
    attackStatus.textContent = `Search failed: ${message.message}`;
    finishAttackControls();
    return;
  }
  if (message.type === 'exhausted') {
    attackStatus.textContent = 'Window exhausted without a matching effective key.';
    finishAttackControls();
    return;
  }

  const reproduced = tea1Inner(
    tea1ExpandIv(activeFixture.frameNumber),
    message.register,
    activeFixture.targetKeystream.length,
  );
  const matches = bytesEqual(reproduced, activeFixture.targetKeystream);
  recoveredRegister.textContent = formatRegister(message.register);
  verificationOutput.textContent = matches
    ? `${reproduced.length} / ${reproduced.length} keystream bytes reproduced exactly`
    : 'Verification failed: recovered candidate did not reproduce the target';
  attackResult.dataset.check = matches ? 'pass' : 'fail';
  attackResult.hidden = false;
  resultFingerprint = activeFixture.fingerprint;
  attackStatus.textContent = matches
    ? `Recovered after ${message.checked.toLocaleString()} real TEA1 evaluations.`
    : 'A worker result failed independent verification.';
  finishAttackControls();
}

function ensureAttackWorker(): Worker {
  // [extension] A CVE-2022-24401 oracle exhibit can use a separate worker and protocol here.
  if (attackWorker === null) {
    attackWorker = new Worker(new URL('../attack/worker.ts', import.meta.url), { type: 'module' });
    attackWorker.addEventListener('message', (event: MessageEvent<AttackResponse>) => {
      handleAttackMessage(event.data);
    });
    attackWorker.addEventListener('error', () => {
      attackStatus.textContent = 'The search worker stopped unexpectedly.';
      finishAttackControls();
    });
  }
  return attackWorker;
}

function prepareAttackPreview(): void {
  try {
    buildAttackFixture();
    attackError.hidden = true;
  } catch (error) {
    attackError.textContent = error instanceof Error ? error.message : 'Invalid attack fixture.';
    attackError.hidden = false;
    ciphertextOutput.textContent = '—';
    knownStreamOutput.textContent = '—';
    searchRangeOutput.textContent = '—';
  }
}

function retireResultIfInputsChanged(): void {
  let currentFingerprint: string | null = null;
  try {
    const { key, frameNumber } = readCipherInputs();
    const plaintext = parseHexBytes(plaintextInput.value, 'Known plaintext');
    currentFingerprint = attackFingerprint(key, frameNumber, plaintext);
  } catch {
    currentFingerprint = null;
  }

  if (resultFingerprint !== null && currentFingerprint !== resultFingerprint) {
    attackResult.hidden = true;
    attackResult.dataset.check = 'retired';
    resultFingerprint = null;
    retiredStatus.hidden = false;
  }

  if (
    activeRequestId !== null &&
    activeFixture !== null &&
    currentFingerprint !== activeFixture.fingerprint
  ) {
    ensureAttackWorker().postMessage({ type: 'cancel', requestId: activeRequestId });
  }
}

cipherForm.addEventListener('submit', (event) => {
  event.preventDefault();
  renderCipher();
  reductionStep = 0;
  renderReduction();
  prepareAttackPreview();
});

loadReset.addEventListener('click', () => {
  reductionStep = 0;
  renderReduction();
});

loadNext.addEventListener('click', () => {
  reductionStep = Math.min(reductionStep + 1, 10);
  renderReduction();
});

loadAll.addEventListener('click', () => {
  reductionStep = 10;
  renderReduction();
});

attackStart.addEventListener('click', () => {
  try {
    const fixture = buildAttackFixture();
    requestSequence += 1;
    activeRequestId = requestSequence;
    activeFixture = fixture;
    retiredStatus.hidden = true;
    attackResult.hidden = true;
    attackResult.dataset.check = 'pending';
    resultFingerprint = null;
    setAttackProgress(0, fixture.endRegisterExclusive - fixture.startRegister);
    attackStatus.textContent = 'Starting worker search…';
    attackStart.disabled = true;
    attackCancel.disabled = false;
    ensureAttackWorker().postMessage({
      type: 'start',
      requestId: activeRequestId,
      frameNumber: fixture.frameNumber,
      targetKeystream: Array.from(fixture.targetKeystream),
      startRegister: fixture.startRegister,
      endRegisterExclusive: fixture.endRegisterExclusive,
    });
  } catch (error) {
    attackError.textContent = error instanceof Error ? error.message : 'Invalid attack fixture.';
    attackError.hidden = false;
  }
});

attackCancel.addEventListener('click', () => {
  if (activeRequestId !== null) {
    ensureAttackWorker().postMessage({ type: 'cancel', requestId: activeRequestId });
    attackStatus.textContent = 'Cancellation requested…';
    attackCancel.disabled = true;
  }
});

for (const input of [keyInput, frameInput, plaintextInput]) {
  input.addEventListener('input', () => {
    retireResultIfInputsChanged();
    prepareAttackPreview();
  });
}

// [extension] A sourced jurisdiction map can join this view model as a fourth tab.
const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
function activateTab(nextTab: HTMLButtonElement, focus = false): void {
  for (const tab of tabs) {
    const selected = tab === nextTab;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    requireElement<HTMLElement>(tab.getAttribute('aria-controls')!).hidden = !selected;
  }
  if (focus) nextTab.focus();
}

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => activateTab(tab));
  tab.addEventListener('keydown', (event) => {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex !== null) {
      event.preventDefault();
      activateTab(tabs[nextIndex], true);
    }
  });
});

renderCipher();
renderReduction();
prepareAttackPreview();