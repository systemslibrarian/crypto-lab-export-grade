import './style.css';

import type { AttackResponse } from '../attack/protocol';
import {
  KEYSPACE_TARGETS,
  SCALE_TIERS,
  SECONDS_PER_YEAR,
  bitsReachableIn,
  extrapolate,
  formatDuration,
  formatMultiplier,
  isAbsurdMultiplier,
  measureRate,
  type RateMeasurement,
} from '../attack/rate';
import {
  BRUTE_FORCE_LINES,
  PUBLISHED_ATTACKS,
  advantageBits,
  largestSingleKeyAdvantage,
  type PublishedAttack,
} from '../data/attacks';
import { tea1, tea1ExpandIv, tea1Inner } from '../tea1/core';
import { TEA1_REGISTER_BITS, tea1InitKeyRegister, traceTea1KeyLoad } from '../tea1/keyload';

const KAT_FRAME = 0x11111111;
const KAT_KEY = new Uint8Array(10);
const KAT_EXPECTED = new Uint8Array([
  0xd3, 0x3f, 0xd8, 0xa6, 0x05, 0xa0, 0xa1, 0xbb, 0x90, 0x23,
]);
const ATTACK_WINDOW_SIZE = 0x1_0000;
/** The widest exponent either chart draws, so both share one log2 axis. */
const CHART_AXIS_BITS = 256;

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
  const outputLength = Number(lengthInput.value);
  if (!Number.isInteger(outputLength) || outputLength < 4 || outputLength > 32) {
    throw new Error('Output length must be a whole number between 4 and 32 bytes.');
  }
  return { key, frameNumber, outputLength };
}

function cipherFingerprint(inputs: CipherInputs): string {
  return `${formatBytes(inputs.key)}|${inputs.frameNumber}|${inputs.outputLength}`;
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
const cipherStatus = requireElement<HTMLParagraphElement>('cipher-status');
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
const recoveryLabel = requireElement<HTMLElement>('recovery-label');
const recoverySummary = requireElement<HTMLParagraphElement>('recovery-summary');
const candidateScope = requireElement<HTMLParagraphElement>('candidate-scope');

let reductionStep = 0;
let renderedCipherFingerprint: string | null = null;
let renderedReductionKey: string | null = null;
let requestSequence = 0;
let activeRequestId: number | null = null;
let activeFixture: AttackFixture | null = null;
let activeProgress: { checked: number; elapsedMs: number } | null = null;
let resultFingerprint: string | null = null;
let attackWorker: Worker | null = null;

function renderKat(): boolean {
  const actual = tea1(KAT_FRAME, KAT_KEY, KAT_EXPECTED.length);
  const matches = bytesEqual(actual, KAT_EXPECTED);
  katVerdict.dataset.state = matches ? 'ok' : 'error';
  katVerdict.dataset.kat = matches ? 'pass' : 'fail';
  katVerdict.textContent = matches
    ? 'KAT MATCH — real TEA1 agrees with the upstream fixture'
    : 'KAT FAILURE — implementation does not match the upstream fixture';
  return matches;
}

function clearCipherOutput(message: string): void {
  keystreamOutput.value = '—';
  cipherByteCount.textContent = 'NOT GENERATED';
  renderedCipherFingerprint = null;
  cipherStatus.textContent = message;
}

function retireCipherIfInputsChanged(): void {
  try {
    if (cipherFingerprint(readCipherInputs()) === renderedCipherFingerprint) return;
    cipherError.hidden = true;
  } catch (error) {
    cipherError.textContent = error instanceof Error ? error.message : 'Invalid cipher input.';
    cipherError.hidden = false;
  }
  clearCipherOutput('Inputs changed. Generate keystream to show bytes for the current inputs.');
}

function renderCipher(): void {
  try {
    const inputs = readCipherInputs();
    const stream = tea1(inputs.frameNumber, inputs.key, inputs.outputLength);
    keystreamOutput.value = formatBytes(stream);
    cipherByteCount.textContent = `${inputs.outputLength} BYTES`;
    renderedCipherFingerprint = cipherFingerprint(inputs);
    cipherStatus.textContent = 'Generated from the current key, frame and output length.';
    cipherError.hidden = true;
    renderKat();
  } catch (error) {
    clearCipherOutput('No keystream is shown for invalid inputs.');
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
    const key = parseHexBytes(keyInput.value, 'Key', 10);
    const keyFingerprint = formatBytes(key);
    if (keyFingerprint !== renderedReductionKey) reductionStep = 0;
    renderedReductionKey = keyFingerprint;
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
    const katMatches = renderKat();
    reductionVerdict.dataset.state = complete ? (katMatches ? 'alarm' : 'error') : 'pending';
    reductionVerdict.dataset.claim = complete ? (katMatches ? 'ok-and-broken' : 'kat-failed') : 'pending';
    reductionVerdict.textContent = !complete
      ? 'Load all ten bytes to inspect the working key.'
      : katMatches
        ? `OK-AND-BROKEN — the KAT passes, while the generator receives ${TEA1_REGISTER_BITS} computed bits.`
        : `KEY LOAD COMPUTED — REFERENCE KAT FAILED. The register contains ${TEA1_REGISTER_BITS} bits, but the cipher failed its reference check.`;
  } catch (error) {
    reductionStep = 0;
    renderedReductionKey = null;
    registerOutput.value = '—';
    nominalBits.value = '—';
    delete nominalBits.dataset.bits;
    keyBitGrid.replaceChildren();
    registerBitGrid.replaceChildren();
    traceBody.replaceChildren();
    loadStepLabel.textContent = 'No valid key loaded';
    loadEquation.textContent = 'Enter a valid ten-byte key to inspect its key load.';
    reductionVerdict.dataset.state = 'error';
    reductionVerdict.dataset.claim = 'error';
    reductionVerdict.textContent = error instanceof Error ? error.message : 'Invalid key.';
    loadNext.disabled = true;
    loadAll.disabled = true;
  }
}

function attackFingerprint(key: Uint8Array, frameNumber: number, plaintext: Uint8Array): string {
  return `${formatBytes(key)}|${frameNumber >>> 0}|${formatBytes(plaintext)}`;
}

function buildAttackFixture(): AttackFixture {
  // The attack uses its own 4–8-byte sample, not Exhibit 1's display length.
  const key = parseHexBytes(keyInput.value, 'Key', 10);
  const frameNumber = parseFrameNumber(frameInput.value);
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
  activeFixture = null;
  activeProgress = null;
  attackStart.disabled = false;
  attackCancel.disabled = true;
}

function retireAttack(message: string): void {
  const requestId = activeRequestId;
  // Retire the request locally before asking the worker to stop. A found answer
  // can already be queued when the cancellation reaches the worker.
  finishAttackControls();
  if (requestId !== null) attackWorker?.postMessage({ type: 'cancel', requestId });
  attackResult.hidden = true;
  attackResult.dataset.check = 'retired';
  resultFingerprint = null;
  retiredStatus.hidden = false;
  retiredStatus.textContent = message;
  attackStatus.textContent = 'Ready for the current inputs. No previous recovery is in force.';
  setAttackProgress(0, ATTACK_WINDOW_SIZE);
}

/**
 * Exhibit 5's only input. The worker has already done this work and already
 * reported both numbers; this divides them. It starts no search and adds no
 * timing of its own, and it refuses to record anything when nothing was tested.
 */
function recordMeasuredRate(checked: number, elapsedMs: number): void {
  if (checked <= 0) return;
  try {
    measuredRate = measureRate(checked, elapsedMs);
  } catch {
    measuredRate = null;
  }
  renderWall();
}

function handleAttackMessage(message: AttackResponse): void {
  if (message.requestId !== activeRequestId || activeFixture === null) return;
  activeProgress = { checked: message.checked, elapsedMs: message.elapsedMs };
  setAttackProgress(message.checked, message.total);

  if (message.type === 'progress') {
    attackStatus.textContent = 'Searching with the real TEA1 core in a Web Worker…';
    return;
  }
  if (message.type !== 'error') recordMeasuredRate(message.checked, message.elapsedMs);
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

  const inRange = Number.isInteger(message.register)
    && message.register >= activeFixture.startRegister
    && message.register < activeFixture.endRegisterExclusive;
  const reproduced = inRange
    ? tea1Inner(tea1ExpandIv(activeFixture.frameNumber), message.register, activeFixture.targetKeystream.length)
    : new Uint8Array();
  const matches = inRange && bytesEqual(reproduced, activeFixture.targetKeystream);
  const fixtureRegister = tea1InitKeyRegister(activeFixture.key);
  const sameFixtureRegister = matches && message.register === fixtureRegister;
  recoveredRegister.textContent = formatRegister(message.register);
  verificationOutput.textContent = matches
    ? `${reproduced.length} / ${reproduced.length} keystream bytes reproduced exactly`
    : 'Verification failed: recovered candidate did not reproduce the target';
  recoveryLabel.textContent = !matches
    ? 'CANDIDATE REJECTED'
    : sameFixtureRegister ? 'FIXTURE REGISTER RECOVERED' : 'MATCHING CANDIDATE — NOT THE FIXTURE REGISTER';
  recoverySummary.textContent = !matches
    ? 'VERIFICATION FAILED — this answer is not evidence of recovery.'
    : sameFixtureRegister
      ? 'OK-AND-BROKEN — the sample matches, and this candidate equals the fixture’s 32-bit register. The original 80-bit key is not recovered.'
      : `SHORT-SAMPLE COLLISION — the known bytes match, but this fixture was generated with ${formatRegister(fixtureRegister)}. Add more known bytes and search again.`;
  candidateScope.textContent = matches
    ? 'The search stops at the first match; matching a short sample does not prove uniqueness. Comparing against the fixture register uses the key this lab already knows, beyond the attacker’s known bytes.'
    : 'No successful recovery is claimed for a candidate that fails the byte check or falls outside the selected window.';
  attackResult.dataset.check = !matches ? 'fail' : sameFixtureRegister ? 'pass' : 'candidate';
  attackResult.hidden = false;
  resultFingerprint = activeFixture.fingerprint;
  attackStatus.textContent = !matches
    ? 'A worker result failed the main-thread byte check.'
    : sameFixtureRegister
      ? `Fixture register recovered after ${message.checked.toLocaleString()} real TEA1 evaluations.`
      : `Matching candidate found after ${message.checked.toLocaleString()} real TEA1 evaluations; it is not the fixture register.`;
  finishAttackControls();
}

function ensureAttackWorker(): Worker {
  // [extension] A CVE-2022-24401 oracle exhibit can use a separate worker and protocol here.
  if (attackWorker === null) {
    const worker = new Worker(new URL('../attack/worker.ts', import.meta.url), { type: 'module' });
    attackWorker = worker;
    worker.addEventListener('message', (event: MessageEvent<AttackResponse>) => {
      handleAttackMessage(event.data);
    });
    worker.addEventListener('error', () => {
      if (attackWorker !== worker) return;
      worker.terminate();
      attackWorker = null;
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
    const key = parseHexBytes(keyInput.value, 'Key', 10);
    const frameNumber = parseFrameNumber(frameInput.value);
    const plaintext = parseHexBytes(plaintextInput.value, 'Known plaintext');
    currentFingerprint = attackFingerprint(key, frameNumber, plaintext);
  } catch {
    currentFingerprint = null;
  }

  if (resultFingerprint !== null && currentFingerprint !== resultFingerprint) {
    retireAttack('A previous result was retired because an input changed.');
  }

  if (
    activeRequestId !== null &&
    activeFixture !== null &&
    currentFingerprint !== activeFixture.fingerprint
  ) {
    retireAttack('The pending search was retired because an input changed. Any late answer is ignored.');
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
    activeProgress = null;
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
    finishAttackControls();
    attackStatus.textContent = 'Search could not start. Correct the reported problem and try again.';
  }
});

attackCancel.addEventListener('click', () => {
  if (activeRequestId !== null) {
    if (activeProgress !== null) recordMeasuredRate(activeProgress.checked, activeProgress.elapsedMs);
    retireAttack('The search was cancelled. Any late answer is ignored.');
    attackStatus.textContent = 'Search cancelled cleanly. No recovery is claimed.';
  }
});

for (const input of [keyInput, frameInput, plaintextInput]) {
  input.addEventListener('input', () => {
    retireResultIfInputsChanged();
    prepareAttackPreview();
  });
}

for (const input of [keyInput, frameInput, lengthInput]) {
  input.addEventListener('input', retireCipherIfInputsChanged);
}
keyInput.addEventListener('input', renderReduction);

// ---------------------------------------------------------------------------
// Exhibit 5 — The Wall
// ---------------------------------------------------------------------------

const wallAbsent = requireElement<HTMLDivElement>('wall-absent');
const wallBody = requireElement<HTMLDivElement>('wall-body');
const wallRate = requireElement<HTMLOutputElement>('wall-rate');
const wallFormula = requireElement<HTMLParagraphElement>('wall-formula');
const wallRateCaveat = requireElement<HTMLParagraphElement>('wall-rate-caveat');
const wallTiers = requireElement<HTMLDivElement>('wall-tiers');
const wallMultiplier = requireElement<HTMLInputElement>('wall-multiplier');
const wallAssumption = requireElement<HTMLParagraphElement>('wall-assumption');
const wallAbsurd = requireElement<HTMLParagraphElement>('wall-absurd');
const wallChart = requireElement<HTMLDivElement>('wall-chart');
const wallVerdict = requireElement<HTMLDivElement>('wall-verdict');

/** The one rate this lab quotes, or null until Exhibit 3 has produced one. */
let measuredRate: RateMeasurement | null = null;
const tierMultipliers = new Map(SCALE_TIERS.map((tier) => [tier.id, tier.defaultMultiplier]));
let activeTierId = SCALE_TIERS[0].id;

function activeTier() {
  return SCALE_TIERS.find((tier) => tier.id === activeTierId) ?? SCALE_TIERS[0];
}

/** True when the field holds something that cannot be a multiplier at all. */
function multiplierIsUnusable(): boolean {
  const typed = Number.parseFloat(wallMultiplier.value);
  return !(Number.isFinite(typed) && typed > 0);
}

function currentMultiplier(): number {
  const typed = Number.parseFloat(wallMultiplier.value);
  return multiplierIsUnusable() ? 1 : typed;
}

function buildTierControls(): void {
  wallTiers.replaceChildren(
    ...SCALE_TIERS.map((tier) => {
      const wrapper = document.createElement('div');
      wrapper.className = 'scale-tier';

      const input = document.createElement('input');
      input.type = 'radio';
      input.name = 'wall-tier';
      input.id = `wall-tier-${tier.id}`;
      input.value = tier.id;
      input.checked = tier.id === activeTierId;
      input.addEventListener('change', () => {
        activeTierId = tier.id;
        wallMultiplier.value = String(tierMultipliers.get(tier.id) ?? 1);
        renderWall();
      });

      const label = document.createElement('label');
      label.htmlFor = input.id;
      label.textContent = tier.label;

      wrapper.append(input, label);
      return wrapper;
    }),
  );
}

interface ChartRow {
  /** Where the bar ends on the shared 0–256 log2 axis. */
  bits: number;
  headline: string;
  detail: string;
  /** Right-hand value: a duration for Exhibit 5, a complexity for Exhibit 6. */
  value: string;
  kind: 'target' | 'mark';
  state?: string;
}

function makeChartRow(row: ChartRow): HTMLDivElement {
  const item = document.createElement('div');
  item.className = 'bar-row';
  item.setAttribute('role', 'listitem');
  item.dataset.kind = row.kind;
  item.dataset.bits = row.bits.toFixed(2);
  if (row.state !== undefined) item.dataset.state = row.state;

  const head = document.createElement('div');
  head.className = 'bar-head';
  const headline = document.createElement('span');
  headline.className = 'bar-headline';
  headline.textContent = row.headline;
  const value = document.createElement('span');
  value.className = 'bar-value';
  value.textContent = row.value;
  head.append(headline, value);

  const track = document.createElement('div');
  track.className = 'bar-track';
  const fill = document.createElement('span');
  fill.className = 'bar-fill';
  const percent = (row.bits / CHART_AXIS_BITS) * 100;
  fill.style.width = `${Math.max(0, Math.min(100, percent)).toFixed(3)}%`;
  fill.dataset.percent = percent.toFixed(3);
  track.append(fill);

  const detail = document.createElement('p');
  detail.className = 'bar-detail';
  detail.textContent = row.detail;

  item.append(head, track, detail);
  return item;
}

function renderWall(): void {
  const hasRate = measuredRate !== null;
  wallAbsent.hidden = hasRate;
  wallBody.hidden = !hasRate;
  wallAbsent.dataset.rate = hasRate ? 'present' : 'absent';
  if (measuredRate === null) {
    // Inert on purpose: no rate means no numbers, not a stand-in rate.
    wallChart.replaceChildren();
    wallVerdict.dataset.claim = 'pending';
    wallVerdict.dataset.state = 'pending';
    wallVerdict.textContent = 'Extrapolation pending.';
    return;
  }

  const rate = measuredRate;
  const multiplier = currentMultiplier();
  tierMultipliers.set(activeTierId, multiplier);
  const tier = activeTier();

  wallRate.value = Math.round(rate.candidatesPerSecond).toLocaleString();
  wallRate.dataset.rate = String(rate.candidatesPerSecond);
  wallFormula.textContent =
    `${rate.checked.toLocaleString()} candidates ÷ ${(rate.denominatorMs / 1000).toFixed(6)} s of search ` +
    `= ${rate.rawCandidatesPerSecond.toLocaleString(undefined, { maximumFractionDigits: 3 })} candidates/second. ` +
    (rate.timerLimited ? `The denominator uses a 1 ms floor; the recorded timer value was ${rate.elapsedMs} ms. ` : '') +
    'Timed inside the Exhibit 3 loop, excluding the pauses that keep the UI responsive.';

  const caveats: string[] = [];
  if (rate.floored) {
    caveats.push(
      'The measured rate is below one candidate per second. These extrapolations use a declared floor of 1 candidate/second, an upper bound on that measured rate; the displayed times are therefore lower bounds.',
    );
  }
  if (rate.timerLimited) {
    caveats.push(
      'The run finished faster than the clock can resolve, so this rate is a lower bound and the times below are upper bounds.',
    );
  }
  wallRateCaveat.textContent = caveats.join(' ');
  wallRateCaveat.hidden = caveats.length === 0;

  // Say which number is in force, and say so explicitly when it is not the one
  // in the field: a silent fallback would make the rows below unexplained.
  wallAssumption.textContent = multiplierIsUnusable()
    ? `${tier.label}: ${tier.assumption} That field does not hold a usable multiplier, so the rows below use ${formatMultiplier(multiplier)} — the measured rate, unscaled.`
    : `${tier.label}: ${tier.assumption} Currently ${formatMultiplier(multiplier)}.`;
  const absurd = isAbsurdMultiplier(multiplier);
  wallAbsurd.hidden = !absurd;
  wallAbsurd.textContent = absurd
    ? `ABSURD ASSUMPTION — ${formatMultiplier(multiplier)} assumes more parallel engines than anyone has built or proposed. The rows below still compute it exactly; they are arithmetic on a number you invented.`
    : '';

  const marks: ChartRow[] = [
    {
      bits: bitsReachableIn(1, rate.candidatesPerSecond, multiplier),
      headline: `2^${bitsReachableIn(1, rate.candidatesPerSecond, multiplier).toFixed(1)}`,
      detail: 'Your own mark: the keyspace this scale clears in one second.',
      value: 'one second',
      kind: 'mark',
    },
    {
      bits: bitsReachableIn(SECONDS_PER_YEAR, rate.candidatesPerSecond, multiplier),
      headline: `2^${bitsReachableIn(SECONDS_PER_YEAR, rate.candidatesPerSecond, multiplier).toFixed(1)}`,
      detail: 'Your own mark: the keyspace this scale clears in one year.',
      value: 'one year',
      kind: 'mark',
    },
  ];

  const targets: ChartRow[] = KEYSPACE_TARGETS.map((target) => {
    const projected = extrapolate(target.bits, rate.candidatesPerSecond, multiplier);
    return {
      bits: target.bits,
      headline: `2^${target.bits}`,
      detail: `${target.label} — ${target.detail}`,
      value: `${rate.floored ? '≥ ' : rate.timerLimited ? '≤ ' : ''}${formatDuration(projected.seconds)}`,
      kind: 'target' as const,
      state: target.thisLab,
    };
  });

  const rows = [...marks, ...targets].sort((left, right) => left.bits - right.bits);
  wallChart.replaceChildren(...rows.map(makeChartRow));

  const register = extrapolate(32, rate.candidatesPerSecond, multiplier);
  const labelled = extrapolate(80, rate.candidatesPerSecond, multiplier);
  const aes128 = extrapolate(128, rate.candidatesPerSecond, multiplier);
  // The window Exhibit 3 really ran, timed rather than extrapolated. It is named
  // separately from 2^32 on purpose: this lab does not let the window it finished
  // stand in for the space it did not.
  const windowSeconds = rate.elapsedMs / 1000;
  wallVerdict.dataset.state = 'alarm';
  wallVerdict.dataset.claim = 'wall';
  wallVerdict.textContent =
    `THE WALL — Exhibit 3 really tested ${rate.checked.toLocaleString()} candidates in ` +
    `${formatDuration(windowSeconds)}. ` +
    `At ${formatMultiplier(multiplier)} that rate, the full 32-bit register TEA1 actually uses would take ` +
    `${formatDuration(register.seconds)}. The 80 bits on the label would take ` +
    `${formatDuration(labelled.seconds)}, and 128 would take ${formatDuration(aes128.seconds)}. ` +
    'Those three are extrapolated from one browser, not predicted. They cover the full space, not the average time to find a uniformly placed target. ' +
    (rate.floored ? 'The quoted times are lower bounds under the declared rate floor.' : rate.timerLimited ? 'The quoted times are upper bounds under the clock-resolution floor.' : '');

  renderContrast();
}

// ---------------------------------------------------------------------------
// Exhibit 6 — Paper vs Practice
// ---------------------------------------------------------------------------

const paperChart = requireElement<HTMLDivElement>('paper-chart');
const paperBody = requireElement<HTMLTableSectionElement>('paper-body');
const paperVerdict = requireElement<HTMLDivElement>('paper-verdict');
const contrastTea1 = requireElement<HTMLElement>('contrast-tea1');
const contrastTea1Note = requireElement<HTMLParagraphElement>('contrast-tea1-note');
const contrastAes = requireElement<HTMLElement>('contrast-aes');
const contrastAdvantage = requireElement<HTMLElement>('contrast-advantage');
const contrastAesTime = requireElement<HTMLElement>('contrast-aes-time');

function makeAttackBar(attack: PublishedAttack): HTMLDivElement {
  const item = document.createElement('div');
  item.className = 'bar-row attack-bar';
  item.setAttribute('role', 'listitem');
  item.dataset.attack = attack.id;
  item.dataset.bits = attack.log2Time.toFixed(2);
  item.dataset.model = attack.model;

  const head = document.createElement('div');
  head.className = 'bar-head';
  const headline = document.createElement('span');
  headline.className = 'bar-headline';
  headline.textContent = attack.attack;
  const value = document.createElement('span');
  value.className = 'bar-value';
  value.textContent = attack.timeLabel;
  head.append(headline, value);

  const track = document.createElement('div');
  track.className = 'bar-track';
  const fill = document.createElement('span');
  fill.className = 'bar-fill';
  const percent = (attack.log2Time / CHART_AXIS_BITS) * 100;
  fill.style.width = `${percent.toFixed(3)}%`;
  fill.dataset.percent = percent.toFixed(3);
  track.append(fill);

  const detail = document.createElement('p');
  detail.className = 'bar-detail';
  detail.textContent =
    `${attack.model === 'single-key' ? 'Single-key' : 'Related-key'} · ` +
    `${advantageBits(attack).toFixed(2)} bits under the ${attack.keyBits}-bit line · ` +
    `data ${attack.dataLabel} · memory ${attack.memoryLabel}`;

  item.append(head, track, detail);
  return item;
}

function renderPaper(): void {
  const groups = BRUTE_FORCE_LINES.map((line) => {
    const group = document.createElement('div');
    group.className = 'attack-group';
    group.dataset.keyBits = String(line.keyBits);

    const heading = document.createElement('h4');
    heading.className = 'attack-group-title';
    heading.id = `attack-group-${line.keyBits}`;
    heading.textContent = `AES-${line.keyBits}`;

    const list = document.createElement('div');
    list.setAttribute('role', 'list');
    list.setAttribute('aria-labelledby', heading.id);
    list.className = 'attack-group-list';

    const bruteRow = makeChartRow({
      bits: line.keyBits,
      headline: line.label,
      detail: `Exhaustive search over 2^${line.keyBits} keys — the line every row below has to beat to count as an attack.`,
      value: `2^${line.keyBits}`,
      kind: 'mark',
      state: 'brute',
    });
    bruteRow.classList.add('brute-line');

    list.append(
      bruteRow,
      ...PUBLISHED_ATTACKS.filter((attack) => attack.keyBits === line.keyBits).map(makeAttackBar),
    );
    group.append(heading, list);
    return group;
  });
  paperChart.replaceChildren(...groups);

  paperBody.replaceChildren(
    ...PUBLISHED_ATTACKS.map((attack) => {
      const row = document.createElement('tr');
      row.dataset.attack = attack.id;

      const cells: (string | HTMLElement)[] = [
        attack.target,
        attack.attack,
        `${attack.model === 'single-key' ? 'Single-key' : 'Related-key'} — ${attack.modelDetail}`,
        `${attack.goal}, ${attack.rounds} of ${attack.fullRounds} rounds`,
        attack.timeLabel,
        attack.dataLabel,
        attack.memoryLabel,
      ];

      for (const [index, content] of cells.entries()) {
        const cell = document.createElement('td');
        cell.textContent = String(content);
        if (index === 4) cell.dataset.time = String(attack.log2Time);
        if (index === 5) cell.dataset.data = String(attack.log2Data);
        if (index === 6) cell.dataset.memory = String(attack.log2Memory);
        row.append(cell);
      }

      const source = document.createElement('td');
      const link = document.createElement('a');
      link.href = attack.citation.url;
      link.target = '_blank';
      link.rel = 'noopener';
      link.textContent = `${attack.citation.authors.split(',')[0].split(' ').pop()} et al., ${attack.citation.year}`;
      const locator = document.createElement('span');
      locator.className = 'citation-locator';
      locator.textContent = `${attack.citation.venue} · ${attack.citation.locator}`;
      source.append(link, locator);
      if (attack.note !== undefined) {
        const note = document.createElement('span');
        note.className = 'citation-note';
        note.textContent = attack.note;
        source.append(note);
      }
      row.append(source);
      return row;
    }),
  );

  const best = largestSingleKeyAdvantage();
  paperVerdict.dataset.state = 'alarm';
  paperVerdict.dataset.claim = 'academically-broken';
  paperVerdict.textContent =
    `ACADEMICALLY BROKEN — AND PRACTICALLY SECURE. ${PUBLISHED_ATTACKS.length} published attacks on full-round AES, ` +
    `every one of them faster than brute force. The largest single-key advantage any of them buys is ` +
    `${advantageBits(best).toFixed(2)} bits, against ${best.target}. Nothing on this chart finishes.`;

  renderContrast();
}

function renderContrast(): void {
  const best = largestSingleKeyAdvantage();
  contrastAes.textContent = `${best.target}: ${best.timeLabel}`;
  contrastAdvantage.textContent = `${advantageBits(best).toFixed(2)} bits`;

  if (measuredRate === null) {
    contrastTea1.textContent = '—';
    contrastAesTime.textContent = '—';
    contrastTea1Note.hidden = false;
    return;
  }

  // Deliberately unscaled. This panel says "the rate your own browser measured",
  // so it uses that rate and nothing else — a multiplier typed into Exhibit 5
  // would make the sentence false.
  const bound = measuredRate.floored ? '≥ ' : measuredRate.timerLimited ? '≤ ' : '';
  contrastTea1.textContent = bound + formatDuration(
    extrapolate(32, measuredRate.candidatesPerSecond, 1).seconds,
  );
  contrastAesTime.textContent = bound + formatDuration(
    extrapolate(best.log2Time, measuredRate.candidatesPerSecond, 1).seconds,
  );
  contrastTea1Note.hidden = true;
}

wallMultiplier.addEventListener('input', renderWall);

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
buildTierControls();
renderWall();
renderPaper();
