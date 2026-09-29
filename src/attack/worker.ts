/// <reference lib="webworker" />

import { findRegisterInRange } from './brute';
import type { AttackRequest, AttackResponse, StartAttackMessage } from './protocol';

const workerScope = self as DedicatedWorkerGlobalScope;
const CHUNK_SIZE = 2_048;
const cancelledRequests = new Set<number>();

function post(message: AttackResponse): void {
  workerScope.postMessage(message);
}

function yieldToWorkerQueue(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function runAttack(message: StartAttackMessage): Promise<void> {
  const total = message.endRegisterExclusive - message.startRegister;
  let checked = 0;
  // Time spent inside the search loop that this worker already runs. The yields
  // below exist only to keep the UI responsive, so they are outside the clock:
  // this measures TEA1 throughput, not setTimeout's clamp. No extra work is done
  // for it and no second search is started.
  let elapsedMs = 0;

  try {
    for (
      let chunkStart = message.startRegister;
      chunkStart < message.endRegisterExclusive;
      chunkStart += CHUNK_SIZE
    ) {
      if (cancelledRequests.delete(message.requestId)) {
        post({ type: 'cancelled', requestId: message.requestId, checked, total, elapsedMs });
        return;
      }

      const chunkEnd = Math.min(chunkStart + CHUNK_SIZE, message.endRegisterExclusive);
      const chunkStartedAt = performance.now();
      const result = findRegisterInRange({
        frameNumber: message.frameNumber,
        targetKeystream: new Uint8Array(message.targetKeystream),
        startRegister: chunkStart,
        endRegisterExclusive: chunkEnd,
      });
      elapsedMs += performance.now() - chunkStartedAt;

      if (result !== null) {
        checked += result.checked;
        post({
          type: 'found',
          requestId: message.requestId,
          register: result.register,
          checked,
          total,
          elapsedMs,
        });
        return;
      }

      checked += chunkEnd - chunkStart;
      post({ type: 'progress', requestId: message.requestId, checked, total, elapsedMs });
      await yieldToWorkerQueue();
    }

    post({ type: 'exhausted', requestId: message.requestId, checked, total, elapsedMs });
  } catch (error) {
    post({
      type: 'error',
      requestId: message.requestId,
      message: error instanceof Error ? error.message : 'Unknown worker error',
      checked,
      total,
      elapsedMs,
    });
  } finally {
    cancelledRequests.delete(message.requestId);
  }
}

workerScope.addEventListener('message', (event: MessageEvent<AttackRequest>) => {
  if (event.data.type === 'cancel') {
    cancelledRequests.add(event.data.requestId);
    return;
  }

  void runAttack(event.data);
});
