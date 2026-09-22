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

  try {
    for (
      let chunkStart = message.startRegister;
      chunkStart < message.endRegisterExclusive;
      chunkStart += CHUNK_SIZE
    ) {
      if (cancelledRequests.delete(message.requestId)) {
        post({ type: 'cancelled', requestId: message.requestId, checked, total });
        return;
      }

      const chunkEnd = Math.min(chunkStart + CHUNK_SIZE, message.endRegisterExclusive);
      const result = findRegisterInRange({
        frameNumber: message.frameNumber,
        targetKeystream: new Uint8Array(message.targetKeystream),
        startRegister: chunkStart,
        endRegisterExclusive: chunkEnd,
      });

      if (result !== null) {
        checked += result.checked;
        post({
          type: 'found',
          requestId: message.requestId,
          register: result.register,
          checked,
          total,
        });
        return;
      }

      checked += chunkEnd - chunkStart;
      post({ type: 'progress', requestId: message.requestId, checked, total });
      await yieldToWorkerQueue();
    }

    post({ type: 'exhausted', requestId: message.requestId, checked, total });
  } catch (error) {
    post({
      type: 'error',
      requestId: message.requestId,
      message: error instanceof Error ? error.message : 'Unknown worker error',
      checked,
      total,
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