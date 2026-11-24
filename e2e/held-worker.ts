import type { Page } from '@playwright/test';
import type { AttackResponse } from '../src/attack/protocol';

declare global {
  interface Window {
    heldReplies: { recipient: EventTarget; data: AttackResponse }[];
    heldWorkers: EventTarget[];
  }
}

/** Delay delivery, not the work: every normal answer comes from the real worker. */
export async function holdRealWorkerReplies(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.heldReplies = [];
    window.heldWorkers = [];
    class HeldWorker extends EventTarget {
      worker: Worker;
      constructor(url: string | URL, options?: WorkerOptions) {
        super();
        window.heldWorkers.push(this);
        this.worker = new NativeWorker(url, options);
        this.worker.addEventListener('message', (event: MessageEvent<AttackResponse>) => {
          window.heldReplies.push({ recipient: this, data: event.data });
        });
        this.worker.addEventListener('error', () => this.dispatchEvent(new Event('error')));
      }
      postMessage(message: unknown): void { this.worker.postMessage(message); }
      terminate(): void { this.worker.terminate(); }
    }
    window.Worker = HeldWorker as unknown as typeof Worker;
  });
  await page.reload();
}

export async function waitForHeldAnswer(page: Page, requestId = 1): Promise<void> {
  await page.waitForFunction((id) => window.heldReplies.some(({ data }) => data.type === 'found' && data.requestId === id), requestId);
}

export async function releaseReplies(page: Page, requestId = 1, mutation?: 'register' | 'clock' | 'slow'): Promise<void> {
  await page.evaluate(({ id, mutate }) => {
    const matching = window.heldReplies.filter(({ data }) => data.requestId === id);
    window.heldReplies = window.heldReplies.filter(({ data }) => data.requestId !== id);
    for (const { recipient, data } of matching) {
      if (mutate === 'register' && data.type === 'found') data.register ^= 1;
      if (mutate === 'clock') data.elapsedMs = 0;
      if (mutate === 'slow') data.elapsedMs = data.checked * 10_000;
      recipient.dispatchEvent(new MessageEvent('message', { data }));
    }
  }, { id: requestId, mutate: mutation });
}
