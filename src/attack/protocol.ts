export interface StartAttackMessage {
  type: 'start';
  requestId: number;
  frameNumber: number;
  targetKeystream: number[];
  startRegister: number;
  endRegisterExclusive: number;
}

export interface CancelAttackMessage {
  type: 'cancel';
  requestId: number;
}

export type AttackRequest = StartAttackMessage | CancelAttackMessage;

// `elapsedMs` is the wall clock around the search loop that already runs. It adds
// no work and starts no second search; Exhibit 5 divides `checked` by it to get
// the only rate this page ever quotes.
interface AttackProgressFields {
  requestId: number;
  checked: number;
  total: number;
  elapsedMs: number;
}

export type AttackResponse =
  | ({ type: 'progress' } & AttackProgressFields)
  | ({ type: 'found'; register: number } & AttackProgressFields)
  | ({ type: 'exhausted' } & AttackProgressFields)
  | ({ type: 'cancelled' } & AttackProgressFields)
  | ({ type: 'error'; message: string } & AttackProgressFields);
