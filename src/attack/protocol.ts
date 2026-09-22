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

export type AttackResponse =
  | { type: 'progress'; requestId: number; checked: number; total: number }
  | { type: 'found'; requestId: number; register: number; checked: number; total: number }
  | { type: 'exhausted'; requestId: number; checked: number; total: number }
  | { type: 'cancelled'; requestId: number; checked: number; total: number }
  | { type: 'error'; requestId: number; message: string; checked: number; total: number };