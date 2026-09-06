/**
 * VEIL — Pure Mathematical State Machine Specification
 *
 * Zero-dependency deterministic formal model of the VEIL Security Kernel.
 */

const STATES = {
  IDLE: 'IDLE',
  REQUESTED: 'REQUESTED',
  EVALUATING: 'EVALUATING',
  AUTHORIZED: 'AUTHORIZED',
  CAPABILITY_ISSUED: 'CAPABILITY_ISSUED',
  EXECUTING: 'EXECUTING',
  VERIFYING: 'VERIFYING',
  COMMITTED: 'COMMITTED',
  ABORTED: 'ABORTED'
};

const TRANSITIONS = {
  [`${STATES.IDLE}:PROPOSAL`]: STATES.REQUESTED,
  [`${STATES.REQUESTED}:EVALUATE`]: STATES.EVALUATING,
  [`${STATES.EVALUATING}:POLICY_ALLOW`]: STATES.AUTHORIZED,
  [`${STATES.EVALUATING}:POLICY_DENY`]: STATES.ABORTED,
  [`${STATES.AUTHORIZED}:MINT_CAPABILITY`]: STATES.CAPABILITY_ISSUED,
  [`${STATES.CAPABILITY_ISSUED}:CONSUME_CAPABILITY`]: STATES.EXECUTING,
  [`${STATES.CAPABILITY_ISSUED}:REPLAY_CAPABILITY`]: STATES.ABORTED,
  [`${STATES.CAPABILITY_ISSUED}:STATE_MISMATCH`]: STATES.ABORTED,
  [`${STATES.EXECUTING}:DISPATCH_EFFECT`]: STATES.VERIFYING,
  [`${STATES.VERIFYING}:POSTCONDITION_PASS`]: STATES.COMMITTED,
  [`${STATES.VERIFYING}:POSTCONDITION_FAIL`]: STATES.ABORTED
};

class PureStateMachine {
  constructor(initialState = STATES.IDLE) {
    this.currentState = initialState;
    this.history = [initialState];
  }

  transition(input) {
    const key = `${this.currentState}:${input}`;
    const nextState = TRANSITIONS[key];

    if (!nextState) {
      // Invalid transition fails closed to ABORTED
      this.currentState = STATES.ABORTED;
      this.history.push(STATES.ABORTED);
      return { ok: false, state: STATES.ABORTED, error: `Invalid transition from ${this.history[this.history.length - 2]} on input ${input}` };
    }

    this.currentState = nextState;
    this.history.push(nextState);
    return { ok: true, state: nextState };
  }

  getState() {
    return this.currentState;
  }

  isTerminal() {
    return this.currentState === STATES.COMMITTED || this.currentState === STATES.ABORTED;
  }
}

module.exports = {
  STATES,
  TRANSITIONS,
  PureStateMachine
};
