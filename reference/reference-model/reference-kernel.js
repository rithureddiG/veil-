/**
 * VEIL — Reference Kernel Implementation (Formal Model)
 *
 * Minimal, zero-dependency, mathematically pure reference kernel.
 * Implements: Request ➔ Decision ➔ Capability ➔ Execute ➔ Verify ➔ Receipt
 */

const crypto = require('crypto');
const { STATES, PureStateMachine } = require('../state-machine/state-machine');

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

class ReferenceKernel {
  constructor() {
    this.fsm = new PureStateMachine();
    this.secret = 'REF_KERNEL_SECRET_9876543210';
    this.issuedCapabilities = new Map();
    this.ledger = [];
  }

  /**
   * Evaluates an abstract request against pure policy.
   */
  evaluateRequest(proposal, policyRule = { allow: true }) {
    this.fsm.transition('PROPOSAL');
    this.fsm.transition('EVALUATE');

    if (!policyRule.allow || proposal.intent === 'unauthorized_intent') {
      this.fsm.transition('POLICY_DENY');
      return { decision: 'DENY', allowed: false };
    }

    this.fsm.transition('POLICY_ALLOW');
    return { decision: 'ALLOW', allowed: true };
  }

  /**
   * Mints a reference capability token.
   */
  mintCapability(params) {
    if (this.fsm.getState() !== STATES.AUTHORIZED) {
      throw new Error(`Cannot mint capability in state ${this.fsm.getState()}`);
    }

    const capabilityId = `ref_cap_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const canonical = `${capabilityId}:${params.actionType}:${params.stateHash}:${this.secret}`;
    const signature = sha256(canonical);

    const token = {
      capabilityId,
      actionType: params.actionType,
      stateHash: params.stateHash,
      consumed: false,
      signature
    };

    this.issuedCapabilities.set(capabilityId, token);
    this.fsm.transition('MINT_CAPABILITY');
    return { ...token };
  }

  /**
   * Consumes capability and executes pure side effect.
   */
  executeEffect(capabilityId, contextStateHash) {
    const token = this.issuedCapabilities.get(capabilityId);

    if (!token) {
      this.fsm.transition('REPLAY_CAPABILITY');
      return { success: false, reason: 'Capability does not exist' };
    }

    if (token.consumed) {
      this.fsm.transition('REPLAY_CAPABILITY');
      return { success: false, reason: 'Capability already consumed (Replay Attack)' };
    }

    if (token.stateHash !== contextStateHash) {
      this.fsm.transition('STATE_MISMATCH');
      return { success: false, reason: 'State mismatch (TOCTOU Attack)' };
    }

    // Atomically consume
    token.consumed = true;
    this.fsm.transition('CONSUME_CAPABILITY');
    this.fsm.transition('DISPATCH_EFFECT');

    return { success: true };
  }

  /**
   * Verifies postcondition and emits receipt.
   */
  verifyAndCommit(postconditionMet = true) {
    if (postconditionMet) {
      this.fsm.transition('POSTCONDITION_PASS');
      const receipt = {
        receiptType: 'REF_ACTION_RECEIPT',
        status: 'COMMITTED',
        timestamp: Date.now(),
        headHash: sha256(`RECEIPT:${Date.now()}`)
      };
      this.ledger.push(receipt);
      return { committed: true, receipt };
    } else {
      this.fsm.transition('POSTCONDITION_FAIL');
      return { committed: false, state: STATES.ABORTED };
    }
  }

  getState() {
    return this.fsm.getState();
  }
}

module.exports = {
  ReferenceKernel
};
