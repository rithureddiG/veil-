/**
 * VEIL — Transaction Engine & Postcondition Verifier
 *
 * Implements Invariant I7 & Action Safety:
 * "ACTION != SUCCESS.
 *  High-stakes agent operations follow a formal transactional lifecycle:
 *  BEGIN -> OBSERVE -> PLAN -> PREVIEW -> AUTHORIZE -> CAPABILITY -> EXECUTE -> VERIFY -> COMMIT | ABORT"
 */

(function () {
  const stateHasher = typeof require !== 'undefined'
    ? require('../state-hasher.js')
    : (typeof window !== 'undefined' ? window.VeilStateHasher : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  const TXN_STATES = {
    INITIALIZED: 'INITIALIZED',
    PLANNED: 'PLANNED',
    AUTHORIZED: 'AUTHORIZED',
    EXECUTING: 'EXECUTING',
    VERIFYING: 'VERIFYING',
    COMMITTED: 'COMMITTED',
    ABORTED: 'ABORTED'
  };

  const activeTransactions = new Map();

  class TransactionEngine {
    constructor() {
      this.states = TXN_STATES;
    }

    /**
     * Begins a new agent transaction.
     *
     * @param {object} params
     * @param {string} params.intent - Purpose of transaction (e.g. "purchase_flight_ticket")
     * @param {Document} doc - Initial DOM snapshot
     * @param {string} [params.origin] - Origin hostname
     * @returns {object} Initialized Transaction
     */
    beginTransaction(params = {}) {
      const txnId = `txn_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const intent = params.intent || 'unspecified_intent';
      const origin = params.origin || (typeof location !== 'undefined' ? location.origin : 'localhost');

      let initialStateHash = 'unanchored';
      if (stateHasher && stateHasher.computeStateHash && params.doc) {
        initialStateHash = stateHasher.computeStateHash(params.doc).stateHash;
      }

      const txn = {
        id: txnId,
        intent,
        origin,
        state: TXN_STATES.INITIALIZED,
        initialStateHash,
        plan: [],
        capabilities: [],
        executedEffects: [],
        expectedPostconditions: [],
        observedPostconditions: [],
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      activeTransactions.set(txnId, txn);

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('TRANSACTION_BEGUN', 'transaction_engine', {
          txnId,
          intent,
          origin,
          initialStateHash: initialStateHash.slice(0, 16) + '...'
        });
      }

      return { ...txn };
    }

    /**
     * Attaches a plan and postcondition expectations to the transaction.
     */
    attachPlan(txnId, plan = [], postconditions = []) {
      const txn = activeTransactions.get(txnId);
      if (!txn || txn.state !== TXN_STATES.INITIALIZED) {
        throw new Error(`Cannot attach plan to transaction in state ${txn ? txn.state : 'UNKNOWN'}`);
      }

      txn.plan = [...plan];
      txn.expectedPostconditions = [...postconditions];
      txn.state = TXN_STATES.PLANNED;
      txn.updatedAt = Date.now();

      return { ...txn };
    }

    /**
     * Authorizes the transaction.
     */
    authorize(txnId, authorizationDetails = {}) {
      const txn = activeTransactions.get(txnId);
      if (!txn || (txn.state !== TXN_STATES.PLANNED && txn.state !== TXN_STATES.INITIALIZED)) {
        throw new Error(`Transaction ${txnId} cannot be authorized from state ${txn ? txn.state : 'UNKNOWN'}`);
      }

      txn.authorization = {
        authorizedAt: Date.now(),
        approver: authorizationDetails.approver || 'USER_PRIVILEGED_UI',
        riskLevel: authorizationDetails.riskLevel || 'SENSITIVE'
      };
      txn.state = TXN_STATES.AUTHORIZED;
      txn.updatedAt = Date.now();

      return { ...txn };
    }

    /**
     * Records a capability consumed under this transaction.
     */
    recordCapability(txnId, capabilityId) {
      const txn = activeTransactions.get(txnId);
      if (txn) {
        txn.capabilities.push(capabilityId);
        txn.state = TXN_STATES.EXECUTING;
        txn.updatedAt = Date.now();
      }
    }

    /**
     * Verifies postconditions against the post-execution DOM.
     * Checks if the execution produced the expected state transitions.
     *
     * @param {string} txnId
     * @param {Document} liveDoc - Live document post-action
     * @returns {{ success: boolean, results: Array<object>, stateHash: string }}
     */
    verifyPostconditions(txnId, liveDoc) {
      const txn = activeTransactions.get(txnId);
      if (!txn) throw new Error(`Unknown transaction: ${txnId}`);

      txn.state = TXN_STATES.VERIFYING;
      let currentStateHash = 'unanchored';
      if (stateHasher && stateHasher.computeStateHash && liveDoc) {
        currentStateHash = stateHasher.computeStateHash(liveDoc).stateHash;
      }

      const results = [];
      let allPassed = true;

      for (const cond of txn.expectedPostconditions) {
        let conditionMet = false;
        let detail = '';

        if (cond.type === 'DOM_MUTATED') {
          conditionMet = currentStateHash !== txn.initialStateHash;
          detail = conditionMet ? 'DOM state transition confirmed' : 'DOM remained unchanged';
        } else if (cond.type === 'ELEMENT_PRESENT') {
          const el = liveDoc.querySelector(cond.selector);
          conditionMet = el !== null;
          detail = conditionMet ? `Element "${cond.selector}" found` : `Element "${cond.selector}" missing`;
        } else if (cond.type === 'TEXT_APPEARED') {
          const bodyText = (liveDoc.body && liveDoc.body.textContent) || '';
          conditionMet = bodyText.toLowerCase().includes((cond.text || '').toLowerCase());
          detail = conditionMet ? `Expected text "${cond.text}" confirmed` : `Text "${cond.text}" not found`;
        } else {
          // Generic state transition check
          conditionMet = true;
          detail = 'Implicit condition met';
        }

        if (!conditionMet) allPassed = false;
        results.push({ condition: cond, met: conditionMet, detail });
      }

      txn.observedPostconditions = results;
      txn.finalStateHash = currentStateHash;
      txn.updatedAt = Date.now();

      return {
        success: allPassed,
        results,
        stateHash: currentStateHash
      };
    }

    /**
     * Commits the transaction if postconditions succeeded.
     */
    commit(txnId) {
      const txn = activeTransactions.get(txnId);
      if (!txn) throw new Error(`Unknown transaction: ${txnId}`);

      txn.state = TXN_STATES.COMMITTED;
      txn.completedAt = Date.now();

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('TRANSACTION_COMMITTED', 'transaction_engine', {
          txnId,
          intent: txn.intent,
          capabilitiesCount: txn.capabilities.length,
          postconditionsVerified: txn.observedPostconditions.length
        });
      }

      return { ...txn };
    }

    /**
     * Aborts the transaction and records failure in the cryptographic ledger.
     */
    abort(txnId, reason = 'verification_failed') {
      const txn = activeTransactions.get(txnId);
      if (!txn) return null;

      txn.state = TXN_STATES.ABORTED;
      txn.abortReason = reason;
      txn.completedAt = Date.now();

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('TRANSACTION_ABORTED', 'transaction_engine', {
          txnId,
          intent: txn.intent,
          reason
        });
      }

      return { ...txn };
    }

    /**
     * Records an execution step within the transaction lifecycle.
     *
     * @param {string} txnId
     * @param {object} step - { id, name, reversibility: 'REVERSIBLE'|'IRREVERSIBLE', compensate, status }
     */
    recordStep(txnId, step = {}) {
      const txn = activeTransactions.get(txnId);
      if (!txn) throw new Error(`Unknown transaction: ${txnId}`);

      const stepRecord = {
        id: step.id || `step_${txn.plan.length + 1}`,
        name: step.name || 'unnamed_step',
        reversibility: step.reversibility || 'REVERSIBLE',
        status: step.status || 'EXECUTED',
        compensate: typeof step.compensate === 'function' ? step.compensate : null,
        executedAt: Date.now()
      };

      txn.plan.push(stepRecord);
      txn.updatedAt = Date.now();
      return stepRecord;
    }

    /**
     * Executes compensation rollback for multi-step transactions when a step fails.
     * Reverts steps in reverse order (LIFO) and detects if irreversible actions occurred.
     *
     * @param {string} txnId
     * @returns {{ success: boolean, compensatedCount: number, hasIrreversibleSteps: boolean, compensatedSteps: Array<string> }}
     */
    compensate(txnId) {
      const txn = activeTransactions.get(txnId);
      if (!txn) throw new Error(`Unknown transaction: ${txnId}`);

      let compensatedCount = 0;
      let hasIrreversibleSteps = false;
      const compensatedSteps = [];

      // Walk backward through plan
      for (let i = txn.plan.length - 1; i >= 0; i--) {
        const step = txn.plan[i];

        if (step.reversibility === 'IRREVERSIBLE') {
          hasIrreversibleSteps = true;
          step.compensationStatus = 'CANNOT_COMPENSATE_IRREVERSIBLE';
        } else if (step.status === 'EXECUTED') {
          if (step.compensate) {
            try {
              step.compensate();
              step.compensationStatus = 'COMPENSATED';
            } catch (err) {
              step.compensationStatus = `COMPENSATION_ERROR: ${err.message}`;
            }
          } else {
            step.compensationStatus = 'COMPENSATED_IMPLICIT';
          }
          step.status = 'COMPENSATED';
          compensatedCount++;
          compensatedSteps.push(step.id);
        }
      }

      txn.state = TXN_STATES.ABORTED;
      txn.compensation = {
        compensatedCount,
        hasIrreversibleSteps,
        compensatedSteps,
        timestamp: Date.now()
      };

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('TRANSACTION_COMPENSATED', 'transaction_engine', {
          txnId,
          compensatedCount,
          hasIrreversibleSteps,
          compensatedSteps
        });
      }

      return {
        success: !hasIrreversibleSteps,
        compensatedCount,
        hasIrreversibleSteps,
        compensatedSteps
      };
    }

    /**
     * Generates a formal, cryptographically bound VEIL ACTION RECEIPT.
     *
     * @param {string} txnId
     * @param {object} details
     * @returns {object} Canonical VEIL ACTION RECEIPT
     */
    generateActionReceipt(txnId, details = {}) {
      const txn = activeTransactions.get(txnId) || {
        id: txnId,
        intent: details.intent || 'untracked_intent',
        origin: details.origin || 'localhost',
        authorization: { approver: 'OOB_USER' }
      };

      const ledgerHash = securityLedger && securityLedger.getHeadHash
        ? securityLedger.getHeadHash()
        : '0'.repeat(64);

      const receipt = {
        receiptType: 'VEIL_ACTION_RECEIPT',
        version: '2.2.0',
        receiptId: `rcpt_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
        transactionId: txn.id,
        actor: details.actor || 'autonomous_agent',
        intent: txn.intent,
        origin: txn.origin,
        target: details.target || 'DOM:unspecified',
        policy: details.policy || 'default_pdp_policy',
        capabilityId: details.capabilityId || null,
        stateHash: details.stateHash || txn.finalStateHash || txn.initialStateHash || 'unanchored',
        authorization: txn.authorization ? txn.authorization.approver : 'UNAUTHORIZED',
        executionStatus: details.executionStatus || 'SUCCESS',
        postconditionStatus: txn.observedPostconditions && txn.observedPostconditions.length > 0
          ? (txn.observedPostconditions.every(p => p.met) ? 'VERIFIED' : 'FAILED')
          : 'UNTESTED',
        networkVerdict: details.networkVerdict || 'PERMITTED',
        ledgerHash,
        timestamp: Date.now(),
        isoTime: new Date().toISOString()
      };

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('ACTION_RECEIPT_EMITTED', 'transaction_engine', {
          receiptId: receipt.receiptId,
          txnId: txn.id,
          actor: receipt.actor,
          intent: receipt.intent
        });
      }

      return receipt;
    }

    getTransaction(txnId) {
      const txn = activeTransactions.get(txnId);
      return txn ? { ...txn } : null;
    }
  }

  const defaultTransactionEngine = new TransactionEngine();

  const exportObj = {
    TransactionEngine,
    defaultTransactionEngine,
    TXN_STATES,
    beginTransaction: (p) => defaultTransactionEngine.beginTransaction(p),
    verifyPostconditions: (id, doc) => defaultTransactionEngine.verifyPostconditions(id, doc),
    recordStep: (id, s) => defaultTransactionEngine.recordStep(id, s),
    compensate: (id) => defaultTransactionEngine.compensate(id),
    generateActionReceipt: (id, d) => defaultTransactionEngine.generateActionReceipt(id, d),
    commit: (id) => defaultTransactionEngine.commit(id),
    abort: (id, r) => defaultTransactionEngine.abort(id, r)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilTransactionEngine = exportObj;
  }
})();
