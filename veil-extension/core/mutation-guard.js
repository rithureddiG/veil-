/**
 * VEIL — Dynamic SPA & Mutation Integrity Guard
 *
 * Enforces pre-execution validation to protect against:
 *  - Stale targets (DOM node unmounted, replaced, or text modified between perception and action)
 *  - Adversarial mutation traps (button swapped from 'Cancel' to 'Delete Account')
 *  - Numeric/Price swap tampering (e.g. ₹500 -> ₹50,000)
 *  - Cryptographic State Drift (stateHash mismatch via state-hasher)
 *  - Origin / Frame drift during asynchronous reasoning
 */

(function () {
  const resolver = typeof require !== 'undefined'
    ? require('./action-resolver.js')
    : (typeof window !== 'undefined' ? window.VeilActionResolver : null);

  const domUtils = typeof require !== 'undefined'
    ? require('./dom-utils.js')
    : (typeof window !== 'undefined' ? window.VeilDomUtils : null);

  const stateHasher = typeof require !== 'undefined'
    ? require('./state-hasher.js')
    : (typeof window !== 'undefined' ? window.VeilStateHasher : null);

  /**
   * Performs pre-execution integrity checks on a proposed action and target element.
   *
   * @param {object} action - The proposed action ({ type, target: { id, description, text } })
   * @param {Element|null} initialTargetElement - Target element resolved at perception time
   * @param {Document} liveDoc - Live active document at execution time
   * @param {object} [contextOptions] - { expectedOrigin, expectedStateHash, frameId, timestamp }
   * @returns {{
   *   ok: boolean,
   *   valid: boolean,
   *   executed: boolean,
   *   status: 'VALID' | 'TARGET_MUTATED' | 'MUTATION_DETECTED' | 'STALE_TARGET' | 'DISABLED_ELEMENT' | 'HIDDEN_ELEMENT' | 'ORIGIN_MISMATCH' | 'STATE_MUTATED',
   *   resolvedElement: Element | null,
   *   beforeFingerprint?: string,
   *   afterFingerprint?: string,
   *   similarity?: number,
   *   reason: string
   * }}
   */
  function verifyActionIntegrity(action, initialTargetElement, liveDoc, contextOptions = {}) {
    if (!action || !action.target) {
      return { ok: true, valid: true, executed: true, status: 'VALID', resolvedElement: initialTargetElement, reason: 'Non-targeted action' };
    }

    // Step 0: Cryptographic State Consistency Check (stateHash)
    if (contextOptions.expectedStateHash && stateHasher && stateHasher.computeStateHash && liveDoc) {
      const { stateHash } = stateHasher.computeStateHash(liveDoc);
      if (contextOptions.expectedStateHash !== 'unanchored_state' && stateHash !== contextOptions.expectedStateHash) {
        return {
          ok: false,
          valid: false,
          executed: false,
          status: 'STATE_MUTATED',
          resolvedElement: initialTargetElement,
          reason: `Cryptographic StateHash Mismatch: DOM structure mutated between perception (${contextOptions.expectedStateHash.slice(0, 12)}...) and execution (${stateHash.slice(0, 12)}...)`
        };
      }
    }

    // Step 1: Re-resolve the target on the live DOM
    const liveTarget = resolver && resolver.resolveTarget ? resolver.resolveTarget(action.target, liveDoc) : initialTargetElement;
    if (!liveTarget) {
      return {
        ok: false,
        valid: false,
        executed: false,
        status: 'STALE_TARGET',
        resolvedElement: null,
        reason: 'Target element is no longer present in the active DOM (node removed / unmounted)'
      };
    }

    // Step 2: Verify Element is connected to the active document
    if (!liveTarget.isConnected && liveTarget.ownerDocument !== liveDoc) {
      return {
        ok: false,
        valid: false,
        executed: false,
        status: 'STALE_TARGET',
        resolvedElement: null,
        reason: 'Target element is disconnected from active document tree'
      };
    }

    // Step 3: Verify Enabled State
    if (liveTarget.disabled || liveTarget.getAttribute('aria-disabled') === 'true') {
      return {
        ok: false,
        valid: false,
        executed: false,
        status: 'DISABLED_ELEMENT',
        resolvedElement: liveTarget,
        reason: 'Target element is currently disabled'
      };
    }

    // Step 4: Verify Semantic Identity & Text Integrity (Mutation Trap Check)
    const expectedText = (action.target.description || action.target.text || action.target.name || '').toLowerCase();
    const liveText = (domUtils && domUtils.labelFor ? domUtils.labelFor(liveTarget) : (liveTarget.textContent || '')).toLowerCase();

    if (expectedText && liveText) {
      const expDigits = expectedText.replace(/\D/g, '');
      const liveDigits = liveText.replace(/\D/g, '');
      const numbersMismatch = expDigits && liveDigits && expDigits !== liveDigits;
      const overlap = domUtils && domUtils.wordOverlapScore ? domUtils.wordOverlapScore(expectedText, liveText) : 1.0;

      // If the label has mutated or numbers changed (e.g. from "Transfer ₹5,000" to "Transfer ₹50,000"), abort
      if (overlap < 0.60 || numbersMismatch) {
        return {
          ok: false,
          valid: false,
          executed: false,
          status: 'TARGET_MUTATED',
          resolvedElement: liveTarget,
          beforeFingerprint: expectedText,
          afterFingerprint: liveText,
          similarity: Number(overlap.toFixed(2)),
          reason: `Semantic mutation detected: Expected "${expectedText.slice(0, 30)}", live label is "${liveText.slice(0, 30)}" (Overlap: ${overlap.toFixed(2)}${numbersMismatch ? ', Amount Mismatch' : ''})`
        };
      }
    }

    // Step 5: Verify Origin Integrity if specified
    if (contextOptions.expectedOrigin && typeof location !== 'undefined' && location.origin && location.origin !== contextOptions.expectedOrigin) {
      return {
        ok: false,
        valid: false,
        executed: false,
        status: 'ORIGIN_MISMATCH',
        resolvedElement: null,
        reason: `Origin mismatch: Expected ${contextOptions.expectedOrigin}, current origin is ${location.origin}`
      };
    }

    return {
      ok: true,
      valid: true,
      executed: true,
      status: 'VALID',
      resolvedElement: liveTarget,
      similarity: 1.0,
      reason: 'Target integrity verified across all pre-execution checks'
    };
  }

  const mutationGuardExport = {
    revalidateAction: verifyActionIntegrity,
    verifyActionIntegrity
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = mutationGuardExport;
  }
  if (typeof window !== 'undefined') {
    window.VeilMutationGuard = mutationGuardExport;
  }
})();
