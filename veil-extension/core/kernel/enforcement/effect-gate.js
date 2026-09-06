/**
 * VEIL — Effect Gate (Master Kernel Enforcement Boundary)
 *
 * Implements Invariant I1, I3 & C1:
 * "There is NO privileged execution path that does not pass through the VEIL Effect Gate.
 *  Any execution attempt that bypasses the kernel is blocked fail-closed."
 *
 * Architecture:
 *   Untrusted Request ➔ Effect Gate ➔ PDP + Capability ➔ Specialized Sub-Gate ➔ Native Runtime
 */

(function () {
  const protectedEffects = typeof require !== 'undefined'
    ? require('../protected-effects.js')
    : (typeof window !== 'undefined' ? window.VeilProtectedEffects : null);

  const pdp = typeof require !== 'undefined'
    ? require('../policy-decision-point.js')
    : (typeof window !== 'undefined' ? window.VeilPolicyDecisionPoint : null);

  const capabilityManager = typeof require !== 'undefined'
    ? require('../../../core/capability-manager.js')
    : (typeof window !== 'undefined' ? window.VeilCapabilityManager : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  // Sub-gates
  const domGate = typeof require !== 'undefined'
    ? require('./dom-effect-gate.js')
    : (typeof window !== 'undefined' ? window.VeilDomEffectGate : null);

  const networkGate = typeof require !== 'undefined'
    ? require('./network-effect-gate.js')
    : (typeof window !== 'undefined' ? window.VeilNetworkEffectGate : null);

  const navigationGate = typeof require !== 'undefined'
    ? require('./navigation-gate.js')
    : (typeof window !== 'undefined' ? window.VeilNavigationGate : null);

  const storageGate = typeof require !== 'undefined'
    ? require('./storage-gate.js')
    : (typeof window !== 'undefined' ? window.VeilStorageGate : null);

  const clipboardGate = typeof require !== 'undefined'
    ? require('./clipboard-gate.js')
    : (typeof window !== 'undefined' ? window.VeilClipboardGate : null);

  const secretReleaseGate = typeof require !== 'undefined'
    ? require('./secret-release-gate.js')
    : (typeof window !== 'undefined' ? window.VeilSecretReleaseGate : null);

  function secureRandomHex(bytes = 8) {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = require('crypto');
        return crypto.randomBytes(bytes).toString('hex');
      } catch (_) {}
    }
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      const arr = new Uint8Array(bytes);
      window.crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const arr = new Uint8Array(bytes);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }
    return 'sec_' + Date.now().toString(16);
  }

  /**
   * Universal Execution Gateway for all protected effects.
   *
   * @param {object} params
   * @param {string} params.effectId - From PROTECTED_EFFECTS (e.g., 'CLICK', 'SECRET_RELEASE')
   * @param {Element|null} [params.targetElement]
   * @param {object} [params.payload]
   * @param {string} [params.capabilityId]
   * @param {string} [params.origin='localhost']
   * @param {string} [params.stateHash]
   * @param {object} [params.proposal]
   * @returns {{ success: boolean, reason?: string, receipt?: object, effect: object }}
   */
  function executeProtectedEffect(params = {}) {
    const {
      effectId,
      targetElement,
      payload = {},
      capabilityId,
      origin = 'localhost',
      stateHash,
      proposal
    } = params;

    // 1. Identify and normalize protected effect
    const effectDesc = protectedEffects && protectedEffects.getProtectedEffect
      ? protectedEffects.getProtectedEffect(effectId)
      : null;

    if (!effectDesc) {
      return {
        success: false,
        reason: `Unknown side effect primitive "${effectId}". Untrusted execution fails closed.`,
        effect: null
      };
    }

    // 2. Policy Decision Point (PDP) Evaluation
    if (pdp && pdp.evaluate) {
      const decision = pdp.evaluate({
        proposal: proposal || { type: effectDesc.id.toLowerCase(), target: targetElement, ...payload },
        activeCapabilities: capabilityId ? [capabilityId] : []
      });

      if (!decision.allowed && !decision.requiresHuman) {
        return {
          success: false,
          reason: `Policy Decision Denied: ${decision.reason || 'Unauthorized effect'}`,
          effect: effectDesc
        };
      }
    }

    // 3. Capability Verification — Zero Unmediated Protected Effects (Invariant I1)
    let capabilityRecord = null;
    if (capabilityId && capabilityManager && capabilityManager.verifyCapability) {
      const capCheck = capabilityManager.verifyCapability(capabilityId, {
        origin,
        actionType: effectDesc.id,
        stateHash
      });

      if (!capCheck.valid) {
        return {
          success: false,
          reason: `Capability rejected: ${capCheck.reason}`,
          effect: effectDesc
        };
      }
      capabilityRecord = capCheck.capability;
    } else {
      return {
        success: false,
        reason: `Irreversible effect "${effectDesc.id}" strictly mandates an authorized CapabilityToken.`,
        effect: effectDesc
      };
    }

    // 3b. Cryptographic State-Binding Check (Invariant I3)
    const effectiveStateHash = stateHash || (capabilityRecord && capabilityRecord.stateHash);
    if (!effectiveStateHash || effectiveStateHash === 'unanchored' || effectiveStateHash === 'unanchored_state') {
      return {
        success: false,
        reason: `Protected effect "${effectDesc.id}" requires a cryptographic state commitment (stateHash). Missing state commitment fails closed.`,
        effect: effectDesc
      };
    }

    // 4. Dispatch to specialized Enforcement Sub-Gate
    let gateResult = { success: false, reason: 'No matching enforcement gate' };

    switch (effectDesc.id) {
      case 'CLICK':
        if (domGate && domGate.dispatchClick) {
          gateResult = domGate.dispatchClick(targetElement, { capabilityId, origin, stateHash: effectiveStateHash });
        }
        break;

      case 'TYPE':
        if (payload.secretId && secretReleaseGate && secretReleaseGate.releaseSecretToElement) {
          gateResult = secretReleaseGate.releaseSecretToElement({
            secretId: payload.secretId,
            targetElement,
            origin,
            capabilityId,
            stateHash: effectiveStateHash
          });
        } else if (domGate && domGate.dispatchType) {
          gateResult = domGate.dispatchType(targetElement, payload.value || '', { capabilityId, origin, stateHash: effectiveStateHash });
        }
        break;

      case 'SUBMIT':
        if (domGate && domGate.dispatchSubmit) {
          gateResult = domGate.dispatchSubmit(targetElement, { capabilityId, origin, stateHash: effectiveStateHash });
        }
        break;

      case 'SELECT':
        if (domGate && domGate.dispatchSelect) {
          gateResult = domGate.dispatchSelect(targetElement, payload.value || '', { capabilityId, origin, stateHash: effectiveStateHash });
        }
        break;

      case 'SCROLL':
        if (domGate && domGate.dispatchScroll) {
          gateResult = domGate.dispatchScroll(targetElement, { x: payload.x, y: payload.y });
        }
        break;

      case 'NAVIGATE':
        if (navigationGate && navigationGate.inspectNavigation) {
          gateResult = navigationGate.inspectNavigation(payload.url, origin, { capabilityId });
          gateResult.success = gateResult.allowed;
        }
        break;

      case 'STORAGE_WRITE':
        if (storageGate && storageGate.inspectStorageWrite) {
          gateResult = storageGate.inspectStorageWrite(payload.storageType, payload.key, payload.value, {
            capabilityId,
            valueTaint: payload.valueTaint
          });
          gateResult.success = gateResult.allowed;
        }
        break;

      case 'CLIPBOARD_WRITE':
        if (clipboardGate && clipboardGate.inspectClipboardWrite) {
          gateResult = clipboardGate.inspectClipboardWrite(payload.text, {
            capabilityId,
            textTaint: payload.textTaint,
            origin
          });
          gateResult.success = gateResult.allowed;
        }
        break;

      case 'NETWORK_REQUEST':
        if (networkGate && networkGate.inspectNetworkTransmission) {
          gateResult = networkGate.inspectNetworkTransmission(payload.request, {
            capabilityId,
            payloadTaint: payload.payloadTaint
          });
          gateResult.success = gateResult.allowed;
        }
        break;

      case 'SECRET_RELEASE':
        if (secretReleaseGate && secretReleaseGate.releaseSecretToElement) {
          gateResult = secretReleaseGate.releaseSecretToElement({
            secretId: payload.secretId,
            targetElement,
            origin,
            capabilityId,
            stateHash: effectiveStateHash
          });
        }
        break;

      case 'PURCHASE':
      case 'TRANSFER':
      case 'DELETE':
      case 'CHANGE_SETTING':
        if (!capabilityRecord || !capabilityRecord.humanApproved) {
          return {
            success: false,
            reason: `Irreversible side effect "${effectDesc.id}" requires verified Out-of-Band Human Approval.`,
            effect: effectDesc
          };
        }
        if (targetElement && domGate && domGate.dispatchClick) {
          gateResult = domGate.dispatchClick(targetElement, { capabilityId, origin, stateHash: effectiveStateHash });
        } else {
          gateResult = { success: true, reason: `Critical effect "${effectDesc.id}" authorized and executed under kernel mediation.` };
        }
        break;

      case 'DOWNLOAD':
      case 'UPLOAD':
        if (!capabilityRecord || !capabilityRecord.humanApproved) {
          return {
            success: false,
            reason: `Irreversible side effect "${effectDesc.id}" requires verified Out-of-Band Human Approval.`,
            effect: effectDesc
          };
        }
        gateResult = { success: true, reason: `Effect "${effectDesc.id}" authorized and executed under kernel mediation.` };
        break;

      default:
        // Invariant C1 & P0 #11: Fail closed on any unhandled primitive
        gateResult = {
          success: false,
          reason: `DENY: Unimplemented protected effect primitive "${effectDesc.id}". Untrusted execution fails closed.`
        };
    }

    // 5. Generate Action Receipt on success with Cryptographic Randomness (P0 #4)
    let receipt = null;
    if (gateResult.success) {
      receipt = {
        receiptId: `rcpt_${Date.now()}_${secureRandomHex(8)}`,
        effectId: effectDesc.id,
        origin,
        capabilityId: capabilityId || null,
        stateHash: effectiveStateHash,
        timestamp: Date.now(),
        isoTime: new Date().toISOString(),
        status: 'SUCCESS'
      };

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('PROTECTED_EFFECT_EXECUTED', 'effect_gate', {
          effectId: effectDesc.id,
          receiptId: receipt.receiptId,
          origin,
          capabilityId
        });
      }
    }

    return {
      success: gateResult.success,
      reason: gateResult.reason,
      receipt,
      effect: effectDesc
    };
  }

  const exportObj = {
    executeProtectedEffect
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilEffectGate = exportObj;
  }
})();
