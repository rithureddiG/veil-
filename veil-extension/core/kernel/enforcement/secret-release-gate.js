/**
 * VEIL — Secret Release Gate (Enforcement Boundary)
 *
 * Implements Invariant I5 & C5:
 * "Secret values never enter model-visible context or client event loops.
 *  They are injected exclusively at the native DOM boundary by the privileged Kernel gate."
 *
 * Capabilities & Security Properties:
 *   - Origin verification: Secret must match the destination origin.
 *   - Field verification: Secret must match the authorized field target.
 *   - Capability verification: Must hold an active, non-replayed CAPABILITY_TOKEN.
 *   - Event scrub: Dispatches synthetic events without exposing plaintext in event properties.
 */

(function () {
  const secretVault = typeof require !== 'undefined'
    ? require('../../../core/secret-vault.js')
    : (typeof window !== 'undefined' ? window.VeilSecretVault : null);

  const capabilityManager = typeof require !== 'undefined'
    ? require('../../../core/capability-manager.js')
    : (typeof window !== 'undefined' ? window.VeilCapabilityManager : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  /**
   * Releases and injects a secret into a target DOM element under strict kernel mediation.
   *
   * @param {object} params
   * @param {string} params.secretId - Secret reference ID (e.g., 'credential://login/password/01' or 'LOCAL_SECRET_01')
   * @param {Element} params.targetElement - Target input DOM element
   * @param {string} params.origin - Target origin
   * @param {string} params.capabilityId - Authorized capability ID
   * @param {string} [params.stateHash] - Anchored DOM state hash
   * @returns {{ success: boolean, reason?: string, injectedSecretId?: string }}
   */
  function releaseSecretToElement(params = {}) {
    const { secretId, targetElement, origin, capabilityId, stateHash } = params;

    if (!targetElement) {
      return { success: false, reason: 'Target element is null or undefined' };
    }

    if (!capabilityId) {
      return { success: false, reason: 'Secret release requires explicit capabilityId' };
    }

    // 1. Verify and consume capability
    if (capabilityManager && capabilityManager.consumeCapability) {
      const consumeRes = capabilityManager.consumeCapability(capabilityId, {
        origin,
        actionType: 'TYPE',
        stateHash
      });

      if (!consumeRes.ok) {
        return {
          success: false,
          reason: `Secret release blocked: capability invalid (${consumeRes.reason})`
        };
      }
    }

    // 2. Resolve secret from isolated vault
    const fieldIdentifier = targetElement.getAttribute('name') ||
                            targetElement.getAttribute('id') ||
                            targetElement.getAttribute('autocomplete') || '';

    let resolved;
    if (secretVault && secretVault.resolveSecret) {
      resolved = secretVault.resolveSecret(secretId, origin, fieldIdentifier);
    } else {
      resolved = { ok: false, reason: 'Secret vault unavailable' };
    }

    if (!resolved.ok) {
      return { success: false, reason: `Vault resolution failed: ${resolved.reason}` };
    }

    // 3. Inject directly into DOM property — native boundary execution
    try {
      if (typeof targetElement.focus === 'function') targetElement.focus();
      targetElement.value = resolved.value;

      const win = (targetElement.ownerDocument && targetElement.ownerDocument.defaultView) ||
                  (typeof window !== 'undefined' ? window : globalThis);

      if (win && win.Event) {
        targetElement.dispatchEvent(new win.Event('input', { bubbles: true }));
        targetElement.dispatchEvent(new win.Event('change', { bubbles: true }));
        if (typeof targetElement.blur === 'function') targetElement.blur();
      }

      // Record release event in audit ledger without exposing plaintext secret value
      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('SECRET_RELEASED_TO_DOM', 'enforcement_boundary', {
          secretId: resolved.secretId,
          label: resolved.label,
          origin,
          targetTag: targetElement.tagName,
          capabilityId
        });
      }

      return {
        success: true,
        injectedSecretId: resolved.secretId,
        label: resolved.label
      };
    } catch (err) {
      return { success: false, reason: `DOM injection error: ${err.message}` };
    }
  }

  const exportObj = {
    releaseSecretToElement
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilSecretReleaseGate = exportObj;
  }
})();
