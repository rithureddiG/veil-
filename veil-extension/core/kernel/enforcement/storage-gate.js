/**
 * VEIL — Storage Gate (Enforcement Boundary)
 *
 * Implements Invariant I5, I6 & C1:
 * "Mediates writes to localStorage, sessionStorage, and cookies.
 *  Prevents tainted credentials from being persisted in unencrypted client storage."
 */

(function () {
  const taintEngine = typeof require !== 'undefined'
    ? require('../../../core/kernel/taint-engine.js')
    : (typeof window !== 'undefined' ? window.VeilTaintEngine : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  /**
   * Evaluates a storage write operation.
   *
   * @param {string} storageType - 'localStorage' | 'sessionStorage' | 'cookie'
   * @param {string} key
   * @param {string} value
   * @param {object} options - { valueTaint, capabilityId }
   * @returns {{ allowed: boolean, reason?: string }}
   */
  function inspectStorageWrite(storageType, key, value, options = {}) {
    const keyLower = String(key || '').toLowerCase();
    const valLower = String(value || '').toLowerCase();

    // 1. Check for plaintext secret patterns
    if (keyLower.includes('password') || keyLower.includes('secret') || keyLower.includes('cvv') || keyLower.includes('private_key')) {
      return {
        allowed: false,
        reason: `Storage Gate: Plaintext secret storage forbidden for key "${key}"`
      };
    }

    // 2. Check value taint
    if (options.valueTaint && taintEngine && taintEngine.canFlow) {
      const flowRes = taintEngine.canFlow(options.valueTaint, taintEngine.SINKS.LOCAL_STORAGE);
      if (!flowRes.allowed) {
        return {
          allowed: false,
          reason: flowRes.reason
        };
      }
    }

    if (securityLedger && securityLedger.recordEvent) {
      securityLedger.recordEvent('STORAGE_WRITE_PERMITTED', 'storage_gate', {
        storageType,
        key: keyLower
      });
    }

    return { allowed: true };
  }

  const exportObj = {
    inspectStorageWrite
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilStorageGate = exportObj;
  }
})();
