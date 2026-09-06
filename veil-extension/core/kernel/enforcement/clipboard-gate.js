/**
 * VEIL — Clipboard Gate (Enforcement Boundary)
 *
 * Implements Invariant I5, I6 & C1:
 * "Mediates clipboard read and write operations.
 *  Prevents arbitrary script execution or prompt injection payloads from hijacking the system clipboard."
 */

(function () {
  const taintEngine = typeof require !== 'undefined'
    ? require('../../../core/kernel/taint-engine.js')
    : (typeof window !== 'undefined' ? window.VeilTaintEngine : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  const capabilityManager = typeof require !== 'undefined'
    ? require('../../../core/capability-manager.js')
    : (typeof window !== 'undefined' ? window.VeilCapabilityManager : null);

  /**
   * Mediates a clipboard write request.
   *
   * @param {string} text - Text to write to clipboard
   * @param {object} options - { capabilityId, textTaint, origin }
   * @returns {{ allowed: boolean, reason?: string }}
   */
  function inspectClipboardWrite(text, options = {}) {
    if (typeof text !== 'string') {
      return { allowed: false, reason: 'Clipboard content must be a valid string' };
    }

    // 1. Check for prompt injection canary or tainted credential
    if (options.textTaint && taintEngine) {
      const taint = taintEngine.getTaint(text);
      if (taint.level >= taintEngine.TAINT_LEVELS.FINANCIAL_SECRET && !options.capabilityId) {
        return {
          allowed: false,
          reason: `Clipboard write blocked: Exfiltration of high-taint data (${taint.name}) requires explicit capability`
        };
      }
    }

    // 2. Consume capability if present
    if (options.capabilityId && capabilityManager && capabilityManager.consumeCapability) {
      const consumeRes = capabilityManager.consumeCapability(options.capabilityId, {
        origin: options.origin || 'localhost',
        actionType: 'CLIPBOARD_WRITE'
      });

      if (!consumeRes.ok) {
        return { allowed: false, reason: `Clipboard write rejected: ${consumeRes.reason}` };
      }
    }

    if (securityLedger && securityLedger.recordEvent) {
      securityLedger.recordEvent('CLIPBOARD_WRITE_PERMITTED', 'clipboard_gate', {
        textLength: text.length,
        hasCapability: Boolean(options.capabilityId)
      });
    }

    return { allowed: true };
  }

  const exportObj = {
    inspectClipboardWrite
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilClipboardGate = exportObj;
  }
})();
