/**
 * VEIL — Navigation Gate (Enforcement Boundary)
 *
 * Implements Invariant I1, I6 & C1:
 * "All tab navigations, window.location updates, and programmatic URL redirects
 *  must be validated against origin security policies to prevent cross-origin navigation attacks."
 */

(function () {
  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  const capabilityManager = typeof require !== 'undefined'
    ? require('../../../core/capability-manager.js')
    : (typeof window !== 'undefined' ? window.VeilCapabilityManager : null);

  /**
   * Evaluates and mediates a target URL navigation request.
   *
   * @param {string} targetUrl - Target navigation URL
   * @param {string} currentOrigin - Current active page origin
   * @param {object} options - { capabilityId }
   * @returns {{ allowed: boolean, reason?: string }}
   */
  function inspectNavigation(targetUrl, currentOrigin = 'localhost', options = {}) {
    if (!targetUrl || typeof targetUrl !== 'string') {
      return { allowed: false, reason: 'Invalid or missing target navigation URL' };
    }

    const trimmed = targetUrl.trim().toLowerCase();

    // 1. Block dangerous pseudo-protocols
    if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('vbscript:')) {
      return {
        allowed: false,
        reason: 'Navigation to executable script URLs (javascript:, data:) is strictly prohibited'
      };
    }

    // 2. Cross-origin navigation check
    let targetOrigin = '';
    try {
      const parsed = new URL(targetUrl, currentOrigin.startsWith('http') ? currentOrigin : `http://${currentOrigin}`);
      targetOrigin = parsed.origin;
    } catch (_) {
      // Relative path is same origin
      targetOrigin = currentOrigin;
    }

    const isCrossOrigin = Boolean(currentOrigin && targetOrigin && targetOrigin !== currentOrigin && !targetOrigin.includes('localhost'));

    if (isCrossOrigin && !options.capabilityId) {
      return {
        allowed: false,
        reason: `Cross-origin navigation from "${currentOrigin}" to "${targetOrigin}" requires explicit capability authorization`
      };
    }

    // 3. Consume capability if present
    if (options.capabilityId && capabilityManager && capabilityManager.consumeCapability) {
      const consumeRes = capabilityManager.consumeCapability(options.capabilityId, {
        origin: currentOrigin,
        actionType: 'NAVIGATE'
      });

      if (!consumeRes.ok) {
        return { allowed: false, reason: `Navigation blocked: capability rejected (${consumeRes.reason})` };
      }
    }

    if (securityLedger && securityLedger.recordEvent) {
      securityLedger.recordEvent('NAVIGATION_EVALUATED', 'navigation_gate', {
        targetUrl,
        currentOrigin,
        targetOrigin,
        isCrossOrigin,
        authorized: true
      });
    }

    return { allowed: true };
  }

  const exportObj = {
    inspectNavigation
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilNavigationGate = exportObj;
  }
})();
