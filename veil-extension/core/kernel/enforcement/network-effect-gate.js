/**
 * VEIL — Network Effect Gate (Enforcement Boundary)
 *
 * Implements Invariant I6 & C6:
 * "All outbound network transmissions (fetch, XMLHttpRequest, WebSocket, sendBeacon)
 *  must be validated against the Egress Firewall and Taint Security Lattice."
 */

(function () {
  const egressFirewall = typeof require !== 'undefined'
    ? require('../../../core/kernel/egress-firewall.js')
    : (typeof window !== 'undefined' ? window.VeilEgressFirewall : null);

  const taintEngine = typeof require !== 'undefined'
    ? require('../../../core/kernel/taint-engine.js')
    : (typeof window !== 'undefined' ? window.VeilTaintEngine : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../../../core/security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  /**
   * Evaluates an outbound network request before transmission.
   *
   * @param {object} request - { url, method, headers, body, origin }
   * @param {object} options - { capabilityId, payloadTaint }
   * @returns {{ allowed: boolean, reason?: string, verdict: string }}
   */
  function inspectNetworkTransmission(request = {}, options = {}) {
    if (!request.url) {
      return { allowed: false, reason: 'Network request missing destination URL', verdict: 'BLOCKED' };
    }

    // 1. Taint sink verification
    if (options.payloadTaint && taintEngine && taintEngine.canFlow) {
      const flowCheck = taintEngine.canFlow(
        options.payloadTaint,
        taintEngine.SINKS.REMOTE_EGRESS,
        {
          sourceOrigin: request.origin || 'localhost',
          sinkOrigin: request.url,
          hasCapability: Boolean(options.capabilityId)
        }
      );

      if (!flowCheck.allowed) {
        return {
          allowed: false,
          reason: flowCheck.reason,
          verdict: 'BLOCKED'
        };
      }
    }

    // 2. Egress Firewall perimeter inspection (domain blacklist, canary detector, format safety)
    if (egressFirewall && egressFirewall.inspectOutbound) {
      const firewallRes = egressFirewall.inspectOutbound({
        url: request.url,
        method: request.method || 'GET',
        headers: request.headers || {},
        body: request.body || ''
      });

      if (!firewallRes.allowed) {
        if (securityLedger && securityLedger.recordEvent) {
          securityLedger.recordEvent('NETWORK_EGRESS_BLOCKED', 'network_effect_gate', {
            url: request.url,
            violations: firewallRes.violations,
            verdict: firewallRes.verdict
          });
        }

        return {
          allowed: false,
          reason: firewallRes.violations.join('; '),
          verdict: firewallRes.verdict
        };
      }
    }

    if (securityLedger && securityLedger.recordEvent) {
      securityLedger.recordEvent('NETWORK_EGRESS_PERMITTED', 'network_effect_gate', {
        url: request.url,
        method: request.method || 'GET'
      });
    }

    return {
      allowed: true,
      verdict: 'PERMITTED'
    };
  }

  const exportObj = {
    inspectNetworkTransmission
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilNetworkEffectGate = exportObj;
  }
})();
