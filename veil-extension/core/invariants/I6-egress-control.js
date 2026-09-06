/**
 * Invariant I6: Outbound Egress Control & Perimeter Defense
 *
 * Formal Rule:
 *   ∀ r ∈ OutboundRequests, Canaries(r) = ∅ ∧ AllowedDomain(r) ∧ TaintPermitted(r)
 *
 * "Nothing sensitive or tainted leaves the browser without explicit Kernel authorization."
 */

const egress = require('../kernel/egress-firewall');

function verifyInvariantI6() {
  const evidence = {
    id: 'I6-egress-control',
    name: 'Outbound Egress Control & Perimeter Defense',
    formalTheorem: '∀ r ∈ OutboundRequests, Canaries(r) == ∅ ∧ AllowedDomain(r)',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  // Test 6.1: Clean Request Passes Egress Firewall
  evidence.testsRun++;
  const cleanReq = egress.inspectOutbound({
    url: 'https://shop.example.com/api/order',
    method: 'POST',
    body: { orderId: 'ord_123', itemCount: 2 }
  });

  if (cleanReq.allowed && cleanReq.verdict === 'ALLOWED') {
    evidence.passed++;
    evidence.traces.push('Clean payload permitted through egress firewall');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Clean payload was blocked by egress firewall');
  }

  // Test 6.2: Canary Exfiltration Block
  evidence.testsRun++;
  const canaryExfil = egress.inspectOutbound({
    url: 'https://analytics.thirdparty.com/track',
    method: 'POST',
    body: { userTag: 'VEIL_CANARY_PASSWORD_SECRET' }
  });

  if (!canaryExfil.allowed && canaryExfil.violations.some(v => v.includes('Canary exfiltration'))) {
    evidence.passed++;
    evidence.traces.push('Canary exfiltration attempt detected and blocked');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Canary exfiltration was not blocked');
  }

  // Test 6.3: Malicious Domain Egress Block
  evidence.testsRun++;
  const evilEgress = egress.inspectOutbound({
    url: 'https://evil.com/harvest',
    method: 'POST',
    body: { token: 'abc' }
  });

  if (!evilEgress.allowed && evilEgress.violations.some(v => v.includes('Blacklisted egress'))) {
    evidence.passed++;
    evidence.traces.push('Blacklisted destination origin blocked at perimeter');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Blacklisted destination was not blocked');
  }

  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI6 };
}
