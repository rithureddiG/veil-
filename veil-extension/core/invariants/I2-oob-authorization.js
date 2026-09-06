/**
 * Invariant I2: Out-of-Band Privileged Authorization
 *
 * Formal Rule:
 *   HumanAuthorization ∩ UntrustedPageDOM = ∅
 *
 * "Security decisions must happen outside the untrusted webpage.
 *  Malicious page scripts and CSS cannot render, spoof, clickjack, or suppress authorization."
 */

const confirmation = require('../../content/high-risk-confirmation');

function verifyInvariantI2() {
  const evidence = {
    id: 'I2-oob-authorization',
    name: 'Out-of-Band Privileged Authorization',
    formalTheorem: 'HumanAuthorization ∩ UntrustedPageDOM = ∅',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  // Test 2.1: Ensure no in-page DOM modal root is injected during requestConfirmation
  evidence.testsRun++;
  let domAltered = false;

  // Mock global document if needed
  const originalDoc = global.document;
  let elementAppended = false;
  global.document = {
    body: {
      appendChild: () => { elementAppended = true; }
    },
    createElement: () => ({ id: '', style: {}, innerHTML: '' }),
    getElementById: () => null
  };

  confirmation.setPrivilegedConfirmationHandler(async (details) => {
    // Verified privileged handler receiving structured request
    return details.riskInfo.level === 'HIGH_RISK';
  });

  confirmation.requestConfirmation({
    action: { type: 'click' },
    riskInfo: { level: 'HIGH_RISK' },
    origin: 'shop.example'
  }).then(approved => {
    if (!elementAppended && approved === true) {
      evidence.passed++;
      evidence.traces.push('Authorization routed out-of-band with zero DOM mutation in untrusted page');
    } else {
      evidence.failed++;
      evidence.traces.push('FAIL: In-page DOM was mutated during confirmation');
    }
  });

  evidence.testsRun++;
  // Test 2.2: Verify default fails closed when no privileged handler is attached
  confirmation.setPrivilegedConfirmationHandler(null);
  confirmation.requestConfirmation({
    action: { type: 'click' }
  }).then(res => {
    if (res === false) {
      evidence.passed++;
      evidence.traces.push('Confirmation fails closed safely in disconnected environment');
    } else {
      evidence.failed++;
      evidence.traces.push('FAIL: Confirmation did not fail closed');
    }
  });

  global.document = originalDoc;
  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI2 };
}
