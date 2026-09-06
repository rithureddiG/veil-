/**
 * Invariant I4: Cryptographic State-Binding & TOCTOU Immunity
 *
 * Formal Rule:
 *   Execute(capability) ⟹ stateHash(DOM_current) = stateHash(DOM_observed)
 *
 * "Capabilities are bound to canonical state.
 *  If the webpage DOM changes between observation and execution (price swap, button swap),
 *  the capability is instantly invalidated."
 */

const { JSDOM } = require('jsdom');
const stateHasher = require('../state-hasher');
const capMgr = require('../capability-manager');

function verifyInvariantI4() {
  const evidence = {
    id: 'I4-state-binding',
    name: 'Cryptographic State-Binding & TOCTOU Immunity',
    formalTheorem: 'Execute(c) ⟹ stateHash(current) == stateHash(observed)',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  const html = `
    <div id="store">
      <div id="price">Price: ₹500</div>
      <button id="pay-btn">Pay ₹500</button>
    </div>
  `;
  const dom = new JSDOM(html);
  const doc = dom.window.document;

  // Test 4.1: Compute Initial stateHash & Issue Bound Capability
  evidence.testsRun++;
  const { stateHash: observedHash } = stateHasher.computeStateHash(doc);
  const cap = capMgr.issueCapability({
    actionType: 'CLICK',
    targetFingerprint: 'button:pay-btn',
    origin: 'shop.example',
    stateHash: observedHash
  });

  const validMatch = capMgr.verifyCapability(cap.capabilityId, {
    origin: 'shop.example',
    actionType: 'CLICK',
    targetFingerprint: 'button:pay-btn',
    stateHash: observedHash
  });

  if (validMatch.valid) {
    evidence.passed++;
    evidence.traces.push('State-bound capability validated successfully against unchanged DOM');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Capability failed against legitimate state');
  }

  // Test 4.2: Adversarial DOM Price Swap (₹500 -> ₹50,000)
  evidence.testsRun++;
  doc.getElementById('pay-btn').textContent = 'Pay ₹50,000';
  const { stateHash: mutatedHash } = stateHasher.computeStateHash(doc);

  const stateMismatchCheck = capMgr.verifyCapability(cap.capabilityId, {
    origin: 'shop.example',
    actionType: 'CLICK',
    targetFingerprint: 'button:pay-btn',
    stateHash: mutatedHash // New mutated state
  });

  if (!stateMismatchCheck.valid && stateMismatchCheck.reason.includes('StateHash mismatch')) {
    evidence.passed++;
    evidence.traces.push('Price swap detected! StateHash mismatch strictly aborted execution');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: StateHash mismatch allowed execution');
  }

  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI4 };
}
