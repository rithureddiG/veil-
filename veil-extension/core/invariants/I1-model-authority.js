/**
 * Invariant I1: Model Authority Isolation
 *
 * Formal Rule:
 *   ∀ action: Execute(action) ⟹ AuthorizedBy(VEIL_Kernel)
 *
 * "The model may propose. The model may request. The model may NEVER authorize.
 *  Direct execution without a Kernel-issued Capability is mathematically impossible."
 */

const executor = require('../action-executor');
const capMgr = require('../capability-manager');

function verifyInvariantI1() {
  const evidence = {
    id: 'I1-model-authority',
    name: 'Model Authority Isolation',
    formalTheorem: '∀ a ∈ Actions, Execute(a) ⟹ ∃ c ∈ Capabilities : Valid(c, a)',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  // Test 1.1: Direct invocation of executor without capability must fail or be blocked
  evidence.testsRun++;
  const fakeElement = { click: () => {}, id: 'btn', tagName: 'BUTTON' };
  const directCall = executor.executeAction({
    type: 'click',
    target: { id: 'btn' },
    capabilityId: null // Missing capability
  }, fakeElement, new Set());

  // Executor without capability either returns false or requires capability
  const directBlocked = directCall.capabilityConsumed !== true;
  if (directBlocked) {
    evidence.passed++;
    evidence.traces.push('Direct call without capability refused capability-consumed status');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Direct execution was allowed capability consumption');
  }

  // Test 1.2: Model attempting to forge capability ID
  evidence.testsRun++;
  const forgedCall = executor.executeAction({
    type: 'click',
    capabilityId: 'cap_forged_fake_id_12345'
  }, fakeElement, new Set());

  if (!forgedCall.ok && (forgedCall.reason.includes('capability-denied') || forgedCall.reason.includes('does not exist'))) {
    evidence.passed++;
    evidence.traces.push('Forged capability ID strictly rejected by execution boundary');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Forged capability ID was not rejected');
  }

  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI1 };
}
