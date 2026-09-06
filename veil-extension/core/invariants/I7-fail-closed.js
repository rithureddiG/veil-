/**
 * Invariant I7: Fail-Closed Default Execution
 *
 * Formal Rule:
 *   Ambiguous(a) ∨ Malformed(a) ∨ Error(a) ⟹ DENY
 *
 * "Whenever there is ambiguity, uncertainty, prototype tampering, or a crash,
 *  the VEIL Kernel defaults to DENY. Zero actions proceed on unhandled error."
 */

const pdp = require('../kernel/policy-decision-point');

function verifyInvariantI7() {
  const evidence = {
    id: 'I7-fail-closed',
    name: 'Fail-Closed Default Execution',
    formalTheorem: 'Ambiguous(a) ∨ Error(a) ⟹ DENY',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  // Test 7.1: Null / Undefined Proposal Defaults to DENY
  evidence.testsRun++;
  const nullDecision = pdp.evaluate({ proposal: null });
  if (nullDecision.decision === 'DENY' && !nullDecision.allowed) {
    evidence.passed++;
    evidence.traces.push('Null proposal strictly failed closed with DENY');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Null proposal did not fail closed');
  }

  // Test 7.2: Prototype Pollution Tampering Defaults to DENY
  evidence.testsRun++;
  const protoAttack = JSON.parse('{"type":"click","__proto__":{"isAdmin":true}}');
  const protoDecision = pdp.evaluate({ proposal: protoAttack });
  if (protoDecision.decision === 'DENY' && protoDecision.error === 'PROTOTYPE_POLLUTION') {
    evidence.passed++;
    evidence.traces.push('Prototype pollution tampering detected and rejected with DENY');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Prototype pollution was not blocked');
  }

  // Test 7.3: Arbitrary Script Execution Defaults to DENY
  evidence.testsRun++;
  const scriptDecision = pdp.evaluate({ proposal: { type: 'EXECUTE_JS', code: 'alert(1)' } });
  if (scriptDecision.decision === 'DENY' && scriptDecision.error === 'ARBITRARY_SCRIPT_FORBIDDEN') {
    evidence.passed++;
    evidence.traces.push('Arbitrary code primitive blocked with DENY');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Arbitrary code primitive was permitted');
  }

  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI7 };
}
