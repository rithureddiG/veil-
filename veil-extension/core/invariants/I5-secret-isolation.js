/**
 * Invariant I5: Secret Isolation & Invariant P1
 *
 * Formal Rule:
 *   ModelContext ∩ PlaintextSecrets = ∅
 *
 * "The model reasoning context never contains raw credentials or form values.
 *  The model reasons exclusively over VEIL-IR and ValueRefs."
 */

const { JSDOM } = require('jsdom');
const veilIR = require('../veil-ir');
const privacyAudit = require('../privacy-audit');
const taintEngine = require('../kernel/taint-engine');

function verifyInvariantI5() {
  const evidence = {
    id: 'I5-secret-isolation',
    name: 'Secret Isolation & Zero-Leakage (Invariant P1)',
    formalTheorem: 'ModelContext ∩ PlaintextSecrets = ∅',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  const html = `
    <form id="login">
      <input id="email" type="text" value="user@domain.com" />
      <input id="pwd" type="password" value="SuperSecretPassword#123" />
      <input id="card" type="text" value="4111 2222 3333 4444" />
    </form>
  `;
  const dom = new JSDOM(html);
  const doc = dom.window.document;

  // Test 5.1: VEIL-IR Compilation Strips All .value Properties
  evidence.testsRun++;
  const ir = veilIR.compileVeilIR(doc, [
    { element: doc.getElementById('pwd'), type: 'password' },
    { element: doc.getElementById('card'), type: 'credit_card' }
  ]);

  const validation = veilIR.validateIR(ir);
  let valueFound = false;
  for (const el of ir.elements) {
    if ('value' in el) valueFound = true;
  }

  if (validation.valid && !valueFound) {
    evidence.passed++;
    evidence.traces.push('VEIL-IR AST contains 0 bytes of .value field data (Invariant P1 verified)');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: VEIL-IR leaked field value property');
  }

  // Test 5.2: Privacy Audit Firewall Blocks Leak Injections
  evidence.testsRun++;
  const leakedContext = { elements: [{ id: 'el-1', value: '4111 2222 3333 4444' }] };
  const audit = privacyAudit.runPrivacyAudit(leakedContext, 'Do checkout');
  if (audit.status === 'FAIL') {
    evidence.passed++;
    evidence.traces.push('Pre-flight privacy firewall blocked outbound transmission of unredacted card number');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Pre-flight privacy firewall allowed unredacted card leak');
  }

  // Test 5.3: Taint Engine Prohibits Secret to Cloud Model Flow
  evidence.testsRun++;
  const flowCheck = taintEngine.canFlow('CREDENTIAL', taintEngine.sinks.CLOUD_MODEL);
  if (!flowCheck.allowed) {
    evidence.passed++;
    evidence.traces.push('Taint engine strictly prohibited CREDENTIAL flow to CLOUD_MODEL');
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Taint engine allowed credential flow to model');
  }

  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI5 };
}
