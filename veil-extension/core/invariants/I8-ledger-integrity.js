/**
 * Invariant I8: Cryptographic Ledger Integrity & Non-Repudiation
 *
 * Formal Rule:
 *   ∀ i > 0, H_i = SHA-256(H_{i-1} || index || timestamp || type || payloadHash) ∧ ValidChain()
 *
 * "The historical audit log is an immutable hash chain.
 *  Any post-hoc event tampering, reordering, or alteration is cryptographically detectable."
 */

const ledger = require('../security-ledger');

function verifyInvariantI8() {
  const evidence = {
    id: 'I8-ledger-integrity',
    name: 'Cryptographic Ledger Integrity & Non-Repudiation',
    formalTheorem: '∀ i > 0, H_i = SHA-256(H_{i-1} || data_i)',
    testsRun: 0,
    passed: 0,
    failed: 0,
    traces: []
  };

  ledger.clearLedger();

  // Test 8.1: Construct Valid Chained Event Sequence
  evidence.testsRun++;
  const e0 = ledger.recordEvent('PERCEPTION_PASS', 'detector', { items: 5 });
  const e1 = ledger.recordEvent('POLICY_EVALUATION', 'pdp', { decision: 'ALLOW' });
  const e2 = ledger.recordEvent('CAPABILITY_ISSUED', 'cap_manager', { id: 'cap_1' });

  const integrityCheck = ledger.verifyChainIntegrity();
  if (integrityCheck.valid && integrityCheck.length === 3) {
    evidence.passed++;
    evidence.traces.push(`Cryptographic chain verified across ${integrityCheck.length} events`);
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Valid cryptographic ledger chain failed verification');
  }

  // Test 8.2: Tamper Detection (Adversary modifies past policy decision event)
  evidence.testsRun++;
  const rawEvents = ledger.getChronologicalLedger();
  rawEvents[1].detail.decision = 'DENIED_MALICIOUS_TAMPER'; // Tamper historic record

  const tamperedCheck = ledger.verifyChainIntegrity();
  if (!tamperedCheck.valid && tamperedCheck.brokenAtIndex === 1) {
    evidence.passed++;
    evidence.traces.push(`Tamper detection triggered correctly: broken chain detected at index ${tamperedCheck.brokenAtIndex}`);
  } else {
    evidence.failed++;
    evidence.traces.push('FAIL: Tampered event was not detected by cryptographic validator');
  }

  ledger.clearLedger();
  evidence.certified = evidence.failed === 0;
  return evidence;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { verifyInvariantI8 };
}
