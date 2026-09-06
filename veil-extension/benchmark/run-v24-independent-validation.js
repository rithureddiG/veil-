/**
 * VEIL v2.4 — Master Independent Reproduction & Validation Suite (Suite 14)
 *
 * Executes the core verification pillars of VEIL v2.4:
 * 1. Offline Independent Receipt Verification (Zero runtime dependency)
 * 2. Reference Kernel Mutation Testing (100% Mutation Score)
 * 3. Tri-Fold Differential Conformance Testing (Production vs Reference vs Oracle)
 * 4. Canonicalization & Semantic Commitment Resilience
 */

const assert = require('assert');
const path = require('path');
const { verifyReceipt } = require('../../external-verifier/receipt-verifier');
const { runMutationTesting } = require('./test-mutation-coverage');
const { runDifferentialConformanceSuite } = require('./test-differential-conformance');
const { runCanonicalizationSuite } = require('./test-canonicalization');

function testReceiptVerifierTamperResistance() {
  console.log('='.repeat(75));
  console.log('🔍 TEST 1: OFFLINE INDEPENDENT RECEIPT VERIFICATION & TAMPER PROOF');
  console.log('='.repeat(75));

  const crypto = require('crypto');
  function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

  // 1. Build a synthetic valid receipt
  const genesis = '0'.repeat(64);
  const e1Payload = { type: 'INTENT_PROPOSAL', intent: 'safe_browse', ts: 1000 };
  const e1Hash = sha256(genesis + JSON.stringify(e1Payload));

  const e2Payload = { type: 'CAPABILITY_MINT', cap: 'cap_001', ts: 1001 };
  const e2Hash = sha256(e1Hash + JSON.stringify(e2Payload));

  const validReceipt = {
    receiptType: 'VEIL_SECURITY_RECEIPT',
    genesisHash: genesis,
    sessionRoot: e2Hash,
    chain: [
      { prevHash: genesis, payload: e1Payload, eventHash: e1Hash },
      { prevHash: e1Hash, payload: e2Payload, eventHash: e2Hash }
    ]
  };

  const validResult = verifyReceipt(validReceipt);
  console.log(`  Valid Receipt Result: ${validResult.verdict} (Verified: ${validResult.verifiedEvents} events)`);
  assert.strictEqual(validResult.verdict, 'VALID', 'Valid receipt must verify successfully');

  // 2. Tamper with event payload
  const tamperedReceipt = JSON.parse(JSON.stringify(validReceipt));
  tamperedReceipt.chain[0].payload.intent = 'MALICIOUS_STEAL_KEYS';

  const tamperedResult = verifyReceipt(tamperedReceipt);
  console.log(`  Tampered Receipt Result: ${tamperedResult.verdict} (Errors: ${tamperedResult.errors.length})`);
  assert.strictEqual(tamperedResult.verdict, 'TAMPERED', 'Tampered receipt must be flagged TAMPERED');

  console.log('  [PASS] Receipt Verifier: 100% Cryptographic Integrity & Tamper Detection.\n');
}

function runIndependentValidationSuite() {
  console.log('\n' + '#'.repeat(75));
  console.log('  VEIL v2.4 — SUITE 14: INDEPENDENT REPRODUCTION & VALIDATION');
  console.log('#'.repeat(75) + '\n');

  // Step 1: Offline Receipt Verifier
  testReceiptVerifierTamperResistance();

  // Step 2: Reference Kernel Mutation Testing
  const mutationRes = runMutationTesting();
  assert.strictEqual(mutationRes.certified, true, 'Mutation testing must achieve 100% kill rate');

  // Step 3: Tri-Fold Differential Conformance
  const diffRes = runDifferentialConformanceSuite(50);
  assert.strictEqual(diffRes.certified, true, 'Differential conformance must have 0 discrepancies');

  // Step 4: Canonicalization & Semantic Commitment Resilience
  const canonRes = runCanonicalizationSuite();
  assert.strictEqual(canonRes.certified, true, 'Canonicalization suite must pass 100%');

  console.log('='.repeat(75));
  console.log('🏆 SUITE 14 COMPLETE: ALL INDEPENDENT VALIDATION PILLARS VERIFIED');
  console.log('='.repeat(75) + '\n');

  return {
    suite: 'SUITE_14_INDEPENDENT_VALIDATION',
    passed: true,
    mutationScore: mutationRes.mutationScore,
    diffScenarios: diffRes.passedScenarios,
    canonTests: canonRes.passedTests
  };
}

if (require.main === module) {
  runIndependentValidationSuite();
}

module.exports = {
  runIndependentValidationSuite
};
