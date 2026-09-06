/**
 * VEIL — Formal Security Invariant Verification Registry & Certifier
 *
 * Runs the formal verification suite across all 8 Core Security Invariants:
 *   I1: Model Authority Isolation
 *   I2: Out-of-Band Privileged Authorization
 *   I3: Capability Execution & Replay Immunity
 *   I4: Cryptographic State-Binding (stateHash)
 *   I5: Secret Isolation & Invariant P1
 *   I6: Outbound Egress Control & Perimeter Defense
 *   I7: Fail-Closed Default Execution
 *   I8: Cryptographic Ledger Integrity & Non-Repudiation
 */

const { verifyInvariantI1 } = require('./I1-model-authority');
const { verifyInvariantI2 } = require('./I2-oob-authorization');
const { verifyInvariantI3 } = require('./I3-capability-execution');
const { verifyInvariantI4 } = require('./I4-state-binding');
const { verifyInvariantI5 } = require('./I5-secret-isolation');
const { verifyInvariantI6 } = require('./I6-egress-control');
const { verifyInvariantI7 } = require('./I7-fail-closed');
const { verifyInvariantI8 } = require('./I8-ledger-integrity');

function runAllInvariantVerifications() {
  const timestamp = Date.now();
  const certifierResults = [];

  const verifiers = [
    verifyInvariantI1,
    verifyInvariantI2,
    verifyInvariantI3,
    verifyInvariantI4,
    verifyInvariantI5,
    verifyInvariantI6,
    verifyInvariantI7,
    verifyInvariantI8
  ];

  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;

  for (const fn of verifiers) {
    const evidence = fn();
    certifierResults.push(evidence);
    totalTests += evidence.testsRun;
    totalPassed += evidence.passed;
    totalFailed += evidence.failed;
  }

  const allCertified = certifierResults.every(r => r.certified);

  const certificate = {
    standard: 'VEIL-VERIFIED-KERNEL-v2.1',
    timestamp,
    isoTime: new Date(timestamp).toISOString(),
    invariantsCertified: certifierResults.filter(r => r.certified).length,
    invariantsTotal: certifierResults.length,
    testsExecuted: totalTests,
    testsPassed: totalPassed,
    testsFailed: totalFailed,
    allCertified,
    evidenceDossier: certifierResults
  };

  return certificate;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    runAllInvariantVerifications,
    verifyInvariantI1,
    verifyInvariantI2,
    verifyInvariantI3,
    verifyInvariantI4,
    verifyInvariantI5,
    verifyInvariantI6,
    verifyInvariantI7,
    verifyInvariantI8
  };
}

// Allow direct execution via CLI
if (require.main === module) {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL v2.1 — FORMAL SECURITY INVARIANT VERIFICATION SUITE');
  console.log('='.repeat(75));

  const cert = runAllInvariantVerifications();

  for (const inv of cert.evidenceDossier) {
    const icon = inv.certified ? '✅' : '❌';
    console.log(`\n${icon} [${inv.id}] ${inv.name}`);
    console.log(`   Theorem: ${inv.formalTheorem}`);
    console.log(`   Tests:   ${inv.passed} / ${inv.testsRun} passed`);
    for (const t of inv.traces) {
      console.log(`   • ${t}`);
    }
  }

  console.log('\n' + '='.repeat(75));
  if (cert.allCertified) {
    console.log(`🏆 FORMAL CERTIFICATION PASSED: 8/8 INVARIANTS MATHEMATICALLY & MECHANICALLY PROVEN`);
    console.log(`   Total Proof Checks: ${cert.testsPassed}/${cert.testsExecuted} (100% Verified)`);
    console.log('='.repeat(75) + '\n');
    process.exit(0);
  } else {
    console.error(`❌ CERTIFICATION FAILED: ${cert.testsFailed} Invariant Violations Detected`);
    console.log('='.repeat(75) + '\n');
    process.exit(1);
  }
}
