/**
 * VEIL v2.1 — Master Formal Invariant Test Suite
 *
 * Runs all 8 core invariant verification theorems plus the autonomous attacker simulation.
 */

const assert = require('assert');
const { runAllInvariantVerifications } = require('../core/invariants');
const { runAttackerSimulation } = require('./attacker-agent');

async function runFormalMasterSuite() {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL v2.1 — MASTER FORMAL INVARIANT VERIFICATION');
  console.log('='.repeat(75));

  // 1. Run All 8 Invariant Proofs
  const cert = runAllInvariantVerifications();

  console.log(`\n▶ [PART 1: 8 FORMAL SECURITY INVARIANTS]`);
  console.log('-'.repeat(75));
  for (const inv of cert.evidenceDossier) {
    const icon = inv.certified ? '✅' : '❌';
    console.log(`  ${icon} [${inv.id}] ${inv.name.padEnd(45)} (${inv.passed}/${inv.testsRun})`);
  }
  assert.strictEqual(cert.allCertified, true, 'All 8 Invariants must be formally certified');

  // 2. Run Autonomous Red-Team Attacker Agent
  console.log(`\n▶ [PART 2: RED-TEAM ATTACKER AGENT SIMULATION]`);
  console.log('-'.repeat(75));
  const sim = await runAttackerSimulation();
  assert.strictEqual(sim.certified, true, 'Attacker agent must be 100% blocked');

  console.log('='.repeat(75));
  console.log('🏆 VEIL v2.1 MASTER VERIFICATION: 100% FORMAL & ADVERSARIAL CERTIFICATION');
  console.log('   • 8/8 Formal Security Invariants Certified');
  console.log(`   • ${cert.testsPassed} Formal Proof Checks Passed`);
  console.log(`   • ${sim.blockedCount}/${sim.attacksGenerated} Adversarial Attacks Blocked (Zero Escaped)`);
  console.log('='.repeat(75) + '\n');
  return true;
}

if (require.main === module) {
  runFormalMasterSuite().then(ok => process.exit(ok ? 0 : 1));
}

module.exports = { runFormalMasterSuite };
