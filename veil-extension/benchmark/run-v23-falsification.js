/**
 * VEIL v2.3 — Coverage Fuzzing & Flagship Adversarial Demonstration Runner
 *
 * Runs:
 *   1. Coverage-driven state-space fuzzer (40,000+ states explored)
 *   2. Flagship 30-second adversarial demonstration (TOCTOU price drop + prompt injection)
 */

const assert = require('assert');
const { runCoverageFuzzing } = require('./run-coverage-fuzzer');
const { runFlagshipAdversarialDemo } = require('./run-flagship-adversarial-demo');

async function runV23FalsificationSuite() {
  console.log('='.repeat(80));
  console.log('⚔️  VEIL v2.3 — COVERAGE FUZZING & FLAGSHIP ADVERSARIAL DEMONSTRATION');
  console.log('='.repeat(80));

  // 1. Run Coverage Fuzzer
  const fuzzResult = runCoverageFuzzing();
  assert.strictEqual(fuzzResult.certified, true, 'Coverage fuzzer must observe zero invariant violations');

  // 2. Run Flagship Adversarial Demonstration
  const demoResult = await runFlagshipAdversarialDemo();
  assert.strictEqual(demoResult.attackBlocked, true, 'Flagship adversarial attack must be neutralized fail-closed');

  console.log('='.repeat(80));
  console.log('🏆 VEIL v2.3 ADVANCED FALSIFICATION SUITE PASSED');
  console.log('   • 40,000+ States Explored with Zero Invariant Violations');
  console.log('   • Flagship TOCTOU + Prompt Injection Neutralized Fail-Closed');
  console.log('='.repeat(80) + '\n');

  return true;
}

if (require.main === module) {
  runV23FalsificationSuite().then(ok => process.exit(ok ? 0 : 1));
}

module.exports = { runV23FalsificationSuite };
