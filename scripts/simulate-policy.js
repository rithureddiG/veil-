/**
 * VEIL — Developer Policy Simulator CLI
 *
 * Usage:
 *   node scripts/simulate-policy.js [action] [origin] [amount]
 *
 * Example:
 *   node scripts/simulate-policy.js PURCHASE shop.example 4999
 *   node scripts/simulate-policy.js PURCHASE evil.test 999999
 */

const simulator = require('../veil-extension/core/kernel/policy-simulator');

function runCLISimulator() {
  const samplePolicy = {
    policy: 'ecommerce_checkout_policy',
    actor: { type: 'autonomous_agent' },
    action: {
      allow: ['CLICK', 'SELECT', 'TYPE', 'SCROLL'],
      confirm: ['PURCHASE', 'TRANSFER', 'DELETE']
    },
    data: {
      deny: ['CREDENTIAL', 'FINANCIAL_SECRET']
    },
    network: {
      allow: ['shop.example', 'api.shop.example']
    },
    constraints: {
      max_transaction: 50000,
      capability_ttl: 3000
    }
  };

  const action = process.argv[2] || 'CLICK';
  const origin = process.argv[3] || 'shop.example';
  const amount = process.argv[4] ? parseFloat(process.argv[4]) : null;

  console.log('='.repeat(75));
  console.log('🛡️  VEIL — DEVELOPER POLICY SIMULATOR CLI');
  console.log('='.repeat(75));
  console.log(`  Policy Name:  ${samplePolicy.policy}`);
  console.log(`  Simulating:   Action=${action} | Origin=${origin} | Amount=${amount || 'N/A'}`);
  console.log('-'.repeat(75));

  const result = simulator.simulate(samplePolicy, { action, origin, amount });

  const icon = result.verdict === 'ALLOW' ? '✅' : (result.verdict === 'CONFIRM_OOB' ? '⚠️' : '❌');
  console.log(`\n  SIMULATION VERDICT: ${icon} ${result.verdict}`);
  console.log(`  Reasons:            ${result.reasons.join('; ')}`);

  if (result.explanations && result.explanations.length > 0) {
    console.log('\n  Step-by-Step Explanations:');
    for (const exp of result.explanations) {
      console.log(`    ${exp}`);
    }
  }

  if (result.capabilityPreview) {
    console.log('\n  Preview Capability Token:');
    console.log(`    Action Type: ${result.capabilityPreview.actionType}`);
    console.log(`    Bound Origin:${result.capabilityPreview.origin}`);
    console.log(`    TTL:         ${result.capabilityPreview.ttlMs} ms`);
  }

  console.log('='.repeat(75) + '\n');
  return result;
}

if (require.main === module) {
  runCLISimulator();
}

module.exports = { runCLISimulator };
