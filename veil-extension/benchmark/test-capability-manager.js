/**
 * Unit Test: VEIL Action Capability Manager
 */

const assert = require('assert');
const capMgr = require('../core/capability-manager');

console.log('Testing VEIL Action Capability Manager...');

// 1. Issue capability
const token = capMgr.issueCapability({
  actionType: 'CLICK',
  targetFingerprint: 'button:submit:place_order',
  origin: 'shop.example.com',
  stateHash: 'state_hash_abc123',
  purpose: 'checkout',
  ttlMs: 5000
});

assert.strictEqual(typeof token.capabilityId, 'string');
assert.strictEqual(token.actionType, 'CLICK');
assert.strictEqual(token.consumed, false);
console.log(`  ✔ Capability issued successfully: ${token.capabilityId}`);

// 2. Verify with matching context
let verifyRes = capMgr.verifyCapability(token.capabilityId, {
  origin: 'shop.example.com',
  stateHash: 'state_hash_abc123',
  actionType: 'CLICK',
  targetFingerprint: 'button:submit:place_order'
});
assert.strictEqual(verifyRes.valid, true);
console.log('  ✔ Capability verified with valid matching context.');

// 3. Verify failure on origin mismatch
verifyRes = capMgr.verifyCapability(token.capabilityId, {
  origin: 'phishing-site.ru',
  stateHash: 'state_hash_abc123',
  actionType: 'CLICK'
});
assert.strictEqual(verifyRes.valid, false);
assert(verifyRes.reason.includes('Origin mismatch'));
console.log(`  ✔ Origin mismatch rejected: ${verifyRes.reason}`);

// 4. Verify failure on stateHash mismatch (DOM mutation / TOCTOU)
verifyRes = capMgr.verifyCapability(token.capabilityId, {
  origin: 'shop.example.com',
  stateHash: 'mutated_state_hash_xyz999',
  actionType: 'CLICK'
});
assert.strictEqual(verifyRes.valid, false);
assert(verifyRes.reason.includes('StateHash mismatch'));
console.log(`  ✔ StateHash mutation rejected: ${verifyRes.reason}`);

// 5. Consume capability (Single-Use)
const consumeRes = capMgr.consumeCapability(token.capabilityId, {
  origin: 'shop.example.com',
  stateHash: 'state_hash_abc123',
  actionType: 'CLICK'
});
assert.strictEqual(consumeRes.ok, true);
assert.strictEqual(consumeRes.capability.consumed, true);
console.log('  ✔ Capability consumed atomically.');

// 6. Replay attack prevention (attempting to use consumed capability)
const replayRes = capMgr.consumeCapability(token.capabilityId, {
  origin: 'shop.example.com',
  stateHash: 'state_hash_abc123',
  actionType: 'CLICK'
});
assert.strictEqual(replayRes.ok, false);
assert(replayRes.reason.includes('already consumed'));
console.log(`  ✔ Replay attack blocked: ${replayRes.reason}`);

console.log('✅ ALL CAPABILITY MANAGER TESTS PASSED\n');
