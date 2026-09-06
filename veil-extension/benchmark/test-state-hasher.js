/**
 * Unit Test: Canonical DOM State Hasher
 */

const assert = require('assert');
const { JSDOM } = require('jsdom');
const stateHasher = require('../core/state-hasher');

console.log('Testing Canonical DOM State Hasher...');

const html = `
<!DOCTYPE html>
<html>
<head><title>Checkout Test</title></head>
<body>
  <div id="cart">
    <span>Total: ₹500</span>
    <button id="pay-btn" role="button">Pay ₹500</button>
  </div>
</body>
</html>
`;

const dom = new JSDOM(html);
const doc = dom.window.document;

// 1. Compute initial state hash
const { stateHash: hash1, elementCount } = stateHasher.computeStateHash(doc);
assert.strictEqual(typeof hash1, 'string');
assert.strictEqual(hash1.length, 64);
assert.strictEqual(elementCount, 1);
console.log(`  ✔ Initial StateHash computed: ${hash1.slice(0, 16)}...`);

// 2. Compute again on identical DOM -> must match exactly (deterministic)
const { stateHash: hash2 } = stateHasher.computeStateHash(doc);
assert.strictEqual(hash1, hash2);
console.log('  ✔ StateHash is deterministic across identical evaluations.');

// 3. Mutate DOM (Simulate Adversarial Price Swap attack: ₹500 -> ₹50,000)
const btn = doc.getElementById('pay-btn');
btn.textContent = 'Pay ₹50,000';

const { stateHash: hashMutated } = stateHasher.computeStateHash(doc);
assert.notStrictEqual(hash1, hashMutated);
console.log(`  ✔ Price swap detected! Mutated StateHash: ${hashMutated.slice(0, 16)}... != Initial`);

// 4. Test Element Fingerprint
const fp = stateHasher.computeElementFingerprint(btn);
assert(fp.includes('button'));
assert(fp.includes('pay-btn'));
console.log(`  ✔ Element fingerprint generated: ${fp}`);

console.log('✅ ALL STATE HASHER TESTS PASSED\n');
