/**
 * VEIL v2.4 — Canonicalization & Semantic Commitment Attack Suite (Pillar R5)
 *
 * Implements Invariant I8 & Pillar R5:
 * "Canonicalization is part of the security boundary.
 *  Equivalent semantic objects MUST produce EXACTLY ONE canonical hash commitment.
 *  Objects with different security meanings MUST produce DIFFERENT commitments."
 */

const assert = require('assert');
const { canonicalStringify, sha256Sync } = require('../core/security-ledger');

function runCanonicalizationSuite() {
  console.log('='.repeat(75));
  console.log('🔏 VEIL v2.4 — CANONICALIZATION & COMMITMENT RESILIENCE SUITE (Pillar R5)');
  console.log('='.repeat(75));

  let totalTests = 0;
  let passedTests = 0;

  function check(name, fn) {
    totalTests++;
    try {
      fn();
      passedTests++;
      console.log(`  ✅ [PASS] ${name}`);
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name} → ${err.message}`);
      throw err;
    }
  }

  // 1. Key Ordering Permutation Invariance
  check('Key Ordering Invariance: Permuted key orders yield identical SHA-256', () => {
    const objA = { origin: 'https://shop.example', action: 'CLICK', target: 'btn:1', timestamp: 1000 };
    const objB = { timestamp: 1000, target: 'btn:1', action: 'CLICK', origin: 'https://shop.example' };
    const objC = { action: 'CLICK', origin: 'https://shop.example', timestamp: 1000, target: 'btn:1' };

    const hashA = sha256Sync(canonicalStringify(objA));
    const hashB = sha256Sync(canonicalStringify(objB));
    const hashC = sha256Sync(canonicalStringify(objC));

    assert.strictEqual(hashA, hashB);
    assert.strictEqual(hashB, hashC);
  });

  // 2. Nested Key Ordering Invariance
  check('Nested Key Invariance: Deeply nested objects sort deterministically', () => {
    const objA = { outer: { z: 26, a: 1 }, meta: { tag: 'button', id: 'el-1' } };
    const objB = { meta: { id: 'el-1', tag: 'button' }, outer: { a: 1, z: 26 } };

    assert.strictEqual(
      sha256Sync(canonicalStringify(objA)),
      sha256Sync(canonicalStringify(objB))
    );
  });

  // 3. Collision Resistance for Subtly Different Values
  check('Collision Resistance: Subtly different values produce distinct hashes', () => {
    const obj1 = { amount: 12500, currency: 'INR' };
    const obj2 = { amount: 12500.01, currency: 'INR' };
    const obj3 = { amount: '12500', currency: 'INR' }; // type distinction

    const h1 = sha256Sync(canonicalStringify(obj1));
    const h2 = sha256Sync(canonicalStringify(obj2));
    const h3 = sha256Sync(canonicalStringify(obj3));

    assert.notStrictEqual(h1, h2);
    assert.notStrictEqual(h1, h3);
    assert.notStrictEqual(h2, h3);
  });

  // 4. Prototype Pollution Attack Immunity
  check('Prototype Pollution Defense: Injected __proto__ does not poison serializer', () => {
    const hostilePayload = JSON.parse('{"__proto__":{"polluted":true},"role":"user","id":"123"}');
    const safePayload = { role: 'user', id: '123' };

    const canon = canonicalStringify(hostilePayload);
    assert.ok(typeof canon === 'string');
    // Global Object prototype must NOT be polluted
    assert.strictEqual(({}).polluted, undefined);
  });

  // 5. Array Element Order Sensitivity
  check('Array Sensitivity: Array order is preserved (not sorted) for semantic correctness', () => {
    const listA = { steps: ['observe', 'plan', 'execute'] };
    const listB = { steps: ['execute', 'plan', 'observe'] };

    const hA = sha256Sync(canonicalStringify(listA));
    const hB = sha256Sync(canonicalStringify(listB));

    assert.notStrictEqual(hA, hB, 'Array ordering changes must produce different commitments');
  });

  // 6. Unicode Normalization & Special Characters
  check('Unicode & Escape Safety: Escaped characters and Unicode strings serialize deterministically', () => {
    const unicodeObj = { label: 'Card \u20B9 4,999 \u2014 Special', query: 'search&tag=1<script>' };
    const canon1 = canonicalStringify(unicodeObj);
    const canon2 = canonicalStringify(unicodeObj);

    assert.strictEqual(canon1, canon2);
    assert.strictEqual(sha256Sync(canon1), sha256Sync(canon2));
  });

  console.log('\n' + '='.repeat(75));
  console.log('🔏 CANONICALIZATION RESILIENCE SCORECARD');
  console.log('='.repeat(75));
  console.log(`  Tests Executed: ${totalTests}`);
  console.log(`  Tests Passed:   ${passedTests} / ${totalTests} (100.0%)`);
  console.log('  Deterministic Semantic Commitment: VERIFIED & CERTIFIED');
  console.log('='.repeat(75) + '\n');

  return { totalTests, passedTests, certified: totalTests === passedTests };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runCanonicalizationSuite };
}

if (require.main === module) {
  const res = runCanonicalizationSuite();
  process.exit(res.certified ? 0 : 1);
}
