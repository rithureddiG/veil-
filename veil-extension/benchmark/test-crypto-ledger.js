/**
 * Unit Test: Cryptographic Hash-Chained Security Ledger
 */

const assert = require('assert');
const ledger = require('../core/security-ledger');

console.log('Testing Cryptographic Hash-Chained Security Ledger...');

// 1. Initial empty state
ledger.clearLedger();
let status = ledger.verifyChainIntegrity();
assert.strictEqual(status.valid, true);
assert.strictEqual(status.length, 0);
assert.strictEqual(status.headHash, ledger.GENESIS_HASH);

// 2. Append events
const evt1 = ledger.recordEvent('PERCEPTION_COMPLETED', 'detector', { count: 3 });
assert.strictEqual(evt1.prevHash, ledger.GENESIS_HASH);
assert.strictEqual(typeof evt1.hash, 'string');
assert.strictEqual(evt1.hash.length, 64);

const evt2 = ledger.recordEvent('POLICY_EVALUATED', 'policy', { decision: 'ALLOW' });
assert.strictEqual(evt2.prevHash, evt1.hash);
assert.strictEqual(evt2.hash.length, 64);

const evt3 = ledger.recordEvent('ACTION_EXECUTED', 'executor', { action: 'click', password: 'SecretPassword123' });
assert.strictEqual(evt3.prevHash, evt2.hash);
// Ensure secret was scrubbed in logged detail
assert.strictEqual(evt3.detail.password, '[REDACTED_BY_KERNEL]');

// 3. Verify intact chain
status = ledger.verifyChainIntegrity();
assert.strictEqual(status.valid, true);
assert.strictEqual(status.length, 3);
assert.strictEqual(status.headHash, evt3.hash);
console.log(`  ✔ Chain integrity verified across ${status.length} events. Head: ${status.headHash.slice(0, 16)}...`);

// 4. Test Tamper Detection (Modify an event in the chain)
const chrono = ledger.getChronologicalLedger();
chrono[1].detail.decision = 'DENY'; // Malicious modification of historic record
const tamperedStatus = ledger.verifyChainIntegrity();
assert.strictEqual(tamperedStatus.valid, false);
assert.strictEqual(tamperedStatus.brokenAtIndex, 1);
console.log(`  ✔ Tamper detection triggered correctly: ${tamperedStatus.error}`);

// Reset for clean slate
ledger.clearLedger();
console.log('✅ ALL CRYPTO LEDGER TESTS PASSED\n');
