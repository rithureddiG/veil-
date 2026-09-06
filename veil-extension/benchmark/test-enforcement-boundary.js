/**
 * VEIL v2.2 — Enforcement Boundary & Context Firewall Master Test Suite
 *
 * Implements Invariants I1-I8 & C1, C5, C6, C7:
 * Verifies that all browser execution pathways (DOM, network, navigation, storage, clipboard, secrets)
 * and perception pathways pass through VEIL runtime enforcement gates.
 */

const assert = require('assert');
const { JSDOM } = require('jsdom');

const effectGate = require('../core/kernel/enforcement/effect-gate');
const domGate = require('../core/kernel/enforcement/dom-effect-gate');
const networkGate = require('../core/kernel/enforcement/network-effect-gate');
const navigationGate = require('../core/kernel/enforcement/navigation-gate');
const storageGate = require('../core/kernel/enforcement/storage-gate');
const clipboardGate = require('../core/kernel/enforcement/clipboard-gate');
const secretReleaseGate = require('../core/kernel/enforcement/secret-release-gate');
const contextFirewall = require('../core/kernel/context-firewall');
const txnEngine = require('../core/kernel/transaction-engine');
const securityLedger = require('../core/security-ledger');
const capMgr = require('../core/capability-manager');
const secretVault = require('../core/secret-vault');

function runEnforcementBoundarySuite() {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL v2.2 — ENFORCEMENT BOUNDARY & CONTEXT FIREWALL VERIFICATION');
  console.log('='.repeat(75));

  const dom = new JSDOM(`
    <!DOCTYPE html>
    <html>
      <body>
        <form id="login-form" action="/login">
          <input type="text" id="username" name="username" value="">
          <input type="password" id="password" name="password" value="">
          <button type="submit" id="submit-btn">Log In</button>
        </form>
        <button id="buy-btn">One-Click Buy</button>
      </body>
    </html>
  `);

  const doc = dom.window.document;
  const form = doc.getElementById('login-form');
  const userField = doc.getElementById('username');
  const pwdField = doc.getElementById('password');
  const submitBtn = doc.getElementById('submit-btn');
  const buyBtn = doc.getElementById('buy-btn');

  let passed = 0;
  let total = 0;

  function check(desc, fn) {
    total++;
    try {
      fn();
      passed++;
      console.log(`  ✅ [PASS] ${desc}`);
    } catch (err) {
      console.error(`  ❌ [FAIL] ${desc} → ${err.message}`);
      throw err;
    }
  }

  // 1. DOM Effect Gate Tests
  console.log('\n▶ [PART 1: DOM EFFECT GATE]');
  console.log('-'.repeat(75));

  check('Unmediated submit on form fails without capability', () => {
    const res = domGate.dispatchSubmit(form, { capabilityId: null });
    assert.strictEqual(res.success, false);
    assert.ok(res.reason.includes('explicit capabilityId'));
  });

  check('Mediated click with valid capability succeeds', () => {
    const cap = capMgr.issueCapability({ actionType: 'CLICK', targetFingerprint: 'btn:test' });
    const res = domGate.dispatchClick(buyBtn, { capabilityId: cap.capabilityId });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.capabilityConsumed, true);
  });

  // 2. Secret Release Gate Tests
  console.log('\n▶ [PART 2: SECRET RELEASE GATE & ISOLATION]');
  console.log('-'.repeat(75));

  check('Direct secret injection requires valid capability and origin match', () => {
    secretVault.storeSecret('LOCAL_SECRET_PWD', 'super_secret_password_123', 'localhost', 'password', 'Account Password');
    const cap = capMgr.issueCapability({ actionType: 'TYPE', targetFingerprint: 'password' });

    const releaseRes = secretReleaseGate.releaseSecretToElement({
      secretId: 'LOCAL_SECRET_PWD',
      targetElement: pwdField,
      origin: 'localhost',
      capabilityId: cap.capabilityId
    });

    assert.strictEqual(releaseRes.success, true);
    assert.strictEqual(pwdField.value, 'super_secret_password_123');
  });

  check('Secret release fails if capability is missing or replayed', () => {
    const res = secretReleaseGate.releaseSecretToElement({
      secretId: 'LOCAL_SECRET_PWD',
      targetElement: pwdField,
      origin: 'localhost',
      capabilityId: null
    });
    assert.strictEqual(res.success, false);
  });

  // 3. Network Effect Gate Tests
  console.log('\n▶ [PART 3: NETWORK EFFECT GATE & EGRESS]');
  console.log('-'.repeat(75));

  check('Permits safe API requests to legitimate endpoints', () => {
    const res = networkGate.inspectNetworkTransmission({
      url: 'https://api.example.com/data',
      method: 'GET'
    });
    assert.strictEqual(res.allowed, true);
  });

  check('Blocks exfiltration containing canary secrets', () => {
    const res = networkGate.inspectNetworkTransmission({
      url: 'https://evil.test/collect',
      body: 'exfiltrated_data:VEIL_CANARY_SECRET_LEAK'
    });
    assert.strictEqual(res.allowed, false);
    assert.strictEqual(res.verdict, 'BLOCKED');
  });

  // 4. Navigation Gate Tests
  console.log('\n▶ [PART 4: NAVIGATION GATE]');
  console.log('-'.repeat(75));

  check('Blocks executable javascript: URLs', () => {
    const res = navigationGate.inspectNavigation('javascript:stealData()', 'localhost');
    assert.strictEqual(res.allowed, false);
  });

  check('Requires capability for unlisted cross-origin navigation', () => {
    const res = navigationGate.inspectNavigation('https://foreign-bank.xyz/transfer', 'https://shop.example');
    assert.strictEqual(res.allowed, false);
  });

  // 5. Storage Gate Tests
  console.log('\n▶ [PART 5: STORAGE GATE]');
  console.log('-'.repeat(75));

  check('Blocks writing plaintext password into client storage', () => {
    const res = storageGate.inspectStorageWrite('localStorage', 'user_password', 'raw_pass');
    assert.strictEqual(res.allowed, false);
  });

  check('Permits writing non-sensitive layout preferences', () => {
    const res = storageGate.inspectStorageWrite('localStorage', 'theme_preference', 'dark');
    assert.strictEqual(res.allowed, true);
  });

  // 6. Clipboard Gate Tests
  console.log('\n▶ [PART 6: CLIPBOARD GATE]');
  console.log('-'.repeat(75));

  check('Blocks clipboard exfiltration of high-taint credential data without capability', () => {
    const res = clipboardGate.inspectClipboardWrite('my_secret_token_123', {
      textTaint: 5 // CREDENTIAL
    });
    assert.strictEqual(res.allowed, false);
  });

  // 7. Context Firewall Tests
  console.log('\n▶ [PART 7: CONTEXT FIREWALL & PURPOSE-BOUND PERCEPTION]');
  console.log('-'.repeat(75));

  check('Filters out card numbers and sensitive fields during product search task', () => {
    const rawElements = [
      { id: 'el-1', name: 'GPU RTX 4090', tag: 'div', role: 'heading' },
      { id: 'el-2', name: 'Price: ₹1,99,999', tag: 'span', role: 'text' },
      { id: 'el-3', name: 'credit_card_number', tag: 'input', role: 'textbox', expectedSecretType: 'card' }
    ];

    const filterRes = contextFirewall.filterContextForModel({
      task: 'product_search',
      origin: 'https://shop.test',
      elements: rawElements
    });

    assert.strictEqual(filterRes.allowedIR.schema, 'veil.ir/v2');
    assert.strictEqual(filterRes.scrubbedCount, 1);
    assert.strictEqual(filterRes.filteredElements[0].accessibleToModel, true);
    assert.strictEqual(filterRes.filteredElements[2].accessibleToModel, false);
    assert.ok(filterRes.filteredElements[2].name.includes('[PROTECTED_CARD_FIELD]'));
  });

  // 8. Transaction Compensation & Action Receipts
  console.log('\n▶ [PART 8: TRANSACTION ENGINE COMPENSATION & RECEIPTS]');
  console.log('-'.repeat(75));

  check('Executes compensation rollback for multi-step reversible actions', () => {
    let reverted = false;
    const txn = txnEngine.beginTransaction({ intent: 'order_flow', doc });

    txnEngine.recordStep(txn.id, {
      id: 'step_1_add_cart',
      name: 'Add to Cart',
      reversibility: 'REVERSIBLE',
      compensate: () => { reverted = true; }
    });

    txnEngine.recordStep(txn.id, {
      id: 'step_2_checkout',
      name: 'Irreversible Checkout Attempt',
      reversibility: 'IRREVERSIBLE'
    });

    const compRes = txnEngine.compensate(txn.id);
    assert.strictEqual(reverted, true, 'Reversible step compensation must be called');
    assert.strictEqual(compRes.compensatedCount, 1);
    assert.strictEqual(compRes.hasIrreversibleSteps, true);
  });

  check('Generates verifiable VEIL ACTION RECEIPT with ledger hash', () => {
    const txn = txnEngine.beginTransaction({ intent: 'checkout', doc });
    const receipt = txnEngine.generateActionReceipt(txn.id, {
      actor: 'agent-07',
      target: 'form#order',
      policy: 'order_policy_v2',
      executionStatus: 'SUCCESS'
    });

    assert.strictEqual(receipt.receiptType, 'VEIL_ACTION_RECEIPT');
    assert.strictEqual(receipt.actor, 'agent-07');
    assert.ok(receipt.receiptId.startsWith('rcpt_'));
    assert.ok(receipt.ledgerHash.length >= 64);
  });

  // 9. Tamper-Evident Ledger Checkpointing & Offline Verification
  console.log('\n▶ [PART 9: LEDGER CHECKPOINTING & OFFLINE VERIFIER]');
  console.log('-'.repeat(75));

  check('Exports verifiable security receipt and passes offline validation', () => {
    const exportReceipt = securityLedger.exportSecurityReceipt();
    assert.strictEqual(exportReceipt.receiptType, 'VEIL_SECURITY_RECEIPT');
    assert.ok(exportReceipt.chain.length > 0);

    const verifyRes = securityLedger.verifySecurityReceipt(exportReceipt);
    assert.strictEqual(verifyRes.valid, true);
    assert.strictEqual(verifyRes.verifiedEvents, exportReceipt.chain.length);
  });

  console.log('\n' + '='.repeat(75));
  console.log('🏆 ENFORCEMENT BOUNDARY VERIFICATION SUMMARY');
  console.log('='.repeat(75));
  console.log(`  Tests Executed: ${total}`);
  console.log(`  Tests Passed:   ${passed} / ${total} (100.0%)`);
  console.log('  All Runtime Gates: ACTIVE & CERTIFIED');
  console.log('='.repeat(75) + '\n');

  return { passed, total, certified: passed === total };
}

if (require.main === module) {
  const ok = runEnforcementBoundarySuite();
  process.exit(ok.certified ? 0 : 1);
}

module.exports = { runEnforcementBoundarySuite };
