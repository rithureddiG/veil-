/**
 * VEIL — Independent Offline Security Receipt Verifier CLI
 *
 * Usage:
 *   node scripts/verify-receipt.js <path-to-receipt.json>
 *
 * Implements Invariant I8 & C7:
 * "Any third party or independent auditor can verify the cryptographic integrity
 *  of a VEIL security receipt completely offline without running VEIL."
 */

const fs = require('fs');
const path = require('path');
const securityLedger = require('../veil-extension/core/security-ledger');

function runReceiptVerifier(filePath) {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL — INDEPENDENT OFFLINE SECURITY RECEIPT VERIFIER');
  console.log('='.repeat(75));

  let receiptData;
  if (!filePath) {
    // Self-test mode: export from live ledger and verify
    console.log('▶ [SELF-TEST MODE]: Generating synthetic live audit receipt for verification...');
    securityLedger.clearLedger();
    securityLedger.recordEvent('BOOT_INITIALIZE', 'kernel', { version: '2.2.0' });
    securityLedger.recordEvent('POLICY_EVALUATED', 'pdp', { decision: 'ALLOW', risk: 'SAFE' });
    securityLedger.recordEvent('CAPABILITY_ISSUED', 'capability_manager', { actionType: 'CLICK', scope: 'btn:1' });
    securityLedger.recordEvent('ACTION_EXECUTED', 'effect_gate', { effect: 'CLICK', status: 'SUCCESS' });

    receiptData = securityLedger.exportSecurityReceipt();
  } else {
    const resolved = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(resolved)) {
      console.error(`❌ Error: File not found at ${resolved}`);
      process.exit(1);
    }
    const raw = fs.readFileSync(resolved, 'utf8');
    receiptData = JSON.parse(raw);
  }

  console.log(`  • Receipt Type:     ${receiptData.receiptType || 'UNKNOWN'}`);
  console.log(`  • Version:          ${receiptData.version || 'UNKNOWN'}`);
  console.log(`  • Event Count:      ${receiptData.eventCount || 0}`);
  console.log(`  • Claimed HeadHash: ${receiptData.headHash}`);
  console.log(`  • Session Root:     ${receiptData.sessionRoot}`);
  console.log('-'.repeat(75));

  const result = securityLedger.verifySecurityReceipt(receiptData);

  if (result.valid) {
    console.log('✅ OFFLINE CRYPTOGRAPHIC VERIFICATION SUCCESSFUL');
    console.log(`   • All ${result.verifiedEvents} events verified from Genesis to Head.`);
    console.log(`   • Terminal Hash: ${result.headHash}`);
    console.log('   • Tamper-evidence check: ZERO modifications detected.');
    console.log('='.repeat(75) + '\n');
    return true;
  } else {
    console.error('❌ OFFLINE CRYPTOGRAPHIC VERIFICATION FAILED');
    console.error(`   • Error: ${result.error}`);
    console.error(`   • Failed after verifying ${result.verifiedEvents} events.`);
    console.log('='.repeat(75) + '\n');
    return false;
  }
}

if (require.main === module) {
  const targetFile = process.argv[2];
  const ok = runReceiptVerifier(targetFile);
  process.exit(ok ? 0 : 1);
}

module.exports = { runReceiptVerifier };
