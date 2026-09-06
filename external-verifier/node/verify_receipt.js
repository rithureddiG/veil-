#!/usr/bin/env node
/**
 * VEIL — Independent Node.js Receipt Verifier CLI
 *
 * Usage:
 *   node external-verifier/node/verify_receipt.js [path/to/receipt.json]
 *
 * Evaluates authenticity without trusting the VEIL extension runtime.
 */

const fs = require('fs');
const path = require('path');
const { verifyReceipt } = require('../receipt-verifier');

function main() {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL — INDEPENDENT NODE.JS RECEIPT VERIFIER');
  console.log('='.repeat(75));

  const targetPath = process.argv[2];
  let receiptData;

  if (!targetPath) {
    console.log('▶ [SELF-TEST MODE]: Generating and verifying synthetic receipt bundle...');
    const crypto = require('crypto');
    const h0 = '0'.repeat(64);
    const p1 = '{"version":"2.4.0"}';
    const h1 = crypto.createHash('sha256').update(`${h0}:0:1000:BOOT:${crypto.createHash('sha256').update(p1).digest('hex')}`).digest('hex');

    receiptData = {
      receiptType: 'VEIL_SECURITY_RECEIPT',
      version: '2.4.0',
      genesisHash: h0,
      headHash: h1,
      sessionRoot: crypto.createHash('sha256').update(`SESSION_ROOT:${h1}::1`).digest('hex'),
      eventCount: 1,
      checkpoints: [],
      chain: [
        {
          id: 'evt-0',
          eventIndex: 0,
          timestamp: 1000,
          type: 'BOOT',
          stage: 'kernel',
          detail: { version: '2.4.0' },
          payloadHash: crypto.createHash('sha256').update(p1).digest('hex'),
          prevHash: h0,
          hash: h1
        }
      ],
      exportedAt: Date.now()
    };
  } else {
    const resolved = path.resolve(process.cwd(), targetPath);
    if (!fs.existsSync(resolved)) {
      console.error(`❌ Error: File not found at ${resolved}`);
      process.exit(1);
    }
    receiptData = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  }

  const result = verifyReceipt(receiptData);

  console.log(`  • Claimed Version:     ${receiptData.version || 'UNKNOWN'}`);
  console.log(`  • Claimed Head Hash:   ${receiptData.headHash}`);
  console.log(`  • Events Verified:     ${result.verifiedEvents}`);
  console.log(`  • Session Root Valid:  ${result.sessionRootValid ? 'YES' : 'NO'}`);
  console.log('-'.repeat(75));

  if (result.verdict === 'VALID') {
    console.log('✅ INDEPENDENT VERIFICATION VERDICT: VALID');
    console.log('   • Cryptographic hash chain confirmed from Genesis to Head.');
    console.log('   • All payload commitments recomputed and confirmed.');
    console.log('   • Zero tampering or truncation detected.');
    console.log('='.repeat(75) + '\n');
    process.exit(0);
  } else {
    console.error(`❌ INDEPENDENT VERIFICATION VERDICT: ${result.verdict}`);
    for (const err of result.errors) {
      console.error(`   • Error: ${err}`);
    }
    console.log('='.repeat(75) + '\n');
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main };
