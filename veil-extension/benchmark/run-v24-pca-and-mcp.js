/**
 * VEIL v2.4 — Master PCA, MCP Gateway & Unknown Attack Suite (Suite 15)
 *
 * Validates:
 * 1. Proof-Carrying Actions (Pillar R6): Mathematical symmetry between authorization and execution.
 * 2. Zero-Trust MCP Tool Security Gateway (Pillar R7): Taint isolation, capability binding, TOCTOU guard.
 * 3. Unknown Attack Challenge & V-ATM Taxonomy (Pillar R5): 100% fail-closed on compound unknown attacks.
 */

const assert = require('assert');
const { ProofCarryingActionManager } = require('../core/kernel/proof-carrying-actions');
const { ZeroTrustMcpGateway, MCP_TIERS } = require('../core/kernel/mcp-gateway');
const { runChallenge } = require('../../lab/unknown-attack-challenge');

function testProofCarryingActions() {
  console.log('='.repeat(75));
  console.log('📜 TEST 1: PROOF-CARRYING ACTIONS (PCA) MATHEMATICAL SYMMETRY');
  console.log('='.repeat(75));

  const pcaMgr = new ProofCarryingActionManager();
  const preState = '0x_dom_state_checkout_clean_778899';
  const postState = '0x_dom_state_checkout_confirmed_112233';

  // 1. Generate PreExecutionProof
  const action = { type: 'CLICK', target: '#confirm-checkout-btn', parameters: { orderId: 4491 } };
  const pca = pcaMgr.generatePreExecutionProof({
    action,
    intent: 'confirm_order',
    origin: 'https://trusted-merchant.com',
    preStateHash: preState,
    permittedEffects: ['EFFECT_INTERACT_CLICK'],
    policyRuleId: 'VPL-ALLOW-CHECKOUT'
  });

  console.log(`  [+] Generated PreExecutionProof: ${pca.pcaId}`);
  assert.strictEqual(pca.status, 'PRE_EXECUTION');
  assert.ok(pca.preProof.authorizationSignature);

  // 2. Verify PreExecutionProof under correct state
  const preVerifyValid = pcaMgr.verifyPreExecutionProof(pca, preState);
  assert.strictEqual(preVerifyValid.valid, true, 'PreProof must be valid when state matches');

  // 3. Negative Test: TOCTOU State Mismatch
  const preVerifyTamperedState = pcaMgr.verifyPreExecutionProof(pca, '0x_adversary_swapped_dom_state');
  assert.strictEqual(preVerifyTamperedState.valid, false);
  assert.strictEqual(preVerifyTamperedState.error, 'ERR_PCA_STATE_COMMITMENT_MISMATCH');
  console.log('  [+] TOCTOU State Mismatch intercepted fail-closed');

  // 4. Negative Test: Action Tampering
  const tamperedActionPca = JSON.parse(JSON.stringify(pca));
  tamperedActionPca.action.target = '#wire-transfer-evil-btn';
  const actionTamperRes = pcaMgr.verifyPreExecutionProof(tamperedActionPca, preState);
  assert.strictEqual(actionTamperRes.valid, false);
  assert.strictEqual(actionTamperRes.error, 'ERR_PCA_ACTION_TAMPERED');
  console.log('  [+] Action Mutation intercepted fail-closed');

  // 5. Complete PostExecutionProof
  const completedPca = pcaMgr.completePostExecutionProof(pca, {
    postStateHash: postState,
    executionTrace: ['RESOLVE_NODE', 'DISPATCH_CLICK', 'CONFIRM_NAVIGATION'],
    receiptId: 'rec_order_4491',
    success: true
  });

  console.log(`  [+] Completed PostExecutionProof: status=${completedPca.status}`);
  assert.strictEqual(completedPca.status, 'COMPLETED');
  assert.ok(completedPca.postProof.completionSignature);

  // 6. Negative Test: Single-Use Replay Protection
  const replayAttempt = pcaMgr.verifyPreExecutionProof(pca, preState);
  assert.strictEqual(replayAttempt.valid, false);
  assert.strictEqual(replayAttempt.error, 'ERR_PCA_ALREADY_CONSUMED');
  console.log('  [+] PCA Single-Use Replay attempt blocked fail-closed');

  // 7. Offline Independent Verification of Full Bundle
  const offlineAudit = pcaMgr.verifyCompleteProof(completedPca);
  assert.strictEqual(offlineAudit.valid, true);
  console.log(`  [+] Offline Auditor Certification: ${offlineAudit.transition}`);
  console.log('  [PASS] Proof-Carrying Actions: Verified & Invariants Certified.\n');
}

function testZeroTrustMcpGateway() {
  console.log('='.repeat(75));
  console.log('🚪 TEST 2: ZERO-TRUST MCP TOOL SECURITY GATEWAY');
  console.log('='.repeat(75));

  const gateway = new ZeroTrustMcpGateway();
  gateway.setHandler('write_file', (args) => ({ bytesWritten: 1024, path: args.path }));
  gateway.setHandler('execute_command', (args) => ({ stdout: 'clean' }));

  const preState = 'hash_config_file_v1';

  // 1. Tier 0 Tool: Read allowed without token
  const readRes = gateway.mediateToolCall({
    toolName: 'read_file',
    arguments: { path: '/data/read.txt' },
    caller: { agentId: 'reader_agent' }
  });
  assert.strictEqual(readRes.status, 'ALLOWED');
  console.log('  [+] Tier 0 Read-Only tool mediated and allowed');

  // 2. Negative Test: Tainted input invoking Tier 2 tool
  const taintedRes = gateway.mediateToolCall({
    toolName: 'write_file',
    arguments: { path: '/etc/hosts', content: '127.0.0.1 evil.com' },
    caller: { agentId: 'web_agent' },
    taintTags: ['TAINT_UNTRUSTED_DOM', 'TAINT_INDIRECT_PROMPT'],
    capabilityToken: { targetTool: 'write_file', nonce: 'nonce_01', expiresAt: Date.now() + 5000 },
    preStateHash: preState,
    currentStateHash: preState
  });
  assert.strictEqual(taintedRes.status, 'BLOCKED');
  assert.strictEqual(taintedRes.error, 'ERR_TAINT_PROPAGATION_DETECTED');
  console.log('  [+] Tainted Prompt Injection into Tier 2 tool BLOCKED');

  // 3. Positive Test: Clean Tier 2 tool invocation with Capability & Pre-State
  const cleanRes = gateway.mediateToolCall({
    toolName: 'write_file',
    arguments: { path: '/app/config.json', content: '{"ok":true}' },
    caller: { agentId: 'builder_agent' },
    taintTags: [],
    capabilityToken: { targetTool: 'write_file', nonce: 'nonce_clean_01', expiresAt: Date.now() + 5000 },
    preStateHash: preState,
    currentStateHash: preState
  });
  assert.strictEqual(cleanRes.status, 'ALLOWED');
  assert.ok(cleanRes.receipt);
  console.log(`  [+] Tier 2 Authorized Tool executed, receipt: ${cleanRes.receipt.receiptId}`);

  // 4. Offline Verification of Tool Receipt
  const receiptVerify = gateway.verifyToolReceipt(cleanRes.receipt);
  assert.strictEqual(receiptVerify.valid, true);
  console.log('  [+] Tool Receipt cryptographic signature validated offline');

  // 5. Negative Test: Replay of consumed capability nonce
  const replayRes = gateway.mediateToolCall({
    toolName: 'write_file',
    arguments: { path: '/app/config.json', content: '{"ok":true}' },
    caller: { agentId: 'builder_agent' },
    taintTags: [],
    capabilityToken: { targetTool: 'write_file', nonce: 'nonce_clean_01', expiresAt: Date.now() + 5000 },
    preStateHash: preState,
    currentStateHash: preState
  });
  assert.strictEqual(replayRes.status, 'BLOCKED');
  assert.strictEqual(replayRes.error, 'ERR_TOKEN_REPLAY');
  console.log('  [+] MCP Capability Nonce Replay BLOCKED');

  // 6. Negative Test: Tier 3 Command Execution without user confirmation
  const tier3Res = gateway.mediateToolCall({
    toolName: 'execute_command',
    arguments: { cmd: 'rm -rf /' },
    caller: { agentId: 'admin_agent' },
    taintTags: [],
    capabilityToken: { targetTool: 'execute_command', nonce: 'nonce_sh_01', expiresAt: Date.now() + 5000 },
    preStateHash: 'shell_state_0',
    currentStateHash: 'shell_state_0',
    userConfirmation: false
  });
  assert.strictEqual(tier3Res.status, 'CONFIRM_REQUIRED');
  assert.strictEqual(tier3Res.error, 'ERR_REQUIRES_EXPLICIT_CONFIRMATION');
  console.log('  [+] Tier 3 Critical Tool Execution escalated to out-of-band confirmation');

  console.log('  [PASS] Zero-Trust MCP Gateway: 100% Policy & Taint Enforcement.\n');
}

function runPcaAndMcpSuite() {
  console.log('\n' + '#'.repeat(75));
  console.log('  VEIL v2.4 — SUITE 15: PCA, MCP GATEWAY & UNKNOWN ATTACK CHALLENGE');
  console.log('#'.repeat(75) + '\n');

  // Sub-suite 1: Proof-Carrying Actions
  testProofCarryingActions();

  // Sub-suite 2: Zero-Trust MCP Gateway
  testZeroTrustMcpGateway();

  // Sub-suite 3: Unknown Attack Challenge
  const challengeRes = runChallenge();
  assert.strictEqual(challengeRes.bypasses, 0, 'Zero hostile bypasses allowed in Unknown Attack Challenge');

  console.log('='.repeat(75));
  console.log('🏆 SUITE 15 COMPLETE: PCA, MCP GATEWAY & UNKNOWN ATTACK CHALLENGE PASSED');
  console.log('='.repeat(75) + '\n');

  return {
    suite: 'SUITE_15_PCA_MCP_UNKNOWN_ATTACK',
    passed: true,
    attacksBlocked: challengeRes.blockedAttacks
  };
}

if (require.main === module) {
  runPcaAndMcpSuite();
}

module.exports = {
  runPcaAndMcpSuite
};
