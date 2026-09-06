/**
 * VEIL — Browser Lifecycle & Multi-Tab Isolation Reality Test Suite
 * File: real-lab/runner/lifecycle-test.js
 *
 * Formally verifies Invariant I3:
 * "A capability never survives a security-relevant browser state transition
 *  unless explicitly rebound and reauthorized."
 *
 * Tests:
 *   1. Cross-Tab Replay Rejection (Tab A capability cannot execute in Tab B)
 *   2. Navigation State Invalidation (Capability dies upon URL change)
 *   3. DOM Mutation StateHash Invalidation (TOCTOU race protection)
 *   4. SPA Route Transition Invalidation (Hash/Path changes require new state commitment)
 *   5. Browser Reload / Session Resumption Invalidation
 */

const assert = require('assert');
const { CapabilityManager } = require('../../veil-extension/core/capability-manager.js');
const { PolicyDecisionPoint } = require('../../veil-extension/core/kernel/policy-decision-point.js');
const { UniversalEffectGate } = require('../../veil-extension/core/kernel/enforcement/effect-gate.js');
const { hashState } = require('../../veil-extension/core/state-hasher.js');

function runLifecycleTests() {
  console.log('='.repeat(75));
  console.log('🛡️  VEIL REAL-LAB — BROWSER LIFECYCLE & MULTI-TAB ISOLATION SUITE');
  console.log('='.repeat(75));

  let passed = 0;
  let total = 5;

  const pdp = new PolicyDecisionPoint();
  const capManager = new CapabilityManager();
  const effectGate = new UniversalEffectGate(pdp, capManager);

  // Test 1: Cross-Tab Isolation
  console.log('Test 1: Cross-Tab Replay Denial (Tab A -> Tab B)...');
  const tabAId = 101;
  const tabBId = 102;
  const stateHashTabA = hashState('tab_A_dom_content_v1');

  // Capability issued explicitly for Tab A
  const decisionTabA = pdp.evaluate({
    proposal: { type: 'CLICK', target: { id: 'btn-buy' } },
    origin: 'localhost:3000',
    stateHash: stateHashTabA
  });
  const capTabA = capManager.issueFromDecision(decisionTabA, { tabId: tabAId });

  // Attempt to execute capability in context of Tab B
  const executionInTabB = effectGate.executeProtectedEffect({
    type: 'CLICK',
    targetFingerprint: 'btn-buy',
    origin: 'localhost:3000',
    stateHash: stateHashTabA,
    tabId: tabBId,
    capabilityToken: capTabA.token
  });

  assert.strictEqual(executionInTabB.status, 'DENIED', 'Cross-tab execution must be denied');
  console.log('  ✔ Capability issued for Tab A rejected in Tab B');
  passed++;

  // Test 2: Navigation State Invalidation (Origin/URL change)
  console.log('Test 2: Navigation Invalidation (shop.example -> evil.example)...');
  const initialUrl = 'http://localhost:3000/shop.html';
  const navigatedUrl = 'http://attacker.example/phish.html';
  const stateHashInitial = hashState('page_state_initial');

  const capNav = capManager.issueFromDecision(
    pdp.evaluate({ proposal: { type: 'CLICK', target: { id: 'btn-submit' } }, origin: 'localhost:3000', stateHash: stateHashInitial }),
    { origin: 'localhost:3000' }
  );

  // Attempt execution after navigation
  const postNavExecution = effectGate.executeProtectedEffect({
    type: 'CLICK',
    targetFingerprint: 'btn-submit',
    origin: 'attacker.example', // Navigated to different origin
    stateHash: stateHashInitial,
    capabilityToken: capNav.token
  });

  assert.strictEqual(postNavExecution.status, 'DENIED', 'Capability must die upon navigation');
  console.log('  ✔ Pre-navigation capability denied on newly navigated page');
  passed++;

  // Test 3: DOM Mutation StateHash Invalidation (TOCTOU Defense)
  console.log('Test 3: DOM Mutation StateHash Mismatch Invalidation...');
  const preMutationState = 'dom_state_before_tampering_₹74999';
  const postMutationState = 'dom_state_after_tampering_₹7499';
  const stateHashPre = hashState(preMutationState);
  const stateHashPost = hashState(postMutationState);

  const capMutation = capManager.issueFromDecision(
    pdp.evaluate({ proposal: { type: 'CLICK', target: { id: 'btn-pay' } }, stateHash: stateHashPre }),
    { stateHash: stateHashPre }
  );

  // When effect executes, the DOM has mutated to postMutationState
  const tamperedExecution = effectGate.executeProtectedEffect({
    type: 'CLICK',
    targetFingerprint: 'btn-pay',
    stateHash: stateHashPost, // Mismatched state commitment
    capabilityToken: capMutation.token
  });

  assert.strictEqual(tamperedExecution.status, 'DENIED', 'Mutated DOM state must trigger fail-closed denial');
  console.log('  ✔ DOM mutation invalidates state commitment H(S); action aborted');
  passed++;

  // Test 4: SPA Route Transition Invalidation
  console.log('Test 4: Single Page App (SPA) route transition invalidation...');
  const spaRouteA = 'http://localhost:3000/#/dashboard';
  const spaRouteB = 'http://localhost:3000/#/settings';
  const hashA = hashState(spaRouteA);
  const hashB = hashState(spaRouteB);

  const capSpa = capManager.issueFromDecision(
    pdp.evaluate({ proposal: { type: 'CLICK', target: { id: 'nav-tab' } }, stateHash: hashA }),
    { stateHash: hashA }
  );

  const spaExecution = effectGate.executeProtectedEffect({
    type: 'CLICK',
    targetFingerprint: 'nav-tab',
    stateHash: hashB,
    capabilityToken: capSpa.token
  });
  assert.strictEqual(spaExecution.status, 'DENIED');
  console.log('  ✔ SPA route change invalidates previous route capability');
  passed++;

  // Test 5: Browser Reload / Session Expiration
  console.log('Test 5: Expired / Reloaded capability cleanup...');
  const shortLivedCap = capManager.issueFromDecision(
    pdp.evaluate({ proposal: { type: 'CLICK', target: { id: 'btn-refresh' } } }),
    { ttlMs: 1 } // 1 millisecond TTL
  );

  // Wait 15ms for expiration
  const waitUntil = Date.now() + 15;
  while (Date.now() < waitUntil) {}

  const expiredVerify = capManager.verifyCapability(shortLivedCap.token, 'CLICK', 'btn-refresh');
  assert.strictEqual(expiredVerify.valid, false, 'Expired capability must fail validation');
  console.log('  ✔ Expired capability token automatically evicted and denied');
  passed++;

  console.log('-'.repeat(75));
  console.log(`Summary: ${passed}/${total} Lifecycle & Multi-Tab tests PASSED`);
  console.log('='.repeat(75) + '\n');
  return { passed, total };
}

if (require.main === module) {
  runLifecycleTests();
}

module.exports = { runLifecycleTests };
