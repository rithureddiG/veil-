/**
 * VEIL v2.2 — Automated Kernel Fuzzing Engine
 *
 * Implements Invariant I1-I8 & C9:
 * "Fuzzing produces ZERO invariant violations and ZERO unauthorized side effects
 *  across 1,000+ randomized permutations of DOM, Capability, Taint, and Network states."
 */

const assert = require('assert');
const { JSDOM } = require('jsdom');

const effectGate = require('../core/kernel/enforcement/effect-gate');
const capMgr = require('../core/capability-manager');
const taintEngine = require('../core/kernel/taint-engine');
const egress = require('../core/kernel/egress-firewall');
const pdp = require('../core/kernel/policy-decision-point');
const stateHasher = require('../core/state-hasher');

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomString(len = 8) {
  return Math.random().toString(36).substring(2, 2 + len);
}

function runFuzzSuite(iterations = 1000) {
  console.log('='.repeat(75));
  console.log(`🎲 VEIL v2.2 — AUTOMATED ADVERSARIAL FUZZING ENGINE (${iterations} Iterations)`);
  console.log('='.repeat(75));

  let unauthorizedSideEffects = 0;
  let invariantViolations = 0;
  let totalPermutationsTested = 0;

  const sampleEffects = ['CLICK', 'TYPE', 'SUBMIT', 'NAVIGATE', 'PURCHASE', 'TRANSFER', 'DELETE', 'SECRET_RELEASE'];
  const sampleSinks = Object.values(taintEngine.SINKS);
  const sampleTaints = [0, 1, 2, 3, 4, 5];
  const sampleProtocols = ['http://', 'https://', 'javascript:', 'data:', 'file://', 'ftp://'];

  console.log('▶ [STAGE 1: CAPABILITY & EFFECT GATE FUZZING]');
  for (let i = 0; i < iterations / 4; i++) {
    totalPermutationsTested++;
    const randomEffect = randomChoice(sampleEffects);
    const hasForgedCap = Math.random() < 0.7;
    const randomCapId = hasForgedCap ? `cap_forged_${randomString(16)}` : null;

    const dom = new JSDOM(`<button id="${randomString(6)}">Test Button</button>`);
    const btn = dom.window.document.querySelector('button');

    // Attempt protected effect dispatch with arbitrary random parameters
    const res = effectGate.executeProtectedEffect({
      effectId: randomEffect,
      targetElement: btn,
      capabilityId: randomCapId,
      origin: `https://${randomString(8)}.example`,
      stateHash: randomString(64),
      payload: { value: randomString(20) }
    });

    // An irreversible or sensitive effect without a valid signed capability MUST fail closed
    if (['PURCHASE', 'TRANSFER', 'DELETE', 'SECRET_RELEASE'].includes(randomEffect)) {
      if (res.success) {
        unauthorizedSideEffects++;
        console.error(`🚨 INVARIANT BREACH: Unauthorized ${randomEffect} dispatched with fake capability!`);
      }
    }
  }

  console.log('▶ [STAGE 2: TAINT LATTICE & SINK FLOW FUZZING]');
  for (let i = 0; i < iterations / 4; i++) {
    totalPermutationsTested++;
    const level = randomChoice(sampleTaints);
    const sink = randomChoice(sampleSinks);
    const hasCap = Math.random() < 0.2;

    const flowRes = taintEngine.canFlow(level, sink, {
      sourceOrigin: 'origin.test',
      sinkOrigin: 'destination.test',
      hasCapability: hasCap
    });

    // Invariant I5: Financial Secret (4) and Credential (5) CAN NEVER flow to CLOUD_MODEL sink
    if (sink === taintEngine.SINKS.CLOUD_MODEL && level >= taintEngine.TAINT_LEVELS.PERSONAL) {
      if (flowRes.allowed) {
        invariantViolations++;
        console.error(`🚨 TAINT VIOLATION: Level ${level} allowed to flow to CLOUD_MODEL!`);
      }
    }

    // Invariant I6: Tainted data without capability cannot flow to REMOTE_EGRESS
    if (sink === taintEngine.SINKS.REMOTE_EGRESS && level >= taintEngine.TAINT_LEVELS.SENSITIVE && !hasCap) {
      if (flowRes.allowed) {
        invariantViolations++;
        console.error(`🚨 TAINT VIOLATION: Level ${level} allowed to flow to REMOTE_EGRESS without capability!`);
      }
    }
  }

  console.log('▶ [STAGE 3: EGRESS & PROTOCOL INJECTION FUZZING]');
  for (let i = 0; i < iterations / 4; i++) {
    totalPermutationsTested++;
    const proto = randomChoice(sampleProtocols);
    const targetUrl = `${proto}${randomString(10)}.xyz/path?param=${randomString(8)}`;
    const containsCanary = Math.random() < 0.5;
    const body = containsCanary ? `VEIL_CANARY_TEST_${randomString(12)}` : randomString(50);

    const egressRes = egress.inspectOutbound({ url: targetUrl, body });

    if (containsCanary && egressRes.allowed) {
      invariantViolations++;
      console.error(`🚨 EGRESS VIOLATION: Canary token leaked in outbound request!`);
    }

    if (egress.isBlacklisted(targetUrl) && egressRes.allowed) {
      invariantViolations++;
      console.error(`🚨 EGRESS VIOLATION: Blacklisted URL permitted!`);
    }
  }

  console.log('▶ [STAGE 4: DOM STATE MUTATION & INTEGRITY FUZZING]');
  for (let i = 0; i < iterations / 4; i++) {
    totalPermutationsTested++;
    const dom = new JSDOM(`<div><span id="price">₹${Math.floor(Math.random() * 10000)}</span></div>`);
    const doc = dom.window.document;
    const hash1 = stateHasher.computeStateHash(doc).stateHash;

    // Mutate state
    doc.getElementById('price').textContent = `₹${Math.floor(Math.random() * 10000) + 20000}`;
    const hash2 = stateHasher.computeStateHash(doc).stateHash;

    if (hash1 === hash2) {
      invariantViolations++;
      console.error('🚨 STATE INTEGRITY VIOLATION: State hash collision under DOM mutation!');
    }
  }

  console.log('\n' + '='.repeat(75));
  console.log('📊 FUZZING VERIFICATION SCORECARD');
  console.log('='.repeat(75));
  console.log(`  Permutations Fuzzed:        ${totalPermutationsTested}`);
  console.log(`  Unauthorized Side Effects:  ${unauthorizedSideEffects} (Zero Tolerance)`);
  console.log(`  Invariant Violations:       ${invariantViolations} (Zero Tolerance)`);
  console.log(`  Fuzzing Certification:      ${unauthorizedSideEffects === 0 && invariantViolations === 0 ? '✅ PASSED' : '❌ FAILED'}`);
  console.log('='.repeat(75) + '\n');

  return {
    iterations: totalPermutationsTested,
    unauthorizedSideEffects,
    invariantViolations,
    certified: unauthorizedSideEffects === 0 && invariantViolations === 0
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runFuzzSuite };
}

if (require.main === module) {
  const result = runFuzzSuite(1000);
  process.exit(result.certified ? 0 : 1);
}
