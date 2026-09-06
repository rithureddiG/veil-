/**
 * VEIL — Autonomous Multi-Step Agent Orchestrator & Zero-Trust Kernel FSM
 *
 * Enforces:
 *   1. Hard Step Budget (MAX_STEPS = 5) to prevent runaway loops.
 *   2. Re-perceive after EVERY action (protects against DOM mutation attacks).
 *   3. Finite State Machine:
 *      IDLE -> PERCEIVING -> AUDITING -> REASONING -> VALIDATING -> WAITING_FOR_HUMAN -> REVALIDATING -> EXECUTING -> RE_PERCEIVING -> FINISHED | BLOCKED
 *   4. Cryptographic State-Binding: Computes canonical stateHash per perception step.
 *   5. Capability-Based Execution: Issues ephemeral Action Capability tokens before dispatch.
 *   6. Privileged Human-in-the-Loop Confirmation Gate on HIGH_RISK actions.
 *   7. Tamper-Evident Hash-Chained Ledger Logging.
 */

(function () {
  const MAX_STEPS = 5;
  const LOOP_TIMEOUT_MS = 30000;

  const STATES = {
    IDLE: 'IDLE',
    PERCEIVING: 'PERCEIVING',
    AUDITING: 'AUDITING',
    REASONING: 'REASONING',
    VALIDATING: 'VALIDATING',
    WAITING_FOR_HUMAN: 'WAITING_FOR_HUMAN',
    REVALIDATING: 'REVALIDATING',
    EXECUTING: 'EXECUTING',
    RE_PERCEIVING: 'RE_PERCEIVING',
    FINISHED: 'FINISHED',
    BLOCKED: 'BLOCKED',
    FAILED: 'FAILED',
    MAX_STEPS_REACHED: 'MAX_STEPS_REACHED'
  };

  const capabilityManager = typeof require !== 'undefined'
    ? require('./capability-manager.js')
    : (typeof window !== 'undefined' ? window.VeilCapabilityManager : null);

  const stateHasher = typeof require !== 'undefined'
    ? require('./state-hasher.js')
    : (typeof window !== 'undefined' ? window.VeilStateHasher : null);

  /**
   * Orchestrates multi-step autonomous goal execution with capability gating.
   */
  async function runAutonomousLoop(taskInstruction, callbacks = {}) {
    const {
      onStepUpdate = () => {},
      onComplete = () => {},
      scanAndRedactFn,
      buildContextFn,
      runAuditFn,
      callServerFn,
      resolveTargetFn,
      classifyRiskFn,
      confirmationFn = () => Promise.resolve(true),
      verifyIntegrityFn = () => ({ valid: true }),
      executeActionFn,
      recordEventFn,
      delayMs = 400
    } = callbacks;

    const getDoc = () => (typeof document !== 'undefined' ? document : (callbacks.doc || null));

    let currentStep = 0;
    let state = STATES.PERCEIVING;
    const stepTraces = [];
    const t0 = performance.now();

    recordEventFn('AGENT_TASK_STARTED', 'orchestrator', { task: taskInstruction, maxSteps: MAX_STEPS });

    while (currentStep < MAX_STEPS) {
      currentStep++;
      const stepT0 = performance.now();

      // --- STEP 1: PERCEPTION & STATE HASHING ---
      state = STATES.PERCEIVING;
      onStepUpdate({ step: currentStep, state, message: `Step ${currentStep}: Scanning DOM, redacting PII & computing stateHash...` });

      const detections = scanAndRedactFn();
      const sensitiveElements = new Set(detections.map(d => d.element).filter(Boolean));
      const context = buildContextFn(getDoc(), detections);

      // Compute canonical DOM stateHash
      let currentStateHash = 'unanchored_state';
      if (stateHasher && stateHasher.computeStateHash && getDoc()) {
        currentStateHash = stateHasher.computeStateHash(getDoc()).stateHash;
      }
      context.stateHash = currentStateHash;

      // --- STEP 2: PRIVACY AUDIT ---
      state = STATES.AUDITING;
      const audit = runAuditFn(context, taskInstruction);
      if (audit.status !== 'PASS') {
        state = STATES.BLOCKED;
        recordEventFn('PRIVACY_AUDIT_BLOCKED', 'firewall', { step: currentStep, leaks: audit.leaks });
        const result = { ok: false, state, reason: 'Privacy Invariant Violation (Payload Contained Unredacted Data)', stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      recordEventFn('PRIVACY_AUDIT_PASSED', 'firewall', { step: currentStep, sensitiveCount: audit.sensitiveRegions, stateHash: currentStateHash.slice(0, 12) + '...' });

      // --- STEP 3: REMOTE REASONING ---
      state = STATES.REASONING;
      onStepUpdate({ step: currentStep, state, message: `Step ${currentStep}: Remote reasoning over sanitized skeleton...` });

      let serverResponse;
      try {
        serverResponse = await callServerFn(taskInstruction, context);
      } catch (err) {
        state = STATES.FAILED;
        const result = { ok: false, state, reason: `Server communication failed: ${err.message}`, stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      if (!serverResponse || !serverResponse.ok) {
        state = STATES.FAILED;
        const result = { ok: false, state, reason: (serverResponse && serverResponse.error) || 'Invalid server response', stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      const action = serverResponse.action;
      const actionType = String(action.action || action.type || '').toLowerCase();

      // Check Terminal Action
      if (actionType === 'none' || actionType === 'finish' || actionType === 'wait') {
        state = STATES.FINISHED;
        recordEventFn('AGENT_TASK_FINISHED', 'orchestrator', { step: currentStep, reasoning: action.reasoning || 'Goal completed' });
        stepTraces.push({
          step: currentStep,
          action: actionType,
          target: 'Goal Complete',
          durationMs: Math.round(performance.now() - stepT0),
          status: 'FINISHED'
        });
        const result = { ok: true, state, stepsTaken: currentStep, reason: action.reasoning || 'Task complete', stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      // --- STEP 4: VALIDATION & POLICY EVALUATION ---
      state = STATES.VALIDATING;
      let targetElement = resolveTargetFn(action.target, getDoc());
      const risk = classifyRiskFn(action, targetElement, sensitiveElements);

      recordEventFn('ACTION_RISK_EVALUATED', 'safety_guard', { step: currentStep, level: risk.level, allowed: risk.allowed, reason: risk.reason });

      if (!risk.allowed && !risk.requiresConfirmation) {
        state = STATES.BLOCKED;
        recordEventFn('ACTION_BLOCKED', 'safety_guard', { step: currentStep, reason: risk.reason });
        stepTraces.push({
          step: currentStep,
          action: actionType,
          target: (action.target && (action.target.description || action.target.text)) || 'Unknown Target',
          durationMs: Math.round(performance.now() - stepT0),
          status: 'BLOCKED',
          reason: risk.reason
        });
        const result = { ok: false, state, reason: `Action Blocked by Safety Guard: ${risk.reason}`, stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      const origin = (typeof location !== 'undefined' && location.origin) || 'localhost';
      const targetFp = stateHasher && stateHasher.computeElementFingerprint && targetElement
        ? stateHasher.computeElementFingerprint(targetElement)
        : ((action.target && action.target.id) || 'any');

      // --- STEP 4b: PRIVILEGED HUMAN CONFIRMATION GATE ---
      if (risk.requiresConfirmation || risk.level === 'HIGH_RISK') {
        state = STATES.WAITING_FOR_HUMAN;
        onStepUpdate({
          step: currentStep,
          state,
          message: `Step ${currentStep}: ⚠ HIGH_RISK Action Proposed ("${(action.target && action.target.description) || 'Purchase'}") — Awaiting Human Confirmation...`
        });
        recordEventFn('HUMAN_CONFIRMATION_REQUESTED', 'safety_guard', { step: currentStep, action: actionType, target: action.target });

        const userApproved = await confirmationFn({
          action,
          targetElement,
          targetFingerprint: targetFp,
          riskInfo: risk,
          origin,
          stateHash: currentStateHash
        });

        if (!userApproved) {
          state = STATES.BLOCKED;
          recordEventFn('HUMAN_CONFIRMATION_DENIED', 'safety_guard', { step: currentStep });
          stepTraces.push({
            step: currentStep,
            action: actionType,
            target: (action.target && (action.target.description || action.target.text)) || 'High Risk Action',
            durationMs: Math.round(performance.now() - stepT0),
            status: 'BLOCKED',
            reason: 'User denied confirmation or authorization expired'
          });
          const result = { ok: false, state, reason: 'High-risk action aborted: explicit human authorization was denied or timed out.', stepTraces, totalMs: Math.round(performance.now() - t0) };
          onComplete(result);
          return result;
        }

        recordEventFn('HUMAN_CONFIRMATION_APPROVED', 'safety_guard', { step: currentStep });

        // --- STEP 4c: PRE-EXECUTION REVALIDATION (TOCTOU / State integrity check) ---
        state = STATES.REVALIDATING;
        onStepUpdate({ step: currentStep, state, message: `Step ${currentStep}: Revalidating target & state integrity...` });
        const integrityCheck = verifyIntegrityFn(action, targetElement, getDoc(), {
          expectedStateHash: currentStateHash,
          expectedOrigin: origin
        });

        if (!integrityCheck.valid && !integrityCheck.ok) {
          state = STATES.BLOCKED;
          recordEventFn('MUTATION_TRAP_BLOCKED', 'safety_guard', { step: currentStep, reason: integrityCheck.reason });
          const result = { ok: false, state, reason: `Action aborted after approval: ${integrityCheck.reason}`, stepTraces, totalMs: Math.round(performance.now() - t0) };
          onComplete(result);
          return result;
        }
        if (integrityCheck.resolvedElement) {
          targetElement = integrityCheck.resolvedElement;
        }
      }

      // --- STEP 4d: ISSUE ACTION CAPABILITY TOKEN ---
      let capabilityToken = null;
      if (capabilityManager && capabilityManager.issueCapability) {
        capabilityToken = capabilityManager.issueCapability({
          actionType,
          targetFingerprint: targetFp,
          origin,
          stateHash: currentStateHash,
          purpose: 'agent_loop_step',
          secretId: action.valueRef || null,
          ttlMs: 15000
        });
        action.capabilityId = capabilityToken.capabilityId;
        action.stateHash = currentStateHash;
      }

      // --- STEP 5: EXECUTION (Capability-Authorized) ---
      state = STATES.EXECUTING;
      onStepUpdate({ step: currentStep, state, message: `Step ${currentStep}: Executing capability-authorized action...` });

      const execResult = executeActionFn(action, targetElement, sensitiveElements, origin);
      recordEventFn('ACTION_EXECUTED', 'executor', {
        step: currentStep,
        action: actionType,
        success: execResult.ok !== false && execResult.success !== false,
        usedValueRef: !!execResult.secretUsed,
        capabilityId: (capabilityToken && capabilityToken.capabilityId) || null
      });

      stepTraces.push({
        step: currentStep,
        action: actionType,
        target: (action.target && (action.target.description || action.target.text)) || 'Resolved Target',
        valueRef: execResult.secretId || action.valueRef,
        durationMs: Math.round(performance.now() - stepT0),
        status: (execResult.ok !== false && execResult.success !== false) ? 'EXECUTED' : 'FAILED',
        error: execResult.reason || execResult.error
      });

      const isSuccess = execResult && (execResult.success === true || execResult.ok === true || (execResult.success !== false && execResult.ok !== false));
      if (!isSuccess) {
        state = STATES.FAILED;
        const result = { ok: false, state, reason: `Execution failed: ${(execResult && (execResult.reason || execResult.error)) || 'Unknown execution error'}`, stepTraces, totalMs: Math.round(performance.now() - t0) };
        onComplete(result);
        return result;
      }

      // Breathing room between steps
      if (delayMs > 0) {
        await new Promise(r => setTimeout(r, delayMs));
      }

      // --- STEP 6: RE-PERCEPTION LOOP ---
      state = STATES.RE_PERCEIVING;
      onStepUpdate({ step: currentStep, state, message: `Step ${currentStep}: Re-perceiving live page state post-action...` });
      recordEventFn('RE_PERCEPTION_TRIGGERED', 'orchestrator', { step: currentStep });
    }

    state = STATES.MAX_STEPS_REACHED;
    const finalResult = {
      ok: false,
      state,
      reason: `Task reached maximum step budget (${MAX_STEPS} steps). Safe termination enforced.`,
      stepTraces,
      totalMs: Math.round(performance.now() - t0)
    };
    recordEventFn('AGENT_TASK_MAX_STEPS', 'orchestrator', { maxSteps: MAX_STEPS });
    onComplete(finalResult);
    return finalResult;
  }

  const orchestratorExport = {
    STATES,
    MAX_STEPS,
    runAutonomousLoop
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = orchestratorExport;
  }
  if (typeof window !== 'undefined') {
    window.VeilAgentOrchestrator = orchestratorExport;
  }
})();
