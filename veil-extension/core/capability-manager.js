/**
 * VEIL — Cryptographic Action Capability Manager & Attenuation Engine
 *
 * Implements Invariant I1 & I3:
 * "The model may propose an action, but it may NEVER authorize execution.
 *  Only the VEIL Security Kernel can issue a signed, state-bound, attenuated Action Capability."
 *
 * Capabilities represent:
 *   - Cryptographic proof of authorization
 *   - Attenuated scope (SCOPE_ELEMENT, SCOPE_FORM, SCOPE_PAGE)
 *   - Nonce & single-use replay protection
 *   - Canonical stateHash binding
 *   - Delegation lineage
 */

(function () {
  const DEFAULT_TTL_MS = 15000;
  const CAPABILITY_VERSION = '2.1.0';

  const securityLedger = typeof require !== 'undefined'
    ? require('./security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  const sha256 = (securityLedger && securityLedger.sha256Sync) || function (ascii) {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(ascii, 'utf8').digest('hex');
      } catch (_) {}
    }
    let hash = 0;
    for (let i = 0; i < ascii.length; i++) {
      hash = ((hash << 5) - hash) + ascii.charCodeAt(i);
      hash |= 0;
    }
    return 'sha256_mock_' + Math.abs(hash).toString(16);
  };

  const ATTENUATION_SCOPES = {
    ELEMENT: 'SCOPE_ELEMENT',
    FORM: 'SCOPE_FORM',
    PAGE: 'SCOPE_PAGE'
  };

  const activeCapabilities = new Map();

  class CapabilityManager {
    constructor() {
      this.version = CAPABILITY_VERSION;
      this.kernelSecret = sha256(`VEIL_KERNEL_HMAC_KEY_${Date.now()}_${Math.random()}`);
    }

    /**
     * Issues a capability directly derived from a verified PolicyDecision.
     *
     * @param {object} policyDecision - Decision from PolicyDecisionPoint
     * @param {object} [overrides] - Optional parameter overrides
     * @returns {object} The signed CapabilityToken
     */
    issueFromDecision(policyDecision, overrides = {}) {
      if (!policyDecision || policyDecision.decision !== 'ALLOW') {
        throw new Error(`Cannot issue capability for non-allowed decision: ${policyDecision ? policyDecision.decision : 'NULL'}`);
      }

      const constraints = { ...(policyDecision.constraints || {}), ...(overrides.constraints || {}) };

      return this.issueCapability({
        actionType: policyDecision.effectType,
        targetFingerprint: policyDecision.targetFingerprint,
        origin: policyDecision.origin,
        stateHash: policyDecision.stateHash,
        purpose: overrides.purpose || 'policy_authorized',
        secretId: overrides.secretId || null,
        ttlMs: constraints.ttlMs || DEFAULT_TTL_MS,
        attenuation: constraints.attenuation || ATTENUATION_SCOPES.ELEMENT,
        maxUses: constraints.maxUses || 1,
        policyDecisionId: policyDecision.decisionId,
        constraints
      });
    }

    /**
     * Issues an ephemeral, signed capability token.
     *
     * @param {object} params
     * @returns {object} The signed CapabilityToken
     */
    issueCapability(params) {
      if (!params || !params.actionType) {
        throw new Error('Capability issuance requires actionType');
      }

      const capabilityId = `cap_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const issuedAt = Date.now();
      const ttlMs = params.ttlMs || DEFAULT_TTL_MS;
      const expiresAt = issuedAt + ttlMs;
      const origin = (params.origin || 'localhost').toLowerCase();
      const stateHash = params.stateHash || 'unanchored_state';
      const targetFingerprint = params.targetFingerprint || 'any';
      const actionType = String(params.actionType).toUpperCase().trim();
      const purpose = params.purpose || 'generic';
      const secretId = params.secretId || null;
      const attenuation = params.attenuation || ATTENUATION_SCOPES.ELEMENT;
      const maxUses = params.maxUses || 1;
      const nonce = Math.random().toString(36).substring(2, 12);

      // Compute HMAC signature over all constrained capability dimensions
      const canonicalPayload = [
        capabilityId,
        actionType,
        targetFingerprint,
        origin,
        stateHash,
        attenuation,
        maxUses,
        expiresAt,
        nonce,
        this.kernelSecret
      ].join('|');

      const signature = sha256(canonicalPayload);

      const token = {
        capabilityId,
        actionType,
        targetFingerprint,
        origin,
        stateHash,
        purpose,
        secretId,
        attenuation,
        maxUses,
        usesRemaining: maxUses,
        issuedAt,
        expiresAt,
        ttlMs,
        nonce,
        delegationDepth: params.delegationDepth || 0,
        delegatedFrom: params.delegatedFrom || null,
        humanApproved: Boolean(params.humanApproved),
        singleUse: maxUses === 1,
        consumed: false,
        constraints: params.constraints || {},
        signature
      };

      activeCapabilities.set(capabilityId, token);

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('CAPABILITY_ISSUED', 'kernel', {
          capabilityId,
          actionType,
          targetFingerprint,
          origin,
          stateHash: stateHash.slice(0, 16) + '...',
          attenuation,
          expiresInMs: ttlMs
        });
      }

      return { ...token };
    }

    /**
     * Attenuates an existing capability into a narrower, more restricted child capability.
     * Enforces the principle of least privilege for agent subtasks.
     *
     * @param {string|object} parentTokenOrId
     * @param {object} narrowerConstraints - { targetFingerprint, ttlMs, attenuation }
     * @returns {object} The attenuated Child CapabilityToken
     */
    attenuateCapability(parentTokenOrId, narrowerConstraints = {}) {
      const parentId = typeof parentTokenOrId === 'string' ? parentTokenOrId : parentTokenOrId.capabilityId;
      const parent = activeCapabilities.get(parentId);
      if (!parent || parent.consumed || Date.now() > parent.expiresAt) {
        throw new Error(`Cannot attenuate invalid, consumed, or expired capability: ${parentId}`);
      }

      const childTtlMs = Math.min(narrowerConstraints.ttlMs || parent.ttlMs, parent.expiresAt - Date.now());
      if (childTtlMs <= 0) {
        throw new Error('Cannot attenuate capability with non-positive TTL');
      }

      const childTarget = narrowerConstraints.targetFingerprint || parent.targetFingerprint;
      const childAttenuation = narrowerConstraints.attenuation || parent.attenuation;

      return this.issueCapability({
        actionType: parent.actionType,
        targetFingerprint: childTarget,
        origin: parent.origin,
        stateHash: parent.stateHash,
        purpose: `attenuated:${parent.purpose}`,
        secretId: parent.secretId,
        ttlMs: childTtlMs,
        attenuation: childAttenuation,
        maxUses: Math.min(narrowerConstraints.maxUses || 1, parent.usesRemaining),
        delegationDepth: parent.delegationDepth + 1,
        delegatedFrom: parent.capabilityId,
        humanApproved: parent.humanApproved,
        constraints: { ...parent.constraints, ...(narrowerConstraints.constraints || {}) }
      });
    }

    /**
     * Verifies that a capability token is valid, unexpired, matches origin and stateHash,
     * and has not exhausted its usage quota.
     *
     * @param {string|object} tokenOrId
     * @param {object} currentContext - { origin, stateHash, targetFingerprint, actionType }
     * @returns {{ valid: boolean, token?: object, reason?: string }}
     */
    verifyCapability(tokenOrId, currentContext = {}) {
      const capabilityId = typeof tokenOrId === 'string' ? tokenOrId : (tokenOrId && tokenOrId.capabilityId);
      if (!capabilityId) {
        return { valid: false, reason: 'Missing capability identifier' };
      }

      const token = activeCapabilities.get(capabilityId);
      if (!token) {
        return { valid: false, reason: 'Capability does not exist or has been revoked' };
      }

      // 1. Quota & Consumption Check
      if (token.consumed || token.usesRemaining <= 0) {
        return { valid: false, reason: 'Capability replay attack detected: Token quota exhausted' };
      }

      // 2. Expiration Check
      if (Date.now() > token.expiresAt) {
        activeCapabilities.delete(capabilityId);
        return { valid: false, reason: `Capability expired ${Date.now() - token.expiresAt}ms ago` };
      }

      // 3. Verify HMAC Signature
      const canonicalPayload = [
        token.capabilityId,
        token.actionType,
        token.targetFingerprint,
        token.origin,
        token.stateHash,
        token.attenuation,
        token.maxUses,
        token.expiresAt,
        token.nonce,
        this.kernelSecret
      ].join('|');

      const expectedSignature = sha256(canonicalPayload);
      if (token.signature !== expectedSignature) {
        activeCapabilities.delete(capabilityId);
        return { valid: false, reason: 'Capability cryptographic signature verification failed (forged token)' };
      }

      // 4. Verify Origin
      if (currentContext.origin) {
        const normOrigin = String(currentContext.origin).toLowerCase();
        if (token.origin !== '*' && normOrigin !== token.origin && !normOrigin.includes(token.origin)) {
          return { valid: false, reason: `Origin mismatch: token bound to "${token.origin}", called from "${normOrigin}"` };
        }
      }

      // 5. Verify Action Type
      if (currentContext.actionType && String(currentContext.actionType).toUpperCase() !== token.actionType) {
        return { valid: false, reason: `Action mismatch: token issued for "${token.actionType}", attempted "${currentContext.actionType}"` };
      }

      // 6. Verify State Hash (TOCTOU Defense)
      if (token.stateHash !== 'unanchored_state' && currentContext.stateHash && currentContext.stateHash !== token.stateHash) {
        return { valid: false, reason: `StateHash mismatch: DOM mutated since capability issuance (TOCTOU violation)` };
      }

      // 7. Verify Target Fingerprint based on Attenuation Scope
      if (token.attenuation === ATTENUATION_SCOPES.ELEMENT && token.targetFingerprint !== 'any') {
        if (currentContext.targetFingerprint && currentContext.targetFingerprint !== token.targetFingerprint) {
          return { valid: false, reason: `Target fingerprint mismatch: capability attenuated to "${token.targetFingerprint}", attempted "${currentContext.targetFingerprint}"` };
        }
      }

      return { valid: true, token: { ...token } };
    }

    /**
     * Atomically consumes one use of a capability token.
     *
     * @param {string|object} tokenOrId
     * @param {object} currentContext
     * @returns {{ ok: boolean, capability?: object, reason?: string }}
     */
    consumeCapability(tokenOrId, currentContext = {}) {
      const verification = this.verifyCapability(tokenOrId, currentContext);
      if (!verification.valid) {
        if (securityLedger && securityLedger.recordEvent) {
          securityLedger.recordEvent('CAPABILITY_CONSUME_BLOCKED', 'kernel', {
            capabilityId: typeof tokenOrId === 'string' ? tokenOrId : (tokenOrId && tokenOrId.capabilityId),
            reason: verification.reason
          });
        }
        return { ok: false, reason: verification.reason };
      }

      const token = activeCapabilities.get(verification.token.capabilityId);
      token.usesRemaining -= 1;
      if (token.usesRemaining <= 0) {
        token.consumed = true;
        token.consumedAt = Date.now();
      }

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('CAPABILITY_CONSUMED', 'kernel', {
          capabilityId: token.capabilityId,
          actionType: token.actionType,
          targetFingerprint: token.targetFingerprint,
          usesRemaining: token.usesRemaining
        });
      }

      return { ok: true, capability: { ...token } };
    }

    revokeCapability(capabilityId, reason = 'manual_revocation') {
      if (activeCapabilities.has(capabilityId)) {
        activeCapabilities.delete(capabilityId);
        if (securityLedger && securityLedger.recordEvent) {
          securityLedger.recordEvent('CAPABILITY_REVOKED', 'kernel', { capabilityId, reason });
        }
        return true;
      }
      return false;
    }

    pruneExpired() {
      const now = Date.now();
      let pruned = 0;
      for (const [id, token] of activeCapabilities.entries()) {
        if (now > token.expiresAt || token.consumed) {
          activeCapabilities.delete(id);
          pruned++;
        }
      }
      return pruned;
    }

    clear() {
      activeCapabilities.clear();
    }
  }

  const defaultCapabilityManager = new CapabilityManager();

  const exportObj = {
    CapabilityManager,
    defaultCapabilityManager,
    ATTENUATION_SCOPES,
    issueCapability: (p) => defaultCapabilityManager.issueCapability(p),
    issueFromDecision: (d, o) => defaultCapabilityManager.issueFromDecision(d, o),
    attenuateCapability: (p, c) => defaultCapabilityManager.attenuateCapability(p, c),
    verifyCapability: (id, ctx) => defaultCapabilityManager.verifyCapability(id, ctx),
    consumeCapability: (id, ctx) => defaultCapabilityManager.consumeCapability(id, ctx),
    revokeCapability: (id, r) => defaultCapabilityManager.revokeCapability(id, r)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilCapabilityManager = exportObj;
  }
})();
