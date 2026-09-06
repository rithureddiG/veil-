/**
 * VEIL — Reference Kernel Mutant Generator (Mutation Testing)
 *
 * Implements Pillar R3:
 * Injects deliberate security faults into the Reference Kernel to verify
 * that the test suite actually detects broken security properties.
 */

const { ReferenceKernel } = require('../reference-model/reference-kernel');

const MUTANT_TYPES = {
  MUTANT_SKIP_STATE_CHECK: 'MUTANT_SKIP_STATE_CHECK',
  MUTANT_ALLOW_REPLAY: 'MUTANT_ALLOW_REPLAY',
  MUTANT_INVERT_POLICY: 'MUTANT_INVERT_POLICY',
  MUTANT_SKIP_SIGNATURE: 'MUTANT_SKIP_SIGNATURE',
  MUTANT_ACCEPT_EXPIRED: 'MUTANT_ACCEPT_EXPIRED'
};

function createMutantKernel(mutantType) {
  const kernel = new ReferenceKernel();

  switch (mutantType) {
    case MUTANT_TYPES.MUTANT_SKIP_STATE_CHECK:
      // Flaw: Ignores stateHash mismatch
      kernel.executeEffect = function (capabilityId, contextStateHash) {
        const token = this.issuedCapabilities.get(capabilityId);
        if (!token || token.consumed) return { success: false, reason: 'failed' };
        token.consumed = true;
        return { success: true }; // Flaw: never checks stateHash
      };
      break;

    case MUTANT_TYPES.MUTANT_ALLOW_REPLAY:
      // Flaw: Never marks token.consumed, allowing replay attacks
      kernel.executeEffect = function (capabilityId, contextStateHash) {
        const token = this.issuedCapabilities.get(capabilityId);
        if (!token) return { success: false, reason: 'failed' };
        if (token.stateHash !== contextStateHash) return { success: false, reason: 'mismatch' };
        // Flaw: does NOT mark token.consumed = true
        return { success: true };
      };
      break;

    case MUTANT_TYPES.MUTANT_INVERT_POLICY:
      // Flaw: Allows unauthorized intents
      kernel.evaluateRequest = function (proposal, policyRule) {
        return { decision: 'ALLOW', allowed: true }; // Flaw: always approves
      };
      break;

    case MUTANT_TYPES.MUTANT_SKIP_SIGNATURE:
      // Flaw: Mints invalid signature
      kernel.mintCapability = function (params) {
        const capabilityId = `mutant_cap_${Date.now()}`;
        const token = {
          capabilityId,
          actionType: params.actionType,
          stateHash: params.stateHash,
          consumed: false,
          signature: 'corrupted_signature_xyz' // Flaw: broken signature
        };
        this.issuedCapabilities.set(capabilityId, token);
        return token;
      };
      break;

    case MUTANT_TYPES.MUTANT_ACCEPT_EXPIRED:
      // Flaw: Ignores expiration timestamps
      kernel.isExpired = function () {
        return false; // Flaw: never expires
      };
      break;

    default:
      throw new Error(`Unknown mutant type: ${mutantType}`);
  }

  kernel.mutantType = mutantType;
  return kernel;
}

module.exports = {
  MUTANT_TYPES,
  createMutantKernel
};
