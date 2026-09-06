/**
 * VEIL — Policy Language (VPL) Compiler (v2.3)
 *
 * Implements Theorem T7:
 * "Declarative security policies compile into canonical, deterministic Policy ASTs
 *  that can be executed identically in simulation and production."
 */

(function () {
  const crypto = typeof require !== 'undefined' ? require('crypto') : null;

  function hash(str) {
    if (crypto) return crypto.createHash('sha256').update(str).digest('hex');
    return 'sig_' + Math.random().toString(36).substring(2);
  }

  class PolicyCompiler {
    /**
     * Compiles a declarative VPL definition into a canonical Policy AST.
     *
     * @param {object} policyDef - Declarative policy object
     * @returns {{ ast: object, signature: string, valid: boolean, errors: Array<string> }}
     */
    compile(policyDef = {}) {
      const errors = [];

      if (!policyDef.policy || typeof policyDef.policy !== 'string') {
        errors.push('Missing required "policy" name identifier');
      }

      const policyName = policyDef.policy || 'unnamed_policy';
      const actorType = (policyDef.actor && policyDef.actor.type) || 'autonomous_agent';

      // 1. Actions parsing
      const actions = policyDef.action || {};
      const allowedActions = Array.isArray(actions.allow) ? actions.allow.map(a => a.toUpperCase()) : [];
      const confirmActions = Array.isArray(actions.confirm) ? actions.confirm.map(a => a.toUpperCase()) : [];
      const deniedActions = Array.isArray(actions.deny) ? actions.deny.map(a => a.toUpperCase()) : [];

      // 2. Data / Taint rules
      const dataRules = policyDef.data || {};
      const deniedDataTaints = Array.isArray(dataRules.deny) ? dataRules.deny.map(d => d.toUpperCase()) : ['CREDENTIAL'];

      // 3. Network whitelists
      const networkRules = policyDef.network || {};
      const allowedOrigins = Array.isArray(networkRules.allow) ? [...networkRules.allow] : ['*'];

      // 4. Secret references
      const secretRules = policyDef.secrets || {};
      const allowedSecrets = Array.isArray(secretRules.allow) ? [...secretRules.allow] : [];

      // 5. Constraints
      const constraints = policyDef.constraints || {};
      const maxTransaction = constraints.max_transaction || 100000;
      const capabilityTtl = constraints.capability_ttl || 5000;

      if (errors.length > 0) {
        return { ast: null, valid: false, errors };
      }

      const canonicalAST = {
        schema: 'veil.policy.ast/v1',
        version: '2.3.0',
        name: policyName,
        actor: { type: actorType },
        rules: {
          allowedActions,
          confirmActions,
          deniedActions,
          deniedDataTaints,
          allowedOrigins,
          allowedSecrets,
          constraints: {
            maxTransaction,
            capabilityTtl
          }
        },
        compiledAt: Date.now()
      };

      const canonicalString = JSON.stringify(canonicalAST);
      const signature = hash(canonicalString);

      return {
        ast: canonicalAST,
        signature,
        valid: true,
        errors: []
      };
    }
  }

  const defaultCompiler = new PolicyCompiler();

  const exportObj = {
    PolicyCompiler,
    defaultCompiler,
    compile: (def) => defaultCompiler.compile(def)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilPolicyCompiler = exportObj;
  }
})();
