/**
 * VEIL — Policy Simulator Engine (v2.3)
 *
 * Provides full explainability for developer policies:
 * Evaluates (Policy + Agent Request + Context + State) and returns:
 *   - Verdict: ALLOW | CONFIRM_OOB | DENY
 *   - Step-by-step explainable audit trail
 *   - Capability preview
 */

(function () {
  const compiler = typeof require !== 'undefined'
    ? require('./policy-compiler.js')
    : (typeof window !== 'undefined' ? window.VeilPolicyCompiler : null);

  class PolicySimulator {
    /**
     * Simulates a policy evaluation with full explainability.
     *
     * @param {object} policyDef - Raw policy or compiled AST
     * @param {object} agentRequest - { action, origin, target, payload, amount, secretRef }
     * @param {object} [context={}] - Context metadata
     * @returns {object} Simulation report
     */
    simulate(policyDef, agentRequest = {}, context = {}) {
      const ast = policyDef.schema === 'veil.policy.ast/v1'
        ? policyDef
        : (compiler ? compiler.compile(policyDef).ast : policyDef);

      if (!ast || !ast.rules) {
        return {
          verdict: 'DENY',
          allowed: false,
          reasons: ['Malformed or invalid policy definition']
        };
      }

      const explanations = [];
      const action = String(agentRequest.action || '').toUpperCase();
      const origin = agentRequest.origin || 'localhost';
      const rules = ast.rules;

      // 1. Action Check
      if (rules.deniedActions.includes(action)) {
        return {
          verdict: 'DENY',
          allowed: false,
          reasons: [`Action "${action}" is explicitly in deniedActions`],
          explanations
        };
      }

      // 2. Origin Whitelist Check
      const originAllowed = rules.allowedOrigins.includes('*') || rules.allowedOrigins.some(o => origin.includes(o));
      if (!originAllowed) {
        return {
          verdict: 'DENY',
          allowed: false,
          reasons: [`Origin "${origin}" is not in policy allowedOrigins list [${rules.allowedOrigins.join(', ')}]`],
          explanations
        };
      }
      explanations.push(`✓ Origin "${origin}" is authorized`);

      // 3. Amount Constraint Check
      if (agentRequest.amount != null && rules.constraints.maxTransaction) {
        if (agentRequest.amount > rules.constraints.maxTransaction) {
          return {
            verdict: 'DENY',
            allowed: false,
            reasons: [`Transaction amount ${agentRequest.amount} exceeds maxTransaction limit ${rules.constraints.maxTransaction}`],
            explanations
          };
        }
        explanations.push(`✓ Amount ${agentRequest.amount} within limit (${rules.constraints.maxTransaction})`);
      }

      // 4. Confirmation Requirement Check
      if (rules.confirmActions.includes(action)) {
        explanations.push(`! Action "${action}" requires Out-of-Band Human Approval`);
        return {
          verdict: 'CONFIRM_OOB',
          allowed: false,
          requiresHumanApproval: true,
          reasons: [`Action "${action}" is designated as high-risk and requires human verification`],
          explanations,
          capabilityPreview: {
            actionType: action,
            origin,
            ttlMs: rules.constraints.capabilityTtl || 3000,
            pendingApproval: true
          }
        };
      }

      // 5. Allowed Action Check
      if (rules.allowedActions.includes(action)) {
        explanations.push(`✓ Action "${action}" explicitly permitted`);
        return {
          verdict: 'ALLOW',
          allowed: true,
          reasons: ['All policy conditions and constraints satisfied'],
          explanations,
          capabilityPreview: {
            actionType: action,
            origin,
            ttlMs: rules.constraints.capabilityTtl || 5000,
            pendingApproval: false
          }
        };
      }

      // Default fail closed
      return {
        verdict: 'DENY',
        allowed: false,
        reasons: [`Action "${action}" is not permitted by policy rule set (fail-closed default)`],
        explanations
      };
    }
  }

  const defaultSimulator = new PolicySimulator();

  const exportObj = {
    PolicySimulator,
    defaultSimulator,
    simulate: (pol, req, ctx) => defaultSimulator.simulate(pol, req, ctx)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilPolicySimulator = exportObj;
  }
})();
