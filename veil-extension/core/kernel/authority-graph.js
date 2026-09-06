/**
 * VEIL — Authority Graph & Singularity Engine (v2.3)
 *
 * Implements Invariant I1-I8 & T1:
 * "There exists exactly ONE authority capable of authorizing each protected side effect.
 *  Any execution attempt from an unauthorized node fails closed."
 */

(function () {
  const ENTITY_CLASSIFICATIONS = {
    UNTRUSTED: 'UNTRUSTED',
    PARTIALLY_TRUSTED: 'PARTIALLY_TRUSTED',
    TCB: 'TCB'
  };

  const AUTHORITY_LEVELS = {
    NONE: 0,
    PROPOSE: 1,
    SANITIZE: 2,
    FILTER: 3,
    DECIDE: 4,
    AUTHORIZE: 5,
    EXECUTE: 6,
    ROOT_AUTH: 7
  };

  /**
   * Authority Graph Node Registry
   */
  const AUTHORITY_NODES = {
    AI_MODEL: {
      id: 'AI_MODEL',
      classification: ENTITY_CLASSIFICATIONS.UNTRUSTED,
      maxAuthority: AUTHORITY_LEVELS.PROPOSE,
      allowedActions: ['PROPOSE_ACTION'],
      prohibitedActions: ['DECIDE_POLICY', 'MINT_CAPABILITY', 'EXECUTE_EFFECT', 'RELEASE_SECRET']
    },
    PAGE_DOM: {
      id: 'PAGE_DOM',
      classification: ENTITY_CLASSIFICATIONS.UNTRUSTED,
      maxAuthority: AUTHORITY_LEVELS.NONE,
      allowedActions: [],
      prohibitedActions: ['PROPOSE_ACTION', 'MINT_CAPABILITY', 'EXECUTE_EFFECT']
    },
    CONTENT_SCRIPT: {
      id: 'CONTENT_SCRIPT',
      classification: ENTITY_CLASSIFICATIONS.PARTIALLY_TRUSTED,
      maxAuthority: AUTHORITY_LEVELS.SANITIZE,
      allowedActions: ['FORWARD_PROPOSAL', 'OBSERVE_DOM'],
      prohibitedActions: ['MINT_CAPABILITY', 'EXECUTE_EFFECT', 'RELEASE_SECRET']
    },
    POLICY_DECISION_POINT: {
      id: 'POLICY_DECISION_POINT',
      classification: ENTITY_CLASSIFICATIONS.TCB,
      maxAuthority: AUTHORITY_LEVELS.DECIDE,
      allowedActions: ['EVALUATE_POLICY', 'EMIT_DECISION'],
      prohibitedActions: ['MINT_CAPABILITY', 'DISPATCH_NATIVE_DOM']
    },
    CAPABILITY_MANAGER: {
      id: 'CAPABILITY_MANAGER',
      classification: ENTITY_CLASSIFICATIONS.TCB,
      maxAuthority: AUTHORITY_LEVELS.AUTHORIZE,
      allowedActions: ['MINT_CAPABILITY', 'CONSUME_CAPABILITY', 'ATTENUATE_CAPABILITY'],
      prohibitedActions: ['EVALUATE_POLICY', 'DISPATCH_NATIVE_DOM']
    },
    EFFECT_GATE: {
      id: 'EFFECT_GATE',
      classification: ENTITY_CLASSIFICATIONS.TCB,
      maxAuthority: AUTHORITY_LEVELS.EXECUTE,
      allowedActions: ['MEDIATE_EFFECT', 'DISPATCH_SUB_GATE', 'EMIT_ACTION_RECEIPT'],
      prohibitedActions: ['MINT_CAPABILITY', 'EVALUATE_POLICY']
    },
    SIDE_PANEL_UI: {
      id: 'SIDE_PANEL_UI',
      classification: ENTITY_CLASSIFICATIONS.TCB,
      maxAuthority: AUTHORITY_LEVELS.ROOT_AUTH,
      allowedActions: ['HUMAN_APPROVE', 'HUMAN_DENY', 'REVOKE_ALL'],
      prohibitedActions: []
    }
  };

  /**
   * Asserts whether a given entity has authority to execute a specific kernel action.
   *
   * @param {string} entityId - From AUTHORITY_NODES
   * @param {string} requestedAction - E.g. 'MINT_CAPABILITY', 'EXECUTE_EFFECT'
   * @returns {{ allowed: boolean, reason?: string }}
   */
  function verifyNodeAuthority(entityId, requestedAction) {
    const node = AUTHORITY_NODES[entityId];
    if (!node) {
      return { allowed: false, reason: `Unknown entity "${entityId}". Untrusted entities fail closed.` };
    }

    // Check prohibited actions
    if (node.prohibitedActions && node.prohibitedActions.includes(requestedAction)) {
      return {
        allowed: false,
        reason: `Authority Violation: Node "${entityId}" (${node.classification}) is strictly prohibited from "${requestedAction}"`
      };
    }

    // Check allowed actions
    if (node.allowedActions && !node.allowedActions.includes(requestedAction)) {
      return {
        allowed: false,
        reason: `Authority Violation: Action "${requestedAction}" is not in permitted capability set of node "${entityId}"`
      };
    }

    return { allowed: true };
  }

  /**
   * Verifies the Authority Singularity Theorem:
   * Only the Capability Manager can mint capability tokens, and only the Effect Gate can mediate side effects.
   */
  function verifyAuthoritySingularity() {
    const minters = Object.values(AUTHORITY_NODES).filter(n =>
      n.allowedActions.includes('MINT_CAPABILITY')
    );

    const executors = Object.values(AUTHORITY_NODES).filter(n =>
      n.allowedActions.includes('MEDIATE_EFFECT')
    );

    const singularityMinter = (minters.length === 1 && minters[0].id === 'CAPABILITY_MANAGER');
    const singularityExecutor = (executors.length === 1 && executors[0].id === 'EFFECT_GATE');

    return {
      singularMinter: singularityMinter,
      singularExecutor: singularityExecutor,
      certified: singularityMinter && singularityExecutor
    };
  }

  const exportObj = {
    ENTITY_CLASSIFICATIONS,
    AUTHORITY_LEVELS,
    AUTHORITY_NODES,
    verifyNodeAuthority,
    verifyAuthoritySingularity
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilAuthorityGraph = exportObj;
  }
})();
