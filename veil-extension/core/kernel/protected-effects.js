/**
 * VEIL — Protected Side Effects & Execution Interceptor
 *
 * Implements Invariant I1 & I3:
 * "No untrusted component or remote model may directly cause a protected side effect.
 *  Every side effect MUST be classified, gated, and authorized via an Action Capability."
 *
 * Side Effect Taxonomy:
 *   - INTERACTION: CLICK, TYPE, SUBMIT, SELECT, SCROLL
 *   - NAVIGATION & IO: NAVIGATE, DOWNLOAD, UPLOAD, CLIPBOARD_WRITE, STORAGE_WRITE
 *   - CRITICAL & IRREVERSIBLE: PURCHASE, TRANSFER, DELETE, CHANGE_SETTING
 *   - EGRESS & SECRETS: NETWORK_REQUEST, SECRET_RELEASE
 */

(function () {
  const EFFECT_CATEGORIES = {
    INTERACTION: 'INTERACTION',
    NAVIGATION_IO: 'NAVIGATION_IO',
    CRITICAL_IRREVERSIBLE: 'CRITICAL_IRREVERSIBLE',
    EGRESS_SECRET: 'EGRESS_SECRET'
  };

  const REVERSIBILITY = {
    REVERSIBLE: 'REVERSIBLE',
    IRREVERSIBLE: 'IRREVERSIBLE'
  };

  /**
   * Complete inventory of all 14 protected side effects recognized by the VEIL Kernel.
   */
  const PROTECTED_EFFECTS = {
    CLICK: {
      id: 'CLICK',
      category: EFFECT_CATEGORIES.INTERACTION,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'SAFE',
      description: 'Triggering native click event on a DOM element'
    },
    TYPE: {
      id: 'TYPE',
      category: EFFECT_CATEGORIES.INTERACTION,
      reversibility: REVERSIBLE = REVERSIBILITY.REVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'SAFE',
      description: 'Injecting text input into a DOM form field'
    },
    SUBMIT: {
      id: 'SUBMIT',
      category: EFFECT_CATEGORIES.INTERACTION,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'SENSITIVE',
      description: 'Submitting a form or sending interactive data'
    },
    SELECT: {
      id: 'SELECT',
      category: EFFECT_CATEGORIES.INTERACTION,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'SAFE',
      description: 'Changing selection option on a dropdown or list'
    },
    SCROLL: {
      id: 'SCROLL',
      category: EFFECT_CATEGORIES.INTERACTION,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'SAFE',
      description: 'Scrolling viewport to view element or coordinates'
    },
    NAVIGATE: {
      id: 'NAVIGATE',
      category: EFFECT_CATEGORIES.NAVIGATION_IO,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'SENSITIVE',
      description: 'Navigating active tab to a new URL'
    },
    DOWNLOAD: {
      id: 'DOWNLOAD',
      category: EFFECT_CATEGORIES.NAVIGATION_IO,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'HIGH_RISK',
      description: 'Triggering local file download from web'
    },
    UPLOAD: {
      id: 'UPLOAD',
      category: EFFECT_CATEGORIES.NAVIGATION_IO,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      description: 'Uploading local file/document to remote origin'
    },
    CLIPBOARD_WRITE: {
      id: 'CLIPBOARD_WRITE',
      category: EFFECT_CATEGORIES.NAVIGATION_IO,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'SENSITIVE',
      description: 'Writing data to system clipboard'
    },
    STORAGE_WRITE: {
      id: 'STORAGE_WRITE',
      category: EFFECT_CATEGORIES.NAVIGATION_IO,
      reversibility: REVERSIBILITY.REVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'SENSITIVE',
      description: 'Writing to localStorage, sessionStorage, or cookies'
    },
    PURCHASE: {
      id: 'PURCHASE',
      category: EFFECT_CATEGORIES.CRITICAL_IRREVERSIBLE,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      mandatoryHumanAuth: true,
      description: 'Monetary transaction, checkout submission, or card charge'
    },
    TRANSFER: {
      id: 'TRANSFER',
      category: EFFECT_CATEGORIES.CRITICAL_IRREVERSIBLE,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      mandatoryHumanAuth: true,
      description: 'Wire transfer, funds remittance, or banking withdrawal'
    },
    DELETE: {
      id: 'DELETE',
      category: EFFECT_CATEGORIES.CRITICAL_IRREVERSIBLE,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      mandatoryHumanAuth: true,
      description: 'Account termination, resource deletion, or data wipe'
    },
    CHANGE_SETTING: {
      id: 'CHANGE_SETTING',
      category: EFFECT_CATEGORIES.CRITICAL_IRREVERSIBLE,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      mandatoryHumanAuth: true,
      description: 'Modifying security settings, password, or 2FA credentials'
    },
    NETWORK_REQUEST: {
      id: 'NETWORK_REQUEST',
      category: EFFECT_CATEGORIES.EGRESS_SECRET,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: false,
      defaultRisk: 'SENSITIVE',
      description: 'Dispatching outbound fetch, XHR, or WebSocket connection'
    },
    SECRET_RELEASE: {
      id: 'SECRET_RELEASE',
      category: EFFECT_CATEGORIES.EGRESS_SECRET,
      reversibility: REVERSIBILITY.IRREVERSIBLE,
      requiresTarget: true,
      defaultRisk: 'HIGH_RISK',
      description: 'Injecting a decrypted credential into DOM at native boundary'
    }
  };

  /**
   * Normalizes an action string or object to a canonical Protected Side Effect descriptor.
   *
   * @param {string|object} actionOrType
   * @returns {object|null}
   */
  function getProtectedEffect(actionOrType) {
    if (!actionOrType) return null;
    let raw = '';
    if (typeof actionOrType === 'string') {
      raw = actionOrType.toUpperCase().trim();
    } else if (typeof actionOrType === 'object') {
      raw = String(actionOrType.type || actionOrType.action || actionOrType.effect || '').toUpperCase().trim();
    }

    if (PROTECTED_EFFECTS[raw]) {
      return PROTECTED_EFFECTS[raw];
    }

    // Heuristic normalization for common action variations
    if (raw === 'INPUT') return PROTECTED_EFFECTS.TYPE;
    if (raw === 'BUY' || raw === 'PAY' || raw === 'CHECKOUT') return PROTECTED_EFFECTS.PURCHASE;
    if (raw === 'SEND_MONEY' || raw === 'WIRE') return PROTECTED_EFFECTS.TRANSFER;
    if (raw === 'WIPE' || raw === 'DESTROY') return PROTECTED_EFFECTS.DELETE;

    return null;
  }

  /**
   * Interceptor checking if a side effect is authorized to proceed.
   *
   * @param {string|object} effect - Protected side effect name or object
   * @param {object} capability - Capability token
   * @param {object} context - Execution context
   * @returns {{ authorized: boolean, reason?: string, effect: object }}
   */
  function assertSideEffectAuthorized(effect, capability, context = {}) {
    const effectDesc = getProtectedEffect(effect);
    if (!effectDesc) {
      return {
        authorized: false,
        reason: `Unknown side effect primitive "${typeof effect === 'object' ? JSON.stringify(effect) : effect}". Untrusted actions fail closed.`,
        effect: null
      };
    }

    // Irreversible effects MANDATE explicit capability authorization
    if (!capability) {
      return {
        authorized: false,
        reason: `Direct side effect invocation blocked: Effect "${effectDesc.id}" requires an authorized CapabilityToken.`,
        effect: effectDesc
      };
    }

    // Check action type match
    if (capability.actionType !== effectDesc.id) {
      return {
        authorized: false,
        reason: `Side effect mismatch: Capability issued for "${capability.actionType}", attempted "${effectDesc.id}".`,
        effect: effectDesc
      };
    }

    // Check mandatory human approval for critical irreversible effects
    if (effectDesc.mandatoryHumanAuth && !capability.humanApproved && capability.riskLevel === 'HIGH_RISK') {
      return {
        authorized: false,
        reason: `Irreversible side effect "${effectDesc.id}" requires verified Out-of-Band Human Approval.`,
        effect: effectDesc
      };
    }

    return {
      authorized: true,
      effect: effectDesc
    };
  }

  const exportObj = {
    PROTECTED_EFFECTS,
    EFFECT_CATEGORIES,
    REVERSIBILITY,
    getProtectedEffect,
    assertSideEffectAuthorized
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilProtectedEffects = exportObj;
  }
})();
