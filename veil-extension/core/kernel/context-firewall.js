/**
 * VEIL — Context Firewall (Purpose-Bound Information Flow Control)
 *
 * Implements Invariant I4, I5 & C5:
 * "The model does not ask: 'What information can we redact?'
 *  The Context Firewall asks: 'What is this model actually allowed to know?'"
 *
 * Formal Law:
 *   Information Access = f(entity, sensitivity, purpose, destination, task, policy)
 *
 * Pipeline:
 *   RAW WORLD ➔ PERCEPTION ➔ SENSITIVITY ANALYSIS ➔ TAINT PROPAGATION
 *   ➔ ABSTRACTION ➔ PURPOSE FILTER ➔ CONTEXT FIREWALL ➔ VEIL-IR v2 ➔ MODEL
 */

(function () {
  const taintEngine = typeof require !== 'undefined'
    ? require('./taint-engine.js')
    : (typeof window !== 'undefined' ? window.VeilTaintEngine : null);

  const stateHasher = typeof require !== 'undefined'
    ? require('../state-hasher.js')
    : (typeof window !== 'undefined' ? window.VeilStateHasher : null);

  const securityLedger = typeof require !== 'undefined'
    ? require('../security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  /**
   * Purpose-to-Allowed-Attributes Policy Matrix.
   * Defines what entities an agent is authorized to perceive based on declared task purpose.
   */
  const PURPOSE_ACCESS_MATRIX = {
    // E-commerce product browsing / price comparison
    product_search: {
      allowedFields: ['product_name', 'price', 'rating', 'availability', 'description', 'reviews', 'category'],
      strictlyProhibited: ['card_number', 'cvv', 'password', 'billing_address', 'ssn', 'aadhaar', 'pan']
    },
    // Adding product to cart / navigating checkout
    checkout_preparation: {
      allowedFields: ['product_name', 'price', 'quantity', 'shipping_options', 'total_amount', 'submit_button'],
      strictlyProhibited: ['card_number', 'cvv', 'pin', 'password', 'security_answer']
    },
    // Authentication / Login navigation
    login_flow: {
      allowedFields: ['login_form', 'username_field', 'password_field_ref', 'submit_button'],
      strictlyProhibited: ['plaintext_password', 'auth_token', 'session_cookie', 'mfa_seed']
    },
    // General assistance
    general_navigation: {
      allowedFields: ['link', 'button', 'menu', 'heading', 'text_paragraph'],
      strictlyProhibited: ['card_number', 'cvv', 'password', 'pin', 'aadhaar', 'pan']
    }
  };

  class ContextFirewall {
    constructor() {
      this.accessMatrix = PURPOSE_ACCESS_MATRIX;
    }

    /**
     * Filters a perceived world state into a constrained, purpose-authorized view.
     *
     * @param {object} rawContext
     * @param {Array<object>} rawContext.elements - Extracted interactive elements
     * @param {string} [rawContext.task='general_navigation'] - Declared agent task
     * @param {string} [rawContext.purpose='general_navigation'] - Declared purpose
     * @param {string} [rawContext.origin='localhost']
     * @param {Document} [doc] - Raw document
     * @returns {{ allowedIR: object, scrubbedCount: number, filteredElements: Array<object> }}
     */
    filterContextForModel(rawContext = {}, doc = null) {
      const task = rawContext.task || rawContext.purpose || 'general_navigation';
      const policy = this.accessMatrix[task] || this.accessMatrix.general_navigation;
      const elements = rawContext.elements || [];

      const filteredElements = [];
      let scrubbedCount = 0;

      for (const el of elements) {
        // 1. Evaluate element sensitivity and taint
        const taint = taintEngine ? taintEngine.getTaint(el) : { level: 0, name: 'PUBLIC' };
        const nameLower = String(el.name || el.id || el.role || '').toLowerCase();
        const tagLower = String(el.tag || '').toLowerCase();

        // 2. Check if element matches strictly prohibited categories for this purpose
        const isProhibited = policy.strictlyProhibited.some(prohib =>
          nameLower.includes(prohib) || (el.expectedSecretType && el.expectedSecretType.includes(prohib))
        ) || taint.level >= (taintEngine ? taintEngine.TAINT_LEVELS.FINANCIAL_SECRET : 4);

        if (isProhibited) {
          scrubbedCount++;
          // Model receives synthetic, opaque ValueRef rather than raw field content or true descriptor
          filteredElements.push({
            id: el.id,
            tag: el.tag,
            role: el.role,
            name: `[PROTECTED_${(el.expectedSecretType || 'SECRET').toUpperCase()}_FIELD]`,
            fingerprint: el.fingerprint,
            state: {
              enabled: el.state ? el.state.enabled : true,
              visible: true,
              filled: Boolean(el.state && el.state.filled)
            },
            sensitivity: 'RESTRICTED_SECRET',
            valueRef: `credential://${rawContext.origin || 'origin'}/${el.expectedSecretType || 'field'}/${el.id}`,
            accessibleToModel: false
          });
        } else {
          // Permitted public / task-aligned element
          filteredElements.push({
            ...el,
            accessibleToModel: true
          });
        }
      }

      // Compute cryptographic anchor
      let stateHash = 'unanchored';
      if (stateHasher && stateHasher.computeStateHash && doc) {
        stateHash = stateHasher.computeStateHash(doc).stateHash;
      } else if (rawContext.stateHash) {
        stateHash = rawContext.stateHash;
      }

      const constrainedIR = {
        schema: 'veil.ir/v2',
        version: '2.2.0',
        purpose: task,
        origin: rawContext.origin || 'localhost',
        stateHash,
        timestamp: Date.now(),
        isoTime: new Date().toISOString(),
        totalElementsPerceived: elements.length,
        accessibleElements: filteredElements.filter(e => e.accessibleToModel).length,
        protectedElements: scrubbedCount,
        elements: filteredElements
      };

      if (securityLedger && securityLedger.recordEvent && scrubbedCount > 0) {
        securityLedger.recordEvent('CONTEXT_FIREWALL_FILTERED', 'context_firewall', {
          purpose: task,
          totalElementsPerceived: elements.length,
          protectedElements: scrubbedCount
        });
      }

      return {
        allowedIR: constrainedIR,
        scrubbedCount,
        filteredElements
      };
    }
  }

  const defaultContextFirewall = new ContextFirewall();

  const exportObj = {
    ContextFirewall,
    defaultContextFirewall,
    PURPOSE_ACCESS_MATRIX,
    filterContextForModel: (ctx, doc) => defaultContextFirewall.filterContextForModel(ctx, doc)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilContextFirewall = exportObj;
  }
})();
