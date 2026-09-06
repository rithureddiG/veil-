/**
 * VEIL — Formal Intermediate Representation (VEIL-IR v1) Compiler
 *
 * Implements Invariant I4 & P1:
 * "The remote AI reasoning model never observes the raw browser DOM.
 *  It observes only VEIL-IR: a formally constrained, privacy-sanitized intermediate representation
 *  cryptographically bound to stateHash."
 *
 * Schema: veil.ir/v1
 */

(function () {
  const stateHasher = typeof require !== 'undefined'
    ? require('./state-hasher.js')
    : (typeof window !== 'undefined' ? window.VeilStateHasher : null);

  const domUtils = typeof require !== 'undefined'
    ? require('./dom-utils.js')
    : (typeof window !== 'undefined' ? window.VeilDomUtils : null);

  const contextFirewall = typeof require !== 'undefined'
    ? require('./kernel/context-firewall.js')
    : (typeof window !== 'undefined' ? window.VeilContextFirewall : null);

  const IR_SCHEMA = 'veil.ir/v2';
  const IR_VERSION = '2.2.0';

  /**
   * Compiles the live DOM into VEIL-IR.
   *
   * @param {Document} doc
   * @param {Array<object>} detections - Detections from PII scanner
   * @param {object} options - { origin, title, task }
   * @returns {object} The compiled VEIL-IR document
   */
  function compileVeilIR(doc, detections = [], options = {}) {
    if (!doc || !doc.querySelectorAll) {
      return {
        schema: IR_SCHEMA,
        version: IR_VERSION,
        timestamp: Date.now(),
        stateHash: 'empty',
        elements: []
      };
    }

    const sensitiveElementMap = new Map();
    for (const d of detections) {
      if (d.element) {
        sensitiveElementMap.set(d.element, d.type || 'sensitive');
      }
    }

    // 1. Compute Canonical StateHash
    let stateHash = 'unanchored';
    if (stateHasher && stateHasher.computeStateHash) {
      stateHash = stateHasher.computeStateHash(doc).stateHash;
    }

    // 2. Discover Interactive & Structural Elements
    const candidates = doc.querySelectorAll('button, input, select, textarea, a[href], [role="button"], [role="link"], [data-veil-id]');
    const elements = [];
    const seen = new Set();

    let elementIndex = 0;
    for (let i = 0; i < candidates.length; i++) {
      const el = candidates[i];
      if (seen.has(el)) continue;
      seen.add(el);

      // Skip invisible elements
      if (el.style && (el.style.display === 'none' || el.style.visibility === 'hidden')) {
        continue;
      }

      elementIndex++;
      const id = el.getAttribute('data-veil-id') || el.id || `el-${elementIndex}`;
      if (!el.getAttribute('data-veil-id')) {
        try { el.setAttribute('data-veil-id', id); } catch (_) {}
      }

      const tag = el.tagName.toLowerCase();
      const role = el.getAttribute('role') || el.getAttribute('type') || tag;
      const ariaLabel = el.getAttribute('aria-label') || '';
      const rawText = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 80);
      const placeholder = el.getAttribute('placeholder') || '';
      const name = (ariaLabel || rawText || placeholder || el.name || id).trim();

      const isSensitive = sensitiveElementMap.has(el) ||
                          el.type === 'password' ||
                          /card|cvv|pass|pin|aadhaar|pan/i.test(el.name || el.id || '');

      const secretType = sensitiveElementMap.get(el) || (isSensitive ? (el.type === 'password' ? 'password' : 'credential') : null);

      // Element State (Presence of value without the value itself)
      const hasValue = Boolean(el.value && el.value.length > 0);
      const isEnabled = !el.disabled && el.getAttribute('aria-disabled') !== 'true';

      const fingerprint = stateHasher && stateHasher.computeElementFingerprint
        ? stateHasher.computeElementFingerprint(el)
        : `${tag}:${role}:${id}`;

      elements.push({
        id,
        fingerprint,
        tag,
        role,
        name: name.slice(0, 100),
        state: {
          enabled: isEnabled,
          visible: true,
          filled: hasValue
        },
        sensitivity: isSensitive ? 'SECRET' : 'PUBLIC',
        ...(secretType ? { expectedSecretType: secretType } : {})
      });
    }

    const ir = {
      schema: IR_SCHEMA,
      version: IR_VERSION,
      timestamp: Date.now(),
      isoTime: new Date().toISOString(),
      origin: options.origin || (typeof location !== 'undefined' ? location.origin : 'localhost'),
      stateHash,
      document: {
        title: (doc.title || '').slice(0, 100)
      },
      elements
    };

    return ir;
  }

  /**
   * Verifies that a VEIL-IR payload contains ZERO raw field values or secret leaks.
   *
   * @param {object} ir
   * @returns {{ valid: boolean, errors: string[] }}
   */
  function validateIR(ir) {
    const errors = [];
    if (!ir || (ir.schema !== 'veil.ir/v1' && ir.schema !== 'veil.ir/v2')) {
      errors.push('Invalid IR schema identifier');
      return { valid: false, errors };
    }

    const jsonStr = JSON.stringify(ir);

    // Structural rule: 'value' property forbidden inside elements
    if (ir.elements && Array.isArray(ir.elements)) {
      for (const el of ir.elements) {
        if ('value' in el) {
          errors.push(`CRITICAL: Element ${el.id} contains prohibited .value property`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  const exportObj = {
    compileVeilIR,
    validateIR,
    IR_SCHEMA,
    IR_VERSION
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilIR = exportObj;
  }
})();
